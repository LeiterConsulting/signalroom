from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..cases import CaseStore
from ..discovery import DiscoveryJobStore
from ..rag import EvidenceStore


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_scope(value: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9._-]{2,63}", value):
        raise ValueError("Tenant scope is not safe for an isolated data root.")
    return value


class TenantDataPlaneRegistry:
    """Global routing authority for tenant-owned local stores."""

    def __init__(self, path: Path | str, data_root: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data_root = Path(data_root).resolve()
        self.operation_lock = RLock()
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self.connect() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenant_data_routes (
                    tenant_scope_id TEXT PRIMARY KEY,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    generation_id TEXT NOT NULL,
                    writes_since_cutover INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_data_migrations (
                    id TEXT PRIMARY KEY,
                    tenant_scope_id TEXT NOT NULL,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    generation_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_digest TEXT NOT NULL,
                    target_digest TEXT NOT NULL,
                    components_json TEXT NOT NULL,
                    error TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verified_at TEXT,
                    cutover_at TEXT,
                    rolled_back_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_data_migrations_scope_created
                    ON tenant_data_migrations(tenant_scope_id,created_at DESC);
                """
            )

    def route(self, tenant_scope_id: str) -> dict[str, Any]:
        tenant_scope_id = _safe_scope(tenant_scope_id)
        with self.connect() as database:
            row = database.execute(
                "SELECT * FROM tenant_data_routes WHERE tenant_scope_id=?",
                (tenant_scope_id,),
            ).fetchone()
        if not row:
            return {
                "tenant_scope_id": tenant_scope_id,
                "mode": "shared",
                "generation_id": "",
                "writes_since_cutover": 0,
            }
        return dict(row)

    def path_for(self, component: str, tenant_scope_id: str) -> Path:
        filenames = {
            "evidence": "evidence.db",
            "cases": "cases.db",
            "manual-discovery": "discovery_jobs.db",
        }
        if component not in filenames:
            raise ValueError(f"Unsupported tenant store component: {component}")
        route = self.route(tenant_scope_id)
        if route["mode"] != "isolated-routing":
            return self.data_root / filenames[component]
        path = (
            self.data_root
            / "tenants"
            / tenant_scope_id
            / "generations"
            / str(route["generation_id"])
            / filenames[component]
        ).resolve()
        self.assert_contained(path)
        if not path.is_file():
            raise RuntimeError(f"The active isolated {component} store is missing; routing failed closed.")
        return path

    def generation_root(self, tenant_scope_id: str, generation_id: str) -> Path:
        _safe_scope(tenant_scope_id)
        if not re.fullmatch(r"[a-f0-9]{32}", generation_id):
            raise ValueError("Tenant generation ID is invalid.")
        path = (self.data_root / "tenants" / tenant_scope_id / "generations" / generation_id).resolve()
        self.assert_contained(path)
        return path

    def assert_contained(self, path: Path) -> None:
        if path != self.data_root and self.data_root not in path.parents:
            raise ValueError("Tenant data path escapes the SignalRoom data root.")

    def isolated_tenants(self) -> list[str]:
        with self.connect() as database:
            rows = database.execute(
                """SELECT tenant_scope_id FROM tenant_data_routes
                WHERE mode='isolated-routing' ORDER BY tenant_scope_id"""
            ).fetchall()
        return [str(row["tenant_scope_id"]) for row in rows]

    def migrations(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as database:
            rows = database.execute(
                """SELECT * FROM tenant_data_migrations
                ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(100, int(limit))),),
            ).fetchall()
        return [self._migration(row) for row in rows]

    def migration(self, migration_id: str) -> dict[str, Any] | None:
        with self.connect() as database:
            row = database.execute(
                "SELECT * FROM tenant_data_migrations WHERE id=?", (migration_id,)
            ).fetchone()
        return self._migration(row) if row else None

    def begin_migration(
        self,
        binding: dict[str, str],
        plan_id: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant = _safe_scope(binding["tenant_scope_id"])
        route = self.route(tenant)
        if route["mode"] != "shared":
            raise ValueError("This tenant already uses an isolated store generation.")
        migration_id = uuid4().hex
        generation_id = uuid4().hex
        now = _now()
        with self.connect() as database:
            pending = database.execute(
                """SELECT id,status FROM tenant_data_migrations WHERE tenant_scope_id=?
                AND status IN ('copying','verified','cutover') ORDER BY created_at DESC LIMIT 1""",
                (tenant,),
            ).fetchone()
            if pending:
                raise ValueError(f"Migration {pending['id']} is already {pending['status']} for this tenant.")
            database.execute(
                """INSERT INTO tenant_data_migrations
                (id,tenant_scope_id,connection_alias,connection_fingerprint,plan_id,
                generation_id,status,source_digest,target_digest,components_json,error,
                created_by,created_at,verified_at,cutover_at,rolled_back_at,updated_at)
                VALUES (?,?,?,?,?,?,'copying','','','[]','',?,?,NULL,NULL,NULL,?)""",
                (
                    migration_id,
                    tenant,
                    binding["alias"],
                    binding["fingerprint"],
                    plan_id,
                    generation_id,
                    actor,
                    now,
                    now,
                ),
            )
        result = self.migration(migration_id)
        assert result is not None
        return result

    def verified(
        self,
        migration_id: str,
        source_digest: str,
        target_digest: str,
        components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = _now()
        with self.connect() as database:
            result = database.execute(
                """UPDATE tenant_data_migrations SET status='verified',source_digest=?,
                target_digest=?,components_json=?,verified_at=?,updated_at=?
                WHERE id=? AND status='copying'""",
                (
                    source_digest,
                    target_digest,
                    json.dumps(components, sort_keys=True),
                    now,
                    now,
                    migration_id,
                ),
            )
            if not result.rowcount:
                raise ValueError("Migration is no longer in the copy phase.")
        migration = self.migration(migration_id)
        assert migration is not None
        return migration

    def failed(self, migration_id: str, error: str) -> None:
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_data_migrations SET status='failed',error=?,updated_at=?
                WHERE id=? AND status='copying'""",
                (error[:2000], _now(), migration_id),
            )

    def cutover(self, migration_id: str) -> dict[str, Any]:
        migration = self.migration(migration_id)
        if not migration or migration["status"] != "verified":
            raise ValueError("Only a verified migration can be cut over.")
        now = _now()
        with self.connect() as database:
            route = database.execute(
                "SELECT mode FROM tenant_data_routes WHERE tenant_scope_id=?",
                (migration["tenant_scope_id"],),
            ).fetchone()
            if route and route["mode"] != "shared":
                raise ValueError("Tenant routing changed after migration verification.")
            database.execute(
                """INSERT INTO tenant_data_routes
                (tenant_scope_id,connection_alias,connection_fingerprint,mode,generation_id,
                writes_since_cutover,updated_at) VALUES (?,?,?,'isolated-routing',?,0,?)
                ON CONFLICT(tenant_scope_id) DO UPDATE SET
                connection_alias=excluded.connection_alias,
                connection_fingerprint=excluded.connection_fingerprint,
                mode=excluded.mode,generation_id=excluded.generation_id,
                writes_since_cutover=0,updated_at=excluded.updated_at""",
                (
                    migration["tenant_scope_id"],
                    migration["connection_alias"],
                    migration["connection_fingerprint"],
                    migration["generation_id"],
                    now,
                ),
            )
            database.execute(
                """UPDATE tenant_data_migrations SET status='cutover',cutover_at=?,updated_at=?
                WHERE id=? AND status='verified'""",
                (now, now, migration_id),
            )
        result = self.migration(migration_id)
        assert result is not None
        return result

    def rollback(self, migration_id: str) -> dict[str, Any]:
        migration = self.migration(migration_id)
        if not migration or migration["status"] != "cutover":
            raise ValueError("Only an active cutover can be rolled back.")
        route = self.route(migration["tenant_scope_id"])
        if route["generation_id"] != migration["generation_id"]:
            raise ValueError("The active tenant generation no longer matches this migration.")
        if int(route["writes_since_cutover"]):
            raise ValueError(
                "Rollback is blocked because the isolated generation has accepted writes. "
                "A verified reverse migration is required to preserve them."
            )
        now = _now()
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_data_routes SET mode='shared',generation_id='',
                writes_since_cutover=0,updated_at=? WHERE tenant_scope_id=?""",
                (now, migration["tenant_scope_id"]),
            )
            database.execute(
                """UPDATE tenant_data_migrations SET status='rolled-back',
                rolled_back_at=?,updated_at=? WHERE id=? AND status='cutover'""",
                (now, now, migration_id),
            )
        result = self.migration(migration_id)
        assert result is not None
        return result

    def note_write(self, tenant_scope_id: str) -> None:
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_data_routes
                SET writes_since_cutover=writes_since_cutover+1,updated_at=?
                WHERE tenant_scope_id=? AND mode='isolated-routing'""",
                (_now(), tenant_scope_id),
            )

    def overview(self) -> dict[str, Any]:
        with self.connect() as database:
            routes = [
                dict(row)
                for row in database.execute(
                    "SELECT * FROM tenant_data_routes ORDER BY tenant_scope_id"
                ).fetchall()
            ]
        for item in routes:
            item["source_retained_for_rollback"] = item["mode"] == "isolated-routing"
            item["physical_source_purge_complete"] = False
        return {
            "routes": routes,
            "migrations": self.migrations(),
            "contract": {
                "components": ["evidence", "cases", "manual-discovery"],
                "cutover_requires_exact_source_digest": True,
                "rollback_requires_zero_post_cutover_writes": True,
                "source_retained_until_future_finalization": True,
                "physical_source_purge_available": False,
            },
        }

    @staticmethod
    def _migration(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["components"] = json.loads(str(value.pop("components_json")))
        value["migration_executable"] = value["status"] == "verified"
        value["rollback_available"] = value["status"] == "cutover"
        return value


class TenantDataMigrationService:
    """Copy and verify tenant data before changing the runtime route."""

    COMPONENTS = ("evidence", "cases", "manual-discovery")

    def __init__(self, registry: TenantDataPlaneRegistry):
        self.registry = registry

    def overview(self) -> dict[str, Any]:
        return self.registry.overview()

    def stage(
        self,
        binding: dict[str, str],
        plan: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        ready = {
            item["id"]
            for item in plan.get("components", [])
            if item.get("readiness") == "copy-contract-ready"
        }
        missing = [component for component in self.COMPONENTS if component not in ready]
        if missing:
            raise ValueError("The readiness plan does not admit: " + ", ".join(missing))
        with self.registry.operation_lock:
            self._assert_no_active_discovery(binding["tenant_scope_id"])
            migration = self.registry.begin_migration(binding, plan["plan_id"], actor)
            root = self.registry.generation_root(binding["tenant_scope_id"], migration["generation_id"])
            try:
                if root.exists():
                    raise ValueError("The new tenant generation path already exists.")
                root.mkdir(parents=True)
                results = [
                    self._copy_component(component, binding["tenant_scope_id"], root)
                    for component in self.COMPONENTS
                ]
                source_digest = self._aggregate_digest(results, "source_digest")
                target_digest = self._aggregate_digest(results, "target_digest")
                if source_digest != target_digest:
                    raise ValueError("Tenant copy digest verification failed.")
                return self.registry.verified(migration["id"], source_digest, target_digest, results)
            except Exception as exc:
                self.registry.failed(migration["id"], str(exc))
                if root.exists():
                    shutil.rmtree(root)
                raise

    def cutover(self, migration_id: str, binding: dict[str, str]) -> dict[str, Any]:
        with self.registry.operation_lock:
            migration = self._bound_migration(migration_id, binding, "verified")
            self._assert_no_active_discovery(binding["tenant_scope_id"])
            root = self.registry.generation_root(binding["tenant_scope_id"], migration["generation_id"])
            current = [
                self._component_digest(component, binding["tenant_scope_id"], root=None)
                for component in self.COMPONENTS
            ]
            target = [
                self._component_digest(component, binding["tenant_scope_id"], root=root)
                for component in self.COMPONENTS
            ]
            if self._aggregate_digest(current, "digest") != migration["source_digest"]:
                raise ValueError(
                    "Shared tenant data changed after staging. Build a fresh migration generation."
                )
            if self._aggregate_digest(target, "digest") != migration["target_digest"]:
                raise ValueError("The staged tenant generation changed after verification.")
            return self.registry.cutover(migration_id)

    def rollback(self, migration_id: str, binding: dict[str, str]) -> dict[str, Any]:
        with self.registry.operation_lock:
            self._bound_migration(migration_id, binding, "cutover")
            return self.registry.rollback(migration_id)

    def _bound_migration(self, migration_id: str, binding: dict[str, str], status: str) -> dict[str, Any]:
        migration = self.registry.migration(migration_id)
        if not migration or migration["status"] != status:
            raise ValueError(f"Migration must be {status} for this action.")
        expected = (
            migration["connection_alias"],
            migration["connection_fingerprint"],
            migration["tenant_scope_id"],
        )
        observed = (
            binding["alias"],
            binding["fingerprint"],
            binding["tenant_scope_id"],
        )
        if observed != expected:
            raise ValueError("Migration is bound to a different immutable Splunk scope.")
        return migration

    def _assert_no_active_discovery(self, tenant_scope_id: str) -> None:
        path = self.registry.data_root / "discovery_jobs.db"
        if not path.is_file():
            return
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as database:
            row = database.execute(
                """SELECT id FROM discovery_jobs WHERE tenant_scope_id=?
                AND status IN ('queued','running') ORDER BY created_at LIMIT 1""",
                (tenant_scope_id,),
            ).fetchone()
        if row:
            raise ValueError(f"Manual discovery job {row[0]} must finish or be cancelled before migration.")

    def _copy_component(self, component: str, tenant_scope_id: str, root: Path) -> dict[str, Any]:
        source = self.registry.path_for(component, tenant_scope_id)
        target = root / source.name
        self._initialize_target(component, target, root)
        queries = self._queries(component, tenant_scope_id)
        source_hasher = hashlib.sha256()
        counts: dict[str, int] = {}
        with closing(sqlite3.connect(source)) as source_db, closing(sqlite3.connect(target)) as target_db:
            source_db.row_factory = sqlite3.Row
            source_db.execute("BEGIN")
            target_db.execute("BEGIN")
            for table, sql, params in queries:
                count = self._copy_rows(source_db, target_db, table, sql, params, source_hasher)
                counts[table] = count
            target_db.commit()
        target_digest = self._digest_path(target, queries)
        return {
            "id": component,
            "source_records": sum(counts.values()),
            "target_records": sum(counts.values()),
            "tables": counts,
            "source_digest": source_hasher.hexdigest(),
            "target_digest": target_digest,
            "verified": source_hasher.hexdigest() == target_digest,
        }

    @staticmethod
    def _initialize_target(component: str, target: Path, root: Path) -> None:
        if target.exists():
            raise ValueError(f"Target {component} store already exists.")
        if component == "evidence":
            EvidenceStore(target)
        elif component == "cases":
            CaseStore(target, root / "case_exports")
        else:
            DiscoveryJobStore(target)

    def _component_digest(self, component: str, tenant_scope_id: str, root: Path | None) -> dict[str, Any]:
        path = (
            root
            / {
                "evidence": "evidence.db",
                "cases": "cases.db",
                "manual-discovery": "discovery_jobs.db",
            }[component]
            if root
            else self.registry.data_root
            / {
                "evidence": "evidence.db",
                "cases": "cases.db",
                "manual-discovery": "discovery_jobs.db",
            }[component]
        )
        return {
            "id": component,
            "digest": self._digest_path(path, self._queries(component, tenant_scope_id)),
        }

    @staticmethod
    def _queries(component: str, tenant_scope_id: str) -> list[tuple[str, str, tuple[Any, ...]]]:
        if component == "evidence":
            root = "SELECT id FROM artifacts WHERE tenant_scope_id=?"
            return [
                (
                    "artifacts",
                    "SELECT * FROM artifacts WHERE tenant_scope_id=? ORDER BY id",
                    (tenant_scope_id,),
                ),
                (
                    "chunks",
                    f"SELECT * FROM chunks WHERE artifact_id IN ({root}) ORDER BY id",
                    (tenant_scope_id,),
                ),
                (
                    "chunks_fts",
                    f"SELECT * FROM chunks_fts WHERE artifact_id IN ({root}) ORDER BY chunk_id",
                    (tenant_scope_id,),
                ),
                (
                    "embeddings",
                    "SELECT * FROM embeddings WHERE chunk_id IN "
                    f"(SELECT id FROM chunks WHERE artifact_id IN ({root})) "
                    "ORDER BY chunk_id,model_profile",
                    (tenant_scope_id,),
                ),
            ]
        if component == "cases":
            root = "SELECT id FROM cases WHERE tenant_scope_id=?"
            return [
                ("cases", "SELECT * FROM cases WHERE tenant_scope_id=? ORDER BY id", (tenant_scope_id,)),
                (
                    "case_items",
                    f"SELECT * FROM case_items WHERE case_id IN ({root}) ORDER BY id",
                    (tenant_scope_id,),
                ),
            ]
        root = "SELECT id FROM discovery_jobs WHERE tenant_scope_id=?"
        return [
            (
                "discovery_jobs",
                "SELECT * FROM discovery_jobs WHERE tenant_scope_id=? ORDER BY id",
                (tenant_scope_id,),
            ),
            (
                "discovery_job_events",
                f"SELECT * FROM discovery_job_events WHERE job_id IN ({root}) ORDER BY id",
                (tenant_scope_id,),
            ),
        ]

    @staticmethod
    def _copy_rows(
        source: sqlite3.Connection,
        target: sqlite3.Connection,
        table: str,
        sql: str,
        params: tuple[Any, ...],
        hasher: Any,
    ) -> int:
        cursor = source.execute(sql, params)
        columns = [str(item[0]) for item in cursor.description or []]
        quoted = ",".join(f'"{column}"' for column in columns)
        placeholders = ",".join("?" for _ in columns)
        insert = f'INSERT INTO "{table}" ({quoted}) VALUES ({placeholders})'
        hasher.update(f"table:{table}\n".encode())
        count = 0
        while rows := cursor.fetchmany(250):
            values = [tuple(row[column] for column in columns) for row in rows]
            target.executemany(insert, values)
            for value in values:
                hasher.update(json.dumps(value, separators=(",", ":"), default=str).encode())
                hasher.update(b"\n")
            count += len(values)
        return count

    @staticmethod
    def _digest_path(path: Path, queries: list[tuple[str, str, tuple[Any, ...]]]) -> str:
        if not path.is_file():
            raise ValueError(f"Tenant store is missing: {path.name}")
        hasher = hashlib.sha256()
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as database:
            database.row_factory = sqlite3.Row
            for table, sql, params in queries:
                hasher.update(f"table:{table}\n".encode())
                cursor = database.execute(sql, params)
                columns = [str(item[0]) for item in cursor.description or []]
                while rows := cursor.fetchmany(250):
                    for row in rows:
                        value = tuple(row[column] for column in columns)
                        hasher.update(json.dumps(value, separators=(",", ":"), default=str).encode())
                        hasher.update(b"\n")
        return hasher.hexdigest()

    @staticmethod
    def _aggregate_digest(values: list[dict[str, Any]], key: str) -> str:
        identity = [
            {"id": item["id"], "digest": item[key]} for item in sorted(values, key=lambda entry: entry["id"])
        ]
        return hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class RoutedEvidenceStore:
    def __init__(self, registry: TenantDataPlaneRegistry):
        self.registry = registry
        self.path = registry.data_root / "evidence.db"
        self._stores: dict[str, EvidenceStore] = {}

    def _store(self, tenant_scope_id: str) -> EvidenceStore:
        path = self.registry.path_for("evidence", tenant_scope_id)
        return self._stores.setdefault(str(path), EvidenceStore(path))

    def _shared(self) -> EvidenceStore:
        return self._stores.setdefault(str(self.path), EvidenceStore(self.path))

    def connect(self) -> sqlite3.Connection:
        return self._shared().connect()

    def bind_unbound(self, binding: dict[str, Any]) -> None:
        self._shared().bind_unbound(binding)

    def add(self, record: Any, metadata: dict[str, Any] | None = None) -> Any:
        with self.registry.operation_lock:
            result = self._store(record.tenant_scope_id).add(record, metadata)
            self.registry.note_write(record.tenant_scope_id)
            return result

    def list(self, limit: int = 100, tenant_scope_id: str | None = None) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list(limit, tenant_scope_id)
        return self._aggregate("list", limit)

    def get(self, artifact_id: str, tenant_scope_id: str | None = None) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).get(artifact_id, tenant_scope_id)
        for tenant, store in self._active_stores():
            result = store.get(artifact_id, tenant)
            if result:
                return result
        result = self._shared().get(artifact_id)
        return result if result and result.tenant_scope_id not in self.registry.isolated_tenants() else None

    def update(self, artifact_id: str, value: Any, tenant_scope_id: str | None = None) -> Any:
        tenant = tenant_scope_id or self._tenant_for_artifact(artifact_id)
        if not tenant:
            return None
        with self.registry.operation_lock:
            result = self._store(tenant).update(artifact_id, value, tenant)
            if result:
                self.registry.note_write(tenant)
            return result

    def delete(self, artifact_id: str, tenant_scope_id: str | None = None) -> bool:
        tenant = tenant_scope_id or self._tenant_for_artifact(artifact_id)
        if not tenant:
            return False
        with self.registry.operation_lock:
            result = self._store(tenant).delete(artifact_id, tenant)
            if result:
                self.registry.note_write(tenant)
            return result

    def search(self, query: str, limit: int = 6, tenant_scope_id: str | None = None) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).search(query, limit, tenant_scope_id)
        values: list[Any] = []
        for tenant, store in self._active_stores():
            values.extend(store.search(query, limit, tenant))
        shared = self._shared().search(query, limit)
        isolated = set(self.registry.isolated_tenants())
        values.extend(item for item in shared if item.tenant_scope_id not in isolated)
        return sorted(values, key=lambda item: item.score, reverse=True)[:limit]

    def pending_embeddings(
        self, model_profile: str, limit: int = 32, tenant_scope_id: str | None = None
    ) -> list[tuple[str, str]]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).pending_embeddings(model_profile, limit, tenant_scope_id)
        values: list[tuple[str, str]] = []
        for tenant, store in self._active_stores():
            values.extend(store.pending_embeddings(model_profile, limit, tenant))
        isolated = set(self.registry.isolated_tenants())
        for item in self._shared().pending_embeddings(model_profile, limit):
            tenant = self._tenant_for_chunk(item[0], self._shared())
            if tenant not in isolated:
                values.append(item)
        return values[:limit]

    def embedding_status(self, model_profile: str, tenant_scope_id: str | None = None) -> dict[str, int]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).embedding_status(model_profile, tenant_scope_id)
        statuses = [store.embedding_status(model_profile, tenant) for tenant, store in self._active_stores()]
        isolated = set(self.registry.isolated_tenants())
        with self._shared().connect() as database:
            placeholders = ",".join("?" for _ in isolated)
            condition = f" WHERE a.tenant_scope_id NOT IN ({placeholders})" if isolated else ""
            params = tuple(isolated)
            total = int(
                database.execute(
                    f"SELECT COUNT(*) FROM chunks c JOIN artifacts a ON a.id=c.artifact_id{condition}", params
                ).fetchone()[0]
            )
            indexed = int(
                database.execute(
                    "SELECT COUNT(*) FROM embeddings e "
                    "JOIN chunks c ON c.id=e.chunk_id "
                    "JOIN artifacts a ON a.id=c.artifact_id"
                    f"{condition}{' AND' if condition else ' WHERE'} e.model_profile=?",
                    (*params, model_profile),
                ).fetchone()[0]
            )
        statuses.append(
            {"total_chunks": total, "indexed_chunks": indexed, "pending_chunks": max(0, total - indexed)}
        )
        return {
            key: sum(item[key] for item in statuses)
            for key in ("total_chunks", "indexed_chunks", "pending_chunks")
        }

    def semantic_candidates(self, limit: int = 24, tenant_scope_id: str | None = None) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).semantic_candidates(limit, tenant_scope_id)
        return self._aggregate("semantic_candidates", limit)[:limit]

    def semantic_search(
        self,
        query_vector: list[float],
        model_profile: str,
        limit: int = 6,
        tenant_scope_id: str | None = None,
    ) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).semantic_search(
                query_vector, model_profile, limit, tenant_scope_id
            )
        values: list[Any] = []
        for tenant, store in self._active_stores():
            values.extend(store.semantic_search(query_vector, model_profile, limit, tenant))
        isolated = set(self.registry.isolated_tenants())
        values.extend(
            item
            for item in self._shared().semantic_search(query_vector, model_profile, limit)
            if item.tenant_scope_id not in isolated
        )
        return sorted(values, key=lambda item: item.score, reverse=True)[:limit]

    def save_embeddings(self, model_profile: str, values: list[tuple[str, list[float]]]) -> None:
        if not values:
            return
        with self.registry.operation_lock:
            remaining = {chunk_id: vector for chunk_id, vector in values}
            for tenant, store in self._active_stores():
                matched = [
                    (chunk_id, vector)
                    for chunk_id, vector in remaining.items()
                    if self._tenant_for_chunk(chunk_id, store) == tenant
                ]
                if matched:
                    store.save_embeddings(model_profile, matched)
                    self.registry.note_write(tenant)
                    for chunk_id, _ in matched:
                        remaining.pop(chunk_id, None)
            if remaining:
                isolated = set(self.registry.isolated_tenants())
                matched = [
                    (chunk_id, vector)
                    for chunk_id, vector in remaining.items()
                    if self._tenant_for_chunk(chunk_id, self._shared()) not in isolated
                ]
                self._shared().save_embeddings(model_profile, matched)

    def _aggregate(self, method: str, limit: int) -> list[Any]:
        values: list[Any] = []
        for tenant, store in self._active_stores():
            values.extend(getattr(store, method)(limit, tenant_scope_id=tenant))
        isolated = set(self.registry.isolated_tenants())
        values.extend(
            item for item in getattr(self._shared(), method)(limit) if item.tenant_scope_id not in isolated
        )
        return values[:limit]

    def _active_stores(self) -> list[tuple[str, EvidenceStore]]:
        return [(tenant, self._store(tenant)) for tenant in self.registry.isolated_tenants()]

    def _tenant_for_artifact(self, artifact_id: str) -> str:
        record = self.get(artifact_id)
        return str(record.tenant_scope_id) if record else ""

    @staticmethod
    def _tenant_for_chunk(chunk_id: str, store: EvidenceStore) -> str:
        with store.connect() as database:
            row = database.execute(
                "SELECT a.tenant_scope_id FROM chunks c JOIN artifacts a ON a.id=c.artifact_id WHERE c.id=?",
                (chunk_id,),
            ).fetchone()
        return str(row[0]) if row else ""


class RoutedCaseStore:
    def __init__(self, registry: TenantDataPlaneRegistry):
        self.registry = registry
        self.path = registry.data_root / "cases.db"
        self.export_dir = registry.data_root / "case_exports"
        self._stores: dict[str, CaseStore] = {}

    def _store(self, tenant: str) -> CaseStore:
        path = self.registry.path_for("cases", tenant)
        export_dir = path.parent / "case_exports" if path != self.path else self.export_dir
        return self._stores.setdefault(str(path), CaseStore(path, export_dir))

    def _shared(self) -> CaseStore:
        return self._stores.setdefault(str(self.path), CaseStore(self.path, self.export_dir))

    def bind_unbound(self, binding: dict[str, object]) -> None:
        self._shared().bind_unbound(binding)

    def create(self, value: Any) -> Any:
        with self.registry.operation_lock:
            result = self._store(value.tenant_scope_id).create(value)
            self.registry.note_write(value.tenant_scope_id)
            return result

    def list(self, limit: int = 100, tenant_scope_id: str | None = None) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list(limit, tenant_scope_id)
        isolated = set(self.registry.isolated_tenants())
        values = [item for item in self._shared().list(limit) if item.tenant_scope_id not in isolated]
        for tenant in isolated:
            values.extend(self._store(tenant).list(limit, tenant))
        return sorted(values, key=lambda item: item.updated_at, reverse=True)[:limit]

    def get(self, case_id: str, tenant_scope_id: str | None = None) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).get(case_id, tenant_scope_id)
        for tenant in self.registry.isolated_tenants():
            if result := self._store(tenant).get(case_id, tenant):
                return result
        result = self._shared().get(case_id)
        return result if result and result.tenant_scope_id not in self.registry.isolated_tenants() else None

    def update(self, case_id: str, value: Any, tenant_scope_id: str | None = None) -> Any:
        return self._mutate("update", case_id, value, tenant_scope_id=tenant_scope_id)

    def delete(self, case_id: str, tenant_scope_id: str | None = None) -> bool:
        return bool(self._mutate("delete", case_id, tenant_scope_id=tenant_scope_id))

    def add_item(self, case_id: str, value: Any, tenant_scope_id: str | None = None) -> Any:
        return self._mutate("add_item", case_id, value, tenant_scope_id=tenant_scope_id)

    def update_item(self, case_id: str, item_id: str, value: Any, tenant_scope_id: str | None = None) -> Any:
        return self._mutate("update_item", case_id, item_id, value, tenant_scope_id=tenant_scope_id)

    def delete_item(self, case_id: str, item_id: str, tenant_scope_id: str | None = None) -> bool:
        return bool(self._mutate("delete_item", case_id, item_id, tenant_scope_id=tenant_scope_id))

    def export(self, case_id: str, formats: list[str], tenant_scope_id: str | None = None) -> list[Path]:
        tenant = tenant_scope_id or self._tenant_for_case(case_id)
        return self._store(tenant).export(case_id, formats, tenant) if tenant else []

    def _mutate(self, method: str, case_id: str, *args: Any, tenant_scope_id: str | None = None) -> Any:
        tenant = tenant_scope_id or self._tenant_for_case(case_id)
        if not tenant:
            return None
        with self.registry.operation_lock:
            result = getattr(self._store(tenant), method)(case_id, *args, tenant_scope_id=tenant)
            if result:
                self.registry.note_write(tenant)
            return result

    def _tenant_for_case(self, case_id: str) -> str:
        result = self.get(case_id)
        return str(result.tenant_scope_id) if result else ""


class RoutedDiscoveryJobStore:
    def __init__(self, registry: TenantDataPlaneRegistry):
        self.registry = registry
        self.path = registry.data_root / "discovery_jobs.db"
        self._stores: dict[str, DiscoveryJobStore] = {}

    def _store(self, tenant: str) -> DiscoveryJobStore:
        path = self.registry.path_for("manual-discovery", tenant)
        return self._stores.setdefault(str(path), DiscoveryJobStore(path))

    def _shared(self) -> DiscoveryJobStore:
        return self._stores.setdefault(str(self.path), DiscoveryJobStore(self.path))

    def bind_unbound(self, binding: dict[str, Any]) -> int:
        return self._shared().bind_unbound(binding)

    def create_job(
        self, depth: str, requested_by: str, call_budget: int, binding: dict[str, Any] | None = None
    ) -> Any:
        binding = binding or {"tenant_scope_id": "workspace-primary"}
        tenant = str(binding.get("tenant_scope_id") or "workspace-primary")
        with self.registry.operation_lock:
            result = self._store(tenant).create_job(depth, requested_by, call_budget, binding)
            self.registry.note_write(tenant)
            return result

    def get_job(self, job_id: str, tenant_scope_id: str | None = None) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).get_job(job_id, tenant_scope_id)
        found = self._find(job_id)
        return found[1] if found else None

    def list_jobs(self, limit: int = 20, tenant_scope_id: str | None = None) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list_jobs(limit, tenant_scope_id)
        isolated = set(self.registry.isolated_tenants())
        values = [item for item in self._shared().list_jobs(limit) if item.tenant_scope_id not in isolated]
        for tenant in isolated:
            values.extend(self._store(tenant).list_jobs(limit, tenant))
        return sorted(values, key=lambda item: item.created_at, reverse=True)[:limit]

    def active_job(self, tenant_scope_id: str | None = None) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).active_job(tenant_scope_id)
        jobs = [item for tenant in self._all_tenants() if (item := self._store(tenant).active_job(tenant))]
        shared = self._shared().active_job()
        if shared and shared.tenant_scope_id not in self.registry.isolated_tenants():
            jobs.append(shared)
        return sorted(jobs, key=lambda item: item.created_at)[0] if jobs else None

    def next_queued(self) -> Any:
        jobs = [item for tenant in self._all_tenants() if (item := self._store(tenant).next_queued())]
        shared = self._shared().next_queued()
        if shared and shared.tenant_scope_id not in self.registry.isolated_tenants():
            jobs.append(shared)
        return sorted(jobs, key=lambda item: item.created_at)[0] if jobs else None

    def recover_interrupted(self) -> int:
        return self._shared().recover_interrupted() + sum(
            self._store(tenant).recover_interrupted() for tenant in self._all_tenants()
        )

    def mark_running(self, job_id: str) -> Any:
        return self._mutate("mark_running", job_id)

    def update_progress(self, job_id: str, event: dict[str, Any], calls_used: int) -> None:
        self._mutate("update_progress", job_id, event, calls_used)

    def complete_job(
        self,
        job_id: str,
        status: str,
        summary: dict[str, Any],
        result: dict[str, Any] | None,
        calls_used: int,
    ) -> Any:
        return self._mutate("complete_job", job_id, status, summary, result, calls_used)

    def fail_job(self, job_id: str, status: str, error: str, calls_used: int) -> Any:
        return self._mutate("fail_job", job_id, status, error, calls_used)

    def request_cancel(self, job_id: str) -> Any:
        return self._mutate("request_cancel", job_id)

    def requeue_for_restart(self, job_id: str) -> None:
        self._mutate("requeue_for_restart", job_id)

    def events(self, job_id: str, limit: int = 20, after_id: int = 0) -> list[dict[str, Any]]:
        found = self._find(job_id)
        return found[0].events(job_id, limit, after_id) if found else []

    def result(self, job_id: str) -> dict[str, Any] | None:
        found = self._find(job_id)
        return found[0].result(job_id) if found else None

    def _mutate(self, method: str, job_id: str, *args: Any) -> Any:
        with self.registry.operation_lock:
            found = self._find(job_id)
            if not found:
                return None
            store, job = found
            result = getattr(store, method)(job_id, *args)
            self.registry.note_write(job.tenant_scope_id)
            return result

    def _find(self, job_id: str) -> tuple[DiscoveryJobStore, Any] | None:
        for tenant in self._all_tenants():
            store = self._store(tenant)
            if job := store.get_job(job_id, tenant):
                return store, job
        job = self._shared().get_job(job_id)
        if job and job.tenant_scope_id not in self.registry.isolated_tenants():
            return self._shared(), job
        return None

    def _all_tenants(self) -> list[str]:
        return self.registry.isolated_tenants()
