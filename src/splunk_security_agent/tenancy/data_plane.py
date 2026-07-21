from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..assurance import AssuranceStore
from ..cases import CaseStore
from ..delivery import DeliveryStore
from ..detections import DetectionStore
from ..discovery import DiscoveryJobStore
from ..forecasting import TimeSeriesExperimentStore
from ..rag import EvidenceStore
from ..validation import ValidationStore

TENANT_STORE_FILENAMES = {
    "evidence": "evidence.db",
    "cases": "cases.db",
    "manual-discovery": "discovery_jobs.db",
    "validations": "validations.db",
    "detections": "detections.db",
    "forecast-experiments": "time_series_experiments.db",
    "assurance-responses": "assurance_responses.db",
    "outbound-delivery": "delivery_history.db",
}

SHARED_STORE_FILENAMES = {
    **TENANT_STORE_FILENAMES,
    "assurance-responses": "assurance.db",
    "outbound-delivery": "delivery.db",
}

TENANT_DIRECTORY_NAMES = {
    "discovery-files": "artifacts",
    "case-exports": "case_exports",
}

TENANT_DATA_COMPONENTS = (*TENANT_STORE_FILENAMES, *TENANT_DIRECTORY_NAMES)


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
                    shared_source_purged INTEGER NOT NULL DEFAULT 0,
                    finalized_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_data_migrations (
                    id TEXT PRIMARY KEY,
                    tenant_scope_id TEXT NOT NULL,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    generation_id TEXT NOT NULL,
                    source_generation_id TEXT NOT NULL DEFAULT '',
                    source_writes_since_cutover INTEGER NOT NULL DEFAULT 0,
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
                CREATE TABLE IF NOT EXISTS tenant_file_manifests (
                    component TEXT NOT NULL,
                    storage_generation_id TEXT NOT NULL DEFAULT '',
                    relative_path TEXT NOT NULL,
                    tenant_scope_id TEXT NOT NULL,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    source_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(component,storage_generation_id,relative_path)
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_file_manifest_scope
                    ON tenant_file_manifests(
                        tenant_scope_id,connection_alias,connection_fingerprint,
                        storage_generation_id,component
                    );
                CREATE TABLE IF NOT EXISTS tenant_reverse_migrations (
                    id TEXT PRIMARY KEY,
                    forward_migration_id TEXT NOT NULL,
                    tenant_scope_id TEXT NOT NULL,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    generation_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    resume_status TEXT NOT NULL DEFAULT '',
                    source_digest TEXT NOT NULL,
                    shared_baseline_digest TEXT NOT NULL,
                    shared_target_digest TEXT NOT NULL,
                    pre_finalize_shared_digest TEXT NOT NULL DEFAULT '',
                    components_json TEXT NOT NULL,
                    error TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verified_at TEXT,
                    finalized_at TEXT,
                    applied_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_reverse_scope_created
                    ON tenant_reverse_migrations(tenant_scope_id,created_at DESC);
                """
            )
            route_columns = {
                str(row["name"])
                for row in database.execute("PRAGMA table_info(tenant_data_routes)").fetchall()
            }
            if "shared_source_purged" not in route_columns:
                database.execute(
                    """ALTER TABLE tenant_data_routes ADD COLUMN
                    shared_source_purged INTEGER NOT NULL DEFAULT 0"""
                )
            if "finalized_at" not in route_columns:
                database.execute("ALTER TABLE tenant_data_routes ADD COLUMN finalized_at TEXT")
            reverse_columns = {
                str(row["name"])
                for row in database.execute(
                    "PRAGMA table_info(tenant_reverse_migrations)"
                ).fetchall()
            }
            if "resume_status" not in reverse_columns:
                database.execute(
                    """ALTER TABLE tenant_reverse_migrations ADD COLUMN
                    resume_status TEXT NOT NULL DEFAULT ''"""
                )
            now = _now()
            database.execute(
                """UPDATE tenant_reverse_migrations SET status='failed',
                error='SignalRoom restarted before reverse staging completed.',updated_at=?
                WHERE status='copying'""",
                (now,),
            )
            database.execute(
                """UPDATE tenant_reverse_migrations SET status=CASE
                    WHEN resume_status IN ('verified','finalized-ready') THEN resume_status
                    WHEN EXISTS (
                        SELECT 1 FROM tenant_data_routes route
                        WHERE route.tenant_scope_id=tenant_reverse_migrations.tenant_scope_id
                        AND route.mode='isolated-routing' AND route.shared_source_purged=1
                    ) THEN 'finalized-ready'
                    ELSE 'verified' END,
                error='SignalRoom restarted during reverse apply; verified component progress was retained.',
                resume_status='',updated_at=? WHERE status='applying'""",
                (now,),
            )
            columns = {
                str(row["name"])
                for row in database.execute("PRAGMA table_info(tenant_data_migrations)").fetchall()
            }
            if "source_generation_id" not in columns:
                database.execute(
                    """ALTER TABLE tenant_data_migrations ADD COLUMN
                    source_generation_id TEXT NOT NULL DEFAULT ''"""
                )
            if "source_writes_since_cutover" not in columns:
                database.execute(
                    """ALTER TABLE tenant_data_migrations ADD COLUMN
                    source_writes_since_cutover INTEGER NOT NULL DEFAULT 0"""
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
                "shared_source_purged": 0,
                "finalized_at": None,
            }
        return dict(row)

    def path_for(self, component: str, tenant_scope_id: str) -> Path:
        if component not in TENANT_STORE_FILENAMES:
            raise ValueError(f"Unsupported tenant store component: {component}")
        route = self.route(tenant_scope_id)
        if route["mode"] != "isolated-routing" or not self.component_isolated(
            component, tenant_scope_id, route=route
        ):
            return self.shared_path(component)
        path = (
            self.data_root
            / "tenants"
            / tenant_scope_id
            / "generations"
            / str(route["generation_id"])
            / TENANT_STORE_FILENAMES[component]
        ).resolve()
        self.assert_contained(path)
        if not path.is_file():
            raise RuntimeError(f"The active isolated {component} store is missing; routing failed closed.")
        return path

    def shared_path(self, component: str) -> Path:
        if component not in SHARED_STORE_FILENAMES:
            raise ValueError(f"Unsupported tenant store component: {component}")
        path = (self.data_root / SHARED_STORE_FILENAMES[component]).resolve()
        self.assert_contained(path)
        return path

    def directory_for(self, component: str, tenant_scope_id: str) -> Path:
        """Resolve a tenant-owned file root through the active generation manifest."""
        if component not in TENANT_DIRECTORY_NAMES:
            raise ValueError(f"Unsupported tenant directory component: {component}")
        route = self.route(tenant_scope_id)
        generation = self.directory_generation(component, tenant_scope_id, route=route)
        if not generation:
            path = (self.data_root / TENANT_DIRECTORY_NAMES[component]).resolve()
        else:
            path = (
                self.generation_root(tenant_scope_id, generation)
                / TENANT_DIRECTORY_NAMES[component]
            ).resolve()
        self.assert_contained(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def directory_generation(
        self,
        component: str,
        tenant_scope_id: str,
        *,
        route: dict[str, Any] | None = None,
    ) -> str:
        """Return the storage generation for one file component, including legacy case routing."""
        if component not in TENANT_DIRECTORY_NAMES:
            raise ValueError(f"Unsupported tenant directory component: {component}")
        route = route or self.route(tenant_scope_id)
        if route.get("mode") != "isolated-routing":
            return ""
        if self.component_isolated(component, tenant_scope_id, route=route):
            return str(route.get("generation_id") or "")
        # The original eight-store route already placed case exports beside cases. Preserve
        # that location while an administrator stages an expanded filesystem generation.
        if component == "case-exports" and self.component_isolated(
            "cases", tenant_scope_id, route=route
        ):
            return str(route.get("generation_id") or "")
        return ""

    def register_file(
        self,
        component: str,
        path: Path | str,
        binding: dict[str, Any],
        *,
        source_id: str = "",
        storage_generation_id: str | None = None,
        count_write: bool = True,
    ) -> dict[str, Any]:
        """Bind an app-created file to an immutable tenant/Splunk identity and digest."""
        tenant = _safe_scope(str(binding.get("tenant_scope_id") or ""))
        if component not in TENANT_DIRECTORY_NAMES:
            raise ValueError(f"Unsupported tenant directory component: {component}")
        route = self.route(tenant)
        generation = (
            str(storage_generation_id)
            if storage_generation_id is not None
            else self.directory_generation(component, tenant, route=route)
        )
        root = (
            self.generation_root(tenant, generation) / TENANT_DIRECTORY_NAMES[component]
            if generation
            else self.data_root / TENANT_DIRECTORY_NAMES[component]
        ).resolve()
        candidate = Path(path).resolve()
        self.assert_contained(candidate)
        if candidate == root or root not in candidate.parents or not candidate.is_file():
            raise ValueError("Tenant file is missing or outside its routed component root.")
        relative = candidate.relative_to(root).as_posix()
        digest = self._file_sha256(candidate)
        now = _now()
        with self.connect() as database:
            existing = database.execute(
                """SELECT tenant_scope_id,connection_alias,connection_fingerprint
                FROM tenant_file_manifests
                WHERE component=? AND storage_generation_id=? AND relative_path=?""",
                (component, generation, relative),
            ).fetchone()
            expected_identity = (
                tenant,
                str(binding.get("alias") or "primary"),
                str(binding.get("fingerprint") or ""),
            )
            if existing and tuple(existing) != expected_identity:
                raise ValueError("A tenant file manifest cannot be reassigned to another scope.")
            database.execute(
                """INSERT INTO tenant_file_manifests
                (component,storage_generation_id,relative_path,tenant_scope_id,
                connection_alias,connection_fingerprint,content_sha256,source_id,
                created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(component,storage_generation_id,relative_path) DO UPDATE SET
                tenant_scope_id=excluded.tenant_scope_id,
                connection_alias=excluded.connection_alias,
                connection_fingerprint=excluded.connection_fingerprint,
                content_sha256=excluded.content_sha256,source_id=excluded.source_id,
                updated_at=excluded.updated_at""",
                (
                    component,
                    generation,
                    relative,
                    tenant,
                    str(binding.get("alias") or "primary"),
                    str(binding.get("fingerprint") or ""),
                    digest,
                    str(source_id or ""),
                    now,
                    now,
                ),
            )
        if count_write and route.get("mode") == "isolated-routing" and generation == str(
            route.get("generation_id") or ""
        ):
            self.note_write(tenant)
        return {
            "component": component,
            "storage_generation_id": generation,
            "relative_path": relative,
            "content_sha256": digest,
            "source_id": str(source_id or ""),
        }

    def manifested_files(
        self,
        component: str,
        binding: dict[str, Any],
        *,
        storage_generation_id: str | None = None,
    ) -> list[dict[str, Any]]:
        tenant = _safe_scope(str(binding.get("tenant_scope_id") or ""))
        if component not in TENANT_DIRECTORY_NAMES:
            raise ValueError(f"Unsupported tenant directory component: {component}")
        if storage_generation_id is None:
            route = self.route(tenant)
            generation = self.directory_generation(component, tenant, route=route)
        else:
            generation = str(storage_generation_id)
        with self.connect() as database:
            rows = database.execute(
                """SELECT * FROM tenant_file_manifests
                WHERE component=? AND storage_generation_id=? AND tenant_scope_id=?
                AND connection_alias=? AND connection_fingerprint=?
                ORDER BY relative_path""",
                (
                    component,
                    generation,
                    tenant,
                    str(binding.get("alias") or "primary"),
                    str(binding.get("fingerprint") or ""),
                ),
            ).fetchall()
        return [dict(row) for row in rows]

    def inspect_files(self, component: str, binding: dict[str, Any]) -> dict[str, Any]:
        tenant = _safe_scope(str(binding.get("tenant_scope_id") or ""))
        route = self.route(tenant)
        generation = self.directory_generation(component, tenant, route=route)
        root = self.directory_for(component, tenant)
        files = [
            item
            for item in root.rglob("*")
            if item.is_file() and item.name != ".gitkeep"
        ]
        manifests = self.manifested_files(
            component, binding, storage_generation_id=generation
        )
        by_path = {str(item["relative_path"]): item for item in manifests}
        with self.connect() as database:
            all_rows = database.execute(
                """SELECT relative_path,tenant_scope_id,connection_alias,connection_fingerprint,
                content_sha256 FROM tenant_file_manifests
                WHERE component=? AND storage_generation_id=?""",
                (component, generation),
            ).fetchall()
        all_by_path = {str(item["relative_path"]): dict(item) for item in all_rows}
        tracked = 0
        mismatched = 0
        observed: set[str] = set()
        observed_any: set[str] = set()
        for item in files:
            relative = item.relative_to(root).as_posix()
            if relative in all_by_path:
                observed_any.add(relative)
            manifest = by_path.get(relative)
            if not manifest:
                continue
            observed.add(relative)
            if self._file_sha256(item) == str(manifest["content_sha256"]):
                tracked += 1
            else:
                mismatched += 1
        missing = len(set(by_path) - observed)
        other = len(all_by_path) - len(by_path)
        unbound = max(0, len(files) - len(observed_any)) + missing + mismatched
        return {
            "source_exists": root.is_dir(),
            "schema_observed": True,
            "scope_records": tracked,
            "other_scope_records": other,
            "unbound_records": unbound,
            "integrity_mismatches": mismatched + missing,
            "total_records": len(files),
        }

    def remove_generation_manifests(self, generation_id: str) -> None:
        with self.connect() as database:
            database.execute(
                "DELETE FROM tenant_file_manifests WHERE storage_generation_id=?",
                (generation_id,),
            )

    def reconcile_legacy_files(self, binding: dict[str, Any]) -> dict[str, Any]:
        """Adopt only legacy files whose embedded ownership exactly matches the binding."""
        tenant = _safe_scope(str(binding.get("tenant_scope_id") or ""))
        expected = (
            str(binding.get("alias") or "primary"),
            str(binding.get("fingerprint") or ""),
            tenant,
        )
        adopted = {component: 0 for component in TENANT_DIRECTORY_NAMES}
        examined = {component: 0 for component in TENANT_DIRECTORY_NAMES}

        discovery_root = self.directory_for("discovery-files", tenant)
        known_discovery = self._manifested_relative_paths("discovery-files", tenant)
        for candidate in sorted(discovery_root.glob("*.json")):
            relative = candidate.relative_to(discovery_root).as_posix()
            if relative in known_discovery:
                continue
            examined["discovery-files"] += 1
            payload = self._read_json_object(candidate)
            provenance = payload.get("provenance") if payload else None
            observed = (
                str((provenance or {}).get("connection_alias") or ""),
                str((provenance or {}).get("connection_fingerprint") or ""),
                str((provenance or {}).get("tenant_scope_id") or ""),
            )
            if observed != expected:
                continue
            run_id = str(payload.get("run_id") or "")
            self.register_file("discovery-files", candidate, binding, source_id=run_id)
            known_discovery.add(relative)
            adopted["discovery-files"] += 1
            for name in payload.get("artifacts") or []:
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                    continue
                related = (discovery_root / name).resolve()
                if discovery_root not in related.parents or not related.is_file():
                    continue
                related_relative = related.relative_to(discovery_root).as_posix()
                if related_relative in known_discovery:
                    continue
                self.register_file("discovery-files", related, binding, source_id=run_id)
                known_discovery.add(related_relative)
                adopted["discovery-files"] += 1

        export_root = self.directory_for("case-exports", tenant)
        known_exports = self._manifested_relative_paths("case-exports", tenant)
        for candidate in sorted(export_root.glob("*.json")):
            relative = candidate.relative_to(export_root).as_posix()
            if relative in known_exports:
                continue
            examined["case-exports"] += 1
            payload = self._read_json_object(candidate)
            observed = (
                str(payload.get("connection_alias") or "") if payload else "",
                str(payload.get("connection_fingerprint") or "") if payload else "",
                str(payload.get("tenant_scope_id") or "") if payload else "",
            )
            if observed != expected:
                continue
            case_id = str(payload.get("id") or "")
            self.register_file("case-exports", candidate, binding, source_id=case_id)
            known_exports.add(relative)
            adopted["case-exports"] += 1
            markdown = candidate.with_suffix(".md")
            markdown_relative = markdown.relative_to(export_root).as_posix()
            if (
                markdown.is_file()
                and markdown_relative not in known_exports
                and self._case_markdown_matches(markdown, expected)
            ):
                self.register_file("case-exports", markdown, binding, source_id=case_id)
                known_exports.add(markdown_relative)
                adopted["case-exports"] += 1

        status = {
            component: self.inspect_files(component, binding)
            for component in TENANT_DIRECTORY_NAMES
        }
        return {
            "tenant_scope_id": tenant,
            "connection_alias": expected[0],
            "connection_fingerprint": expected[1],
            "examined_json_files": examined,
            "adopted_files": adopted,
            "adopted_total": sum(adopted.values()),
            "unbound_remaining": sum(
                int(item.get("unbound_records") or 0) for item in status.values()
            ),
            "components": status,
            "contract": {
                "payload_ownership_envelopes_parsed": True,
                "filename_inference_allowed": False,
                "files_moved_or_deleted": False,
                "ambiguous_files_remain_blocked": True,
            },
        }

    def _manifested_relative_paths(self, component: str, tenant_scope_id: str) -> set[str]:
        route = self.route(tenant_scope_id)
        generation = self.directory_generation(component, tenant_scope_id, route=route)
        with self.connect() as database:
            rows = database.execute(
                """SELECT relative_path FROM tenant_file_manifests
                WHERE component=? AND storage_generation_id=?""",
                (component, generation),
            ).fetchall()
        return {str(row["relative_path"]) for row in rows}

    @staticmethod
    def _read_json_object(path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _case_markdown_matches(path: Path, expected: tuple[str, str, str]) -> bool:
        try:
            content = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            return False
        alias, fingerprint, tenant = expected
        return all(
            marker in content
            for marker in (
                f"- Splunk connection: {alias}",
                f"- Tenant scope: `{tenant}`",
                f"- Connection revision: `{fingerprint}`",
            )
        )

    @staticmethod
    def _file_sha256(path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    def component_isolated(
        self,
        component: str,
        tenant_scope_id: str,
        *,
        route: dict[str, Any] | None = None,
    ) -> bool:
        route = route or self.route(tenant_scope_id)
        if route["mode"] != "isolated-routing":
            return False
        with self.connect() as database:
            row = database.execute(
                """SELECT components_json FROM tenant_data_migrations
                WHERE tenant_scope_id=? AND generation_id=? AND status='cutover'
                ORDER BY cutover_at DESC LIMIT 1""",
                (tenant_scope_id, route["generation_id"]),
            ).fetchone()
        if not row:
            raise RuntimeError("The active isolated generation manifest is missing; routing failed closed.")
        try:
            components = json.loads(str(row["components_json"]))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "The active isolated generation manifest is invalid; routing failed closed."
            ) from exc
        return component in {str(item.get("id") or "") for item in components if isinstance(item, dict)}

    def generation_root(self, tenant_scope_id: str, generation_id: str) -> Path:
        _safe_scope(tenant_scope_id)
        if not re.fullmatch(r"[a-f0-9]{32}", generation_id):
            raise ValueError("Tenant generation ID is invalid.")
        path = (self.data_root / "tenants" / tenant_scope_id / "generations" / generation_id).resolve()
        self.assert_contained(path)
        return path

    def reverse_root(self, tenant_scope_id: str, reverse_id: str) -> Path:
        _safe_scope(tenant_scope_id)
        if not re.fullmatch(r"[a-f0-9]{32}", reverse_id):
            raise ValueError("Reverse migration ID is invalid.")
        path = (self.data_root / "tenants" / tenant_scope_id / "reverse" / reverse_id).resolve()
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
        if route["mode"] == "isolated-routing":
            expected = (
                route.get("connection_alias"),
                route.get("connection_fingerprint"),
                route.get("tenant_scope_id"),
            )
            observed = (
                binding["alias"],
                binding["fingerprint"],
                binding["tenant_scope_id"],
            )
            if expected != observed:
                raise ValueError("The active tenant generation belongs to a different Splunk identity.")
        elif route["mode"] != "shared":
            raise ValueError("The tenant data route is not eligible for migration.")
        migration_id = uuid4().hex
        generation_id = uuid4().hex
        now = _now()
        with self.connect() as database:
            pending = database.execute(
                """SELECT id,status FROM tenant_data_migrations WHERE tenant_scope_id=?
                AND status IN ('copying','verified') ORDER BY created_at DESC LIMIT 1""",
                (tenant,),
            ).fetchone()
            if pending:
                raise ValueError(f"Migration {pending['id']} is already {pending['status']} for this tenant.")
            database.execute(
                """INSERT INTO tenant_data_migrations
                (id,tenant_scope_id,connection_alias,connection_fingerprint,plan_id,
                generation_id,source_generation_id,source_writes_since_cutover,status,
                source_digest,target_digest,components_json,error,
                created_by,created_at,verified_at,cutover_at,rolled_back_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,'copying','','','[]','',?,?,NULL,NULL,NULL,?)""",
                (
                    migration_id,
                    tenant,
                    binding["alias"],
                    binding["fingerprint"],
                    plan_id,
                    generation_id,
                    str(route.get("generation_id") or ""),
                    int(route.get("writes_since_cutover") or 0),
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
                "SELECT mode,generation_id FROM tenant_data_routes WHERE tenant_scope_id=?",
                (migration["tenant_scope_id"],),
            ).fetchone()
            expected_source = str(migration.get("source_generation_id") or "")
            if expected_source:
                if (
                    not route
                    or route["mode"] != "isolated-routing"
                    or route["generation_id"] != expected_source
                ):
                    raise ValueError("Tenant routing changed after migration verification.")
            elif route and route["mode"] != "shared":
                raise ValueError("Tenant routing changed after migration verification.")
            database.execute(
                """INSERT INTO tenant_data_routes
                (tenant_scope_id,connection_alias,connection_fingerprint,mode,generation_id,
                writes_since_cutover,shared_source_purged,finalized_at,updated_at)
                VALUES (?,?,?,'isolated-routing',?,0,0,NULL,?)
                ON CONFLICT(tenant_scope_id) DO UPDATE SET
                connection_alias=excluded.connection_alias,
                connection_fingerprint=excluded.connection_fingerprint,
                mode=excluded.mode,generation_id=excluded.generation_id,
                writes_since_cutover=0,shared_source_purged=0,finalized_at=NULL,
                updated_at=excluded.updated_at""",
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
        if int(route.get("shared_source_purged") or 0):
            raise ValueError(
                "Direct rollback is blocked because shared duplicates were finalized. "
                "Apply a verified reverse migration instead."
            )
        if int(route["writes_since_cutover"]):
            raise ValueError(
                "Rollback is blocked because the isolated generation has accepted writes. "
                "A verified reverse migration is required to preserve them."
            )
        now = _now()
        with self.connect() as database:
            source_generation = str(migration.get("source_generation_id") or "")
            if source_generation:
                database.execute(
                    """UPDATE tenant_data_routes SET mode='isolated-routing',generation_id=?,
                    writes_since_cutover=?,updated_at=? WHERE tenant_scope_id=?""",
                    (
                        source_generation,
                        int(migration.get("source_writes_since_cutover") or 0),
                        now,
                        migration["tenant_scope_id"],
                    ),
                )
            else:
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

    def reverse_migrations(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as database:
            rows = database.execute(
                """SELECT * FROM tenant_reverse_migrations
                ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(100, int(limit))),),
            ).fetchall()
        return [self._reverse_migration(row) for row in rows]

    def reverse_migration(self, reverse_id: str) -> dict[str, Any] | None:
        with self.connect() as database:
            row = database.execute(
                "SELECT * FROM tenant_reverse_migrations WHERE id=?", (reverse_id,)
            ).fetchone()
        return self._reverse_migration(row) if row else None

    def begin_reverse(
        self,
        binding: dict[str, str],
        actor: str,
        source_digest: str,
    ) -> dict[str, Any]:
        tenant = _safe_scope(binding["tenant_scope_id"])
        route = self.route(tenant)
        if route.get("mode") != "isolated-routing" or not route.get("generation_id"):
            raise ValueError("A reverse migration requires an active isolated tenant generation.")
        expected = (
            route.get("connection_alias"),
            route.get("connection_fingerprint"),
            route.get("tenant_scope_id"),
        )
        observed = (binding["alias"], binding["fingerprint"], binding["tenant_scope_id"])
        if expected != observed:
            raise ValueError("The active tenant generation belongs to a different Splunk identity.")
        with self.connect() as database:
            forward = database.execute(
                """SELECT id FROM tenant_data_migrations
                WHERE tenant_scope_id=? AND generation_id=? AND status='cutover'
                ORDER BY cutover_at DESC LIMIT 1""",
                (tenant, route["generation_id"]),
            ).fetchone()
            if not forward:
                raise ValueError("The active forward-generation manifest is unavailable.")
            pending = database.execute(
                """SELECT id FROM tenant_reverse_migrations WHERE tenant_scope_id=?
                AND status IN ('copying','applying') ORDER BY created_at DESC LIMIT 1""",
                (tenant,),
            ).fetchone()
            if pending:
                raise ValueError(f"Reverse migration {pending['id']} is already active for this tenant.")
            reverse_id = uuid4().hex
            now = _now()
            database.execute(
                """INSERT INTO tenant_reverse_migrations
                (id,forward_migration_id,tenant_scope_id,connection_alias,
                connection_fingerprint,generation_id,status,resume_status,source_digest,
                shared_baseline_digest,shared_target_digest,pre_finalize_shared_digest,
                components_json,error,created_by,created_at,verified_at,finalized_at,
                applied_at,updated_at)
                VALUES (?,?,?,?,?,?,'copying','',?,'','','','[]','',?,?,NULL,NULL,NULL,?)""",
                (
                    reverse_id,
                    str(forward["id"]),
                    tenant,
                    binding["alias"],
                    binding["fingerprint"],
                    str(route["generation_id"]),
                    source_digest,
                    actor,
                    now,
                    now,
                ),
            )
        result = self.reverse_migration(reverse_id)
        assert result is not None
        return result

    def reverse_verified(
        self,
        reverse_id: str,
        shared_baseline_digest: str,
        shared_target_digest: str,
        components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        reverse = self.reverse_migration(reverse_id)
        if not reverse or reverse["status"] != "copying":
            raise ValueError("Reverse migration is no longer in the copy phase.")
        route = self.route(reverse["tenant_scope_id"])
        status = "finalized-ready" if int(route.get("shared_source_purged") or 0) else "verified"
        now = _now()
        with self.connect() as database:
            result = database.execute(
                """UPDATE tenant_reverse_migrations SET status=?,shared_baseline_digest=?,
                shared_target_digest=?,components_json=?,verified_at=?,updated_at=?
                WHERE id=? AND status='copying'""",
                (
                    status,
                    shared_baseline_digest,
                    shared_target_digest,
                    json.dumps(components, sort_keys=True),
                    now,
                    now,
                    reverse_id,
                ),
            )
            if not result.rowcount:
                raise ValueError("Reverse migration state changed before verification.")
            database.execute(
                """UPDATE tenant_reverse_migrations SET status='superseded',updated_at=?
                WHERE tenant_scope_id=? AND id<>?
                AND status IN ('verified','finalized-ready')""",
                (now, reverse["tenant_scope_id"], reverse_id),
            )
        result = self.reverse_migration(reverse_id)
        assert result is not None
        return result

    def reverse_failed(self, reverse_id: str, error: str) -> None:
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_reverse_migrations SET status='failed',error=?,updated_at=?
                WHERE id=? AND status='copying'""",
                (error[:2000], _now(), reverse_id),
            )

    def reverse_finalized(
        self,
        reverse_id: str,
        pre_finalize_shared_digest: str,
        shared_baseline_digest: str,
        components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        reverse = self.reverse_migration(reverse_id)
        if not reverse or reverse["status"] != "verified":
            raise ValueError("Only a verified reverse path can authorize finalization.")
        now = _now()
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_reverse_migrations SET status='finalized-ready',
                pre_finalize_shared_digest=?,
                shared_baseline_digest=?,components_json=?,finalized_at=?,updated_at=?
                WHERE id=? AND status='verified'""",
                (
                    pre_finalize_shared_digest,
                    shared_baseline_digest,
                    json.dumps(components, sort_keys=True),
                    now,
                    now,
                    reverse_id,
                ),
            )
            database.execute(
                """UPDATE tenant_data_routes SET shared_source_purged=1,finalized_at=?,updated_at=?
                WHERE tenant_scope_id=? AND mode='isolated-routing' AND generation_id=?""",
                (now, now, reverse["tenant_scope_id"], reverse["generation_id"]),
            )
        result = self.reverse_migration(reverse_id)
        assert result is not None
        return result

    def begin_reverse_apply(self, reverse_id: str) -> tuple[dict[str, Any], str]:
        reverse = self.reverse_migration(reverse_id)
        if not reverse or reverse["status"] not in {"verified", "finalized-ready"}:
            raise ValueError("Only a verified reverse migration can be applied.")
        prior_status = str(reverse["status"])
        with self.connect() as database:
            result = database.execute(
                """UPDATE tenant_reverse_migrations SET status='applying',resume_status=?,
                error='',updated_at=?
                WHERE id=? AND status=?""",
                (prior_status, _now(), reverse_id, prior_status),
            )
            if not result.rowcount:
                raise ValueError("Reverse migration state changed before apply.")
        applying = self.reverse_migration(reverse_id)
        assert applying is not None
        return applying, prior_status

    def reverse_apply_failed(self, reverse_id: str, prior_status: str, error: str) -> None:
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_reverse_migrations SET status=?,resume_status='',error=?,updated_at=?
                WHERE id=? AND status='applying'""",
                (prior_status, error[:2000], _now(), reverse_id),
            )

    def reverse_applied(self, reverse_id: str) -> dict[str, Any]:
        reverse = self.reverse_migration(reverse_id)
        if not reverse or reverse["status"] != "applying":
            raise ValueError("Reverse migration is not in the apply phase.")
        route = self.route(reverse["tenant_scope_id"])
        if route.get("mode") != "isolated-routing" or route.get("generation_id") != reverse[
            "generation_id"
        ]:
            raise ValueError("Tenant routing changed during reverse migration.")
        now = _now()
        with self.connect() as database:
            database.execute(
                """UPDATE tenant_data_routes SET mode='shared',generation_id='',
                writes_since_cutover=0,shared_source_purged=0,finalized_at=NULL,updated_at=?
                WHERE tenant_scope_id=?""",
                (now, reverse["tenant_scope_id"]),
            )
            database.execute(
                """UPDATE tenant_data_migrations SET status='reverse-migrated',updated_at=?
                WHERE id=? AND status='cutover'""",
                (now, reverse["forward_migration_id"]),
            )
            database.execute(
                """UPDATE tenant_reverse_migrations SET status='applied',resume_status='',
                applied_at=?,updated_at=?
                WHERE id=? AND status='applying'""",
                (now, now, reverse_id),
            )
        result = self.reverse_migration(reverse_id)
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
            item["shared_source_purged"] = bool(item.get("shared_source_purged"))
            item["source_retained_for_rollback"] = (
                item["mode"] == "isolated-routing" and not item["shared_source_purged"]
            )
            item["physical_source_purge_complete"] = item["shared_source_purged"]
        return {
            "routes": routes,
            "migrations": self.migrations(),
            "reverse_migrations": self.reverse_migrations(),
            "contract": {
                "components": list(TENANT_DATA_COMPONENTS),
                "cutover_requires_exact_source_digest": True,
                "rollback_requires_zero_post_cutover_writes": True,
                "reverse_migration_requires_exact_digests": True,
                "source_retained_until_explicit_finalization": True,
                "physical_source_purge_available": True,
            },
        }

    @staticmethod
    def _migration(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["components"] = json.loads(str(value.pop("components_json")))
        value["migration_executable"] = value["status"] == "verified"
        value["rollback_available"] = value["status"] == "cutover"
        return value

    @staticmethod
    def _reverse_migration(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["components"] = json.loads(str(value.pop("components_json")))
        value["apply_available"] = value["status"] in {"verified", "finalized-ready"}
        value["finalization_available"] = value["status"] == "verified"
        return value


class TenantDataMigrationService:
    """Copy and verify tenant data before changing the runtime route."""

    COMPONENTS = TENANT_DATA_COMPONENTS

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
                results = [self._copy_component(component, binding, root) for component in self.COMPONENTS]
                source_digest = self._aggregate_digest(results, "source_digest")
                target_digest = self._aggregate_digest(results, "target_digest")
                if source_digest != target_digest:
                    raise ValueError("Tenant copy digest verification failed.")
                return self.registry.verified(migration["id"], source_digest, target_digest, results)
            except Exception as exc:
                self.registry.failed(migration["id"], str(exc))
                self.registry.remove_generation_manifests(migration["generation_id"])
                if root.exists():
                    shutil.rmtree(root)
                raise

    def cutover(self, migration_id: str, binding: dict[str, str]) -> dict[str, Any]:
        with self.registry.operation_lock:
            migration = self._bound_migration(migration_id, binding, "verified")
            self._assert_no_active_discovery(binding["tenant_scope_id"])
            root = self.registry.generation_root(binding["tenant_scope_id"], migration["generation_id"])
            current = [
                self._component_digest(component, binding, root=None)
                for component in self.COMPONENTS
            ]
            target = [
                self._component_digest(component, binding, root=root)
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

    def stage_reverse(self, binding: dict[str, str], actor: str) -> dict[str, Any]:
        """Build a verified shared-data snapshot without changing the active isolated route."""
        with self.registry.operation_lock:
            route = self._bound_isolated_route(binding)
            self._assert_full_generation(binding["tenant_scope_id"], route)
            self._assert_no_active_discovery(binding["tenant_scope_id"])
            source = [
                self._component_digest(component, binding, root=None)
                for component in self.COMPONENTS
            ]
            source_digest = self._aggregate_digest(source, "digest")
            reverse = self.registry.begin_reverse(binding, actor, source_digest)
            root = self.registry.reverse_root(binding["tenant_scope_id"], reverse["id"])
            try:
                if root.exists():
                    raise ValueError("The reverse-migration staging path already exists.")
                (root / "shared").mkdir(parents=True)
                results = [
                    self._stage_reverse_component(component, binding, root)
                    for component in self.COMPONENTS
                ]
                observed_source = self._aggregate_digest(results, "source_digest")
                if observed_source != source_digest:
                    raise ValueError("The isolated tenant generation changed during reverse staging.")
                shared_baseline = self._aggregate_digest(results, "shared_baseline_digest")
                shared_target = self._aggregate_digest(results, "shared_target_digest")
                return self.registry.reverse_verified(
                    reverse["id"], shared_baseline, shared_target, results
                )
            except Exception as exc:
                self.registry.reverse_failed(reverse["id"], str(exc))
                if root.exists():
                    shutil.rmtree(root)
                raise

    def apply_reverse(
        self,
        reverse_id: str,
        binding: dict[str, str],
        expected_source_digest: str,
        expected_shared_target_digest: str,
    ) -> dict[str, Any]:
        """Restore shared routing from a verified, unchanged reverse snapshot."""
        with self.registry.operation_lock:
            reverse = self._bound_reverse(reverse_id, binding, {"verified", "finalized-ready"})
            self._assert_reverse_confirmation(
                reverse, expected_source_digest, expected_shared_target_digest
            )
            route = self._bound_isolated_route(binding)
            if route["generation_id"] != reverse["generation_id"]:
                raise ValueError("The active generation changed after reverse verification.")
            self._assert_no_active_discovery(binding["tenant_scope_id"])
            self._assert_reverse_source(reverse, binding)
            self._assert_shared_components_match(reverse, binding, allow_target=True)
            applying, prior_status = self.registry.begin_reverse_apply(reverse_id)
            try:
                root = self.registry.reverse_root(binding["tenant_scope_id"], reverse_id)
                for component in applying["components"]:
                    self._apply_reverse_component(component, binding, root)
                self._assert_shared_target(applying, binding)
                return self.registry.reverse_applied(reverse_id)
            except Exception as exc:
                self.registry.reverse_apply_failed(reverse_id, prior_status, str(exc))
                raise

    def finalize_shared_source(
        self,
        reverse_id: str,
        binding: dict[str, str],
        expected_source_digest: str,
        expected_shared_target_digest: str,
    ) -> dict[str, Any]:
        """Remove stale shared duplicates only after proving an exact reverse path."""
        with self.registry.operation_lock:
            reverse = self._bound_reverse(reverse_id, binding, {"verified"})
            self._assert_reverse_confirmation(
                reverse, expected_source_digest, expected_shared_target_digest
            )
            route = self._bound_isolated_route(binding)
            if route["generation_id"] != reverse["generation_id"]:
                raise ValueError("The active generation changed after reverse verification.")
            if int(route.get("shared_source_purged") or 0):
                raise ValueError("Shared duplicates are already finalized for this tenant.")
            self._assert_no_active_discovery(binding["tenant_scope_id"])
            self._assert_reverse_source(reverse, binding)
            self._assert_shared_components_match(reverse, binding, allow_purged=True)
            updated: list[dict[str, Any]] = []
            for component in reverse["components"]:
                self._purge_shared_component(component, binding)
                value = dict(component)
                value["pre_finalize_shared_digest"] = value["shared_baseline_digest"]
                value["shared_baseline_digest"] = value["shared_purged_digest"]
                updated.append(value)
            purged_digest = self._aggregate_digest(updated, "shared_baseline_digest")
            self._assert_shared_component_values(updated, binding, "shared_baseline_digest")
            return self.registry.reverse_finalized(
                reverse_id,
                reverse["shared_baseline_digest"],
                purged_digest,
                updated,
            )

    def _bound_isolated_route(self, binding: dict[str, str]) -> dict[str, Any]:
        route = self.registry.route(binding["tenant_scope_id"])
        expected = (
            route.get("connection_alias"),
            route.get("connection_fingerprint"),
            route.get("tenant_scope_id"),
        )
        observed = (binding["alias"], binding["fingerprint"], binding["tenant_scope_id"])
        if route.get("mode") != "isolated-routing" or expected != observed:
            raise ValueError("No matching isolated tenant generation is active.")
        return route

    def _assert_full_generation(
        self, tenant_scope_id: str, route: dict[str, Any]
    ) -> None:
        missing = [
            component
            for component in self.COMPONENTS
            if not self.registry.component_isolated(component, tenant_scope_id, route=route)
        ]
        if missing:
            raise ValueError(
                "Reverse migration requires a complete ten-component generation; missing: "
                + ", ".join(missing)
            )

    def _bound_reverse(
        self,
        reverse_id: str,
        binding: dict[str, str],
        statuses: set[str],
    ) -> dict[str, Any]:
        reverse = self.registry.reverse_migration(reverse_id)
        if not reverse or reverse["status"] not in statuses:
            raise ValueError("Reverse migration is not in an eligible verified state.")
        expected = (
            reverse["connection_alias"],
            reverse["connection_fingerprint"],
            reverse["tenant_scope_id"],
        )
        observed = (binding["alias"], binding["fingerprint"], binding["tenant_scope_id"])
        if expected != observed:
            raise ValueError("Reverse migration is bound to a different immutable Splunk scope.")
        return reverse

    @staticmethod
    def _assert_reverse_confirmation(
        reverse: dict[str, Any],
        expected_source_digest: str,
        expected_shared_target_digest: str,
    ) -> None:
        if (
            reverse["source_digest"] != expected_source_digest
            or reverse["shared_target_digest"] != expected_shared_target_digest
        ):
            raise ValueError("Reverse migration digest confirmation does not match the verified plan.")

    def _assert_reverse_source(
        self, reverse: dict[str, Any], binding: dict[str, str]
    ) -> None:
        current = [
            self._component_digest(component, binding, root=None)
            for component in self.COMPONENTS
        ]
        if self._aggregate_digest(current, "digest") != reverse["source_digest"]:
            raise ValueError(
                "The isolated tenant generation changed after reverse staging. Build a fresh path."
            )

    def _assert_shared_components_match(
        self,
        reverse: dict[str, Any],
        binding: dict[str, str],
        *,
        allow_target: bool = False,
        allow_purged: bool = False,
    ) -> None:
        for component in reverse["components"]:
            current = self._shared_component_digest(component, binding)
            admitted = {str(component["shared_baseline_digest"])}
            if allow_target:
                admitted.add(str(component["shared_target_digest"]))
            if allow_purged:
                admitted.add(str(component["shared_purged_digest"]))
            if current not in admitted:
                raise ValueError(
                    f"Shared {component['id']} changed after reverse staging. Build a fresh path."
                )

    def _assert_shared_target(
        self, reverse: dict[str, Any], binding: dict[str, str]
    ) -> None:
        self._assert_shared_component_values(reverse["components"], binding, "shared_target_digest")
        current = [
            {"id": item["id"], "digest": self._shared_component_digest(item, binding)}
            for item in reverse["components"]
        ]
        if self._aggregate_digest(current, "digest") != reverse["shared_target_digest"]:
            raise ValueError("The restored shared target does not match its verified digest.")

    def _assert_shared_component_values(
        self,
        components: list[dict[str, Any]],
        binding: dict[str, str],
        key: str,
    ) -> None:
        for component in components:
            if self._shared_component_digest(component, binding) != component[key]:
                raise ValueError(f"Shared {component['id']} does not match {key}.")

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
        active_checks = (
            (
                "manual-discovery",
                "discovery_jobs",
                "id",
                ("queued", "running"),
                "Manual discovery job",
            ),
            (
                "validations",
                "validation_tasks",
                "id",
                ("running",),
                "Validation task",
            ),
            (
                "assurance-responses",
                "assurance_runs",
                "id",
                ("queued", "running"),
                "Assurance run",
            ),
            (
                "outbound-delivery",
                "delivery_jobs",
                "id",
                ("queued", "retrying", "sending"),
                "Delivery job",
            ),
        )
        for component, table, id_column, statuses, label in active_checks:
            path = self.registry.path_for(component, tenant_scope_id)
            if not path.is_file():
                continue
            placeholders = ",".join("?" for _ in statuses)
            with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as database:
                row = database.execute(
                    f"SELECT {id_column} FROM {table} WHERE tenant_scope_id=? "
                    f"AND status IN ({placeholders}) ORDER BY rowid LIMIT 1",
                    (tenant_scope_id, *statuses),
                ).fetchone()
            if row:
                raise ValueError(f"{label} {row[0]} must finish or be cancelled before migration.")

    def _stage_reverse_component(
        self,
        component: str,
        binding: dict[str, str],
        root: Path,
    ) -> dict[str, Any]:
        if component in TENANT_DIRECTORY_NAMES:
            return self._stage_reverse_directory(component, binding, root)
        return self._stage_reverse_database(component, binding, root)

    def _stage_reverse_database(
        self,
        component: str,
        binding: dict[str, str],
        root: Path,
    ) -> dict[str, Any]:
        tenant = binding["tenant_scope_id"]
        source = self.registry.path_for(component, tenant)
        shared = self.registry.shared_path(component)
        target = root / "shared" / SHARED_STORE_FILENAMES[component]
        if not source.is_file() or not shared.is_file():
            raise ValueError(f"Reverse migration requires both isolated and shared {component} stores.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(shared)) as source_db, closing(
            sqlite3.connect(target)
        ) as target_db:
            source_db.backup(target_db)
        baseline_digest = self._database_logical_digest(target)
        queries = self._queries(component, tenant)
        with closing(sqlite3.connect(source)) as source_db, closing(
            sqlite3.connect(target)
        ) as target_db:
            source_db.row_factory = sqlite3.Row
            target_db.execute("BEGIN IMMEDIATE")
            self._delete_tenant_rows(target_db, queries)
            target_db.commit()
        purged_digest = self._database_logical_digest(target)
        counts: dict[str, int] = {}
        with closing(sqlite3.connect(source)) as source_db, closing(
            sqlite3.connect(target)
        ) as target_db:
            source_db.row_factory = sqlite3.Row
            source_db.execute("BEGIN")
            target_db.execute("BEGIN IMMEDIATE")
            sink = hashlib.sha256()
            for table, sql, params in queries:
                counts[table] = self._copy_rows(
                    source_db, target_db, table, sql, params, sink
                )
            target_db.commit()
        source_digest = self._digest_path(source, queries)
        target_tenant_digest = self._digest_path(target, queries)
        if source_digest != target_tenant_digest:
            raise ValueError(f"Reverse {component} tenant digest verification failed.")
        return {
            "id": component,
            "kind": "sqlite",
            "source_records": sum(counts.values()),
            "tables": counts,
            "source_digest": source_digest,
            "shared_baseline_digest": baseline_digest,
            "shared_purged_digest": purged_digest,
            "shared_target_digest": self._database_logical_digest(target),
            "target_tenant_digest": target_tenant_digest,
            "verified": True,
        }

    def _stage_reverse_directory(
        self,
        component: str,
        binding: dict[str, str],
        root: Path,
    ) -> dict[str, Any]:
        tenant = binding["tenant_scope_id"]
        route = self.registry.route(tenant)
        generation = self.registry.directory_generation(component, tenant, route=route)
        if generation != route.get("generation_id"):
            raise ValueError(f"The active generation does not isolate {component}.")
        source_root = self.registry.directory_for(component, tenant)
        shared_root = (self.registry.data_root / TENANT_DIRECTORY_NAMES[component]).resolve()
        target_root = root / "shared" / TENANT_DIRECTORY_NAMES[component]
        target_root.mkdir(parents=True, exist_ok=True)
        manifests = self.registry.manifested_files(
            component, binding, storage_generation_id=generation
        )
        identity: list[dict[str, str]] = []
        files: list[dict[str, str]] = []
        for manifest in manifests:
            relative = Path(str(manifest["relative_path"]))
            source = (source_root / relative).resolve()
            target = (target_root / relative).resolve()
            shared_candidate = (shared_root / relative).resolve()
            if (
                source_root not in source.parents
                or target_root not in target.parents
                or shared_root not in shared_candidate.parents
            ):
                raise ValueError(f"Unsafe reverse {component} path: {relative.as_posix()}")
            digest = self.registry._file_sha256(source) if source.is_file() else ""
            if digest != str(manifest["content_sha256"]):
                raise ValueError(f"The isolated {component} file changed: {relative.as_posix()}")
            self._assert_shared_file_admissible(component, relative.as_posix(), binding)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if self.registry._file_sha256(target) != digest:
                raise ValueError(f"The staged reverse {component} file changed during copy.")
            identity.append({"path": relative.as_posix(), "sha256": digest})
            files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": digest,
                    "source_id": str(manifest.get("source_id") or ""),
                }
            )
        source_digest = self._digest_file_identity(identity)
        return {
            "id": component,
            "kind": "filesystem",
            "source_records": len(files),
            "files": files,
            "source_digest": source_digest,
            "shared_baseline_digest": self._shared_directory_digest(component, binding),
            "shared_purged_digest": self._digest_file_identity([]),
            "shared_target_digest": source_digest,
            "target_tenant_digest": source_digest,
            "verified": True,
        }

    def _assert_shared_file_admissible(
        self,
        component: str,
        relative_path: str,
        binding: dict[str, str],
    ) -> None:
        shared_root = (self.registry.data_root / TENANT_DIRECTORY_NAMES[component]).resolve()
        candidate = (shared_root / relative_path).resolve()
        with self.registry.connect() as database:
            row = database.execute(
                """SELECT tenant_scope_id,connection_alias,connection_fingerprint
                FROM tenant_file_manifests WHERE component=?
                AND storage_generation_id='' AND relative_path=?""",
                (component, relative_path),
            ).fetchone()
        expected = (
            binding["tenant_scope_id"], binding["alias"], binding["fingerprint"]
        )
        if row and tuple(row) != expected:
            raise ValueError(f"Shared {component} path belongs to another tenant.")
        if candidate.is_file() and not row:
            raise ValueError(
                f"Shared {component} path is unmanifested and cannot be overwritten: {relative_path}"
            )

    def _apply_reverse_component(
        self,
        component: dict[str, Any],
        binding: dict[str, str],
        root: Path,
    ) -> None:
        current = self._shared_component_digest(component, binding)
        if current == component["shared_target_digest"]:
            return
        if current != component["shared_baseline_digest"]:
            raise ValueError(f"Shared {component['id']} changed before reverse apply.")
        if component["kind"] == "filesystem":
            self._apply_reverse_directory(component, binding, root)
        else:
            target = root / "shared" / SHARED_STORE_FILENAMES[component["id"]]
            shared = self.registry.shared_path(component["id"])
            if self._database_logical_digest(target) != component["shared_target_digest"]:
                raise ValueError(f"The staged reverse {component['id']} database changed.")
            # SQLite's backup API replaces the destination as one database
            # transaction and remains portable when Windows processes retain a
            # handle to the shared database file. A filesystem rename cannot
            # provide that guarantee on Windows.
            with closing(sqlite3.connect(target)) as source_db, closing(
                sqlite3.connect(shared)
            ) as shared_db:
                source_db.backup(shared_db)
        if self._shared_component_digest(component, binding) != component["shared_target_digest"]:
            raise ValueError(f"Shared {component['id']} failed post-apply verification.")

    def _apply_reverse_directory(
        self,
        component: dict[str, Any],
        binding: dict[str, str],
        root: Path,
    ) -> None:
        component_id = str(component["id"])
        shared_root = (self.registry.data_root / TENANT_DIRECTORY_NAMES[component_id]).resolve()
        staged_root = root / "shared" / TENANT_DIRECTORY_NAMES[component_id]
        target_paths = {str(item["path"]) for item in component.get("files", [])}
        existing = self.registry.manifested_files(
            component_id, binding, storage_generation_id=""
        )
        for manifest in existing:
            relative = str(manifest["relative_path"])
            if relative in target_paths:
                continue
            candidate = (shared_root / relative).resolve()
            if shared_root not in candidate.parents:
                raise ValueError(f"Unsafe shared {component_id} manifest path.")
            if not candidate.is_file() or self.registry._file_sha256(candidate) != manifest[
                "content_sha256"
            ]:
                raise ValueError(f"Shared {component_id} changed before reverse apply.")
            candidate.unlink()
            self._delete_file_manifest(component_id, "", relative, binding)
        for item in component.get("files", []):
            relative = str(item["path"])
            self._assert_shared_file_admissible(component_id, relative, binding)
            staged = (staged_root / relative).resolve()
            target = (shared_root / relative).resolve()
            if staged_root not in staged.parents or shared_root not in target.parents:
                raise ValueError(f"Unsafe staged {component_id} reverse path.")
            if not staged.is_file() or self.registry._file_sha256(staged) != item["sha256"]:
                raise ValueError(f"The staged reverse {component_id} file changed.")
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.{uuid4().hex}.reverse.tmp")
            try:
                shutil.copy2(staged, temporary)
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    temporary.unlink()
            self.registry.register_file(
                component_id,
                target,
                binding,
                source_id=str(item.get("source_id") or ""),
                storage_generation_id="",
                count_write=False,
            )

    def _purge_shared_component(
        self,
        component: dict[str, Any],
        binding: dict[str, str],
    ) -> None:
        current = self._shared_component_digest(component, binding)
        if current == component["shared_purged_digest"]:
            return
        if current != component["shared_baseline_digest"]:
            raise ValueError(f"Shared {component['id']} changed before finalization.")
        if component["kind"] == "filesystem":
            self._purge_shared_directory(str(component["id"]), binding)
        else:
            path = self.registry.shared_path(str(component["id"]))
            with closing(sqlite3.connect(path)) as database:
                database.execute("BEGIN IMMEDIATE")
                self._delete_tenant_rows(
                    database,
                    self._queries(str(component["id"]), binding["tenant_scope_id"]),
                )
                database.commit()
        if self._shared_component_digest(component, binding) != component[
            "shared_purged_digest"
        ]:
            raise ValueError(f"Shared {component['id']} failed finalization verification.")

    def _purge_shared_directory(
        self, component: str, binding: dict[str, str]
    ) -> None:
        root = (self.registry.data_root / TENANT_DIRECTORY_NAMES[component]).resolve()
        manifests = self.registry.manifested_files(
            component, binding, storage_generation_id=""
        )
        for manifest in manifests:
            relative = str(manifest["relative_path"])
            candidate = (root / relative).resolve()
            if root not in candidate.parents:
                raise ValueError(f"Unsafe shared {component} manifest path.")
            if not candidate.is_file() or self.registry._file_sha256(candidate) != manifest[
                "content_sha256"
            ]:
                raise ValueError(f"Shared {component} changed before finalization.")
            candidate.unlink()
            self._delete_file_manifest(component, "", relative, binding)

    def _delete_file_manifest(
        self,
        component: str,
        generation: str,
        relative: str,
        binding: dict[str, str],
    ) -> None:
        with self.registry.connect() as database:
            result = database.execute(
                """DELETE FROM tenant_file_manifests WHERE component=?
                AND storage_generation_id=? AND relative_path=? AND tenant_scope_id=?
                AND connection_alias=? AND connection_fingerprint=?""",
                (
                    component,
                    generation,
                    relative,
                    binding["tenant_scope_id"],
                    binding["alias"],
                    binding["fingerprint"],
                ),
            )
            if not result.rowcount:
                raise ValueError(f"Shared {component} ownership manifest changed.")

    def _shared_component_digest(
        self,
        component: dict[str, Any],
        binding: dict[str, str],
    ) -> str:
        component_id = str(component["id"])
        if component.get("kind") == "filesystem" or component_id in TENANT_DIRECTORY_NAMES:
            return self._shared_directory_digest(component_id, binding)
        return self._database_logical_digest(self.registry.shared_path(component_id))

    def _shared_directory_digest(
        self,
        component: str,
        binding: dict[str, str],
    ) -> str:
        return self._directory_digest(
            component,
            binding,
            self.registry.data_root,
            "",
        )

    @classmethod
    def _database_logical_digest(cls, path: Path) -> str:
        if not path.is_file():
            raise ValueError(f"Shared database is missing: {path.name}")
        hasher = hashlib.sha256()
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as database:
            database.row_factory = sqlite3.Row
            database.execute("BEGIN")
            tables = database.execute(
                """SELECT name,COALESCE(sql,'') sql FROM sqlite_master
                WHERE type='table' AND (name NOT LIKE 'sqlite_%' OR name='sqlite_sequence')
                ORDER BY name"""
            ).fetchall()
            for table in tables:
                name = str(table["name"])
                quoted = name.replace('"', '""')
                hasher.update(f"table:{name}\nschema:{table['sql']}\n".encode())
                try:
                    cursor = database.execute(f'SELECT * FROM "{quoted}" ORDER BY rowid')
                    rows = cursor.fetchall()
                except sqlite3.OperationalError:
                    cursor = database.execute(f'SELECT * FROM "{quoted}"')
                    rows = sorted(
                        cursor.fetchall(),
                        key=lambda row: json.dumps(tuple(row), default=str),
                    )
                columns = [str(item[0]) for item in cursor.description or []]
                hasher.update(json.dumps(columns, separators=(",", ":")).encode())
                hasher.update(b"\n")
                for row in rows:
                    hasher.update(
                        json.dumps(tuple(row), separators=(",", ":"), default=str).encode()
                    )
                    hasher.update(b"\n")
        return hasher.hexdigest()

    @staticmethod
    def _delete_tenant_rows(
        database: sqlite3.Connection,
        queries: list[tuple[str, str, tuple[Any, ...]]],
    ) -> None:
        for table, sql, params in reversed(queries):
            where_at = sql.find(" WHERE ")
            order_at = sql.rfind(" ORDER BY ")
            if where_at < 0 or order_at < where_at:
                raise ValueError(f"Tenant delete contract is invalid for {table}.")
            predicate = sql[where_at:order_at]
            database.execute(f'DELETE FROM "{table}"{predicate}', params)

    def _copy_component(
        self, component: str, binding: dict[str, str], root: Path
    ) -> dict[str, Any]:
        if component in TENANT_DIRECTORY_NAMES:
            return self._copy_directory(component, binding, root)
        tenant_scope_id = binding["tenant_scope_id"]
        source = self.registry.path_for(component, tenant_scope_id)
        target = root / TENANT_STORE_FILENAMES[component]
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
        elif component == "manual-discovery":
            DiscoveryJobStore(target)
        elif component == "validations":
            ValidationStore(target)
        elif component == "detections":
            DetectionStore(target)
        elif component == "forecast-experiments":
            TimeSeriesExperimentStore(target)
        elif component == "assurance-responses":
            AssuranceStore(target)
        elif component == "outbound-delivery":
            DeliveryStore(target)
        else:
            raise ValueError(f"Unsupported tenant store component: {component}")

    def _component_digest(
        self, component: str, binding: dict[str, str], root: Path | None
    ) -> dict[str, Any]:
        if component in TENANT_DIRECTORY_NAMES:
            generation = root.name if root else None
            return {
                "id": component,
                "digest": self._directory_digest(component, binding, root, generation),
            }
        tenant_scope_id = binding["tenant_scope_id"]
        path = (
            root / TENANT_STORE_FILENAMES[component]
            if root
            else self.registry.path_for(component, tenant_scope_id)
        )
        return {
            "id": component,
            "digest": self._digest_path(path, self._queries(component, tenant_scope_id)),
        }

    def _copy_directory(
        self, component: str, binding: dict[str, str], root: Path
    ) -> dict[str, Any]:
        tenant = binding["tenant_scope_id"]
        route = self.registry.route(tenant)
        source_generation = self.registry.directory_generation(
            component, tenant, route=route
        )
        source_root = self.registry.directory_for(component, tenant)
        target_root = root / TENANT_DIRECTORY_NAMES[component]
        target_root.mkdir(parents=True, exist_ok=True)
        if any(item.is_file() for item in target_root.rglob("*")):
            raise ValueError(f"Target {component} directory is not empty.")
        manifests = self.registry.manifested_files(
            component, binding, storage_generation_id=source_generation
        )
        source_identity: list[dict[str, str]] = []
        for manifest in manifests:
            relative = Path(str(manifest["relative_path"]))
            source = (source_root / relative).resolve()
            target = (target_root / relative).resolve()
            if source_root not in source.parents or target_root not in target.parents:
                raise ValueError(f"Unsafe {component} manifest path: {relative.as_posix()}")
            if not source.is_file() or self.registry._file_sha256(source) != manifest["content_sha256"]:
                raise ValueError(f"The manifested {component} file changed: {relative.as_posix()}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            entry = self.registry.register_file(
                component,
                target,
                binding,
                source_id=str(manifest.get("source_id") or ""),
                storage_generation_id=root.name,
                count_write=False,
            )
            source_identity.append(
                {"path": str(manifest["relative_path"]), "sha256": str(manifest["content_sha256"])}
            )
            if entry["content_sha256"] != manifest["content_sha256"]:
                raise ValueError(f"The copied {component} digest changed: {relative.as_posix()}")
        digest = self._digest_file_identity(source_identity)
        target_digest = self._directory_digest(component, binding, root, root.name)
        return {
            "id": component,
            "source_records": len(manifests),
            "target_records": len(manifests),
            "files": source_identity,
            "source_digest": digest,
            "target_digest": target_digest,
            "verified": digest == target_digest,
        }

    def _directory_digest(
        self,
        component: str,
        binding: dict[str, str],
        root: Path | None,
        generation: str | None,
    ) -> str:
        tenant = binding["tenant_scope_id"]
        route = self.registry.route(tenant)
        storage_generation = (
            str(generation)
            if generation is not None
            else self.registry.directory_generation(component, tenant, route=route)
        )
        directory = (
            root / TENANT_DIRECTORY_NAMES[component]
            if root
            else self.registry.directory_for(component, tenant)
        ).resolve()
        identity: list[dict[str, str]] = []
        for manifest in self.registry.manifested_files(
            component, binding, storage_generation_id=storage_generation
        ):
            candidate = (directory / str(manifest["relative_path"])).resolve()
            if directory not in candidate.parents or not candidate.is_file():
                raise ValueError(f"A manifested {component} file is missing.")
            identity.append(
                {
                    "path": str(manifest["relative_path"]),
                    "sha256": self.registry._file_sha256(candidate),
                }
            )
        return self._digest_file_identity(identity)

    @staticmethod
    def _digest_file_identity(identity: list[dict[str, str]]) -> str:
        return hashlib.sha256(
            json.dumps(sorted(identity, key=lambda item: item["path"]), separators=(",", ":")).encode()
        ).hexdigest()

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
        if component == "manual-discovery":
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
        if component == "validations":
            return [
                (
                    "validation_tasks",
                    "SELECT * FROM validation_tasks WHERE tenant_scope_id=? ORDER BY id",
                    (tenant_scope_id,),
                )
            ]
        if component == "detections":
            root = "SELECT id FROM detections WHERE tenant_scope_id=?"
            return [
                (
                    "detections",
                    "SELECT * FROM detections WHERE tenant_scope_id=? ORDER BY id",
                    (tenant_scope_id,),
                ),
                *[
                    (
                        table,
                        f"SELECT * FROM {table} WHERE detection_id IN ({root}) ORDER BY id",
                        (tenant_scope_id,),
                    )
                    for table in (
                        "detection_versions",
                        "detection_reviews",
                        "detection_exports",
                        "detection_gate_runs",
                    )
                ],
            ]
        if component == "forecast-experiments":
            root = "SELECT id FROM time_series_runs WHERE tenant_scope_id=?"
            return [
                (
                    "time_series_runs",
                    "SELECT * FROM time_series_runs WHERE tenant_scope_id=? ORDER BY id",
                    (tenant_scope_id,),
                ),
                (
                    "time_series_alert_candidates",
                    f"SELECT * FROM time_series_alert_candidates WHERE run_id IN ({root}) ORDER BY id",
                    (tenant_scope_id,),
                ),
                (
                    "time_series_baselines",
                    f"SELECT * FROM time_series_baselines WHERE run_id IN ({root}) ORDER BY series_key,slot",
                    (tenant_scope_id,),
                ),
            ]
        if component == "assurance-responses":
            return [
                (
                    "assurance_signals",
                    "SELECT * FROM assurance_signals WHERE tenant_scope_id=? ORDER BY fingerprint",
                    (tenant_scope_id,),
                ),
                (
                    "assurance_packages",
                    "SELECT * FROM assurance_packages WHERE tenant_scope_id=? ORDER BY id",
                    (tenant_scope_id,),
                ),
            ]
        if component == "outbound-delivery":
            root = "SELECT id FROM delivery_jobs WHERE tenant_scope_id=?"
            return [
                (
                    "delivery_jobs",
                    "SELECT * FROM delivery_jobs WHERE tenant_scope_id=? ORDER BY id",
                    (tenant_scope_id,),
                ),
                (
                    "delivery_attempts",
                    f"SELECT * FROM delivery_attempts WHERE job_id IN ({root}) ORDER BY id",
                    (tenant_scope_id,),
                ),
                (
                    "delivery_reconciliations",
                    f"SELECT * FROM delivery_reconciliations WHERE job_id IN ({root}) ORDER BY id",
                    (tenant_scope_id,),
                ),
            ]
        raise ValueError(f"Unsupported tenant store component: {component}")

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
        if not tenant:
            return []
        with self.registry.operation_lock:
            paths = self._store(tenant).export(case_id, formats, tenant)
            case = self._store(tenant).get(case_id, tenant)
            if case:
                binding = {
                    "alias": case.connection_alias,
                    "fingerprint": case.connection_fingerprint,
                    "tenant_scope_id": case.tenant_scope_id,
                }
                for path in paths:
                    self.registry.register_file(
                        "case-exports", path, binding, source_id=case_id
                    )
            return paths

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

    def result(
        self, job_id: str, tenant_scope_id: str | None = None
    ) -> dict[str, Any] | None:
        if tenant_scope_id:
            store = self._store(tenant_scope_id)
            if not store.get_job(job_id, tenant_scope_id):
                return None
            return store.result(job_id)
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
