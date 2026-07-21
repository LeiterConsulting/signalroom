from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from .recovery import RecoveryPackageService
from .schemas import RetentionPolicyUpdate
from .tenancy import TenantDataPlaneRegistry

RETENTION_KINDS = (
    "tenant-generation",
    "reverse-snapshot",
    "recovery-export",
    "recovery-checkpoint",
)
MAX_PREVIEW_ITEMS = 100


def _now() -> str:
    return datetime.now(UTC).isoformat()


class RetentionStore:
    """Durable policy and deletion receipts; retained payloads never enter this store."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS retention_policy (
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    generation_min_age_days INTEGER NOT NULL,
                    generation_keep_count INTEGER NOT NULL,
                    reverse_min_age_days INTEGER NOT NULL,
                    reverse_keep_count INTEGER NOT NULL,
                    recovery_export_min_age_days INTEGER NOT NULL,
                    recovery_export_keep_count INTEGER NOT NULL,
                    recovery_checkpoint_min_age_days INTEGER NOT NULL,
                    recovery_checkpoint_keep_count INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_cleanup_runs (
                    id TEXT PRIMARY KEY,
                    preview_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    item_count INTEGER NOT NULL,
                    deleted_bytes INTEGER NOT NULL,
                    items_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_retention_cleanup_created
                    ON retention_cleanup_runs(created_at DESC);
                """
            )
            database.execute(
                """INSERT OR IGNORE INTO retention_policy
                (id,generation_min_age_days,generation_keep_count,
                reverse_min_age_days,reverse_keep_count,
                recovery_export_min_age_days,recovery_export_keep_count,
                recovery_checkpoint_min_age_days,recovery_checkpoint_keep_count,
                revision,updated_by,updated_at)
                VALUES (1,30,2,30,2,30,3,90,3,1,'built-in',?)""",
                (_now(),),
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def policy(self) -> dict[str, Any]:
        with self.connect() as database:
            row = database.execute("SELECT * FROM retention_policy WHERE id=1").fetchone()
        assert row is not None
        return dict(row)

    def update_policy(self, value: RetentionPolicyUpdate, actor: str) -> dict[str, Any]:
        current = self.policy()
        now = _now()
        with self._lock, self.connect() as database:
            result = database.execute(
                """UPDATE retention_policy SET
                generation_min_age_days=?,generation_keep_count=?,
                reverse_min_age_days=?,reverse_keep_count=?,
                recovery_export_min_age_days=?,recovery_export_keep_count=?,
                recovery_checkpoint_min_age_days=?,recovery_checkpoint_keep_count=?,
                revision=revision+1,updated_by=?,updated_at=?
                WHERE id=1 AND revision=?""",
                (
                    value.generation_min_age_days,
                    value.generation_keep_count,
                    value.reverse_min_age_days,
                    value.reverse_keep_count,
                    value.recovery_export_min_age_days,
                    value.recovery_export_keep_count,
                    value.recovery_checkpoint_min_age_days,
                    value.recovery_checkpoint_keep_count,
                    actor[:120],
                    now,
                    current["revision"],
                ),
            )
            if not result.rowcount:
                raise ValueError("The retention policy changed; reload it before saving.")
        return self.policy()

    def record_run(
        self,
        preview_sha256: str,
        status: str,
        items: list[dict[str, Any]],
        actor: str,
    ) -> dict[str, Any]:
        run = {
            "id": str(uuid4()),
            "preview_sha256": preview_sha256,
            "status": status,
            "item_count": sum(1 for item in items if item.get("status") == "deleted"),
            "deleted_bytes": sum(
                int(item.get("size_bytes") or 0)
                for item in items
                if item.get("status") == "deleted"
            ),
            "items": items,
            "created_by": actor[:120],
            "created_at": _now(),
        }
        with self._lock, self.connect() as database:
            database.execute(
                """INSERT INTO retention_cleanup_runs
                (id,preview_sha256,status,item_count,deleted_bytes,items_json,
                created_by,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    run["id"],
                    preview_sha256,
                    status,
                    run["item_count"],
                    run["deleted_bytes"],
                    json.dumps(items, sort_keys=True),
                    run["created_by"],
                    run["created_at"],
                ),
            )
        return run

    def recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as database:
            rows = database.execute(
                """SELECT * FROM retention_cleanup_runs
                ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(50, int(limit))),),
            ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["items"] = json.loads(str(value.pop("items_json")))
            values.append(value)
        return values


class RetentionService:
    """Preview-bound cleanup for inactive tenant and encrypted recovery storage."""

    def __init__(
        self,
        store: RetentionStore,
        registry: TenantDataPlaneRegistry,
        recovery: RecoveryPackageService,
    ):
        self.store = store
        self.registry = registry
        self.recovery = recovery
        self.data_root = registry.data_root
        self._lock = RLock()

    def overview(self) -> dict[str, Any]:
        return {
            "policy": self.store.policy(),
            "preview": self.preview(),
            "recent_runs": self.store.recent_runs(),
            "contract": {
                "manual_execution_only": True,
                "exact_preview_required": True,
                "active_generations_protected": True,
                "rollback_sources_protected": True,
                "pending_recovery_protected": True,
                "metadata_retained": True,
                "max_items_per_run": MAX_PREVIEW_ITEMS,
            },
        }

    def update_policy(self, value: RetentionPolicyUpdate, actor: str) -> dict[str, Any]:
        policy = self.store.update_policy(value, actor)
        return {"policy": policy, "preview": self.preview()}

    def preview(self) -> dict[str, Any]:
        policy = self.store.policy()
        candidates, protected = self._candidate_inventory(policy)
        truncated = len(candidates) > MAX_PREVIEW_ITEMS
        candidates = candidates[:MAX_PREVIEW_ITEMS]
        digest_payload = {
            "schema": 1,
            "policy_revision": policy["revision"],
            "items": [
                {
                    key: item[key]
                    for key in (
                        "kind",
                        "id",
                        "tenant_scope_id",
                        "relative_path",
                        "size_bytes",
                        "file_count",
                        "content_sha256",
                    )
                }
                for item in candidates
            ],
        }
        preview_sha256 = hashlib.sha256(
            json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        count = len(candidates)
        by_kind = {
            kind: {
                "count": sum(1 for item in candidates if item["kind"] == kind),
                "size_bytes": sum(
                    int(item["size_bytes"])
                    for item in candidates
                    if item["kind"] == kind
                ),
            }
            for kind in RETENTION_KINDS
        }
        return {
            "generated_at": _now(),
            "policy_revision": policy["revision"],
            "preview_sha256": preview_sha256,
            "confirmation": f"CLEAN {count} ITEMS {preview_sha256[:12].upper()}" if count else "",
            "candidate_count": count,
            "candidate_size_bytes": sum(int(item["size_bytes"]) for item in candidates),
            "candidates": candidates,
            "by_kind": by_kind,
            "protected": protected,
            "truncated": truncated,
        }

    def execute(
        self,
        expected_preview_sha256: str,
        confirmation: str,
        actor: str,
    ) -> dict[str, Any]:
        with self._lock, self.registry.operation_lock:
            preview = self.preview()
            if not preview["candidate_count"]:
                raise ValueError("No retained local storage currently satisfies the cleanup policy.")
            if expected_preview_sha256 != preview["preview_sha256"]:
                raise ValueError("The cleanup inventory changed; review a fresh preview before deleting.")
            if confirmation.strip() != preview["confirmation"]:
                raise ValueError(f"Type {preview['confirmation']} exactly to authorize cleanup.")

            # Validate the complete set before the first deletion. A changed byte fails closed.
            for item in preview["candidates"]:
                observed = self._path_record(
                    self._resolve_relative(item["relative_path"]),
                    item["kind"],
                    item["id"],
                    item.get("tenant_scope_id") or "",
                    item.get("status") or "",
                    item.get("created_at") or "",
                    item.get("reason") or "",
                )
                if any(
                    observed[key] != item[key]
                    for key in ("size_bytes", "file_count", "content_sha256")
                ):
                    raise ValueError(
                        f"Retained storage {item['relative_path']} changed after preview; "
                        "no files were deleted."
                    )

            results: list[dict[str, Any]] = []
            for item in preview["candidates"]:
                path = self._resolve_relative(item["relative_path"])
                result = {
                    key: item[key]
                    for key in (
                        "kind",
                        "id",
                        "tenant_scope_id",
                        "relative_path",
                        "size_bytes",
                        "content_sha256",
                    )
                }
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                    if item["kind"] == "tenant-generation":
                        self.registry.remove_generation_file_manifests(
                            str(item["tenant_scope_id"]), str(item["id"])
                        )
                    result["status"] = "deleted"
                except OSError as exc:
                    result["status"] = "error"
                    result["error"] = str(exc)[:500]
                results.append(result)
            status = "complete" if all(item["status"] == "deleted" for item in results) else "partial"
            run = self.store.record_run(preview["preview_sha256"], status, results, actor)
            return {"run": run, "preview": self.preview()}

    def _candidate_inventory(
        self, policy: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        migrations = self.registry.retention_migrations()
        reverses = self.registry.retention_reverse_migrations()
        routes = self.registry.overview()["routes"]
        active = {
            str(route.get("generation_id") or "")
            for route in routes
            if route.get("mode") == "isolated-routing" and route.get("generation_id")
        }
        pending = {
            str(item.get("generation_id") or "")
            for item in migrations
            if item.get("status") in {"copying", "verified"}
        }
        rollback_sources = {
            str(item.get("source_generation_id") or "")
            for item in migrations
            if item.get("generation_id") in active and item.get("status") == "cutover"
        }
        reverse_sources = {
            str(item.get("generation_id") or "")
            for item in reverses
            if item.get("status") in {"copying", "verified", "finalized-ready", "applying"}
        }
        pending.discard("")
        rollback_sources.discard("")
        reverse_sources.discard("")
        protected_generations = active | pending | rollback_sources | reverse_sources
        terminal_generations = [
            item
            for item in migrations
            if item.get("generation_id")
            and item.get("generation_id") not in protected_generations
            and item.get("status")
            in {"failed", "rolled-back", "reverse-migrated", "cutover"}
        ]
        generation_records = self._retained_records(
            terminal_generations,
            keep=int(policy["generation_keep_count"]),
            min_age=int(policy["generation_min_age_days"]),
            kind="tenant-generation",
            path_for=lambda item: self.registry.generation_root(
                str(item["tenant_scope_id"]), str(item["generation_id"])
            ),
            id_field="generation_id",
            reason="Inactive tenant generation; immutable migration metadata remains retained.",
        )

        terminal_reverses = [
            item
            for item in reverses
            if item.get("status") in {"failed", "superseded", "applied"}
        ]
        reverse_records = self._retained_records(
            terminal_reverses,
            keep=int(policy["reverse_keep_count"]),
            min_age=int(policy["reverse_min_age_days"]),
            kind="reverse-snapshot",
            path_for=lambda item: self.registry.reverse_root(
                str(item["tenant_scope_id"]), str(item["id"])
            ),
            id_field="id",
            reason="Terminal reverse snapshot; immutable reverse-migration metadata remains retained.",
        )

        pending_restore = self.recovery.overview().get("pending_restore") or {}
        pending_package = str(pending_restore.get("package_id") or "")
        pending_checkpoint = str((pending_restore.get("checkpoint") or {}).get("package_id") or "")
        export_records = self._recovery_records(
            self.recovery.exports,
            "recovery-export",
            int(policy["recovery_export_keep_count"]),
            int(policy["recovery_export_min_age_days"]),
            {pending_package},
        )
        checkpoint_records = self._recovery_records(
            self.recovery.rollbacks,
            "recovery-checkpoint",
            int(policy["recovery_checkpoint_keep_count"]),
            int(policy["recovery_checkpoint_min_age_days"]),
            {pending_checkpoint},
        )
        candidates = sorted(
            generation_records + reverse_records + export_records + checkpoint_records,
            key=lambda item: (item["created_at"], item["kind"], item["id"]),
        )
        protected = {
            "active_generation_count": len(active),
            "pending_generation_count": len(pending),
            "rollback_source_count": len(rollback_sources),
            "active_reverse_snapshot_count": sum(
                1
                for item in reverses
                if item.get("status") in {"copying", "verified", "finalized-ready", "applying"}
            ),
            "pending_recovery_package": pending_package,
            "pending_recovery_checkpoint": pending_checkpoint,
        }
        return candidates, protected

    def _retained_records(
        self,
        values: list[dict[str, Any]],
        *,
        keep: int,
        min_age: int,
        kind: str,
        path_for: Any,
        id_field: str,
        reason: str,
    ) -> list[dict[str, Any]]:
        by_tenant: dict[str, list[dict[str, Any]]] = {}
        for value in values:
            by_tenant.setdefault(str(value["tenant_scope_id"]), []).append(value)
        records = []
        for tenant_values in by_tenant.values():
            ordered = sorted(
                tenant_values,
                key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""),
                reverse=True,
            )
            for item in ordered[keep:]:
                created_at = str(item.get("updated_at") or item.get("created_at") or "")
                if not self._old_enough(created_at, min_age):
                    continue
                path = path_for(item)
                if not path.exists():
                    continue
                records.append(
                    self._path_record(
                        path,
                        kind,
                        str(item[id_field]),
                        str(item["tenant_scope_id"]),
                        str(item.get("status") or ""),
                        created_at,
                        reason,
                    )
                )
        return records

    def _recovery_records(
        self,
        directory: Path,
        kind: str,
        keep: int,
        min_age: int,
        protected_ids: set[str],
    ) -> list[dict[str, Any]]:
        paths = sorted(
            directory.glob("*.signalroom-recovery"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        records = []
        for path in paths[keep:]:
            package_id = path.stem[-36:]
            created_at = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
            if package_id in protected_ids or not self._old_enough(created_at, min_age):
                continue
            reason = (
                "Superseded encrypted operator backup; package contents are never decrypted for cleanup."
                if kind == "recovery-export"
                else "Superseded encrypted pre-restore checkpoint; no pending restore references it."
            )
            records.append(
                self._path_record(path, kind, package_id, "", "retained", created_at, reason)
            )
        return records

    def _path_record(
        self,
        path: Path,
        kind: str,
        item_id: str,
        tenant_scope_id: str,
        status: str,
        created_at: str,
        reason: str,
    ) -> dict[str, Any]:
        if path.is_symlink():
            raise ValueError(f"Retention refuses symbolic-link storage: {path.name}")
        resolved = path.resolve()
        self.registry.assert_contained(resolved)
        if resolved.is_dir():
            entries = []
            size = 0
            for candidate in sorted(resolved.rglob("*")):
                if candidate.is_symlink():
                    raise ValueError(
                        f"Retention refuses a symbolic link inside {resolved.name}: {candidate.name}"
                    )
                if not candidate.is_file():
                    continue
                file_size, file_sha256 = self._file_digest(candidate)
                size += file_size
                entries.append(
                    {
                        "path": candidate.relative_to(resolved).as_posix(),
                        "size": file_size,
                        "sha256": file_sha256,
                    }
                )
            content_sha256 = hashlib.sha256(
                json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            file_count = len(entries)
        elif resolved.is_file():
            size, content_sha256 = self._file_digest(resolved)
            file_count = 1
        else:
            raise ValueError(f"Retained storage disappeared: {resolved.name}")
        return {
            "kind": kind,
            "id": item_id,
            "tenant_scope_id": tenant_scope_id,
            "status": status,
            "created_at": created_at,
            "relative_path": resolved.relative_to(self.data_root).as_posix(),
            "size_bytes": size,
            "file_count": file_count,
            "content_sha256": content_sha256,
            "reason": reason,
        }

    def _resolve_relative(self, value: str) -> Path:
        candidate = self.data_root / value
        if candidate.is_symlink():
            raise ValueError(f"Retention refuses symbolic-link storage: {candidate.name}")
        path = candidate.resolve()
        self.registry.assert_contained(path)
        if path == self.data_root:
            raise ValueError("Retention cannot target the SignalRoom data root.")
        return path

    @staticmethod
    def _file_digest(path: Path) -> tuple[int, str]:
        size = 0
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                hasher.update(chunk)
        return size, hasher.hexdigest()

    @staticmethod
    def _old_enough(value: str, days: int) -> bool:
        try:
            observed = datetime.fromisoformat(value)
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return False
        return (datetime.now(UTC) - observed).total_seconds() >= days * 86400
