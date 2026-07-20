from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Literal


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class TenantDataComponent:
    id: str
    label: str
    kind: Literal["sqlite", "filesystem"]
    source: str
    root_table: str = ""
    scope_column: str = ""
    dependent_tables: tuple[str, ...] = ()
    readiness: Literal[
        "copy-contract-ready",
        "scope-key-required",
        "relationship-map-required",
        "filesystem-router-required",
    ] = "copy-contract-ready"
    detail: str = ""
    sequence: int = 1


TENANT_COMPONENTS = (
    TenantDataComponent(
        "evidence",
        "Evidence, chunks, and embeddings",
        "sqlite",
        "evidence.db",
        "artifacts",
        "tenant_scope_id",
        ("chunks", "chunks_fts", "embeddings"),
        detail=(
            "Artifacts carry a direct tenant key; chunks and embeddings inherit it through "
            "artifact and chunk relationships."
        ),
    ),
    TenantDataComponent(
        "cases",
        "Cases and timelines",
        "sqlite",
        "cases.db",
        "cases",
        "tenant_scope_id",
        ("case_items",),
        detail="Cases carry a direct tenant key; timeline items inherit the case boundary.",
    ),
    TenantDataComponent(
        "manual-discovery",
        "Manual discovery jobs",
        "sqlite",
        "discovery_jobs.db",
        "discovery_jobs",
        "tenant_scope_id",
        ("discovery_job_events",),
        detail="Jobs carry a direct tenant key; their retained event stream follows the job.",
    ),
    TenantDataComponent(
        "assurance",
        "Continuous assurance state",
        "sqlite",
        "assurance.db",
        "assurance_runs",
        "tenant_scope_id",
        (
            "assurance_policy",
            "assurance_run_events",
            "assurance_notifications",
            "assurance_signals",
            "assurance_packages",
        ),
        "relationship-map-required",
        (
            "Runs are directly scoped, but the singleton policy and response tables need a "
            "per-tenant ownership key before physical separation."
        ),
        2,
    ),
    TenantDataComponent(
        "assurance-responses",
        "Assurance signals and response packages",
        "sqlite",
        "assurance.db",
        "assurance_packages",
        "tenant_scope_id",
        ("assurance_signals",),
        readiness="copy-contract-ready",
        detail=(
            "Response packages retain the exact assurance-run tenant identity; correlated signals "
            "carry the same indexed ownership and package membership relationship."
        ),
        sequence=3,
    ),
    TenantDataComponent(
        "shadow-forecasting",
        "Shadow forecast schedules",
        "sqlite",
        "time_series_schedules.db",
        "time_series_schedules",
        "tenant_scope_id",
        (
            "time_series_schedule_attempts",
            "time_series_schedule_events",
            "time_series_schedule_reviews",
        ),
        "relationship-map-required",
        (
            "Schedules and attempts are directly scoped; events and analyst reviews must move "
            "through their parent relationships."
        ),
        2,
    ),
    TenantDataComponent(
        "validations",
        "Validation queue and retained previews",
        "sqlite",
        "validations.db",
        "validation_tasks",
        "tenant_scope_id",
        readiness="copy-contract-ready",
        detail=(
            "Validation tasks retain the immutable Splunk alias, revision, and tenant key; "
            "execution revalidates that identity before any MCP call."
        ),
        sequence=3,
    ),
    TenantDataComponent(
        "detections",
        "Detection engineering records",
        "sqlite",
        "detections.db",
        "detections",
        "tenant_scope_id",
        dependent_tables=(
            "detection_versions",
            "detection_reviews",
            "detection_exports",
            "detection_gate_runs",
        ),
        readiness="copy-contract-ready",
        detail=(
            "Detection projects retain the exact tenant identity inherited from their completed "
            "validation; child history follows the detection relationship."
        ),
        sequence=3,
    ),
    TenantDataComponent(
        "forecast-experiments",
        "Forecast experiments and baselines",
        "sqlite",
        "time_series_experiments.db",
        "time_series_runs",
        "tenant_scope_id",
        dependent_tables=("time_series_alert_candidates", "time_series_baselines"),
        readiness="copy-contract-ready",
        detail=(
            "Forecast runs retain the immutable Splunk alias, revision, and indexed tenant key; "
            "baselines and alert candidates inherit ownership from the exact run."
        ),
        sequence=3,
    ),
    TenantDataComponent(
        "outbound-delivery",
        "Response-package delivery history",
        "sqlite",
        "delivery.db",
        "delivery_jobs",
        "tenant_scope_id",
        dependent_tables=("delivery_attempts", "delivery_reconciliations"),
        readiness="copy-contract-ready",
        detail=(
            "Delivery jobs copy the source package tenant identity at approval and recheck it before "
            "delivery. Destination policy remains a global control-plane decision."
        ),
        sequence=3,
    ),
    TenantDataComponent(
        "discovery-files",
        "Discovery blueprints and briefs",
        "filesystem",
        "artifacts",
        readiness="filesystem-router-required",
        detail=(
            "Filenames include scope and connection revision, but retained files still share one "
            "artifact directory."
        ),
        sequence=4,
    ),
    TenantDataComponent(
        "case-exports",
        "Case handoff exports",
        "filesystem",
        "case_exports",
        readiness="filesystem-router-required",
        detail="Export content is scope-checked, but files still share one export directory.",
        sequence=4,
    ),
)


GLOBAL_CONTROL_PLANE = (
    "Configuration and encrypted secret vault",
    "Connection identities and diagnostics",
    "Authentication, OIDC policy, and sessions",
    "Hash-chained audit authority and remote audit cursor",
    "Model trust, evaluation suites, benchmarks, and routing decisions",
    "Global workload and outbound-destination policy",
)


class TenantIsolationStore:
    """Global control-plane history for review-only tenant isolation plans."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenant_isolation_plans (
                    plan_id TEXT PRIMARY KEY,
                    tenant_scope_id TEXT NOT NULL,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_isolation_scope_created
                    ON tenant_isolation_plans(tenant_scope_id,created_at DESC);
                """
            )

    def save(self, plan: dict[str, Any], actor: str) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO tenant_isolation_plans
                (plan_id,tenant_scope_id,connection_alias,connection_fingerprint,
                plan_json,created_by,created_at) VALUES (?,?,?,?,?,?,?)""",
                (
                    plan["plan_id"],
                    plan["tenant_scope_id"],
                    plan["connection_alias"],
                    plan["connection_fingerprint"],
                    json.dumps(plan, sort_keys=True),
                    actor,
                    plan["generated_at"],
                ),
            )
        return {**plan, "created_by": actor}

    def latest(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT plan_json,created_by FROM tenant_isolation_plans
                ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [{**json.loads(str(row["plan_json"])), "created_by": row["created_by"]} for row in rows]


class TenantIsolationPlanner:
    """Build content-free, fail-closed plans before tenant data is ever moved."""

    SCHEMA_VERSION = "signalroom.tenant-isolation-plan.v1"

    def __init__(self, data_root: Path | str, store: TenantIsolationStore):
        self.data_root = Path(data_root).resolve()
        self.store = store

    def overview(self) -> dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "runtime": {
                "mode": "shared-row-filtered",
                "physical_isolation_enforced": False,
                "activation_available": False,
                "detail": (
                    "Tenant predicates are enforced, but tenant data still resides in shared "
                    "database and artifact files."
                ),
            },
            "contract": {
                "plan_reads_payload_content": False,
                "plan_moves_data": False,
                "plan_changes_runtime_routing": False,
                "activation_fails_closed": True,
                "global_audit_remains_shared": True,
            },
            "global_control_plane": list(GLOBAL_CONTROL_PLANE),
            "component_count": len(TENANT_COMPONENTS),
            "latest_plans": self.store.latest(),
        }

    def create_plan(self, binding: dict[str, Any], actor: str) -> dict[str, Any]:
        plan = self.preview(binding)
        return self.store.save(plan, actor)

    def preview(self, binding: dict[str, Any]) -> dict[str, Any]:
        scope = self._scope(binding)
        components = [self._inspect(component, scope) for component in TENANT_COMPONENTS]
        blockers = [
            {
                "component_id": item["id"],
                "label": item["label"],
                "reason": item["detail"],
                "required_change": item["readiness"],
            }
            for item in components
            if item["readiness"] != "copy-contract-ready"
        ]
        identity = {
            "schema_version": self.SCHEMA_VERSION,
            "connection_alias": scope["alias"],
            "connection_fingerprint": scope["fingerprint"],
            "tenant_scope_id": scope["tenant_scope_id"],
            "target_root": self._target_root(scope["tenant_scope_id"]),
            "components": components,
            "blockers": blockers,
        }
        return {
            **identity,
            "plan_id": _digest(identity),
            "generated_at": _now(),
            "phase": "readiness-only",
            "migration_executable": False,
            "activation_available": False,
            "records_attributed": sum(item["scope_records"] for item in components),
            "unbound_records": sum(item["unbound_records"] for item in components),
            "blocker_count": len(blockers),
            "safety_contract": [
                "No database row, artifact, export, or credential is copied by this plan.",
                "No payload content is read; inspection is limited to schemas, counts, and filenames.",
                "The immutable Splunk binding must still match when a future migration begins.",
                "Workers and writes must be quiesced before any future copy-and-verify phase.",
                "Source data remains authoritative until digest verification and explicit cutover.",
                "The global audit chain records planning, migration, verification, and rollback.",
            ],
            "next_step": (
                "Implement tenant-aware store routing for copy-contract-ready components, then add "
                "direct tenant keys to every blocking component before exposing migration authority."
            ),
        }

    def _inspect(self, component: TenantDataComponent, scope: dict[str, str]) -> dict[str, Any]:
        base = {
            "id": component.id,
            "label": component.label,
            "kind": component.kind,
            "source": component.source,
            "target": f"{self._target_root(scope['tenant_scope_id'])}/{component.source}",
            "root_table": component.root_table,
            "dependent_tables": list(component.dependent_tables),
            "readiness": component.readiness,
            "detail": component.detail,
            "sequence": component.sequence,
            "source_exists": False,
            "scope_records": 0,
            "other_scope_records": 0,
            "unbound_records": 0,
            "total_records": 0,
        }
        path = (self.data_root / component.source).resolve()
        self._assert_contained(path)
        if component.kind == "filesystem":
            return {**base, **self._inspect_directory(path, scope["tenant_scope_id"])}
        return {**base, **self._inspect_database(path, component, scope["tenant_scope_id"])}

    def _inspect_database(
        self,
        path: Path,
        component: TenantDataComponent,
        tenant_scope_id: str,
    ) -> dict[str, Any]:
        if not path.is_file():
            return {}
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            tables = {
                str(row["name"])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if component.root_table not in tables:
                return {"source_exists": True, "schema_observed": False}
            total = int(
                connection.execute(f'SELECT COUNT(*) count FROM "{component.root_table}"').fetchone()["count"]
            )
            columns = {
                str(row["name"])
                for row in connection.execute(f'PRAGMA table_info("{component.root_table}")').fetchall()
            }
            if not component.scope_column or component.scope_column not in columns:
                result: dict[str, Any] = {
                    "source_exists": True,
                    "schema_observed": True,
                    "total_records": total,
                }
                if component.readiness == "copy-contract-ready" and component.scope_column:
                    result.update(
                        {
                            "readiness": "scope-key-required",
                            "detail": (
                                f"The observed {component.root_table} schema does not contain "
                                f"the required {component.scope_column} ownership column."
                            ),
                        }
                    )
                return result
            scope_count = int(
                connection.execute(
                    f'SELECT COUNT(*) count FROM "{component.root_table}" WHERE "{component.scope_column}"=?',
                    (tenant_scope_id,),
                ).fetchone()["count"]
            )
            unbound = int(
                connection.execute(
                    f'SELECT COUNT(*) count FROM "{component.root_table}" '
                    f"WHERE COALESCE(\"{component.scope_column}\",'')=''"
                ).fetchone()["count"]
            )
            return {
                "source_exists": True,
                "schema_observed": True,
                "scope_records": scope_count,
                "other_scope_records": max(0, total - scope_count - unbound),
                "unbound_records": unbound,
                "total_records": total,
            }
        finally:
            connection.close()

    @staticmethod
    def _inspect_directory(path: Path, tenant_scope_id: str) -> dict[str, Any]:
        if not path.is_dir():
            return {}
        safe_scope = re.sub(r"[^a-zA-Z0-9_.-]+", "-", tenant_scope_id).strip("-")
        files = [item for item in path.rglob("*") if item.is_file()]
        attributed = [item for item in files if safe_scope.casefold() in item.name.casefold()]
        return {
            "source_exists": True,
            "schema_observed": True,
            "scope_records": len(attributed),
            "other_scope_records": len(files) - len(attributed),
            "total_records": len(files),
        }

    def _assert_contained(self, path: Path) -> None:
        if path != self.data_root and self.data_root not in path.parents:
            raise ValueError("Tenant isolation source path escapes the SignalRoom data root.")

    @staticmethod
    def _scope(value: dict[str, Any]) -> dict[str, str]:
        tenant_scope_id = str(value.get("tenant_scope_id") or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9._-]{2,63}", tenant_scope_id):
            raise ValueError("Tenant scope is not safe for an isolation plan.")
        return {
            "alias": str(value.get("alias") or "primary"),
            "fingerprint": str(value.get("fingerprint") or ""),
            "tenant_scope_id": tenant_scope_id,
        }

    @staticmethod
    def _target_root(tenant_scope_id: str) -> str:
        safe = re.sub(r"[^a-z0-9._-]+", "-", tenant_scope_id.lower()).strip("-")
        return f"tenants/{safe}"
