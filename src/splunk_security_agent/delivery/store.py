from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import DeliveryPolicyUpdate

DEFAULT_SIGNAL_KINDS = ["finding", "coverage", "inventory", "mltk", "collection"]
DEFAULT_DESTINATION_KIND = "generic-webhook"


def _now() -> str:
    return datetime.now(UTC).isoformat()


class DeliveryStore:
    """Durable policy, approval, attempt, and retry state for outbound packages."""

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
        now = _now()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS delivery_policy (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    enabled INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    destination_kind TEXT NOT NULL DEFAULT 'generic-webhook',
                    minimum_severity TEXT NOT NULL,
                    signal_kinds TEXT NOT NULL,
                    redaction_level TEXT NOT NULL,
                    destination_label TEXT NOT NULL,
                    jira_project_key TEXT NOT NULL DEFAULT '',
                    jira_issue_type TEXT NOT NULL DEFAULT 'Task',
                    jira_summary_prefix TEXT NOT NULL DEFAULT '[SignalRoom]',
                    jira_labels TEXT NOT NULL DEFAULT '["signalroom","security-assurance"]',
                    jira_priority_map TEXT NOT NULL DEFAULT
                        '{"critical":"Highest","high":"High","medium":"Medium","low":"Low"}',
                    soar_label TEXT NOT NULL DEFAULT 'events',
                    soar_container_type TEXT NOT NULL DEFAULT 'default',
                    soar_status TEXT NOT NULL DEFAULT 'new',
                    soar_name_prefix TEXT NOT NULL DEFAULT '[SignalRoom]',
                    soar_sensitivity TEXT NOT NULL DEFAULT 'amber',
                    soar_tags TEXT NOT NULL DEFAULT '["signalroom","security-assurance"]',
                    soar_severity_map TEXT NOT NULL DEFAULT
                        '{"critical":"high","high":"high","medium":"medium","low":"low"}',
                    soar_tenant_id TEXT NOT NULL DEFAULT '',
                    verify_tls INTEGER NOT NULL,
                    ca_bundle TEXT NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    retry_backoff_seconds INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delivery_jobs (
                    id TEXT PRIMARY KEY,
                    package_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approval_mode TEXT NOT NULL,
                    destination_kind TEXT NOT NULL DEFAULT 'generic-webhook',
                    destination_label TEXT NOT NULL,
                    destination_fingerprint TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    attempt_count INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    next_attempt_at TEXT,
                    last_error TEXT NOT NULL,
                    http_status INTEGER,
                    created_at TEXT NOT NULL,
                    approved_at TEXT NOT NULL,
                    delivered_at TEXT,
                    external_record_id TEXT NOT NULL DEFAULT '',
                    external_record_key TEXT NOT NULL DEFAULT '',
                    external_record_url TEXT NOT NULL DEFAULT '',
                    external_record_created_at TEXT,
                    updated_at TEXT NOT NULL,
                    connection_alias TEXT NOT NULL DEFAULT 'primary',
                    connection_fingerprint TEXT NOT NULL DEFAULT '',
                    tenant_scope_id TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_delivery_jobs_state
                    ON delivery_jobs(status, next_attempt_at, created_at);
                CREATE INDEX IF NOT EXISTS idx_delivery_jobs_package
                    ON delivery_jobs(package_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS delivery_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    outcome TEXT NOT NULL,
                    http_status INTEGER,
                    error TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES delivery_jobs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_delivery_attempts_job
                    ON delivery_attempts(job_id, id DESC);
                CREATE TABLE IF NOT EXISTS delivery_reconciliations (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    http_status INTEGER,
                    snapshot TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL,
                    drift TEXT NOT NULL,
                    error TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES delivery_jobs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_delivery_reconciliations_job
                    ON delivery_reconciliations(job_id, observed_at DESC);
                """
            )
            policy_columns = {
                str(row["name"]) for row in db.execute("PRAGMA table_info(delivery_policy)").fetchall()
            }
            policy_migrations = {
                "destination_kind": "TEXT NOT NULL DEFAULT 'generic-webhook'",
                "jira_project_key": "TEXT NOT NULL DEFAULT ''",
                "jira_issue_type": "TEXT NOT NULL DEFAULT 'Task'",
                "jira_summary_prefix": "TEXT NOT NULL DEFAULT '[SignalRoom]'",
                "jira_labels": ("""TEXT NOT NULL DEFAULT '["signalroom","security-assurance"]'"""),
                "jira_priority_map": (
                    "TEXT NOT NULL DEFAULT "
                    """'{"critical":"Highest","high":"High","medium":"Medium","low":"Low"}'"""
                ),
                "soar_label": "TEXT NOT NULL DEFAULT 'events'",
                "soar_container_type": "TEXT NOT NULL DEFAULT 'default'",
                "soar_status": "TEXT NOT NULL DEFAULT 'new'",
                "soar_name_prefix": "TEXT NOT NULL DEFAULT '[SignalRoom]'",
                "soar_sensitivity": "TEXT NOT NULL DEFAULT 'amber'",
                "soar_tags": ("""TEXT NOT NULL DEFAULT '["signalroom","security-assurance"]'"""),
                "soar_severity_map": (
                    "TEXT NOT NULL DEFAULT "
                    """'{"critical":"high","high":"high","medium":"medium","low":"low"}'"""
                ),
                "soar_tenant_id": "TEXT NOT NULL DEFAULT ''",
            }
            for column, definition in policy_migrations.items():
                if column not in policy_columns:
                    db.execute(f"ALTER TABLE delivery_policy ADD COLUMN {column} {definition}")
            job_columns = {
                str(row["name"]) for row in db.execute("PRAGMA table_info(delivery_jobs)").fetchall()
            }
            job_migrations = {
                "destination_kind": "TEXT NOT NULL DEFAULT 'generic-webhook'",
                "external_record_id": "TEXT NOT NULL DEFAULT ''",
                "external_record_key": "TEXT NOT NULL DEFAULT ''",
                "external_record_url": "TEXT NOT NULL DEFAULT ''",
                "external_record_created_at": "TEXT",
                "connection_alias": "TEXT NOT NULL DEFAULT 'primary'",
                "connection_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "tenant_scope_id": "TEXT NOT NULL DEFAULT ''",
            }
            for column, definition in job_migrations.items():
                if column not in job_columns:
                    db.execute(f"ALTER TABLE delivery_jobs ADD COLUMN {column} {definition}")
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_delivery_jobs_tenant_state
                ON delivery_jobs(tenant_scope_id,status,created_at DESC)"""
            )
            db.execute(
                """INSERT OR IGNORE INTO delivery_policy
                (id,enabled,mode,destination_kind,minimum_severity,signal_kinds,redaction_level,
                destination_label,verify_tls,ca_bundle,max_attempts,retry_backoff_seconds,
                updated_at)
                VALUES (1,0,'manual','generic-webhook','high',?,'strict',
                'Primary webhook',1,'',3,60,?)""",
                (json.dumps(DEFAULT_SIGNAL_KINDS), now),
            )

    def bind_unbound(
        self,
        binding: dict[str, Any],
        package_resolver: Any | None = None,
    ) -> int:
        """Backfill jobs from their exact response package, with a primary fallback."""
        fallback = {
            "connection_alias": str(binding.get("alias") or "primary"),
            "connection_fingerprint": str(binding.get("fingerprint") or ""),
            "tenant_scope_id": str(binding.get("tenant_scope_id") or "workspace-primary"),
        }
        changed = 0
        with self._lock, self.connect() as db:
            rows = db.execute(
                """SELECT id,package_id FROM delivery_jobs
                WHERE connection_fingerprint='' OR tenant_scope_id=''"""
            ).fetchall()
            for row in rows:
                package = package_resolver(str(row["package_id"])) if package_resolver else None
                source = package or fallback
                changed += db.execute(
                    """UPDATE delivery_jobs SET connection_alias=?,
                    connection_fingerprint=?,tenant_scope_id=?
                    WHERE id=? AND (connection_fingerprint='' OR tenant_scope_id='')""",
                    (
                        str(source.get("connection_alias") or fallback["connection_alias"]),
                        str(source.get("connection_fingerprint") or fallback["connection_fingerprint"]),
                        str(source.get("tenant_scope_id") or fallback["tenant_scope_id"]),
                        row["id"],
                    ),
                ).rowcount
        return int(changed)

    def policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM delivery_policy WHERE id=1").fetchone()
        assert row is not None
        return self._policy(row)

    def update_policy(self, value: DeliveryPolicyUpdate) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE delivery_policy SET enabled=?,mode=?,minimum_severity=?,
                destination_kind=?,signal_kinds=?,redaction_level=?,destination_label=?,verify_tls=?,
                ca_bundle=?,max_attempts=?,retry_backoff_seconds=?,jira_project_key=?,
                jira_issue_type=?,jira_summary_prefix=?,jira_labels=?,jira_priority_map=?,
                soar_label=?,soar_container_type=?,soar_status=?,soar_name_prefix=?,
                soar_sensitivity=?,soar_tags=?,soar_severity_map=?,soar_tenant_id=?,
                updated_at=? WHERE id=1""",
                (
                    int(value.enabled),
                    value.mode,
                    value.minimum_severity,
                    value.destination_kind,
                    json.dumps(sorted(set(value.signal_kinds))),
                    value.redaction_level,
                    value.destination_label,
                    int(value.verify_tls),
                    value.ca_bundle or "",
                    value.max_attempts,
                    value.retry_backoff_seconds,
                    value.jira_project_key,
                    value.jira_issue_type,
                    value.jira_summary_prefix,
                    json.dumps(value.jira_labels),
                    json.dumps(value.jira_priority_map, sort_keys=True),
                    value.soar_label,
                    value.soar_container_type,
                    value.soar_status,
                    value.soar_name_prefix,
                    value.soar_sensitivity,
                    json.dumps(value.soar_tags),
                    json.dumps(value.soar_severity_map, sort_keys=True),
                    value.soar_tenant_id,
                    now,
                ),
            )
        return self.policy()

    def approve(
        self,
        *,
        package_id: str,
        approval_mode: str,
        destination_kind: str,
        destination_label: str,
        destination_fingerprint: str,
        payload: dict[str, Any],
        payload_sha256: str,
        idempotency_key: str,
        max_attempts: int,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        binding = binding or {}
        with self._lock, self.connect() as db:
            existing = db.execute(
                "SELECT * FROM delivery_jobs WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing:
                existing_job_id = str(existing["id"])
            else:
                existing_job_id = ""
            job_id = str(uuid4())
            now = _now()
            if existing_job_id:
                job_id = existing_job_id
            else:
                db.execute(
                    """INSERT INTO delivery_jobs
                    (id,package_id,status,approval_mode,destination_kind,destination_label,
                    destination_fingerprint,
                    payload,payload_sha256,idempotency_key,attempt_count,max_attempts,next_attempt_at,
                    last_error,http_status,created_at,approved_at,delivered_at,updated_at,
                    connection_alias,connection_fingerprint,tenant_scope_id)
                    VALUES (?,?,'queued',?,?,?,?,?,?,?,0,?,?,'',NULL,?,?,NULL,?,?,?,?)""",
                    (
                        job_id,
                        package_id,
                        approval_mode,
                        destination_kind,
                        destination_label,
                        destination_fingerprint,
                        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str),
                        payload_sha256,
                        idempotency_key,
                        max_attempts,
                        now,
                        now,
                        now,
                        now,
                        str(binding.get("connection_alias") or "primary"),
                        str(binding.get("connection_fingerprint") or ""),
                        str(binding.get("tenant_scope_id") or "workspace-primary"),
                    ),
                )
        result = self.get(job_id)
        assert result is not None
        return result

    def get(self, job_id: str, tenant_scope_id: str = "") -> dict[str, Any] | None:
        with self.connect() as db:
            if tenant_scope_id:
                row = db.execute(
                    "SELECT * FROM delivery_jobs WHERE id=? AND tenant_scope_id=?",
                    (job_id, tenant_scope_id),
                ).fetchone()
            else:
                row = db.execute("SELECT * FROM delivery_jobs WHERE id=?", (job_id,)).fetchone()
        return self._job_with_attempts(row) if row else None

    def jobs(self, limit: int = 30, *, tenant_scope_id: str = "") -> list[dict[str, Any]]:
        with self.connect() as db:
            if tenant_scope_id:
                rows = db.execute(
                    """SELECT * FROM delivery_jobs WHERE tenant_scope_id=? ORDER BY
                    CASE status WHEN 'sending' THEN 0 WHEN 'queued' THEN 1
                    WHEN 'retrying' THEN 2 ELSE 3 END, created_at DESC LIMIT ?""",
                    (tenant_scope_id, min(max(limit, 1), 200)),
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM delivery_jobs ORDER BY
                    CASE status WHEN 'sending' THEN 0 WHEN 'queued' THEN 1
                    WHEN 'retrying' THEN 2 ELSE 3 END, created_at DESC LIMIT ?""",
                    (min(max(limit, 1), 200),),
                ).fetchall()
        return [self._job_with_attempts(row) for row in rows]

    def next_due(self, excluded_tenant_scope_ids: set[str] | None = None) -> dict[str, Any] | None:
        now = _now()
        excluded = sorted(excluded_tenant_scope_ids or set())
        tenant_clause = f" AND tenant_scope_id NOT IN ({','.join('?' for _ in excluded)})" if excluded else ""
        with self.connect() as db:
            row = db.execute(
                f"""SELECT * FROM delivery_jobs
                WHERE status IN ('queued','retrying')
                AND (next_attempt_at IS NULL OR next_attempt_at<=?)
                {tenant_clause} ORDER BY created_at LIMIT 1""",
                (now, *excluded),
            ).fetchone()
        return self._job_with_attempts(row) if row else None

    def mark_sending(self, job_id: str) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            changed = db.execute(
                """UPDATE delivery_jobs SET status='sending',updated_at=?
                WHERE id=? AND status IN ('queued','retrying')""",
                (now, job_id),
            ).rowcount
        return self.get(job_id) if changed else None

    def record_attempt(
        self,
        job_id: str,
        *,
        started_at: str,
        outcome: str,
        http_status: int | None,
        error: str,
        retryable: bool,
        retry_backoff_seconds: int,
    ) -> dict[str, Any] | None:
        now = datetime.now(UTC)
        completed_at = now.isoformat()
        current = self.get(job_id)
        if current is None:
            return None
        attempt_number = int(current["attempt_count"]) + 1
        delivered = outcome == "delivered"
        if delivered:
            status = "delivered"
            next_attempt_at = None
        elif retryable and attempt_number < int(current["max_attempts"]):
            status = "retrying"
            delay = retry_backoff_seconds * (2 ** max(0, attempt_number - 1))
            next_attempt_at = datetime.fromtimestamp(now.timestamp() + delay, UTC).isoformat()
        else:
            status = "failed"
            next_attempt_at = None
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO delivery_attempts
                (job_id,attempt_number,outcome,http_status,error,started_at,completed_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    job_id,
                    attempt_number,
                    outcome,
                    http_status,
                    error[:1000],
                    started_at,
                    completed_at,
                ),
            )
            db.execute(
                """UPDATE delivery_jobs SET status=?,attempt_count=?,next_attempt_at=?,
                last_error=?,http_status=?,delivered_at=?,updated_at=? WHERE id=?""",
                (
                    status,
                    attempt_number,
                    next_attempt_at,
                    error[:1000],
                    http_status,
                    completed_at if delivered else None,
                    completed_at,
                    job_id,
                ),
            )
        return self.get(job_id)

    def retry(self, job_id: str, additional_attempts: int) -> dict[str, Any] | None:
        current = self.get(job_id)
        if current is None or current["status"] != "failed":
            return None
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE delivery_jobs SET status='queued',max_attempts=?,
                next_attempt_at=?,last_error='',http_status=NULL,updated_at=? WHERE id=?""",
                (
                    int(current["attempt_count"]) + additional_attempts,
                    now,
                    now,
                    job_id,
                ),
            )
        return self.get(job_id)

    def cancel(self, job_id: str, reason: str = "Cancelled by local operator") -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            changed = db.execute(
                """UPDATE delivery_jobs SET status='cancelled',last_error=?,next_attempt_at=NULL,
                updated_at=? WHERE id=? AND status IN ('queued','retrying','failed')""",
                (reason[:1000], now, job_id),
            ).rowcount
        return self.get(job_id) if changed else None

    def cancel_sending(self, job_id: str, reason: str) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            changed = db.execute(
                """UPDATE delivery_jobs SET status='cancelled',last_error=?,next_attempt_at=NULL,
                updated_at=? WHERE id=? AND status='sending'""",
                (reason[:1000], now, job_id),
            ).rowcount
        return self.get(job_id) if changed else None

    def cancel_package(self, package_id: str, reason: str) -> int:
        now = _now()
        with self._lock, self.connect() as db:
            changed = db.execute(
                """UPDATE delivery_jobs SET status='cancelled',last_error=?,next_attempt_at=NULL,
                updated_at=? WHERE package_id=? AND status IN ('queued','retrying','failed')""",
                (reason[:1000], now, package_id),
            ).rowcount
        return int(changed)

    def cancel_pending(
        self,
        reason: str,
        excluded_tenant_scope_ids: set[str] | None = None,
    ) -> int:
        now = _now()
        excluded = sorted(excluded_tenant_scope_ids or set())
        tenant_clause = f" AND tenant_scope_id NOT IN ({','.join('?' for _ in excluded)})" if excluded else ""
        with self._lock, self.connect() as db:
            changed = db.execute(
                f"""UPDATE delivery_jobs SET status='cancelled',last_error=?,next_attempt_at=NULL,
                updated_at=? WHERE status IN ('queued','retrying','failed'){tenant_clause}""",
                (reason[:1000], now, *excluded),
            ).rowcount
        return int(changed)

    def fail_without_attempt(self, job_id: str, error: str) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE delivery_jobs SET status='failed',last_error=?,next_attempt_at=NULL,
                updated_at=? WHERE id=?""",
                (error[:1000], now, job_id),
            )
        return self.get(job_id)

    def record_external_record(
        self,
        job_id: str,
        *,
        record_id: str,
        record_key: str,
        record_url: str,
    ) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            changed = db.execute(
                """UPDATE delivery_jobs SET external_record_id=?,external_record_key=?,
                external_record_url=?,external_record_created_at=?,updated_at=?
                WHERE id=? AND status='sending'""",
                (
                    record_id[:120],
                    record_key[:120],
                    record_url[:2000],
                    now,
                    now,
                    job_id,
                ),
            ).rowcount
        return self.get(job_id) if changed else None

    def recover_interrupted(self, excluded_tenant_scope_ids: set[str] | None = None) -> dict[str, int]:
        now = _now()
        excluded = sorted(excluded_tenant_scope_ids or set())
        tenant_clause = f" AND tenant_scope_id NOT IN ({','.join('?' for _ in excluded)})" if excluded else ""
        with self._lock, self.connect() as db:
            correlated = db.execute(
                f"""UPDATE delivery_jobs SET status='delivered',next_attempt_at=NULL,
                last_error='Recovered after the external record correlation was durably recorded.',
                delivered_at=COALESCE(delivered_at,external_record_created_at,?),
                updated_at=? WHERE status='sending'
                AND destination_kind IN ('jira-cloud','splunk-soar')
                AND external_record_id<>''{tenant_clause}""",
                (now, now, *excluded),
            ).rowcount
            uncertain = db.execute(
                f"""UPDATE delivery_jobs SET status='failed',next_attempt_at=NULL,
                last_error='Process restarted during Jira issue creation; the outcome is
                unknown. Inspect Jira for the SignalRoom correlation label before an
                explicit retry.',updated_at=? WHERE status='sending'
                AND destination_kind='jira-cloud' AND external_record_key=''{tenant_clause}""",
                (now, *excluded),
            ).rowcount
            retrying = db.execute(
                f"""UPDATE delivery_jobs SET status='retrying',next_attempt_at=?,
                last_error='Process restarted during delivery; retry uses the original approved payload.',
                updated_at=? WHERE status='sending' AND destination_kind<>'jira-cloud'
                {tenant_clause}""",
                (now, now, *excluded),
            ).rowcount
        return {
            "correlated": int(correlated),
            "uncertain": int(uncertain),
            "retrying": int(retrying),
        }

    def attempts(self, job_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM delivery_attempts WHERE job_id=?
                ORDER BY attempt_number DESC""",
                (job_id,),
            ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "attempt_number": int(row["attempt_number"]),
                "outcome": row["outcome"],
                "http_status": row["http_status"],
                "error": row["error"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
            }
            for row in rows
        ]

    def record_reconciliation(
        self,
        job_id: str,
        *,
        outcome: str,
        http_status: int | None,
        snapshot: dict[str, Any],
        drift: dict[str, Any],
        error: str,
    ) -> dict[str, Any] | None:
        if self.get(job_id) is None:
            return None
        reconciliation_id = str(uuid4())
        observed_at = _now()
        canonical_snapshot = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
        snapshot_sha256 = hashlib.sha256(canonical_snapshot.encode()).hexdigest()
        canonical_drift = json.dumps(drift, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO delivery_reconciliations
                (id,job_id,outcome,http_status,snapshot,snapshot_sha256,drift,error,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    reconciliation_id,
                    job_id,
                    outcome[:80],
                    http_status,
                    canonical_snapshot,
                    snapshot_sha256,
                    canonical_drift,
                    error[:1000],
                    observed_at,
                ),
            )
        return self.reconciliation(reconciliation_id)

    def reconciliation(self, reconciliation_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM delivery_reconciliations WHERE id=?",
                (reconciliation_id,),
            ).fetchone()
        return self._reconciliation(row) if row else None

    def reconciliations(self, job_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM delivery_reconciliations WHERE job_id=?
                ORDER BY observed_at DESC, id DESC LIMIT ?""",
                (job_id, min(max(limit, 1), 100)),
            ).fetchall()
        return [self._reconciliation(row) for row in rows]

    @staticmethod
    def _policy(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "enabled": bool(row["enabled"]),
            "mode": row["mode"],
            "destination_kind": row["destination_kind"] or DEFAULT_DESTINATION_KIND,
            "minimum_severity": row["minimum_severity"],
            "signal_kinds": json.loads(row["signal_kinds"]),
            "redaction_level": row["redaction_level"],
            "destination_label": row["destination_label"],
            "jira_project_key": row["jira_project_key"],
            "jira_issue_type": row["jira_issue_type"],
            "jira_summary_prefix": row["jira_summary_prefix"],
            "jira_labels": json.loads(row["jira_labels"]),
            "jira_priority_map": json.loads(row["jira_priority_map"]),
            "soar_label": row["soar_label"],
            "soar_container_type": row["soar_container_type"],
            "soar_status": row["soar_status"],
            "soar_name_prefix": row["soar_name_prefix"],
            "soar_sensitivity": row["soar_sensitivity"],
            "soar_tags": json.loads(row["soar_tags"]),
            "soar_severity_map": json.loads(row["soar_severity_map"]),
            "soar_tenant_id": row["soar_tenant_id"],
            "verify_tls": bool(row["verify_tls"]),
            "ca_bundle": row["ca_bundle"] or None,
            "max_attempts": int(row["max_attempts"]),
            "retry_backoff_seconds": int(row["retry_backoff_seconds"]),
            "updated_at": row["updated_at"],
        }

    def _job_with_attempts(self, row: sqlite3.Row) -> dict[str, Any]:
        value = self._job(row)
        value["attempts"] = self.attempts(value["id"])
        value["reconciliations"] = self.reconciliations(value["id"])
        value["latest_reconciliation"] = value["reconciliations"][0] if value["reconciliations"] else None
        return value

    @staticmethod
    def _reconciliation(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "job_id": row["job_id"],
            "outcome": row["outcome"],
            "http_status": row["http_status"],
            "snapshot": json.loads(row["snapshot"]),
            "snapshot_sha256": row["snapshot_sha256"],
            "drift": json.loads(row["drift"]),
            "error": row["error"],
            "observed_at": row["observed_at"],
        }

    @staticmethod
    def _job(row: sqlite3.Row) -> dict[str, Any]:
        external_record = (
            {
                "id": row["external_record_id"],
                "key": row["external_record_key"],
                "url": row["external_record_url"],
                "created_at": row["external_record_created_at"],
            }
            if row["external_record_key"]
            else None
        )
        return {
            "id": row["id"],
            "package_id": row["package_id"],
            "status": row["status"],
            "approval_mode": row["approval_mode"],
            "destination_kind": row["destination_kind"] or DEFAULT_DESTINATION_KIND,
            "destination_label": row["destination_label"],
            "destination_fingerprint": row["destination_fingerprint"],
            "payload": json.loads(row["payload"]),
            "payload_sha256": row["payload_sha256"],
            "idempotency_key": row["idempotency_key"],
            "attempt_count": int(row["attempt_count"]),
            "max_attempts": int(row["max_attempts"]),
            "next_attempt_at": row["next_attempt_at"],
            "last_error": row["last_error"],
            "http_status": row["http_status"],
            "created_at": row["created_at"],
            "approved_at": row["approved_at"],
            "delivered_at": row["delivered_at"],
            "external_record": external_record,
            "connection_alias": row["connection_alias"],
            "connection_fingerprint": row["connection_fingerprint"],
            "tenant_scope_id": row["tenant_scope_id"],
            "updated_at": row["updated_at"],
        }
