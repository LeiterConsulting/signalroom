from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import AuditExportPolicyUpdate, AuditOperationsPolicyUpdate


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AuditExportStore:
    """Durable HEC policy, cursor, and delivery-attempt state."""

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
                CREATE TABLE IF NOT EXISTS audit_export_policy (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    enabled INTEGER NOT NULL,
                    index_name TEXT NOT NULL,
                    sourcetype TEXT NOT NULL,
                    source TEXT NOT NULL,
                    host TEXT NOT NULL,
                    verify_tls INTEGER NOT NULL,
                    ca_bundle TEXT NOT NULL,
                    use_indexer_ack INTEGER NOT NULL,
                    channel_id TEXT NOT NULL,
                    batch_size INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    retry_backoff_seconds INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_export_state (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    cursor_sequence INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    consecutive_failures INTEGER NOT NULL,
                    next_attempt_at TEXT,
                    last_error TEXT NOT NULL,
                    last_http_status INTEGER,
                    last_batch_first_sequence INTEGER,
                    last_batch_last_sequence INTEGER,
                    last_batch_event_count INTEGER NOT NULL,
                    last_payload_sha256 TEXT NOT NULL,
                    last_ack_id INTEGER,
                    last_ack_confirmed INTEGER NOT NULL,
                    last_success_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_export_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_sequence INTEGER NOT NULL,
                    last_sequence INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    destination_fingerprint TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    http_status INTEGER,
                    ack_id INTEGER,
                    ack_confirmed INTEGER NOT NULL,
                    error TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_export_attempts_created
                    ON audit_export_attempts(completed_at DESC);
                CREATE TABLE IF NOT EXISTS audit_operations_policy (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    retention_days INTEGER NOT NULL,
                    deduplication_mode TEXT NOT NULL,
                    expected_export_lag_minutes INTEGER NOT NULL,
                    source_silence_minutes INTEGER NOT NULL,
                    denied_request_threshold INTEGER NOT NULL,
                    dashboard_earliest TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_operations_exports (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL UNIQUE,
                    archive_sha256 TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    destination_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_operations_exports_created
                    ON audit_operations_exports(created_at DESC);
                CREATE TABLE IF NOT EXISTS audit_operations_reconciliations (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    destination_fingerprint TEXT NOT NULL,
                    export_id TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    connection_alias TEXT NOT NULL,
                    connection_fingerprint TEXT NOT NULL,
                    tenant_scope_id TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    FOREIGN KEY(export_id) REFERENCES audit_operations_exports(id)
                );
                CREATE INDEX IF NOT EXISTS idx_audit_operations_reconciliations_observed
                    ON audit_operations_reconciliations(observed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_operations_reconciliations_binding
                    ON audit_operations_reconciliations(
                        connection_alias,connection_fingerprint,tenant_scope_id,observed_at DESC
                    );
                """
            )
            db.execute(
                """INSERT OR IGNORE INTO audit_export_policy
                (id,enabled,index_name,sourcetype,source,host,verify_tls,ca_bundle,
                use_indexer_ack,channel_id,batch_size,max_attempts,retry_backoff_seconds,
                updated_at)
                VALUES (1,0,'signalroom_audit','signalroom:audit','signalroom:audit',
                'signalroom',1,'',0,?,25,5,30,?)""",
                (str(uuid4()), now),
            )
            db.execute(
                """INSERT OR IGNORE INTO audit_export_state
                (id,cursor_sequence,status,consecutive_failures,next_attempt_at,last_error,
                last_http_status,last_batch_first_sequence,last_batch_last_sequence,
                last_batch_event_count,last_payload_sha256,last_ack_id,last_ack_confirmed,
                last_success_at,updated_at)
                VALUES (1,0,'disabled',0,NULL,'',NULL,NULL,NULL,0,'',NULL,0,NULL,?)""",
                (now,),
            )
            db.execute(
                """INSERT OR IGNORE INTO audit_operations_policy
                (id,retention_days,deduplication_mode,expected_export_lag_minutes,
                source_silence_minutes,denied_request_threshold,dashboard_earliest,
                updated_at)
                VALUES (1,365,'stable-event-id',15,60,5,'-24h',?)""",
                (now,),
            )

    def policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM audit_export_policy WHERE id=1").fetchone()
        assert row is not None
        return {
            "enabled": bool(row["enabled"]),
            "index_name": row["index_name"],
            "sourcetype": row["sourcetype"],
            "source": row["source"],
            "host": row["host"],
            "verify_tls": bool(row["verify_tls"]),
            "ca_bundle": row["ca_bundle"] or None,
            "use_indexer_ack": bool(row["use_indexer_ack"]),
            "channel_id": row["channel_id"],
            "batch_size": int(row["batch_size"]),
            "max_attempts": int(row["max_attempts"]),
            "retry_backoff_seconds": int(row["retry_backoff_seconds"]),
            "updated_at": row["updated_at"],
        }

    def state(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM audit_export_state WHERE id=1").fetchone()
        assert row is not None
        return {
            "cursor_sequence": int(row["cursor_sequence"]),
            "status": row["status"],
            "consecutive_failures": int(row["consecutive_failures"]),
            "next_attempt_at": row["next_attempt_at"],
            "last_error": row["last_error"],
            "last_http_status": row["last_http_status"],
            "last_batch_first_sequence": row["last_batch_first_sequence"],
            "last_batch_last_sequence": row["last_batch_last_sequence"],
            "last_batch_event_count": int(row["last_batch_event_count"]),
            "last_payload_sha256": row["last_payload_sha256"],
            "last_ack_id": row["last_ack_id"],
            "last_ack_confirmed": bool(row["last_ack_confirmed"]),
            "last_success_at": row["last_success_at"],
            "updated_at": row["updated_at"],
        }

    def update_policy(
        self,
        value: AuditExportPolicyUpdate,
        *,
        reset_cursor: int | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE audit_export_policy SET enabled=?,index_name=?,sourcetype=?,
                source=?,host=?,verify_tls=?,ca_bundle=?,use_indexer_ack=?,batch_size=?,
                max_attempts=?,retry_backoff_seconds=?,updated_at=? WHERE id=1""",
                (
                    int(value.enabled),
                    value.index_name,
                    value.sourcetype,
                    value.source,
                    value.host,
                    int(value.verify_tls),
                    value.ca_bundle or "",
                    int(value.use_indexer_ack),
                    value.batch_size,
                    value.max_attempts,
                    value.retry_backoff_seconds,
                    now,
                ),
            )
            if reset_cursor is not None:
                db.execute(
                    """UPDATE audit_export_state SET cursor_sequence=?,status=?,
                    consecutive_failures=0,next_attempt_at=?,last_error='',
                    last_http_status=NULL,updated_at=? WHERE id=1""",
                    (
                        max(int(reset_cursor), 0),
                        "pending" if value.enabled else "disabled",
                        now if value.enabled else None,
                        now,
                    ),
                )
            else:
                db.execute(
                    """UPDATE audit_export_state SET status=?,next_attempt_at=?,
                    consecutive_failures=CASE WHEN ? THEN 0 ELSE consecutive_failures END,
                    last_error=CASE WHEN ? THEN '' ELSE last_error END,updated_at=?
                    WHERE id=1""",
                    (
                        "pending" if value.enabled else "disabled",
                        now if value.enabled else None,
                        int(value.enabled),
                        int(value.enabled),
                        now,
                    ),
                )
        return self.policy()

    def recover_interrupted(self) -> bool:
        now = _now()
        with self._lock, self.connect() as db:
            changed = db.execute(
                """UPDATE audit_export_state SET status='pending',
                next_attempt_at=?,last_error='Process restarted during export; the
                uncommitted cursor will be retried with the same stable event IDs.',
                updated_at=? WHERE id=1 AND status='sending'""",
                (now, now),
            ).rowcount
        return bool(changed)

    def mark_sending(self) -> None:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE audit_export_state SET status='sending',next_attempt_at=NULL,
                updated_at=? WHERE id=1""",
                (now,),
            )

    def mark_idle(self) -> None:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE audit_export_state SET status='idle',next_attempt_at=NULL,
                consecutive_failures=0,last_error='',updated_at=? WHERE id=1""",
                (now,),
            )

    def mark_blocked(self, status: str, error: str) -> None:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE audit_export_state SET status=?,next_attempt_at=NULL,
                last_error=?,updated_at=? WHERE id=1""",
                (status[:40], error[:1000], now),
            )

    def reset_failures(self) -> None:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE audit_export_state SET status='pending',
                consecutive_failures=0,next_attempt_at=?,last_error='',
                last_http_status=NULL,updated_at=? WHERE id=1""",
                (now, now),
            )

    def record_attempt(
        self,
        *,
        first_sequence: int,
        last_sequence: int,
        event_count: int,
        payload_bytes: int,
        payload_sha256: str,
        destination_fingerprint: str,
        outcome: str,
        http_status: int | None,
        ack_id: int | None,
        ack_confirmed: bool,
        error: str,
        started_at: str,
        retryable: bool,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        completed_at = now.isoformat()
        policy = self.policy()
        state = self.state()
        failures = int(state["consecutive_failures"]) + (0 if outcome == "delivered" else 1)
        if outcome == "delivered":
            status = "pending"
            next_attempt_at = completed_at
            cursor = last_sequence
            failures = 0
        elif retryable and failures < int(policy["max_attempts"]):
            status = "retrying"
            delay = int(policy["retry_backoff_seconds"]) * (2 ** max(0, failures - 1))
            next_attempt_at = datetime.fromtimestamp(now.timestamp() + min(delay, 3600), UTC).isoformat()
            cursor = int(state["cursor_sequence"])
        else:
            status = "failed"
            next_attempt_at = None
            cursor = int(state["cursor_sequence"])
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO audit_export_attempts
                (first_sequence,last_sequence,event_count,payload_bytes,payload_sha256,
                destination_fingerprint,outcome,http_status,ack_id,ack_confirmed,error,
                started_at,completed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    first_sequence,
                    last_sequence,
                    event_count,
                    payload_bytes,
                    payload_sha256,
                    destination_fingerprint,
                    outcome[:40],
                    http_status,
                    ack_id,
                    int(ack_confirmed),
                    error[:1000],
                    started_at,
                    completed_at,
                ),
            )
            db.execute(
                """UPDATE audit_export_state SET cursor_sequence=?,status=?,
                consecutive_failures=?,next_attempt_at=?,last_error=?,
                last_http_status=?,last_batch_first_sequence=?,
                last_batch_last_sequence=?,last_batch_event_count=?,
                last_payload_sha256=?,last_ack_id=?,last_ack_confirmed=?,
                last_success_at=?,updated_at=? WHERE id=1""",
                (
                    cursor,
                    status,
                    failures,
                    next_attempt_at,
                    error[:1000],
                    http_status,
                    first_sequence,
                    last_sequence,
                    event_count,
                    payload_sha256,
                    ack_id,
                    int(ack_confirmed),
                    completed_at if outcome == "delivered" else state["last_success_at"],
                    completed_at,
                ),
            )
        return self.state()

    def attempts(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM audit_export_attempts
                ORDER BY id DESC LIMIT ?""",
                (min(max(limit, 1), 100),),
            ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "first_sequence": int(row["first_sequence"]),
                "last_sequence": int(row["last_sequence"]),
                "event_count": int(row["event_count"]),
                "payload_bytes": int(row["payload_bytes"]),
                "payload_sha256": row["payload_sha256"],
                "destination_fingerprint": row["destination_fingerprint"],
                "outcome": row["outcome"],
                "http_status": row["http_status"],
                "ack_id": row["ack_id"],
                "ack_confirmed": bool(row["ack_confirmed"]),
                "error": row["error"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
            }
            for row in rows
        ]

    def operations_policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM audit_operations_policy WHERE id=1").fetchone()
        assert row is not None
        return {
            "retention_days": int(row["retention_days"]),
            "deduplication_mode": row["deduplication_mode"],
            "expected_export_lag_minutes": int(row["expected_export_lag_minutes"]),
            "source_silence_minutes": int(row["source_silence_minutes"]),
            "denied_request_threshold": int(row["denied_request_threshold"]),
            "dashboard_earliest": row["dashboard_earliest"],
            "updated_at": row["updated_at"],
        }

    def update_operations_policy(self, value: AuditOperationsPolicyUpdate) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE audit_operations_policy SET retention_days=?,
                deduplication_mode=?,expected_export_lag_minutes=?,
                source_silence_minutes=?,denied_request_threshold=?,
                dashboard_earliest=?,updated_at=? WHERE id=1""",
                (
                    value.retention_days,
                    value.deduplication_mode,
                    value.expected_export_lag_minutes,
                    value.source_silence_minutes,
                    value.denied_request_threshold,
                    value.dashboard_earliest,
                    now,
                ),
            )
        return self.operations_policy()

    def record_operations_export(
        self,
        *,
        export_id: str,
        filename: str,
        archive_sha256: str,
        manifest_sha256: str,
        policy_sha256: str,
        destination_fingerprint: str,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO audit_operations_exports
                (id,filename,archive_sha256,manifest_sha256,policy_sha256,
                destination_fingerprint,created_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    export_id,
                    filename,
                    archive_sha256,
                    manifest_sha256,
                    policy_sha256,
                    destination_fingerprint,
                    created_at,
                ),
            )
        return {
            "id": export_id,
            "filename": filename,
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
            "policy_sha256": policy_sha256,
            "destination_fingerprint": destination_fingerprint,
            "created_at": created_at,
        }

    def operations_exports(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM audit_operations_exports
                ORDER BY created_at DESC LIMIT ?""",
                (min(max(limit, 1), 100),),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "filename": row["filename"],
                "archive_sha256": row["archive_sha256"],
                "manifest_sha256": row["manifest_sha256"],
                "policy_sha256": row["policy_sha256"],
                "destination_fingerprint": row["destination_fingerprint"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def record_operations_reconciliation(
        self,
        *,
        reconciliation_id: str,
        status: str,
        policy_sha256: str,
        destination_fingerprint: str,
        export_id: str,
        manifest_sha256: str,
        connection_alias: str,
        connection_fingerprint: str,
        tenant_scope_id: str,
        snapshot_sha256: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        observed_at = str(snapshot.get("observed_at") or _now())
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO audit_operations_reconciliations
                (id,status,policy_sha256,destination_fingerprint,export_id,
                manifest_sha256,connection_alias,connection_fingerprint,
                tenant_scope_id,snapshot_sha256,snapshot,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    reconciliation_id,
                    status[:40],
                    policy_sha256,
                    destination_fingerprint,
                    export_id,
                    manifest_sha256,
                    connection_alias,
                    connection_fingerprint,
                    tenant_scope_id,
                    snapshot_sha256,
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str),
                    observed_at,
                ),
            )
        result = self.operations_reconciliation(reconciliation_id)
        assert result is not None
        return result

    def operations_reconciliation(self, reconciliation_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM audit_operations_reconciliations WHERE id=?",
                (reconciliation_id,),
            ).fetchone()
        return self._operations_reconciliation(row) if row else None

    def operations_reconciliations(
        self,
        limit: int = 20,
        allowed_connection_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        requested = min(max(limit, 1), 100)
        if allowed_connection_ids is not None and not allowed_connection_ids:
            return []
        with self.connect() as db:
            if allowed_connection_ids is None:
                rows = db.execute(
                    """SELECT * FROM audit_operations_reconciliations
                    ORDER BY observed_at DESC LIMIT ?""",
                    (requested,),
                ).fetchall()
            else:
                aliases = sorted(allowed_connection_ids)
                placeholders = ",".join("?" for _ in aliases)
                rows = db.execute(
                    f"""SELECT * FROM audit_operations_reconciliations
                    WHERE connection_alias IN ({placeholders})
                    ORDER BY observed_at DESC LIMIT ?""",
                    (*aliases, requested),
                ).fetchall()
        values = [self._operations_reconciliation(row) for row in rows]
        return values

    @staticmethod
    def _operations_reconciliation(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "status": row["status"],
            "policy_sha256": row["policy_sha256"],
            "destination_fingerprint": row["destination_fingerprint"],
            "export_id": row["export_id"],
            "manifest_sha256": row["manifest_sha256"],
            "connection_alias": row["connection_alias"],
            "connection_fingerprint": row["connection_fingerprint"],
            "tenant_scope_id": row["tenant_scope_id"],
            "snapshot_sha256": row["snapshot_sha256"],
            "snapshot": json.loads(row["snapshot"]),
            "observed_at": row["observed_at"],
        }
