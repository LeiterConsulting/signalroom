from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import ValidationTaskCreate, ValidationTaskRecord, ValidationTaskUpdate


class ValidationStore:
    """Restart-safe analyst approval and result state for bounded Splunk validations."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()
        self.recover_interrupted()
        self.expire_due()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS validation_tasks (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, rationale TEXT NOT NULL,
                    spl TEXT NOT NULL, earliest_time TEXT NOT NULL, latest_time TEXT NOT NULL,
                    row_limit INTEGER NOT NULL, evidence_refs TEXT NOT NULL,
                    source_run_id TEXT NOT NULL, source_finding_ref TEXT NOT NULL,
                    case_id TEXT, expires_at TEXT, assurance_package_id TEXT NOT NULL DEFAULT '',
                    approval_scope TEXT NOT NULL DEFAULT 'single-execution',
                    status TEXT NOT NULL, query_fingerprint TEXT NOT NULL,
                    result_count INTEGER NOT NULL DEFAULT 0, result_preview TEXT NOT NULL,
                    artifact_id TEXT NOT NULL, error TEXT NOT NULL,
                    approved_at TEXT, started_at TEXT, completed_at TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_validation_status_updated
                    ON validation_tasks(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_validation_source
                    ON validation_tasks(source_run_id, source_finding_ref);
                """
            )
            columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(validation_tasks)").fetchall()
            }
            migrations = {
                "expires_at": "ALTER TABLE validation_tasks ADD COLUMN expires_at TEXT",
                "assurance_package_id": (
                    "ALTER TABLE validation_tasks ADD COLUMN assurance_package_id "
                    "TEXT NOT NULL DEFAULT ''"
                ),
                "approval_scope": (
                    "ALTER TABLE validation_tasks ADD COLUMN approval_scope "
                    "TEXT NOT NULL DEFAULT 'single-execution'"
                ),
            }
            for name, statement in migrations.items():
                if name not in columns:
                    db.execute(statement)
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_package
                ON validation_tasks(assurance_package_id, status)"""
            )

    def recover_interrupted(self) -> int:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE validation_tasks
                SET status = 'approved', error = ?, started_at = NULL, updated_at = ?
                WHERE status = 'running'""",
                ("Execution was interrupted by a SignalRoom restart; approval was preserved.", now),
            )
        return int(result.rowcount)

    def create(self, value: ValidationTaskCreate) -> ValidationTaskRecord:
        now = datetime.now(UTC).isoformat()
        task_id = str(uuid4())
        fingerprint = self.fingerprint(value.spl, value.earliest_time, value.latest_time, value.row_limit)
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO validation_tasks
                (id,title,rationale,spl,earliest_time,latest_time,row_limit,evidence_refs,
                source_run_id,source_finding_ref,case_id,expires_at,assurance_package_id,
                approval_scope,status,query_fingerprint,result_count,result_preview,artifact_id,error,
                approved_at,started_at,completed_at,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    task_id,
                    value.title.strip(),
                    value.rationale.strip(),
                    value.spl.strip(),
                    value.earliest_time.strip(),
                    value.latest_time.strip(),
                    value.row_limit,
                    json.dumps(sorted(set(value.evidence_refs))),
                    value.source_run_id,
                    value.source_finding_ref,
                    value.case_id,
                    value.expires_at,
                    value.assurance_package_id,
                    value.approval_scope,
                    "draft",
                    fingerprint,
                    0,
                    "[]",
                    "",
                    "",
                    None,
                    None,
                    None,
                    now,
                    now,
                ),
            )
        result = self.get(task_id)
        assert result is not None
        return result

    def list(self, limit: int = 100) -> list[ValidationTaskRecord]:
        self.expire_due()
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM validation_tasks
                ORDER BY CASE status WHEN 'running' THEN 0 WHEN 'approved' THEN 1
                WHEN 'draft' THEN 2 WHEN 'error' THEN 3 WHEN 'expired' THEN 4 ELSE 5 END,
                updated_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._record(row) for row in rows]

    def get(self, task_id: str) -> ValidationTaskRecord | None:
        self.expire_due()
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM validation_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return self._record(row) if row else None

    def update(self, task_id: str, value: ValidationTaskUpdate) -> ValidationTaskRecord | None:
        current = self.get(task_id)
        if current is None:
            return None
        if current.status not in {"draft", "error"}:
            raise ValueError("Only draft or failed validation tasks can be edited")
        fields = value.model_dump(exclude_none=True)
        if not fields:
            return current
        if "evidence_refs" in fields:
            fields["evidence_refs"] = json.dumps(sorted(set(fields["evidence_refs"])))
        merged = current.model_dump()
        merged.update(value.model_dump(exclude_none=True))
        fields.update(
            {
                "status": "draft",
                "approved_at": None,
                "started_at": None,
                "completed_at": None,
                "result_count": 0,
                "result_preview": "[]",
                "artifact_id": "",
                "error": "",
                "query_fingerprint": self.fingerprint(
                    merged["spl"],
                    merged["earliest_time"],
                    merged["latest_time"],
                    merged["row_limit"],
                ),
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        assignments = ", ".join(f"{key} = ?" for key in fields)
        with self._lock, self.connect() as db:
            db.execute(
                f"UPDATE validation_tasks SET {assignments} WHERE id = ?",
                (*fields.values(), task_id),
            )
        return self.get(task_id)

    def approve(self, task_id: str) -> ValidationTaskRecord | None:
        current = self.get(task_id)
        if current is None:
            return None
        if current.status == "expired":
            raise ValueError("This validation draft expired and cannot be approved")
        if current.status not in {"draft", "error", "approved"}:
            raise ValueError("Only draft or failed validation tasks can be approved")
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE validation_tasks SET status = 'approved', approved_at = ?,
                error = '', updated_at = ? WHERE id = ?""",
                (current.approved_at or now, now, task_id),
            )
        return self.get(task_id)

    def mark_running(self, task_id: str) -> ValidationTaskRecord | None:
        self.expire_due()
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE validation_tasks SET status = 'running', started_at = ?,
                completed_at = NULL, error = '', updated_at = ?
                WHERE id = ? AND status = 'approved'""",
                (now, now, task_id),
            )
        return self.get(task_id) if result.rowcount else None

    def complete(
        self, task_id: str, result_count: int, result_preview: list[Any], artifact_id: str
    ) -> ValidationTaskRecord | None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE validation_tasks SET status = 'complete', result_count = ?,
                result_preview = ?, artifact_id = ?, error = '', completed_at = ?, updated_at = ?
                WHERE id = ? AND status = 'running'""",
                (
                    result_count,
                    json.dumps(result_preview, default=str),
                    artifact_id,
                    now,
                    now,
                    task_id,
                ),
            )
        return self.get(task_id) if result.rowcount else None

    def fail(self, task_id: str, error: str) -> ValidationTaskRecord | None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE validation_tasks SET status = 'error', error = ?,
                completed_at = ?, updated_at = ? WHERE id = ?""",
                (error[:4000], now, now, task_id),
            )
        return self.get(task_id)

    def requeue_interrupted(self, task_id: str, reason: str) -> ValidationTaskRecord | None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE validation_tasks SET status = 'approved', error = ?,
                started_at = NULL, updated_at = ? WHERE id = ?""",
                (reason[:4000], now, task_id),
            )
        return self.get(task_id)

    def delete(self, task_id: str) -> bool:
        with self._lock, self.connect() as db:
            result = db.execute(
                "DELETE FROM validation_tasks WHERE id = ? AND status != 'running'", (task_id,)
            )
        return bool(result.rowcount)

    def expire_due(self) -> int:
        """Expire unexecuted assurance drafts without changing completed evidence."""
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE validation_tasks SET status='expired',
                error='The assurance response window expired before execution.', updated_at=?
                WHERE expires_at IS NOT NULL AND expires_at<=?
                AND status IN ('draft','approved','error')""",
                (now, now),
            )
        return int(result.rowcount)

    def find_reusable(self, query_fingerprint: str) -> ValidationTaskRecord | None:
        """Reuse only live, unexecuted work so recurring assurance cannot spam drafts."""
        self.expire_due()
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM validation_tasks WHERE query_fingerprint=?
                AND status IN ('draft','approved','running')
                ORDER BY updated_at DESC LIMIT 1""",
                (query_fingerprint,),
            ).fetchone()
        return self._record(row) if row else None

    @staticmethod
    def fingerprint(spl: str, earliest_time: str, latest_time: str, row_limit: int) -> str:
        payload = json.dumps(
            {
                "spl": spl.strip(),
                "earliest_time": earliest_time.strip(),
                "latest_time": latest_time.strip(),
                "row_limit": row_limit,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _record(row: sqlite3.Row) -> ValidationTaskRecord:
        return ValidationTaskRecord(
            id=row["id"],
            title=row["title"],
            rationale=row["rationale"],
            spl=row["spl"],
            earliest_time=row["earliest_time"],
            latest_time=row["latest_time"],
            row_limit=int(row["row_limit"]),
            evidence_refs=json.loads(row["evidence_refs"]),
            source_run_id=row["source_run_id"],
            source_finding_ref=row["source_finding_ref"],
            case_id=row["case_id"],
            expires_at=row["expires_at"],
            assurance_package_id=row["assurance_package_id"],
            approval_scope=row["approval_scope"],
            status=row["status"],
            query_fingerprint=row["query_fingerprint"],
            result_count=int(row["result_count"]),
            result_preview=json.loads(row["result_preview"]),
            artifact_id=row["artifact_id"],
            error=row["error"],
            approved_at=row["approved_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
