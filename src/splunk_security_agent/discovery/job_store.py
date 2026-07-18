from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import DiscoveryJobRecord


def _now() -> str:
    return datetime.now(UTC).isoformat()


class DiscoveryJobStore:
    """Durable manual-discovery jobs, progress events, and renderable results."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()
        self.recover_interrupted()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS discovery_jobs (
                    id TEXT PRIMARY KEY, depth TEXT NOT NULL, requested_by TEXT NOT NULL,
                    status TEXT NOT NULL, phase TEXT NOT NULL, progress INTEGER NOT NULL,
                    label TEXT NOT NULL, detail TEXT NOT NULL, metrics TEXT NOT NULL,
                    summary TEXT NOT NULL, result TEXT NOT NULL, result_run_id TEXT NOT NULL,
                    error TEXT NOT NULL, call_budget INTEGER NOT NULL,
                    calls_used INTEGER NOT NULL, cancel_requested INTEGER NOT NULL,
                    recovery_count INTEGER NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_discovery_jobs_status_created
                    ON discovery_jobs(status, created_at);
                CREATE TABLE IF NOT EXISTS discovery_job_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
                    phase TEXT NOT NULL, label TEXT NOT NULL, detail TEXT NOT NULL,
                    status TEXT NOT NULL, progress INTEGER NOT NULL, metrics TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES discovery_jobs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_discovery_job_events_job
                    ON discovery_job_events(job_id, id DESC);
                """
            )

    def create_job(self, depth: str, requested_by: str, call_budget: int) -> DiscoveryJobRecord:
        job_id = str(uuid4())
        now = _now()
        label = "Queued for manual discovery"
        detail = "Waiting for the durable read-only discovery worker."
        with self._lock, self.connect() as db:
            active = db.execute(
                """SELECT id FROM discovery_jobs
                WHERE status IN ('queued','running') LIMIT 1"""
            ).fetchone()
            if active:
                raise ValueError("A manual discovery job is already queued or running")
            db.execute(
                """INSERT INTO discovery_jobs
                (id,depth,requested_by,status,phase,progress,label,detail,metrics,summary,
                result,result_run_id,error,call_budget,calls_used,cancel_requested,
                recovery_count,created_at,started_at,completed_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    depth,
                    requested_by[:120] or "local-operator",
                    "queued",
                    "queued",
                    0,
                    label,
                    detail,
                    "{}",
                    "{}",
                    "{}",
                    "",
                    "",
                    call_budget,
                    0,
                    0,
                    0,
                    now,
                    None,
                    None,
                    now,
                ),
            )
            self._insert_event(
                db,
                job_id,
                {
                    "phase": "queued",
                    "label": label,
                    "detail": detail,
                    "status": "running",
                    "progress": 0,
                    "metrics": {"call_budget": call_budget},
                },
                now,
            )
        result = self.get_job(job_id)
        assert result is not None
        return result

    def get_job(self, job_id: str) -> DiscoveryJobRecord | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM discovery_jobs WHERE id=?", (job_id,)).fetchone()
        return self._job(row) if row else None

    def list_jobs(self, limit: int = 20) -> list[DiscoveryJobRecord]:
        limit = max(1, min(100, int(limit)))
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM discovery_jobs ORDER BY
                CASE status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,
                created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._job(row) for row in rows]

    def active_job(self) -> DiscoveryJobRecord | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM discovery_jobs WHERE status IN ('running','queued')
                ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, created_at LIMIT 1"""
            ).fetchone()
        return self._job(row) if row else None

    def next_queued(self) -> DiscoveryJobRecord | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM discovery_jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
        return self._job(row) if row else None

    def mark_running(self, job_id: str) -> DiscoveryJobRecord | None:
        now = _now()
        label = "Starting manual discovery"
        detail = "Loading the bounded, read-only collection plan."
        with self._lock, self.connect() as db:
            updated = db.execute(
                """UPDATE discovery_jobs SET status='running', phase='starting', progress=1,
                label=?, detail=?, started_at=?, completed_at=NULL, error='',
                cancel_requested=0, updated_at=? WHERE id=? AND status='queued'""",
                (label, detail, now, now, job_id),
            )
            if updated.rowcount:
                self._insert_event(
                    db,
                    job_id,
                    {
                        "phase": "starting",
                        "label": label,
                        "detail": detail,
                        "status": "running",
                        "progress": 1,
                        "metrics": {},
                    },
                    now,
                )
        return self.get_job(job_id) if updated.rowcount else None

    def update_progress(self, job_id: str, event: dict[str, Any], calls_used: int) -> None:
        now = _now()
        metrics = event.get("metrics") if isinstance(event.get("metrics"), dict) else {}
        progress = max(0, min(100, int(event.get("progress", 0))))
        phase = str(event.get("phase") or "working")[:120]
        label = str(event.get("label") or "Working")[:500]
        detail = str(event.get("detail") or "")[:4000]
        status = str(event.get("status") or "running")[:40]
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE discovery_jobs SET phase=?, progress=?, label=?, detail=?,
                metrics=?, calls_used=?, updated_at=?
                WHERE id=? AND status='running'""",
                (
                    phase,
                    progress,
                    label,
                    detail,
                    json.dumps(metrics, default=str),
                    calls_used,
                    now,
                    job_id,
                ),
            )
            self._insert_event(
                db,
                job_id,
                {
                    "phase": phase,
                    "label": label,
                    "detail": detail,
                    "status": status,
                    "progress": progress,
                    "metrics": metrics,
                },
                now,
            )

    def complete_job(
        self,
        job_id: str,
        status: str,
        summary: dict[str, Any],
        result: dict[str, Any] | None,
        calls_used: int,
    ) -> DiscoveryJobRecord | None:
        now = _now()
        label = {
            "complete": "Manual discovery complete",
            "partial": "Manual discovery completed with collection gaps",
            "budget-blocked": "Manual discovery reached its Splunk-call budget",
            "connection-blocked": "Manual discovery blocked by connection readiness",
        }.get(status, "Manual discovery finished")
        detail = str(summary.get("headline") or "The durable result is ready.")[:4000]
        result_value = result or {}
        result_run_id = str(result_value.get("run_id") or summary.get("discovery_run_id") or "")
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE discovery_jobs SET status=?, phase='complete', progress=100,
                label=?, detail=?, summary=?, result=?, result_run_id=?, calls_used=?,
                completed_at=?, updated_at=? WHERE id=?""",
                (
                    status,
                    label,
                    detail,
                    json.dumps(summary, default=str),
                    json.dumps(result_value, default=str),
                    result_run_id,
                    calls_used,
                    now,
                    now,
                    job_id,
                ),
            )
            self._insert_event(
                db,
                job_id,
                {
                    "phase": "complete",
                    "label": label,
                    "detail": detail,
                    "status": "complete" if status in {"complete", "partial"} else status,
                    "progress": 100,
                    "metrics": {
                        "splunk_calls": calls_used,
                        **{
                            key: summary[key] for key in ("findings", "collection_failures") if key in summary
                        },
                    },
                },
                now,
            )
        return self.get_job(job_id)

    def fail_job(self, job_id: str, status: str, error: str, calls_used: int) -> DiscoveryJobRecord | None:
        now = _now()
        current = self.get_job(job_id)
        cancelled = status == "cancelled"
        label = "Manual discovery cancelled" if cancelled else "Manual discovery failed"
        detail = str(error)[:4000]
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE discovery_jobs SET status=?, phase=?, label=?, detail=?, error=?,
                calls_used=?, completed_at=?, updated_at=? WHERE id=?""",
                (
                    status,
                    status,
                    label,
                    detail,
                    "" if cancelled else detail,
                    calls_used,
                    now,
                    now,
                    job_id,
                ),
            )
            self._insert_event(
                db,
                job_id,
                {
                    "phase": status,
                    "label": label,
                    "detail": detail,
                    "status": status,
                    "progress": current.progress if current else 0,
                    "metrics": {"splunk_calls": calls_used},
                },
                now,
            )
        return self.get_job(job_id)

    def request_cancel(self, job_id: str) -> DiscoveryJobRecord | None:
        current = self.get_job(job_id)
        if current is None:
            return None
        now = _now()
        with self._lock, self.connect() as db:
            if current.status == "queued":
                detail = "Cancelled before execution; no Splunk calls were made."
                db.execute(
                    """UPDATE discovery_jobs SET status='cancelled', phase='cancelled',
                    label='Manual discovery cancelled', detail=?, cancel_requested=1,
                    completed_at=?, updated_at=? WHERE id=?""",
                    (detail, now, now, job_id),
                )
                self._insert_event(
                    db,
                    job_id,
                    {
                        "phase": "cancelled",
                        "label": "Manual discovery cancelled",
                        "detail": detail,
                        "status": "cancelled",
                        "progress": current.progress,
                        "metrics": {"splunk_calls": 0},
                    },
                    now,
                )
            elif current.status == "running":
                db.execute(
                    """UPDATE discovery_jobs SET cancel_requested=1,
                    detail='Cancellation requested; no further Splunk calls will be scheduled.',
                    updated_at=? WHERE id=?""",
                    (now, job_id),
                )
        return self.get_job(job_id)

    def requeue_for_restart(self, job_id: str) -> None:
        now = _now()
        detail = "The read-only run was interrupted during shutdown and will restart from a fresh collection."
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE discovery_jobs SET status='queued', phase='recovered', progress=0,
                label='Recovered after restart', detail=?, started_at=NULL,
                cancel_requested=0, recovery_count=recovery_count+1, updated_at=?
                WHERE id=?""",
                (detail, now, job_id),
            )
            self._insert_event(
                db,
                job_id,
                {
                    "phase": "recovered",
                    "label": "Recovered after restart",
                    "detail": detail,
                    "status": "running",
                    "progress": 0,
                    "metrics": {"restart_recovery": "fresh-read-only-retry"},
                },
                now,
            )

    def recover_interrupted(self) -> int:
        with self._lock, self.connect() as db:
            rows = db.execute(
                """SELECT id,cancel_requested FROM discovery_jobs
                WHERE status='running'"""
            ).fetchall()
        for row in rows:
            if bool(row["cancel_requested"]):
                self.fail_job(
                    row["id"],
                    "cancelled",
                    "Cancellation persisted across restart; no further calls were made.",
                    0,
                )
            else:
                self.requeue_for_restart(row["id"])
        return len(rows)

    def events(self, job_id: str, limit: int = 20, after_id: int = 0) -> list[dict[str, Any]]:
        limit = max(1, min(200, int(limit)))
        with self.connect() as db:
            if after_id:
                rows = db.execute(
                    """SELECT * FROM discovery_job_events
                    WHERE job_id=? AND id>? ORDER BY id LIMIT ?""",
                    (job_id, after_id, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM discovery_job_events WHERE job_id=?
                    ORDER BY id DESC LIMIT ?""",
                    (job_id, limit),
                ).fetchall()
                rows = list(reversed(rows))
        return [
            {
                "id": int(row["id"]),
                "phase": row["phase"],
                "label": row["label"],
                "detail": row["detail"],
                "status": row["status"],
                "progress": int(row["progress"]),
                "metrics": json.loads(row["metrics"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def result(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT result FROM discovery_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        value = json.loads(row["result"])
        return value if value else None

    @staticmethod
    def _insert_event(
        db: sqlite3.Connection,
        job_id: str,
        event: dict[str, Any],
        created_at: str,
    ) -> None:
        db.execute(
            """INSERT INTO discovery_job_events
            (job_id,phase,label,detail,status,progress,metrics,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (
                job_id,
                str(event.get("phase") or "working")[:120],
                str(event.get("label") or "Working")[:500],
                str(event.get("detail") or "")[:4000],
                str(event.get("status") or "running")[:40],
                max(0, min(100, int(event.get("progress", 0)))),
                json.dumps(event.get("metrics") or {}, default=str),
                created_at,
            ),
        )

    @staticmethod
    def _job(row: sqlite3.Row) -> DiscoveryJobRecord:
        return DiscoveryJobRecord(
            id=row["id"],
            depth=row["depth"],
            requested_by=row["requested_by"],
            status=row["status"],
            phase=row["phase"],
            progress=int(row["progress"]),
            label=row["label"],
            detail=row["detail"],
            metrics=json.loads(row["metrics"]),
            summary=json.loads(row["summary"]),
            result_run_id=row["result_run_id"],
            error=row["error"],
            call_budget=int(row["call_budget"]),
            calls_used=int(row["calls_used"]),
            cancel_requested=bool(row["cancel_requested"]),
            recovery_count=int(row["recovery_count"]),
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            updated_at=row["updated_at"],
        )
