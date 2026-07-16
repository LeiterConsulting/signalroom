from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import AssurancePolicyUpdate, AssuranceRunRecord


def _now() -> datetime:
    return datetime.now(UTC)


class AssuranceStore:
    """Durable policy, run, event, and notification state for continuous assurance."""

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
        now = _now().isoformat()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS assurance_policy (
                    id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL,
                    interval_minutes INTEGER NOT NULL, discovery_depth TEXT NOT NULL,
                    max_splunk_calls_per_run INTEGER NOT NULL, max_runs_per_day INTEGER NOT NULL,
                    notify_on_drift INTEGER NOT NULL, notify_on_high_findings INTEGER NOT NULL,
                    next_run_at TEXT, last_scheduled_at TEXT, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assurance_runs (
                    id TEXT PRIMARY KEY, trigger TEXT NOT NULL, depth TEXT NOT NULL,
                    status TEXT NOT NULL, phase TEXT NOT NULL, progress INTEGER NOT NULL,
                    label TEXT NOT NULL, detail TEXT NOT NULL, metrics TEXT NOT NULL,
                    summary TEXT NOT NULL, error TEXT NOT NULL, call_budget INTEGER NOT NULL,
                    calls_used INTEGER NOT NULL, cancel_requested INTEGER NOT NULL,
                    recovery_count INTEGER NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_assurance_runs_status_created
                    ON assurance_runs(status, created_at);
                CREATE TABLE IF NOT EXISTS assurance_run_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                    phase TEXT NOT NULL, label TEXT NOT NULL, detail TEXT NOT NULL,
                    status TEXT NOT NULL, progress INTEGER NOT NULL, metrics TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES assurance_runs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_assurance_events_run
                    ON assurance_run_events(run_id, id DESC);
                CREATE TABLE IF NOT EXISTS assurance_notifications (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, severity TEXT NOT NULL,
                    category TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_assurance_notifications_state
                    ON assurance_notifications(acknowledged, created_at DESC);
                """
            )
            db.execute(
                """INSERT OR IGNORE INTO assurance_policy
                (id,enabled,interval_minutes,discovery_depth,max_splunk_calls_per_run,
                max_runs_per_day,notify_on_drift,notify_on_high_findings,next_run_at,
                last_scheduled_at,updated_at) VALUES (1,0,360,'standard',12,4,1,1,NULL,NULL,?)""",
                (now,),
            )

    def policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM assurance_policy WHERE id = 1").fetchone()
        assert row is not None
        return self._policy(row)

    def update_policy(self, value: AssurancePolicyUpdate) -> dict[str, Any]:
        now = _now()
        current = self.policy()
        reset_schedule = (
            value.enabled
            and (
                not current["enabled"]
                or value.interval_minutes != current["interval_minutes"]
            )
        )
        next_run_at = current.get("next_run_at")
        if not value.enabled:
            next_run_at = None
        elif reset_schedule or not next_run_at:
            next_run_at = (now + timedelta(minutes=value.interval_minutes)).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_policy SET enabled=?, interval_minutes=?,
                discovery_depth=?, max_splunk_calls_per_run=?, max_runs_per_day=?,
                notify_on_drift=?, notify_on_high_findings=?, next_run_at=?, updated_at=?
                WHERE id=1""",
                (
                    int(value.enabled),
                    value.interval_minutes,
                    value.discovery_depth,
                    value.max_splunk_calls_per_run,
                    value.max_runs_per_day,
                    int(value.notify_on_drift),
                    int(value.notify_on_high_findings),
                    next_run_at,
                    now.isoformat(),
                ),
            )
        return self.policy()

    def advance_schedule(self, *, scheduled_at: datetime | None = None) -> dict[str, Any]:
        policy = self.policy()
        now = scheduled_at or _now()
        next_run = now + timedelta(minutes=policy["interval_minutes"])
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_policy SET last_scheduled_at=?, next_run_at=?, updated_at=?
                WHERE id=1""",
                (now.isoformat(), next_run.isoformat(), now.isoformat()),
            )
        return self.policy()

    def create_run(self, trigger: str, depth: str, call_budget: int) -> AssuranceRunRecord:
        run_id = str(uuid4())
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO assurance_runs
                (id,trigger,depth,status,phase,progress,label,detail,metrics,summary,error,
                call_budget,calls_used,cancel_requested,recovery_count,created_at,started_at,
                completed_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    trigger,
                    depth,
                    "queued",
                    "queued",
                    0,
                    "Queued for continuous assurance",
                    "Waiting for the single-instance assurance worker.",
                    "{}",
                    "{}",
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
        result = self.get_run(run_id)
        assert result is not None
        return result

    def get_run(self, run_id: str) -> AssuranceRunRecord | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM assurance_runs WHERE id=?", (run_id,)).fetchone()
        return self._run(row) if row else None

    def list_runs(self, limit: int = 20) -> list[AssuranceRunRecord]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM assurance_runs ORDER BY
                CASE status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,
                created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._run(row) for row in rows]

    def active_run(self) -> AssuranceRunRecord | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM assurance_runs WHERE status IN ('running','queued')
                ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, created_at LIMIT 1"""
            ).fetchone()
        return self._run(row) if row else None

    def next_queued(self) -> AssuranceRunRecord | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assurance_runs WHERE status='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
        return self._run(row) if row else None

    def mark_running(self, run_id: str) -> AssuranceRunRecord | None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE assurance_runs SET status='running', phase='starting', progress=1,
                label='Starting continuous assurance', detail='Loading the bounded read-only plan.',
                started_at=?, completed_at=NULL, error='', cancel_requested=0, updated_at=?
                WHERE id=? AND status='queued'""",
                (now, now, run_id),
            )
        return self.get_run(run_id) if result.rowcount else None

    def update_progress(self, run_id: str, event: dict[str, Any], calls_used: int) -> None:
        now = _now().isoformat()
        metrics = event.get("metrics") if isinstance(event.get("metrics"), dict) else {}
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_runs SET phase=?, progress=?, label=?, detail=?, metrics=?,
                calls_used=?, updated_at=? WHERE id=? AND status='running'""",
                (
                    str(event.get("phase") or "working")[:120],
                    max(0, min(100, int(event.get("progress", 0)))),
                    str(event.get("label") or "Working")[:500],
                    str(event.get("detail") or "")[:4000],
                    json.dumps(metrics, default=str),
                    calls_used,
                    now,
                    run_id,
                ),
            )
            db.execute(
                """INSERT INTO assurance_run_events
                (run_id,phase,label,detail,status,progress,metrics,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    str(event.get("phase") or "working")[:120],
                    str(event.get("label") or "Working")[:500],
                    str(event.get("detail") or "")[:4000],
                    str(event.get("status") or "running")[:40],
                    max(0, min(100, int(event.get("progress", 0)))),
                    json.dumps(metrics, default=str),
                    now,
                ),
            )

    def complete_run(
        self, run_id: str, status: str, summary: dict[str, Any], calls_used: int
    ) -> AssuranceRunRecord | None:
        now = _now().isoformat()
        label = {
            "complete": "Continuous assurance complete",
            "partial": "Continuous assurance completed with collection gaps",
            "budget-blocked": "Continuous assurance reached its Splunk-call budget",
        }.get(status, "Continuous assurance finished")
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_runs SET status=?, phase='complete', progress=100, label=?,
                detail=?, summary=?, calls_used=?, completed_at=?, updated_at=? WHERE id=?""",
                (
                    status,
                    label,
                    str(summary.get("headline") or "The durable result is ready.")[:4000],
                    json.dumps(summary, default=str),
                    calls_used,
                    now,
                    now,
                    run_id,
                ),
            )
        return self.get_run(run_id)

    def fail_run(self, run_id: str, status: str, error: str, calls_used: int) -> None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_runs SET status=?, phase=?, label=?, detail=?, error=?,
                calls_used=?, completed_at=?, updated_at=? WHERE id=?""",
                (
                    status,
                    status,
                    "Continuous assurance cancelled" if status == "cancelled" else "Assurance run failed",
                    error[:4000],
                    error[:4000] if status != "cancelled" else "",
                    calls_used,
                    now,
                    now,
                    run_id,
                ),
            )

    def requeue_for_restart(self, run_id: str) -> None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_runs SET status='queued', trigger='recovered', phase='recovered',
                progress=0, label='Recovered after restart', detail=?, started_at=NULL,
                recovery_count=recovery_count+1, updated_at=? WHERE id=?""",
                (
                    (
                        "The read-only run was interrupted during shutdown and will resume "
                        "from a fresh collection."
                    ),
                    now,
                    run_id,
                ),
            )

    def request_cancel(self, run_id: str) -> AssuranceRunRecord | None:
        current = self.get_run(run_id)
        if current is None:
            return None
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            if current.status == "queued":
                db.execute(
                    """UPDATE assurance_runs SET status='cancelled', phase='cancelled',
                    label='Continuous assurance cancelled', detail='Cancelled before execution.',
                    cancel_requested=1, completed_at=?, updated_at=? WHERE id=?""",
                    (now, now, run_id),
                )
            elif current.status == "running":
                db.execute(
                    """UPDATE assurance_runs SET cancel_requested=1,
                    detail='Cancellation requested; stopping active local and Splunk work.', updated_at=?
                    WHERE id=?""",
                    (now, run_id),
                )
        return self.get_run(run_id)

    def recover_interrupted(self) -> int:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            cancelled = db.execute(
                """UPDATE assurance_runs SET status='cancelled', phase='cancelled',
                label='Continuous assurance cancelled', detail='Cancellation persisted across restart.',
                completed_at=?, updated_at=? WHERE status='running' AND cancel_requested=1""",
                (now, now),
            ).rowcount
            recovered = db.execute(
                """UPDATE assurance_runs SET status='queued', trigger='recovered', phase='recovered',
                progress=0, label='Recovered after restart', detail=?, started_at=NULL,
                recovery_count=recovery_count+1, updated_at=?
                WHERE status='running' AND cancel_requested=0""",
                (
                    "The prior process stopped mid-run; a fresh read-only collection is queued.",
                    now,
                ),
            ).rowcount
        return int(cancelled + recovered)

    def events(self, run_id: str, limit: int = 12) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM assurance_run_events WHERE run_id=?
                ORDER BY id DESC LIMIT ?""",
                (run_id, limit),
            ).fetchall()
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
            for row in reversed(rows)
        ]

    def add_notification(
        self, run_id: str, severity: str, category: str, title: str, detail: str
    ) -> dict[str, Any]:
        bounded_title = title[:240]
        bounded_detail = detail[:4000]
        with self.connect() as db:
            existing = db.execute(
                """SELECT * FROM assurance_notifications WHERE acknowledged=0
                AND severity=? AND category=? AND title=? AND detail=?
                ORDER BY created_at DESC LIMIT 1""",
                (severity, category, bounded_title, bounded_detail),
            ).fetchone()
        if existing:
            return self._notification(existing)
        notification_id = str(uuid4())
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO assurance_notifications
                (id,run_id,severity,category,title,detail,acknowledged,created_at)
                VALUES (?,?,?,?,?,?,0,?)""",
                (
                    notification_id,
                    run_id,
                    severity,
                    category,
                    bounded_title,
                    bounded_detail,
                    now,
                ),
            )
        return self.get_notification(notification_id) or {}

    def get_notification(self, notification_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assurance_notifications WHERE id=?", (notification_id,)
            ).fetchone()
        return self._notification(row) if row else None

    def notifications(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM assurance_notifications
                ORDER BY acknowledged, created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._notification(row) for row in rows]

    def acknowledge(self, notification_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as db:
            db.execute(
                "UPDATE assurance_notifications SET acknowledged=1 WHERE id=?",
                (notification_id,),
            )
        return self.get_notification(notification_id)

    def usage_today(self) -> dict[str, int]:
        start = _now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        with self.connect() as db:
            row = db.execute(
                """SELECT COALESCE(SUM(CASE WHEN status NOT IN ('cancelled','queued')
                OR calls_used>0 THEN 1 ELSE 0 END),0) AS runs,
                COALESCE(SUM(calls_used),0) AS calls
                FROM assurance_runs WHERE created_at>=?""",
                (start,),
            ).fetchone()
        return {"runs": int(row["runs"]), "splunk_calls": int(row["calls"])}

    @staticmethod
    def _policy(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "enabled": bool(row["enabled"]),
            "interval_minutes": int(row["interval_minutes"]),
            "discovery_depth": row["discovery_depth"],
            "max_splunk_calls_per_run": int(row["max_splunk_calls_per_run"]),
            "max_runs_per_day": int(row["max_runs_per_day"]),
            "notify_on_drift": bool(row["notify_on_drift"]),
            "notify_on_high_findings": bool(row["notify_on_high_findings"]),
            "next_run_at": row["next_run_at"],
            "last_scheduled_at": row["last_scheduled_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _run(row: sqlite3.Row) -> AssuranceRunRecord:
        return AssuranceRunRecord(
            id=row["id"],
            trigger=row["trigger"],
            depth=row["depth"],
            status=row["status"],
            phase=row["phase"],
            progress=int(row["progress"]),
            label=row["label"],
            detail=row["detail"],
            metrics=json.loads(row["metrics"]),
            summary=json.loads(row["summary"]),
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

    @staticmethod
    def _notification(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "severity": row["severity"],
            "category": row["category"],
            "title": row["title"],
            "detail": row["detail"],
            "acknowledged": bool(row["acknowledged"]),
            "created_at": row["created_at"],
        }
