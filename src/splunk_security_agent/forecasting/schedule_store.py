from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import (
    TimeSeriesReviewDecision,
    TimeSeriesScheduleCreate,
    TimeSeriesScheduleUpdate,
)

GLOBAL_MAX_RUNS_PER_DAY = 24


def _now() -> datetime:
    return datetime.now(UTC)


class TimeSeriesScheduleStore:
    """Durable shadow-forecast schedules, attempts, progress, and analyst reviews."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS time_series_schedules (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    archived INTEGER NOT NULL DEFAULT 0,
                    interval_minutes INTEGER NOT NULL,
                    max_runs_per_day INTEGER NOT NULL,
                    seasonal_comparison INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    next_run_at TEXT,
                    last_run_at TEXT
                );
                CREATE TABLE IF NOT EXISTS time_series_schedule_attempts (
                    id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    trigger TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    label TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    error TEXT NOT NULL,
                    experiment_run_id TEXT NOT NULL,
                    run_fingerprint TEXT NOT NULL,
                    recovery_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(schedule_id) REFERENCES time_series_schedules(id)
                );
                CREATE TABLE IF NOT EXISTS time_series_schedule_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempt_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    label TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    metrics_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(attempt_id) REFERENCES time_series_schedule_attempts(id)
                );
                CREATE TABLE IF NOT EXISTS time_series_schedule_reviews (
                    id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL UNIQUE,
                    experiment_run_id TEXT NOT NULL,
                    run_fingerprint TEXT NOT NULL,
                    comparison_decision TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewed_by TEXT NOT NULL DEFAULT '',
                    review_note TEXT NOT NULL DEFAULT '',
                    reviewed_at TEXT,
                    FOREIGN KEY(schedule_id) REFERENCES time_series_schedules(id),
                    FOREIGN KEY(attempt_id) REFERENCES time_series_schedule_attempts(id)
                );
                CREATE INDEX IF NOT EXISTS idx_time_series_schedules_due
                    ON time_series_schedules(enabled,archived,next_run_at);
                CREATE INDEX IF NOT EXISTS idx_time_series_attempts_status
                    ON time_series_schedule_attempts(status,created_at);
                CREATE INDEX IF NOT EXISTS idx_time_series_attempts_schedule
                    ON time_series_schedule_attempts(schedule_id,created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_time_series_reviews_state
                    ON time_series_schedule_reviews(state,created_at DESC);
                """
            )

    def create(self, value: TimeSeriesScheduleCreate, *, actor: str) -> dict[str, Any]:
        schedule_id = str(uuid4())
        now = _now()
        next_run = now + timedelta(minutes=value.interval_minutes) if value.enabled else None
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO time_series_schedules
                (id,title,request_json,enabled,archived,interval_minutes,max_runs_per_day,
                seasonal_comparison,created_by,created_at,updated_at,next_run_at,last_run_at)
                VALUES (?,?,?,?,0,?,?,?,?,?,?,?,NULL)""",
                (
                    schedule_id,
                    value.title.strip(),
                    json.dumps(value.request.model_dump(mode="json"), sort_keys=True),
                    int(value.enabled),
                    value.interval_minutes,
                    value.max_runs_per_day,
                    int(value.seasonal_comparison),
                    actor[:160] or "local-operator",
                    now.isoformat(),
                    now.isoformat(),
                    next_run.isoformat() if next_run else None,
                ),
            )
        schedule = self.get(schedule_id)
        assert schedule is not None
        return schedule

    def get(self, schedule_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM time_series_schedules WHERE id=?",
                (schedule_id,),
            ).fetchone()
        return self._schedule(row) if row else None

    def list(self, *, include_archived: bool = False) -> list[dict[str, Any]]:
        where = "" if include_archived else "WHERE archived=0"
        with self.connect() as db:
            rows = db.execute(
                f"""SELECT * FROM time_series_schedules {where}
                ORDER BY archived,created_at DESC"""
            ).fetchall()
        return [self._schedule(row) for row in rows]

    def update(
        self,
        schedule_id: str,
        value: TimeSeriesScheduleUpdate,
    ) -> dict[str, Any] | None:
        current = self.get(schedule_id)
        if current is None or current["archived"]:
            return None
        values = value.model_dump(exclude_none=True)
        expected = values.pop("expected_updated_at")
        title = str(values.get("title", current["title"])).strip()
        request = values.get("request", current["request"])
        if hasattr(request, "model_dump"):
            request = request.model_dump(mode="json")
        enabled = bool(values.get("enabled", current["enabled"]))
        interval = int(values.get("interval_minutes", current["interval_minutes"]))
        daily = int(values.get("max_runs_per_day", current["max_runs_per_day"]))
        seasonal = bool(values.get("seasonal_comparison", current["seasonal_comparison"]))
        now = _now()
        reschedule = (
            enabled != current["enabled"]
            or interval != current["interval_minutes"]
            or not current["next_run_at"]
        )
        next_run = (
            (now + timedelta(minutes=interval)).isoformat()
            if enabled and reschedule
            else current["next_run_at"]
            if enabled
            else None
        )
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE time_series_schedules SET title=?,request_json=?,enabled=?,
                interval_minutes=?,max_runs_per_day=?,seasonal_comparison=?,updated_at=?,
                next_run_at=? WHERE id=? AND updated_at=? AND archived=0""",
                (
                    title,
                    json.dumps(request, sort_keys=True),
                    int(enabled),
                    interval,
                    daily,
                    int(seasonal),
                    now.isoformat(),
                    next_run,
                    schedule_id,
                    expected,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("The schedule changed; refresh before applying this update")
        return self.get(schedule_id)

    def archive(self, schedule_id: str, *, expected_updated_at: str) -> dict[str, Any] | None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            current = db.execute(
                "SELECT * FROM time_series_schedules WHERE id=?",
                (schedule_id,),
            ).fetchone()
            if current is None:
                return None
            cursor = db.execute(
                """UPDATE time_series_schedules SET archived=1,enabled=0,next_run_at=NULL,
                updated_at=? WHERE id=? AND updated_at=? AND archived=0""",
                (now, schedule_id, expected_updated_at),
            )
            if cursor.rowcount != 1:
                raise ValueError("The schedule changed; refresh before archiving it")
        return self.get(schedule_id)

    def due(self) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM time_series_schedules
                WHERE enabled=1 AND archived=0 AND next_run_at IS NOT NULL AND next_run_at<=?
                ORDER BY next_run_at LIMIT 1""",
                (_now().isoformat(),),
            ).fetchone()
        return self._schedule(row) if row else None

    def active_attempt(self) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM time_series_schedule_attempts
                WHERE status IN ('queued','running') ORDER BY created_at LIMIT 1"""
            ).fetchone()
        return self._attempt(row) if row else None

    def enqueue(self, schedule_id: str, *, trigger: str) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT * FROM time_series_schedules WHERE id=? AND archived=0",
                (schedule_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown shadow forecast schedule: {schedule_id}")
            schedule = self._schedule(row)
            if trigger == "scheduled" and not schedule["enabled"]:
                raise ValueError("This shadow forecast schedule is paused")
            active = db.execute(
                """SELECT id FROM time_series_schedule_attempts
                WHERE status IN ('queued','running') LIMIT 1"""
            ).fetchone()
            if active:
                raise ValueError("Another shadow forecast is already queued or running")
            day = _now().date().isoformat()
            schedule_count = db.execute(
                """SELECT COUNT(*) AS count FROM time_series_schedule_attempts
                WHERE schedule_id=? AND substr(created_at,1,10)=?""",
                (schedule_id, day),
            ).fetchone()
            global_count = db.execute(
                """SELECT COUNT(*) AS count FROM time_series_schedule_attempts
                WHERE substr(created_at,1,10)=?""",
                (day,),
            ).fetchone()
            if int(schedule_count["count"]) >= schedule["max_runs_per_day"]:
                raise ValueError(
                    f"This schedule reached its {schedule['max_runs_per_day']}-run UTC daily budget"
                )
            if int(global_count["count"]) >= GLOBAL_MAX_RUNS_PER_DAY:
                raise ValueError(
                    f"The global {GLOBAL_MAX_RUNS_PER_DAY}-run UTC daily shadow budget was reached"
                )
            now = _now()
            attempt_id = str(uuid4())
            db.execute(
                """INSERT INTO time_series_schedule_attempts
                (id,schedule_id,trigger,status,phase,progress,label,detail,metrics_json,
                error,experiment_run_id,run_fingerprint,recovery_count,created_at,
                started_at,completed_at,updated_at)
                VALUES (?,?,?,'queued','schedule:queued',0,
                'Shadow forecast queued','Waiting for the single local forecast lane.','{}',
                '','','',0,?,NULL,NULL,?)""",
                (attempt_id, schedule_id, trigger, now.isoformat(), now.isoformat()),
            )
            self._insert_event(
                db,
                attempt_id,
                {
                    "phase": "schedule:queued",
                    "label": "Shadow forecast queued",
                    "detail": "Waiting for the single local forecast lane.",
                    "status": "running",
                    "progress": 0,
                    "metrics": {"trigger": trigger},
                },
            )
            if trigger == "scheduled":
                db.execute(
                    """UPDATE time_series_schedules SET next_run_at=?,updated_at=?
                    WHERE id=?""",
                    (
                        (now + timedelta(minutes=schedule["interval_minutes"])).isoformat(),
                        now.isoformat(),
                        schedule_id,
                    ),
                )
        attempt = self.attempt(attempt_id)
        assert attempt is not None
        return attempt

    def defer_due(self, schedule_id: str) -> None:
        schedule = self.get(schedule_id)
        if not schedule:
            return
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE time_series_schedules SET next_run_at=?,updated_at=?
                WHERE id=? AND enabled=1 AND archived=0""",
                (
                    (now + timedelta(minutes=schedule["interval_minutes"])).isoformat(),
                    now.isoformat(),
                    schedule_id,
                ),
            )

    def next_queued(self) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM time_series_schedule_attempts
                WHERE status='queued' ORDER BY created_at LIMIT 1"""
            ).fetchone()
        return self._attempt(row) if row else None

    def attempt(self, attempt_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM time_series_schedule_attempts WHERE id=?",
                (attempt_id,),
            ).fetchone()
        return self._attempt(row) if row else None

    def attempts(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM time_series_schedule_attempts
                ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        return [self._attempt(row) for row in rows]

    def events(self, attempt_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM time_series_schedule_events
                WHERE attempt_id=? ORDER BY id""",
                (attempt_id,),
            ).fetchall()
        return [self._event(row) for row in rows]

    def mark_running(self, attempt_id: str) -> dict[str, Any] | None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE time_series_schedule_attempts SET status='running',
                phase='schedule:preflight',label='Validating schedule authority and runtime',
                detail='No Splunk query runs until access and local inference are ready.',
                progress=2,started_at=?,updated_at=? WHERE id=? AND status='queued'""",
                (now, now, attempt_id),
            )
            if cursor.rowcount != 1:
                return None
            self._insert_event(
                db,
                attempt_id,
                {
                    "phase": "schedule:preflight",
                    "label": "Validating schedule authority and runtime",
                    "detail": "No Splunk query runs until access and local inference are ready.",
                    "status": "running",
                    "progress": 2,
                    "metrics": {},
                },
            )
        return self.attempt(attempt_id)

    def update_progress(self, attempt_id: str, event: dict[str, Any]) -> None:
        progress = max(0, min(int(event.get("progress", 0)), 99))
        now = _now().isoformat()
        metrics = event.get("metrics") or {}
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE time_series_schedule_attempts SET phase=?,progress=?,label=?,
                detail=?,metrics_json=?,updated_at=? WHERE id=? AND status='running'""",
                (
                    str(event.get("phase") or "forecast:working")[:120],
                    progress,
                    str(event.get("label") or "Forecasting")[:500],
                    str(event.get("detail") or "")[:4000],
                    json.dumps(metrics, sort_keys=True, default=str),
                    now,
                    attempt_id,
                ),
            )
            self._insert_event(db, attempt_id, {**event, "progress": progress})

    def complete(self, attempt_id: str, result: dict[str, Any]) -> dict[str, Any]:
        experiment = result.get("experiment") or {}
        comparison = experiment.get("comparison") or {}
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT schedule_id FROM time_series_schedule_attempts WHERE id=?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown shadow forecast attempt: {attempt_id}")
            db.execute(
                """UPDATE time_series_schedule_attempts SET status='complete',
                phase='schedule:complete',progress=100,label='Shadow forecast complete',
                detail=?,metrics_json=?,error='',experiment_run_id=?,run_fingerprint=?,
                completed_at=?,updated_at=? WHERE id=? AND status='running'""",
                (
                    (f"Retained experiment {result.get('run_id', '')}; no alert or threshold was changed."),
                    json.dumps(
                        {
                            "comparison": comparison.get("decision", "no-baseline"),
                            "promotion_ready": bool((result.get("promotion_gate") or {}).get("ready")),
                            "network_inference": False,
                        },
                        sort_keys=True,
                    ),
                    str(result.get("run_id") or ""),
                    str(experiment.get("run_fingerprint") or ""),
                    now,
                    now,
                    attempt_id,
                ),
            )
            db.execute(
                """UPDATE time_series_schedules SET last_run_at=?,updated_at=?
                WHERE id=?""",
                (now, now, row["schedule_id"]),
            )
            self._insert_event(
                db,
                attempt_id,
                {
                    "phase": "schedule:complete",
                    "label": "Shadow forecast complete",
                    "detail": "Experiment retained for analyst comparison; no alert was created.",
                    "status": "complete",
                    "progress": 100,
                    "metrics": {
                        "comparison": comparison.get("decision", "no-baseline"),
                        "network_inference": False,
                    },
                },
            )
            if experiment.get("run_fingerprint") and comparison.get("decision") in {
                "no-baseline",
                "review",
                "material-drift",
            }:
                reasons = list(comparison.get("reasons") or [])
                db.execute(
                    """INSERT OR IGNORE INTO time_series_schedule_reviews
                    (id,schedule_id,attempt_id,experiment_run_id,run_fingerprint,
                    comparison_decision,summary,reasons_json,state,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        str(uuid4()),
                        row["schedule_id"],
                        attempt_id,
                        str(result.get("run_id") or ""),
                        str(experiment["run_fingerprint"]),
                        str(comparison.get("decision") or "no-baseline"),
                        self._review_summary(comparison),
                        json.dumps(reasons, sort_keys=True),
                        "pending",
                        now,
                    ),
                )
        completed = self.attempt(attempt_id)
        assert completed is not None
        return completed

    def fail(self, attempt_id: str, error: str) -> dict[str, Any] | None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE time_series_schedule_attempts SET status='error',
                phase='schedule:error',label='Shadow forecast stopped',detail=?,error=?,
                completed_at=?,updated_at=? WHERE id=? AND status IN ('queued','running')""",
                (str(error)[:4000], str(error)[:4000], now, now, attempt_id),
            )
            self._insert_event(
                db,
                attempt_id,
                {
                    "phase": "schedule:error",
                    "label": "Shadow forecast stopped",
                    "detail": str(error)[:4000],
                    "status": "error",
                    "progress": 100,
                    "metrics": {},
                },
            )
        return self.attempt(attempt_id)

    def requeue_for_restart(self, attempt_id: str) -> None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE time_series_schedule_attempts SET status='queued',
                trigger='recovered',phase='schedule:recovered',progress=0,
                label='Recovered after restart',
                detail='The interrupted attempt will restart as a fresh read-only run.',
                recovery_count=recovery_count+1,started_at=NULL,updated_at=?
                WHERE id=? AND status='running'""",
                (now, attempt_id),
            )
            self._insert_event(
                db,
                attempt_id,
                {
                    "phase": "schedule:recovered",
                    "label": "Recovered after restart",
                    "detail": "The interrupted attempt will restart as a fresh read-only run.",
                    "status": "running",
                    "progress": 0,
                    "metrics": {},
                },
            )

    def recover_interrupted(self) -> int:
        with self._lock, self.connect() as db:
            rows = db.execute(
                """SELECT id FROM time_series_schedule_attempts
                WHERE status='running'"""
            ).fetchall()
        for row in rows:
            self.requeue_for_restart(str(row["id"]))
        return len(rows)

    def reviews(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM time_series_schedule_reviews
                ORDER BY state='pending' DESC,created_at DESC LIMIT ?""",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        return [self._review(row) for row in rows]

    def decide_review(
        self,
        review_id: str,
        value: TimeSeriesReviewDecision,
        *,
        actor: str,
    ) -> dict[str, Any] | None:
        state = "acknowledged" if value.decision == "acknowledge" else "dismissed"
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            current = db.execute(
                "SELECT * FROM time_series_schedule_reviews WHERE id=?",
                (review_id,),
            ).fetchone()
            if current is None:
                return None
            if current["state"] != "pending":
                raise ValueError("This shadow forecast review has already been decided")
            if current["run_fingerprint"] != value.expected_run_fingerprint:
                raise ValueError("The reviewed forecast fingerprint does not match")
            cursor = db.execute(
                """UPDATE time_series_schedule_reviews SET state=?,reviewed_by=?,
                review_note=?,reviewed_at=? WHERE id=? AND state='pending'
                AND run_fingerprint=?""",
                (
                    state,
                    actor[:160] or "local-operator",
                    value.note.strip()[:4000],
                    now,
                    review_id,
                    value.expected_run_fingerprint,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("The review changed; refresh before deciding it")
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM time_series_schedule_reviews WHERE id=?",
                (review_id,),
            ).fetchone()
        return self._review(row) if row else None

    def usage_today(self, schedule_id: str = "") -> dict[str, int]:
        day = _now().date().isoformat()
        with self.connect() as db:
            global_row = db.execute(
                """SELECT COUNT(*) AS count FROM time_series_schedule_attempts
                WHERE substr(created_at,1,10)=?""",
                (day,),
            ).fetchone()
            schedule_row = (
                db.execute(
                    """SELECT COUNT(*) AS count FROM time_series_schedule_attempts
                    WHERE schedule_id=? AND substr(created_at,1,10)=?""",
                    (schedule_id, day),
                ).fetchone()
                if schedule_id
                else None
            )
        return {
            "global_runs": int(global_row["count"]),
            "global_limit": GLOBAL_MAX_RUNS_PER_DAY,
            "schedule_runs": int(schedule_row["count"]) if schedule_row else 0,
        }

    def overview(self, limit: int = 30) -> dict[str, Any]:
        schedules = self.list()
        attempts = self.attempts(limit)
        return {
            "schedules": [{**item, "usage_today": self.usage_today(item["id"])} for item in schedules],
            "attempts": [{**item, "events": self.events(item["id"])} for item in attempts],
            "reviews": self.reviews(limit),
            "usage_today": self.usage_today(),
            "contract": {
                "opt_in": True,
                "single_run_concurrency": 1,
                "global_daily_limit": GLOBAL_MAX_RUNS_PER_DAY,
                "missed_intervals_coalesced": True,
                "restart_recovery": "fresh-read-only-retry",
                "automatic_alerting": False,
                "automatic_threshold_change": False,
                "network_inference": False,
            },
        }

    @staticmethod
    def _insert_event(
        db: sqlite3.Connection,
        attempt_id: str,
        event: dict[str, Any],
    ) -> None:
        db.execute(
            """INSERT INTO time_series_schedule_events
            (attempt_id,phase,label,detail,status,progress,metrics_json,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (
                attempt_id,
                str(event.get("phase") or "forecast:working")[:120],
                str(event.get("label") or "Forecasting")[:500],
                str(event.get("detail") or "")[:4000],
                str(event.get("status") or "running")[:40],
                max(0, min(int(event.get("progress", 0)), 100)),
                json.dumps(event.get("metrics") or {}, sort_keys=True, default=str),
                _now().isoformat(),
            ),
        )

    @staticmethod
    def _review_summary(comparison: dict[str, Any]) -> str:
        decision = str(comparison.get("decision") or "no-baseline")
        if decision == "no-baseline":
            return "A shadow forecast has no reviewed comparison baseline."
        if decision == "material-drift":
            return "A shadow forecast materially diverged from its reviewed baseline."
        return "A shadow forecast changed enough to require analyst interpretation."

    @staticmethod
    def _schedule(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "title": row["title"],
            "request": json.loads(row["request_json"]),
            "enabled": bool(row["enabled"]),
            "archived": bool(row["archived"]),
            "interval_minutes": int(row["interval_minutes"]),
            "max_runs_per_day": int(row["max_runs_per_day"]),
            "seasonal_comparison": bool(row["seasonal_comparison"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "next_run_at": row["next_run_at"],
            "last_run_at": row["last_run_at"],
        }

    @staticmethod
    def _attempt(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "schedule_id": row["schedule_id"],
            "trigger": row["trigger"],
            "status": row["status"],
            "phase": row["phase"],
            "progress": int(row["progress"]),
            "label": row["label"],
            "detail": row["detail"],
            "metrics": json.loads(row["metrics_json"]),
            "error": row["error"],
            "experiment_run_id": row["experiment_run_id"],
            "run_fingerprint": row["run_fingerprint"],
            "recovery_count": int(row["recovery_count"]),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "attempt_id": row["attempt_id"],
            "phase": row["phase"],
            "label": row["label"],
            "detail": row["detail"],
            "status": row["status"],
            "progress": int(row["progress"]),
            "metrics": json.loads(row["metrics_json"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _review(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "schedule_id": row["schedule_id"],
            "attempt_id": row["attempt_id"],
            "experiment_run_id": row["experiment_run_id"],
            "run_fingerprint": row["run_fingerprint"],
            "comparison_decision": row["comparison_decision"],
            "summary": row["summary"],
            "reasons": json.loads(row["reasons_json"]),
            "state": row["state"],
            "created_at": row["created_at"],
            "reviewed_by": row["reviewed_by"],
            "review_note": row["review_note"],
            "reviewed_at": row["reviewed_at"],
        }
