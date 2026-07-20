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
                CREATE TABLE IF NOT EXISTS assurance_signals (
                    fingerprint TEXT PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL,
                    title TEXT NOT NULL, detail TEXT NOT NULL, subject TEXT NOT NULL,
                    source_ref TEXT NOT NULL, status TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL, consecutive_count INTEGER NOT NULL,
                    first_run_id TEXT NOT NULL, last_run_id TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, resolved_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_assurance_signals_state
                    ON assurance_signals(status, last_seen_at DESC);
                CREATE TABLE IF NOT EXISTS assurance_packages (
                    id TEXT PRIMARY KEY, source_run_id TEXT NOT NULL, severity TEXT NOT NULL,
                    status TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL,
                    signal_fingerprints TEXT NOT NULL, validation_task_ids TEXT NOT NULL,
                    expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    closed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_assurance_packages_state
                    ON assurance_packages(status, created_at DESC);
                """
            )
            self._ensure_column(
                db, "assurance_policy", "connection_alias", "TEXT NOT NULL DEFAULT 'primary'"
            )
            self._ensure_column(
                db, "assurance_policy", "connection_fingerprint", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(
                db, "assurance_policy", "tenant_scope_id", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(
                db, "assurance_runs", "connection_alias", "TEXT NOT NULL DEFAULT 'primary'"
            )
            self._ensure_column(
                db, "assurance_runs", "connection_fingerprint", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(
                db, "assurance_runs", "tenant_scope_id", "TEXT NOT NULL DEFAULT ''"
            )
            db.execute(
                """INSERT OR IGNORE INTO assurance_policy
                (id,enabled,interval_minutes,discovery_depth,max_splunk_calls_per_run,
                max_runs_per_day,notify_on_drift,notify_on_high_findings,next_run_at,
                last_scheduled_at,updated_at) VALUES (1,0,360,'standard',12,4,1,1,NULL,NULL,?)""",
                (now,),
            )
            db.execute(
                """UPDATE assurance_packages
                SET title=REPLACE(title, ' persistent signal', ' actionable signal'),
                    updated_at=?
                WHERE title LIKE 'Assurance response · % persistent signal%'""",
                (now,),
            )
            db.execute(
                """UPDATE assurance_notifications
                SET title=REPLACE(title, ' persistent signal', ' actionable signal')
                WHERE category='response-package'
                AND title LIKE 'Assurance response · % persistent signal%'"""
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

    def bind_unbound(self, binding: dict[str, Any]) -> dict[str, int]:
        """One-time migration for policy and runs created before identity binding."""
        values = (
            str(binding["alias"]),
            str(binding["fingerprint"]),
            str(binding["tenant_scope_id"]),
        )
        with self._lock, self.connect() as db:
            policy = db.execute(
                """UPDATE assurance_policy SET connection_alias=?,
                connection_fingerprint=?,tenant_scope_id=?
                WHERE id=1 AND connection_fingerprint=''""",
                values,
            )
            runs = db.execute(
                """UPDATE assurance_runs SET connection_alias=?,
                connection_fingerprint=?,tenant_scope_id=?
                WHERE connection_fingerprint=''""",
                values,
            )
        return {"policy": int(policy.rowcount), "runs": int(runs.rowcount)}

    def rebind_policy(
        self,
        binding: dict[str, Any],
        *,
        expected_connection_fingerprint: str,
        expected_updated_at: str,
    ) -> dict[str, Any]:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE assurance_policy SET connection_alias=?,
                connection_fingerprint=?,tenant_scope_id=?,enabled=0,next_run_at=NULL,
                updated_at=? WHERE id=1 AND connection_fingerprint=? AND updated_at=?""",
                (
                    str(binding["alias"]),
                    str(binding["fingerprint"]),
                    str(binding["tenant_scope_id"]),
                    now,
                    expected_connection_fingerprint,
                    expected_updated_at,
                ),
            )
            if result.rowcount != 1:
                raise ValueError(
                    "The assurance policy or connection binding changed; refresh before rebinding"
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
        policy = self.policy()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO assurance_runs
                (id,trigger,depth,status,phase,progress,label,detail,metrics,summary,error,
                call_budget,calls_used,cancel_requested,recovery_count,created_at,started_at,
                completed_at,updated_at,connection_alias,connection_fingerprint,tenant_scope_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                    policy["connection_alias"],
                    policy["connection_fingerprint"],
                    policy["tenant_scope_id"],
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
            "connection-blocked": "Continuous assurance blocked by connection readiness",
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

    def correlate_signals(
        self,
        run_id: str,
        signals: list[dict[str, str]],
        *,
        authoritative: bool,
        authoritative_kinds: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Correlate deterministic signals while protecting partial reads from false resolution."""
        now = _now().isoformat()
        seen = {item["fingerprint"] for item in signals if item.get("fingerprint")}
        with self._lock, self.connect() as db:
            active_rows = db.execute(
                "SELECT * FROM assurance_signals WHERE status!='resolved'"
            ).fetchall()
            for item in signals:
                fingerprint = item.get("fingerprint", "")
                if not fingerprint:
                    continue
                existing = db.execute(
                    "SELECT * FROM assurance_signals WHERE fingerprint=?", (fingerprint,)
                ).fetchone()
                if existing and existing["last_run_id"] == run_id:
                    continue
                observation_authoritative = (
                    str(item.get("authoritative", "true")).lower() != "false"
                )
                occurrence_count = int(existing["occurrence_count"]) + 1 if existing else 1
                if observation_authoritative:
                    consecutive_count = (
                        int(existing["consecutive_count"]) + 1
                        if existing and existing["status"] != "resolved"
                        else 1
                    )
                else:
                    consecutive_count = int(existing["consecutive_count"]) if existing else 0
                severity = str(item.get("severity") or "medium")
                if observation_authoritative:
                    status = (
                        "persistent"
                        if severity in {"critical", "high"} or consecutive_count >= 2
                        else "watching"
                    )
                else:
                    status = str(existing["status"]) if existing else "watching"
                if existing:
                    db.execute(
                        """UPDATE assurance_signals SET kind=?, severity=?, title=?, detail=?,
                        subject=?, source_ref=?, status=?, occurrence_count=?, consecutive_count=?,
                        last_run_id=?, last_seen_at=?, resolved_at=NULL WHERE fingerprint=?""",
                        (
                            item.get("kind", "finding"),
                            severity,
                            str(item.get("title") or "Assurance signal")[:240],
                            str(item.get("detail") or "")[:4000],
                            str(item.get("subject") or "")[:500],
                            str(item.get("source_ref") or "")[:40],
                            status,
                            occurrence_count,
                            consecutive_count,
                            run_id,
                            now,
                            fingerprint,
                        ),
                    )
                else:
                    db.execute(
                        """INSERT INTO assurance_signals
                        (fingerprint,kind,severity,title,detail,subject,source_ref,status,
                        occurrence_count,consecutive_count,first_run_id,last_run_id,
                        first_seen_at,last_seen_at,resolved_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                        (
                            fingerprint,
                            item.get("kind", "finding"),
                            severity,
                            str(item.get("title") or "Assurance signal")[:240],
                            str(item.get("detail") or "")[:4000],
                            str(item.get("subject") or "")[:500],
                            str(item.get("source_ref") or "")[:40],
                            status,
                            occurrence_count,
                            consecutive_count,
                            run_id,
                            run_id,
                            now,
                            now,
                        ),
                    )
            if authoritative:
                for row in active_rows:
                    if row["fingerprint"] not in seen and (
                        authoritative_kinds is None or row["kind"] in authoritative_kinds
                    ):
                        db.execute(
                            """UPDATE assurance_signals SET status='resolved',
                            consecutive_count=0, resolved_at=? WHERE fingerprint=?""",
                            (now, row["fingerprint"]),
                        )
        return [
            item
            for fingerprint in seen
            if (item := self.get_signal(fingerprint)) is not None
        ]

    def get_signal(self, fingerprint: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assurance_signals WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
        return self._signal(row) if row else None

    def signals(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM assurance_signals ORDER BY
                CASE status WHEN 'persistent' THEN 0 WHEN 'watching' THEN 1 ELSE 2 END,
                CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 ELSE 3 END, last_seen_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._signal(row) for row in rows]

    def signal_counts(self) -> dict[str, int]:
        signals = self.signals(limit=10000)
        counts = {
            "actionable": sum(item["status"] == "persistent" for item in signals),
            "repeated": sum(
                item["status"] == "persistent" and item["consecutive_count"] >= 2
                for item in signals
            ),
            "severity_elevated": sum(
                item["status"] == "persistent" and item["consecutive_count"] < 2
                for item in signals
            ),
            "watching": sum(item["status"] == "watching" for item in signals),
            "resolved": sum(item["status"] == "resolved" for item in signals),
        }
        return counts

    def create_package(
        self,
        source_run_id: str,
        severity: str,
        title: str,
        summary: str,
        signal_fingerprints: list[str],
        expires_at: str,
    ) -> dict[str, Any]:
        package_id = str(uuid4())
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO assurance_packages
                (id,source_run_id,severity,status,title,summary,signal_fingerprints,
                validation_task_ids,expires_at,created_at,updated_at,closed_at)
                VALUES (?,?,?,'review',?,?,?,?,?,?,?,NULL)""",
                (
                    package_id,
                    source_run_id,
                    severity,
                    title[:240],
                    summary[:4000],
                    json.dumps(sorted(set(signal_fingerprints))),
                    "[]",
                    expires_at,
                    now,
                    now,
                ),
            )
        result = self.get_package(package_id)
        assert result is not None
        return result

    def update_package_validations(
        self, package_id: str, validation_task_ids: list[str]
    ) -> dict[str, Any] | None:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_packages SET validation_task_ids=?, updated_at=?
                WHERE id=?""",
                (json.dumps(sorted(set(validation_task_ids))), now, package_id),
            )
        return self.get_package(package_id)

    def expire_packages(self) -> int:
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE assurance_packages SET status='expired', updated_at=?
                WHERE status='review' AND expires_at<=?""",
                (now, now),
            )
        return int(result.rowcount)

    def get_package(self, package_id: str) -> dict[str, Any] | None:
        self.expire_packages()
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM assurance_packages WHERE id=?", (package_id,)
            ).fetchone()
        return self._package_with_signals(row) if row else None

    def packages(self, limit: int = 20) -> list[dict[str, Any]]:
        self.expire_packages()
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM assurance_packages ORDER BY
                CASE status WHEN 'review' THEN 0 WHEN 'expired' THEN 1 ELSE 2 END,
                created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._package_with_signals(row) for row in rows]

    def covered_signal_fingerprints(self) -> set[str]:
        self.expire_packages()
        with self.connect() as db:
            rows = db.execute(
                """SELECT signal_fingerprints FROM assurance_packages
                WHERE status='review'"""
            ).fetchall()
        return {
            fingerprint
            for row in rows
            for fingerprint in json.loads(row["signal_fingerprints"])
        }

    def close_package(self, package_id: str) -> dict[str, Any] | None:
        self.expire_packages()
        now = _now().isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE assurance_packages SET status='closed', closed_at=?, updated_at=?
                WHERE id=? AND status='review'""",
                (now, now, package_id),
            )
        return self.get_package(package_id)

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
            "connection_alias": row["connection_alias"],
            "connection_fingerprint": row["connection_fingerprint"],
            "tenant_scope_id": row["tenant_scope_id"],
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
            connection_alias=row["connection_alias"],
            connection_fingerprint=row["connection_fingerprint"],
            tenant_scope_id=row["tenant_scope_id"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _ensure_column(
        db: sqlite3.Connection,
        table: str,
        column: str,
        declaration: str,
    ) -> None:
        columns = {str(row["name"]) for row in db.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

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

    @staticmethod
    def _signal(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "fingerprint": row["fingerprint"],
            "kind": row["kind"],
            "severity": row["severity"],
            "title": row["title"],
            "detail": row["detail"],
            "subject": row["subject"],
            "source_ref": row["source_ref"],
            "status": row["status"],
            "occurrence_count": int(row["occurrence_count"]),
            "consecutive_count": int(row["consecutive_count"]),
            "first_run_id": row["first_run_id"],
            "last_run_id": row["last_run_id"],
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "resolved_at": row["resolved_at"],
        }

    def _package_with_signals(self, row: sqlite3.Row) -> dict[str, Any]:
        value = self._package(row)
        value["signals"] = [
            signal
            for fingerprint in value["signal_fingerprints"]
            if (signal := self.get_signal(fingerprint)) is not None
        ]
        return value

    @staticmethod
    def _package(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "source_run_id": row["source_run_id"],
            "severity": row["severity"],
            "status": row["status"],
            "title": row["title"],
            "summary": row["summary"],
            "signal_fingerprints": json.loads(row["signal_fingerprints"]),
            "validation_task_ids": json.loads(row["validation_task_ids"]),
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "closed_at": row["closed_at"],
        }
