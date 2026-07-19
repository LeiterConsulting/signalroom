from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import WorkloadPolicyUpdate


def _now() -> str:
    return datetime.now(UTC).isoformat()


class WorkloadStore:
    """Durable policy and query-safe workload admission history."""

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
        now = _now()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS workload_policy (
                    id INTEGER PRIMARY KEY CHECK (id = 1), mode TEXT NOT NULL,
                    max_concurrent_calls INTEGER NOT NULL,
                    max_concurrent_queries INTEGER NOT NULL,
                    queue_timeout_seconds INTEGER NOT NULL,
                    max_query_risk_score INTEGER NOT NULL,
                    max_query_cost_units INTEGER NOT NULL,
                    daily_query_cost_units INTEGER NOT NULL,
                    generation INTEGER NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workload_events (
                    id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
                    operation TEXT NOT NULL, logical_name TEXT NOT NULL,
                    lane TEXT NOT NULL, query_fingerprint TEXT NOT NULL,
                    risk TEXT NOT NULL, risk_score INTEGER NOT NULL,
                    cost_units INTEGER NOT NULL, decision TEXT NOT NULL,
                    status TEXT NOT NULL, reasons TEXT NOT NULL,
                    wait_ms INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
                    policy_generation INTEGER NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT, completed_at TEXT, error TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workload_events_instance_created
                    ON workload_events(instance_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_workload_events_status_created
                    ON workload_events(status, created_at DESC);
                """
            )
            db.execute(
                """INSERT OR IGNORE INTO workload_policy
                (id,mode,max_concurrent_calls,max_concurrent_queries,queue_timeout_seconds,
                max_query_risk_score,max_query_cost_units,daily_query_cost_units,generation,updated_at)
                VALUES (1,'audit',6,2,60,70,90,1000,1,?)""",
                (now,),
            )

    def recover_interrupted(self) -> int:
        now = _now()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE workload_events SET status='interrupted', completed_at=?,
                error='SignalRoom restarted while this admission was active.'
                WHERE status IN ('queued','running')""",
                (now,),
            )
        return int(result.rowcount)

    def policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM workload_policy WHERE id=1").fetchone()
        assert row is not None
        return {
            "mode": str(row["mode"]),
            "max_concurrent_calls": int(row["max_concurrent_calls"]),
            "max_concurrent_queries": int(row["max_concurrent_queries"]),
            "queue_timeout_seconds": int(row["queue_timeout_seconds"]),
            "max_query_risk_score": int(row["max_query_risk_score"]),
            "max_query_cost_units": int(row["max_query_cost_units"]),
            "daily_query_cost_units": int(row["daily_query_cost_units"]),
            "generation": int(row["generation"]),
            "updated_at": str(row["updated_at"]),
        }

    def update_policy(self, value: WorkloadPolicyUpdate) -> dict[str, Any]:
        current = self.policy()
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE workload_policy SET mode=?, max_concurrent_calls=?,
                max_concurrent_queries=?, queue_timeout_seconds=?, max_query_risk_score=?,
                max_query_cost_units=?, daily_query_cost_units=?, generation=?, updated_at=?
                WHERE id=1""",
                (
                    value.mode,
                    value.max_concurrent_calls,
                    value.max_concurrent_queries,
                    value.queue_timeout_seconds,
                    value.max_query_risk_score,
                    value.max_query_cost_units,
                    value.daily_query_cost_units,
                    current["generation"] + 1,
                    now,
                ),
            )
        return self.policy()

    def create_event(
        self,
        *,
        instance_id: str,
        operation: str,
        logical_name: str,
        lane: str,
        query_fingerprint: str,
        risk: str,
        risk_score: int,
        cost_units: int,
        decision: str,
        status: str,
        reasons: list[str],
        policy_generation: int,
    ) -> str:
        event_id = str(uuid4())
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO workload_events
                (id,instance_id,operation,logical_name,lane,query_fingerprint,risk,risk_score,
                cost_units,decision,status,reasons,wait_ms,duration_ms,policy_generation,
                created_at,started_at,completed_at,error)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,?,NULL,NULL,'')""",
                (
                    event_id,
                    instance_id,
                    operation[:160],
                    logical_name[:160],
                    lane,
                    query_fingerprint,
                    risk,
                    risk_score,
                    cost_units,
                    decision,
                    status,
                    json.dumps(reasons),
                    policy_generation,
                    _now(),
                ),
            )
            db.execute(
                """DELETE FROM workload_events WHERE id IN (
                SELECT id FROM workload_events ORDER BY created_at DESC LIMIT -1 OFFSET 5000
                )"""
            )
        return event_id

    def update_event(
        self,
        event_id: str,
        status: str,
        *,
        wait_ms: int = 0,
        duration_ms: int = 0,
        error: str = "",
    ) -> None:
        now = _now()
        started_at = now if status == "running" else None
        completed_at = now if status in {"complete", "error", "cancelled", "blocked"} else None
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE workload_events SET status=?, wait_ms=?, duration_ms=?, error=?,
                started_at=COALESCE(started_at,?), completed_at=COALESCE(?,completed_at)
                WHERE id=?""",
                (
                    status,
                    max(0, wait_ms),
                    max(0, duration_ms),
                    error[:1000],
                    started_at,
                    completed_at,
                    event_id,
                ),
            )

    def daily_usage(self, instance_id: str) -> int:
        day = datetime.now(UTC).date().isoformat()
        with self.connect() as db:
            row = db.execute(
                """SELECT COALESCE(SUM(cost_units),0) AS units FROM workload_events
                WHERE instance_id=? AND lane='query' AND substr(created_at,1,10)=?
                AND status IN ('complete','error','interrupted')""",
                (instance_id, day),
            ).fetchone()
        return int(row["units"]) if row else 0

    def recent(self, limit: int = 40) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM workload_events ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [
            {
                **dict(row),
                "reasons": json.loads(row["reasons"] or "[]"),
            }
            for row in rows
        ]
