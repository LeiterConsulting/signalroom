from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from .schemas import AnalystFeedbackCreate

POSITIVE_RATINGS = {"useful", "corrected"}


class AnalystFeedbackStore:
    """Local analyst outcome feedback and model/task scorecards."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
                    task_type TEXT NOT NULL, rating TEXT NOT NULL, model_profile TEXT NOT NULL,
                    model TEXT NOT NULL, route TEXT NOT NULL, note TEXT NOT NULL,
                    correction TEXT NOT NULL, metadata TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_feedback_model_task
                    ON analyst_feedback(model_profile,task_type,created_at DESC);
                """
            )
            db.execute("DROP INDEX IF EXISTS idx_feedback_target_rating")
            db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_feedback_target
                ON analyst_feedback(target_type,target_id)"""
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def record(self, value: AnalystFeedbackCreate) -> dict[str, Any]:
        feedback_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            existing = db.execute(
                """SELECT id FROM analyst_feedback
                WHERE target_type=? AND target_id=?""",
                (value.target_type, value.target_id),
            ).fetchone()
            if existing:
                feedback_id = str(existing["id"])
                db.execute(
                    """UPDATE analyst_feedback SET task_type=?,rating=?,model_profile=?,model=?,
                    route=?,note=?,correction=?,metadata=?,created_at=?
                    WHERE id=?""",
                    (
                        value.task_type,
                        value.rating,
                        value.model_profile,
                        value.model,
                        value.route,
                        value.note,
                        value.correction,
                        json.dumps(value.metadata, default=str),
                        now,
                        feedback_id,
                    ),
                )
            else:
                db.execute(
                    """INSERT INTO analyst_feedback
                    (id,target_type,target_id,task_type,rating,model_profile,model,route,
                    note,correction,metadata,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        feedback_id,
                        value.target_type,
                        value.target_id,
                        value.task_type,
                        value.rating,
                        value.model_profile,
                        value.model,
                        value.route,
                        value.note,
                        value.correction,
                        json.dumps(value.metadata, default=str),
                        now,
                    ),
                )
        return {"id": feedback_id, **value.model_dump(mode="json"), "created_at": now}

    def benchmarks(self) -> dict[str, Any]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT model_profile,model,task_type,rating,COUNT(*) count
                FROM analyst_feedback GROUP BY model_profile,model,task_type,rating
                ORDER BY model_profile,task_type"""
            ).fetchall()
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        totals: dict[str, int] = {}
        for row in rows:
            key = (row["model_profile"], row["model"], row["task_type"])
            group = groups.setdefault(
                key,
                {
                    "model_profile": row["model_profile"] or "unattributed",
                    "model": row["model"],
                    "task_type": row["task_type"],
                    "ratings": {},
                    "total": 0,
                    "positive": 0,
                },
            )
            count = int(row["count"])
            group["ratings"][row["rating"]] = count
            group["total"] += count
            if row["rating"] in POSITIVE_RATINGS:
                group["positive"] += count
            totals[row["rating"]] = totals.get(row["rating"], 0) + count
        values = []
        for group in groups.values():
            group["positive_rate"] = round(group["positive"] / group["total"], 3)
            group["confidence"] = "directional" if group["total"] < 10 else "established"
            values.append(group)
        values.sort(key=lambda item: (-item["total"], item["model_profile"], item["task_type"]))
        return {"total": sum(totals.values()), "ratings": totals, "scorecards": values}
