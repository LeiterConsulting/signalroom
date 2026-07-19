from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


class ModelTournamentStore:
    """Durable model comparisons and exact routing-promotion history."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS model_tournaments (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    suite_id TEXT NOT NULL DEFAULT 'builtin-core',
                    status TEXT NOT NULL,
                    profile_ids TEXT NOT NULL,
                    assignment_before TEXT NOT NULL,
                    suite_version TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    candidate_run_ids TEXT NOT NULL,
                    ranking TEXT NOT NULL,
                    review_pairs TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    error TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_promotions (
                    id TEXT PRIMARY KEY,
                    tournament_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    previous_profile_id TEXT NOT NULL,
                    tournament_fingerprint TEXT NOT NULL,
                    promoted_run_id TEXT NOT NULL,
                    previous_baseline_run_id TEXT NOT NULL,
                    config_before_sha256 TEXT NOT NULL,
                    config_after_sha256 TEXT NOT NULL,
                    artifact_fingerprint TEXT NOT NULL DEFAULT '',
                    attestation_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    promoted_at TEXT NOT NULL,
                    rolled_back_at TEXT,
                    FOREIGN KEY(tournament_id) REFERENCES model_tournaments(id)
                );
                CREATE INDEX IF NOT EXISTS idx_model_tournaments_created
                    ON model_tournaments(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_model_promotions_created
                    ON model_promotions(promoted_at DESC);
                CREATE INDEX IF NOT EXISTS idx_model_promotions_active
                    ON model_promotions(target, status);
                """
            )
            promotion_columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(model_promotions)").fetchall()
            }
            for name in ("artifact_fingerprint", "attestation_id"):
                if name not in promotion_columns:
                    db.execute(
                        f"ALTER TABLE model_promotions ADD COLUMN {name} "
                        "TEXT NOT NULL DEFAULT ''"
                    )
            tournament_columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(model_tournaments)").fetchall()
            }
            if "suite_id" not in tournament_columns:
                db.execute(
                    "ALTER TABLE model_tournaments ADD COLUMN "
                    "suite_id TEXT NOT NULL DEFAULT 'builtin-core'"
                )
            now = datetime.now(UTC).isoformat()
            db.execute(
                """UPDATE model_tournaments
                SET status='error',
                    error='Tournament execution was interrupted by a SignalRoom restart.',
                    completed_at=?,
                    updated_at=?
                WHERE status='running'""",
                (now, now),
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def create(
        self,
        *,
        target: str,
        profile_ids: list[str],
        assignment_before: str,
        suite_id: str,
        suite_version: str,
        prompt_version: str,
    ) -> dict[str, Any]:
        tournament_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO model_tournaments
                (id,target,suite_id,status,profile_ids,assignment_before,suite_version,prompt_version,
                candidate_run_ids,ranking,review_pairs,recommendation,fingerprint,error,
                created_at,started_at,completed_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    tournament_id,
                    target,
                    suite_id,
                    "running",
                    json.dumps(profile_ids),
                    assignment_before,
                    suite_version,
                    prompt_version,
                    "[]",
                    "[]",
                    "[]",
                    "{}",
                    "",
                    "",
                    now,
                    now,
                    None,
                    now,
                ),
            )
        result = self.get(tournament_id)
        assert result is not None
        return result

    def save_evaluation(
        self,
        tournament_id: str,
        *,
        status: str,
        candidate_run_ids: list[str],
        ranking: list[dict[str, Any]],
        review_pairs: list[dict[str, Any]],
        recommendation: dict[str, Any],
        fingerprint: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        completed_at = now if status in {"complete", "hold"} else None
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE model_tournaments
                SET status=?,candidate_run_ids=?,ranking=?,review_pairs=?,recommendation=?,
                    fingerprint=?,completed_at=?,updated_at=?
                WHERE id=?""",
                (
                    status,
                    json.dumps(candidate_run_ids, default=str),
                    json.dumps(ranking, default=str),
                    json.dumps(review_pairs, default=str),
                    json.dumps(recommendation, default=str),
                    fingerprint,
                    completed_at,
                    now,
                    tournament_id,
                ),
            )
        result = self.get(tournament_id)
        if result is None:
            raise KeyError(f"Unknown model tournament: {tournament_id}")
        return result

    def fail(self, tournament_id: str, error: str) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE model_tournaments
                SET status='error',error=?,completed_at=?,updated_at=? WHERE id=?""",
                (error[:4000], now, now, tournament_id),
            )
        result = self.get(tournament_id)
        if result is None:
            raise KeyError(f"Unknown model tournament: {tournament_id}")
        return result

    def get(self, tournament_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM model_tournaments WHERE id=?", (tournament_id,)
            ).fetchone()
        return self._tournament(row) if row else None

    def list(self, limit: int = 12) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM model_tournaments ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._tournament(row) for row in rows]

    def create_promotion(
        self,
        *,
        tournament_id: str,
        target: str,
        profile_id: str,
        previous_profile_id: str,
        tournament_fingerprint: str,
        promoted_run_id: str,
        previous_baseline_run_id: str,
        config_before_sha256: str,
        config_after_sha256: str,
        artifact_fingerprint: str = "",
        attestation_id: str = "",
    ) -> dict[str, Any]:
        promotion_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE model_promotions SET status='superseded'
                WHERE target=? AND status='active'""",
                (target,),
            )
            db.execute(
                """INSERT INTO model_promotions
                (id,tournament_id,target,profile_id,previous_profile_id,
                tournament_fingerprint,promoted_run_id,previous_baseline_run_id,
                config_before_sha256,config_after_sha256,artifact_fingerprint,
                attestation_id,status,promoted_at,rolled_back_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    promotion_id,
                    tournament_id,
                    target,
                    profile_id,
                    previous_profile_id,
                    tournament_fingerprint,
                    promoted_run_id,
                    previous_baseline_run_id,
                    config_before_sha256,
                    config_after_sha256,
                    artifact_fingerprint,
                    attestation_id,
                    "active",
                    now,
                    None,
                ),
            )
        result = self.get_promotion(promotion_id)
        assert result is not None
        return result

    def get_promotion(self, promotion_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM model_promotions WHERE id=?", (promotion_id,)
            ).fetchone()
        return self._promotion(row) if row else None

    def active_promotion(self, target: str = "") -> dict[str, Any] | None:
        query = "SELECT * FROM model_promotions WHERE status='active'"
        values: tuple[Any, ...] = ()
        if target:
            query += " AND target=?"
            values = (target,)
        query += " ORDER BY promoted_at DESC LIMIT 1"
        with self.connect() as db:
            row = db.execute(query, values).fetchone()
        return self._promotion(row) if row else None

    def list_promotions(self, limit: int = 12) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM model_promotions ORDER BY promoted_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._promotion(row) for row in rows]

    def mark_rolled_back(self, promotion_id: str) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE model_promotions
                SET status='rolled-back',rolled_back_at=?
                WHERE id=? AND status='active'""",
                (now, promotion_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Only the active model promotion can be rolled back")
        result = self.get_promotion(promotion_id)
        assert result is not None
        return result

    @staticmethod
    def _tournament(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "target": row["target"],
            "suite_id": row["suite_id"],
            "status": row["status"],
            "profile_ids": json.loads(row["profile_ids"]),
            "assignment_before": row["assignment_before"],
            "suite_version": row["suite_version"],
            "prompt_version": row["prompt_version"],
            "candidate_run_ids": json.loads(row["candidate_run_ids"]),
            "ranking": json.loads(row["ranking"]),
            "review_pairs": json.loads(row["review_pairs"]),
            "recommendation": json.loads(row["recommendation"]),
            "fingerprint": row["fingerprint"],
            "error": row["error"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _promotion(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tournament_id": row["tournament_id"],
            "target": row["target"],
            "profile_id": row["profile_id"],
            "previous_profile_id": row["previous_profile_id"],
            "tournament_fingerprint": row["tournament_fingerprint"],
            "promoted_run_id": row["promoted_run_id"],
            "previous_baseline_run_id": row["previous_baseline_run_id"],
            "config_before_sha256": row["config_before_sha256"],
            "config_after_sha256": row["config_after_sha256"],
            "artifact_fingerprint": row["artifact_fingerprint"],
            "attestation_id": row["attestation_id"],
            "status": row["status"],
            "promoted_at": row["promoted_at"],
            "rolled_back_at": row["rolled_back_at"],
        }
