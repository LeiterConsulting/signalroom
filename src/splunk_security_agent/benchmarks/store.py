from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


class GoldenBenchmarkStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS benchmark_runs (
                    id TEXT PRIMARY KEY, suite_version TEXT NOT NULL, profile_id TEXT NOT NULL,
                    model TEXT NOT NULL, prompt_version TEXT NOT NULL, status TEXT NOT NULL,
                    score REAL NOT NULL, pass_rate REAL NOT NULL, critical_failures INTEGER NOT NULL,
                    gate TEXT NOT NULL, feedback TEXT NOT NULL, comparison TEXT NOT NULL,
                    is_baseline INTEGER NOT NULL, error TEXT NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT, completed_at TEXT,
                    artifact_binding TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, scenario_id TEXT NOT NULL,
                    title TEXT NOT NULL, task_type TEXT NOT NULL, score REAL NOT NULL,
                    passed INTEGER NOT NULL, critical INTEGER NOT NULL, checks TEXT NOT NULL,
                    response TEXT NOT NULL, model TEXT NOT NULL, route TEXT NOT NULL,
                    tools TEXT NOT NULL, evidence_refs TEXT NOT NULL, duration_ms INTEGER NOT NULL,
                    error TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES benchmark_runs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_benchmark_runs_created
                    ON benchmark_runs(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_benchmark_results_run
                    ON benchmark_results(run_id, scenario_id);
                """
            )
            columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(benchmark_runs)").fetchall()
            }
            if "artifact_binding" not in columns:
                db.execute(
                    "ALTER TABLE benchmark_runs ADD COLUMN "
                    "artifact_binding TEXT NOT NULL DEFAULT '{}'"
                )
            now = datetime.now(UTC).isoformat()
            db.execute(
                """UPDATE benchmark_runs SET status='error',
                error='Benchmark execution was interrupted by a SignalRoom restart.',
                completed_at=? WHERE status='running'""",
                (now,),
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def create_run(
        self,
        suite_version: str,
        profile_id: str,
        model: str,
        prompt_version: str,
        artifact_binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        run_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO benchmark_runs
                (id,suite_version,profile_id,model,prompt_version,status,score,pass_rate,
                critical_failures,gate,feedback,comparison,is_baseline,error,created_at,
                started_at,completed_at,artifact_binding)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    suite_version,
                    profile_id,
                    model,
                    prompt_version,
                    "running",
                    0,
                    0,
                    0,
                    "{}",
                    "{}",
                    "{}",
                    0,
                    "",
                    now,
                    now,
                    None,
                    json.dumps(artifact_binding or {}, default=str),
                ),
            )
        result = self.get(run_id)
        assert result is not None
        return result

    def add_result(self, run_id: str, value: dict[str, Any]) -> None:
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO benchmark_results
                (id,run_id,scenario_id,title,task_type,score,passed,critical,checks,response,
                model,route,tools,evidence_refs,duration_ms,error)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid4()),
                    run_id,
                    value["scenario_id"],
                    value["title"],
                    value["task_type"],
                    value["score"],
                    int(value["passed"]),
                    int(value["critical"]),
                    json.dumps(value["checks"], default=str),
                    value.get("response", "")[:20000],
                    value.get("model", ""),
                    value.get("route", ""),
                    json.dumps(value.get("tools", []), default=str),
                    json.dumps(value.get("evidence_refs", []), default=str),
                    int(value.get("duration_ms", 0)),
                    value.get("error", "")[:4000],
                ),
            )

    def complete(
        self,
        run_id: str,
        *,
        score: float,
        pass_rate: float,
        critical_failures: int,
        gate: dict[str, Any],
        feedback: dict[str, Any],
        comparison: dict[str, Any],
    ) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE benchmark_runs SET status='complete',score=?,pass_rate=?,
                critical_failures=?,gate=?,feedback=?,comparison=?,completed_at=? WHERE id=?""",
                (
                    score,
                    pass_rate,
                    critical_failures,
                    json.dumps(gate, default=str),
                    json.dumps(feedback, default=str),
                    json.dumps(comparison, default=str),
                    now,
                    run_id,
                ),
            )
        result = self.get(run_id)
        assert result is not None
        return result

    def fail(self, run_id: str, error: str) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE benchmark_runs SET status='error',error=?,completed_at=? WHERE id=?""",
                (error[:4000], now, run_id),
            )
        result = self.get(run_id)
        assert result is not None
        return result

    def accept_baseline(self, run_id: str) -> dict[str, Any] | None:
        return self.set_baseline(run_id)

    def set_baseline(self, run_id: str | None) -> dict[str, Any] | None:
        if run_id is None:
            with self._lock, self.connect() as db:
                db.execute("UPDATE benchmark_runs SET is_baseline=0 WHERE is_baseline=1")
            return None
        current = self.get(run_id)
        if current is None or current["status"] != "complete" or not current["gate"].get("ready"):
            return None
        with self._lock, self.connect() as db:
            db.execute("UPDATE benchmark_runs SET is_baseline=0 WHERE is_baseline=1")
            db.execute("UPDATE benchmark_runs SET is_baseline=1 WHERE id=?", (run_id,))
        return self.get(run_id)

    def baseline(self, exclude_run_id: str = "") -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT id FROM benchmark_runs WHERE is_baseline=1 AND id<>?
                ORDER BY completed_at DESC LIMIT 1""",
                (exclude_run_id,),
            ).fetchone()
        return self.get(str(row["id"])) if row else None

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM benchmark_runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                return None
            results = db.execute(
                """SELECT * FROM benchmark_results WHERE run_id=?
                ORDER BY rowid""",
                (run_id,),
            ).fetchall()
        return self._run(row, results)

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM benchmark_runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            run_ids = [str(row["id"]) for row in rows]
            result_rows = (
                db.execute(
                    f"SELECT * FROM benchmark_results WHERE run_id IN ({','.join('?' for _ in run_ids)})",
                    run_ids,
                ).fetchall()
                if run_ids
                else []
            )
        grouped: dict[str, list[sqlite3.Row]] = {run_id: [] for run_id in run_ids}
        for result in result_rows:
            grouped[str(result["run_id"])].append(result)
        return [self._run(row, grouped[str(row["id"])]) for row in rows]

    @staticmethod
    def _run(row: sqlite3.Row, results: list[sqlite3.Row]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "suite_version": row["suite_version"],
            "profile_id": row["profile_id"],
            "model": row["model"],
            "prompt_version": row["prompt_version"],
            "status": row["status"],
            "score": float(row["score"]),
            "pass_rate": float(row["pass_rate"]),
            "critical_failures": int(row["critical_failures"]),
            "gate": json.loads(row["gate"]),
            "feedback": json.loads(row["feedback"]),
            "comparison": json.loads(row["comparison"]),
            "is_baseline": bool(row["is_baseline"]),
            "error": row["error"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "artifact_binding": json.loads(row["artifact_binding"]),
            "results": [
                {
                    "scenario_id": item["scenario_id"],
                    "title": item["title"],
                    "task_type": item["task_type"],
                    "score": float(item["score"]),
                    "passed": bool(item["passed"]),
                    "critical": bool(item["critical"]),
                    "checks": json.loads(item["checks"]),
                    "response": item["response"],
                    "model": item["model"],
                    "route": item["route"],
                    "tools": json.loads(item["tools"]),
                    "evidence_refs": json.loads(item["evidence_refs"]),
                    "duration_ms": int(item["duration_ms"]),
                    "error": item["error"],
                }
                for item in results
            ],
        }
