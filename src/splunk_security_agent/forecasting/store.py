from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import statistics
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class TimeSeriesExperimentStore:
    """Immutable forecast history, reviewed baselines, and alert-candidate handoffs."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS time_series_runs (
                    id TEXT PRIMARY KEY,
                    series_key TEXT NOT NULL,
                    run_fingerprint TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    comparison_json TEXT NOT NULL,
                    promotion_ready INTEGER NOT NULL,
                    is_baseline INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    baseline_accepted_by TEXT NOT NULL DEFAULT '',
                    baseline_review_note TEXT NOT NULL DEFAULT '',
                    baseline_accepted_at TEXT
                );
                CREATE TABLE IF NOT EXISTS time_series_alert_candidates (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    series_key TEXT NOT NULL,
                    run_fingerprint TEXT NOT NULL,
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    threshold_source TEXT NOT NULL,
                    proposed_spl TEXT NOT NULL,
                    validation_task_id TEXT NOT NULL,
                    case_id TEXT,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES time_series_runs(id)
                );
                CREATE INDEX IF NOT EXISTS idx_time_series_runs_created
                    ON time_series_runs(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_time_series_runs_series
                    ON time_series_runs(series_key, created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_time_series_baseline
                    ON time_series_runs(series_key) WHERE is_baseline=1;
                CREATE INDEX IF NOT EXISTS idx_time_series_candidates_created
                    ON time_series_alert_candidates(created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_time_series_candidate_direction
                    ON time_series_alert_candidates(run_id, direction);
                """
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def series_key(request: dict[str, Any]) -> str:
        spl = re.sub(r"\s+", " ", str(request.get("spl") or "").strip())
        spl_template = re.sub(
            r"\bspan\s*=\s*\d+\s*[smhd]\b",
            "span=?",
            spl,
            flags=re.IGNORECASE,
        )
        return _digest(
            {
                "spl_template": spl_template,
                "timestamp_field": str(request.get("timestamp_field") or ""),
                "value_field": str(request.get("value_field") or ""),
            }
        )

    @staticmethod
    def run_fingerprint(request: dict[str, Any], result: dict[str, Any]) -> str:
        immutable_result = {key: value for key, value in result.items() if key not in {"experiment"}}
        return _digest({"request": request, "result": immutable_result})

    def record(
        self,
        request: dict[str, Any],
        result: dict[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        series_key = self.series_key(request)
        fingerprint = self.run_fingerprint(request, result)
        baseline = self.baseline(series_key)
        comparison = self._comparison(result, baseline)
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO time_series_runs
                (id,series_key,run_fingerprint,title,status,request_json,result_json,
                comparison_json,promotion_ready,is_baseline,created_by,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    result["run_id"],
                    series_key,
                    fingerprint,
                    str(result.get("title") or "Untitled forecast"),
                    str(result.get("status") or "complete"),
                    json.dumps(request, sort_keys=True, default=str),
                    json.dumps(result, sort_keys=True, default=str),
                    json.dumps(comparison, sort_keys=True, default=str),
                    int(bool((result.get("promotion_gate") or {}).get("ready"))),
                    0,
                    actor[:160] or "local-operator",
                    str(result.get("executed_at") or _now()),
                ),
            )
        recorded = self.get(str(result["run_id"]))
        assert recorded is not None
        return recorded

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM time_series_runs WHERE id=?",
                (run_id,),
            ).fetchone()
        return self._run(row, full=True) if row else None

    def list(
        self,
        limit: int = 30,
        *,
        series_key: str = "",
    ) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 100))
        with self.connect() as db:
            if series_key:
                rows = db.execute(
                    """SELECT * FROM time_series_runs
                    WHERE series_key=? ORDER BY created_at DESC LIMIT ?""",
                    (series_key, bounded),
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM time_series_runs
                    ORDER BY created_at DESC LIMIT ?""",
                    (bounded,),
                ).fetchall()
        return [self._run(row, full=False) for row in rows]

    def baseline(self, series_key: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM time_series_runs
                WHERE series_key=? AND is_baseline=1 LIMIT 1""",
                (series_key,),
            ).fetchone()
        return self._run(row, full=True) if row else None

    def accept_baseline(
        self,
        run_id: str,
        *,
        expected_fingerprint: str,
        actor: str,
        review_note: str,
    ) -> dict[str, Any]:
        current = self.get(run_id)
        if current is None:
            raise KeyError(f"Unknown time-series run: {run_id}")
        if current["run_fingerprint"] != expected_fingerprint:
            raise ValueError("The forecast run changed or the reviewed fingerprint does not match")
        if not current["promotion_ready"]:
            raise ValueError("Only a promotion-eligible forecast can become a comparison baseline")
        note = review_note.strip()
        if len(note) < 3:
            raise ValueError("Record why this run is acceptable as the comparison baseline")
        accepted_at = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE time_series_runs SET is_baseline=0
                WHERE series_key=? AND is_baseline=1""",
                (current["series_key"],),
            )
            cursor = db.execute(
                """UPDATE time_series_runs
                SET is_baseline=1,baseline_accepted_by=?,
                    baseline_review_note=?,baseline_accepted_at=?
                WHERE id=? AND run_fingerprint=? AND promotion_ready=1""",
                (
                    actor[:160] or "local-operator",
                    note[:4000],
                    accepted_at,
                    run_id,
                    expected_fingerprint,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("The exact eligible run could not be accepted")
        accepted = self.get(run_id)
        assert accepted is not None
        return accepted

    def create_alert_candidate(
        self,
        *,
        run_id: str,
        run_fingerprint: str,
        title: str,
        rationale: str,
        direction: str,
        threshold: float,
        threshold_source: str,
        proposed_spl: str,
        validation_task_id: str,
        case_id: str | None,
        actor: str,
    ) -> dict[str, Any]:
        candidate_id = str(uuid4())
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO time_series_alert_candidates
                (id,run_id,series_key,run_fingerprint,title,rationale,direction,
                threshold,threshold_source,proposed_spl,validation_task_id,case_id,
                status,created_by,created_at)
                SELECT ?,id,series_key,run_fingerprint,?,?,?,?,?,?,?,?,?,?,?
                FROM time_series_runs
                WHERE id=? AND run_fingerprint=? AND is_baseline=1
                    AND promotion_ready=1""",
                (
                    candidate_id,
                    title[:240],
                    rationale[:4000],
                    direction,
                    float(threshold),
                    threshold_source,
                    proposed_spl,
                    validation_task_id,
                    case_id,
                    "validation-draft",
                    actor[:160] or "local-operator",
                    _now(),
                    run_id,
                    run_fingerprint,
                ),
            )
            row = db.execute(
                "SELECT * FROM time_series_alert_candidates WHERE id=?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Alert candidates require the exact current accepted baseline")
        return self._candidate(row)

    def list_alert_candidates(self, limit: int = 30) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 100))
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM time_series_alert_candidates
                ORDER BY created_at DESC LIMIT ?""",
                (bounded,),
            ).fetchall()
        return [self._candidate(row) for row in rows]

    def alert_candidate(
        self,
        run_id: str,
        direction: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM time_series_alert_candidates
                WHERE run_id=? AND direction=? LIMIT 1""",
                (run_id, direction),
            ).fetchone()
        return self._candidate(row) if row else None

    def overview(self, limit: int = 30) -> dict[str, Any]:
        runs = self.list(limit)
        series: dict[str, dict[str, Any]] = {}
        for run in runs:
            item = series.setdefault(
                run["series_key"],
                {
                    "series_key": run["series_key"],
                    "title": run["title"],
                    "runs": 0,
                    "baseline_run_id": "",
                    "latest_run_id": run["id"],
                    "latest_at": run["created_at"],
                },
            )
            item["runs"] += 1
            if run["is_baseline"]:
                item["baseline_run_id"] = run["id"]
        return {
            "runs": runs,
            "series": list(series.values()),
            "alert_candidates": self.list_alert_candidates(limit),
            "contract": {
                "source_rows_persisted": False,
                "runs_immutable": True,
                "baseline_requires_exact_fingerprint": True,
                "alert_candidate_executes_spl": False,
                "alert_candidate_creates_validation_draft": True,
            },
        }

    @classmethod
    def _comparison(
        cls,
        result: dict[str, Any],
        baseline: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if baseline is None:
            return {
                "decision": "no-baseline",
                "baseline_run_id": "",
                "baseline_fingerprint": "",
                "reasons": ["No reviewed baseline exists for this logical series."],
                "metrics": {},
            }
        baseline_result = baseline["result"]
        current_series = result.get("series") or {}
        baseline_series = baseline_result.get("series") or {}
        current_backtest = result.get("backtest") or {}
        baseline_backtest = baseline_result.get("backtest") or {}
        current_forecast = result.get("forecast") or {}
        baseline_forecast = baseline_result.get("forecast") or {}
        current_mase = cls._number(current_backtest.get("mase_vs_last_value"))
        baseline_mase = cls._number(baseline_backtest.get("mase_vs_last_value"))
        mean_change = cls._percent_change(
            cls._number(current_series.get("mean")),
            cls._number(baseline_series.get("mean")),
        )
        forecast_change = cls._percent_change(
            cls._mean(current_forecast.get("mean")),
            cls._mean(baseline_forecast.get("mean")),
        )
        imputation_delta = cls._number(current_series.get("imputation_ratio"), 0.0) - cls._number(
            baseline_series.get("imputation_ratio"), 0.0
        )
        mase_delta = (
            current_mase - baseline_mase if current_mase is not None and baseline_mase is not None else None
        )
        current_source = result.get("source") or {}
        baseline_source = baseline_result.get("source") or {}
        current_runtime = result.get("runtime") or {}
        baseline_runtime = baseline_result.get("runtime") or {}
        span_changed = current_source.get("interval_seconds") != baseline_source.get("interval_seconds")
        window_changed = current_source.get("earliest_time") != baseline_source.get("earliest_time")
        revision_changed = current_runtime.get("source_revision") != baseline_runtime.get("source_revision")
        current_ready = bool((result.get("promotion_gate") or {}).get("ready"))
        performance_regressed = bool(
            baseline_mase is not None and baseline_mase < 1 and (current_mase is None or current_mase >= 1)
        )
        reasons: list[str] = []
        material = False
        review = False
        if not current_ready:
            material = True
            reasons.append("The current run no longer passes its promotion gate.")
        if performance_regressed:
            material = True
            reasons.append("Backtest performance no longer beats the naive baseline.")
        if mean_change is not None and abs(mean_change) >= 50:
            material = True
            reasons.append("Observed series mean moved at least 50% from baseline.")
        elif mean_change is not None and abs(mean_change) >= 20:
            review = True
            reasons.append("Observed series mean moved at least 20% from baseline.")
        if imputation_delta >= 0.10:
            material = True
            reasons.append("Imputation increased by at least ten percentage points.")
        if mase_delta is not None and mase_delta >= 0.20:
            review = True
            reasons.append("Backtest MASE deteriorated by at least 0.20.")
        if forecast_change is not None and abs(forecast_change) >= 20:
            review = True
            reasons.append("Forecast center moved at least 20% from baseline.")
        if span_changed:
            review = True
            reasons.append("Bucket span differs from the accepted baseline.")
        if window_changed:
            review = True
            reasons.append("Source window differs from the accepted baseline.")
        if revision_changed:
            review = True
            reasons.append("The model revision differs from the accepted baseline.")
        decision = "material-drift" if material else "review" if review else "stable"
        if not reasons:
            reasons.append("Performance, data quality, model revision, span, and window remain comparable.")
        return {
            "decision": decision,
            "baseline_run_id": baseline["id"],
            "baseline_fingerprint": baseline["run_fingerprint"],
            "reasons": reasons,
            "metrics": {
                "series_mean_change_percent": mean_change,
                "forecast_center_change_percent": forecast_change,
                "mase_delta": mase_delta,
                "imputation_delta_points": imputation_delta,
                "span_changed": span_changed,
                "window_changed": window_changed,
                "model_revision_changed": revision_changed,
            },
        }

    @staticmethod
    def _number(value: Any, default: float | None = None) -> float | None:
        try:
            result = float(value)
        except (TypeError, ValueError):
            return default
        return result if result == result else default

    @classmethod
    def _mean(cls, values: Any) -> float | None:
        if not isinstance(values, list) or not values:
            return None
        numbers = [value for item in values if (value := cls._number(item)) is not None]
        return statistics.fmean(numbers) if numbers else None

    @staticmethod
    def _percent_change(
        current: float | None,
        baseline: float | None,
    ) -> float | None:
        if current is None or baseline is None or baseline == 0:
            return None
        return (current - baseline) / abs(baseline) * 100

    @staticmethod
    def _run(row: sqlite3.Row, *, full: bool) -> dict[str, Any]:
        result = json.loads(row["result_json"])
        forecast = result.get("forecast") or {}
        backtest = result.get("backtest") or {}
        if not full:
            forecast = {
                "horizon": forecast.get("horizon", 0),
                "mean_min": min(forecast.get("mean") or [0]),
                "mean_max": max(forecast.get("mean") or [0]),
            }
            backtest = {key: value for key, value in backtest.items() if key not in {"actual", "predicted"}}
        return {
            "id": row["id"],
            "series_key": row["series_key"],
            "run_fingerprint": row["run_fingerprint"],
            "title": row["title"],
            "status": row["status"],
            "request": json.loads(row["request_json"]),
            "result": result if full else None,
            "source": result.get("source") or {},
            "series": result.get("series") or {},
            "runtime": result.get("runtime") or {},
            "forecast": forecast,
            "backtest": backtest,
            "promotion_gate": result.get("promotion_gate") or {},
            "comparison": json.loads(row["comparison_json"]),
            "promotion_ready": bool(row["promotion_ready"]),
            "is_baseline": bool(row["is_baseline"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "baseline_accepted_by": row["baseline_accepted_by"],
            "baseline_review_note": row["baseline_review_note"],
            "baseline_accepted_at": row["baseline_accepted_at"],
        }

    @staticmethod
    def _candidate(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "series_key": row["series_key"],
            "run_fingerprint": row["run_fingerprint"],
            "title": row["title"],
            "rationale": row["rationale"],
            "direction": row["direction"],
            "threshold": float(row["threshold"]),
            "threshold_source": row["threshold_source"],
            "proposed_spl": row["proposed_spl"],
            "validation_task_id": row["validation_task_id"],
            "case_id": row["case_id"],
            "status": row["status"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
        }
