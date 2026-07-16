from __future__ import annotations

import re
from typing import Any

from ..schemas import QueryIntelligenceRequest
from ..splunk.guardrails import validate_read_only_spl


class QueryIntelligenceService:
    """Explain bounded SPL execution risk and known reuse without running a query."""

    def __init__(self, store: Any):
        self.store = store

    def analyze(self, request: QueryIntelligenceRequest) -> dict[str, Any]:
        query = request.spl.strip()
        lowered = query.lower()
        score = 0
        drivers: list[dict[str, str]] = []
        controls: list[str] = []
        blocked_reason = ""
        try:
            validate_read_only_spl(query)
        except ValueError as exc:
            blocked_reason = str(exc)
            score = 100
            drivers.append({"level": "blocked", "label": blocked_reason})

        index_scoped = bool(re.search(r"(?i)(?:^|\s)index\s*=\s*[^*\s|]+", query))
        if index_scoped:
            controls.append("Explicit index scope")
        else:
            score += 28
            drivers.append(
                {"level": "high", "label": "No explicit non-wildcard index scope"}
            )
        time_seconds = self._relative_window_seconds(request.earliest_time, request.latest_time)
        if time_seconds is None:
            score += 15
            drivers.append({"level": "medium", "label": "Time window could not be estimated"})
        elif time_seconds > 30 * 86400:
            score += 30
            drivers.append({"level": "high", "label": "Time range exceeds 30 days"})
        elif time_seconds > 7 * 86400:
            score += 18
            drivers.append({"level": "medium", "label": "Time range exceeds 7 days"})
        elif time_seconds <= 86400:
            controls.append("Time range is 24 hours or less")

        expensive = {
            "transaction": (25, "Transaction can retain large event groups in memory"),
            "join": (20, "Join can create expensive subsearch and result expansion"),
            "map": (100, "Map is prohibited by the read-only execution policy"),
            "regex": (8, "Regex evaluation may scan every candidate event"),
        }
        for command, (weight, label) in expensive.items():
            if re.search(rf"(?i)\|\s*{command}\b", query):
                score = max(score, 100) if command == "map" else score + weight
                drivers.append(
                    {"level": "blocked" if command == "map" else "medium", "label": label}
                )
        if "| tstats" in lowered or lowered.startswith("| tstats"):
            score = max(0, score - 12)
            controls.append("Accelerated tstats pattern")
        if re.search(r"(?i)\|\s*(head|tail)\s+\d+", query):
            controls.append("SPL includes an explicit result limiter")
        if request.row_limit <= 100:
            controls.append(f"SignalRoom row cap is {request.row_limit}")
        elif request.row_limit > 300:
            score += 8
            drivers.append({"level": "low", "label": "Row cap exceeds 300"})

        fingerprint = self.store.fingerprint(
            query, request.earliest_time, request.latest_time, request.row_limit
        )
        reusable = self.store.find_latest_complete(fingerprint, request.exclude_task_id)
        risk = "blocked" if blocked_reason else "high" if score >= 55 else "medium" if score >= 25 else "low"
        staged = self._staged_query(query, index_scoped, time_seconds, request.row_limit)
        return {
            "risk": risk,
            "score": min(100, score),
            "blocked_reason": blocked_reason,
            "cost_drivers": drivers,
            "positive_controls": controls,
            "estimated_window_seconds": time_seconds,
            "query_fingerprint": fingerprint,
            "reusable_result": reusable.model_dump(mode="json") if reusable else None,
            "execution_recommendation": (
                "Blocked by the read-only policy. Edit the SPL before approval."
                if blocked_reason
                else "Reuse the preserved result unless fresher evidence is materially required."
                if reusable
                else "Stage this query with the narrow contract below before widening."
                if risk in {"high", "medium"}
                else "The query is bounded enough for explicit analyst approval."
            ),
            "staged_contract": staged,
        }

    @staticmethod
    def _relative_window_seconds(earliest: str, latest: str) -> int | None:
        if latest.strip().lower() != "now":
            return None
        match = re.fullmatch(r"-(\d+)([smhdw])(?:@\w+)?", earliest.strip().lower())
        if not match:
            return None
        units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
        return int(match.group(1)) * units[match.group(2)]

    @staticmethod
    def _staged_query(
        query: str, index_scoped: bool, time_seconds: int | None, row_limit: int
    ) -> dict[str, Any]:
        earliest = "-24h" if time_seconds is None or time_seconds > 86400 else None
        suggestion = query
        if not re.search(r"(?i)\|\s*(head|tail)\s+\d+", query):
            suggestion = f"{query} | head {min(row_limit, 100)}"
        return {
            "spl": suggestion,
            "earliest_time": earliest,
            "row_limit": min(row_limit, 100),
            "requires_index_scope": not index_scoped,
        }
