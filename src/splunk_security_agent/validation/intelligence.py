from __future__ import annotations

from typing import Any

from ..schemas import QueryIntelligenceRequest
from ..workload import estimate_query


class QueryIntelligenceService:
    """Explain bounded SPL execution risk and known reuse without running a query."""

    def __init__(self, store: Any, workload: Any | None = None):
        self.store = store
        self.workload = workload

    def analyze(self, request: QueryIntelligenceRequest) -> dict[str, Any]:
        query = request.spl.strip()
        result = estimate_query(
            query,
            request.earliest_time,
            request.latest_time,
            request.row_limit,
        )
        fingerprint = self.store.fingerprint(
            query, request.earliest_time, request.latest_time, request.row_limit
        )
        reusable = self.store.find_latest_complete(
            fingerprint,
            request.exclude_task_id,
            tenant_scope_id=request.tenant_scope_id,
        )
        workload = (
            self.workload.assess_query(
                query,
                request.earliest_time,
                request.latest_time,
                request.row_limit,
            )
            if self.workload is not None
            else None
        )
        result.update(
            {
                "query_fingerprint": fingerprint,
                "reusable_result": reusable.model_dump(mode="json") if reusable else None,
                "workload": workload,
                "execution_recommendation": self._recommendation(
                    result, reusable, workload
                ),
            }
        )
        return result

    @staticmethod
    def _recommendation(
        estimate: dict[str, Any], reusable: Any | None, workload: dict[str, Any] | None
    ) -> str:
        if estimate["blocked_reason"]:
            return "Blocked by the read-only policy. Edit the SPL before approval."
        if workload and workload["decision"] == "block":
            return (
                "Blocked by the enforced Splunk workload policy. Narrow the contract "
                "or ask an administrator to review the configured thresholds."
            )
        if reusable:
            return "Reuse the preserved result unless fresher evidence is materially required."
        if workload and workload["decision"] == "audit-warning":
            return (
                "Audit mode would allow this query, but it crosses one or more configured "
                "workload thresholds. Stage the narrower contract before enforcement is enabled."
            )
        if estimate["risk"] in {"high", "medium"}:
            return "Stage this query with the narrow contract below before widening."
        return "The query is bounded enough for explicit analyst approval."
