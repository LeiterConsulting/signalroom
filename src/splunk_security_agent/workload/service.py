from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from ..progress import ProgressCallback, report_progress
from ..schemas import WorkloadPolicyUpdate
from .estimator import estimate_query
from .store import WorkloadStore

_operation: contextvars.ContextVar[str] = contextvars.ContextVar(
    "signalroom_workload_operation", default="splunk-mcp"
)
_progress: contextvars.ContextVar[ProgressCallback | None] = contextvars.ContextVar(
    "signalroom_workload_progress", default=None
)


class WorkloadPolicyBlocked(RuntimeError):
    pass


class WorkloadQueueTimeout(RuntimeError):
    pass


@dataclass
class _InstanceState:
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)
    active_calls: int = 0
    active_queries: int = 0
    queued_calls: int = 0
    queued_queries: int = 0
    reserved_query_units: int = 0


class SplunkWorkloadService:
    """One enforceable admission controller shared by every normal Splunk MCP caller."""

    def __init__(self, store: WorkloadStore):
        self.store = store
        self._states: dict[str, _InstanceState] = {}
        self.current_instance_id = "unconfigured"

    @staticmethod
    def instance_id(identity: dict[str, Any]) -> str:
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]

    def set_current_instance(self, identity: dict[str, Any]) -> str:
        self.current_instance_id = self.instance_id(identity)
        self._state(self.current_instance_id)
        return self.current_instance_id

    def _state(self, instance_id: str) -> _InstanceState:
        return self._states.setdefault(instance_id, _InstanceState())

    @asynccontextmanager
    async def scope(
        self, operation: str, progress: ProgressCallback | None = None
    ):
        operation_token = _operation.set(operation[:160] or "splunk-mcp")
        progress_token = _progress.set(progress)
        try:
            yield
        finally:
            _progress.reset(progress_token)
            _operation.reset(operation_token)

    async def update_policy(self, value: WorkloadPolicyUpdate) -> dict[str, Any]:
        self.store.update_policy(value)
        for state in self._states.values():
            async with state.condition:
                state.condition.notify_all()
        return self.overview()

    def assess_query(
        self,
        spl: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        row_limit: int = 100,
        *,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        selected = instance_id or self.current_instance_id
        estimate = estimate_query(spl, earliest_time, latest_time, row_limit)
        return self._assessment(estimate, selected)

    def _assessment(self, estimate: dict[str, Any], instance_id: str) -> dict[str, Any]:
        policy = self.store.policy()
        state = self._state(instance_id)
        used = self.store.daily_usage(instance_id)
        projected = used + state.reserved_query_units + estimate["estimated_cost_units"]
        reasons: list[str] = []
        hard_block = bool(estimate["blocked_reason"])
        if hard_block:
            reasons.append(estimate["blocked_reason"])
        if estimate["score"] > policy["max_query_risk_score"]:
            reasons.append(
                f"Risk score {estimate['score']} exceeds the configured "
                f"{policy['max_query_risk_score']} threshold"
            )
        if estimate["estimated_cost_units"] > policy["max_query_cost_units"]:
            reasons.append(
                f"Estimated cost {estimate['estimated_cost_units']} exceeds the configured "
                f"{policy['max_query_cost_units']}-unit per-query limit"
            )
        if projected > policy["daily_query_cost_units"]:
            reasons.append(
                f"Projected UTC-day usage {projected} exceeds the configured "
                f"{policy['daily_query_cost_units']}-unit budget"
            )
        governed_block = policy["mode"] == "enforce" and bool(reasons) and not hard_block
        decision = (
            "block"
            if hard_block or governed_block
            else "audit-warning"
            if reasons
            else "allow"
        )
        return {
            "mode": policy["mode"],
            "decision": decision,
            "reasons": reasons,
            "estimated_cost_units": estimate["estimated_cost_units"],
            "cost_model": estimate["cost_model"],
            "daily_used_units": used,
            "daily_reserved_units": state.reserved_query_units,
            "daily_budget_units": policy["daily_query_cost_units"],
            "daily_remaining_units": max(0, policy["daily_query_cost_units"] - used),
            "policy_generation": policy["generation"],
            "limits": {
                "max_concurrent_calls": policy["max_concurrent_calls"],
                "max_concurrent_queries": policy["max_concurrent_queries"],
                "queue_timeout_seconds": policy["queue_timeout_seconds"],
                "max_query_risk_score": policy["max_query_risk_score"],
                "max_query_cost_units": policy["max_query_cost_units"],
            },
            "instance": self.runtime(instance_id),
        }

    def runtime(self, instance_id: str | None = None) -> dict[str, Any]:
        selected = instance_id or self.current_instance_id
        state = self._state(selected)
        return {
            "id": selected,
            "active_calls": state.active_calls,
            "active_queries": state.active_queries,
            "queued_calls": state.queued_calls,
            "queued_queries": state.queued_queries,
        }

    def overview(self) -> dict[str, Any]:
        policy = self.store.policy()
        runtime = self.runtime()
        used = self.store.daily_usage(self.current_instance_id)
        return {
            "policy": policy,
            "runtime": runtime,
            "budget": {
                "used_units": used,
                "reserved_units": self._state(self.current_instance_id).reserved_query_units,
                "limit_units": policy["daily_query_cost_units"],
                "remaining_units": max(0, policy["daily_query_cost_units"] - used),
                "resets": "00:00 UTC",
            },
            "events": self.store.recent(40),
            "contract": {
                "audit_first": True,
                "concurrency_limits": (
                    "Always enforced to prevent local bursts; risk and daily cost gates block "
                    "only in enforce mode."
                ),
                "cost_estimate": (
                    "Relative preflight units, not predicted scan bytes or Splunk scheduler cost."
                ),
                "splunk_authority": (
                    "Splunk workload pools, roles, quotas, and search limits remain authoritative."
                ),
                "raw_spl_retained": False,
            },
        }

    async def call(
        self,
        client: Any,
        instance_id: str,
        name: str,
        arguments: dict[str, Any],
    ) -> Any:
        query = name == "run_query"
        estimate = (
            estimate_query(
                str(arguments.get("query") or arguments.get("search") or ""),
                str(arguments.get("earliest_time") or "-24h"),
                str(arguments.get("latest_time") or "now"),
                int(arguments.get("row_limit") or arguments.get("count") or 100),
            )
            if query
            else {
                "risk": "none",
                "score": 0,
                "blocked_reason": "",
                "estimated_cost_units": 0,
                "cost_model": "",
            }
        )
        assessment = self._assessment(estimate, instance_id) if query else None
        policy = self.store.policy()
        decision = assessment["decision"] if assessment else "allow"
        reasons = assessment["reasons"] if assessment else []
        fingerprint = (
            hashlib.sha256(
                json.dumps(
                    {
                        "query": str(arguments.get("query") or arguments.get("search") or "").strip(),
                        "earliest_time": arguments.get("earliest_time"),
                        "latest_time": arguments.get("latest_time"),
                        "row_limit": arguments.get("row_limit") or arguments.get("count"),
                    },
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            if query
            else ""
        )
        event_id = self.store.create_event(
            instance_id=instance_id,
            operation=_operation.get(),
            logical_name=name,
            lane="query" if query else "metadata",
            query_fingerprint=fingerprint,
            risk=estimate["risk"],
            risk_score=estimate["score"],
            cost_units=estimate["estimated_cost_units"],
            decision=decision,
            status="blocked" if decision == "block" else "queued",
            reasons=reasons,
            policy_generation=policy["generation"],
        )
        if decision == "block":
            await self._blocked_progress(assessment or {}, name)
            raise WorkloadPolicyBlocked(
                "Splunk workload policy blocked this query: " + "; ".join(reasons)
            )

        state = self._state(instance_id)
        wait_started = time.monotonic()
        admitted = False
        wait_ms = 0
        started = 0.0
        try:
            await self._admit(
                state,
                instance_id,
                query=query,
                cost_units=estimate["estimated_cost_units"],
                risk_score=estimate["score"],
                timeout_seconds=policy["queue_timeout_seconds"],
                event_id=event_id,
                logical_name=name,
            )
            admitted = True
            wait_ms = int((time.monotonic() - wait_started) * 1000)
            started = time.monotonic()
            self.store.update_event(event_id, "running", wait_ms=wait_ms)
            result = await client.call(name, arguments)
            duration_ms = int((time.monotonic() - started) * 1000)
            self.store.update_event(
                event_id, "complete", wait_ms=wait_ms, duration_ms=duration_ms
            )
            return result
        except asyncio.CancelledError:
            self.store.update_event(event_id, "cancelled")
            raise
        except WorkloadQueueTimeout as exc:
            self.store.update_event(event_id, "blocked", wait_ms=wait_ms, error=str(exc))
            raise
        except WorkloadPolicyBlocked as exc:
            self.store.update_event(event_id, "blocked", wait_ms=wait_ms, error=str(exc))
            await report_progress(
                _progress.get(),
                "workload:blocked",
                "Splunk workload policy changed while this call was queued",
                str(exc),
                status="error",
                metrics={"tool": name, "estimated_cost_units": estimate["estimated_cost_units"]},
            )
            raise
        except Exception as exc:
            duration_ms = int((time.monotonic() - started) * 1000) if started else 0
            self.store.update_event(
                event_id,
                "error",
                wait_ms=wait_ms,
                duration_ms=duration_ms,
                error=str(exc),
            )
            raise
        finally:
            if admitted:
                await self._release(state, query, estimate["estimated_cost_units"])

    async def _admit(
        self,
        state: _InstanceState,
        instance_id: str,
        *,
        query: bool,
        cost_units: int,
        risk_score: int,
        timeout_seconds: int,
        event_id: str,
        logical_name: str,
    ) -> None:
        queued_at = time.monotonic()
        reported = False
        async with state.condition:
            state.queued_calls += 1
            if query:
                state.queued_queries += 1
            try:
                while True:
                    policy = self.store.policy()
                    if query and policy["mode"] == "enforce":
                        used = self.store.daily_usage(instance_id)
                        if (
                            risk_score > policy["max_query_risk_score"]
                            or cost_units > policy["max_query_cost_units"]
                            or used + state.reserved_query_units + cost_units
                            > policy["daily_query_cost_units"]
                        ):
                            raise WorkloadPolicyBlocked(
                                "The enforced risk or UTC-day cost threshold is no longer available"
                            )
                    call_ready = state.active_calls < policy["max_concurrent_calls"]
                    query_ready = (
                        not query
                        or state.active_queries < policy["max_concurrent_queries"]
                    )
                    if call_ready and query_ready:
                        state.queued_calls -= 1
                        if query:
                            state.queued_queries -= 1
                            state.active_queries += 1
                            state.reserved_query_units += cost_units
                        state.active_calls += 1
                        await report_progress(
                            _progress.get(),
                            "workload:admitted",
                            "Splunk workload admission granted",
                            (
                                f"{logical_name} entered the shared "
                                f"{'query' if query else 'metadata'} lane."
                            ),
                            status="complete",
                            metrics={
                                "active_calls": state.active_calls,
                                "active_queries": state.active_queries,
                                "estimated_cost_units": cost_units,
                            },
                        )
                        return
                    if not reported:
                        reported = True
                        self.store.update_event(event_id, "queued")
                        await report_progress(
                            _progress.get(),
                            "workload:queue",
                            "Waiting for Splunk workload capacity",
                            (
                                "SignalRoom is holding this call locally so concurrent "
                                "investigations do not overload the configured instance."
                            ),
                            metrics={
                                "queue_position": state.queued_calls,
                                "active_calls": state.active_calls,
                                "active_queries": state.active_queries,
                                "call_limit": policy["max_concurrent_calls"],
                                "query_limit": policy["max_concurrent_queries"],
                                "estimated_cost_units": cost_units,
                            },
                        )
                    remaining = timeout_seconds - (time.monotonic() - queued_at)
                    if remaining <= 0:
                        raise WorkloadQueueTimeout(
                            f"Splunk workload admission timed out after {timeout_seconds} seconds"
                        )
                    try:
                        await asyncio.wait_for(state.condition.wait(), timeout=remaining)
                    except TimeoutError as exc:
                        raise WorkloadQueueTimeout(
                            f"Splunk workload admission timed out after {timeout_seconds} seconds"
                        ) from exc
            except BaseException:
                state.queued_calls = max(0, state.queued_calls - 1)
                if query:
                    state.queued_queries = max(0, state.queued_queries - 1)
                raise

    async def _release(
        self, state: _InstanceState, query: bool, cost_units: int
    ) -> None:
        async with state.condition:
            state.active_calls = max(0, state.active_calls - 1)
            if query:
                state.active_queries = max(0, state.active_queries - 1)
                state.reserved_query_units = max(
                    0, state.reserved_query_units - cost_units
                )
            state.condition.notify_all()

    @staticmethod
    async def _blocked_progress(assessment: dict[str, Any], name: str) -> None:
        await report_progress(
            _progress.get(),
            "workload:blocked",
            "Splunk workload policy blocked execution",
            "; ".join(assessment.get("reasons") or ["Policy threshold exceeded"]),
            status="error",
            metrics={
                "tool": name,
                "estimated_cost_units": assessment.get("estimated_cost_units", 0),
                "daily_remaining_units": assessment.get("daily_remaining_units", 0),
            },
        )


class WorkloadControlledSplunkClient:
    def __init__(
        self, client: Any, workload: SplunkWorkloadService, instance_id: str
    ):
        self.client = client
        self.workload = workload
        self.instance_id = instance_id

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        return await self.workload.call(
            self.client, self.instance_id, name, arguments or {}
        )

    def scope(
        self, operation: str, progress: ProgressCallback | None = None
    ):
        return self.workload.scope(operation, progress)
