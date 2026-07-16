from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from ..schemas import AssurancePolicyUpdate, AssuranceRunRecord
from .store import AssuranceStore

DISCOVERY_CALL_ESTIMATES = {"quick": 4, "standard": 9, "deep": 12}


class AssuranceBudgetExceeded(RuntimeError):
    pass


class BudgetedSplunkClient:
    """Concurrency-safe, hard call ceiling around one assurance run's MCP client."""

    def __init__(self, client: Any, limit: int):
        self.client = client
        self.limit = limit
        self.calls_used = 0
        self.exceeded = False
        self._lock = asyncio.Lock()

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        async with self._lock:
            if self.calls_used >= self.limit:
                self.exceeded = True
                raise AssuranceBudgetExceeded(
                    f"Continuous assurance stopped at its {self.limit}-call Splunk budget"
                )
            self.calls_used += 1
        return await self.client.call(name, arguments or {})


class AssuranceService:
    """Single-instance scheduler and executor for durable read-only assurance runs."""

    def __init__(
        self,
        store: AssuranceStore,
        client_factory: Callable[[], Any],
        pipeline_factory: Callable[[Any], Any],
        on_complete: Callable[[str, dict[str, Any]], Awaitable[None] | None] | None = None,
        run_lock: asyncio.Lock | None = None,
        preflight: Callable[[str, Any], Awaitable[dict[str, Any]]] | None = None,
        poll_seconds: float = 2.0,
    ):
        self.store = store
        self.client_factory = client_factory
        self.pipeline_factory = pipeline_factory
        self.on_complete = on_complete
        self.run_lock = run_lock
        self.preflight = preflight
        self.poll_seconds = poll_seconds
        self._worker: asyncio.Task[None] | None = None
        self._active_task: asyncio.Task[None] | None = None
        self._active_run_id = ""
        self._wake = asyncio.Event()
        self._stopping = False

    async def start(self) -> None:
        if self._worker and not self._worker.done():
            return
        self._stopping = False
        self.store.recover_interrupted()
        self._worker = asyncio.create_task(self._work_loop(), name="signalroom-assurance")

    async def stop(self) -> None:
        self._stopping = True
        if self._active_task and not self._active_task.done():
            self._active_task.cancel()
            await asyncio.gather(self._active_task, return_exceptions=True)
        if self._worker and not self._worker.done():
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
        self._worker = None
        self._active_task = None
        self._active_run_id = ""

    def update_policy(self, value: AssurancePolicyUpdate) -> dict[str, Any]:
        self._validate_budget(value.discovery_depth, value.max_splunk_calls_per_run)
        result = self.store.update_policy(value)
        self._wake.set()
        return result

    def enqueue(self, depth: str | None = None, trigger: str = "manual") -> AssuranceRunRecord:
        policy = self.store.policy()
        selected_depth = depth or policy["discovery_depth"]
        self._validate_budget(selected_depth, policy["max_splunk_calls_per_run"])
        if self.store.active_run() is not None:
            raise ValueError("A continuous assurance run is already queued or running")
        usage = self.store.usage_today()
        if usage["runs"] >= policy["max_runs_per_day"]:
            raise ValueError(
                f"The daily assurance limit of {policy['max_runs_per_day']} run(s) has been reached"
            )
        run = self.store.create_run(
            trigger, selected_depth, policy["max_splunk_calls_per_run"]
        )
        self._wake.set()
        return run

    async def cancel(self, run_id: str) -> AssuranceRunRecord | None:
        run = self.store.request_cancel(run_id)
        if run and run_id == self._active_run_id and self._active_task:
            self._active_task.cancel()
            await asyncio.gather(self._active_task, return_exceptions=True)
            run = self.store.get_run(run_id)
        self._wake.set()
        return run

    def overview(self) -> dict[str, Any]:
        policy = self.store.policy()
        active = self.store.active_run()
        return {
            "policy": policy,
            "required_calls": DISCOVERY_CALL_ESTIMATES,
            "usage_today": self.store.usage_today(),
            "active_run": active.model_dump(mode="json") if active else None,
            "active_events": self.store.events(active.id) if active else [],
            "runs": [item.model_dump(mode="json") for item in self.store.list_runs()],
            "notifications": self.store.notifications(),
            "signals": self.store.signals(),
            "signal_counts": self.store.signal_counts(),
            "response_packages": self.store.packages(),
            "worker": {
                "online": bool(self._worker and not self._worker.done()),
                "single_run_concurrency": 1,
                "restart_recovery": "fresh-read-only-retry",
            },
        }

    async def _work_loop(self) -> None:
        while not self._stopping:
            try:
                self._schedule_due()
                queued = self.store.next_queued()
                if queued:
                    self._active_run_id = queued.id
                    self._active_task = asyncio.create_task(self._execute(queued.id))
                    await self._active_task
                    self._active_task = None
                    self._active_run_id = ""
                    continue
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self.poll_seconds)
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.store.add_notification(
                    "", "high", "worker", "Continuous assurance worker error", str(exc)
                )
                await asyncio.sleep(min(self.poll_seconds, 2))

    def _schedule_due(self) -> None:
        policy = self.store.policy()
        if not policy["enabled"] or not policy.get("next_run_at") or self.store.active_run():
            return
        try:
            due = datetime.fromisoformat(policy["next_run_at"])
        except ValueError:
            due = datetime.now(UTC)
        if due > datetime.now(UTC):
            return
        usage = self.store.usage_today()
        if usage["runs"] >= policy["max_runs_per_day"]:
            self.store.add_notification(
                "",
                "medium",
                "budget",
                "Scheduled assurance deferred by daily budget",
                (
                    f"The configured limit of {policy['max_runs_per_day']} run(s) per UTC day "
                    "has been reached. The next interval remains scheduled."
                ),
            )
            self.store.advance_schedule()
            return
        try:
            self.enqueue(trigger="scheduled")
        except ValueError as exc:
            self.store.add_notification(
                "", "medium", "schedule", "Scheduled assurance was not queued", str(exc)
            )
        finally:
            self.store.advance_schedule()

    async def _execute(self, run_id: str) -> None:
        running = self.store.mark_running(run_id)
        if running is None:
            return
        client = BudgetedSplunkClient(self.client_factory(), running.call_budget)

        async def progress(event: dict[str, Any]) -> None:
            current = self.store.get_run(run_id)
            if current and current.cancel_requested:
                raise asyncio.CancelledError
            event = {
                **event,
                "progress": event.get("progress", current.progress if current else 0),
                "metrics": {
                    **(event.get("metrics") or {}),
                    "splunk_calls": client.calls_used,
                    "call_budget": client.limit,
                },
            }
            self.store.update_progress(run_id, event, client.calls_used)

        try:
            if self.preflight is not None:
                await progress(
                    {
                        "phase": "connection:preflight",
                        "label": "Checking Splunk connection readiness",
                        "detail": "No Splunk tool calls will run until transport and MCP tools are ready.",
                        "progress": 2,
                        "metrics": {"splunk_calls": 0},
                    }
                )
                readiness = await self.preflight(running.depth, progress)
                if not readiness.get("depth_readiness", {}).get(running.depth, False):
                    blocking_stage = str(readiness.get("blocking_stage") or "tool-contract")
                    stage = next(
                        (
                            item
                            for item in readiness.get("stages", [])
                            if item.get("id") == blocking_stage
                        ),
                        {},
                    )
                    detail = str(
                        stage.get("detail")
                        or f"The endpoint is not ready for {running.depth} discovery."
                    )
                    summary = {
                        "discovery_run_id": "",
                        "findings": 0,
                        "high_findings": 0,
                        "inventory_drift": 0,
                        "coverage_drift": 0,
                        "mltk_drift": 0,
                        "dependency_issues": 0,
                        "collection_failures": 0,
                        "coverage_score": None,
                        "connection_blocked": True,
                        "blocking_stage": blocking_stage,
                        "headline": detail,
                    }
                    self.store.complete_run(run_id, "connection-blocked", summary, 0)
                    self.store.add_notification(
                        run_id,
                        "high",
                        "connection",
                        "Continuous assurance paused before Splunk access",
                        detail,
                    )
                    return
            pipeline = self.pipeline_factory(client)
            if self.run_lock is not None:
                if self.run_lock.locked():
                    await progress(
                        {
                            "phase": "instance-queue",
                            "label": "Waiting for the Splunk discovery lane",
                            "detail": (
                                "Another discovery or MLTK inventory owns the single-instance "
                                "read-only execution lane."
                            ),
                            "progress": 1,
                            "metrics": {"instance_concurrency": 1},
                        }
                    )
                async with self.run_lock:
                    result = await pipeline.run(running.depth, progress=progress)
            else:
                result = await pipeline.run(running.depth, progress=progress)
            summary = self._summary(result)
            if client.exceeded:
                status = "budget-blocked"
                summary["headline"] = (
                    f"The {client.limit}-call ceiling was reached; review partial collection gaps."
                )
            elif summary["collection_failures"]:
                status = "partial"
            else:
                status = "complete"
            self.store.complete_run(run_id, status, summary, client.calls_used)
            self._create_notifications(run_id, result, summary, client.exceeded)
            if self.on_complete:
                try:
                    completed = self.on_complete(run_id, result)
                    if inspect.isawaitable(completed):
                        await completed
                except Exception as exc:
                    self.store.add_notification(
                        run_id,
                        "high",
                        "response-package",
                        "Assurance response packaging failed",
                        str(exc),
                    )
        except asyncio.CancelledError:
            current = self.store.get_run(run_id)
            if current and current.cancel_requested:
                self.store.fail_run(
                    run_id,
                    "cancelled",
                    "Cancelled by the operator. No further Splunk calls will be made.",
                    client.calls_used,
                )
            else:
                self.store.requeue_for_restart(run_id)
        except Exception as exc:
            self.store.fail_run(run_id, "error", str(exc), client.calls_used)
            self.store.add_notification(
                run_id,
                "high",
                "execution",
                "Continuous assurance run failed",
                str(exc),
            )

    @staticmethod
    def _summary(result: dict[str, Any]) -> dict[str, Any]:
        changes = result.get("changes", {})
        inventory_drift = sum(
            len(value.get("added", [])) + len(value.get("removed", []))
            for value in changes.get("inventory", {}).values()
            if isinstance(value, dict)
        )
        coverage_drift = len(changes.get("coverage", {}))
        findings = result.get("findings", [])
        high_findings = sum(
            1 for item in findings if item.get("severity") in {"critical", "high"}
        )
        mltk = result.get("splunk_models", {}).get("summary", {})
        collection_failures = int(result.get("collection_status", {}).get("failed_calls", 0))
        return {
            "discovery_run_id": result.get("run_id", ""),
            "findings": len(findings),
            "high_findings": high_findings,
            "inventory_drift": inventory_drift,
            "coverage_drift": coverage_drift,
            "mltk_drift": int(mltk.get("changed", 0)) + int(mltk.get("missing", 0)),
            "dependency_issues": int(mltk.get("dependencies_not_observed", 0)),
            "collection_failures": collection_failures,
            "coverage_score": result.get("coverage", {}).get("score"),
            "headline": (
                f"{len(findings)} findings · {inventory_drift + coverage_drift} posture changes · "
                f"{collection_failures} collection gaps."
            ),
        }

    def _create_notifications(
        self,
        run_id: str,
        result: dict[str, Any],
        summary: dict[str, Any],
        budget_exceeded: bool,
    ) -> None:
        policy = self.store.policy()
        drift = summary["inventory_drift"] + summary["coverage_drift"] + summary["mltk_drift"]
        if policy["notify_on_drift"] and drift:
            self.store.add_notification(
                run_id,
                "medium",
                "drift",
                "Security posture drift detected",
                (
                    f"{summary['inventory_drift']} inventory changes, "
                    f"{summary['coverage_drift']} coverage changes, and "
                    f"{summary['mltk_drift']} MLTK model changes require review."
                ),
            )
        if policy["notify_on_high_findings"] and summary["high_findings"]:
            titles = [
                str(item.get("title") or "High-severity finding")
                for item in result.get("findings", [])
                if item.get("severity") in {"critical", "high"}
            ]
            self.store.add_notification(
                run_id,
                "high",
                "finding",
                f"{summary['high_findings']} high-severity discovery finding(s)",
                "; ".join(titles[:5]),
            )
        if summary["collection_failures"]:
            self.store.add_notification(
                run_id,
                "high",
                "collection",
                "Continuous assurance has collection gaps",
                (
                    f"{summary['collection_failures']} bounded read-only MCP call(s) failed. "
                    "Treat absent inventory as unknown until the connection is validated."
                ),
            )
        if summary["dependency_issues"]:
            self.store.add_notification(
                run_id,
                "low",
                "model-dependency",
                "MLTK model dependencies need endpoint validation",
                (
                    f"{summary['dependency_issues']} declared dependency/dependencies were not "
                    "observed on SignalRoom's configured Ollama endpoint."
                ),
            )
        if budget_exceeded:
            self.store.add_notification(
                run_id,
                "medium",
                "budget",
                "Splunk-call budget reached",
                "The run stopped issuing MCP calls at the configured hard ceiling.",
            )

    @staticmethod
    def _validate_budget(depth: str, budget: int) -> None:
        required = DISCOVERY_CALL_ESTIMATES.get(depth)
        if required is None:
            raise ValueError(f"Unsupported assurance depth: {depth}")
        if budget < required:
            raise ValueError(
                f"{depth.title()} discovery requires up to {required} bounded Splunk calls; "
                f"the configured budget is {budget}"
            )
