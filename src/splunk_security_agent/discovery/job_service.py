from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from ..assurance.service import (
    DISCOVERY_CALL_ESTIMATES,
    AssuranceBudgetExceeded,
    BudgetedSplunkClient,
)
from ..schemas import DiscoveryJobRecord
from .job_store import DiscoveryJobStore


class DiscoveryJobService:
    """Single-instance durable executor for operator-initiated discovery."""

    def __init__(
        self,
        store: DiscoveryJobStore,
        client_factory: Callable[[], Any],
        pipeline_factory: Callable[[Any], Any],
        on_complete: Callable[[str, dict[str, Any]], Awaitable[None] | None] | None = None,
        run_lock: asyncio.Lock | None = None,
        preflight: Callable[[str, Any], Awaitable[dict[str, Any]]] | None = None,
        audit: Any | None = None,
        poll_seconds: float = 1.0,
    ):
        self.store = store
        self.client_factory = client_factory
        self.pipeline_factory = pipeline_factory
        self.on_complete = on_complete
        self.run_lock = run_lock
        self.preflight = preflight
        self.audit = audit
        self.poll_seconds = poll_seconds
        self._worker: asyncio.Task[None] | None = None
        self._active_task: asyncio.Task[None] | None = None
        self._active_job_id = ""
        self._wake = asyncio.Event()
        self._stopping = False

    async def start(self) -> None:
        if self._worker and not self._worker.done():
            return
        self._stopping = False
        self.store.recover_interrupted()
        self._worker = asyncio.create_task(self._work_loop(), name="signalroom-manual-discovery")

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
        self._active_job_id = ""

    def enqueue(self, depth: str, requested_by: str) -> DiscoveryJobRecord:
        if depth not in DISCOVERY_CALL_ESTIMATES:
            raise ValueError(f"Unsupported discovery depth: {depth}")
        if self.store.active_job() is not None:
            raise ValueError("A manual discovery job is already queued or running")
        job = self.store.create_job(depth, requested_by or "local-operator", DISCOVERY_CALL_ESTIMATES[depth])
        self._wake.set()
        return job

    async def cancel(self, job_id: str) -> DiscoveryJobRecord | None:
        job = self.store.request_cancel(job_id)
        if job and job_id == self._active_job_id and self._active_task:
            self._active_task.cancel()
            await asyncio.gather(self._active_task, return_exceptions=True)
            job = self.store.get_job(job_id)
        self._wake.set()
        return job

    def overview(self, limit: int = 20) -> dict[str, Any]:
        active = self.store.active_job()
        return {
            "active_job": active.model_dump(mode="json") if active else None,
            "active_events": self.store.events(active.id) if active else [],
            "jobs": [item.model_dump(mode="json") for item in self.store.list_jobs(limit=limit)],
            "required_calls": DISCOVERY_CALL_ESTIMATES,
            "worker": {
                "online": bool(self._worker and not self._worker.done()),
                "single_run_concurrency": 1,
                "restart_recovery": "fresh-read-only-retry",
                "result_retention": "durable-local-summary",
            },
        }

    async def _work_loop(self) -> None:
        while not self._stopping:
            try:
                queued = self.store.next_queued()
                if queued:
                    self._active_job_id = queued.id
                    self._active_task = asyncio.create_task(self._execute(queued.id))
                    await self._active_task
                    self._active_task = None
                    self._active_job_id = ""
                    continue
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self.poll_seconds)
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._record(
                    "discovery.worker.error",
                    "execute",
                    "",
                    "system",
                    "error",
                    f"Manual discovery worker error: {exc}",
                    {},
                )
                await asyncio.sleep(min(self.poll_seconds, 2))

    async def _execute(self, job_id: str) -> None:
        running = self.store.mark_running(job_id)
        if running is None:
            return
        client = BudgetedSplunkClient(self.client_factory(), running.call_budget)

        async def progress(event: dict[str, Any]) -> None:
            current = self.store.get_job(job_id)
            if current and current.cancel_requested:
                raise asyncio.CancelledError
            merged = {
                **event,
                "progress": event.get("progress", current.progress if current else 0),
                "metrics": {
                    **(event.get("metrics") or {}),
                    "splunk_calls": client.calls_used,
                    "call_budget": client.limit,
                },
            }
            self.store.update_progress(job_id, merged, client.calls_used)

        try:
            if self.preflight is not None:
                await progress(
                    {
                        "phase": "connection:preflight",
                        "label": "Checking Splunk connection readiness",
                        "detail": (
                            "No Splunk discovery calls will run until transport, TLS, "
                            "authentication, and required MCP tools are ready."
                        ),
                        "progress": 2,
                        "metrics": {"splunk_calls": 0},
                    }
                )
                readiness = await self.preflight(running.depth, progress)
                if not readiness.get("depth_readiness", {}).get(running.depth, False):
                    blocking_stage = str(readiness.get("blocking_stage") or "tool-contract")
                    stage = next(
                        (item for item in readiness.get("stages", []) if item.get("id") == blocking_stage),
                        {},
                    )
                    detail = str(
                        stage.get("detail") or f"The endpoint is not ready for {running.depth} discovery."
                    )
                    summary = {
                        "discovery_run_id": "",
                        "findings": 0,
                        "collection_failures": 0,
                        "connection_blocked": True,
                        "blocking_stage": blocking_stage,
                        "headline": detail,
                    }
                    self.store.complete_job(job_id, "connection-blocked", summary, None, client.calls_used)
                    self._record_completion(running, "connection-blocked", summary, client.calls_used)
                    return

            pipeline = self.pipeline_factory(client)
            if self.run_lock is not None:
                if self.run_lock.locked():
                    await progress(
                        {
                            "phase": "instance-queue",
                            "label": "Waiting for the Splunk discovery lane",
                            "detail": (
                                "Another manual discovery, assurance run, or MLTK inventory "
                                "owns the single-instance read-only lane."
                            ),
                            "progress": 1,
                            "metrics": {"instance_concurrency": 1},
                        }
                    )
                async with self.run_lock:
                    result = await pipeline.run(running.depth, progress=progress)
                    projection = self._projection(pipeline, result)
            else:
                result = await pipeline.run(running.depth, progress=progress)
                projection = self._projection(pipeline, result)

            summary = self._summary(result)
            if client.exceeded:
                status = "budget-blocked"
                summary["headline"] = (
                    f"The {client.limit}-call ceiling was reached; review the retained "
                    "partial result and collection gaps."
                )
            elif summary["collection_failures"]:
                status = "partial"
            else:
                status = "complete"
            self.store.complete_job(job_id, status, summary, projection, client.calls_used)
            self._record_completion(running, status, summary, client.calls_used)
            if self.on_complete:
                completed = self.on_complete(job_id, result)
                if inspect.isawaitable(completed):
                    await completed
        except asyncio.CancelledError:
            current = self.store.get_job(job_id)
            if current and current.cancel_requested:
                self.store.fail_job(
                    job_id,
                    "cancelled",
                    "Cancelled by the operator. No further Splunk calls will be made.",
                    client.calls_used,
                )
            else:
                self.store.requeue_for_restart(job_id)
        except AssuranceBudgetExceeded as exc:
            summary = {
                "discovery_run_id": "",
                "findings": 0,
                "collection_failures": 1,
                "headline": str(exc),
            }
            self.store.complete_job(job_id, "budget-blocked", summary, None, client.calls_used)
            self._record_completion(running, "budget-blocked", summary, client.calls_used)
        except Exception as exc:
            self.store.fail_job(job_id, "error", str(exc), client.calls_used)
            self._record(
                "discovery.job.failed",
                "execute",
                job_id,
                running.requested_by,
                "error",
                str(exc),
                {
                    "depth": running.depth,
                    "splunk_calls": client.calls_used,
                    "call_budget": client.limit,
                },
            )

    @staticmethod
    def _projection(pipeline: Any, result: dict[str, Any]) -> dict[str, Any]:
        if hasattr(pipeline, "latest_summary"):
            projected = pipeline.latest_summary()
            if projected:
                return projected
        excluded = {"catalogs", "raw_inventory", "raw_results"}
        return {key: value for key, value in result.items() if key not in excluded}

    @staticmethod
    def _summary(result: dict[str, Any]) -> dict[str, Any]:
        changes = result.get("changes", {})
        inventory_drift = sum(
            len(value.get("added", [])) + len(value.get("removed", []))
            for value in changes.get("inventory", {}).values()
            if isinstance(value, dict)
        )
        findings = result.get("findings", [])
        collection_failures = int(result.get("collection_status", {}).get("failed_calls", 0))
        return {
            "discovery_run_id": result.get("run_id", ""),
            "findings": len(findings),
            "high_findings": sum(1 for item in findings if item.get("severity") in {"critical", "high"}),
            "inventory_drift": inventory_drift,
            "coverage_drift": len(changes.get("coverage", {})),
            "collection_failures": collection_failures,
            "coverage_score": result.get("coverage", {}).get("score"),
            "headline": (
                f"{len(findings)} findings · {inventory_drift} inventory changes · "
                f"{collection_failures} collection gaps."
            ),
        }

    def _record_completion(
        self,
        job: DiscoveryJobRecord,
        status: str,
        summary: dict[str, Any],
        calls_used: int,
    ) -> None:
        self._record(
            "discovery.job.completed",
            "complete",
            job.id,
            job.requested_by,
            status,
            str(summary.get("headline") or "Manual discovery finished."),
            {
                "depth": job.depth,
                "status": status,
                "splunk_calls": calls_used,
                "call_budget": job.call_budget,
                "discovery_run_id": summary.get("discovery_run_id", ""),
            },
        )

    def _record(
        self,
        event_type: str,
        action: str,
        job_id: str,
        actor: str,
        outcome: str,
        summary: str,
        metadata: dict[str, Any],
    ) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                event_type,
                action,
                target_type="discovery-job",
                target_id=job_id,
                outcome=outcome,
                summary=summary,
                metadata=metadata,
                actor=actor,
            )
        except Exception:
            pass
