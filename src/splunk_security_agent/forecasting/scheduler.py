from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from ..audit import AuditStore
from ..schemas import TimeSeriesForecastRequest
from .schedule_store import TimeSeriesScheduleStore
from .service import TimeSeriesForecastService

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None]]
AuthorizationCheck = Callable[[str], tuple[bool, str]]


class TimeSeriesScheduleService:
    """Single-lane executor for explicitly enabled local shadow forecasts."""

    def __init__(
        self,
        store: TimeSeriesScheduleStore,
        forecast: TimeSeriesForecastService,
        audit: AuditStore,
        authorize_owner: AuthorizationCheck,
        *,
        poll_seconds: float = 2.0,
    ):
        self.store = store
        self.forecast = forecast
        self.audit = audit
        self.authorize_owner = authorize_owner
        self.poll_seconds = poll_seconds
        self._worker: asyncio.Task[None] | None = None
        self._active_task: asyncio.Task[None] | None = None
        self._active_attempt_id = ""
        self._wake = asyncio.Event()
        self._stopping = False

    async def start(self) -> None:
        if self._worker and not self._worker.done():
            return
        self._stopping = False
        self.store.recover_interrupted()
        self._worker = asyncio.create_task(
            self._work_loop(),
            name="signalroom-shadow-forecasts",
        )

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
        self._active_attempt_id = ""

    def wake(self) -> None:
        self._wake.set()

    def overview(self, limit: int = 30) -> dict[str, Any]:
        result = self.store.overview(limit)
        result["worker"] = {
            "online": bool(self._worker and not self._worker.done()),
            "active_attempt_id": self._active_attempt_id,
            "single_run_concurrency": 1,
            "restart_recovery": "fresh-read-only-retry",
        }
        return result

    async def run_now(
        self,
        schedule_id: str,
        progress: ProgressCallback,
    ) -> dict[str, Any]:
        if self._worker is None or self._worker.done():
            raise RuntimeError("The shadow forecast worker is offline")
        attempt = self.store.enqueue(schedule_id, trigger="manual")
        self._wake.set()
        emitted = 0
        while True:
            events = self.store.events(attempt["id"])
            for event in events[emitted:]:
                await progress(
                    {
                        key: event[key]
                        for key in (
                            "phase",
                            "label",
                            "detail",
                            "status",
                            "progress",
                            "metrics",
                        )
                    }
                )
            emitted = len(events)
            current = self.store.attempt(attempt["id"])
            if current is None:
                raise RuntimeError("The queued shadow forecast attempt disappeared")
            if current["status"] == "complete":
                return {
                    "attempt": current,
                    "review": next(
                        (item for item in self.store.reviews() if item["attempt_id"] == current["id"]),
                        None,
                    ),
                    "contract": {
                        "automatic_alerting": False,
                        "automatic_threshold_change": False,
                        "network_inference": False,
                    },
                }
            if current["status"] == "error":
                raise RuntimeError(current["error"] or current["detail"])
            await asyncio.sleep(0.15)

    async def _work_loop(self) -> None:
        while not self._stopping:
            try:
                if self.store.active_attempt() is None:
                    self._enqueue_due()
                queued = self.store.next_queued()
                if queued:
                    self._active_attempt_id = queued["id"]
                    self._active_task = asyncio.create_task(
                        self._execute(queued["id"]),
                        name=f"signalroom-shadow-{queued['id'][:8]}",
                    )
                    await self._active_task
                    self._active_task = None
                    self._active_attempt_id = ""
                    continue
                self._wake.clear()
                try:
                    await asyncio.wait_for(
                        self._wake.wait(),
                        timeout=self.poll_seconds,
                    )
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.audit.record(
                    "model.capability.time-series.schedule-worker-failed",
                    "schedule",
                    target_type="forecast-scheduler",
                    outcome="error",
                    summary="The shadow forecast worker recovered from an internal error.",
                    metadata={"error": str(exc)[:1000]},
                    actor="system",
                )
                await asyncio.sleep(min(self.poll_seconds, 2))

    def _enqueue_due(self) -> None:
        schedule = self.store.due()
        if schedule is None:
            return
        try:
            attempt = self.store.enqueue(schedule["id"], trigger="scheduled")
        except ValueError as exc:
            self.store.defer_due(schedule["id"])
            self.audit.record(
                "model.capability.time-series.schedule-deferred",
                "schedule",
                target_type="forecast-schedule",
                target_id=schedule["id"],
                outcome="deferred",
                summary="A due shadow forecast was coalesced into its next interval.",
                metadata={"reason": str(exc)[:1000]},
                actor="system",
            )
            return
        self.audit.record(
            "model.capability.time-series.schedule-enqueued",
            "schedule",
            target_type="forecast-schedule",
            target_id=schedule["id"],
            summary="An enabled shadow forecast entered the single local execution lane.",
            metadata={"attempt_id": attempt["id"], "trigger": "scheduled"},
            actor="system",
        )

    async def _execute(self, attempt_id: str) -> None:
        running = self.store.mark_running(attempt_id)
        if running is None:
            return
        schedule = self.store.get(running["schedule_id"])
        if schedule is None:
            self.store.fail(attempt_id, "The source schedule no longer exists")
            return

        async def progress(event: dict[str, Any]) -> None:
            self.store.update_progress(attempt_id, event)

        try:
            allowed, reason = self.authorize_owner(schedule["created_by"])
            if not allowed:
                raise PermissionError(reason)
            result = await self.forecast.run(
                TimeSeriesForecastRequest(**schedule["request"]),
                progress,
                actor=schedule["created_by"],
                seasonal_comparison=schedule["seasonal_comparison"],
            )
            completed = self.store.complete(attempt_id, result)
            comparison = (result.get("experiment") or {}).get("comparison") or {}
            self.audit.record(
                "model.capability.time-series.shadow-forecasted",
                "forecast",
                target_type="forecast-schedule",
                target_id=schedule["id"],
                summary="A scheduled read-only series was forecast locally and retained for review.",
                metadata={
                    "attempt_id": attempt_id,
                    "run_id": result.get("run_id", ""),
                    "run_fingerprint": (result.get("experiment") or {}).get(
                        "run_fingerprint",
                        "",
                    ),
                    "comparison_decision": comparison.get("decision", ""),
                    "trigger": completed["trigger"],
                    "network_inference": False,
                    "automatic_alerting": False,
                },
                actor=schedule["created_by"],
            )
        except asyncio.CancelledError:
            self.store.requeue_for_restart(attempt_id)
            raise
        except Exception as exc:
            self.store.fail(attempt_id, str(exc))
            self.audit.record(
                "model.capability.time-series.shadow-forecast-failed",
                "forecast",
                target_type="forecast-schedule",
                target_id=schedule["id"],
                outcome="error",
                summary="A shadow forecast stopped without changing an alert or threshold.",
                metadata={
                    "attempt_id": attempt_id,
                    "error": str(exc)[:1000],
                    "network_inference": False,
                },
                actor=schedule["created_by"],
            )
