from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None]]


async def report_progress(
    callback: ProgressCallback | None,
    phase: str,
    label: str,
    detail: str = "",
    *,
    progress: int | None = None,
    status: str = "running",
    metrics: dict[str, Any] | None = None,
) -> None:
    """Emit a sanitized, presentation-ready operation event when a listener is present."""
    if callback is None:
        return
    event: dict[str, Any] = {
        "type": "progress",
        "phase": phase,
        "label": label,
        "detail": detail,
        "status": status,
    }
    if progress is not None:
        event["progress"] = max(0, min(100, progress))
    if metrics:
        event["metrics"] = metrics
    await callback(event)
