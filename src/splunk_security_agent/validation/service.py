from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any

from ..cases import CaseStore
from ..progress import ProgressCallback, report_progress
from ..rag import EvidenceStore
from ..schemas import (
    ArtifactCreate,
    CaseItemCreate,
    ValidationTaskCreate,
    ValidationTaskRecord,
    ValidationTaskUpdate,
)
from ..splunk.guardrails import validate_read_only_spl
from .store import ValidationStore

RELATIVE_TIME = re.compile(r"^-(?P<count>\d{1,4})(?P<unit>[smhdw])$")
MAX_WINDOW_SECONDS = 30 * 24 * 60 * 60
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class ValidationService:
    def __init__(
        self,
        store: ValidationStore,
        splunk_client: Any,
        evidence: EvidenceStore,
        cases: CaseStore,
    ):
        self.store = store
        self.splunk = splunk_client
        self.evidence = evidence
        self.cases = cases

    def create(self, value: ValidationTaskCreate) -> ValidationTaskRecord:
        self.validate_contract(value.spl, value.earliest_time, value.latest_time, value.row_limit)
        return self.store.create(value)

    def update(
        self, task_id: str, value: ValidationTaskUpdate
    ) -> ValidationTaskRecord | None:
        current = self.store.get(task_id)
        if current is None:
            return None
        merged = current.model_dump()
        merged.update(value.model_dump(exclude_none=True))
        self.validate_contract(
            merged["spl"],
            merged["earliest_time"],
            merged["latest_time"],
            merged["row_limit"],
        )
        return self.store.update(task_id, value)

    def approve(self, task_id: str) -> ValidationTaskRecord | None:
        current = self.store.get(task_id)
        if current is None:
            return None
        self.validate_contract(
            current.spl, current.earliest_time, current.latest_time, current.row_limit
        )
        return self.store.approve(task_id)

    @staticmethod
    def validate_contract(
        spl: str, earliest_time: str, latest_time: str, row_limit: int
    ) -> None:
        validate_read_only_spl(spl)
        match = RELATIVE_TIME.fullmatch(earliest_time.strip())
        if not match:
            raise ValueError("Earliest time must be a bounded relative value such as -24h or -7d")
        seconds = int(match.group("count")) * UNIT_SECONDS[match.group("unit")]
        if seconds > MAX_WINDOW_SECONDS:
            raise ValueError("Validation time windows cannot exceed 30 days")
        if latest_time.strip() != "now":
            raise ValueError("Validation tasks currently require latest_time=now")
        if not 1 <= row_limit <= 500:
            raise ValueError("Validation row limits must be between 1 and 500")

    async def execute(
        self, task_id: str, progress: ProgressCallback | None = None
    ) -> ValidationTaskRecord:
        task = self.store.get(task_id)
        if task is None:
            raise KeyError(f"Validation task not found: {task_id}")
        self.validate_contract(task.spl, task.earliest_time, task.latest_time, task.row_limit)
        running = self.store.mark_running(task_id)
        if running is None:
            raise ValueError("Validation task must be explicitly approved before execution")
        await report_progress(
            progress,
            "validation:guardrail",
            "Approval and read-only guardrails confirmed",
            (
                f"Window: {running.earliest_time} to {running.latest_time} · "
                f"row limit: {running.row_limit}."
            ),
            progress=18,
            status="complete",
            metrics={"row_limit": running.row_limit, "approved": True},
        )
        arguments = {
            "query": running.spl,
            "earliest_time": running.earliest_time,
            "latest_time": running.latest_time,
            "row_limit": running.row_limit,
        }
        try:
            await report_progress(
                progress,
                "validation:splunk",
                "Running approved validation through Splunk MCP",
                "SignalRoom is executing the exact previewed SPL contract.",
                progress=46,
                metrics={"tool": "run_query", "fingerprint": running.query_fingerprint[:12]},
            )
            result = await self.splunk.call("run_query", arguments)
            rows = self._rows(result)
            preview = self._bounded_preview(rows)
            await report_progress(
                progress,
                "validation:preserve",
                "Preserving validation evidence",
                f"Splunk returned {len(rows)} row(s); a bounded preview is being indexed locally.",
                progress=78,
                metrics={"result_count": len(rows), "preview_rows": len(preview)},
            )
            artifact = self.evidence.add(
                ArtifactCreate(
                    title=f"Validation · {running.title}",
                    kind="validation",
                    source="Approved Splunk MCP validation",
                    tags=["splunk", "validation", *running.evidence_refs],
                    content=self._artifact_content(running, len(rows), preview),
                ),
                metadata={
                    "validation_task_id": running.id,
                    "source_run_id": running.source_run_id,
                    "query_fingerprint": running.query_fingerprint,
                    "executed_at": datetime.now(UTC).isoformat(),
                },
            )
            if running.case_id and self.cases.get(running.case_id):
                self.cases.add_item(
                    running.case_id,
                    CaseItemCreate(
                        kind="evidence",
                        title=running.title,
                        content=(
                            f"Approved validation returned {len(rows)} row(s).\n\n"
                            f"SPL: {running.spl}\nWindow: {running.earliest_time} to "
                            f"{running.latest_time}\nArtifact: {artifact.id}"
                        ),
                        source="SignalRoom validation queue",
                        confidence="high",
                        status="observed",
                        metadata={
                            "validation_task_id": running.id,
                            "artifact_id": artifact.id,
                            "evidence_refs": running.evidence_refs,
                        },
                    ),
                )
            completed = self.store.complete(running.id, len(rows), preview, artifact.id)
            assert completed is not None
            await report_progress(
                progress,
                "validation:complete",
                "Validation result preserved",
                f"{len(rows)} row(s) · evidence artifact {artifact.id}.",
                progress=100,
                status="complete",
                metrics={"result_count": len(rows), "artifact_id": artifact.id},
            )
            return completed
        except asyncio.CancelledError:
            self.store.requeue_interrupted(
                running.id, "Execution was cancelled; approval is preserved for a retry."
            )
            raise
        except Exception as exc:
            self.store.fail(running.id, str(exc))
            raise

    @staticmethod
    def _rows(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            status_code = value.get("status_code")
            try:
                failed = status_code is not None and int(status_code) >= 400
            except (TypeError, ValueError):
                failed = False
            if failed:
                detail = value.get("content") or value.get("error") or "The query was rejected"
                raise ValueError(f"Splunk MCP query failed ({status_code}): {detail}")
            if value.get("error"):
                raise ValueError(f"Splunk MCP query failed: {value['error']}")
            for key in ("results", "items", "data"):
                if isinstance(value.get(key), list):
                    return value[key]
        return []

    @staticmethod
    def _bounded_preview(rows: list[Any]) -> list[Any]:
        preview: list[Any] = []
        total_chars = 0
        for row in rows[:50]:
            if isinstance(row, dict):
                bounded = {
                    str(key)[:160]: str(value)[:4000] if not isinstance(value, (int, float, bool)) else value
                    for key, value in list(row.items())[:80]
                }
            else:
                bounded = str(row)[:4000]
            size = len(json.dumps(bounded, default=str))
            if total_chars + size > 100000:
                break
            preview.append(bounded)
            total_chars += size
        return preview

    @staticmethod
    def _artifact_content(
        task: ValidationTaskRecord, result_count: int, preview: list[Any]
    ) -> str:
        return "\n".join(
            [
                f"# {task.title}",
                "",
                f"- Validation task: `{task.id}`",
                f"- Source discovery: `{task.source_run_id or 'manual'}`",
                f"- Evidence references: {', '.join(task.evidence_refs) or 'none'}",
                f"- Query fingerprint: `{task.query_fingerprint}`",
                f"- Window: `{task.earliest_time}` to `{task.latest_time}`",
                f"- Row limit: {task.row_limit}",
                f"- Result count: {result_count}",
                "",
                "## Rationale",
                task.rationale,
                "",
                "## Executed SPL",
                f"```spl\n{task.spl}\n```",
                "",
                "## Bounded result preview",
                f"```json\n{json.dumps(preview, indent=2, default=str)}\n```",
            ]
        )
