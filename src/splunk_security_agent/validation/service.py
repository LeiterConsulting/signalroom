from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
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
from ..splunk.validation_adapter import SplValidationAdapter
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
        workload: Any | None = None,
        splunk_factory: Callable[[dict[str, Any]], Any] | None = None,
        binding_validator: Callable[[str, str, str], tuple[bool, str]] | None = None,
    ):
        self.store = store
        self.splunk = splunk_client
        self.evidence = evidence
        self.cases = cases
        self.workload = workload
        self.splunk_factory = splunk_factory
        self.binding_validator = binding_validator
        self.adapter = SplValidationAdapter()

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

    async def preflight(
        self,
        task_id: str,
        *,
        include_saia: bool = False,
        progress: ProgressCallback | None = None,
    ) -> ValidationTaskRecord:
        task = self.store.get(task_id)
        if task is None:
            raise KeyError(f"Validation task not found: {task_id}")
        self.validate_contract(task.spl, task.earliest_time, task.latest_time, task.row_limit)
        splunk = self._bound_client(task)
        await report_progress(
            progress,
            "validation:preflight-capabilities",
            "Inspecting Splunk validation capabilities",
            "Checking the exact MCP connection for parser and optional SAIA SPL tools.",
            progress=6,
        )
        receipt = await self.adapter.preflight(task, splunk, include_saia=include_saia)
        updated = self.store.set_preflight(task_id, receipt)
        if updated is None:
            raise ValueError("This validation task cannot be preflighted in its current state")
        await report_progress(
            progress,
            "validation:preflight",
            (
                "Splunk parser preflight passed"
                if receipt["status"] == "passed"
                else "Splunk parser proof is incomplete"
                if receipt["status"] == "advisory-only"
                else "Splunk preflight blocked execution"
            ),
            self._preflight_detail(receipt),
            progress=16,
            status="error" if receipt["status"] == "blocked" else "complete",
            metrics={
                "status": receipt["status"],
                "parser": (receipt.get("parser") or {}).get("status", "unavailable"),
                "saia": (receipt.get("saia") or {}).get("status", "not-requested"),
            },
        )
        if receipt["status"] == "blocked":
            raise ValueError(self._preflight_detail(receipt))
        return updated

    async def ensure_preflight(
        self,
        task_id: str,
        *,
        include_saia: bool = False,
        refresh: bool = False,
        progress: ProgressCallback | None = None,
    ) -> ValidationTaskRecord:
        task = self.store.get(task_id)
        if task is None:
            raise KeyError(f"Validation task not found: {task_id}")
        receipt = task.preflight_receipt or {}
        current = (
            receipt.get("query_fingerprint") == task.query_fingerprint
            and receipt.get("connection_fingerprint") == task.connection_fingerprint
            and receipt.get("status") in {"passed", "advisory-only"}
        )
        saia_complete = not include_saia or (receipt.get("saia") or {}).get("status") in {
            "passed",
            "unavailable",
            "error",
        }
        if current and saia_complete and not refresh:
            return task
        return await self.preflight(
            task_id,
            include_saia=include_saia,
            progress=progress,
        )

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
        if task.status != "approved":
            raise ValueError("Validation task must be explicitly approved before execution")
        try:
            task = await self.ensure_preflight(
                task_id,
                include_saia=False,
                refresh=True,
                progress=progress,
            )
        except Exception as exc:
            self.store.fail(task_id, str(exc))
            raise
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
            splunk = self._bound_client(running)
            await report_progress(
                progress,
                "validation:splunk",
                "Running approved validation through Splunk MCP",
                "SignalRoom is executing the exact previewed SPL contract.",
                progress=46,
                metrics={"tool": "run_query", "fingerprint": running.query_fingerprint[:12]},
            )
            if self.workload is not None:
                async with self.workload.scope(
                    f"validation:{running.id}", progress
                ):
                    result = await splunk.call("run_query", arguments)
            else:
                result = await splunk.call("run_query", arguments)
            rows = self._rows(result)
            preview = self._bounded_preview(rows)
            execution_receipt = self.adapter.compare_result_shape(running, rows)
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
                    content=self._artifact_content(
                        running,
                        len(rows),
                        preview,
                        execution_receipt,
                    ),
                    connection_alias=running.connection_alias,
                    connection_fingerprint=running.connection_fingerprint,
                    tenant_scope_id=running.tenant_scope_id,
                ),
                metadata={
                    "validation_task_id": running.id,
                    "source_run_id": running.source_run_id,
                    "query_fingerprint": running.query_fingerprint,
                    "executed_at": datetime.now(UTC).isoformat(),
                    "connection_alias": running.connection_alias,
                    "connection_fingerprint": running.connection_fingerprint,
                    "tenant_scope_id": running.tenant_scope_id,
                    "preflight_receipt": running.preflight_receipt,
                    "execution_receipt": execution_receipt,
                },
            )
            if running.case_id and self.cases.get(
                running.case_id, running.tenant_scope_id
            ):
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
                    running.tenant_scope_id,
                )
            completed = self.store.complete(
                running.id,
                len(rows),
                preview,
                artifact.id,
                execution_receipt,
            )
            assert completed is not None
            await report_progress(
                progress,
                "validation:complete",
                "Validation result preserved",
                (
                    f"{len(rows)} row(s) · shape {execution_receipt['status']} · "
                    f"evidence artifact {artifact.id}."
                ),
                progress=100,
                status="complete",
                metrics={
                    "result_count": len(rows),
                    "artifact_id": artifact.id,
                    "shape_status": execution_receipt["status"],
                },
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

    def _bound_client(self, task: ValidationTaskRecord) -> Any:
        if self.binding_validator is not None:
            valid, reason = self.binding_validator(
                task.connection_alias,
                task.connection_fingerprint,
                task.tenant_scope_id,
            )
            if not valid:
                raise ValueError("Validation target is no longer executable: " + reason)
        scope = {
            "alias": task.connection_alias,
            "fingerprint": task.connection_fingerprint,
            "tenant_scope_id": task.tenant_scope_id,
        }
        return self.splunk_factory(scope) if self.splunk_factory else self.splunk

    @staticmethod
    def _preflight_detail(receipt: dict[str, Any]) -> str:
        checks = receipt.get("checks") or []
        blocked = [
            str(item.get("detail") or "")
            for item in checks
            if isinstance(item, dict) and item.get("status") == "blocked"
        ]
        parser = receipt.get("parser") or {}
        return (
            " ".join(blocked)
            or str(parser.get("summary") or "")
            or "Splunk validation preflight completed."
        )[:4000]

    @staticmethod
    def _artifact_content(
        task: ValidationTaskRecord,
        result_count: int,
        preview: list[Any],
        execution_receipt: dict[str, Any] | None = None,
    ) -> str:
        receipts = json.dumps(
            {
                "preflight": task.preflight_receipt,
                "execution": execution_receipt or {},
            },
            indent=2,
            default=str,
        )
        return "\n".join(
            [
                f"# {task.title}",
                "",
                f"- Validation task: `{task.id}`",
                f"- Source discovery: `{task.source_run_id or 'manual'}`",
                f"- Splunk identity: `{task.connection_alias}` / `{task.tenant_scope_id}`",
                f"- Connection revision: `{task.connection_fingerprint}`",
                f"- Evidence references: {', '.join(task.evidence_refs) or 'none'}",
                f"- Query fingerprint: `{task.query_fingerprint}`",
                f"- Window: `{task.earliest_time}` to `{task.latest_time}`",
                f"- Row limit: {task.row_limit}",
                f"- Result count: {result_count}",
                f"- Result-shape status: `{(execution_receipt or {}).get('status', 'not-assessed')}`",
                "",
                "## Rationale",
                task.rationale,
                "",
                "## Executed SPL",
                f"```spl\n{task.spl}\n```",
                "",
                "## SPL validation receipts",
                f"```json\n{receipts}\n```",
                "",
                "## Bounded result preview",
                f"```json\n{json.dumps(preview, indent=2, default=str)}\n```",
            ]
        )
