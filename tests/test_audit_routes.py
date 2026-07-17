from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest

from splunk_security_agent.schemas import (
    CaseUpdate,
    DetectionGateRunRequest,
    DetectionUpdate,
    DetectionValidationDraftRequest,
    ValidationTaskUpdate,
)


class AuditRecorder:
    def __init__(self) -> None:
        self.event_types: list[str] = []

    def record(self, event_type: str, *args: Any, **kwargs: Any) -> None:
        self.event_types.append(event_type)


class Record(SimpleNamespace):
    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return dict(vars(self))


@pytest.mark.asyncio
async def test_gets_do_not_create_mutation_audits_and_write_routes_do(monkeypatch):
    app_module = importlib.import_module("splunk_security_agent.app")
    audit = AuditRecorder()
    validation = Record(
        id="validation-1",
        query_fingerprint="fingerprint",
        status="draft",
        approval_scope="single-execution",
        expires_at=None,
    )
    case = Record(
        id="case-1",
        status="investigating",
        severity="high",
        owner="Analyst",
    )
    detection = {
        "id": "detection-1",
        "current_version": 2,
        "current_sha256": "a" * 64,
        "status": "draft",
    }
    fake_services = SimpleNamespace(
        audit=audit,
        validation_store=SimpleNamespace(get=lambda task_id: validation),
        validations=SimpleNamespace(
            update=lambda task_id, request: validation,
            approve=lambda task_id: validation,
        ),
        cases=SimpleNamespace(
            get=lambda case_id: case,
            update=lambda case_id, request: case,
        ),
        detection_store=SimpleNamespace(get=lambda detection_id: detection | {"current_version": 1}),
        detections=SimpleNamespace(
            update=lambda detection_id, request: detection,
        ),
    )
    monkeypatch.setattr(app_module, "services", fake_services)

    await app_module.get_validation(validation.id)
    await app_module.get_case(case.id)
    await app_module.get_detection(detection["id"])

    assert audit.event_types == []

    await app_module.update_validation(validation.id, ValidationTaskUpdate(title="Updated"))
    await app_module.approve_validation(validation.id)
    await app_module.update_case(case.id, CaseUpdate(status="monitoring"))
    await app_module.update_detection(
        detection["id"], DetectionUpdate(title="Updated detection")
    )

    assert audit.event_types == [
        "validation.updated",
        "validation.approved",
        "case.updated",
        "detection.version.created",
    ]


@pytest.mark.asyncio
async def test_detection_gate_and_validation_handoff_are_audited(monkeypatch):
    app_module = importlib.import_module("splunk_security_agent.app")
    audit = AuditRecorder()
    detection = {
        "id": "detection-1",
        "current_version": 3,
        "current_sha256": "a" * 64,
        "status": "draft",
    }
    gate = {
        "id": "gate-1",
        "version": 3,
        "content_sha256": "a" * 64,
        "status": "fail",
        "score": 15,
        "validation_task_id": "",
        "baseline_gate_id": "",
        "result_count": 0,
        "result_delta_percent": None,
    }
    task = Record(
        id="validation-1",
        status="draft",
        query_fingerprint="fingerprint",
    )
    fake_services = SimpleNamespace(
        audit=audit,
        detection_store=SimpleNamespace(get=lambda detection_id: detection),
        detections=SimpleNamespace(
            run_gate=lambda detection_id, request: gate,
            create_validation_draft=lambda detection_id, request: (task, False),
        ),
    )
    monkeypatch.setattr(app_module, "services", fake_services)

    gate_result = await app_module.run_detection_gate(
        detection["id"],
        DetectionGateRunRequest(expected_content_sha256="a" * 64),
    )
    draft_result = await app_module.create_detection_validation_draft(
        detection["id"],
        DetectionValidationDraftRequest(expected_content_sha256="a" * 64),
    )

    assert gate_result["gate"]["status"] == "fail"
    assert draft_result["validation"]["status"] == "draft"
    assert draft_result["reused"] is False
    assert audit.event_types == [
        "detection.gate.completed",
        "detection.validation.draft.created",
    ]
