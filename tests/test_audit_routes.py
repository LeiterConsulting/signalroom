from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from splunk_security_agent.schemas import (
    CaseUpdate,
    DetectionDeploymentCaseRequest,
    DetectionDeploymentRefreshRequest,
    DetectionGateRunRequest,
    DetectionGitExportRequest,
    DetectionRepositoryApprovalRequest,
    DetectionRepositoryCaseRequest,
    DetectionRepositoryPreviewRequest,
    DetectionRepositoryRemoteRequest,
    DetectionRepositoryReviewRequest,
    DetectionRuntimeAssessmentRequest,
    DetectionRuntimeCaseRequest,
    DetectionRuntimeDraftRequest,
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
        detection_deployment=SimpleNamespace(
            latest=lambda detection_id, content_sha256: None
        ),
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


@pytest.mark.asyncio
async def test_signed_git_change_export_is_audited(monkeypatch):
    app_module = importlib.import_module("splunk_security_agent.app")
    audit = AuditRecorder()
    detection = {
        "id": "detection-1",
        "current_version": 3,
        "current_sha256": "a" * 64,
        "status": "approved",
    }
    verification = {
        "valid": True,
        "trust": "pinned",
        "key_id": "b" * 64,
        "detections": [],
    }
    fake_services = SimpleNamespace(
        audit=audit,
        detections=SimpleNamespace(
            export_git_change=lambda detection_id, request: (
                detection,
                Path("signalroom_git_change.zip"),
                verification,
            ),
        ),
    )
    monkeypatch.setattr(app_module, "services", fake_services)

    result = await app_module.export_detection_git_change(
        detection["id"],
        DetectionGitExportRequest(expected_content_sha256="a" * 64),
    )

    assert result["verification"]["valid"] is True
    assert result["authority"]["creates_git_commit"] is False
    assert result["authority"]["opens_pull_request"] is False
    assert audit.event_types == ["detection.git_change.exported"]


@pytest.mark.asyncio
async def test_repository_handoff_control_plane_is_audited(monkeypatch):
    app_module = importlib.import_module("splunk_security_agent.app")
    audit = AuditRecorder()
    handoff = {
        "id": "handoff-1",
        "detection_id": "detection-1",
        "version": 2,
        "content_sha256": "a" * 64,
        "preview_sha256": "b" * 64,
        "base_commit": "c" * 40,
        "branch_name": "signalroom/detection-v2",
        "commit_sha": "d" * 40,
        "remote_name": "origin",
        "pull_request_url": "https://github.com/example/repo/pull/1",
        "summary": {"added": 10, "modified": 0},
        "blocking_reasons": [],
        "review": {
            "snapshot_sha256": "e" * 64,
            "case_item_id": "case-item-1",
            "identity_status": "exact",
            "lifecycle": "open",
            "review_decision": "approved",
            "checks_status": "pass",
            "risk_level": "low",
        },
    }
    fake_repository = SimpleNamespace(
        preview=lambda detection_id, expected: handoff,
        apply=lambda handoff_id, expected: handoff,
        push=lambda handoff_id, expected: handoff,
        open_draft_pull_request=lambda handoff_id, expected: handoff,
        refresh_pull_request=lambda handoff_id, expected: handoff,
        preserve_review_to_case=lambda handoff_id, expected: handoff,
    )
    monkeypatch.setattr(
        app_module,
        "services",
        SimpleNamespace(audit=audit, detection_repository=fake_repository),
    )

    await app_module.preview_detection_repository_handoff(
        "detection-1",
        DetectionRepositoryPreviewRequest(expected_content_sha256="a" * 64),
    )
    await app_module.apply_detection_repository_handoff(
        "handoff-1",
        DetectionRepositoryApprovalRequest(expected_preview_sha256="b" * 64),
    )
    await app_module.push_detection_repository_handoff(
        "handoff-1",
        DetectionRepositoryRemoteRequest(expected_commit_sha="d" * 40),
    )
    await app_module.open_detection_repository_pull_request(
        "handoff-1",
        DetectionRepositoryRemoteRequest(expected_commit_sha="d" * 40),
    )
    await app_module.refresh_detection_repository_review(
        "handoff-1",
        DetectionRepositoryReviewRequest(expected_commit_sha="d" * 40),
    )
    await app_module.preserve_detection_repository_review(
        "handoff-1",
        DetectionRepositoryCaseRequest(expected_snapshot_sha256="e" * 64),
    )

    assert audit.event_types == [
        "detection.repository.previewed",
        "detection.repository.committed",
        "detection.repository.pushed",
        "detection.repository.pull_request.opened",
        "detection.repository.review.refreshed",
        "detection.repository.review.preserved",
    ]


@pytest.mark.asyncio
async def test_splunk_deployment_observation_and_case_preservation_are_audited(
    monkeypatch,
):
    app_module = importlib.import_module("splunk_security_agent.app")
    audit = AuditRecorder()
    snapshot = {
        "id": "deployment-1",
        "detection_id": "detection-1",
        "content_sha256": "a" * 64,
        "snapshot_sha256": "b" * 64,
        "case_item_id": "case-item-1",
        "status": "drifted",
        "risk_level": "critical",
        "target": {"name": "PowerShell", "app": "security_content"},
        "collection": {"exhaustive": True},
    }

    async def refresh(detection_id, expected_content_sha256, target_app):
        return snapshot

    fake_deployment = SimpleNamespace(
        refresh=refresh,
        preserve_to_case=lambda detection_id, expected: snapshot,
    )
    monkeypatch.setattr(
        app_module,
        "services",
        SimpleNamespace(
            audit=audit,
            detection_deployment=fake_deployment,
        ),
    )

    await app_module.refresh_detection_deployment_verification(
        "detection-1",
        DetectionDeploymentRefreshRequest(
            expected_content_sha256="a" * 64,
            target_app="security_content",
        ),
    )
    await app_module.preserve_detection_deployment_verification(
        "detection-1",
        DetectionDeploymentCaseRequest(
            expected_snapshot_sha256="b" * 64,
        ),
    )

    assert audit.event_types == [
        "detection.deployment.observed",
        "detection.deployment.preserved",
    ]


@pytest.mark.asyncio
async def test_snapshot_bound_runtime_workflow_is_audited(monkeypatch):
    app_module = importlib.import_module("splunk_security_agent.app")
    audit = AuditRecorder()
    runtime = {
        "id": "runtime-1",
        "detection_id": "detection-1",
        "deployment_snapshot_sha256": "b" * 64,
        "check_sha256": "c" * 64,
        "query_fingerprint": "d" * 64,
        "validation_task_id": "validation-1",
        "assessment_sha256": "e" * 64,
        "case_item_id": "case-item-1",
        "assessment": {
            "status": "healthy",
            "risk_level": "low",
            "validation": {"artifact_id": "artifact-1"},
        },
    }
    fake_deployment = SimpleNamespace(
        create_runtime_draft=lambda *args: (runtime, False),
        assess_runtime=lambda *args: runtime,
        preserve_runtime_to_case=lambda *args: runtime,
    )
    monkeypatch.setattr(
        app_module,
        "services",
        SimpleNamespace(
            audit=audit,
            detection_deployment=fake_deployment,
        ),
    )

    await app_module.create_detection_runtime_draft(
        "detection-1",
        DetectionRuntimeDraftRequest(
            expected_snapshot_sha256="b" * 64,
        ),
    )
    await app_module.assess_detection_runtime(
        "detection-1",
        DetectionRuntimeAssessmentRequest(
            expected_runtime_check_sha256="c" * 64,
        ),
    )
    await app_module.preserve_detection_runtime(
        "detection-1",
        DetectionRuntimeCaseRequest(
            expected_assessment_sha256="e" * 64,
        ),
    )

    assert audit.event_types == [
        "detection.runtime.validation.staged",
        "detection.runtime.assessed",
        "detection.runtime.preserved",
    ]
