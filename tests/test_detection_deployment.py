from __future__ import annotations

import sqlite3

import pytest

from splunk_security_agent.cases import CaseStore
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.detections import (
    DeploymentVerificationError,
    DetectionDeploymentService,
    DetectionDeploymentStore,
    DetectionService,
    DetectionStore,
)
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import (
    ArtifactCreate,
    CaseCreate,
    DetectionCreate,
    DetectionGateRunRequest,
    DetectionReviewRequest,
    ValidationTaskCreate,
)
from splunk_security_agent.validation import ValidationStore


class DeploymentClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def call(self, logical_name, arguments=None):
        self.calls.append((logical_name, arguments or {}))
        return self.response


def deployment_fixture(tmp_path, response):
    config = ConfigStore(tmp_path / "config")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    cases = CaseStore(tmp_path / "cases.db", tmp_path / "case_exports")
    validations = ValidationStore(tmp_path / "validations.db")
    detection_store = DetectionStore(tmp_path / "detections.db")
    detections = DetectionService(
        detection_store,
        validations,
        evidence,
        cases,
        tmp_path / "detection_exports",
    )
    case = cases.create(
        CaseCreate(
            title="Deployment verification",
            severity="high",
            owner="Detection engineering",
        )
    )
    artifact = evidence.add(
        ArtifactCreate(
            title="PowerShell validation",
            content="A bounded exact-query validation.",
            kind="validation",
            source="test",
        )
    )
    task = validations.create(
        ValidationTaskCreate(
            title="Suspicious encoded PowerShell",
            rationale="Validate encoded PowerShell execution.",
            spl=(
                'index=endpoint process_name="powershell.exe" '
                '| stats count by host user'
            ),
            earliest_time="-24h",
            latest_time="now",
            row_limit=100,
            case_id=case.id,
        )
    )
    validations.approve(task.id)
    validations.mark_running(task.id)
    completed = validations.complete(
        task.id,
        2,
        [{"host": "workstation-1", "count": 2}],
        artifact.id,
    )
    assert completed is not None
    detection = detections.create(
        DetectionCreate(
            validation_task_id=task.id,
            title="Suspicious encoded PowerShell",
            description="Detect encoded PowerShell process activity.",
            severity="high",
            security_domain="endpoint",
            cron_schedule="*/10 * * * *",
            earliest_time="-24h",
            latest_time="now",
            case_id=case.id,
        )
    )
    gate = detections.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=detection["current_sha256"],
        ),
    )
    assert gate["status"] == "pass"
    detections.submit(detection["id"])
    approved = detections.review(
        detection["id"],
        DetectionReviewRequest(
            decision="approve",
            expected_content_sha256=detection["current_sha256"],
            reviewer="Deployment test reviewer",
        ),
    )
    assert approved is not None
    client = DeploymentClient(response)
    store = DetectionDeploymentStore(tmp_path / "deployment.db")
    service = DetectionDeploymentService(
        config,
        detections,
        store,
        lambda: client,
    )
    return service, client, approved, cases


def deployed_row(detection, **changes):
    content = detection["content"]
    schedule = content["schedule"]
    value = {
        "name": content["title"],
        "app": "security_content",
        "search": content["search"],
        "cron_schedule": schedule["cron"],
        "dispatch.earliest_time": schedule["earliest_time"],
        "dispatch.latest_time": schedule["latest_time"],
        "disabled": False,
    }
    value.update(changes)
    return value


@pytest.mark.asyncio
async def test_exact_enabled_deployment_is_verified_and_preserved(tmp_path):
    response = {"results": [], "total_rows": 1, "truncated": False}
    service, client, detection, cases = deployment_fixture(tmp_path, response)
    client.response["results"] = [deployed_row(detection)]

    snapshot = await service.refresh(
        detection["id"],
        detection["current_sha256"],
        "security_content",
    )

    assert snapshot["status"] == "verified"
    assert snapshot["risk_level"] == "low"
    assert snapshot["subject"] == {
        "detection_id": detection["id"],
        "version": detection["current_version"],
        "content_sha256": detection["current_sha256"],
    }
    assert snapshot["observed"]["definition_sha256"] == (
        snapshot["expected"]["definition_sha256"]
    )
    assert all(
        item["status"] == "pass"
        for item in snapshot["controls"]
    )
    assert snapshot["authority"]["changes_splunk"] is False
    assert snapshot["collection"]["exhaustive"] is True
    assert client.calls == [
        (
            "get_knowledge_objects",
            {"type": "saved_searches", "row_limit": 1000},
        )
    ]

    case_before = cases.get(detection["case_id"])
    assert case_before is not None
    preserved = service.preserve_to_case(
        detection["id"],
        snapshot["snapshot_sha256"],
    )
    assert preserved["case_item_id"]
    case_after = cases.get(detection["case_id"])
    assert case_after is not None
    assert len(case_after.items) == len(case_before.items) + 1
    assert (
        case_after.items[-1].metadata["detection_deployment_sha256"]
        == snapshot["snapshot_sha256"]
    )
    assert "did not deploy" in case_after.items[-1].content

    service.preserve_to_case(
        detection["id"],
        snapshot["snapshot_sha256"],
    )
    idempotent = cases.get(detection["case_id"])
    assert idempotent is not None
    assert len(idempotent.items) == len(case_after.items)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "status", "risk"),
    [
        ({"disabled": True}, "deployed-disabled", "medium"),
        (
            {"search": "index=other | stats count"},
            "drifted",
            "critical",
        ),
        (
            {"cron_schedule": "0 * * * *"},
            "drifted",
            "high",
        ),
    ],
)
async def test_deployment_state_distinguishes_disabled_and_drift(
    tmp_path,
    changes,
    status,
    risk,
):
    response = {"results": [], "total_rows": 1, "truncated": False}
    service, client, detection, _ = deployment_fixture(tmp_path, response)
    client.response["results"] = [deployed_row(detection, **changes)]

    snapshot = await service.refresh(
        detection["id"],
        detection["current_sha256"],
        "security_content",
    )

    assert snapshot["status"] == status
    assert snapshot["risk_level"] == risk


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "status", "exhaustive"),
    [
        (
            {"results": [], "total_rows": 0, "truncated": False},
            "missing",
            True,
        ),
        (
            {"results": [], "total_rows": 2500, "truncated": True},
            "inconclusive",
            False,
        ),
    ],
)
async def test_absence_is_only_missing_when_catalog_is_exhaustive(
    tmp_path,
    response,
    status,
    exhaustive,
):
    service, _, detection, _ = deployment_fixture(tmp_path, response)

    snapshot = await service.refresh(
        detection["id"],
        detection["current_sha256"],
    )

    assert snapshot["status"] == status
    assert snapshot["collection"]["exhaustive"] is exhaustive


@pytest.mark.asyncio
async def test_duplicate_name_requires_target_app_before_verification(tmp_path):
    response = {"results": [], "total_rows": 2, "truncated": False}
    service, client, detection, _ = deployment_fixture(tmp_path, response)
    client.response["results"] = [
        deployed_row(detection, app="security_content"),
        deployed_row(detection, app="local"),
    ]

    ambiguous = await service.refresh(
        detection["id"],
        detection["current_sha256"],
    )
    exact = await service.refresh(
        detection["id"],
        detection["current_sha256"],
        "security_content",
    )

    assert ambiguous["status"] == "ambiguous"
    assert ambiguous["risk_level"] == "critical"
    assert len(ambiguous["candidates"]) == 2
    assert exact["status"] == "verified"
    assert exact["observed"]["app"] == "security_content"


@pytest.mark.asyncio
async def test_match_in_truncated_catalog_requires_target_app_identity(tmp_path):
    response = {"results": [], "total_rows": 2500, "truncated": True}
    service, client, detection, _ = deployment_fixture(tmp_path, response)
    client.response["results"] = [deployed_row(detection)]

    unscoped = await service.refresh(
        detection["id"],
        detection["current_sha256"],
    )
    scoped = await service.refresh(
        detection["id"],
        detection["current_sha256"],
        "security_content",
    )
    wrong_app = await service.refresh(
        detection["id"],
        detection["current_sha256"],
        "enterprise_security",
    )

    assert unscoped["status"] == "inconclusive"
    assert "target app" in unscoped["recommended_action"]
    assert scoped["status"] == "verified"
    assert wrong_app["status"] == "inconclusive"
    assert "absence remains unknown" in wrong_app["recommended_action"]


@pytest.mark.asyncio
async def test_tampered_deployment_snapshot_cannot_be_preserved(tmp_path):
    response = {"results": [], "total_rows": 1, "truncated": False}
    service, client, detection, _ = deployment_fixture(tmp_path, response)
    client.response["results"] = [deployed_row(detection)]
    snapshot = await service.refresh(
        detection["id"],
        detection["current_sha256"],
        "security_content",
    )
    with sqlite3.connect(service.store.path) as db:
        db.execute(
            """UPDATE detection_deployment_snapshots
            SET snapshot='{}' WHERE id=?""",
            (snapshot["id"],),
        )

    with pytest.raises(
        DeploymentVerificationError,
        match="snapshot is invalid",
    ):
        service.preserve_to_case(
            detection["id"],
            snapshot["snapshot_sha256"],
        )


@pytest.mark.asyncio
async def test_deployment_verification_requires_exact_approved_content(tmp_path):
    response = {"results": [], "total_rows": 0, "truncated": False}
    service, client, detection, _ = deployment_fixture(tmp_path, response)

    with pytest.raises(
        DeploymentVerificationError,
        match="content changed",
    ):
        await service.refresh(detection["id"], "0" * 64)
    assert client.calls == []
