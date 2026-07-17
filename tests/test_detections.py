from __future__ import annotations

import json
import zipfile

import pytest

from splunk_security_agent.cases import CaseStore
from splunk_security_agent.detections import DetectionService, DetectionStore
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import (
    ArtifactCreate,
    CaseCreate,
    DetectionCreate,
    DetectionExportRequest,
    DetectionGateRunRequest,
    DetectionReviewRequest,
    DetectionUpdate,
    DetectionValidationDraftRequest,
    ValidationTaskCreate,
)
from splunk_security_agent.validation import ValidationStore


def completed_validation(
    validations: ValidationStore,
    evidence: EvidenceStore,
    *,
    case_id: str | None = None,
):
    artifact = evidence.add(
        ArtifactCreate(
            title="Observed suspicious PowerShell",
            content="A bounded test result used only for the detection review fixture.",
            kind="validation",
            source="test",
        )
    )
    task = validations.create(
        ValidationTaskCreate(
            title="Suspicious encoded PowerShell",
            rationale="Identify encoded PowerShell command lines for analyst review.",
            spl='index=endpoint process_name="powershell.exe" | stats count by host user',
            earliest_time="-24h",
            latest_time="now",
            row_limit=100,
            evidence_refs=["D1"],
            case_id=case_id,
        )
    )
    validations.approve(task.id)
    validations.mark_running(task.id)
    return validations.complete(task.id, 3, [{"host": "workstation-1", "count": 3}], artifact.id)


def service_fixture(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.db")
    cases = CaseStore(tmp_path / "cases.db", tmp_path / "case_exports")
    validations = ValidationStore(tmp_path / "validations.db")
    store = DetectionStore(tmp_path / "detections.db")
    service = DetectionService(
        store,
        validations,
        evidence,
        cases,
        tmp_path / "detection_exports",
    )
    return service, store, validations, evidence, cases


def test_detection_versions_review_and_export_are_hash_bound(tmp_path):
    service, store, validations, evidence, cases = service_fixture(tmp_path)
    case = cases.create(
        CaseCreate(
            title="PowerShell investigation",
            severity="high",
            owner="Detection engineering",
        )
    )
    task = completed_validation(validations, evidence, case_id=case.id)
    assert task is not None

    detection = service.create(
        DetectionCreate(
            validation_task_id=task.id,
            severity="high",
            security_domain="endpoint",
            mitre_attack=["T1059.001"],
            tags=["PowerShell", "endpoint"],
        )
    )

    assert detection["status"] == "draft"
    assert detection["current_version"] == 1
    assert detection["content"]["search"] == task.spl
    assert detection["content"]["evidence"]["artifact_id"] == task.artifact_id
    assert detection["content"]["deployment"]["splunk_write_permitted"] is False

    revised = service.update(
        detection["id"],
        DetectionUpdate(
            description="Detect encoded or otherwise suspicious PowerShell execution.",
            cron_schedule="*/10 * * * *",
            throttle_seconds=7200,
        ),
    )
    assert revised is not None
    assert revised["current_version"] == 2
    assert revised["current_sha256"] != detection["current_sha256"]
    assert revised["status"] == "draft"

    gate = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    assert gate["status"] == "pass"
    assert gate["score"] == 100
    assert gate["validation_task_id"] == task.id

    submitted = service.submit(detection["id"])
    assert submitted is not None
    assert submitted["status"] == "in-review"
    with pytest.raises(ValueError, match="content changed"):
        service.review(
            detection["id"],
            DetectionReviewRequest(
                decision="approve",
                expected_content_sha256=detection["current_sha256"],
                reviewer="Reviewer",
            ),
        )

    approved = service.review(
        detection["id"],
        DetectionReviewRequest(
            decision="approve",
            expected_content_sha256=revised["current_sha256"],
            reviewer="Reviewer",
            note="Evidence and schedule reviewed.",
        ),
    )
    assert approved is not None
    assert approved["status"] == "approved"
    assert approved["approved_sha256"] == revised["current_sha256"]
    assert approved["reviews"][0]["decision"] == "approve"

    detection_artifacts = [item for item in evidence.list() if item.kind == "detection"]
    assert len(detection_artifacts) == 1
    assert detection_artifacts[0].metadata["content_sha256"] == revised["current_sha256"]
    linked_case = cases.get(case.id)
    assert linked_case is not None
    assert any(item.metadata.get("detection_id") == detection["id"] for item in linked_case.items)

    exported, path = service.export(
        detection["id"],
        DetectionExportRequest(expected_content_sha256=revised["current_sha256"]),
    )
    assert exported["export_count"] == 1
    assert path.exists()
    with zipfile.ZipFile(path) as archive:
        assert set(archive.namelist()) == {
            "README.md",
            "default/savedsearches.conf",
            "detection.yml",
            "manifest.json",
        }
        savedsearch = archive.read("default/savedsearches.conf").decode()
        assert "disabled = 1" in savedsearch
        assert "enableSched = 0" in savedsearch
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["content_sha256"] == revised["current_sha256"]
        assert manifest["promotion_gate"]["id"] == gate["id"]
        assert manifest["promotion_gate"]["accepted_at"]
        assert manifest["authority"]["deploys_to_splunk"] is False
        assert manifest["authority"]["contains_raw_results"] is False

    with pytest.raises(ValueError, match="retained and retired"):
        service.delete(detection["id"])
    retired = service.retire(detection["id"])
    assert retired is not None
    assert retired["status"] == "retired"


def test_detection_requires_completed_preserved_validation_and_valid_contract(tmp_path):
    service, _, validations, evidence, _ = service_fixture(tmp_path)
    draft = validations.create(
        ValidationTaskCreate(
            title="Unexecuted validation",
            rationale="This draft has no observed evidence yet.",
            spl="index=main | stats count",
        )
    )
    with pytest.raises(ValueError, match="completed validation"):
        service.create(DetectionCreate(validation_task_id=draft.id))

    task = completed_validation(validations, evidence)
    assert task is not None
    detection = service.create(DetectionCreate(validation_task_id=task.id))
    with pytest.raises(ValueError, match="five valid fields"):
        service.update(
            detection["id"],
            DetectionUpdate(cron_schedule="not a valid cron schedule"),
        )
    with pytest.raises(ValueError, match="MITRE ATT&CK"):
        service.update(
            detection["id"],
            DetectionUpdate(mitre_attack=["TA0001"]),
        )
    with pytest.raises(ValueError, match="already has"):
        service.create(DetectionCreate(validation_task_id=task.id))


def test_unapproved_detection_can_be_deleted_but_review_blocks_editing(tmp_path):
    service, store, validations, evidence, _ = service_fixture(tmp_path)
    task = completed_validation(validations, evidence)
    assert task is not None
    detection = service.create(DetectionCreate(validation_task_id=task.id))

    gate = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    assert gate["status"] == "pass"
    service.submit(detection["id"])
    with pytest.raises(ValueError, match="receive a decision"):
        service.update(detection["id"], DetectionUpdate(title="Changed during review"))

    changes = service.review(
        detection["id"],
        DetectionReviewRequest(
            decision="request-changes",
            expected_content_sha256=detection["current_sha256"],
            reviewer="Reviewer",
            note="Add a narrower schedule.",
        ),
    )
    assert changes is not None
    assert changes["status"] == "changes-requested"
    assert service.delete(detection["id"]) is True
    assert store.get(detection["id"]) is None


def test_edited_search_requires_an_analyst_run_exact_validation(tmp_path):
    service, _, validations, evidence, _ = service_fixture(tmp_path)
    source = completed_validation(validations, evidence)
    assert source is not None
    detection = service.create(DetectionCreate(validation_task_id=source.id))
    first_gate = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    assert first_gate["status"] == "pass"
    service.submit(detection["id"])
    approved = service.review(
        detection["id"],
        DetectionReviewRequest(
            decision="approve",
            expected_content_sha256=detection["current_sha256"],
            reviewer="Reviewer",
        ),
    )
    assert approved is not None
    assert approved["latest_gate"]["accepted_at"]

    revised = service.update(
        detection["id"],
        DetectionUpdate(
            search=(
                'index=endpoint process_name="powershell.exe" encoded=true '
                "| stats count by host user"
            )
        ),
    )
    assert revised is not None
    blocked = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    assert blocked["status"] == "fail"
    exact = next(item for item in blocked["controls"] if item["id"] == "exact-validation")
    assert exact["blocking"] is True
    assert exact["status"] == "fail"
    with pytest.raises(ValueError, match="passing promotion gate"):
        service.submit(detection["id"])

    draft, reused = service.create_validation_draft(
        detection["id"],
        DetectionValidationDraftRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    assert reused is False
    assert draft.status == "draft"
    assert draft.approved_at is None
    assert draft.started_at is None
    assert draft.spl == revised["content"]["search"]

    same_draft, reused = service.create_validation_draft(
        detection["id"],
        DetectionValidationDraftRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    assert reused is True
    assert same_draft.id == draft.id
    validations.approve(draft.id)
    validations.mark_running(draft.id)
    artifact = evidence.add(
        ArtifactCreate(
            title="Fresh exact regression evidence",
            content="Exact bounded result for the edited search.",
            kind="validation",
            source="test",
        )
    )
    validations.complete(
        draft.id,
        3,
        [{"host": "workstation-1", "user": "analyst", "count": 3}],
        artifact.id,
    )
    passed = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    assert passed["status"] == "pass"
    assert passed["baseline_gate_id"] == first_gate["id"]
    assert passed["result_delta_percent"] == 0


def test_gate_blocks_field_count_and_baseline_regressions(tmp_path):
    service, _, validations, evidence, _ = service_fixture(tmp_path)
    source = completed_validation(validations, evidence)
    assert source is not None
    detection = service.create(DetectionCreate(validation_task_id=source.id))
    gate = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    service.submit(detection["id"])
    service.review(
        detection["id"],
        DetectionReviewRequest(
            decision="approve",
            expected_content_sha256=detection["current_sha256"],
            reviewer="Reviewer",
        ),
    )
    assert gate["status"] == "pass"

    field_contract = service.update(
        detection["id"],
        DetectionUpdate(
            required_fields=["host", "process_name"],
            max_result_count=2,
        ),
    )
    assert field_contract is not None
    blocked = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=field_contract["current_sha256"]
        ),
    )
    failures = {
        item["id"]
        for item in blocked["controls"]
        if item["status"] == "fail"
    }
    assert blocked["status"] == "fail"
    assert {"required-fields", "maximum-result-count"} <= failures

    revised = service.update(
        detection["id"],
        DetectionUpdate(
            search=(
                'index=endpoint process_name="powershell.exe" '
                "| stats count by host user source"
            ),
            required_fields=["host", "user", "source", "count"],
            max_result_count=0,
        ),
    )
    assert revised is not None
    draft, reused = service.create_validation_draft(
        detection["id"],
        DetectionValidationDraftRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    assert reused is False
    validations.approve(draft.id)
    validations.mark_running(draft.id)
    artifact = evidence.add(
        ArtifactCreate(
            title="Regression count evidence",
            content="A materially changed bounded result count.",
            kind="validation",
            source="test",
        )
    )
    validations.complete(
        draft.id,
        20,
        [{"host": "a", "user": "b", "source": "c", "count": 20}],
        artifact.id,
    )
    regression = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=revised["current_sha256"]
        ),
    )
    drift = next(
        item for item in regression["controls"] if item["id"] == "baseline-drift"
    )
    assert regression["status"] == "fail"
    assert regression["result_delta_percent"] > 200
    assert drift["status"] == "fail"


def test_gate_rejects_a_stale_content_hash(tmp_path):
    service, _, validations, evidence, _ = service_fixture(tmp_path)
    source = completed_validation(validations, evidence)
    assert source is not None
    detection = service.create(DetectionCreate(validation_task_id=source.id))
    revised = service.update(
        detection["id"], DetectionUpdate(description="Changed exact content")
    )
    assert revised is not None
    with pytest.raises(ValueError, match="content changed"):
        service.run_gate(
            detection["id"],
            DetectionGateRunRequest(
                expected_content_sha256=detection["current_sha256"]
            ),
        )
    with pytest.raises(ValueError, match="content changed"):
        service.create_validation_draft(
            detection["id"],
            DetectionValidationDraftRequest(
                expected_content_sha256=detection["current_sha256"]
            ),
        )
