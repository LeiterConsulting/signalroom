from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import zipfile

import pytest

from splunk_security_agent.cases import CaseStore
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.detections import DetectionService, DetectionStore
from splunk_security_agent.detections.gitops_verifier import (
    VerificationError,
    verify_change_bundle,
    verify_path,
)
from splunk_security_agent.detections.repository import (
    DetectionRepositoryService,
    RepositoryHandoffError,
)
from splunk_security_agent.detections.repository_store import (
    DetectionRepositoryStore,
)
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import (
    ArtifactCreate,
    CaseCreate,
    DetectionCreate,
    DetectionExportRequest,
    DetectionGateRunRequest,
    DetectionGitExportRequest,
    DetectionRepositorySettings,
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


def test_signed_git_change_is_ci_verifiable_and_policy_bound(tmp_path):
    service, _, validations, evidence, _ = service_fixture(tmp_path)
    source = completed_validation(validations, evidence)
    assert source is not None
    detection = service.create(
        DetectionCreate(
            validation_task_id=source.id,
            title="Encoded PowerShell / CI policy",
            severity="high",
            security_domain="endpoint",
            mitre_attack=["T1059.001"],
        )
    )
    gate = service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    assert gate["status"] == "pass"
    service.submit(detection["id"])
    approved = service.review(
        detection["id"],
        DetectionReviewRequest(
            decision="approve",
            expected_content_sha256=detection["current_sha256"],
            reviewer="Detection reviewer",
        ),
    )
    assert approved is not None

    exported, archive_path, self_check = service.export_git_change(
        detection["id"],
        DetectionGitExportRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    assert exported["export_count"] == 1
    assert exported["exports"][0]["export_kind"] == "git-change"
    assert self_check["valid"] is True
    assert self_check["trust"] == "pinned"
    assert self_check["key_id"] == service.signing_key.key_id()
    assert archive_path.exists()

    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        manifest_name = next(
            name for name in names if name.endswith("/manifest.json")
        )
        detection_root = manifest_name.rsplit("/", 1)[0]
        assert names == {
            ".github/workflows/signalroom-detection-policy.yml",
            ".signalroom/policy.json",
            ".signalroom/signalroom.pub",
            "CHANGE_REQUEST.md",
            f"{detection_root}/README.md",
            f"{detection_root}/detection.json",
            f"{detection_root}/detection.yml",
            f"{detection_root}/manifest.json",
            f"{detection_root}/manifest.sig",
            f"{detection_root}/savedsearches.conf",
            "tools/verify_signalroom_detection.py",
        }
        workflow = archive.read(
            ".github/workflows/signalroom-detection-policy.yml"
        ).decode()
        assert "permissions:\n  contents: read" in workflow
        assert "vars.SIGNALROOM_TRUSTED_KEY_SHA256" in workflow
        assert "pull_request_target" not in workflow
        manifest = json.loads(archive.read(manifest_name))
        assert manifest["promotion_gate"]["id"] == gate["id"]
        assert manifest["promotion_gate"]["accepted_at"]
        assert manifest["authority"]["creates_git_commit"] is False
        assert manifest["authority"]["opens_pull_request"] is False
        assert manifest["authority"]["contains_raw_results"] is False
        canonical_content = json.loads(
            archive.read(f"{detection_root}/detection.json")
        )
        assert hashlib.sha256(
            json.dumps(
                canonical_content,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest() == manifest["content_sha256"]

    repository = tmp_path / "repository"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(repository)
    verified = verify_change_bundle(repository, service.signing_key.key_id())
    assert verified["valid"] is True
    assert verified["trust"] == "pinned"
    assert verify_path(archive_path, service.signing_key.key_id())["valid"] is True
    with pytest.raises(VerificationError, match="not the trusted repository key"):
        verify_change_bundle(repository, "0" * 64)

    detection_yaml = repository / manifest_name.replace("manifest.json", "detection.yml")
    detection_yaml.write_text(
        detection_yaml.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )
    with pytest.raises(VerificationError, match="hash mismatch"):
        verify_change_bundle(repository, service.signing_key.key_id())

    forged_repository = tmp_path / "forged-repository"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(forged_repository)
    forged_manifest_path = next(
        forged_repository.glob("detections/*/manifest.json")
    )
    forged_content_path = forged_manifest_path.parent / "detection.json"
    forged_content = json.loads(forged_content_path.read_text(encoding="utf-8"))
    forged_content["title"] = "Content changed after approval"
    forged_content_path.write_text(
        json.dumps(
            forged_content,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    forged_manifest = json.loads(
        forged_manifest_path.read_text(encoding="utf-8")
    )
    forged_manifest["files"]["detection.json"] = hashlib.sha256(
        forged_content_path.read_bytes()
    ).hexdigest()
    forged_manifest_path.write_text(
        json.dumps(forged_manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (forged_manifest_path.parent / "manifest.sig").write_text(
        f"{service.signing_key.sign(service._canonical_manifest(forged_manifest))}\n",
        encoding="ascii",
    )
    with pytest.raises(
        VerificationError,
        match="canonical detection content hash is invalid",
    ):
        verify_change_bundle(forged_repository, service.signing_key.key_id())

    extra_file_repository = tmp_path / "extra-file-repository"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extra_file_repository)
    extra_manifest = next(extra_file_repository.glob("detections/*/manifest.json"))
    nested = extra_manifest.parent / "scripts" / "deploy.ps1"
    nested.parent.mkdir()
    nested.write_text("Write-Host unsafe", encoding="utf-8")
    with pytest.raises(VerificationError, match="unexpected detection files"):
        verify_change_bundle(extra_file_repository, service.signing_key.key_id())


def test_signed_policy_rejects_an_enabled_saved_search(tmp_path):
    service, _, validations, evidence, _ = service_fixture(tmp_path)
    source = completed_validation(validations, evidence)
    assert source is not None
    detection = service.create(DetectionCreate(validation_task_id=source.id))
    service.run_gate(
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
            reviewer="Detection reviewer",
        ),
    )
    _, archive_path, _ = service.export_git_change(
        detection["id"],
        DetectionGitExportRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    repository = tmp_path / "enabled-repository"
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(repository)
    manifest_path = next(repository.glob("detections/*/manifest.json"))
    saved_search = manifest_path.parent / "savedsearches.conf"
    saved_search.write_text(
        saved_search.read_text(encoding="utf-8").replace(
            "disabled = 1",
            "disabled = 0",
        ),
        encoding="utf-8",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["savedsearches.conf"] = hashlib.sha256(
        saved_search.read_bytes()
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (manifest_path.parent / "manifest.sig").write_text(
        f"{service.signing_key.sign(service._canonical_manifest(manifest))}\n",
        encoding="ascii",
    )

    with pytest.raises(
        VerificationError,
        match="saved search policy requires disabled = 1",
    ):
        verify_change_bundle(repository, service.signing_key.key_id())


def test_detection_store_migrates_legacy_exports(tmp_path):
    path = tmp_path / "legacy-detections.db"
    with sqlite3.connect(path) as db:
        db.execute(
            """CREATE TABLE detection_exports (
                id TEXT PRIMARY KEY,
                detection_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                filename TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                archive_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )

    store = DetectionStore(path)
    with store.connect() as db:
        columns = {
            str(row["name"])
            for row in db.execute("PRAGMA table_info(detection_exports)").fetchall()
        }
    assert "export_kind" in columns
    DetectionStore(path)


def _git(repository, *arguments, check=True):
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        text=True,
    )
    if check and result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return result


def _install_failing_git_hook(repository, name, marker):
    hook = repository / ".git" / "hooks" / name
    marker_path = marker.as_posix().replace("'", "'\"'\"'")
    hook.write_text(
        f"#!/bin/sh\nprintf executed > '{marker_path}'\nexit 91\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)


def repository_handoff_fixture(tmp_path, *, remote=False, linked_case=False):
    detection_service, _, validations, evidence, cases = service_fixture(
        tmp_path / "signalroom"
    )
    case = (
        cases.create(
            CaseCreate(
                title="Repository feedback investigation",
                severity="high",
                owner="Detection engineering",
            )
        )
        if linked_case
        else None
    )
    source = completed_validation(
        validations,
        evidence,
        case_id=case.id if case else None,
    )
    assert source is not None
    detection = detection_service.create(
        DetectionCreate(
            validation_task_id=source.id,
            title="Encoded PowerShell repository handoff",
            severity="high",
            security_domain="endpoint",
            mitre_attack=["T1059.001"],
        )
    )
    detection_service.run_gate(
        detection["id"],
        DetectionGateRunRequest(
            expected_content_sha256=detection["current_sha256"]
        ),
    )
    detection_service.submit(detection["id"])
    approved = detection_service.review(
        detection["id"],
        DetectionReviewRequest(
            decision="approve",
            expected_content_sha256=detection["current_sha256"],
            reviewer="Repository reviewer",
        ),
    )
    assert approved is not None

    repository = tmp_path / "detection-repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    (repository / "README.md").write_text(
        "# Detection repository\n",
        encoding="utf-8",
    )
    _git(repository, "add", "README.md")
    _git(
        repository,
        "-c",
        "user.name=Repository owner",
        "-c",
        "user.email=owner@example.test",
        "commit",
        "-m",
        "Initialize detection repository",
    )
    remote_path = None
    if remote:
        remote_path = tmp_path / "remote.git"
        remote_path.mkdir()
        _git(remote_path, "init", "--bare")
        _git(repository, "remote", "add", "origin", str(remote_path))

    config = ConfigStore(tmp_path / "config")
    settings = config.load()
    settings.detection_repository = DetectionRepositorySettings(
        enabled=True,
        path=str(repository.resolve()),
        base_ref="main",
        branch_prefix="signalroom/",
        remote_name="origin",
        allow_push=remote,
    )
    config.save(settings)
    store = DetectionRepositoryStore(tmp_path / "repository-handoffs.db")
    service = DetectionRepositoryService(
        config,
        detection_service,
        store,
        tmp_path / "repository-runtime",
    )
    return service, config, repository, remote_path, approved


def test_repository_handoff_is_preview_bound_and_keeps_checkout_untouched(tmp_path):
    service, _, repository, _, detection = repository_handoff_fixture(tmp_path)
    hook_marker = tmp_path / "repository-hook-ran"
    _install_failing_git_hook(repository, "post-checkout", hook_marker)
    _install_failing_git_hook(repository, "pre-commit", hook_marker)
    original_branch = _git(repository, "branch", "--show-current").stdout.strip()
    original_status = _git(repository, "status", "--porcelain").stdout
    original_branches = _git(repository, "branch", "--format=%(refname:short)").stdout

    status = service.inspect()
    assert status["ready"] is True
    assert status["current_branch"] == "main"
    preview = service.preview(
        detection["id"],
        detection["current_sha256"],
    )

    assert preview["status"] == "previewed"
    assert preview["blocking_reasons"] == []
    assert preview["summary"]["added"] >= 10
    assert preview["authority"]["changes_primary_worktree"] is False
    assert preview["authority"]["pushes_remote"] is False
    assert _git(repository, "branch", "--format=%(refname:short)").stdout == (
        original_branches
    )
    with pytest.raises(
        RepositoryHandoffError,
        match="preview changed",
    ):
        service.apply(preview["id"], "0" * 64)

    applied = service.apply(preview["id"], preview["preview_sha256"])
    assert applied["status"] == "applied"
    assert len(applied["commit_sha"]) in {40, 64}
    assert (
        _git(repository, "rev-parse", f"{applied['commit_sha']}^").stdout.strip()
        == preview["base_commit"]
    )
    assert (
        _git(
            repository,
            "show",
            f"{applied['commit_sha']}:.signalroom/signalroom.pub",
        ).stdout.startswith("-----BEGIN PUBLIC KEY-----")
    )
    assert _git(repository, "branch", "--show-current").stdout.strip() == original_branch
    assert _git(repository, "status", "--porcelain").stdout == original_status
    assert not (repository / "detections").exists()
    assert not (service.worktree_root / preview["id"]).exists()
    assert not hook_marker.exists()
    assert (
        service.apply(preview["id"], preview["preview_sha256"])["commit_sha"]
        == applied["commit_sha"]
    )


def test_repository_handoff_rejects_a_moved_base(tmp_path):
    service, _, repository, _, detection = repository_handoff_fixture(tmp_path)
    preview = service.preview(detection["id"], detection["current_sha256"])
    (repository / "README.md").write_text(
        "# Detection repository\n\nBase moved.\n",
        encoding="utf-8",
    )
    _git(repository, "add", "README.md")
    _git(
        repository,
        "-c",
        "user.name=Repository owner",
        "-c",
        "user.email=owner@example.test",
        "commit",
        "-m",
        "Advance base",
    )

    with pytest.raises(
        RepositoryHandoffError,
        match="base moved",
    ):
        service.apply(preview["id"], preview["preview_sha256"])
    assert not service._branch_commit(repository, preview["branch_name"])


def test_repository_handoff_rejects_a_tampered_preview_archive(tmp_path):
    service, _, repository, _, detection = repository_handoff_fixture(tmp_path)
    original_branches = _git(repository, "branch", "--format=%(refname:short)").stdout
    preview = service.preview(detection["id"], detection["current_sha256"])
    archive = service.store.get(preview["id"])["archive_path"]
    with open(archive, "ab") as handle:
        handle.write(b"\ntampered after preview\n")

    with pytest.raises(
        RepositoryHandoffError,
        match="archive changed",
    ):
        service.apply(preview["id"], preview["preview_sha256"])
    assert (
        _git(repository, "branch", "--format=%(refname:short)").stdout
        == original_branches
    )
    assert not service._branch_commit(repository, preview["branch_name"])


def test_repository_handoff_blocks_policy_control_replacement(tmp_path):
    service, _, repository, _, detection = repository_handoff_fixture(tmp_path)
    policy_path = repository / ".signalroom" / "signalroom.pub"
    policy_path.parent.mkdir()
    policy_path.write_text("repository-owned-key\n", encoding="utf-8")
    _git(repository, "add", ".signalroom/signalroom.pub")
    _git(
        repository,
        "-c",
        "user.name=Repository owner",
        "-c",
        "user.email=owner@example.test",
        "commit",
        "-m",
        "Add repository trust policy",
    )

    preview = service.preview(detection["id"], detection["current_sha256"])
    assert preview["summary"]["protected-conflict"] == 1
    assert any(
        ".signalroom/signalroom.pub" in reason
        for reason in preview["blocking_reasons"]
    )
    with pytest.raises(RepositoryHandoffError, match="preview is blocked"):
        service.apply(preview["id"], preview["preview_sha256"])


def test_repository_handoff_pushes_only_the_exact_local_commit(tmp_path):
    service, _, repository, remote, detection = repository_handoff_fixture(
        tmp_path,
        remote=True,
    )
    assert remote is not None
    hook_marker = tmp_path / "repository-push-hook-ran"
    _install_failing_git_hook(repository, "pre-push", hook_marker)
    preview = service.preview(detection["id"], detection["current_sha256"])
    applied = service.apply(preview["id"], preview["preview_sha256"])
    with pytest.raises(RepositoryHandoffError, match="commit changed"):
        service.push(applied["id"], "0" * 40)

    pushed = service.push(applied["id"], applied["commit_sha"])
    assert pushed["status"] == "pushed"
    assert (
        _git(
            remote,
            "rev-parse",
            f"refs/heads/{pushed['branch_name']}",
        ).stdout.strip()
        == pushed["commit_sha"]
    )
    assert not hook_marker.exists()
    assert service.push(pushed["id"], pushed["commit_sha"])["status"] == "pushed"


def repository_review_fixture(tmp_path, *, linked_case=False):
    service, _, repository, _, detection = repository_handoff_fixture(
        tmp_path,
        linked_case=linked_case,
    )
    _git(
        repository,
        "remote",
        "add",
        "origin",
        "https://github.com/example/detections.git",
    )
    preview = service.preview(detection["id"], detection["current_sha256"])
    applied = service.apply(preview["id"], preview["preview_sha256"])
    pushed = service.store.mark_pushed(applied["id"], applied["commit_sha"])
    handoff = service.store.mark_pull_request(
        pushed["id"],
        pushed["commit_sha"],
        "https://github.com/example/detections/pull/17",
    )
    return service, repository, detection, handoff


def github_pull_request(handoff, **changes):
    value = {
        "url": handoff["pull_request_url"],
        "number": 17,
        "title": "Detection: encoded PowerShell",
        "state": "OPEN",
        "isDraft": False,
        "mergedAt": None,
        "headRefName": handoff["branch_name"],
        "headRefOid": handoff["commit_sha"],
        "baseRefName": "main",
        "baseRefOid": handoff["base_commit"],
        "reviewDecision": "APPROVED",
        "mergeStateStatus": "CLEAN",
        "mergeable": "MERGEABLE",
        "updatedAt": "2026-07-17T20:15:00Z",
    }
    value.update(changes)
    return value


def test_repository_review_refresh_is_exact_and_can_be_preserved_to_case(
    tmp_path,
    monkeypatch,
):
    service, _, detection, handoff = repository_review_fixture(
        tmp_path,
        linked_case=True,
    )
    checks = [
        {
            "name": "SignalRoom policy",
            "workflow": "Detection policy",
            "state": "SUCCESS",
            "bucket": "pass",
            "description": "Signed bundle verified",
            "startedAt": "2026-07-17T20:10:00Z",
            "completedAt": "2026-07-17T20:11:00Z",
        },
        {
            "name": "Detection tests",
            "workflow": "Detection policy",
            "state": "SUCCESS",
            "bucket": "pass",
        },
    ]
    monkeypatch.setattr(
        service,
        "_github_pull_request",
        lambda repository, github_repository, pull_request_url: (
            github_pull_request(handoff),
            checks,
        ),
    )

    refreshed = service.refresh_pull_request(
        handoff["id"],
        handoff["commit_sha"],
    )
    review = refreshed["review"]
    assert review["identity_status"] == "exact"
    assert review["checks_status"] == "pass"
    assert review["check_counts"]["pass"] == 2
    assert review["review_decision"] == "approved"
    assert review["risk_level"] == "low"
    assert review["authority"]["changes_repository"] is False
    assert review["authority"]["proves_splunk_deployment"] is False
    assert len(review["snapshot_sha256"]) == 64

    with pytest.raises(
        RepositoryHandoffError,
        match="snapshot changed",
    ):
        service.preserve_review_to_case(handoff["id"], "0" * 64)

    case_before = service.detections.cases.get(detection["case_id"])
    assert case_before is not None
    preserved = service.preserve_review_to_case(
        handoff["id"],
        review["snapshot_sha256"],
    )
    assert preserved["review"]["case_item_id"]
    case_after = service.detections.cases.get(detection["case_id"])
    assert case_after is not None
    assert len(case_after.items) == len(case_before.items) + 1
    repository_item = case_after.items[-1]
    assert repository_item.metadata["detection_id"] == detection["id"]
    assert (
        repository_item.metadata["repository_review_sha256"]
        == review["snapshot_sha256"]
    )
    assert "does not prove" in repository_item.content

    service.preserve_review_to_case(
        handoff["id"],
        review["snapshot_sha256"],
    )
    idempotent_case = service.detections.cases.get(detection["case_id"])
    assert idempotent_case is not None
    assert len(idempotent_case.items) == len(case_after.items)


def test_repository_review_flags_a_changed_pull_request_head(
    tmp_path,
    monkeypatch,
):
    service, _, _, handoff = repository_review_fixture(tmp_path)
    monkeypatch.setattr(
        service,
        "_github_pull_request",
        lambda repository, github_repository, pull_request_url: (
            github_pull_request(handoff, headRefOid="f" * 40),
            [{"name": "Policy", "state": "SUCCESS", "bucket": "pass"}],
        ),
    )

    refreshed = service.refresh_pull_request(
        handoff["id"],
        handoff["commit_sha"],
    )
    review = refreshed["review"]
    assert review["identity_status"] == "stale"
    assert review["risk_level"] == "critical"
    assert "Stop promotion" in review["recommended_action"]


def test_repository_review_rejects_changed_pull_request_identity(
    tmp_path,
    monkeypatch,
):
    service, _, _, handoff = repository_review_fixture(tmp_path)
    monkeypatch.setattr(
        service,
        "_github_pull_request",
        lambda repository, github_repository, pull_request_url: (
            github_pull_request(
                handoff,
                url="https://github.com/other/repository/pull/17",
            ),
            [],
        ),
    )

    with pytest.raises(
        RepositoryHandoffError,
        match="different pull-request identity",
    ):
        service.refresh_pull_request(
            handoff["id"],
            handoff["commit_sha"],
        )
    assert service.store.latest_review(handoff["id"]) is None


def test_repository_review_accepts_pending_github_check_exit_code(
    tmp_path,
    monkeypatch,
):
    service, repository, _, handoff = repository_review_fixture(tmp_path)
    responses = iter(
        [
            subprocess.CompletedProcess(
                ["gh", "pr", "view"],
                0,
                stdout=json.dumps(github_pull_request(handoff)).encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                ["gh", "pr", "checks"],
                8,
                stdout=json.dumps(
                    [
                        {
                            "name": "Detection policy",
                            "state": "IN_PROGRESS",
                            "bucket": "pending",
                        }
                    ]
                ).encode(),
                stderr=b"",
            ),
        ]
    )
    commands = []

    def fake_run(command, current_repository, **kwargs):
        commands.append((command, current_repository, kwargs))
        return next(responses)

    monkeypatch.setattr(
        service,
        "_command",
        lambda executable, *arguments: [executable, *arguments],
    )
    monkeypatch.setattr(service, "_run", fake_run)

    pull_request, checks = service._github_pull_request(
        repository,
        "example/detections",
        handoff["pull_request_url"],
    )

    assert pull_request["headRefOid"] == handoff["commit_sha"]
    assert checks[0]["bucket"] == "pending"
    assert len(commands) == 2
    assert commands[1][2]["check"] is False


def test_repository_review_rejects_tampered_snapshot_before_case_preservation(
    tmp_path,
    monkeypatch,
):
    service, _, _, handoff = repository_review_fixture(
        tmp_path,
        linked_case=True,
    )
    monkeypatch.setattr(
        service,
        "_github_pull_request",
        lambda repository, github_repository, pull_request_url: (
            github_pull_request(handoff),
            [],
        ),
    )
    review = service.refresh_pull_request(
        handoff["id"],
        handoff["commit_sha"],
    )["review"]
    with sqlite3.connect(service.store.path) as db:
        db.execute(
            """UPDATE detection_repository_review_snapshots
            SET snapshot='{}' WHERE id=?""",
            (review["id"],),
        )

    with pytest.raises(
        RepositoryHandoffError,
        match="snapshot is invalid",
    ):
        service.preserve_review_to_case(
            handoff["id"],
            review["snapshot_sha256"],
        )
