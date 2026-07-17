from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..cases import CaseStore
from ..rag import EvidenceStore
from ..schemas import (
    ArtifactCreate,
    CaseItemCreate,
    DetectionCreate,
    DetectionExportRequest,
    DetectionGateRunRequest,
    DetectionGitExportRequest,
    DetectionReviewRequest,
    DetectionUpdate,
    DetectionValidationDraftRequest,
    ValidationTaskCreate,
    ValidationTaskRecord,
)
from ..splunk.guardrails import validate_read_only_spl
from ..validation import ValidationService, ValidationStore
from .gitops_verifier import verify_path
from .signing import DetectionSigningKey
from .store import DetectionStore

CRON_PART = re.compile(r"^[0-9*/?,#LW-]+$")
MITRE_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class DetectionService:
    """Evidence-bound detection-as-code drafting, review, and local export."""

    def __init__(
        self,
        store: DetectionStore,
        validations: ValidationStore,
        evidence: EvidenceStore,
        cases: CaseStore,
        export_dir: Path | str,
    ):
        self.store = store
        self.validations = validations
        self.evidence = evidence
        self.cases = cases
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.signing_key = DetectionSigningKey(
            self.export_dir.parent / "detection_signing.key"
        )

    def create(self, value: DetectionCreate) -> dict[str, Any]:
        task = self.validations.get(value.validation_task_id)
        if task is None:
            raise KeyError("Completed validation not found")
        if task.status != "complete" or not task.artifact_id:
            raise ValueError(
                "A detection project requires a completed validation with preserved evidence"
            )
        if task.source_run_id.startswith("detection-runtime:"):
            raise ValueError(
                "A deployment runtime control cannot become a detection project"
            )
        if self.evidence.get(task.artifact_id) is None:
            raise ValueError("The validation evidence artifact is no longer available")
        case_id = value.case_id or task.case_id
        if case_id and self.cases.get(case_id) is None:
            raise ValueError("Linked case not found")
        detection_id = str(uuid4())
        content = {
            "schema_version": "signalroom-detection/v1",
            "id": detection_id,
            "title": value.title.strip() or task.title,
            "description": value.description.strip() or task.rationale,
            "search": task.spl.strip(),
            "schedule": {
                "cron": value.cron_schedule.strip(),
                "earliest_time": task.earliest_time,
                "latest_time": task.latest_time,
                "throttle_seconds": value.throttle_seconds,
            },
            "classification": {
                "severity": value.severity,
                "security_domain": value.security_domain.strip() or "threat",
                "owner": value.owner.strip() or "Unassigned",
                "mitre_attack": self._mitre(value.mitre_attack),
                "tags": self._tags([*value.tags, "signalroom", "detection-as-code"]),
            },
            "evidence": {
                "source_validation_id": task.id,
                "query_fingerprint": task.query_fingerprint,
                "artifact_id": task.artifact_id,
                "result_count": task.result_count,
                "completed_at": task.completed_at,
                "evidence_refs": sorted(set(task.evidence_refs)),
            },
            "testing": {
                "expected_result": "nonzero" if task.result_count else "zero",
                "required_fields": self._result_fields(task.result_preview),
                "validation_row_limit": task.row_limit,
                "max_result_count": 0,
                "max_count_delta_percent": 200,
            },
            "deployment": {
                "enabled": False,
                "authority": "review-package-only",
                "splunk_write_permitted": False,
            },
        }
        self._validate(content)
        return self.store.create(detection_id, task.id, case_id, content)

    def update(self, detection_id: str, value: DetectionUpdate) -> dict[str, Any] | None:
        current = self.store.get(detection_id)
        if current is None:
            return None
        content = json.loads(json.dumps(current["content"]))
        changes = value.model_dump(exclude_none=True)
        direct = {"title", "description", "search"}
        for key in direct.intersection(changes):
            content[key] = changes[key].strip()
        schedule_map = {
            "cron_schedule": "cron",
            "earliest_time": "earliest_time",
            "latest_time": "latest_time",
            "throttle_seconds": "throttle_seconds",
        }
        for source, target in schedule_map.items():
            if source in changes:
                item = changes[source]
                content["schedule"][target] = item.strip() if isinstance(item, str) else item
        classification_map = {
            "owner": "owner",
            "severity": "severity",
            "security_domain": "security_domain",
        }
        for source, target in classification_map.items():
            if source in changes:
                item = changes[source]
                content["classification"][target] = (
                    item.strip() if isinstance(item, str) else item
                )
        if "tags" in changes:
            content["classification"]["tags"] = self._tags(changes["tags"])
        if "mitre_attack" in changes:
            content["classification"]["mitre_attack"] = self._mitre(changes["mitre_attack"])
        testing_map = {
            "expected_result": "expected_result",
            "required_fields": "required_fields",
            "validation_row_limit": "validation_row_limit",
            "max_result_count": "max_result_count",
            "max_count_delta_percent": "max_count_delta_percent",
        }
        testing = content.setdefault("testing", self._default_testing(current["content"]))
        for source, target in testing_map.items():
            if source in changes:
                item = changes[source]
                testing[target] = (
                    self._fields(item) if source == "required_fields" else item
                )
        self._validate(content)
        return self.store.add_version(detection_id, content)

    def submit(self, detection_id: str) -> dict[str, Any] | None:
        current = self.store.get(detection_id)
        if current is None:
            return None
        self._validate(current["content"])
        self._passing_gate(current)
        return self.store.submit(detection_id)

    def run_gate(
        self, detection_id: str, request: DetectionGateRunRequest
    ) -> dict[str, Any]:
        current = self.store.get(detection_id)
        if current is None:
            raise KeyError("Detection not found")
        if current["status"] == "retired":
            raise ValueError("A retired detection cannot run a promotion gate")
        if current["current_sha256"] != request.expected_content_sha256:
            raise ValueError("Detection content changed; run the gate on the current version")
        content = current["content"]
        self._validate(content)
        testing = self._default_testing(content)
        fingerprint = self._validation_fingerprint(content)
        validation = self.validations.find_latest_complete(fingerprint)
        baseline = self.store.accepted_gate(detection_id)
        baseline_count = baseline["result_count"] if baseline else None
        result_count = validation.result_count if validation else 0
        delta = self._result_delta(result_count, baseline_count)
        controls = self._gate_controls(
            content,
            testing,
            validation,
            baseline,
            delta,
        )
        blocking = [item for item in controls if item["blocking"] and item["status"] == "fail"]
        score = sum(
            int(item["weight"])
            for item in controls
            if item["status"] == "pass"
        )
        status = "pass" if not blocking and score >= 80 else "fail"
        return self.store.record_gate(
            detection_id,
            content_sha256=current["current_sha256"],
            status=status,
            score=score,
            validation_task_id=validation.id if validation else "",
            baseline_gate_id=baseline["id"] if baseline else "",
            result_count=result_count,
            baseline_result_count=baseline_count,
            result_delta_percent=delta,
            controls=controls,
        )

    def create_validation_draft(
        self, detection_id: str, request: DetectionValidationDraftRequest
    ) -> tuple[ValidationTaskRecord, bool]:
        current = self.store.get(detection_id)
        if current is None:
            raise KeyError("Detection not found")
        if current["status"] == "retired":
            raise ValueError("A retired detection cannot queue validation work")
        if current["current_sha256"] != request.expected_content_sha256:
            raise ValueError(
                "Detection content changed; queue validation for the current version"
            )
        content = current["content"]
        self._validate(content)
        testing = self._default_testing(content)
        schedule = content["schedule"]
        row_limit = int(testing["validation_row_limit"])
        ValidationService.validate_contract(
            content["search"],
            schedule["earliest_time"],
            schedule["latest_time"],
            row_limit,
        )
        fingerprint = self._validation_fingerprint(content)
        complete = self.validations.find_latest_complete(fingerprint)
        if complete is not None:
            return complete, True
        reusable = self.validations.find_reusable(fingerprint)
        if reusable is not None:
            return reusable, True
        task = self.validations.create(
            ValidationTaskCreate(
                title=(
                    f"Detection regression · {content['title']} · "
                    f"v{current['current_version']}"
                ),
                rationale=(
                    "Refresh the exact bounded evidence contract required by the "
                    f"promotion gate for detection version {current['current_version']} "
                    f"({current['current_sha256'][:12]}). Queueing this draft does not "
                    "approve or execute the Splunk search."
                ),
                spl=content["search"],
                earliest_time=schedule["earliest_time"],
                latest_time=schedule["latest_time"],
                row_limit=row_limit,
                evidence_refs=content["evidence"].get("evidence_refs", []),
                source_run_id=f"detection:{detection_id}",
                source_finding_ref=f"version:{current['current_version']}",
                case_id=current.get("case_id"),
            )
        )
        return task, False

    def review(
        self, detection_id: str, request: DetectionReviewRequest
    ) -> dict[str, Any] | None:
        current = self.store.get(detection_id)
        if current is None:
            return None
        self._validate(current["content"])
        gate: dict[str, Any] | None = None
        if request.decision == "approve":
            gate = self._passing_gate(current)
        reviewed = self.store.review(
            detection_id,
            decision=request.decision,
            expected_sha256=request.expected_content_sha256,
            reviewer=request.reviewer.strip(),
            note=request.note.strip(),
            accepted_gate_id=gate["id"] if gate else "",
        )
        if reviewed and request.decision == "approve":
            assert gate is not None
            self._preserve_approval(reviewed)
        return reviewed

    def export(
        self, detection_id: str, request: DetectionExportRequest
    ) -> tuple[dict[str, Any], Path]:
        current = self._exportable_detection(
            detection_id,
            request.expected_content_sha256,
        )
        content = current["content"]
        stem = f"signalroom_detection_{detection_id[:8]}_v{current['current_version']}"
        files = {
            "detection.yml": self._yaml(current),
            "default/savedsearches.conf": self._savedsearch(content),
            "README.md": self._readme(current),
        }
        manifest = {
            "schema_version": "signalroom-detection-package/v1",
            "detection_id": detection_id,
            "version": current["current_version"],
            "content_sha256": current["current_sha256"],
            "review": {
                "status": current["status"],
                "reviewer": current["reviewed_by"],
                "reviewed_at": current["reviewed_at"],
            },
            "promotion_gate": self._export_gate(current),
            "authority": {
                "deploys_to_splunk": False,
                "enables_saved_search": False,
                "contains_raw_results": False,
            },
            "files": {
                name: hashlib.sha256(value.encode()).hexdigest()
                for name, value in files.items()
            },
        }
        files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True)
        path = self.export_dir / f"{stem}.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        archive_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        result = self.store.record_export(
            detection_id, path.name, current["current_sha256"], archive_sha256
        )
        assert result is not None
        return result, path

    def export_git_change(
        self, detection_id: str, request: DetectionGitExportRequest
    ) -> tuple[dict[str, Any], Path, dict[str, Any]]:
        current = self._exportable_detection(
            detection_id,
            request.expected_content_sha256,
        )
        stem = (
            f"signalroom_git_change_{detection_id[:8]}_"
            f"v{current['current_version']}"
        )
        path = self.export_dir / f"{stem}.zip"
        current, path, verification, archive_sha256 = (
            self.build_git_change_archive(
                detection_id,
                request.expected_content_sha256,
                path,
            )
        )
        result = self.store.record_export(
            detection_id,
            path.name,
            current["current_sha256"],
            archive_sha256,
            export_kind="git-change",
        )
        assert result is not None
        return result, path, verification

    def build_git_change_archive(
        self,
        detection_id: str,
        expected_content_sha256: str,
        destination: Path | str,
    ) -> tuple[dict[str, Any], Path, dict[str, Any], str]:
        """Build and self-verify a signed change without recording an analyst export."""
        current = self._exportable_detection(
            detection_id,
            expected_content_sha256,
        )
        content = current["content"]
        gate = self._export_gate(current)
        if not gate:
            raise ValueError(
                "Git change export requires an accepted promotion gate for this version"
            )
        slug = self._slug(content["title"])
        detection_root = f"detections/{slug}-{detection_id[:8]}"
        detection_files = {
            "detection.json": f"{DetectionStore.canonical(content)}\n",
            "detection.yml": self._yaml(current),
            "savedsearches.conf": self._savedsearch(content),
            "README.md": self._readme(current),
        }
        key_id = self.signing_key.key_id()
        manifest = {
            "schema_version": "signalroom-detection-git-change/v1",
            "detection_id": detection_id,
            "version": current["current_version"],
            "content_sha256": current["current_sha256"],
            "source_validation_id": current["source_validation_id"],
            "review": {
                "status": current["status"],
                "reviewer": current["reviewed_by"],
                "reviewed_at": current["reviewed_at"],
            },
            "promotion_gate": gate,
            "repository_policy": {
                "minimum_gate_score": 80,
                "requires_accepted_gate": True,
                "requires_disabled_saved_search": True,
                "requires_pinned_signing_key": True,
            },
            "authority": {
                "deploys_to_splunk": False,
                "enables_saved_search": False,
                "contains_raw_results": False,
                "creates_git_commit": False,
                "opens_pull_request": False,
            },
            "signing": {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "signature_file": "manifest.sig",
            },
            "files": {
                name: hashlib.sha256(value.encode()).hexdigest()
                for name, value in detection_files.items()
            },
        }
        signature = self.signing_key.sign(self._canonical_manifest(manifest))
        repository_files: dict[str, str | bytes] = {
            **{
                f"{detection_root}/{name}": value
                for name, value in detection_files.items()
            },
            f"{detection_root}/manifest.json": json.dumps(
                manifest,
                indent=2,
                sort_keys=True,
            ),
            f"{detection_root}/manifest.sig": f"{signature}\n",
            ".signalroom/signalroom.pub": self.signing_key.public_pem(),
            ".signalroom/policy.json": json.dumps(
                self._repository_policy(key_id),
                indent=2,
                sort_keys=True,
            ),
            ".github/workflows/signalroom-detection-policy.yml": self._workflow(),
            "tools/verify_signalroom_detection.py": (
                Path(__file__).with_name("gitops_verifier.py").read_text(
                    encoding="utf-8"
                )
            ),
            "CHANGE_REQUEST.md": self._change_request(current, key_id),
        }
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in repository_files.items():
                archive.writestr(name, body)
        try:
            verification = verify_path(path, key_id)
        except Exception:
            path.unlink(missing_ok=True)
            raise
        archive_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        return current, path, verification, archive_sha256

    def retire(self, detection_id: str) -> dict[str, Any] | None:
        return self.store.retire(detection_id)

    def delete(self, detection_id: str) -> bool:
        return self.store.delete(detection_id)

    def _preserve_approval(self, detection: dict[str, Any]) -> None:
        content = detection["content"]
        artifact = self.evidence.add(
            ArtifactCreate(
                title=f"Approved detection · {content['title']} · v{detection['current_version']}",
                kind="detection",
                source="SignalRoom detection review",
                tags=self._tags(
                    [
                        *content["classification"]["tags"],
                        *content["classification"]["mitre_attack"],
                    ]
                ),
                content=self._readme(detection),
            ),
            metadata={
                "detection_id": detection["id"],
                "version": detection["current_version"],
                "content_sha256": detection["current_sha256"],
                "source_validation_id": detection["source_validation_id"],
            },
        )
        case_id = detection.get("case_id")
        if case_id and self.cases.get(case_id):
            self.cases.add_item(
                case_id,
                CaseItemCreate(
                    kind="decision",
                    title=f"Detection approved · {content['title']}",
                    content=(
                        f"Version {detection['current_version']} was approved for export review.\n\n"
                        f"Content SHA-256: {detection['current_sha256']}\n"
                        f"Source validation: {detection['source_validation_id']}\n"
                        f"Context artifact: {artifact.id}\n\n"
                        "This decision does not deploy or enable a saved search in Splunk."
                    ),
                    source="SignalRoom detection review",
                    confidence="high",
                    status="complete",
                    metadata={
                        "detection_id": detection["id"],
                        "detection_version": detection["current_version"],
                        "content_sha256": detection["current_sha256"],
                        "artifact_id": artifact.id,
                    },
                ),
            )

    def _exportable_detection(
        self, detection_id: str, expected_sha256: str
    ) -> dict[str, Any]:
        current = self.store.get(detection_id)
        if current is None:
            raise KeyError("Detection not found")
        if current["status"] != "approved":
            raise ValueError("Only an approved detection version can be exported")
        if (
            expected_sha256 != current["current_sha256"]
            or expected_sha256 != current["approved_sha256"]
        ):
            raise ValueError(
                "Approved detection content changed; review the current version"
            )
        self._validate(current["content"])
        return current

    @staticmethod
    def _canonical_manifest(manifest: dict[str, Any]) -> bytes:
        return json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
        return slug[:72] or "detection"

    @staticmethod
    def _repository_policy(key_id: str) -> dict[str, Any]:
        return {
            "schema_version": "signalroom-repository-policy/v1",
            "trusted_key_sha256": key_id,
            "trust_bootstrap": (
                "Pin this fingerprint as the protected repository variable "
                "SIGNALROOM_TRUSTED_KEY_SHA256. Do not trust a fingerprint changed "
                "inside the same detection pull request."
            ),
            "minimum_gate_score": 80,
            "require_approved_review": True,
            "require_accepted_gate": True,
            "require_disabled_saved_search": True,
            "allow_raw_results": False,
            "allow_splunk_deployment": False,
        }

    @staticmethod
    def _workflow() -> str:
        return """name: SignalRoom detection policy

on:
  pull_request:
    paths:
      - "detections/**"
      - ".signalroom/**"
      - "tools/verify_signalroom_detection.py"
      - ".github/workflows/signalroom-detection-policy.yml"

permissions:
  contents: read

jobs:
  verify-detection-change:
    runs-on: ubuntu-latest
    env:
      SIGNALROOM_TRUSTED_KEY_SHA256: ${{ vars.SIGNALROOM_TRUSTED_KEY_SHA256 }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Require repository-pinned SignalRoom key
        shell: bash
        run: |
          if [ -z "$SIGNALROOM_TRUSTED_KEY_SHA256" ]; then
            echo "Set the protected repository variable SIGNALROOM_TRUSTED_KEY_SHA256."
            exit 1
          fi
      - name: Install offline verifier dependency
        run: python -m pip install "cryptography>=42,<47"
      - name: Verify signed detection change
        run: >-
          python tools/verify_signalroom_detection.py .
          --trusted-key-sha256 "$SIGNALROOM_TRUSTED_KEY_SHA256"
"""

    @staticmethod
    def _change_request(detection: dict[str, Any], key_id: str) -> str:
        content = detection["content"]
        gate = DetectionService._export_gate(detection)
        return "\n".join(
            [
                f"# Detection change · {content['title']}",
                "",
                "This repository-ready change was produced locally by SignalRoom. "
                "It did not create a commit, open a pull request, or write to Splunk.",
                "",
                "## Review identity",
                "",
                f"- Detection: `{detection['id']}`",
                f"- Version: {detection['current_version']}",
                f"- Content SHA-256: `{detection['current_sha256']}`",
                f"- Reviewer: {detection['reviewed_by']}",
                f"- Reviewed: {detection['reviewed_at']}",
                f"- Promotion gate: `{gate.get('id', '')}` · "
                f"{gate.get('score', 0)}/100",
                f"- Signing key SHA-256: `{key_id}`",
                "",
                "## Repository bootstrap",
                "",
                "1. Confirm the signing-key fingerprint with the SignalRoom operator "
                "through a channel outside this change.",
                "2. Store it as the protected repository variable "
                "`SIGNALROOM_TRUSTED_KEY_SHA256`.",
                "3. Protect the generated workflow, verifier, and `.signalroom` policy "
                "with repository ownership rules.",
                "4. Extract this ZIP at the repository root and review the resulting diff.",
                "",
                "## Analyst checklist",
                "",
                "- [ ] Confirm data ownership and target Splunk app.",
                "- [ ] Confirm schedule, search concurrency, and suppression policy.",
                "- [ ] Confirm required fields and accepted result-count drift.",
                "- [ ] Obtain normal deployment approval outside SignalRoom.",
                "",
                "The saved-search stanza remains disabled and unscheduled.",
                "",
            ]
        )

    @staticmethod
    def _tags(values: list[str]) -> list[str]:
        return sorted(
            {
                str(value).strip().lower()[:80]
                for value in values
                if str(value).strip()
            }
        )[:32]

    @staticmethod
    def _fields(values: list[str]) -> list[str]:
        return sorted(
            {
                str(value).strip()[:160]
                for value in values
                if str(value).strip()
            }
        )[:32]

    @classmethod
    def _result_fields(cls, preview: list[Any]) -> list[str]:
        rows = [row for row in preview if isinstance(row, dict)]
        if not rows:
            return []
        common = set(str(key) for key in rows[0])
        for row in rows[1:]:
            common.intersection_update(str(key) for key in row)
        return cls._fields(list(common))[:16]

    @classmethod
    def _default_testing(cls, content: dict[str, Any]) -> dict[str, Any]:
        evidence = content.get("evidence") or {}
        supplied = content.get("testing") or {}
        return {
            "expected_result": supplied.get(
                "expected_result",
                "nonzero" if int(evidence.get("result_count", 0)) else "zero",
            ),
            "required_fields": cls._fields(supplied.get("required_fields") or []),
            "validation_row_limit": int(supplied.get("validation_row_limit", 100)),
            "max_result_count": int(supplied.get("max_result_count", 0)),
            "max_count_delta_percent": int(
                supplied.get("max_count_delta_percent", 200)
            ),
        }

    @classmethod
    def _validation_fingerprint(cls, content: dict[str, Any]) -> str:
        schedule = content["schedule"]
        testing = cls._default_testing(content)
        return ValidationStore.fingerprint(
            content["search"],
            schedule["earliest_time"],
            schedule["latest_time"],
            testing["validation_row_limit"],
        )

    @staticmethod
    def _result_delta(current: int, baseline: int | None) -> float | None:
        if baseline is None:
            return None
        return round(abs(current - baseline) / max(abs(baseline), 1) * 100, 2)

    def _gate_controls(
        self,
        content: dict[str, Any],
        testing: dict[str, Any],
        validation: ValidationTaskRecord | None,
        baseline: dict[str, Any] | None,
        delta: float | None,
    ) -> list[dict[str, Any]]:
        controls: list[dict[str, Any]] = []

        def add(
            control_id: str,
            label: str,
            passed: bool,
            detail: str,
            weight: int,
            *,
            blocking: bool = True,
            warning: bool = False,
        ) -> None:
            controls.append(
                {
                    "id": control_id,
                    "label": label,
                    "status": "pass" if passed else ("warn" if warning else "fail"),
                    "blocking": blocking,
                    "weight": weight,
                    "detail": detail,
                }
            )

        try:
            validate_read_only_spl(content["search"])
            read_only = True
            read_only_detail = "SPL passed the read-only search guardrail."
        except ValueError as exc:
            read_only = False
            read_only_detail = str(exc)
        add("read-only", "Read-only SPL", read_only, read_only_detail, 15)

        exact = validation is not None
        add(
            "exact-validation",
            "Exact completed validation",
            exact,
            (
                f"Completed task {validation.id} matches search, window, and row limit."
                if validation
                else "No completed validation matches this search, window, and row limit."
            ),
            25,
        )
        artifact_ok = bool(
            validation
            and validation.artifact_id
            and self.evidence.get(validation.artifact_id)
        )
        add(
            "preserved-evidence",
            "Preserved evidence artifact",
            artifact_ok,
            (
                f"Evidence artifact {validation.artifact_id} is available."
                if artifact_ok and validation
                else "The exact validation does not have an available evidence artifact."
            ),
            15,
        )
        result_count = validation.result_count if validation else 0
        expected = testing["expected_result"]
        expectation_ok = (
            expected == "any"
            or (expected == "zero" and result_count == 0)
            or (expected == "nonzero" and result_count > 0)
        )
        add(
            "expected-result",
            "Expected result contract",
            bool(validation) and expectation_ok,
            (
                f"Expected {expected}; observed {result_count} result(s)."
                if validation
                else f"Expected {expected}; no exact validation result is available."
            ),
            15,
        )
        observed_fields: set[str] = set()
        rows = (
            [row for row in validation.result_preview if isinstance(row, dict)]
            if validation
            else []
        )
        if rows:
            observed_fields = set(str(key) for key in rows[0])
            for row in rows[1:]:
                observed_fields.intersection_update(str(key) for key in row)
        required = set(testing["required_fields"])
        missing = sorted(required - observed_fields)
        fields_ok = not missing and (not required or bool(rows))
        add(
            "required-fields",
            "Required result fields",
            bool(validation) and fields_ok,
            (
                "All required fields were present in every preview row."
                if validation and fields_ok
                else (
                    f"Missing from one or more preview rows: {', '.join(missing)}."
                    if missing
                    else "No exact result preview is available for the field contract."
                )
            ),
            15,
        )
        maximum = int(testing["max_result_count"])
        maximum_ok = not maximum or result_count <= maximum
        add(
            "maximum-result-count",
            "Maximum result count",
            bool(validation) and maximum_ok,
            (
                f"Observed {result_count}; configured maximum is "
                f"{maximum if maximum else 'unlimited'}."
            ),
            5,
        )
        delta_limit = int(testing["max_count_delta_percent"])
        delta_ok = delta is None or delta <= delta_limit
        add(
            "baseline-drift",
            "Accepted baseline drift",
            bool(validation) and delta_ok,
            (
                "This passing run will establish the first accepted baseline."
                if baseline is None
                else (
                    f"Result count changed {delta:.2f}% from accepted gate "
                    f"{baseline['id'][:12]}; limit is {delta_limit}%."
                )
            ),
            10,
        )
        explicit_scope = bool(
            re.search(r"\bindex\s*=", content["search"], re.IGNORECASE)
            or re.search(r"\bdatamodel\s*=", content["search"], re.IGNORECASE)
            or re.search(r"\|\s*tstats\b", content["search"], re.IGNORECASE)
        )
        add(
            "explicit-scope",
            "Explicit data scope",
            explicit_scope,
            (
                "The SPL declares an index, data model, or tstats scope."
                if explicit_scope
                else "No explicit index or data-model scope was detected; review search cost."
            ),
            0,
            blocking=False,
            warning=not explicit_scope,
        )
        fresh = False
        if validation and validation.completed_at:
            completed = datetime.fromisoformat(validation.completed_at.replace("Z", "+00:00"))
            fresh = (datetime.now(UTC) - completed.astimezone(UTC)).days <= 7
        add(
            "evidence-freshness",
            "Evidence freshness",
            fresh,
            (
                f"Validation completed {validation.completed_at}."
                if validation and validation.completed_at
                else "No completion time is available."
            ),
            0,
            blocking=False,
            warning=not fresh,
        )
        return controls

    def _passing_gate(self, current: dict[str, Any]) -> dict[str, Any]:
        gate = self.store.latest_gate(current["id"], current["current_sha256"])
        if gate is None or gate["status"] != "pass" or gate["score"] < 80:
            raise ValueError(
                "The exact current detection version requires a passing promotion gate"
            )
        task = self.validations.get(gate["validation_task_id"])
        if (
            task is None
            or task.status != "complete"
            or task.query_fingerprint != self._validation_fingerprint(current["content"])
            or not task.artifact_id
            or self.evidence.get(task.artifact_id) is None
        ):
            raise ValueError(
                "Promotion-gate evidence is no longer complete and available; run the gate again"
            )
        return gate

    @staticmethod
    def _export_gate(detection: dict[str, Any]) -> dict[str, Any]:
        gates = [
            item
            for item in detection.get("gate_runs", [])
            if item.get("accepted_at")
            and item["content_sha256"] == detection["current_sha256"]
        ]
        if not gates:
            return {}
        gate = gates[0]
        return {
            "id": gate["id"],
            "status": gate["status"],
            "score": gate["score"],
            "content_sha256": gate["content_sha256"],
            "validation_task_id": gate["validation_task_id"],
            "baseline_gate_id": gate["baseline_gate_id"],
            "result_count": gate["result_count"],
            "baseline_result_count": gate["baseline_result_count"],
            "result_delta_percent": gate["result_delta_percent"],
            "controls": [
                {
                    "id": item["id"],
                    "status": item["status"],
                    "blocking": item["blocking"],
                }
                for item in gate["controls"]
            ],
            "accepted_at": gate["accepted_at"],
        }

    @staticmethod
    def _mitre(values: list[str]) -> list[str]:
        techniques = sorted({str(value).strip().upper() for value in values if str(value).strip()})
        invalid = [value for value in techniques if not MITRE_TECHNIQUE.fullmatch(value)]
        if invalid:
            raise ValueError(
                f"MITRE ATT&CK techniques must look like T1059 or T1059.001: {invalid[0]}"
            )
        return techniques[:32]

    @staticmethod
    def _validate(content: dict[str, Any]) -> None:
        if not str(content.get("title", "")).strip():
            raise ValueError("Detection title is required")
        if len(str(content.get("title", ""))) > 240:
            raise ValueError("Detection title cannot exceed 240 characters")
        search = str(content.get("search", "")).strip()
        validate_read_only_spl(search)
        schedule = content.get("schedule") or {}
        cron = str(schedule.get("cron", "")).strip()
        parts = cron.split()
        if len(parts) != 5 or any(not CRON_PART.fullmatch(part) for part in parts):
            raise ValueError("Cron schedule must contain five valid fields")
        earliest = str(schedule.get("earliest_time", "")).strip()
        latest = str(schedule.get("latest_time", "")).strip()
        if not earliest.startswith("-") or latest != "now":
            raise ValueError("Detection dispatch requires a relative earliest time and latest_time=now")
        throttle = int(schedule.get("throttle_seconds", 0))
        if not 0 <= throttle <= 86400:
            raise ValueError("Detection throttle must be between 0 and 86400 seconds")
        testing = DetectionService._default_testing(content)
        if testing["expected_result"] not in {"any", "zero", "nonzero"}:
            raise ValueError("Expected result must be any, zero, or nonzero")
        if not 1 <= testing["validation_row_limit"] <= 500:
            raise ValueError("Detection validation row limits must be between 1 and 500")
        if not 0 <= testing["max_result_count"] <= 10_000_000:
            raise ValueError("Maximum result count is outside the supported range")
        if not 0 <= testing["max_count_delta_percent"] <= 10_000:
            raise ValueError("Maximum baseline drift is outside the supported range")

    @staticmethod
    def _yaml(detection: dict[str, Any]) -> str:
        content = detection["content"]
        classification = content["classification"]
        schedule = content["schedule"]
        evidence = content["evidence"]
        testing = DetectionService._default_testing(content)

        def quote(value: Any) -> str:
            return json.dumps(value, ensure_ascii=False)

        search = "\n".join(f"  {line}" for line in content["search"].splitlines())
        return "\n".join(
            [
                f"schema_version: {quote(content['schema_version'])}",
                f"id: {quote(content['id'])}",
                f"version: {detection['current_version']}",
                f"content_sha256: {quote(detection['current_sha256'])}",
                f"title: {quote(content['title'])}",
                f"description: {quote(content['description'])}",
                "search: |",
                search,
                "schedule:",
                f"  cron: {quote(schedule['cron'])}",
                f"  earliest_time: {quote(schedule['earliest_time'])}",
                f"  latest_time: {quote(schedule['latest_time'])}",
                f"  throttle_seconds: {schedule['throttle_seconds']}",
                "classification:",
                f"  severity: {quote(classification['severity'])}",
                f"  security_domain: {quote(classification['security_domain'])}",
                f"  owner: {quote(classification['owner'])}",
                f"  mitre_attack: {json.dumps(classification['mitre_attack'])}",
                f"  tags: {json.dumps(classification['tags'])}",
                "evidence:",
                f"  source_validation_id: {quote(evidence['source_validation_id'])}",
                f"  query_fingerprint: {quote(evidence['query_fingerprint'])}",
                f"  artifact_id: {quote(evidence['artifact_id'])}",
                f"  result_count: {evidence['result_count']}",
                f"  completed_at: {quote(evidence['completed_at'])}",
                f"  evidence_refs: {json.dumps(evidence['evidence_refs'])}",
                "testing:",
                f"  expected_result: {quote(testing['expected_result'])}",
                f"  required_fields: {json.dumps(testing['required_fields'])}",
                f"  validation_row_limit: {testing['validation_row_limit']}",
                f"  max_result_count: {testing['max_result_count']}",
                f"  max_count_delta_percent: {testing['max_count_delta_percent']}",
                "deployment:",
                "  enabled: false",
                '  authority: "review-package-only"',
                "  splunk_write_permitted: false",
                "",
            ]
        )

    @staticmethod
    def _savedsearch(content: dict[str, Any]) -> str:
        title = re.sub(r"[\]\r\n]+", " ", content["title"]).strip()
        description = re.sub(r"\s+", " ", content["description"]).strip()
        search = re.sub(r"\s+", " ", content["search"]).strip()
        schedule = content["schedule"]
        severity = content["classification"]["severity"]
        return "\n".join(
            [
                f"[{title}]",
                f"description = {description}",
                f"search = {search}",
                f"cron_schedule = {schedule['cron']}",
                f"dispatch.earliest_time = {schedule['earliest_time']}",
                f"dispatch.latest_time = {schedule['latest_time']}",
                f"alert.severity = {severity}",
                f"alert.suppress.period = {schedule['throttle_seconds']}s",
                "enableSched = 0",
                "disabled = 1",
                "action.notable = 0",
                "",
            ]
        )

    @staticmethod
    def _readme(detection: dict[str, Any]) -> str:
        content = detection["content"]
        classification = content["classification"]
        evidence = content["evidence"]
        testing = DetectionService._default_testing(content)
        gate = DetectionService._export_gate(detection)
        return "\n".join(
            [
                f"# {content['title']}",
                "",
                f"- Detection ID: `{detection['id']}`",
                f"- Version: {detection['current_version']}",
                f"- Review status: {detection['status']}",
                f"- Content SHA-256: `{detection['current_sha256']}`",
                f"- Severity: {classification['severity']}",
                f"- Owner: {classification['owner']}",
                f"- Security domain: {classification['security_domain']}",
                f"- MITRE ATT&CK: {', '.join(classification['mitre_attack']) or 'not assigned'}",
                "",
                "## Detection intent",
                "",
                content["description"] or "No description recorded.",
                "",
                "## Search",
                "",
                f"```spl\n{content['search']}\n```",
                "",
                "## Dispatch",
                "",
                f"- Cron: `{content['schedule']['cron']}`",
                f"- Window: `{content['schedule']['earliest_time']}` to "
                f"`{content['schedule']['latest_time']}`",
                f"- Throttle: {content['schedule']['throttle_seconds']} seconds",
                "",
                "## Evidence contract",
                "",
                f"- Completed validation: `{evidence['source_validation_id']}`",
                f"- Query fingerprint: `{evidence['query_fingerprint']}`",
                f"- Preserved artifact: `{evidence['artifact_id']}`",
                f"- Validation result count: {evidence['result_count']}",
                f"- Evidence references: {', '.join(evidence['evidence_refs']) or 'none'}",
                "",
                "## Promotion gate contract",
                "",
                f"- Expected result: `{testing['expected_result']}`",
                f"- Required fields: {', '.join(testing['required_fields']) or 'none'}",
                f"- Validation row limit: {testing['validation_row_limit']}",
                f"- Maximum result count: "
                f"{testing['max_result_count'] or 'unlimited'}",
                f"- Maximum count drift: {testing['max_count_delta_percent']}%",
                f"- Accepted gate: `{gate.get('id', 'not accepted')}`",
                f"- Gate score: {gate.get('score', 'not available')}",
                f"- Gate validation: `{gate.get('validation_task_id', 'not available')}`",
                "",
                "## Deployment boundary",
                "",
                "This package is disabled by default. SignalRoom did not deploy, enable, or write "
                "this detection to Splunk. Review the target app, permissions, scheduling, "
                "suppression, risk, and notable-event policy through your normal change process.",
                "",
            ]
        )
