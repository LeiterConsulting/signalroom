from __future__ import annotations

import hashlib
import json
import re
import zipfile
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
    DetectionReviewRequest,
    DetectionUpdate,
)
from ..splunk.guardrails import validate_read_only_spl
from ..validation import ValidationStore
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

    def create(self, value: DetectionCreate) -> dict[str, Any]:
        task = self.validations.get(value.validation_task_id)
        if task is None:
            raise KeyError("Completed validation not found")
        if task.status != "complete" or not task.artifact_id:
            raise ValueError(
                "A detection project requires a completed validation with preserved evidence"
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
        self._validate(content)
        return self.store.add_version(detection_id, content)

    def submit(self, detection_id: str) -> dict[str, Any] | None:
        current = self.store.get(detection_id)
        if current is None:
            return None
        self._validate(current["content"])
        return self.store.submit(detection_id)

    def review(
        self, detection_id: str, request: DetectionReviewRequest
    ) -> dict[str, Any] | None:
        current = self.store.get(detection_id)
        if current is None:
            return None
        self._validate(current["content"])
        reviewed = self.store.review(
            detection_id,
            decision=request.decision,
            expected_sha256=request.expected_content_sha256,
            reviewer=request.reviewer.strip(),
            note=request.note.strip(),
        )
        if reviewed and request.decision == "approve":
            self._preserve_approval(reviewed)
        return reviewed

    def export(
        self, detection_id: str, request: DetectionExportRequest
    ) -> tuple[dict[str, Any], Path]:
        current = self.store.get(detection_id)
        if current is None:
            raise KeyError("Detection not found")
        if current["status"] != "approved":
            raise ValueError("Only an approved detection version can be exported")
        expected = request.expected_content_sha256
        if expected != current["current_sha256"] or expected != current["approved_sha256"]:
            raise ValueError("Approved detection content changed; review the current version")
        self._validate(current["content"])
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

    @staticmethod
    def _yaml(detection: dict[str, Any]) -> str:
        content = detection["content"]
        classification = content["classification"]
        schedule = content["schedule"]
        evidence = content["evidence"]

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
                "## Deployment boundary",
                "",
                "This package is disabled by default. SignalRoom did not deploy, enable, or write "
                "this detection to Splunk. Review the target app, permissions, scheduling, "
                "suppression, risk, and notable-event policy through your normal change process.",
                "",
            ]
        )
