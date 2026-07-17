from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from ..config import ConfigStore
from ..schemas import CaseItemCreate, ValidationTaskCreate
from ..validation import ValidationService
from .deployment_store import DetectionDeploymentStore
from .service import DetectionService


class DeploymentVerificationError(ValueError):
    pass


class DetectionDeploymentService:
    """Read-only comparison of approved detections with Splunk saved searches."""

    ROW_LIMIT = 1000

    def __init__(
        self,
        config: ConfigStore,
        detections: DetectionService,
        store: DetectionDeploymentStore,
        splunk: Callable[[], Any],
    ):
        self.config = config
        self.detections = detections
        self.store = store
        self.splunk = splunk
        self._case_lock = RLock()

    async def refresh(
        self,
        detection_id: str,
        expected_content_sha256: str,
        target_app: str = "",
    ) -> dict[str, Any]:
        detection = self._approved_detection(
            detection_id,
            expected_content_sha256,
        )
        if self.config.load().demo_mode:
            raise DeploymentVerificationError(
                "Demo mode cannot verify a real Splunk deployment"
            )
        target_app = target_app.strip()
        if target_app and not re.fullmatch(r"[A-Za-z0-9_.-]+", target_app):
            raise DeploymentVerificationError(
                "Target Splunk app contains unsupported characters"
            )
        result = await self.splunk().call(
            "get_knowledge_objects",
            {
                "type": "saved_searches",
                "row_limit": self.ROW_LIMIT,
            },
        )
        rows, collection = self._collection(result)
        snapshot = self._snapshot(
            detection,
            target_app,
            rows,
            collection,
        )
        snapshot_sha256 = self._sha256(self._canonical(snapshot))
        return self.store.record(
            detection_id,
            detection["current_version"],
            expected_content_sha256,
            snapshot_sha256,
            snapshot,
        )

    def latest(
        self,
        detection_id: str,
        content_sha256: str,
    ) -> dict[str, Any] | None:
        snapshot = self.store.latest(detection_id, content_sha256)
        return self._with_runtime(snapshot) if snapshot else None

    def create_runtime_draft(
        self,
        detection_id: str,
        expected_snapshot_sha256: str,
        earliest_time: str = "",
        max_lag_seconds: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        detection, snapshot = self._current_snapshot(
            detection_id,
            expected_snapshot_sha256,
        )
        if snapshot["status"] != "verified":
            raise DeploymentVerificationError(
                "Runtime validation requires an exact, enabled deployment verification"
            )
        identity = snapshot.get("runtime_identity") or {}
        if not identity.get("unique_name_observed"):
            raise DeploymentVerificationError(
                "Refresh deployment verification before staging runtime evidence; "
                "scheduler attribution requires a uniquely observed saved-search name"
            )
        existing = self.store.latest_runtime_check(snapshot["id"])
        if existing is not None:
            task = self.detections.validations.get(
                existing["validation_task_id"]
            )
            existing_view = self._runtime_view(existing)
            if (
                existing_view["state"]
                not in {"contract-drifted", "validation-missing", "expired"}
                and task is not None
                and (
                task.status in {"draft", "approved", "running", "error"}
                or (
                    task.status == "complete"
                    and not existing["assessment_sha256"]
                )
                )
            ):
                return existing_view, True

        policy = self._runtime_policy(
            detection["content"]["schedule"]["cron"],
            earliest_time,
            max_lag_seconds,
        )
        saved_search_name = str(identity["savedsearch_name"])
        spl = self._runtime_spl(saved_search_name)
        ValidationService.validate_contract(
            spl,
            policy["earliest_time"],
            "now",
            1,
        )
        task = self.detections.validations.create(
            ValidationTaskCreate(
                title=(
                    f"Runtime health · {detection['content']['title']} · "
                    f"v{detection['current_version']}"
                ),
                rationale=(
                    "Observe scheduler execution evidence for the exact deployment "
                    f"snapshot {snapshot['snapshot_sha256'][:12]}. This name-bound "
                    "check reports execution count, last outcome, lag, and duration. "
                    "It does not approve or execute itself, prove alert firing, or "
                    "change Splunk."
                ),
                spl=spl,
                earliest_time=policy["earliest_time"],
                latest_time="now",
                row_limit=1,
                evidence_refs=[
                    f"deployment:{snapshot['snapshot_sha256'][:12]}"
                ],
                source_run_id=f"detection-runtime:{detection_id}",
                source_finding_ref=f"runtime:{snapshot['id'][:32]}",
                case_id=detection.get("case_id"),
            )
        )
        created_at = datetime.now(UTC).isoformat()
        contract = {
            "schema_version": "signalroom-splunk-runtime-check/v1",
            "subject": {
                "detection_id": detection_id,
                "version": detection["current_version"],
                "content_sha256": detection["current_sha256"],
                "deployment_snapshot_sha256": snapshot["snapshot_sha256"],
            },
            "identity": {
                "savedsearch_name": saved_search_name,
                "attribution": "scheduler-name-only",
                "target_app": snapshot["target"]["app"],
                "unique_name_observed": True,
            },
            "validation": {
                "task_id": task.id,
                "query_fingerprint": task.query_fingerprint,
                "spl": task.spl,
                "earliest_time": task.earliest_time,
                "latest_time": task.latest_time,
                "row_limit": task.row_limit,
                "approval_scope": task.approval_scope,
            },
            "policy": policy,
            "limitations": [
                "Scheduler telemetry is attributed by saved-search name, not app.",
                "Observed execution does not prove alert, notable-event, or response delivery.",
                "A zero-result window is absence of observed scheduler events, not proof of disablement.",
            ],
            "authority": {
                "draft_only": True,
                "requires_analyst_approval": True,
                "single_execution": True,
                "changes_splunk": False,
            },
            "created_at": created_at,
        }
        check_sha256 = self._sha256(self._canonical(contract))
        check = self.store.record_runtime_check(
            detection_id,
            snapshot["id"],
            snapshot["snapshot_sha256"],
            detection["current_sha256"],
            task.id,
            task.query_fingerprint,
            check_sha256,
            contract,
        )
        return self._runtime_view(check), False

    def assess_runtime(
        self,
        detection_id: str,
        expected_runtime_check_sha256: str,
    ) -> dict[str, Any]:
        check = self.store.runtime_check_by_sha256(
            detection_id,
            expected_runtime_check_sha256,
        )
        if check is None:
            raise DeploymentVerificationError(
                "Runtime check changed; reopen the current deployment verification"
            )
        self._validate_runtime_check(check)
        if check["assessment_sha256"]:
            return self._runtime_view(check)
        _, snapshot = self._current_snapshot(
            detection_id,
            check["deployment_snapshot_sha256"],
        )
        if snapshot["id"] != check["deployment_snapshot_id"]:
            raise DeploymentVerificationError(
                "Runtime check is not bound to the expected deployment snapshot"
            )
        task = self.detections.validations.get(check["validation_task_id"])
        if task is None:
            raise DeploymentVerificationError(
                "The linked runtime validation task is unavailable"
            )
        if task.status != "complete" or not task.artifact_id:
            raise DeploymentVerificationError(
                "Run and preserve the approved runtime validation before interpreting it"
            )
        expected = check["validation"]
        if (
            task.query_fingerprint != expected["query_fingerprint"]
            or task.spl != expected["spl"]
            or task.earliest_time != expected["earliest_time"]
            or task.latest_time != expected["latest_time"]
            or task.row_limit != expected["row_limit"]
        ):
            raise DeploymentVerificationError(
                "Runtime validation contract changed; stage a new snapshot-bound check"
            )
        if not self._at_or_after(task.completed_at, snapshot["observed_at"]):
            raise DeploymentVerificationError(
                "Runtime evidence predates its deployment snapshot"
            )
        assessment = self._runtime_assessment(
            check,
            task.result_preview,
            task.artifact_id,
            task.completed_at,
        )
        assessment_sha256 = self._sha256(self._canonical(assessment))
        recorded = self.store.record_runtime_assessment(
            check["id"],
            assessment_sha256,
            assessment,
        )
        return self._runtime_view(recorded)

    def preserve_runtime_to_case(
        self,
        detection_id: str,
        expected_assessment_sha256: str,
    ) -> dict[str, Any]:
        check = self.store.runtime_check_by_assessment(
            detection_id,
            expected_assessment_sha256,
        )
        if check is None:
            raise DeploymentVerificationError(
                "Runtime assessment changed; interpret the preserved result again"
            )
        if not check["assessment"]:
            raise DeploymentVerificationError(
                "Stored runtime assessment is invalid"
            )
        self._validate_runtime_check(check)
        if (
            self._sha256(self._canonical(check["assessment"]))
            != expected_assessment_sha256
        ):
            raise DeploymentVerificationError(
                "Stored runtime assessment is invalid"
            )
        detection, snapshot = self._current_snapshot(
            detection_id,
            check["deployment_snapshot_sha256"],
        )
        if snapshot["id"] != check["deployment_snapshot_id"]:
            raise DeploymentVerificationError(
                "Runtime assessment is not bound to the expected deployment snapshot"
            )
        if check["case_item_id"]:
            return self._runtime_view(check)
        case_id = detection.get("case_id")
        if not case_id or self.detections.cases.get(case_id) is None:
            raise DeploymentVerificationError(
                "Link the detection to a case before preserving runtime evidence"
            )
        with self._case_lock:
            latest = self.store.get_runtime_check(check["id"])
            assert latest is not None
            if latest["case_item_id"]:
                return self._runtime_view(latest)
            item = self.detections.cases.add_item(
                case_id,
                self._runtime_case_item(detection, latest),
            )
            if item is None:
                raise DeploymentVerificationError("Linked case is unavailable")
            recorded = self.store.mark_runtime_preserved(
                latest["id"],
                item.id,
            )
        return self._runtime_view(recorded)

    def preserve_to_case(
        self,
        detection_id: str,
        expected_snapshot_sha256: str,
    ) -> dict[str, Any]:
        detection = self.detections.store.get(detection_id)
        if detection is None:
            raise KeyError(f"Detection not found: {detection_id}")
        snapshot = self.store.by_sha256(
            detection_id,
            expected_snapshot_sha256,
        )
        if snapshot is None:
            raise DeploymentVerificationError(
                "Deployment verification snapshot changed; refresh before preserving"
            )
        payload = {
            key: value
            for key, value in snapshot.items()
            if key
            not in {
                "id",
                "detection_id",
                "version",
                "content_sha256",
                "snapshot_sha256",
                "case_item_id",
            }
        }
        if self._sha256(self._canonical(payload)) != expected_snapshot_sha256:
            raise DeploymentVerificationError(
                "Stored deployment verification snapshot is invalid"
            )
        subject = snapshot.get("subject") or {}
        if (
            subject.get("detection_id") != snapshot["detection_id"]
            or subject.get("version") != snapshot["version"]
            or subject.get("content_sha256") != snapshot["content_sha256"]
        ):
            raise DeploymentVerificationError(
                "Stored deployment verification identity is invalid"
            )
        if snapshot["content_sha256"] != detection["current_sha256"]:
            raise DeploymentVerificationError(
                "Deployment verification does not match the current detection version"
            )
        if snapshot["case_item_id"]:
            return self._with_runtime(snapshot)
        case_id = detection.get("case_id")
        if not case_id or self.detections.cases.get(case_id) is None:
            raise DeploymentVerificationError(
                "Link the detection to a case before preserving deployment verification"
            )
        with self._case_lock:
            latest = self.store.get(snapshot["id"])
            assert latest is not None
            if latest["case_item_id"]:
                return self._with_runtime(latest)
            item = self.detections.cases.add_item(
                case_id,
                self._case_item(detection, latest),
            )
            if item is None:
                raise DeploymentVerificationError("Linked case is unavailable")
            return self._with_runtime(
                self.store.mark_preserved(latest["id"], item.id)
            )

    def _approved_detection(
        self,
        detection_id: str,
        expected_content_sha256: str,
    ) -> dict[str, Any]:
        detection = self.detections.store.get(detection_id)
        if detection is None:
            raise KeyError(f"Detection not found: {detection_id}")
        if detection["status"] != "approved":
            raise DeploymentVerificationError(
                "Only an approved detection can be verified in Splunk"
            )
        if (
            detection["current_sha256"] != expected_content_sha256
            or detection["approved_sha256"] != expected_content_sha256
        ):
            raise DeploymentVerificationError(
                "Detection content changed; review the current approved version"
            )
        return detection

    def _snapshot(
        self,
        detection: dict[str, Any],
        target_app: str,
        rows: list[dict[str, Any]],
        collection: dict[str, Any],
    ) -> dict[str, Any]:
        content = detection["content"]
        title = self._text(content.get("title"), 240)
        name_matches = [
            row for row in rows if self._name(row).casefold() == title.casefold()
        ]
        exact_name_matches = [
            row for row in name_matches if self._name(row) == title
        ]
        candidates = exact_name_matches or name_matches
        if target_app:
            candidates = [
                row
                for row in candidates
                if self._app(row).casefold() == target_app.casefold()
            ]
        selected = candidates[0] if len(candidates) == 1 else None
        expected = self._expected_contract(content, target_app)
        controls: list[dict[str, Any]] = []
        observed: dict[str, Any] | None = None

        if selected is not None:
            observed = self._observed_contract(selected)
            controls = self._controls(expected, observed)
            failed = {
                item["id"]
                for item in controls
                if item["status"] == "fail"
            }
            disabled = observed["disabled"]
            if "search" in failed:
                status = "drifted"
                risk = "critical"
                action = (
                    "Stop promotion: the deployed SPL differs from the approved "
                    "detection. Review the exact definition through change control."
                )
            elif failed:
                status = "drifted"
                risk = "high"
                action = (
                    "The deployed schedule or dispatch window differs from the "
                    "approved contract. Reconcile the drift through change control."
                )
            elif disabled is True:
                status = "deployed-disabled"
                risk = "medium"
                action = (
                    "The exact observed definition is present but disabled. Confirm "
                    "whether enablement is intentionally pending or administratively blocked."
                )
            elif disabled is None:
                status = "inconclusive"
                risk = "high"
                action = (
                    "The definition matches, but enabled state was not returned. "
                    "Verify scheduler state with an authorized read-only control."
                )
            else:
                status = "verified"
                risk = "low"
                action = (
                    "The observed SPL, schedule, dispatch window, and enabled state "
                    "match. Continue monitoring runtime health and firing behavior."
                )
            if (
                not collection["exhaustive"]
                and not target_app
                and status in {"verified", "deployed-disabled"}
            ):
                status = "inconclusive"
                risk = "high"
                action = (
                    "A matching definition was observed, but the catalog was "
                    "truncated and no target app was supplied. Specify the app "
                    "before treating this identity as unique."
                )
        elif len(candidates) > 1:
            status = "ambiguous"
            risk = "critical"
            action = (
                "Multiple saved searches match this identity. Specify the target "
                "Splunk app and refresh before making a deployment claim."
            )
        elif name_matches and target_app:
            status = (
                "missing"
                if collection["exhaustive"]
                else "inconclusive"
            )
            risk = "high"
            action = (
                (
                    f"A same-name definition exists outside app {target_app}, but "
                    "no exact target-app deployment was observed in the complete "
                    "catalog. Confirm the intended app."
                )
                if collection["exhaustive"]
                else (
                    f"A same-name definition was returned outside app {target_app}, "
                    "but the catalog was truncated. Target-app absence remains unknown."
                )
            )
        elif collection["exhaustive"]:
            status = "missing"
            risk = "high"
            action = (
                "No matching saved search was observed in the complete returned "
                "catalog. Deploy it through the normal change process, then refresh."
            )
        else:
            status = "inconclusive"
            risk = "high"
            action = (
                "No match appeared in a truncated catalog. Absence is unknown; "
                "narrow the server-side scope or verify through an authorized adapter."
            )

        return {
            "schema_version": "signalroom-splunk-deployment/v1",
            "provider": "splunk-mcp",
            "subject": {
                "detection_id": detection["id"],
                "version": detection["current_version"],
                "content_sha256": detection["current_sha256"],
            },
            "status": status,
            "risk_level": risk,
            "recommended_action": action,
            "target": {
                "name": title,
                "app": target_app,
            },
            "expected": expected,
            "observed": observed,
            "controls": controls,
            "candidates": [
                {
                    "name": self._name(row),
                    "app": self._app(row),
                }
                for row in (
                    candidates
                    if candidates
                    else name_matches
                )[:10]
            ],
            "collection": collection,
            "unobserved_controls": [
                "enableSched scheduler flag",
                "alert actions",
                "suppression configuration",
                "runtime execution health",
                "firing and notable-event behavior",
            ],
            "runtime_identity": {
                "savedsearch_name": title,
                "attribution": "scheduler-name-only",
                "same_name_count": len(name_matches),
                "unique_name_observed": len(name_matches) == 1,
            },
            "authority": {
                "read_only_refresh": True,
                "changes_splunk": False,
                "deploys_saved_search": False,
                "enables_saved_search": False,
                "changes_repository": False,
            },
            "observed_at": datetime.now(UTC).isoformat(),
        }

    def _with_runtime(
        self,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        value = dict(snapshot)
        check = self.store.latest_runtime_check(snapshot["id"])
        value["runtime_verification"] = (
            self._runtime_view(check) if check else None
        )
        return value

    def _current_snapshot(
        self,
        detection_id: str,
        expected_snapshot_sha256: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        detection = self.detections.store.get(detection_id)
        if detection is None:
            raise KeyError(f"Detection not found: {detection_id}")
        snapshot = self.store.by_sha256(
            detection_id,
            expected_snapshot_sha256,
        )
        if snapshot is None:
            raise DeploymentVerificationError(
                "Deployment verification snapshot changed; refresh before continuing"
            )
        payload = {
            key: value
            for key, value in snapshot.items()
            if key
            not in {
                "id",
                "detection_id",
                "version",
                "content_sha256",
                "snapshot_sha256",
                "case_item_id",
            }
        }
        if self._sha256(self._canonical(payload)) != expected_snapshot_sha256:
            raise DeploymentVerificationError(
                "Stored deployment verification snapshot is invalid"
            )
        subject = snapshot.get("subject") or {}
        if (
            subject.get("detection_id") != snapshot["detection_id"]
            or subject.get("version") != snapshot["version"]
            or subject.get("content_sha256") != snapshot["content_sha256"]
        ):
            raise DeploymentVerificationError(
                "Stored deployment verification identity is invalid"
            )
        if (
            detection["status"] != "approved"
            or snapshot["content_sha256"] != detection["current_sha256"]
            or snapshot["content_sha256"] != detection["approved_sha256"]
        ):
            raise DeploymentVerificationError(
                "Deployment verification does not match the current approved detection"
            )
        return detection, snapshot

    def _expected_contract(
        self,
        content: dict[str, Any],
        target_app: str,
    ) -> dict[str, Any]:
        schedule = content["schedule"]
        value = {
            "name": self._text(content.get("title"), 240),
            "app": target_app,
            "search": self._normalize_search(content.get("search")),
            "cron_schedule": self._text(schedule.get("cron"), 160),
            "earliest_time": self._text(
                schedule.get("earliest_time"),
                80,
            ),
            "latest_time": self._text(schedule.get("latest_time"), 80),
        }
        value["definition_sha256"] = self._definition_sha256(value)
        return value

    def _observed_contract(self, row: dict[str, Any]) -> dict[str, Any]:
        value = {
            "name": self._name(row),
            "app": self._app(row),
            "search": self._normalize_search(row.get("search")),
            "cron_schedule": self._text(row.get("cron_schedule"), 160),
            "earliest_time": self._text(
                row.get("dispatch.earliest_time")
                or row.get("earliest_time"),
                80,
            ),
            "latest_time": self._text(
                row.get("dispatch.latest_time")
                or row.get("latest_time"),
                80,
            ),
            "disabled": self._optional_bool(row.get("disabled")),
        }
        value["definition_sha256"] = self._definition_sha256(value)
        return value

    @staticmethod
    def _controls(
        expected: dict[str, Any],
        observed: dict[str, Any],
    ) -> list[dict[str, Any]]:
        definitions = [
            ("name", "Saved-search name"),
            ("app", "Target app"),
            ("search", "SPL definition"),
            ("cron_schedule", "Cron schedule"),
            ("earliest_time", "Earliest dispatch bound"),
            ("latest_time", "Latest dispatch bound"),
        ]
        controls = []
        for key, label in definitions:
            if key == "app" and not expected[key]:
                status = "not-scoped"
                detail = (
                    f"Observed app: {observed[key] or 'not reported'}; no target app "
                    "was requested."
                )
            else:
                status = "pass" if expected[key] == observed[key] else "fail"
                detail = (
                    "Matches the approved contract."
                    if status == "pass"
                    else "Observed value differs from the approved contract."
                )
            controls.append(
                {
                    "id": key,
                    "label": label,
                    "status": status,
                    "detail": detail,
                }
            )
        controls.append(
            {
                "id": "enabled",
                "label": "Enabled state",
                "status": (
                    "pass"
                    if observed["disabled"] is False
                    else "warn"
                    if observed["disabled"] is True
                    else "not-observed"
                ),
                "detail": (
                    "Saved search is enabled."
                    if observed["disabled"] is False
                    else "Saved search is disabled."
                    if observed["disabled"] is True
                    else "The MCP response did not report enabled state."
                ),
            }
        )
        return controls

    def _collection(
        self,
        value: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if isinstance(value, dict) and value.get("error"):
            raise DeploymentVerificationError(
                f"Splunk MCP deployment read failed: {self._text(value['error'], 800)}"
            )
        if isinstance(value, list):
            rows = [item for item in value if isinstance(item, dict)]
            total_rows = None
            truncated = len(rows) >= self.ROW_LIMIT
        elif isinstance(value, dict):
            source = next(
                (
                    value[key]
                    for key in ("results", "items", "data")
                    if isinstance(value.get(key), list)
                ),
                [],
            )
            rows = [item for item in source if isinstance(item, dict)]
            total_rows = self._optional_int(value.get("total_rows"))
            truncated_value = self._optional_bool(value.get("truncated"))
            truncated = (
                truncated_value
                if truncated_value is not None
                else bool(
                    len(rows) >= self.ROW_LIMIT
                    or (
                        total_rows is not None
                        and total_rows > len(rows)
                    )
                )
            )
        else:
            raise DeploymentVerificationError(
                "Splunk MCP returned an invalid saved-search collection"
            )
        exhaustive = not truncated and (
            total_rows <= len(rows)
            if total_rows is not None
            else len(rows) < self.ROW_LIMIT
        )
        return rows, {
            "tool": "get_knowledge_objects",
            "object_type": "saved_searches",
            "row_limit": self.ROW_LIMIT,
            "returned": len(rows),
            "total_rows": total_rows,
            "truncated": truncated,
            "exhaustive": exhaustive,
        }

    def _runtime_view(
        self,
        check: dict[str, Any],
    ) -> dict[str, Any]:
        self._validate_runtime_check(check)
        value = dict(check)
        task = self.detections.validations.get(check["validation_task_id"])
        validation = check["validation"]
        exact_contract = bool(
            task is not None
            and task.query_fingerprint == validation["query_fingerprint"]
            and task.spl == validation["spl"]
            and task.earliest_time == validation["earliest_time"]
            and task.latest_time == validation["latest_time"]
            and task.row_limit == validation["row_limit"]
        )
        if check["assessment"]:
            assessment_sha256 = self._sha256(
                self._canonical(check["assessment"])
            )
            if assessment_sha256 != check["assessment_sha256"]:
                raise DeploymentVerificationError(
                    "Stored runtime assessment is invalid"
                )
            state = check["assessment"]["status"]
        elif task is None:
            state = "validation-missing"
        elif not exact_contract:
            state = "contract-drifted"
        elif task.status == "complete":
            state = "ready-to-interpret"
        else:
            state = task.status
        value["state"] = state
        value["validation_task"] = {
            "id": task.id if task else check["validation_task_id"],
            "status": task.status if task else "missing",
            "exact_contract": exact_contract,
            "artifact_id": task.artifact_id if task else "",
            "completed_at": task.completed_at if task else None,
            "error": task.error if task else "Validation task is unavailable",
        }
        value["ready_to_assess"] = bool(
            task
            and task.status == "complete"
            and exact_contract
            and not check["assessment_sha256"]
        )
        return value

    def _validate_runtime_check(self, check: dict[str, Any]) -> None:
        payload = {
            key: check[key]
            for key in (
                "schema_version",
                "subject",
                "identity",
                "validation",
                "policy",
                "limitations",
                "authority",
                "created_at",
            )
        }
        if self._sha256(self._canonical(payload)) != check["check_sha256"]:
            raise DeploymentVerificationError(
                "Stored runtime check contract is invalid"
            )
        subject = check["subject"]
        validation = check["validation"]
        if (
            subject.get("detection_id") != check["detection_id"]
            or subject.get("content_sha256") != check["content_sha256"]
            or subject.get("deployment_snapshot_sha256")
            != check["deployment_snapshot_sha256"]
            or validation.get("task_id") != check["validation_task_id"]
            or validation.get("query_fingerprint")
            != check["query_fingerprint"]
        ):
            raise DeploymentVerificationError(
                "Stored runtime check identity is invalid"
            )

    def _runtime_assessment(
        self,
        check: dict[str, Any],
        preview: list[Any],
        artifact_id: str,
        completed_at: str | None,
    ) -> dict[str, Any]:
        row = preview[0] if preview and isinstance(preview[0], dict) else None
        executions = self._integer(row.get("executions")) if row else None
        non_success = self._integer(row.get("non_success")) if row else None
        last_run_epoch = self._number(row.get("last_run_epoch")) if row else None
        observed_at_epoch = (
            self._number(row.get("observed_at_epoch")) if row else None
        )
        lag_seconds = self._number(row.get("lag_seconds")) if row else None
        if (
            lag_seconds is None
            and last_run_epoch is not None
            and observed_at_epoch is not None
        ):
            lag_seconds = max(0.0, observed_at_epoch - last_run_epoch)
        last_status = self._text(row.get("last_status"), 120) if row else ""
        statuses = self._status_values(row.get("statuses")) if row else []
        max_lag = int(check["policy"]["max_lag_seconds"])
        if row is None or executions is None:
            status = "inconclusive"
            risk = "high"
            action = (
                "The preserved result did not contain the required aggregate row. "
                "Inspect the artifact and stage a new exact runtime check."
            )
        elif executions <= 0:
            status = "no-executions"
            risk = "high"
            action = (
                "No scheduler execution was observed in the bounded window. Confirm "
                "scheduler eligibility, search ownership, and dispatch history."
            )
        elif last_status and last_status.casefold() != "success":
            status = "failing"
            risk = "critical"
            action = (
                f"The latest scheduler outcome was {last_status}. Inspect scheduler "
                "messages and search logs before relying on this detection."
            )
        elif non_success is not None and non_success > 0:
            status = "degraded"
            risk = "high"
            action = (
                f"{non_success} non-success scheduler outcome(s) were observed. "
                "Review failures, skipped runs, and runtime pressure."
            )
        elif lag_seconds is None:
            status = "inconclusive"
            risk = "high"
            action = (
                "Executions were observed, but last-run lag was unavailable. Inspect "
                "the preserved scheduler result before making a health claim."
            )
        elif lag_seconds > max_lag:
            status = "stale"
            risk = "high"
            action = (
                f"Last observed execution lag ({int(lag_seconds)} seconds) exceeds "
                f"the cron-derived threshold ({max_lag} seconds). Validate scheduling."
            )
        else:
            status = "healthy"
            risk = "low"
            action = (
                "Recent successful scheduler execution is observed within the "
                "derived lag threshold. Continue with firing and delivery evidence "
                "if the operational claim requires it."
            )
        return {
            "schema_version": "signalroom-splunk-runtime-assessment/v1",
            "subject": check["subject"],
            "runtime_check_sha256": check["check_sha256"],
            "validation": {
                "task_id": check["validation_task_id"],
                "query_fingerprint": check["query_fingerprint"],
                "artifact_id": artifact_id,
                "completed_at": completed_at,
            },
            "status": status,
            "risk_level": risk,
            "recommended_action": action,
            "observation": {
                "executions": executions,
                "last_run_epoch": last_run_epoch,
                "last_status": last_status,
                "statuses": statuses,
                "non_success": non_success,
                "avg_run_seconds": (
                    self._number(row.get("avg_run_seconds")) if row else None
                ),
                "max_run_seconds": (
                    self._number(row.get("max_run_seconds")) if row else None
                ),
                "observed_at_epoch": observed_at_epoch,
                "lag_seconds": lag_seconds,
            },
            "limitations": check["limitations"],
            "authority": {
                "interprets_preserved_evidence_only": True,
                "changes_splunk": False,
                "proves_alert_firing": False,
                "proves_response_delivery": False,
            },
            "assessed_at": datetime.now(UTC).isoformat(),
        }

    def _runtime_case_item(
        self,
        detection: dict[str, Any],
        check: dict[str, Any],
    ) -> CaseItemCreate:
        assessment = check["assessment"]
        assert assessment is not None
        observation = assessment["observation"]
        return CaseItemCreate(
            kind="evidence",
            title=(
                f"Splunk runtime health · {detection['content']['title']} · "
                f"{assessment['status']}"
            ),
            content=(
                f"Snapshot-bound scheduler assessment: {assessment['assessed_at']}\n\n"
                f"Deployment snapshot: {check['deployment_snapshot_sha256']}\n"
                f"Runtime check: {check['check_sha256']}\n"
                f"Validation task: {check['validation_task_id']}\n"
                f"Validation artifact: {assessment['validation']['artifact_id']}\n"
                f"Status: {assessment['status']}\n"
                f"Risk: {assessment['risk_level']}\n"
                f"Executions: {observation['executions']}\n"
                f"Last status: {observation['last_status'] or 'not observed'}\n"
                f"Last-run lag seconds: {observation['lag_seconds']}\n"
                f"Non-success outcomes: {observation['non_success']}\n"
                f"Average runtime seconds: {observation['avg_run_seconds']}\n"
                f"Maximum runtime seconds: {observation['max_run_seconds']}\n\n"
                f"Next: {assessment['recommended_action']}\n\n"
                "This assessment interprets one preserved, explicitly approved "
                "read-only scheduler query. It did not change Splunk and does not "
                "prove alert firing, notable-event creation, or response delivery."
            ),
            source="SignalRoom Splunk runtime verification",
            confidence=(
                "high"
                if assessment["status"]
                in {"healthy", "failing", "degraded", "stale", "no-executions"}
                else "medium"
            ),
            status=(
                "complete"
                if assessment["status"] == "healthy"
                else "needs-validation"
            ),
            occurred_at=assessment["assessed_at"],
            metadata={
                "detection_id": detection["id"],
                "detection_runtime_check_id": check["id"],
                "detection_runtime_check_sha256": check["check_sha256"],
                "detection_runtime_assessment_sha256": check[
                    "assessment_sha256"
                ],
                "detection_deployment_sha256": check[
                    "deployment_snapshot_sha256"
                ],
                "validation_task_id": check["validation_task_id"],
                "artifact_id": assessment["validation"]["artifact_id"],
                "runtime_status": assessment["status"],
                "risk_level": assessment["risk_level"],
            },
        )

    @classmethod
    def _runtime_policy(
        cls,
        cron: Any,
        earliest_time: str,
        max_lag_seconds: int | None,
    ) -> dict[str, Any]:
        parts = str(cron or "").strip().split()
        cadence: int | None = None
        confidence = "heuristic"
        if len(parts) == 5:
            minute, hour, day, month, weekday = parts
            if weekday != "*":
                cadence = 7 * 86400
                confidence = "cron-class"
            elif day != "*" or month != "*":
                cadence = 30 * 86400
                confidence = "cron-class"
            elif hour != "*":
                cadence = 86400
                confidence = "cron-class"
            elif minute.startswith("*/") and minute[2:].isdigit():
                cadence = max(1, int(minute[2:])) * 60
                confidence = "cron-interval"
            elif minute == "*":
                cadence = 60
                confidence = "cron-interval"
            elif minute.isdigit():
                cadence = 3600
                confidence = "cron-class"
        cadence = cadence or 86400
        window_seconds = min(30 * 86400, max(86400, cadence * 4))
        if window_seconds % 86400 == 0:
            derived_earliest = f"-{window_seconds // 86400}d"
        else:
            derived_earliest = f"-{max(1, window_seconds // 3600)}h"
        threshold = (
            int(max_lag_seconds)
            if max_lag_seconds is not None
            else min(30 * 86400, max(900, cadence * 3))
        )
        return {
            "earliest_time": earliest_time.strip() or derived_earliest,
            "latest_time": "now",
            "max_lag_seconds": threshold,
            "expected_cadence_seconds": cadence,
            "derivation": confidence,
            "cron_schedule": str(cron or "").strip(),
        }

    @staticmethod
    def _runtime_spl(saved_search_name: str) -> str:
        escaped = saved_search_name.replace("\\", "\\\\").replace('"', '\\"')
        return (
            "search index=_internal source=*scheduler.log* "
            f'savedsearch_name="{escaped}" '
            "| stats count as executions latest(_time) as last_run_epoch "
            "latest(status) as last_status values(status) as statuses "
            "avg(run_time) as avg_run_seconds max(run_time) as max_run_seconds "
            'count(eval(lower(status)!="success")) as non_success '
            "| eval observed_at_epoch=now(), "
            "lag_seconds=if(isnull(last_run_epoch),null(),"
            "observed_at_epoch-last_run_epoch), "
            "avg_run_seconds=round(avg_run_seconds,2), "
            "max_run_seconds=round(max_run_seconds,2) "
            "| fields executions last_run_epoch last_status statuses "
            "avg_run_seconds max_run_seconds non_success observed_at_epoch "
            "lag_seconds"
        )

    @staticmethod
    def _at_or_after(value: str | None, reference: str) -> bool:
        if not value:
            return False
        try:
            return datetime.fromisoformat(value) >= datetime.fromisoformat(reference)
        except ValueError:
            return False

    @staticmethod
    def _number(value: Any) -> float | None:
        if value is None or str(value).strip() == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _integer(cls, value: Any) -> int | None:
        number = cls._number(value)
        return int(number) if number is not None else None

    @staticmethod
    def _status_values(value: Any) -> list[str]:
        if isinstance(value, list):
            return sorted(
                {
                    str(item).strip()[:120]
                    for item in value
                    if str(item).strip()
                }
            )
        text = str(value or "").strip()
        return [text[:120]] if text else []

    def _case_item(
        self,
        detection: dict[str, Any],
        snapshot: dict[str, Any],
    ) -> CaseItemCreate:
        observed = snapshot.get("observed") or {}
        target = snapshot["target"]
        enabled = (
            "yes"
            if observed.get("disabled") is False
            else "no"
            if observed.get("disabled") is True
            else "not observed"
        )
        return CaseItemCreate(
            kind=(
                "decision"
                if snapshot["status"] == "verified"
                else "action"
            ),
            title=(
                f"Splunk deployment verification · "
                f"{detection['content']['title']} · "
                f"{snapshot['status']}"
            ),
            content=(
                f"Explicit read-only Splunk observation: {snapshot['observed_at']}\n\n"
                f"Target saved search: {target['name']}\n"
                f"Target app: {target['app'] or 'not scoped'}\n"
                f"Observed app: {observed.get('app') or 'not observed'}\n"
                f"Status: {snapshot['status']}\n"
                f"Risk: {snapshot['risk_level']}\n"
                f"Enabled: {enabled}\n"
                f"Catalog exhaustive: {snapshot['collection']['exhaustive']}\n\n"
                f"Next: {snapshot['recommended_action']}\n\n"
                "This snapshot is a read-only definition comparison. It did not "
                "deploy, enable, schedule, or otherwise change Splunk, and it does "
                "not prove runtime execution or alert firing."
            ),
            source="SignalRoom Splunk deployment verification",
            confidence=(
                "high"
                if snapshot["status"]
                in {"verified", "drifted", "deployed-disabled"}
                else "medium"
            ),
            status=(
                "complete"
                if snapshot["status"] == "verified"
                else "needs-validation"
            ),
            occurred_at=snapshot["observed_at"],
            metadata={
                "detection_id": detection["id"],
                "detection_deployment_snapshot_id": snapshot["id"],
                "detection_deployment_sha256": snapshot["snapshot_sha256"],
                "content_sha256": snapshot["content_sha256"],
                "deployment_status": snapshot["status"],
                "risk_level": snapshot["risk_level"],
                "target_app": target["app"],
            },
        )

    @staticmethod
    def _name(row: dict[str, Any]) -> str:
        return DetectionDeploymentService._text(
            row.get("name") or row.get("title"),
            240,
        )

    @staticmethod
    def _app(row: dict[str, Any]) -> str:
        return DetectionDeploymentService._text(
            row.get("app") or row.get("eai:acl.app"),
            160,
        )

    @staticmethod
    def _normalize_search(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()[:100_000]

    @classmethod
    def _definition_sha256(cls, value: dict[str, Any]) -> str:
        contract = {
            key: value.get(key, "")
            for key in (
                "name",
                "search",
                "cron_schedule",
                "earliest_time",
                "latest_time",
            )
        }
        return cls._sha256(cls._canonical(contract))

    @staticmethod
    def _text(value: Any, limit: int) -> str:
        return str(value or "").strip()[:limit]

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value or "").strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return None

    @staticmethod
    def _optional_int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _canonical(value: dict[str, Any]) -> str:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()
