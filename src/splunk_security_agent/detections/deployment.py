from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from ..config import ConfigStore
from ..schemas import CaseItemCreate
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
        return self.store.latest(detection_id, content_sha256)

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
            return snapshot
        case_id = detection.get("case_id")
        if not case_id or self.detections.cases.get(case_id) is None:
            raise DeploymentVerificationError(
                "Link the detection to a case before preserving deployment verification"
            )
        with self._case_lock:
            latest = self.store.get(snapshot["id"])
            assert latest is not None
            if latest["case_item_id"]:
                return latest
            item = self.detections.cases.add_item(
                case_id,
                self._case_item(detection, latest),
            )
            if item is None:
                raise DeploymentVerificationError("Linked case is unavailable")
            return self.store.mark_preserved(latest["id"], item.id)

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
            "authority": {
                "read_only_refresh": True,
                "changes_splunk": False,
                "deploys_saved_search": False,
                "enables_saved_search": False,
                "changes_repository": False,
            },
            "observed_at": datetime.now(UTC).isoformat(),
        }

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
