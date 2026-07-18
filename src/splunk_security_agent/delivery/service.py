from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ..audit import AuditStore
from ..config import ConfigStore
from ..schemas import DeliveryPolicyUpdate
from .store import DeliveryStore

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
SLACK_DESTINATION = "slack-incoming-webhook"
JIRA_DESTINATION = "jira-cloud"
GENERIC_DESTINATION = "generic-webhook"
SLACK_WEBHOOK_HOSTS = {"hooks.slack.com", "hooks.slack-gov.com"}
JIRA_PROJECT_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
JIRA_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
JIRA_ISSUE_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,31}-[1-9][0-9]*$")
DELIVERY_SEVERITIES = {"critical", "high", "medium", "low"}


class AssuranceDeliveryService:
    """Policy-bound, redacted outbound response-package delivery."""

    def __init__(
        self,
        store: DeliveryStore,
        assurance_store: Any,
        config: ConfigStore,
        audit: AuditStore,
        *,
        poll_seconds: float = 2.0,
        client_factory: Callable[..., Any] | None = None,
    ):
        self.store = store
        self.assurance_store = assurance_store
        self.config = config
        self.audit = audit
        self.poll_seconds = poll_seconds
        self.client_factory = client_factory or httpx.AsyncClient
        self._worker: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._stopping = False

    async def start(self) -> None:
        if self._worker and not self._worker.done():
            return
        self._stopping = False
        recovered = self.store.recover_interrupted()
        recovered_count = sum(recovered.values())
        if recovered_count:
            self.audit.record(
                "delivery.recovered",
                "recover",
                target_type="delivery-worker",
                outcome="warning" if recovered["uncertain"] else "ok",
                summary=(
                    f"Recovered {recovered_count} interrupted delivery job(s): "
                    f"{recovered['retrying']} queued for retry, "
                    f"{recovered['correlated']} completed from durable correlation, and "
                    f"{recovered['uncertain']} stopped for analyst review."
                ),
                metadata=recovered,
            )
        self._worker = asyncio.create_task(self._work_loop(), name="signalroom-delivery")

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._worker and not self._worker.done():
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
        self._worker = None

    def overview(self) -> dict[str, Any]:
        policy = self.store.policy()
        url = self.config.secret("delivery_webhook_url")
        destination_kind = policy["destination_kind"]
        is_slack = destination_kind == SLACK_DESTINATION
        is_jira = destination_kind == JIRA_DESTINATION
        jira_email = self.config.secret("delivery_jira_email")
        jira_token = self.config.secret("delivery_jira_api_token")
        configured = bool(url)
        if is_jira:
            configured = bool(
                url and jira_email and jira_token and policy["jira_project_key"]
            )
        return {
            "policy": policy,
            "destination": {
                "kind": destination_kind,
                "configured": configured,
                "url_configured": bool(url),
                "origin": self._origin(url) if url else "",
                "authorization_configured": bool(
                    self.config.secret("delivery_authorization")
                ),
                "authorization_supported": not (is_slack or is_jira),
                "jira_email_configured": bool(jira_email),
                "jira_api_token_configured": bool(jira_token),
                "transport": (
                    "verified TLS"
                    if policy["verify_tls"]
                    else "encrypted without certificate verification"
                ),
                "delivery_semantics": (
                    "notification-only · local deduplication · at-least-once delivery"
                    if is_slack
                    else (
                        "create-only issue · durable key correlation · analyst-reviewed retry"
                        if is_jira
                        else "exact JSON · destination idempotency key · bounded retries"
                    )
                ),
            },
            "jobs": self.store.jobs(),
            "worker": {
                "online": bool(self._worker and not self._worker.done()),
                "restart_recovery": (
                    "bounded-at-least-once-retry"
                    if is_slack
                    else (
                        "analyst-reviewed-retry"
                        if is_jira
                        else "idempotent-retry"
                    )
                ),
                "external_authority": "create-issue-only" if is_jira else "notification-only",
                "splunk_authority": "none",
            },
        }

    async def test_destination(self) -> dict[str, Any]:
        policy = self.store.policy()
        if policy["destination_kind"] != JIRA_DESTINATION:
            raise ValueError(
                "Read-only destination testing is currently available for Jira Cloud"
            )
        site_url = self.config.secret("delivery_webhook_url")
        if not site_url:
            raise ValueError("Save the Jira Cloud site URL before testing")
        self._validate_destination_url(JIRA_DESTINATION, site_url)
        self._validate_jira_policy(
            policy,
            email=self.config.secret("delivery_jira_email"),
            api_token=self.config.secret("delivery_jira_api_token"),
            require_credentials=True,
        )
        project_key = policy["jira_project_key"]
        issue_type = policy["jira_issue_type"]
        endpoint = (
            f"{site_url.rstrip('/')}/rest/api/3/issue/createmeta/"
            f"{quote(project_key, safe='')}/issuetypes"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": self._jira_authorization(),
            "User-Agent": "SignalRoom/0.1 outbound-assurance",
        }
        try:
            async with self.client_factory(
                timeout=httpx.Timeout(15),
                verify=True,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(endpoint, headers=headers)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise ValueError(
                f"Jira destination test failed ({type(exc).__name__})"
            ) from exc
        status = int(response.status_code)
        if status != 200:
            raise ValueError(f"Jira destination test returned HTTP {status}")
        try:
            value = response.json()
        except (TypeError, ValueError) as exc:
            raise ValueError("Jira destination test returned invalid JSON") from exc
        issue_types = value.get("issueTypes") if isinstance(value, dict) else None
        if not isinstance(issue_types, list):
            raise ValueError("Jira destination test did not return issue-type metadata")
        available = sorted(
            {
                str(item.get("name") or "")[:120]
                for item in issue_types
                if isinstance(item, dict) and item.get("name")
            }
        )[:30]
        matched = issue_type.casefold() in {
            candidate.casefold() for candidate in available
        }
        result = {
            "ok": matched,
            "adapter": JIRA_DESTINATION,
            "origin": self._origin(site_url),
            "project_key": project_key,
            "issue_type": issue_type,
            "issue_type_available": matched,
            "available_issue_types": available,
            "authority": "read-create-metadata-only",
        }
        self.audit.record(
            "delivery.destination.tested",
            "test",
            target_type="delivery-policy",
            target_id="primary",
            outcome="ok" if matched else "warning",
            summary=(
                f"Verified Jira project {project_key} and issue type {issue_type}."
                if matched
                else f"Jira project {project_key} is reachable, but issue type "
                f"{issue_type} is not available."
            ),
            metadata={
                "destination_kind": JIRA_DESTINATION,
                "destination_origin": self._origin(site_url),
                "project_key": project_key,
                "issue_type": issue_type,
                "available_issue_types": available,
            },
        )
        return result

    def update_policy(self, value: DeliveryPolicyUpdate) -> dict[str, Any]:
        previous_policy = self.store.policy()
        previous_fingerprint = self._destination_fingerprint()
        if value.webhook_url and value.clear_webhook_url:
            raise ValueError("Choose either a replacement webhook URL or removal, not both")
        if value.authorization_header and value.clear_authorization_header:
            raise ValueError(
                "Choose either a replacement authorization header or removal, not both"
            )
        if value.jira_email and value.clear_jira_email:
            raise ValueError(
                "Choose either a replacement Jira account email or removal, not both"
            )
        if value.jira_api_token and value.clear_jira_api_token:
            raise ValueError(
                "Choose either a replacement Jira API token or removal, not both"
            )
        if value.clear_webhook_url and self.config.secret_is_environment_managed(
            "delivery_webhook_url"
        ):
            raise ValueError(
                "The webhook URL is environment-managed; remove SIGNALROOM_WEBHOOK_URL "
                "and restart SignalRoom"
            )
        if value.clear_authorization_header and self.config.secret_is_environment_managed(
            "delivery_authorization"
        ):
            raise ValueError(
                "The authorization header is environment-managed; remove "
                "SIGNALROOM_WEBHOOK_AUTHORIZATION and restart SignalRoom"
            )
        if value.clear_jira_email and self.config.secret_is_environment_managed(
            "delivery_jira_email"
        ):
            raise ValueError(
                "The Jira account email is environment-managed; remove "
                "SIGNALROOM_JIRA_EMAIL and restart SignalRoom"
            )
        if value.clear_jira_api_token and self.config.secret_is_environment_managed(
            "delivery_jira_api_token"
        ):
            raise ValueError(
                "The Jira API token is environment-managed; remove "
                "SIGNALROOM_JIRA_API_TOKEN and restart SignalRoom"
            )
        current_url = self.config.secret("delivery_webhook_url")
        candidate_url = (
            value.webhook_url.strip()
            if value.webhook_url
            else ("" if value.clear_webhook_url else current_url)
        )
        candidate_authorization = (
            value.authorization_header.strip()
            if value.authorization_header
            else (
                ""
                if value.clear_authorization_header
                else self.config.secret("delivery_authorization")
            )
        )
        candidate_jira_email = (
            value.jira_email.strip()
            if value.jira_email
            else (
                ""
                if value.clear_jira_email
                else self.config.secret("delivery_jira_email")
            )
        )
        candidate_jira_token = (
            value.jira_api_token.strip()
            if value.jira_api_token
            else (
                ""
                if value.clear_jira_api_token
                else self.config.secret("delivery_jira_api_token")
            )
        )
        if (
            value.destination_kind != previous_policy["destination_kind"]
            and current_url
            and not value.webhook_url
            and not value.clear_webhook_url
        ):
            raise ValueError(
                "Enter a new destination URL or remove the saved URL when changing adapters"
            )
        if candidate_url:
            self._validate_destination_url(value.destination_kind, candidate_url)
        if "\r" in candidate_authorization or "\n" in candidate_authorization:
            raise ValueError("The authorization header must contain exactly one header value")
        if value.destination_kind == SLACK_DESTINATION and value.authorization_header:
            raise ValueError("Slack Incoming Webhooks do not use SignalRoom's generic authorization header")
        if value.destination_kind == JIRA_DESTINATION and value.authorization_header:
            raise ValueError(
                "Jira Cloud uses its dedicated account email and API token fields"
            )
        if value.destination_kind in {SLACK_DESTINATION, JIRA_DESTINATION} and not value.verify_tls:
            destination_name = (
                "Jira Cloud"
                if value.destination_kind == JIRA_DESTINATION
                else "Slack Incoming Webhooks"
            )
            raise ValueError(
                f"{destination_name} destinations require TLS certificate verification"
            )
        if (
            value.destination_kind in {SLACK_DESTINATION, JIRA_DESTINATION}
            and value.ca_bundle
        ):
            raise ValueError(
                "Public Slack and Jira Cloud destinations do not accept a private CA override"
            )
        if value.destination_kind == JIRA_DESTINATION:
            self._validate_jira_policy(
                value,
                email=candidate_jira_email,
                api_token=candidate_jira_token,
                require_credentials=value.enabled,
            )
        if value.enabled and not candidate_url:
            raise ValueError("A destination URL is required before outbound delivery can be enabled")
        if value.ca_bundle and value.verify_tls:
            path = Path(value.ca_bundle).expanduser()
            if not path.is_file():
                raise ValueError("The outbound private CA bundle path does not exist")
        if value.webhook_url:
            self.config.update_secrets(delivery_webhook_url=value.webhook_url.strip())
        if value.authorization_header:
            self.config.update_secrets(
                delivery_authorization=value.authorization_header.strip()
            )
        if value.jira_email:
            self.config.update_secrets(delivery_jira_email=value.jira_email.strip())
        if value.jira_api_token:
            self.config.update_secrets(
                delivery_jira_api_token=value.jira_api_token.strip()
            )
        if value.clear_webhook_url:
            self.config.delete_secrets("delivery_webhook_url")
        if value.clear_authorization_header:
            self.config.delete_secrets("delivery_authorization")
        if value.clear_jira_email:
            self.config.delete_secrets("delivery_jira_email")
        if value.clear_jira_api_token:
            self.config.delete_secrets("delivery_jira_api_token")
        policy = self.store.update_policy(value)
        destination_changed = previous_fingerprint != self._destination_fingerprint()
        cancelled = 0
        if not policy["enabled"]:
            cancelled = self.store.cancel_pending("Outbound delivery was disabled by the local operator.")
        elif destination_changed:
            cancelled = self.store.cancel_pending(
                "The destination adapter or transport changed; a fresh payload preview is required."
            )
        self.audit.record(
            "delivery.policy.updated",
            "update",
            target_type="delivery-policy",
            target_id="primary",
            summary=(
                f"Outbound delivery {'enabled' if policy['enabled'] else 'disabled'} "
                f"in {policy['mode']} mode."
            ),
            metadata={
                "enabled": policy["enabled"],
                "mode": policy["mode"],
                "minimum_severity": policy["minimum_severity"],
                "signal_kinds": policy["signal_kinds"],
                "redaction_level": policy["redaction_level"],
                "destination_kind": policy["destination_kind"],
                "destination_label": policy["destination_label"],
                "jira_project_key": (
                    policy["jira_project_key"]
                    if policy["destination_kind"] == JIRA_DESTINATION
                    else ""
                ),
                "jira_credentials_configured": bool(
                    candidate_jira_email and candidate_jira_token
                ),
                "destination_origin": self._origin(candidate_url) if candidate_url else "",
                "verify_tls": policy["verify_tls"],
                "max_attempts": policy["max_attempts"],
                "cancelled_pending_jobs": cancelled,
            },
        )
        self._wake.set()
        return self.overview()

    def preview(self, package_id: str) -> dict[str, Any]:
        prepared = self._prepare(package_id)
        self.audit.record(
            "delivery.preview.generated",
            "preview",
            target_type="assurance-package",
            target_id=package_id,
            summary="Generated an analyst-visible redacted outbound payload preview.",
            metadata={
                "payload_sha256": prepared["payload_sha256"],
                "destination_origin": prepared["destination"]["origin"],
                "redaction_level": prepared["redaction_level"],
                "payload_bytes": prepared["payload_bytes"],
            },
        )
        return prepared

    def approve(
        self, package_id: str, expected_payload_sha256: str, *, automatic: bool = False
    ) -> dict[str, Any]:
        prepared = self._prepare(package_id)
        if prepared["payload_sha256"] != expected_payload_sha256:
            self.audit.record(
                "delivery.approval.rejected",
                "approve",
                target_type="assurance-package",
                target_id=package_id,
                outcome="blocked",
                summary="Outbound approval was rejected because the payload changed after preview.",
                metadata={
                    "expected_payload_sha256": expected_payload_sha256,
                    "current_payload_sha256": prepared["payload_sha256"],
                },
            )
            raise ValueError("The outbound payload changed; inspect a fresh preview before approval")
        policy = self.store.policy()
        approval_mode = "automatic-policy" if automatic else "analyst"
        job = self.store.approve(
            package_id=package_id,
            approval_mode=approval_mode,
            destination_kind=policy["destination_kind"],
            destination_label=policy["destination_label"],
            destination_fingerprint=prepared["destination_fingerprint"],
            payload=prepared["payload"],
            payload_sha256=prepared["payload_sha256"],
            idempotency_key=prepared["idempotency_key"],
            max_attempts=policy["max_attempts"],
        )
        self.audit.record(
            "delivery.approved",
            "approve",
            target_type="delivery-job",
            target_id=job["id"],
            summary=(
                f"{'Automatic policy' if automatic else 'Local analyst'} approved the exact "
                "redacted payload for delivery."
            ),
            metadata={
                "package_id": package_id,
                "approval_mode": approval_mode,
                "payload_sha256": job["payload_sha256"],
                "idempotency_key": job["idempotency_key"],
                "destination_fingerprint": job["destination_fingerprint"],
            },
            actor="delivery-policy" if automatic else "local-operator",
        )
        self._wake.set()
        return job

    def consider_package(self, package: dict[str, Any]) -> dict[str, Any] | None:
        policy = self.store.policy()
        if not policy["enabled"] or policy["mode"] != "automatic":
            return None
        try:
            prepared = self._prepare(package["id"])
            return self.approve(
                package["id"], prepared["payload_sha256"], automatic=True
            )
        except ValueError as exc:
            self.audit.record(
                "delivery.automatic.skipped",
                "evaluate",
                target_type="assurance-package",
                target_id=str(package.get("id") or ""),
                outcome="skipped",
                summary=str(exc),
            )
            return None

    def retry(self, job_id: str) -> dict[str, Any]:
        policy = self.store.policy()
        if not policy["enabled"]:
            raise ValueError("Outbound delivery must be enabled before a failed job can be retried")
        current = self.store.get(job_id)
        if current is None:
            raise KeyError(job_id)
        if self._destination_fingerprint() != current["destination_fingerprint"]:
            raise ValueError(
                "The destination changed after approval; create and approve a fresh preview"
            )
        is_jira = current["destination_kind"] == JIRA_DESTINATION
        additional_attempts = 1 if is_jira else policy["max_attempts"]
        job = self.store.retry(job_id, additional_attempts)
        if job is None:
            raise ValueError("Only a failed delivery can be explicitly retried")
        self.audit.record(
            "delivery.retry.requested",
            "retry",
            target_type="delivery-job",
            target_id=job_id,
            summary=(
                "Queued one analyst-requested Jira create attempt."
                if is_jira
                else f"Queued up to {additional_attempts} additional bounded attempt(s)."
            ),
            metadata={
                "attempt_count": job["attempt_count"],
                "max_attempts": job["max_attempts"],
                "destination_kind": current["destination_kind"],
            },
        )
        self._wake.set()
        return job

    def cancel(self, job_id: str) -> dict[str, Any]:
        current = self.store.get(job_id)
        if current is None:
            raise KeyError(job_id)
        job = self.store.cancel(job_id)
        if job is None:
            raise ValueError("Only queued, retrying, or failed delivery work can be cancelled")
        self.audit.record(
            "delivery.cancelled",
            "cancel",
            target_type="delivery-job",
            target_id=job_id,
            outcome="cancelled",
            summary="Outbound delivery was cancelled by the local operator.",
        )
        return job

    def package_closed(self, package_id: str) -> None:
        count = self.store.cancel_package(
            package_id, "The assurance response package was closed before delivery."
        )
        if count:
            self.audit.record(
                "delivery.cancelled",
                "cancel-package",
                target_type="assurance-package",
                target_id=package_id,
                outcome="cancelled",
                summary=f"Cancelled {count} pending delivery job(s) when the package closed.",
            )

    def _prepare(self, package_id: str) -> dict[str, Any]:
        policy = self.store.policy()
        if not policy["enabled"]:
            raise ValueError("Outbound delivery is disabled")
        url = self.config.secret("delivery_webhook_url")
        if not url:
            raise ValueError("The webhook destination is not configured")
        destination_kind = policy["destination_kind"]
        self._validate_destination_url(destination_kind, url)
        if destination_kind in {SLACK_DESTINATION, JIRA_DESTINATION} and not policy["verify_tls"]:
            destination_name = (
                "Jira Cloud"
                if destination_kind == JIRA_DESTINATION
                else "Slack Incoming Webhooks"
            )
            raise ValueError(
                f"{destination_name} destinations require TLS certificate verification"
            )
        if destination_kind == JIRA_DESTINATION:
            self._validate_jira_policy(
                policy,
                email=self.config.secret("delivery_jira_email"),
                api_token=self.config.secret("delivery_jira_api_token"),
                require_credentials=True,
            )
        package = self.assurance_store.get_package(package_id)
        if package is None:
            raise KeyError(package_id)
        if package["status"] != "review":
            raise ValueError("Only an active review package can be delivered")
        if datetime.fromisoformat(package["expires_at"]) <= datetime.now(UTC):
            raise ValueError("The response package has expired")
        if SEVERITY_RANK.get(package["severity"], 0) < SEVERITY_RANK.get(
            policy["minimum_severity"], 0
        ):
            raise ValueError(
                f"Package severity is below the destination's {policy['minimum_severity']} threshold"
            )
        allowed = set(policy["signal_kinds"])
        matched = [item for item in package.get("signals", []) if item.get("kind") in allowed]
        if not matched:
            raise ValueError("No package signals match the destination category policy")
        destination_fingerprint = self._destination_fingerprint()
        correlation_id = (
            hashlib.sha256(
                f"signalroom:jira:{package_id}:{destination_fingerprint}:"
                f"{policy['redaction_level']}".encode()
            ).hexdigest()
            if destination_kind == JIRA_DESTINATION
            else ""
        )
        payload = self._payload(
            package,
            matched,
            policy["redaction_level"],
            destination_kind,
            policy=policy,
            correlation_id=correlation_id,
        )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        payload_sha256 = hashlib.sha256(canonical.encode()).hexdigest()
        idempotency_key = hashlib.sha256(
            f"{package_id}:{payload_sha256}:{destination_fingerprint}".encode()
        ).hexdigest()
        redactions = [
            "Splunk endpoint and credentials",
            "raw event results",
            "SPL and validation task identifiers",
            "signal fingerprints and discovery run identifiers",
        ]
        if policy["redaction_level"] == "strict":
            redactions.append("package and signal titles, summaries, subjects, and details")
        else:
            redactions.append("signal details; bounded titles and subjects remain")
        is_slack = destination_kind == SLACK_DESTINATION
        is_jira = destination_kind == JIRA_DESTINATION
        warnings = (
            [
                "Slack Incoming Webhooks cannot delete a posted message.",
                "Slack Incoming Webhooks do not document a destination idempotency key; "
                "an ambiguous retry can create a duplicate notification.",
                "The destination channel, sender name, and icon come from the Slack app configuration.",
            ]
            if is_slack
            else (
                [
                    "This authority creates one Jira issue only; it cannot update, transition, "
                    "comment on, assign, attach to, or delete an issue.",
                    "A transport failure can leave the create outcome unknown. Automatic retries "
                    "stop so an analyst can inspect Jira for the correlation label first.",
                    "Jira project permissions and create-screen field requirements remain the "
                    "external enforcement boundary.",
                ]
                if is_jira
                else [
                    "The receiving service must honor the idempotency key to prevent duplicates "
                    "after an ambiguous response."
                ]
            )
        )
        return {
            "package_id": package_id,
            "payload": payload,
            "payload_sha256": payload_sha256,
            "payload_bytes": len(canonical.encode()),
            "idempotency_key": idempotency_key,
            "destination_fingerprint": destination_fingerprint,
            "destination": {
                "kind": destination_kind,
                "label": policy["destination_label"],
                "origin": self._origin(url),
                "verify_tls": policy["verify_tls"],
                "delivery_semantics": (
                    "notification-only · local deduplication · at-least-once delivery"
                    if is_slack
                    else (
                        "create-only issue · durable key correlation · analyst-reviewed retry"
                        if is_jira
                        else "exact JSON · destination idempotency key · bounded retries"
                    )
                ),
            },
            "redaction_level": policy["redaction_level"],
            "redactions": redactions,
            "warnings": warnings,
            "authority": {
                "delivery_only": True,
                "external_create": is_jira,
                "external_update": False,
                "external_delete": False,
                "splunk_execution": False,
                "validation_approval": False,
            },
            "correlation_id": correlation_id or None,
            "approval_required": policy["mode"] == "manual",
        }

    @classmethod
    def _payload(
        cls,
        package: dict[str, Any],
        signals: list[dict[str, Any]],
        redaction_level: str,
        destination_kind: str = GENERIC_DESTINATION,
        *,
        policy: dict[str, Any] | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for signal in signals:
            kind = str(signal.get("kind") or "unknown")
            severity = str(signal.get("severity") or "medium")
            by_kind[kind] = by_kind.get(kind, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        signal_summary = {
            "matched": len(signals),
            "by_kind": dict(sorted(by_kind.items())),
            "by_severity": dict(sorted(by_severity.items())),
        }
        if destination_kind == SLACK_DESTINATION:
            return cls._slack_payload(package, signals, redaction_level, signal_summary)
        if destination_kind == JIRA_DESTINATION:
            assert policy is not None and correlation_id
            return cls._jira_payload(
                package,
                signals,
                redaction_level,
                signal_summary,
                policy,
                correlation_id,
            )
        payload: dict[str, Any] = {
            "schema": "signalroom.assurance-response.v1",
            "event": "assurance.response-package",
            "package": {
                "id": package["id"],
                "severity": package["severity"],
                "status": package["status"],
                "created_at": package["created_at"],
                "expires_at": package["expires_at"],
            },
            "signal_summary": signal_summary,
            "authority": {
                "delivery_only": True,
                "splunk_execution": False,
                "validation_approval": False,
            },
        }
        if redaction_level == "standard":
            payload["package"]["title"] = str(package.get("title") or "")[:240]
            payload["package"]["summary"] = str(package.get("summary") or "")[:1000]
            payload["signals"] = [
                {
                    "kind": item.get("kind"),
                    "severity": item.get("severity"),
                    "title": str(item.get("title") or "")[:240],
                    "subject": str(item.get("subject") or "")[:240],
                    "status": item.get("status"),
                    "occurrences": int(item.get("occurrence_count") or 0),
                }
                for item in signals[:12]
            ]
        return payload

    @classmethod
    def _slack_payload(
        cls,
        package: dict[str, Any],
        signals: list[dict[str, Any]],
        redaction_level: str,
        signal_summary: dict[str, Any],
    ) -> dict[str, Any]:
        severity = str(package.get("severity") or "unknown").upper()
        matched = int(signal_summary["matched"])
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": cls._plain_text(f"SignalRoom assurance response · {severity}", 150),
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "plain_text",
                        "text": cls._plain_text(f"Matched signals\n{matched}", 300),
                    },
                    {
                        "type": "plain_text",
                        "text": cls._plain_text(f"Severity\n{severity.title()}", 300),
                    },
                    {
                        "type": "plain_text",
                        "text": cls._plain_text(f"Package\n{package.get('id') or 'Unavailable'}", 300),
                    },
                    {
                        "type": "plain_text",
                        "text": cls._plain_text(
                            f"Expires\n{package.get('expires_at') or 'Unavailable'}",
                            300,
                        ),
                    },
                ],
            },
        ]
        if redaction_level == "standard":
            blocks.extend(
                [
                    {
                        "type": "section",
                        "text": {
                            "type": "plain_text",
                            "text": cls._plain_text(
                                f"{package.get('title') or 'Assurance response'}\n"
                                f"{package.get('summary') or ''}",
                                1800,
                            ),
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "plain_text",
                            "text": cls._plain_text(
                                "Signals\n"
                                + "\n".join(
                                    f"• {item.get('severity') or 'medium'} · "
                                    f"{item.get('kind') or 'unknown'} · "
                                    f"{item.get('title') or 'Untitled'}"
                                    for item in signals[:8]
                                ),
                                2200,
                            ),
                        },
                    },
                ]
            )
        else:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "plain_text",
                        "text": (
                            "Strict redaction is active. Source-derived titles, summaries, "
                            "subjects, and details are withheld."
                        ),
                    },
                }
            )
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "plain_text",
                        "text": ("Notification only · no Splunk execution or validation approval authority"),
                    }
                ],
            }
        )
        return {
            "text": (
                f"SignalRoom assurance response · {severity} · {matched} matched "
                f"signal{'s' if matched != 1 else ''}"
            ),
            "blocks": blocks,
        }

    @classmethod
    def _jira_payload(
        cls,
        package: dict[str, Any],
        signals: list[dict[str, Any]],
        redaction_level: str,
        signal_summary: dict[str, Any],
        policy: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, Any]:
        severity = str(package.get("severity") or "medium").lower()
        matched = int(signal_summary["matched"])
        prefix = cls._one_line(policy.get("jira_summary_prefix") or "", 80)
        if redaction_level == "standard":
            summary_body = (
                f"[{severity.upper()}] "
                f"{cls._one_line(package.get('title') or 'Assurance response', 180)}"
            )
        else:
            summary_body = (
                f"[{severity.upper()}] Assurance response "
                f"({matched} matched signal{'s' if matched != 1 else ''})"
            )
        summary = cls._one_line(f"{prefix} {summary_body}".strip(), 255)
        correlation_label = f"signalroom-{correlation_id[:16]}"
        labels = list(dict.fromkeys([*policy.get("jira_labels", []), correlation_label]))
        categories = ", ".join(
            f"{kind} ({count})"
            for kind, count in signal_summary["by_kind"].items()
        )
        description_content: list[dict[str, Any]] = [
            cls._adf_paragraph("SignalRoom assurance response"),
            cls._adf_paragraph(f"Severity: {severity.title()}"),
            cls._adf_paragraph(f"Matched signals: {matched}"),
            cls._adf_paragraph(f"Signal categories: {categories or 'Unavailable'}"),
            cls._adf_paragraph(f"Package: {package.get('id') or 'Unavailable'}"),
            cls._adf_paragraph(f"Expires: {package.get('expires_at') or 'Unavailable'}"),
            cls._adf_paragraph(f"Correlation label: {correlation_label}"),
        ]
        if redaction_level == "standard":
            description_content.extend(
                [
                    cls._adf_paragraph(
                        f"Summary: {cls._plain_text(package.get('summary') or '', 1000)}"
                    ),
                    cls._adf_bullet_list(
                        [
                            cls._one_line(
                                f"{item.get('severity') or 'medium'} · "
                                f"{item.get('kind') or 'unknown'} · "
                                f"{item.get('title') or 'Untitled'} · "
                                f"{item.get('subject') or 'No subject'}",
                                480,
                            )
                            for item in signals[:10]
                        ]
                    ),
                ]
            )
        else:
            description_content.append(
                cls._adf_paragraph(
                    "Strict redaction withheld source-derived package and signal text."
                )
            )
        description_content.append(
            cls._adf_paragraph(
                "Authority: create this issue only. SignalRoom did not approve or "
                "execute SPL and cannot update, transition, comment on, assign, attach "
                "to, or delete this issue."
            )
        )
        fields: dict[str, Any] = {
            "project": {"key": policy["jira_project_key"]},
            "issuetype": {"name": policy["jira_issue_type"]},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": description_content,
            },
            "labels": labels,
        }
        priority = str(policy.get("jira_priority_map", {}).get(severity) or "").strip()
        if priority:
            fields["priority"] = {"name": priority}
        return {
            "fields": fields,
            "properties": [
                {
                    "key": "signalroom.delivery",
                    "value": {
                        "correlation_id": correlation_id,
                        "package_id": package["id"],
                        "contract": "create-issue-only",
                        "splunk_execution": False,
                        "validation_approval": False,
                    },
                }
            ],
        }

    @staticmethod
    def _adf_paragraph(text: str) -> dict[str, Any]:
        return {
            "type": "paragraph",
            "content": [{"type": "text", "text": text or "Unavailable"}],
        }

    @classmethod
    def _adf_bullet_list(cls, items: list[str]) -> dict[str, Any]:
        return {
            "type": "bulletList",
            "content": [
                {"type": "listItem", "content": [cls._adf_paragraph(item)]}
                for item in items
            ],
        }

    @staticmethod
    def _one_line(value: Any, limit: int) -> str:
        return " ".join(str(value).replace("\x00", "").split())[:limit]

    @staticmethod
    def _plain_text(value: str, limit: int) -> str:
        normalized = "\n".join(
            " ".join(line.split()) for line in str(value).replace("\x00", "").splitlines() if line.strip()
        )
        return normalized[:limit] or "Unavailable"

    async def _work_loop(self) -> None:
        while not self._stopping:
            try:
                job = self.store.next_due()
                if job:
                    await self._deliver(job)
                    continue
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self.poll_seconds)
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.audit.record(
                    "delivery.worker.error",
                    "work",
                    target_type="delivery-worker",
                    outcome="error",
                    summary=f"Delivery worker failed ({type(exc).__name__}).",
                )
                await asyncio.sleep(min(self.poll_seconds, 2))

    async def _deliver(self, candidate: dict[str, Any]) -> None:
        if not self.store.policy()["enabled"]:
            cancelled = self.store.cancel(candidate["id"], "Outbound delivery is disabled.")
            if cancelled:
                self.audit.record(
                    "delivery.cancelled",
                    "policy-block",
                    target_type="delivery-job",
                    target_id=candidate["id"],
                    outcome="cancelled",
                    summary="A queued delivery was cancelled because outbound delivery is disabled.",
                )
            return
        job = self.store.mark_sending(candidate["id"])
        if job is None:
            return
        package = self.assurance_store.get_package(job["package_id"])
        if package is None or package["status"] != "review":
            self.store.cancel_sending(job["id"], "The source package is no longer active for review.")
            self.audit.record(
                "delivery.cancelled",
                "package-block",
                target_type="delivery-job",
                target_id=job["id"],
                outcome="cancelled",
                summary="Delivery was cancelled because the source package is no longer active.",
            )
            return
        if self._destination_fingerprint() != job["destination_fingerprint"]:
            self.store.fail_without_attempt(
                job["id"],
                "Destination changed after payload approval; a fresh preview is required.",
            )
            self.audit.record(
                "delivery.attempt.blocked",
                "send",
                target_type="delivery-job",
                target_id=job["id"],
                outcome="blocked",
                summary="Destination identity changed after approval.",
            )
            return

        policy = self.store.policy()
        canonical_payload = json.dumps(
            job["payload"], sort_keys=True, separators=(",", ":"), default=str
        ).encode()
        if hashlib.sha256(canonical_payload).hexdigest() != job["payload_sha256"]:
            self.store.fail_without_attempt(
                job["id"],
                "Approved payload integrity verification failed before delivery.",
            )
            self.audit.record(
                "delivery.attempt.blocked",
                "send",
                target_type="delivery-job",
                target_id=job["id"],
                outcome="blocked",
                summary="Approved payload integrity verification failed before delivery.",
            )
            return
        url = self.config.secret("delivery_webhook_url")
        authorization = self.config.secret("delivery_authorization")
        destination_kind = job["destination_kind"]
        delivery_url = url
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SignalRoom/0.1 outbound-assurance",
        }
        if destination_kind == GENERIC_DESTINATION:
            headers.update(
                {
                    "Idempotency-Key": job["idempotency_key"],
                    "X-SignalRoom-Event": "assurance.response-package",
                    "X-SignalRoom-Payload-SHA256": job["payload_sha256"],
                }
            )
            if authorization:
                headers["Authorization"] = authorization
        elif destination_kind == JIRA_DESTINATION:
            delivery_url = f"{url.rstrip('/')}/rest/api/3/issue"
            headers["Accept"] = "application/json"
            headers["Authorization"] = self._jira_authorization()
        started_at = datetime.now(UTC).isoformat()
        http_status: int | None = None
        error = ""
        retryable = True
        outcome = "error"
        external_record: dict[str, str] | None = None
        try:
            verify: bool | ssl.SSLContext = policy["verify_tls"]
            if policy["verify_tls"] and policy.get("ca_bundle"):
                verify = ssl.create_default_context(cafile=policy["ca_bundle"])
            async with self.client_factory(
                timeout=httpx.Timeout(15),
                verify=verify,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    delivery_url, content=canonical_payload, headers=headers
                )
            http_status = int(response.status_code)
            if destination_kind == JIRA_DESTINATION and http_status == 201:
                external_record, error = self._jira_external_record(response, url)
                if external_record:
                    stored = self.store.record_external_record(
                        job["id"],
                        record_id=external_record["id"],
                        record_key=external_record["key"],
                        record_url=external_record["url"],
                    )
                    if stored is None:
                        external_record = None
                        error = (
                            "Jira created an issue, but SignalRoom could not persist its "
                            "correlation. Inspect Jira before retrying."
                        )
            successful = (
                bool(external_record)
                if destination_kind == JIRA_DESTINATION
                else (
                    http_status == 200
                    if destination_kind == SLACK_DESTINATION
                    else 200 <= http_status < 300
                )
            )
            if successful:
                outcome = "delivered"
                retryable = False
            else:
                retryable = (
                    False
                    if destination_kind == JIRA_DESTINATION
                    else http_status in {408, 425, 429} or http_status >= 500
                )
                if not error:
                    error = f"Destination adapter returned HTTP {http_status}"
        except (httpx.HTTPError, OSError, ValueError) as exc:
            if destination_kind == JIRA_DESTINATION:
                retryable = False
                error = (
                    f"Jira create outcome is unknown ({type(exc).__name__}). "
                    "Inspect Jira for the SignalRoom correlation label before an explicit retry."
                )
            else:
                error = f"Destination adapter delivery failed ({type(exc).__name__})."
        updated = self.store.record_attempt(
            job["id"],
            started_at=started_at,
            outcome=outcome,
            http_status=http_status,
            error=error,
            retryable=retryable,
            retry_backoff_seconds=policy["retry_backoff_seconds"],
        )
        assert updated is not None
        self.audit.record(
            "delivery.attempted",
            "send",
            target_type="delivery-job",
            target_id=job["id"],
            outcome=updated["status"],
            summary=(
                (
                    f"Created and correlated Jira issue {external_record['key']}."
                    if external_record
                    else "Redacted response package delivered."
                )
                if updated["status"] == "delivered"
                else error or "Delivery did not complete."
            ),
            metadata={
                "package_id": job["package_id"],
                "attempt_number": updated["attempt_count"],
                "max_attempts": updated["max_attempts"],
                "http_status": http_status,
                "payload_sha256": job["payload_sha256"],
                "idempotency_key": job["idempotency_key"],
                "destination_kind": destination_kind,
                "external_record_id": (
                    external_record["id"] if external_record else ""
                ),
                "external_record_key": (
                    external_record["key"] if external_record else ""
                ),
                "next_attempt_at": updated["next_attempt_at"],
            },
            actor="delivery-worker",
        )

    def _jira_authorization(self) -> str:
        email = self.config.secret("delivery_jira_email")
        api_token = self.config.secret("delivery_jira_api_token")
        if not email or not api_token:
            raise ValueError("Jira Cloud credentials are not configured")
        encoded = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        return f"Basic {encoded}"

    @staticmethod
    def _jira_external_record(
        response: Any, site_url: str
    ) -> tuple[dict[str, str] | None, str]:
        try:
            value = response.json()
        except (TypeError, ValueError):
            return (
                None,
                "Jira returned HTTP 201 without a valid issue response. Inspect Jira "
                "before retrying.",
            )
        if not isinstance(value, dict):
            return (
                None,
                "Jira returned HTTP 201 without an issue object. Inspect Jira before retrying.",
            )
        record_id = str(value.get("id") or "")
        record_key = str(value.get("key") or "")
        if not record_id.isdigit() or not JIRA_ISSUE_KEY_PATTERN.fullmatch(record_key):
            return (
                None,
                "Jira returned HTTP 201 without a trustworthy issue ID and key. "
                "Inspect Jira before retrying.",
            )
        return (
            {
                "id": record_id,
                "key": record_key,
                "url": f"{site_url.rstrip('/')}/browse/{quote(record_key, safe='')}",
            },
            "",
        )

    def _destination_fingerprint(self) -> str:
        url = self.config.secret("delivery_webhook_url")
        authorization = self.config.secret("delivery_authorization")
        jira_email = self.config.secret("delivery_jira_email")
        jira_api_token = self.config.secret("delivery_jira_api_token")
        policy = self.store.policy()
        destination_kind = policy["destination_kind"]
        material = json.dumps(
            {
                "destination_kind": destination_kind,
                "url": url,
                "authorization_sha256": (
                    hashlib.sha256(authorization.encode()).hexdigest()
                    if authorization and destination_kind == GENERIC_DESTINATION
                    else ""
                ),
                "jira_email_sha256": (
                    hashlib.sha256(jira_email.encode()).hexdigest()
                    if jira_email and destination_kind == JIRA_DESTINATION
                    else ""
                ),
                "jira_api_token_sha256": (
                    hashlib.sha256(jira_api_token.encode()).hexdigest()
                    if jira_api_token and destination_kind == JIRA_DESTINATION
                    else ""
                ),
                "jira_mapping": (
                    {
                        "project_key": policy["jira_project_key"],
                        "issue_type": policy["jira_issue_type"],
                        "summary_prefix": policy["jira_summary_prefix"],
                        "labels": policy["jira_labels"],
                        "priority_map": policy["jira_priority_map"],
                    }
                    if destination_kind == JIRA_DESTINATION
                    else {}
                ),
                "verify_tls": policy["verify_tls"],
                "ca_bundle": policy.get("ca_bundle") or "",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()

    @classmethod
    def _validate_destination_url(cls, destination_kind: str, value: str) -> None:
        if destination_kind == SLACK_DESTINATION:
            cls._validate_slack_url(value)
            return
        if destination_kind == JIRA_DESTINATION:
            cls._validate_jira_url(value)
            return
        cls._validate_url(value)

    @staticmethod
    def _validate_jira_url(value: str) -> None:
        if any(character.isspace() for character in value):
            raise ValueError("The Jira Cloud site URL must not contain whitespace")
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise ValueError("Jira Cloud requires HTTPS")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("The Jira Cloud site URL contains an invalid port") from exc
        hostname = (parsed.hostname or "").lower()
        if (
            not hostname.endswith(".atlassian.net")
            or hostname == "atlassian.net"
            or port is not None
        ):
            raise ValueError(
                "Use the Jira Cloud site URL for an atlassian.net tenant"
            )
        if parsed.username or parsed.password:
            raise ValueError("Jira credentials must not be embedded in the site URL")
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            raise ValueError(
                "The Jira Cloud destination must be a site origin without a path, "
                "query, or fragment"
            )

    @classmethod
    def _validate_jira_policy(
        cls,
        value: DeliveryPolicyUpdate | dict[str, Any],
        *,
        email: str,
        api_token: str,
        require_credentials: bool,
    ) -> None:
        read = (
            value.get
            if isinstance(value, dict)
            else lambda name, default=None: getattr(value, name, default)
        )
        project_key = str(read("jira_project_key", "") or "")
        issue_type = str(read("jira_issue_type", "") or "")
        summary_prefix = str(read("jira_summary_prefix", "") or "")
        labels = list(read("jira_labels", []) or [])
        priority_map = dict(read("jira_priority_map", {}) or {})
        if not JIRA_PROJECT_PATTERN.fullmatch(project_key):
            raise ValueError(
                "The Jira project key must be 2-32 uppercase letters, numbers, or underscores"
            )
        if (
            not issue_type.strip()
            or issue_type != issue_type.strip()
            or cls._contains_control(issue_type)
        ):
            raise ValueError("The Jira issue type must be a single printable value")
        if summary_prefix != summary_prefix.strip() or cls._contains_control(summary_prefix):
            raise ValueError("The Jira summary prefix must be a single printable value")
        if len(labels) != len(set(labels)):
            raise ValueError("Jira labels must be unique")
        if any(not JIRA_LABEL_PATTERN.fullmatch(str(label)) for label in labels):
            raise ValueError(
                "Jira labels may contain only letters, numbers, underscores, and hyphens"
            )
        if set(priority_map) != DELIVERY_SEVERITIES:
            raise ValueError(
                "The Jira priority map must define critical, high, medium, and low"
            )
        if any(
            len(str(priority)) > 120
            or str(priority) != str(priority).strip()
            or cls._contains_control(str(priority))
            for priority in priority_map.values()
        ):
            raise ValueError("Jira priority names must be printable values")
        if email and (
            any(character.isspace() for character in email)
            or cls._contains_control(email)
            or ":" in email
            or email.count("@") != 1
            or email.startswith("@")
            or email.endswith("@")
        ):
            raise ValueError("Enter the Atlassian account email used by the API token")
        if api_token and (
            any(character.isspace() for character in api_token)
            or cls._contains_control(api_token)
        ):
            raise ValueError("The Jira API token must be a printable value without whitespace")
        if require_credentials and (not email or not api_token):
            raise ValueError(
                "An Atlassian account email and Jira API token are required before "
                "Jira delivery can be enabled"
            )

    @staticmethod
    def _contains_control(value: str) -> bool:
        return any(ord(character) < 32 or ord(character) == 127 for character in value)

    @staticmethod
    def _validate_slack_url(value: str) -> None:
        if any(character.isspace() for character in value):
            raise ValueError("The Slack webhook URL must not contain whitespace")
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise ValueError("Slack Incoming Webhooks require HTTPS")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("The Slack webhook URL contains an invalid port") from exc
        if not parsed.hostname or parsed.hostname.lower() not in SLACK_WEBHOOK_HOSTS or port is not None:
            raise ValueError("Use a Slack Incoming Webhook URL from hooks.slack.com or hooks.slack-gov.com")
        if parsed.username or parsed.password:
            raise ValueError("Slack webhook credentials must not be embedded in the URL")
        if parsed.query or parsed.fragment or parsed.params:
            raise ValueError("Slack Incoming Webhook URLs must not include parameters, queries, or fragments")
        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) != 4 or segments[0] != "services":
            raise ValueError("The Slack destination must be a complete Incoming Webhook /services/ URL")

    @staticmethod
    def _validate_url(value: str) -> None:
        if any(character.isspace() for character in value):
            raise ValueError("The webhook URL must not contain whitespace")
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError("The webhook URL must include a hostname")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("The webhook URL contains an invalid port") from exc
        if parsed.username or parsed.password:
            raise ValueError("Webhook credentials must not be embedded in the URL")
        if parsed.fragment:
            raise ValueError("Webhook URL fragments are not supported")
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http" and parsed.hostname.lower() in LOOPBACK_HOSTS:
            return
        raise ValueError("Webhook delivery requires HTTPS; HTTP is allowed only for loopback testing")

    @staticmethod
    def _origin(value: str) -> str:
        parsed = urlparse(value)
        if not parsed.hostname:
            return ""
        default_port = 443 if parsed.scheme == "https" else 80
        try:
            parsed_port = parsed.port
        except ValueError:
            return ""
        port = f":{parsed_port}" if parsed_port and parsed_port != default_port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port}"
