from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..audit import AuditStore
from ..config import ConfigStore
from ..schemas import DeliveryPolicyUpdate
from .store import DeliveryStore

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
SLACK_DESTINATION = "slack-incoming-webhook"
GENERIC_DESTINATION = "generic-webhook"
SLACK_WEBHOOK_HOSTS = {"hooks.slack.com", "hooks.slack-gov.com"}


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
        if recovered:
            self.audit.record(
                "delivery.recovered",
                "recover",
                target_type="delivery-worker",
                outcome="warning",
                summary=f"Recovered {recovered} interrupted delivery job(s) for bounded retry.",
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
        return {
            "policy": policy,
            "destination": {
                "kind": destination_kind,
                "configured": bool(url),
                "origin": self._origin(url) if url else "",
                "authorization_configured": bool(
                    self.config.secret("delivery_authorization")
                ),
                "authorization_supported": not is_slack,
                "transport": (
                    "verified TLS"
                    if policy["verify_tls"]
                    else "encrypted without certificate verification"
                ),
                "delivery_semantics": (
                    "notification-only · local deduplication · at-least-once delivery"
                    if is_slack
                    else "exact JSON · destination idempotency key · bounded retries"
                ),
            },
            "jobs": self.store.jobs(),
            "worker": {
                "online": bool(self._worker and not self._worker.done()),
                "restart_recovery": ("bounded-at-least-once-retry" if is_slack else "idempotent-retry"),
                "splunk_authority": "none",
            },
        }

    def update_policy(self, value: DeliveryPolicyUpdate) -> dict[str, Any]:
        previous_fingerprint = self._destination_fingerprint()
        if value.webhook_url and value.clear_webhook_url:
            raise ValueError("Choose either a replacement webhook URL or removal, not both")
        if value.authorization_header and value.clear_authorization_header:
            raise ValueError(
                "Choose either a replacement authorization header or removal, not both"
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
        if candidate_url:
            self._validate_destination_url(value.destination_kind, candidate_url)
        if "\r" in candidate_authorization or "\n" in candidate_authorization:
            raise ValueError("The authorization header must contain exactly one header value")
        if value.destination_kind == SLACK_DESTINATION and value.authorization_header:
            raise ValueError("Slack Incoming Webhooks do not use SignalRoom's generic authorization header")
        if value.destination_kind == SLACK_DESTINATION and not value.verify_tls:
            raise ValueError("Slack Incoming Webhooks require TLS certificate verification")
        if value.enabled and not candidate_url:
            raise ValueError("A webhook URL is required before outbound delivery can be enabled")
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
        if value.clear_webhook_url:
            self.config.delete_secrets("delivery_webhook_url")
        if value.clear_authorization_header:
            self.config.delete_secrets("delivery_authorization")
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
        job = self.store.retry(job_id, policy["max_attempts"])
        if job is None:
            raise ValueError("Only a failed delivery can be explicitly retried")
        self.audit.record(
            "delivery.retry.requested",
            "retry",
            target_type="delivery-job",
            target_id=job_id,
            summary=f"Queued up to {policy['max_attempts']} additional bounded attempt(s).",
            metadata={"attempt_count": job["attempt_count"], "max_attempts": job["max_attempts"]},
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
        if destination_kind == SLACK_DESTINATION and not policy["verify_tls"]:
            raise ValueError("Slack Incoming Webhooks require TLS certificate verification")
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
        payload = self._payload(
            package, matched, policy["redaction_level"], destination_kind
        )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        payload_sha256 = hashlib.sha256(canonical.encode()).hexdigest()
        destination_fingerprint = self._destination_fingerprint()
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
        warnings = (
            [
                "Slack Incoming Webhooks cannot delete a posted message.",
                "Slack Incoming Webhooks do not document a destination idempotency key; "
                "an ambiguous retry can create a duplicate notification.",
                "The destination channel, sender name, and icon come from the Slack app configuration.",
            ]
            if is_slack
            else [
                "The receiving service must honor the idempotency key to prevent duplicates "
                "after an ambiguous response."
            ]
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
                    else "exact JSON · destination idempotency key · bounded retries"
                ),
            },
            "redaction_level": policy["redaction_level"],
            "redactions": redactions,
            "warnings": warnings,
            "authority": {
                "delivery_only": True,
                "splunk_execution": False,
                "validation_approval": False,
            },
            "approval_required": policy["mode"] == "manual",
        }

    @classmethod
    def _payload(
        cls,
        package: dict[str, Any],
        signals: list[dict[str, Any]],
        redaction_level: str,
        destination_kind: str = GENERIC_DESTINATION,
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
        started_at = datetime.now(UTC).isoformat()
        http_status: int | None = None
        error = ""
        retryable = True
        outcome = "error"
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
                response = await client.post(url, content=canonical_payload, headers=headers)
            http_status = int(response.status_code)
            successful = (
                http_status == 200 if destination_kind == SLACK_DESTINATION else 200 <= http_status < 300
            )
            if successful:
                outcome = "delivered"
                retryable = False
            else:
                retryable = http_status in {408, 425, 429} or http_status >= 500
                error = f"Destination adapter returned HTTP {http_status}"
        except (httpx.HTTPError, OSError, ValueError) as exc:
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
                "Redacted response package delivered."
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
                "next_attempt_at": updated["next_attempt_at"],
            },
            actor="delivery-worker",
        )

    def _destination_fingerprint(self) -> str:
        url = self.config.secret("delivery_webhook_url")
        authorization = self.config.secret("delivery_authorization")
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
        cls._validate_url(value)

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
