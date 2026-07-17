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


class AssuranceDeliveryService:
    """Policy-bound, redacted, idempotent outbound response-package delivery."""

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
                summary=f"Recovered {recovered} interrupted delivery job(s) for idempotent retry.",
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
        return {
            "policy": policy,
            "destination": {
                "kind": "generic-webhook",
                "configured": bool(url),
                "origin": self._origin(url) if url else "",
                "authorization_configured": bool(
                    self.config.secret("delivery_authorization")
                ),
                "transport": (
                    "verified TLS"
                    if policy["verify_tls"]
                    else "encrypted without certificate verification"
                ),
            },
            "jobs": self.store.jobs(),
            "worker": {
                "online": bool(self._worker and not self._worker.done()),
                "restart_recovery": "idempotent-retry",
                "splunk_authority": "none",
            },
        }

    def update_policy(self, value: DeliveryPolicyUpdate) -> dict[str, Any]:
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
            self._validate_url(candidate_url)
        if "\r" in candidate_authorization or "\n" in candidate_authorization:
            raise ValueError("The authorization header must contain exactly one header value")
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
        cancelled = 0
        if not policy["enabled"]:
            cancelled = self.store.cancel_pending(
                "Outbound delivery was disabled by the local operator."
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
        self._validate_url(url)
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
        payload = self._payload(package, matched, policy["redaction_level"])
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
            redactions.append("signal titles, subjects, and details")
        else:
            redactions.append("signal details; bounded titles and subjects remain")
        return {
            "package_id": package_id,
            "payload": payload,
            "payload_sha256": payload_sha256,
            "payload_bytes": len(canonical.encode()),
            "idempotency_key": idempotency_key,
            "destination_fingerprint": destination_fingerprint,
            "destination": {
                "kind": "generic-webhook",
                "label": policy["destination_label"],
                "origin": self._origin(url),
                "verify_tls": policy["verify_tls"],
            },
            "redaction_level": policy["redaction_level"],
            "redactions": redactions,
            "approval_required": policy["mode"] == "manual",
        }

    @staticmethod
    def _payload(
        package: dict[str, Any], signals: list[dict[str, Any]], redaction_level: str
    ) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for signal in signals:
            kind = str(signal.get("kind") or "unknown")
            severity = str(signal.get("severity") or "medium")
            by_kind[kind] = by_kind.get(kind, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        payload: dict[str, Any] = {
            "schema": "signalroom.assurance-response.v1",
            "event": "assurance.response-package",
            "package": {
                "id": package["id"],
                "severity": package["severity"],
                "title": package["title"],
                "summary": package["summary"],
                "status": package["status"],
                "created_at": package["created_at"],
                "expires_at": package["expires_at"],
            },
            "signal_summary": {
                "matched": len(signals),
                "by_kind": dict(sorted(by_kind.items())),
                "by_severity": dict(sorted(by_severity.items())),
            },
            "authority": {
                "delivery_only": True,
                "splunk_execution": False,
                "validation_approval": False,
            },
        }
        if redaction_level == "standard":
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
            cancelled = self.store.cancel(
                candidate["id"], "Outbound delivery is disabled."
            )
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
            self.store.cancel_sending(
                job["id"], "The source package is no longer active for review."
            )
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
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SignalRoom/0.1 outbound-assurance",
            "Idempotency-Key": job["idempotency_key"],
            "X-SignalRoom-Event": "assurance.response-package",
            "X-SignalRoom-Payload-SHA256": job["payload_sha256"],
        }
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
                response = await client.post(
                    url, content=canonical_payload, headers=headers
                )
            http_status = int(response.status_code)
            if 200 <= http_status < 300:
                outcome = "delivered"
                retryable = False
            else:
                retryable = http_status in {408, 425, 429} or http_status >= 500
                error = f"Webhook returned HTTP {http_status}"
        except (httpx.HTTPError, OSError, ValueError) as exc:
            error = f"Webhook delivery failed ({type(exc).__name__})."
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
                "next_attempt_at": updated["next_attempt_at"],
            },
            actor="delivery-worker",
        )

    def _destination_fingerprint(self) -> str:
        url = self.config.secret("delivery_webhook_url")
        authorization = self.config.secret("delivery_authorization")
        policy = self.store.policy()
        material = json.dumps(
            {
                "url": url,
                "authorization_sha256": (
                    hashlib.sha256(authorization.encode()).hexdigest()
                    if authorization
                    else ""
                ),
                "verify_tls": policy["verify_tls"],
                "ca_bundle": policy.get("ca_bundle") or "",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()

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
