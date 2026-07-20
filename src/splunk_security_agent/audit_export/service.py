from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..audit import AuditStore
from ..config import ConfigStore
from ..schemas import AuditExportPolicyUpdate
from .store import AuditExportStore

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
RESERVED_INDEXES = {
    "default",
    "history",
    "main",
    "summary",
    "_audit",
    "_internal",
    "_introspection",
    "_telemetry",
}
MAX_BATCH_BYTES = 900_000
PRINTABLE_VALUE = re.compile(r"^[^\x00-\x1f\x7f]+$")


class SplunkAuditExportService:
    """Fail-closed, cursor-based export of the verified local audit chain to HEC."""

    def __init__(
        self,
        store: AuditExportStore,
        audit: AuditStore,
        config: ConfigStore,
        *,
        poll_seconds: float = 2.0,
        ack_poll_seconds: float = 0.5,
        ack_timeout_seconds: float = 15.0,
        client_factory: Callable[..., Any] | None = None,
    ):
        self.store = store
        self.audit = audit
        self.config = config
        self.poll_seconds = poll_seconds
        self.ack_poll_seconds = ack_poll_seconds
        self.ack_timeout_seconds = ack_timeout_seconds
        self.client_factory = client_factory or httpx.AsyncClient
        self._worker: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()
        self._stopping = False

    async def start(self) -> None:
        if self._worker and not self._worker.done():
            return
        self._stopping = False
        self.store.recover_interrupted()
        self._worker = asyncio.create_task(
            self._work_loop(), name="signalroom-audit-export"
        )

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._worker and not self._worker.done():
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
        self._worker = None

    def overview(self) -> dict[str, Any]:
        policy = self.store.policy()
        state = self.store.state()
        url = self.config.secret("audit_hec_url")
        token = self.config.secret("audit_hec_token")
        latest_sequence = self.audit.latest_sequence()
        pending = max(0, latest_sequence - int(state["cursor_sequence"]))
        return {
            "policy": policy,
            "destination": {
                "configured": bool(url and token),
                "url_configured": bool(url),
                "token_configured": bool(token),
                "origin": self._origin(url) if url else "",
                "event_endpoint": "/services/collector/event",
                "index": policy["index_name"],
                "transport": (
                    "verified TLS"
                    if policy["verify_tls"]
                    else "encrypted without certificate verification"
                ),
                "authority": "HEC event ingest to the configured index only",
                "delivery_semantics": (
                    "indexer-acknowledged · at-least-once"
                    if policy["use_indexer_ack"]
                    else "HEC-accepted · at-least-once"
                ),
            },
            "chain": self.audit.verify(),
            "state": {
                **state,
                "latest_sequence": latest_sequence,
                "pending_events": pending,
            },
            "attempts": self.store.attempts(),
            "worker": {
                "online": bool(self._worker and not self._worker.done()),
                "sending": self._lock.locked(),
                "restart_recovery": "retry-uncommitted-cursor-with-stable-event-ids",
            },
        }

    def update_policy(self, value: AuditExportPolicyUpdate) -> dict[str, Any]:
        previous_policy = self.store.policy()
        current_url = self.config.secret("audit_hec_url")
        current_token = self.config.secret("audit_hec_token")
        if value.hec_url and value.clear_hec_url:
            raise ValueError("Choose either a replacement HEC URL or removal, not both")
        if value.hec_token and value.clear_hec_token:
            raise ValueError("Choose either a replacement HEC token or removal, not both")
        if value.clear_hec_url and self.config.secret_is_environment_managed(
            "audit_hec_url"
        ):
            raise ValueError(
                "The HEC URL is environment-managed; remove SIGNALROOM_AUDIT_HEC_URL "
                "and restart SignalRoom"
            )
        if value.clear_hec_token and self.config.secret_is_environment_managed(
            "audit_hec_token"
        ):
            raise ValueError(
                "The HEC token is environment-managed; remove SIGNALROOM_AUDIT_HEC_TOKEN "
                "and restart SignalRoom"
            )
        candidate_url = (
            value.hec_url.strip()
            if value.hec_url
            else ("" if value.clear_hec_url else current_url)
        )
        candidate_token = (
            value.hec_token.strip()
            if value.hec_token
            else ("" if value.clear_hec_token else current_token)
        )
        self._validate_policy(value, candidate_url, candidate_token)
        previous_identity = self._destination_fingerprint(
            current_url,
            previous_policy["index_name"],
            previous_policy["sourcetype"],
            previous_policy["source"],
            previous_policy["host"],
        )
        candidate_identity = self._destination_fingerprint(
            candidate_url,
            value.index_name,
            value.sourcetype,
            value.source,
            value.host,
        )
        identity_changed = previous_identity != candidate_identity
        newly_enabled = value.enabled and not previous_policy["enabled"]
        reset_cursor = None
        if newly_enabled or (value.enabled and identity_changed):
            reset_cursor = 0 if value.backfill_existing else self.audit.latest_sequence()
        if value.hec_url:
            self.config.update_secrets(audit_hec_url=value.hec_url.strip())
        if value.hec_token:
            self.config.update_secrets(audit_hec_token=value.hec_token.strip())
        if value.clear_hec_url:
            self.config.delete_secrets("audit_hec_url")
        if value.clear_hec_token:
            self.config.delete_secrets("audit_hec_token")
        policy = self.store.update_policy(value, reset_cursor=reset_cursor)
        self.audit.record(
            "audit.export.policy.updated",
            "update",
            target_type="audit-export-policy",
            target_id="primary",
            summary=(
                f"Dedicated Splunk audit export was "
                f"{'enabled' if policy['enabled'] else 'disabled'}."
            ),
            metadata={
                "enabled": policy["enabled"],
                "destination_origin": self._origin(candidate_url) if candidate_url else "",
                "index_name": policy["index_name"],
                "sourcetype": policy["sourcetype"],
                "verify_tls": policy["verify_tls"],
                "private_ca_configured": bool(policy["ca_bundle"]),
                "use_indexer_ack": policy["use_indexer_ack"],
                "batch_size": policy["batch_size"],
                "max_attempts": policy["max_attempts"],
                "backfill_existing": bool(value.backfill_existing),
                "cursor_reset": reset_cursor,
                "destination_changed": identity_changed,
                "token_configured": bool(candidate_token),
            },
        )
        self._wake.set()
        return self.overview()

    async def run_now(self) -> dict[str, Any]:
        policy = self.store.policy()
        if not policy["enabled"]:
            raise ValueError("Enable the dedicated audit export policy before exporting")
        self.store.reset_failures()
        result = await self._export_once()
        self._wake.set()
        return {"ok": result == "delivered" or result == "idle", **self.overview()}

    async def _work_loop(self) -> None:
        while not self._stopping:
            try:
                policy = self.store.policy()
                state = self.store.state()
                due = (
                    policy["enabled"]
                    and state["status"] not in {"failed", "chain-invalid", "config-error"}
                    and (
                        not state["next_attempt_at"]
                        or state["next_attempt_at"] <= datetime.now(UTC).isoformat()
                    )
                )
                if due:
                    result = await self._export_once()
                    if result == "delivered":
                        continue
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self.poll_seconds)
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.store.mark_blocked(
                    "failed",
                    f"Audit export worker failed ({type(exc).__name__}).",
                )
                await asyncio.sleep(min(self.poll_seconds, 2))

    async def _export_once(self) -> str:
        async with self._lock:
            policy = self.store.policy()
            if not policy["enabled"]:
                return "disabled"
            url = self.config.secret("audit_hec_url")
            token = self.config.secret("audit_hec_token")
            if not url or not token:
                self.store.mark_blocked(
                    "config-error", "A HEC origin and dedicated HEC token are required."
                )
                return "config-error"
            chain = self.audit.verify()
            if not chain["valid"]:
                self.store.mark_blocked(
                    "chain-invalid",
                    (
                        "The local audit chain failed verification at sequence "
                        f"{chain['broken_sequence']}; no events were exported."
                    ),
                )
                return "chain-invalid"
            state = self.store.state()
            events = self.audit.events_after(
                state["cursor_sequence"], policy["batch_size"]
            )
            if not events:
                self.store.mark_idle()
                return "idle"
            envelopes, body = self._batch(events, policy)
            selected = events[: len(envelopes)]
            first_sequence = int(selected[0]["sequence"])
            last_sequence = int(selected[-1]["sequence"])
            payload_sha256 = hashlib.sha256(body).hexdigest()
            destination_fingerprint = self._destination_fingerprint(
                url,
                policy["index_name"],
                policy["sourcetype"],
                policy["source"],
                policy["host"],
            )
            started_at = datetime.now(UTC).isoformat()
            self.store.mark_sending()
            http_status: int | None = None
            ack_id: int | None = None
            ack_confirmed = False
            error = ""
            retryable = True
            outcome = "error"
            try:
                headers = {
                    "Authorization": f"Splunk {token}",
                    "Content-Type": "application/json",
                    "User-Agent": "SignalRoom/0.1 audit-export",
                }
                if policy["use_indexer_ack"]:
                    headers["X-Splunk-Request-Channel"] = policy["channel_id"]
                async with self.client_factory(
                    timeout=httpx.Timeout(15),
                    verify=self._verify(policy),
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = await client.post(
                        f"{url.rstrip('/')}/services/collector/event",
                        content=body,
                        headers=headers,
                    )
                    http_status = int(response.status_code)
                    value = self._response_json(response)
                    if http_status == 200 and value.get("code") == 0:
                        if policy["use_indexer_ack"]:
                            raw_ack_id = value.get("ackId")
                            if not isinstance(raw_ack_id, int) or raw_ack_id < 0:
                                error = (
                                    "HEC accepted the batch without an ackId; enable indexer "
                                    "acknowledgement for the dedicated token or disable the "
                                    "SignalRoom acknowledgement requirement."
                                )
                                retryable = False
                            else:
                                ack_id = raw_ack_id
                                ack_confirmed = await self._wait_for_ack(
                                    client, url, headers, ack_id
                                )
                                if ack_confirmed:
                                    outcome = "delivered"
                                else:
                                    error = (
                                        "HEC did not confirm indexer acknowledgement before "
                                        "the bounded timeout; retry may duplicate stable event IDs."
                                    )
                        else:
                            outcome = "delivered"
                    else:
                        error = (
                            f"HEC rejected the batch with HTTP {http_status}"
                            if http_status != 200
                            else f"HEC returned response code {value.get('code', 'unknown')}"
                        )
                        retryable = http_status in {408, 425, 429} or http_status >= 500
            except (httpx.HTTPError, OSError, ValueError, ssl.SSLError) as exc:
                error = f"HEC audit export failed ({type(exc).__name__})"
            self.store.record_attempt(
                first_sequence=first_sequence,
                last_sequence=last_sequence,
                event_count=len(selected),
                payload_bytes=len(body),
                payload_sha256=payload_sha256,
                destination_fingerprint=destination_fingerprint,
                outcome=outcome,
                http_status=http_status,
                ack_id=ack_id,
                ack_confirmed=ack_confirmed,
                error=error,
                started_at=started_at,
                retryable=retryable,
            )
            return outcome

    async def _wait_for_ack(
        self,
        client: Any,
        url: str,
        headers: dict[str, str],
        ack_id: int,
    ) -> bool:
        deadline = asyncio.get_running_loop().time() + self.ack_timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            response = await client.post(
                f"{url.rstrip('/')}/services/collector/ack",
                content=json.dumps({"acks": [ack_id]}, separators=(",", ":")).encode(),
                headers=headers,
            )
            if int(response.status_code) != 200:
                return False
            value = self._response_json(response)
            acknowledgements = value.get("acks")
            if isinstance(acknowledgements, dict) and acknowledgements.get(
                str(ack_id)
            ) is True:
                return True
            await asyncio.sleep(self.ack_poll_seconds)
        return False

    @classmethod
    def _batch(
        cls, events: list[dict[str, Any]], policy: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bytes]:
        envelopes: list[dict[str, Any]] = []
        encoded: list[bytes] = []
        for event in events:
            envelope = cls._envelope(event, policy)
            item = json.dumps(
                envelope, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
            prospective = sum(len(part) for part in encoded) + len(encoded) + len(item)
            if encoded and prospective > MAX_BATCH_BYTES:
                break
            envelopes.append(envelope)
            encoded.append(item)
        return envelopes, b"\n".join(encoded)

    @staticmethod
    def _envelope(event: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
        try:
            event_time = datetime.fromisoformat(event["created_at"]).timestamp()
        except (TypeError, ValueError):
            event_time = datetime.now(UTC).timestamp()
        return {
            "time": event_time,
            "host": policy["host"],
            "source": policy["source"],
            "sourcetype": policy["sourcetype"],
            "index": policy["index_name"],
            "fields": {
                "signalroom_event_id": event["id"],
                "signalroom_sequence": int(event["sequence"]),
                "signalroom_event_type": event["event_type"],
                "signalroom_outcome": event["outcome"],
                "signalroom_actor": event["actor"],
                "signalroom_target_type": event["target_type"],
                "signalroom_previous_hash": event["previous_hash"],
                "signalroom_event_hash": event["event_hash"],
                "signalroom_schema": "signalroom.audit.v1",
            },
            "event": {
                "schema": "signalroom.audit.v1",
                **event,
                "chain_algorithm": "sha256",
            },
        }

    @staticmethod
    def _response_json(response: Any) -> dict[str, Any]:
        try:
            value = response.json()
        except (TypeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _verify(policy: dict[str, Any]) -> bool | ssl.SSLContext:
        if policy["verify_tls"] and policy.get("ca_bundle"):
            return ssl.create_default_context(cafile=policy["ca_bundle"])
        return bool(policy["verify_tls"])

    @classmethod
    def _validate_policy(
        cls, value: AuditExportPolicyUpdate, url: str, token: str
    ) -> None:
        if value.index_name.lower() in RESERVED_INDEXES or value.index_name.startswith("_"):
            raise ValueError(
                "Choose a dedicated non-default Splunk index for SignalRoom audit events"
            )
        for name, item in (
            ("sourcetype", value.sourcetype),
            ("source", value.source),
            ("host", value.host),
        ):
            if item != item.strip() or not PRINTABLE_VALUE.fullmatch(item):
                raise ValueError(f"The audit {name} must be one printable value")
        if url:
            cls._validate_url(url)
        if token and (
            any(character.isspace() for character in token)
            or not PRINTABLE_VALUE.fullmatch(token)
        ):
            raise ValueError("The HEC token must be printable and contain no whitespace")
        if value.enabled and (not url or not token):
            raise ValueError(
                "A HEC origin and dedicated HEC token are required before audit export "
                "can be enabled"
            )
        if value.ca_bundle and value.verify_tls:
            path = Path(value.ca_bundle).expanduser()
            if not path.is_file():
                raise ValueError("The audit-export private CA bundle path does not exist")

    @staticmethod
    def _validate_url(value: str) -> None:
        if any(character.isspace() for character in value):
            raise ValueError("The HEC origin must not contain whitespace")
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError("The HEC origin must include a hostname")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("The HEC origin contains an invalid port") from exc
        if parsed.username or parsed.password:
            raise ValueError("HEC credentials must not be embedded in the origin")
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            raise ValueError(
                "The HEC destination must be an origin without a path, query, or fragment"
            )
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http" and parsed.hostname.lower() in LOOPBACK_HOSTS:
            return
        raise ValueError(
            "HEC audit export requires HTTPS; HTTP is allowed only for loopback testing"
        )

    @staticmethod
    def _destination_fingerprint(
        url: str, index_name: str, sourcetype: str, source: str, host: str
    ) -> str:
        material = json.dumps(
            {
                "origin": SplunkAuditExportService._origin(url),
                "index_name": index_name,
                "sourcetype": sourcetype,
                "source": source,
                "host": host,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()

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
