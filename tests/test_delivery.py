from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from splunk_security_agent.assurance import AssuranceStore
from splunk_security_agent.audit import AuditStore
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.delivery import AssuranceDeliveryService, DeliveryStore
from splunk_security_agent.schemas import DeliveryPolicyUpdate


def package_fixture(store: AssuranceStore) -> dict[str, Any]:
    signal = {
        "fingerprint": "identity-coverage-gap",
        "kind": "coverage",
        "severity": "high",
        "title": "Identity telemetry coverage changed",
        "detail": "Raw environment detail must not leave the host.",
        "subject": "vpn-authentication",
        "source_ref": "D1",
    }
    store.correlate_signals("run-1", [signal], authoritative=True)
    return store.create_package(
        "run-1",
        "high",
        "Assurance response · identity coverage",
        "One high-severity signal requires review.",
        [signal["fingerprint"]],
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )


def test_audit_store_redacts_secrets_and_detects_chain_tampering(tmp_path):
    store = AuditStore(tmp_path / "audit.db")
    first = store.record(
        "delivery.policy.updated",
        "update",
        target_type="delivery-policy",
        target_id="primary",
        metadata={
            "authorization_header": "Bearer secret",
            "nested": {"api_token": "secret", "safe": "visible"},
        },
    )
    store.record(
        "delivery.preview.generated",
        "preview",
        target_type="assurance-package",
        target_id="package-1",
    )

    assert first["metadata"]["authorization_header"] == "[REDACTED]"
    assert first["metadata"]["nested"]["api_token"] == "[REDACTED]"
    assert first["metadata"]["nested"]["safe"] == "visible"
    assert store.verify()["valid"] is True

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE audit_events SET summary='tampered' WHERE sequence=1")

    result = store.verify()
    assert result["valid"] is False
    assert result["broken_sequence"] == 1


def test_delivery_preview_is_redacted_and_approval_is_hash_bound(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    audit = AuditStore(tmp_path / "audit.db")
    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"), assurance, config, audit
    )
    service.update_policy(
        DeliveryPolicyUpdate(
            enabled=True,
            webhook_url="http://127.0.0.1:9999/hooks/secret?code=hidden",
            destination_label="SOC webhook",
            redaction_level="strict",
            minimum_severity="high",
            signal_kinds=["coverage"],
        )
    )

    preview = service.preview(package["id"])
    serialized = str(preview["payload"])

    assert preview["destination"]["origin"] == "http://127.0.0.1:9999"
    assert "signals" not in preview["payload"]
    assert "Raw environment detail" not in serialized
    assert "vpn-authentication" not in serialized
    assert "validation_task_ids" not in serialized
    assert preview["payload"]["authority"]["splunk_execution"] is False
    assert preview["payload"]["authority"]["validation_approval"] is False
    with pytest.raises(ValueError, match="payload changed"):
        service.approve(package["id"], "0" * 64)

    job = service.approve(package["id"], preview["payload_sha256"])

    assert job["status"] == "queued"
    assert job["payload_sha256"] == preview["payload_sha256"]
    assert job["approval_mode"] == "analyst"
    assert audit.verify()["valid"] is True

    disabled = service.update_policy(
        DeliveryPolicyUpdate(
            enabled=False,
            clear_webhook_url=True,
            signal_kinds=["coverage"],
        )
    )
    assert disabled["destination"]["configured"] is False
    assert config.secret("delivery_webhook_url") == ""
    assert service.store.get(job["id"])["status"] == "cancelled"


def test_delivery_rejects_insecure_remote_http_and_filters_policy(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"),
        assurance,
        ConfigStore(tmp_path / "config"),
        AuditStore(tmp_path / "audit.db"),
    )

    with pytest.raises(ValueError, match="requires HTTPS"):
        service.update_policy(
            DeliveryPolicyUpdate(
                enabled=True,
                webhook_url="http://example.com/webhook",
            )
        )
    with pytest.raises(ValueError, match="invalid port"):
        service.update_policy(
            DeliveryPolicyUpdate(
                enabled=True,
                webhook_url="https://example.com:invalid/webhook",
            )
        )
    with pytest.raises(ValueError, match="exactly one header value"):
        service.update_policy(
            DeliveryPolicyUpdate(
                enabled=True,
                webhook_url="https://example.com/webhook",
                authorization_header="Bearer safe\r\nX-Injected: true",
            )
        )

    service.update_policy(
        DeliveryPolicyUpdate(
            enabled=True,
            webhook_url="https://example.com/webhook",
            minimum_severity="critical",
        )
    )
    with pytest.raises(ValueError, match="below"):
        service.preview(package["id"])


class FakeResponse:
    status_code = 204


class FakeDeliveryClient:
    def __init__(self, calls: list[dict[str, Any]], **kwargs: Any):
        self.calls = calls
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def post(
        self, url: str, *, content: bytes, headers: dict[str, str]
    ) -> FakeResponse:
        self.calls.append({"url": url, "content": content, "headers": headers})
        return FakeResponse()


@pytest.mark.asyncio
async def test_delivery_worker_sends_exact_payload_with_idempotency_and_no_splunk_authority(
    tmp_path,
):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    audit = AuditStore(tmp_path / "audit.db")
    store = DeliveryStore(tmp_path / "delivery.db")
    calls: list[dict[str, Any]] = []
    service = AssuranceDeliveryService(
        store,
        assurance,
        config,
        audit,
        poll_seconds=0.01,
        client_factory=lambda **kwargs: FakeDeliveryClient(calls, **kwargs),
    )
    service.update_policy(
        DeliveryPolicyUpdate(
            enabled=True,
            webhook_url="http://localhost:9876/webhook",
            authorization_header="Bearer encrypted-at-rest",
            minimum_severity="high",
            signal_kinds=["coverage"],
        )
    )
    preview = service.preview(package["id"])
    job = service.approve(package["id"], preview["payload_sha256"])

    await service.start()
    for _ in range(100):
        current = store.get(job["id"])
        if current and current["status"] == "delivered":
            break
        await asyncio.sleep(0.01)
    await service.stop()

    delivered = store.get(job["id"])
    assert delivered is not None and delivered["status"] == "delivered"
    assert len(calls) == 1
    expected_bytes = json.dumps(
        preview["payload"], sort_keys=True, separators=(",", ":")
    ).encode()
    assert calls[0]["content"] == expected_bytes
    assert calls[0]["headers"]["Idempotency-Key"] == job["idempotency_key"]
    assert calls[0]["headers"]["Authorization"] == "Bearer encrypted-at-rest"
    assert preview["payload"]["authority"] == {
        "delivery_only": True,
        "splunk_execution": False,
        "validation_approval": False,
    }
    attempted = [
        event
        for event in audit.events()
        if event["event_type"] == "delivery.attempted"
    ]
    assert attempted[0]["outcome"] == "delivered"
    assert audit.verify()["valid"] is True
