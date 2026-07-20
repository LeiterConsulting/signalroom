from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

from splunk_security_agent.audit import AuditStore
from splunk_security_agent.audit_export import AuditExportStore, SplunkAuditExportService
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.schemas import AuditExportPolicyUpdate


class FakeResponse:
    def __init__(self, value: dict[str, Any], status_code: int = 200):
        self.value = value
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self.value


class FakeHecClient:
    def __init__(
        self,
        calls: list[dict[str, Any]],
        responses: list[FakeResponse],
        **kwargs: Any,
    ):
        self.calls = calls
        self.responses = responses
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def post(
        self, url: str, *, content: bytes, headers: dict[str, str]
    ) -> FakeResponse:
        self.calls.append(
            {
                "url": url,
                "content": content,
                "headers": headers,
                "client": self.kwargs,
            }
        )
        return self.responses.pop(0)


def build_service(
    tmp_path: Any,
    responses: list[FakeResponse],
) -> tuple[
    SplunkAuditExportService,
    AuditStore,
    AuditExportStore,
    ConfigStore,
    list[dict[str, Any]],
]:
    audit = AuditStore(tmp_path / "audit.db")
    store = AuditExportStore(tmp_path / "audit-export.db")
    config = ConfigStore(tmp_path / "config")
    calls: list[dict[str, Any]] = []
    service = SplunkAuditExportService(
        store,
        audit,
        config,
        ack_poll_seconds=0,
        ack_timeout_seconds=0.1,
        client_factory=lambda **kwargs: FakeHecClient(calls, responses, **kwargs),
    )
    return service, audit, store, config, calls


def test_audit_export_policy_is_disabled_and_durable_by_default(tmp_path: Any) -> None:
    store = AuditExportStore(tmp_path / "audit-export.db")

    assert store.policy()["enabled"] is False
    assert store.policy()["index_name"] == "signalroom_audit"
    assert store.policy()["channel_id"]
    assert store.state()["status"] == "disabled"
    assert store.state()["cursor_sequence"] == 0
    assert store.attempts() == []


def test_audit_export_requires_a_dedicated_secure_destination(tmp_path: Any) -> None:
    service, _, _, config, _ = build_service(tmp_path, [])

    with pytest.raises(ValueError, match="dedicated non-default"):
        service.update_policy(
            AuditExportPolicyUpdate(
                enabled=True,
                index_name="main",
                hec_url="https://splunk.example:8088",
                hec_token="token",
            )
        )
    with pytest.raises(ValueError, match="requires HTTPS"):
        service.update_policy(
            AuditExportPolicyUpdate(
                enabled=True,
                hec_url="http://splunk.example:8088",
                hec_token="token",
            )
        )
    with pytest.raises(ValueError, match="origin without a path"):
        service.update_policy(
            AuditExportPolicyUpdate(
                enabled=True,
                hec_url="https://splunk.example:8088/services/collector/event",
                hec_token="token",
            )
        )
    with pytest.raises(ValueError, match="HEC origin and dedicated HEC token"):
        service.update_policy(
            AuditExportPolicyUpdate(
                enabled=True,
                hec_url="https://splunk.example:8088",
            )
        )

    overview = service.update_policy(
        AuditExportPolicyUpdate(
            enabled=True,
            hec_url="https://splunk.example:8088",
            hec_token="dedicated-secret-token",
            verify_tls=False,
        )
    )
    assert overview["destination"]["origin"] == "https://splunk.example:8088"
    assert overview["destination"]["token_configured"] is True
    assert config.secret("audit_hec_token") == "dedicated-secret-token"
    assert "dedicated-secret-token" not in json.dumps(overview)
    assert "dedicated-secret-token" not in json.dumps(service.audit.events())


@pytest.mark.asyncio
async def test_audit_export_sends_verified_events_and_advances_durable_cursor(
    tmp_path: Any,
) -> None:
    service, audit, store, _, calls = build_service(
        tmp_path, [FakeResponse({"text": "Success", "code": 0})]
    )
    old = audit.record(
        "case.created",
        "create",
        target_type="case",
        target_id="case-1",
        summary="Existing local event",
    )
    service.update_policy(
        AuditExportPolicyUpdate(
            enabled=True,
            hec_url="http://localhost:8088",
            hec_token="token-1",
            verify_tls=False,
            index_name="signalroom_audit",
            backfill_existing=False,
        )
    )

    result = await service.run_now()

    assert result["ok"] is True
    assert len(calls) == 1
    assert calls[0]["url"] == "http://localhost:8088/services/collector/event"
    assert calls[0]["headers"]["Authorization"] == "Splunk token-1"
    assert "X-Splunk-Request-Channel" not in calls[0]["headers"]
    envelopes = [
        json.loads(line)
        for line in calls[0]["content"].decode().splitlines()
        if line
    ]
    assert len(envelopes) == 1
    envelope = envelopes[0]
    assert envelope["index"] == "signalroom_audit"
    assert envelope["sourcetype"] == "signalroom:audit"
    assert envelope["event"]["event_type"] == "audit.export.policy.updated"
    assert envelope["event"]["sequence"] == old["sequence"] + 1
    assert envelope["event"]["chain_algorithm"] == "sha256"
    assert envelope["fields"]["signalroom_event_id"] == envelope["event"]["id"]
    assert (
        envelope["fields"]["signalroom_previous_hash"]
        == envelope["event"]["previous_hash"]
    )
    assert envelope["fields"]["signalroom_schema"] == "signalroom.audit.v1"
    assert envelope["fields"]["signalroom_event_hash"] == envelope["event"]["event_hash"]
    assert store.state()["cursor_sequence"] == envelope["event"]["sequence"]
    assert store.state()["status"] == "pending"
    assert store.attempts()[0]["outcome"] == "delivered"


@pytest.mark.asyncio
async def test_audit_export_can_backfill_and_require_indexer_ack(tmp_path: Any) -> None:
    service, audit, store, _, calls = build_service(
        tmp_path,
        [
            FakeResponse({"text": "Success", "code": 0, "ackId": 42}),
            FakeResponse({"acks": {"42": True}}),
        ],
    )
    audit.record(
        "auth.enabled",
        "enable",
        target_type="auth-policy",
        summary="Named access enabled",
    )
    service.update_policy(
        AuditExportPolicyUpdate(
            enabled=True,
            hec_url="https://splunk.example:8088",
            hec_token="token-2",
            index_name="signalroom_audit",
            backfill_existing=True,
            use_indexer_ack=True,
        )
    )

    result = await service.run_now()

    assert result["ok"] is True
    assert len(calls) == 2
    channel = store.policy()["channel_id"]
    assert calls[0]["headers"]["X-Splunk-Request-Channel"] == channel
    assert calls[1]["url"] == "https://splunk.example:8088/services/collector/ack"
    assert json.loads(calls[1]["content"]) == {"acks": [42]}
    attempt = store.attempts()[0]
    assert attempt["first_sequence"] == 1
    assert attempt["event_count"] == 2
    assert attempt["ack_id"] == 42
    assert attempt["ack_confirmed"] is True
    assert store.state()["cursor_sequence"] == 2


@pytest.mark.asyncio
async def test_audit_export_fails_closed_when_local_chain_is_tampered(
    tmp_path: Any,
) -> None:
    service, audit, store, _, calls = build_service(tmp_path, [])
    audit.record(
        "detection.approved",
        "approve",
        target_type="detection",
        target_id="detection-1",
    )
    service.update_policy(
        AuditExportPolicyUpdate(
            enabled=True,
            hec_url="https://splunk.example:8088",
            hec_token="token-3",
            backfill_existing=True,
        )
    )
    with sqlite3.connect(audit.path) as db:
        db.execute("UPDATE audit_events SET summary='tampered' WHERE sequence=1")

    result = await service.run_now()

    assert result["ok"] is False
    assert calls == []
    assert store.state()["status"] == "chain-invalid"
    assert "failed verification" in store.state()["last_error"]
    assert store.state()["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_audit_export_does_not_advance_cursor_on_hec_rejection(
    tmp_path: Any,
) -> None:
    service, audit, store, _, _ = build_service(
        tmp_path, [FakeResponse({"text": "Invalid token", "code": 4}, 403)]
    )
    audit.record(
        "workload.policy.updated",
        "update",
        target_type="workload-policy",
    )
    service.update_policy(
        AuditExportPolicyUpdate(
            enabled=True,
            hec_url="https://splunk.example:8088",
            hec_token="token-4",
            backfill_existing=True,
        )
    )

    result = await service.run_now()

    assert result["ok"] is False
    assert store.state()["cursor_sequence"] == 0
    assert store.state()["status"] == "failed"
    assert store.attempts()[0]["http_status"] == 403
    assert store.attempts()[0]["outcome"] == "error"
