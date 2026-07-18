from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
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
    assert "Assurance response · identity coverage" not in serialized
    assert "One high-severity signal requires review." not in serialized
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
    with pytest.raises(ValueError, match="new destination URL"):
        service.update_policy(
            DeliveryPolicyUpdate(
                enabled=False,
                destination_kind="jira-cloud",
                jira_project_key="SEC",
            )
        )


def test_delivery_store_migrates_legacy_destination_columns(tmp_path):
    path = tmp_path / "legacy-delivery.db"
    with sqlite3.connect(path) as db:
        db.executescript(
            """
            CREATE TABLE delivery_policy (
                id INTEGER PRIMARY KEY CHECK (id=1),
                enabled INTEGER NOT NULL,
                mode TEXT NOT NULL,
                minimum_severity TEXT NOT NULL,
                signal_kinds TEXT NOT NULL,
                redaction_level TEXT NOT NULL,
                destination_label TEXT NOT NULL,
                verify_tls INTEGER NOT NULL,
                ca_bundle TEXT NOT NULL,
                max_attempts INTEGER NOT NULL,
                retry_backoff_seconds INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO delivery_policy VALUES
                (1,0,'manual','high','["coverage"]','strict','Legacy',1,'',3,60,'now');
            CREATE TABLE delivery_jobs (
                id TEXT PRIMARY KEY,
                package_id TEXT NOT NULL,
                status TEXT NOT NULL,
                approval_mode TEXT NOT NULL,
                destination_label TEXT NOT NULL,
                destination_fingerprint TEXT NOT NULL,
                payload TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                attempt_count INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                next_attempt_at TEXT,
                last_error TEXT NOT NULL,
                http_status INTEGER,
                created_at TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                delivered_at TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

    store = DeliveryStore(path)

    assert store.policy()["destination_kind"] == "generic-webhook"
    with store.connect() as db:
        policy_columns = {row["name"] for row in db.execute("PRAGMA table_info(delivery_policy)")}
        job_columns = {row["name"] for row in db.execute("PRAGMA table_info(delivery_jobs)")}
    assert "destination_kind" in policy_columns
    assert "destination_kind" in job_columns
    assert {
        "jira_project_key",
        "jira_issue_type",
        "jira_summary_prefix",
        "jira_labels",
        "jira_priority_map",
        "soar_label",
        "soar_container_type",
        "soar_status",
        "soar_name_prefix",
        "soar_sensitivity",
        "soar_tags",
        "soar_severity_map",
        "soar_tenant_id",
    } <= policy_columns
    assert {
        "external_record_id",
        "external_record_key",
        "external_record_url",
        "external_record_created_at",
    } <= job_columns
    with store.connect() as db:
        reconciliation_tables = {
            row["name"]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "delivery_reconciliations" in reconciliation_tables


def test_slack_adapter_restricts_destination_and_builds_plain_text_preview(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"),
        assurance,
        ConfigStore(tmp_path / "config"),
        AuditStore(tmp_path / "audit.db"),
    )

    for invalid_url in (
        "https://example.com/services/T/B/secret",
        "http://hooks.slack.com/services/T/B/secret",
        "https://hooks.slack.com/not-services/T/B/secret",
        "https://hooks.slack.com/services/T/B/secret?redirect=true",
    ):
        with pytest.raises(ValueError):
            service.update_policy(
                DeliveryPolicyUpdate(
                    enabled=True,
                    destination_kind="slack-incoming-webhook",
                    webhook_url=invalid_url,
                )
            )
    with pytest.raises(ValueError, match="require TLS certificate verification"):
        service.update_policy(
            DeliveryPolicyUpdate(
                enabled=True,
                destination_kind="slack-incoming-webhook",
                webhook_url="https://hooks.slack.com/services/T000/B000/secret",
                verify_tls=False,
            )
        )

    service.update_policy(
        DeliveryPolicyUpdate(
            enabled=True,
            destination_kind="slack-incoming-webhook",
            webhook_url="https://hooks.slack.com/services/T000/B000/secret",
            destination_label="SOC alerts",
            minimum_severity="high",
            signal_kinds=["coverage"],
            redaction_level="strict",
        )
    )
    preview = service.preview(package["id"])
    serialized = json.dumps(preview["payload"])

    assert preview["destination"]["kind"] == "slack-incoming-webhook"
    assert preview["destination"]["origin"] == "https://hooks.slack.com"
    assert "at-least-once" in preview["destination"]["delivery_semantics"]
    assert preview["payload"]["text"].startswith("SignalRoom assurance response")
    assert "blocks" in preview["payload"]
    assert "schema" not in preview["payload"]
    assert "Identity telemetry coverage changed" not in serialized
    assert "Assurance response · identity coverage" not in serialized
    assert "vpn-authentication" not in serialized
    assert "mrkdwn" not in serialized
    assert all(
        text_object["type"] == "plain_text"
        for block in preview["payload"]["blocks"]
        for text_object in (
            ([block["text"]] if isinstance(block.get("text"), dict) else [])
            + list(block.get("fields") or [])
            + list(block.get("elements") or [])
        )
    )
    assert any("duplicate" in warning for warning in preview["warnings"])


def jira_policy(**overrides: Any) -> DeliveryPolicyUpdate:
    values: dict[str, Any] = {
        "enabled": True,
        "destination_kind": "jira-cloud",
        "webhook_url": "https://security-team.atlassian.net",
        "destination_label": "Security operations Jira",
        "minimum_severity": "high",
        "signal_kinds": ["coverage"],
        "redaction_level": "strict",
        "jira_project_key": "SEC",
        "jira_issue_type": "Task",
        "jira_summary_prefix": "[SignalRoom]",
        "jira_labels": ["signalroom", "security-assurance"],
        "jira_priority_map": {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        },
        "jira_email": "analyst@example.com",
        "jira_api_token": "jira-api-token",
    }
    values.update(overrides)
    return DeliveryPolicyUpdate(**values)


def soar_policy(**overrides: Any) -> DeliveryPolicyUpdate:
    values: dict[str, Any] = {
        "enabled": True,
        "destination_kind": "splunk-soar",
        "webhook_url": "https://soar.internal:8443",
        "destination_label": "Security operations SOAR",
        "minimum_severity": "high",
        "signal_kinds": ["coverage"],
        "redaction_level": "strict",
        "verify_tls": False,
        "max_attempts": 3,
        "retry_backoff_seconds": 10,
        "soar_label": "events",
        "soar_container_type": "default",
        "soar_status": "new",
        "soar_name_prefix": "[SignalRoom]",
        "soar_sensitivity": "amber",
        "soar_tags": ["signalroom", "security-assurance"],
        "soar_severity_map": {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
        },
        "soar_tenant_id": "tenant-blue",
        "soar_auth_token": "soar-auth-token",
    }
    values.update(overrides)
    return DeliveryPolicyUpdate(**values)


def test_jira_adapter_restricts_authority_and_builds_redacted_create_payload(
    tmp_path,
):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"),
        assurance,
        config,
        AuditStore(tmp_path / "audit.db"),
    )

    for invalid_url in (
        "http://security-team.atlassian.net",
        "https://atlassian.net",
        "https://security-team.atlassian.net.evil.example",
        "https://security-team.atlassian.net/rest/api/3/issue",
        "https://security-team.atlassian.net:8443",
    ):
        with pytest.raises(ValueError):
            service.update_policy(jira_policy(webhook_url=invalid_url))
    with pytest.raises(ValueError, match="require TLS certificate verification"):
        service.update_policy(jira_policy(verify_tls=False))
    with pytest.raises(ValueError, match="private CA override"):
        service.update_policy(jira_policy(ca_bundle=str(tmp_path / "jira-ca.pem")))
    with pytest.raises(ValueError, match="project key"):
        service.update_policy(jira_policy(jira_project_key="security"))
    with pytest.raises(ValueError, match="labels"):
        service.update_policy(jira_policy(jira_labels=["not a label"]))

    overview = service.update_policy(jira_policy())
    assert overview["destination"]["configured"] is True
    assert overview["destination"]["authorization_supported"] is False
    assert overview["destination"]["jira_email_configured"] is True
    assert overview["destination"]["jira_api_token_configured"] is True
    assert "jira_email" not in overview["destination"]
    assert "jira_api_token" not in overview["destination"]

    preview = service.preview(package["id"])
    serialized = json.dumps(preview["payload"])
    fields = preview["payload"]["fields"]
    delivery_property = preview["payload"]["properties"][0]

    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert fields["priority"] == {"name": "High"}
    assert fields["description"]["type"] == "doc"
    assert fields["description"]["version"] == 1
    assert delivery_property["key"] == "signalroom.delivery"
    assert delivery_property["value"]["correlation_id"] == preview["correlation_id"]
    assert delivery_property["value"]["contract"] == "create-issue-only"
    assert delivery_property["value"]["splunk_execution"] is False
    assert any(
        label.startswith("signalroom-") for label in fields["labels"]
    )
    assert "Identity telemetry coverage changed" not in serialized
    assert "Raw environment detail" not in serialized
    assert "vpn-authentication" not in serialized
    assert "Assurance response · identity coverage" not in serialized
    assert preview["authority"] == {
        "delivery_only": True,
        "external_create": True,
        "external_update": False,
        "external_delete": False,
        "splunk_execution": False,
        "validation_approval": False,
    }
    assert "analyst-reviewed" in preview["destination"]["delivery_semantics"]
    assert any("cannot update" in warning for warning in preview["warnings"])

    service.update_policy(jira_policy(webhook_url=None, redaction_level="standard"))
    standard = json.dumps(service.preview(package["id"])["payload"])
    assert "Identity telemetry coverage changed" in standard
    assert "vpn-authentication" in standard
    assert "Raw environment detail" not in standard


class FakeResponse:
    status_code = 204


class FakeSlackResponse:
    status_code = 200


class FakeJiraResponse:
    status_code = 201

    @staticmethod
    def json() -> dict[str, str]:
        return {
            "id": "10042",
            "key": "SEC-42",
            "self": "https://evil.example/rest/api/3/issue/10042",
        }


class FakeJiraIssueResponse:
    def __init__(self, status_code: int, value: dict[str, Any] | None = None):
        self.status_code = status_code
        self.value = value

    def json(self) -> dict[str, Any]:
        if self.value is None:
            raise ValueError("No JSON response")
        return self.value


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


@pytest.mark.asyncio
async def test_slack_worker_sends_exact_blocks_without_generic_headers(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    audit = AuditStore(tmp_path / "audit.db")
    store = DeliveryStore(tmp_path / "delivery.db")
    calls: list[dict[str, Any]] = []

    class FakeSlackClient(FakeDeliveryClient):
        async def post(self, url: str, *, content: bytes, headers: dict[str, str]) -> FakeSlackResponse:
            self.calls.append({"url": url, "content": content, "headers": headers})
            return FakeSlackResponse()

    service = AssuranceDeliveryService(
        store,
        assurance,
        config,
        audit,
        poll_seconds=0.01,
        client_factory=lambda **kwargs: FakeSlackClient(calls, **kwargs),
    )
    service.update_policy(
        DeliveryPolicyUpdate(
            enabled=True,
            webhook_url="https://example.com/generic",
            authorization_header="Bearer generic-only",
            signal_kinds=["coverage"],
        )
    )
    generic_preview = service.preview(package["id"])
    generic_job = service.approve(package["id"], generic_preview["payload_sha256"])
    service.update_policy(
        DeliveryPolicyUpdate(
            enabled=True,
            destination_kind="slack-incoming-webhook",
            webhook_url="https://hooks.slack.com/services/T000/B000/secret",
            signal_kinds=["coverage"],
        )
    )
    assert store.get(generic_job["id"])["status"] == "cancelled"
    assert "fresh payload preview" in store.get(generic_job["id"])["last_error"]
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
    assert delivered["destination_kind"] == "slack-incoming-webhook"
    assert (
        calls[0]["content"] == json.dumps(preview["payload"], sort_keys=True, separators=(",", ":")).encode()
    )
    assert "Authorization" not in calls[0]["headers"]
    assert "Idempotency-Key" not in calls[0]["headers"]
    assert "X-SignalRoom-Event" not in calls[0]["headers"]


@pytest.mark.asyncio
async def test_jira_worker_creates_once_and_persists_trusted_external_correlation(
    tmp_path,
):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    audit = AuditStore(tmp_path / "audit.db")
    store = DeliveryStore(tmp_path / "delivery.db")
    calls: list[dict[str, Any]] = []

    class FakeJiraClient(FakeDeliveryClient):
        async def post(
            self, url: str, *, content: bytes, headers: dict[str, str]
        ) -> FakeJiraResponse:
            self.calls.append(
                {
                    "url": url,
                    "content": content,
                    "headers": headers,
                    "client": self.kwargs,
                }
            )
            return FakeJiraResponse()

    service = AssuranceDeliveryService(
        store,
        assurance,
        config,
        audit,
        client_factory=lambda **kwargs: FakeJiraClient(calls, **kwargs),
    )
    service.update_policy(jira_policy(max_attempts=8))
    preview = service.preview(package["id"])
    job = service.approve(package["id"], preview["payload_sha256"])

    await service._deliver(job)

    delivered = store.get(job["id"])
    assert delivered is not None and delivered["status"] == "delivered"
    assert delivered["attempt_count"] == 1
    assert delivered["external_record"] == {
        "id": "10042",
        "key": "SEC-42",
        "url": "https://security-team.atlassian.net/browse/SEC-42",
        "created_at": delivered["external_record"]["created_at"],
    }
    assert delivered["external_record"]["created_at"]
    assert len(calls) == 1
    assert calls[0]["url"] == (
        "https://security-team.atlassian.net/rest/api/3/issue"
    )
    assert calls[0]["content"] == json.dumps(
        preview["payload"], sort_keys=True, separators=(",", ":")
    ).encode()
    assert calls[0]["client"]["verify"] is True
    assert calls[0]["client"]["follow_redirects"] is False
    assert "Idempotency-Key" not in calls[0]["headers"]
    assert "X-SignalRoom-Event" not in calls[0]["headers"]
    scheme, encoded = calls[0]["headers"]["Authorization"].split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == (
        "analyst@example.com:jira-api-token"
    )
    attempted = [
        event
        for event in audit.events()
        if event["event_type"] == "delivery.attempted"
    ]
    assert attempted[0]["metadata"]["external_record_key"] == "SEC-42"
    assert attempted[0]["outcome"] == "delivered"

    with store.connect() as db:
        db.execute(
            "UPDATE delivery_jobs SET status='sending',delivered_at=NULL WHERE id=?",
            (job["id"],),
        )
    recovered = store.recover_interrupted()
    assert recovered == {"correlated": 1, "uncertain": 0, "retrying": 0}
    recovered_job = store.get(job["id"])
    assert recovered_job is not None and recovered_job["status"] == "delivered"
    assert recovered_job["external_record"]["key"] == "SEC-42"


async def delivered_jira_for_reconciliation(
    tmp_path,
    responses: list[FakeJiraIssueResponse],
    calls: list[dict[str, Any]],
) -> tuple[
    AssuranceDeliveryService,
    DeliveryStore,
    AuditStore,
    dict[str, Any],
    dict[str, Any],
]:
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    audit = AuditStore(tmp_path / "audit.db")
    store = DeliveryStore(tmp_path / "delivery.db")

    class ReconciliationClient(FakeDeliveryClient):
        async def post(
            self, url: str, *, content: bytes, headers: dict[str, str]
        ) -> FakeJiraResponse:
            self.calls.append(
                {
                    "method": "POST",
                    "url": url,
                    "content": content,
                    "headers": headers,
                    "client": self.kwargs,
                }
            )
            return FakeJiraResponse()

        async def get(
            self, url: str, *, headers: dict[str, str]
        ) -> FakeJiraIssueResponse:
            self.calls.append(
                {
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    "client": self.kwargs,
                }
            )
            return responses.pop(0)

    service = AssuranceDeliveryService(
        store,
        assurance,
        config,
        audit,
        client_factory=lambda **kwargs: ReconciliationClient(calls, **kwargs),
    )
    service.update_policy(jira_policy())
    preview = service.preview(package["id"])
    job = service.approve(package["id"], preview["payload_sha256"])
    await service._deliver(job)
    return service, store, audit, store.get(job["id"]), preview


def jira_issue_observation(
    correlation_label: str,
    *,
    issue_id: str = "10042",
    issue_key: str = "SEC-42",
    project_key: str = "SEC",
    status_id: str = "3",
    status_name: str = "In Progress",
    status_category: str = "indeterminate",
    priority_name: str = "High",
    resolution: dict[str, str] | None = None,
    include_correlation: bool = True,
) -> dict[str, Any]:
    return {
        "id": issue_id,
        "key": issue_key,
        "self": "https://untrusted.example/rest/api/3/issue/10042",
        "fields": {
            "summary": "This field was not requested and must not be retained",
            "project": {"id": "10000", "key": project_key},
            "issuetype": {"id": "10001", "name": "Task"},
            "status": {
                "id": status_id,
                "name": status_name,
                "statusCategory": {
                    "key": status_category,
                    "name": status_name,
                },
            },
            "priority": {"id": "2", "name": priority_name},
            "resolution": resolution,
            "updated": "2026-07-18T12:30:00.000-0400",
            "labels": [correlation_label] if include_correlation else [],
            "description": "Sensitive content must not be retained",
            "comment": {"comments": [{"body": "Sensitive comment"}]},
        },
    }


@pytest.mark.asyncio
async def test_jira_reconciliation_reads_minimal_fields_and_preserves_material_drift(
    tmp_path,
):
    calls: list[dict[str, Any]] = []
    responses: list[FakeJiraIssueResponse] = []
    service, store, audit, job, preview = await delivered_jira_for_reconciliation(
        tmp_path, responses, calls
    )
    assert job is not None
    correlation_label = next(
        label
        for label in preview["payload"]["fields"]["labels"]
        if label.startswith("signalroom-")
    )
    responses.extend(
        [
            FakeJiraIssueResponse(
                200, jira_issue_observation(correlation_label)
            ),
            FakeJiraIssueResponse(
                200,
                jira_issue_observation(
                    correlation_label,
                    issue_key="OPS-42",
                    project_key="OPS",
                    status_id="6",
                    status_name="Done",
                    status_category="done",
                    priority_name="Medium",
                    resolution={"id": "1", "name": "Fixed"},
                    include_correlation=False,
                ),
            ),
        ]
    )

    baseline = await service.reconcile(job["id"])
    changed = await service.reconcile(job["id"])

    get_calls = [call for call in calls if call["method"] == "GET"]
    assert len(get_calls) == 2
    assert get_calls[0]["url"].startswith(
        "https://security-team.atlassian.net/rest/api/3/issue/10042?"
    )
    assert "fields=status%2Cpriority%2Cresolution%2Cupdated%2Cproject%2Cissuetype%2Clabels" in (
        get_calls[0]["url"]
    )
    assert "summary" not in get_calls[0]["url"]
    assert "description" not in get_calls[0]["url"]
    assert "comments" not in get_calls[0]["url"]
    assert get_calls[0]["client"]["verify"] is True
    assert get_calls[0]["client"]["follow_redirects"] is False
    assert get_calls[0]["client"]["trust_env"] is False
    assert baseline["outcome"] == "observed"
    assert baseline["drift"]["baseline"] == "established"
    assert baseline["drift"]["changed"] is False
    assert baseline["snapshot"]["browse_url"] == (
        "https://security-team.atlassian.net/browse/SEC-42"
    )
    serialized = json.dumps(baseline["snapshot"])
    assert "Sensitive" not in serialized
    assert "summary" not in serialized
    assert "description" not in serialized
    assert "comment" not in serialized
    assert "untrusted.example" not in serialized
    assert changed["snapshot"]["browse_url"] == (
        "https://security-team.atlassian.net/browse/OPS-42"
    )
    assert changed["snapshot"]["correlation_label_present"] is False
    assert changed["drift"]["changed"] is True
    changed_fields = {
        item["field"] for item in changed["drift"]["changes"]
    }
    assert {
        "issue_key",
        "project_key",
        "status",
        "priority",
        "resolution",
        "correlation_label_present",
    } <= changed_fields
    current = store.get(job["id"])
    assert current is not None
    assert len(current["reconciliations"]) == 2
    assert current["latest_reconciliation"]["id"] == changed["id"]
    assert current["reconciliations"][1]["snapshot_sha256"] == (
        baseline["snapshot_sha256"]
    )
    reconciled_events = [
        event
        for event in audit.events()
        if event["event_type"] == "delivery.external.reconciled"
    ]
    assert len(reconciled_events) == 2
    assert reconciled_events[0]["metadata"]["snapshot_sha256"]
    assert max(event["metadata"]["drift_count"] for event in reconciled_events) >= 6


@pytest.mark.asyncio
async def test_jira_reconciliation_preserves_ambiguous_visibility_and_fails_closed(
    tmp_path,
):
    calls: list[dict[str, Any]] = []
    responses: list[FakeJiraIssueResponse] = []
    service, store, _, job, preview = await delivered_jira_for_reconciliation(
        tmp_path, responses, calls
    )
    assert job is not None
    correlation_label = next(
        label
        for label in preview["payload"]["fields"]["labels"]
        if label.startswith("signalroom-")
    )
    responses.extend(
        [
            FakeJiraIssueResponse(
                200, jira_issue_observation(correlation_label)
            ),
            FakeJiraIssueResponse(404),
            FakeJiraIssueResponse(
                200,
                jira_issue_observation(
                    correlation_label, issue_id="99999"
                ),
            ),
        ]
    )
    await service.reconcile(job["id"])

    hidden = await service.reconcile(job["id"])
    assert hidden["outcome"] == "not-found-or-not-visible"
    assert "missing" in hidden["error"]
    assert "permitted" in hidden["error"]
    assert hidden["snapshot"] == {}
    assert hidden["drift"]["changes"][0]["field"] == "availability"

    mismatched = await service.reconcile(job["id"])
    assert mismatched["outcome"] == "identity-mismatch"
    assert mismatched["snapshot"] == {}
    assert "did not match" in mismatched["error"]
    assert len(store.get(job["id"])["reconciliations"]) == 3

    service.update_policy(
        jira_policy(webhook_url="https://other-team.atlassian.net")
    )
    get_count = len([call for call in calls if call["method"] == "GET"])
    with pytest.raises(ValueError, match="destination or credentials changed"):
        await service.reconcile(job["id"])
    assert len([call for call in calls if call["method"] == "GET"]) == get_count


@pytest.mark.asyncio
async def test_jira_unknown_create_outcome_stops_automatic_retry_and_restart(
    tmp_path,
):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    store = DeliveryStore(tmp_path / "delivery.db")

    class UnknownJiraClient(FakeDeliveryClient):
        async def post(
            self, url: str, *, content: bytes, headers: dict[str, str]
        ) -> FakeResponse:
            raise httpx.ReadTimeout("response not received")

    service = AssuranceDeliveryService(
        store,
        assurance,
        ConfigStore(tmp_path / "config"),
        AuditStore(tmp_path / "audit.db"),
        client_factory=lambda **kwargs: UnknownJiraClient([], **kwargs),
    )
    service.update_policy(jira_policy(max_attempts=8))
    preview = service.preview(package["id"])
    job = service.approve(package["id"], preview["payload_sha256"])

    await service._deliver(job)

    failed = store.get(job["id"])
    assert failed is not None and failed["status"] == "failed"
    assert failed["attempt_count"] == 1
    assert failed["next_attempt_at"] is None
    assert "outcome is unknown" in failed["last_error"]
    assert "explicit retry" in failed["last_error"]

    retried = service.retry(job["id"])
    assert retried["status"] == "queued"
    assert retried["max_attempts"] == 2
    sending = store.mark_sending(job["id"])
    assert sending is not None
    recovered = store.recover_interrupted()
    assert recovered == {"correlated": 0, "uncertain": 1, "retrying": 0}
    after_restart = store.get(job["id"])
    assert after_restart is not None and after_restart["status"] == "failed"
    assert "unknown" in after_restart["last_error"]


@pytest.mark.asyncio
async def test_jira_destination_test_reads_metadata_without_creating_issue(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    calls: list[dict[str, Any]] = []

    class MetadataResponse:
        status_code = 200

        @staticmethod
        def json() -> dict[str, list[dict[str, str]]]:
            return {"issueTypes": [{"id": "10001", "name": "Task"}]}

    class MetadataClient(FakeDeliveryClient):
        async def get(
            self, url: str, *, headers: dict[str, str]
        ) -> MetadataResponse:
            self.calls.append(
                {
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    "client": self.kwargs,
                }
            )
            return MetadataResponse()

        async def post(
            self, url: str, *, content: bytes, headers: dict[str, str]
        ) -> FakeResponse:
            raise AssertionError("The destination test must not create a Jira issue")

    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"),
        assurance,
        ConfigStore(tmp_path / "config"),
        AuditStore(tmp_path / "audit.db"),
        client_factory=lambda **kwargs: MetadataClient(calls, **kwargs),
    )
    service.update_policy(jira_policy())

    result = await service.test_destination()

    assert result["ok"] is True
    assert result["authority"] == "read-create-metadata-only"
    assert result["available_issue_types"] == ["Task"]
    assert calls[0]["method"] == "GET"
    assert calls[0]["url"].endswith(
        "/rest/api/3/issue/createmeta/SEC/issuetypes"
    )
    assert calls[0]["client"]["verify"] is True
    assert calls[0]["client"]["follow_redirects"] is False


def test_soar_adapter_builds_bounded_create_only_container_payload(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    config = ConfigStore(tmp_path / "config")
    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"),
        assurance,
        config,
        AuditStore(tmp_path / "audit.db"),
    )

    for invalid_url in (
        "http://soar.internal",
        "https://soar.internal/rest/container",
        "https://user:password@soar.internal",
        "https://soar.internal?redirect=true",
    ):
        with pytest.raises(ValueError):
            service.update_policy(soar_policy(webhook_url=invalid_url))
    with pytest.raises(ValueError, match="tags"):
        service.update_policy(soar_policy(soar_tags=["not\nprintable"]))
    with pytest.raises(ValueError, match="auth token"):
        service.update_policy(soar_policy(soar_auth_token="token with spaces"))

    overview = service.update_policy(soar_policy())
    assert overview["destination"]["configured"] is True
    assert overview["destination"]["authorization_supported"] is False
    assert overview["destination"]["soar_auth_token_configured"] is True
    assert overview["destination"]["transport"] == (
        "encrypted without certificate verification"
    )
    assert overview["worker"]["external_authority"] == "create-container-only"
    assert overview["worker"]["external_read_authority"] == (
        "read-container-options-only"
    )
    assert "soar_auth_token" not in overview["destination"]

    preview = service.preview(package["id"])
    payload = preview["payload"]
    serialized = json.dumps(payload)

    assert payload["name"].startswith("[SignalRoom] [HIGH] Assurance response")
    assert payload["label"] == "events"
    assert payload["severity"] == "high"
    assert payload["sensitivity"] == "amber"
    assert payload["status"] == "new"
    assert payload["container_type"] == "default"
    assert payload["tenant_id"] == "tenant-blue"
    assert payload["tags"] == ["signalroom", "security-assurance"]
    assert payload["run_automation"] is False
    assert payload["source_data_identifier"] == (
        f"signalroom-{preview['correlation_id']}"
    )
    assert "artifacts" not in payload
    assert "data" not in payload
    assert "Identity telemetry coverage changed" not in serialized
    assert "Raw environment detail" not in serialized
    assert "vpn-authentication" not in serialized
    assert "Assurance response · identity coverage" not in serialized
    assert preview["authority"]["external_create"] is True
    assert "automation disabled" in preview["destination"]["delivery_semantics"]
    assert any("no artifacts" in warning for warning in preview["warnings"])

    service.update_policy(
        soar_policy(webhook_url=None, redaction_level="standard")
    )
    standard = json.dumps(service.preview(package["id"])["payload"])
    assert "Identity telemetry coverage changed" in standard
    assert "vpn-authentication" in standard
    assert "Raw environment detail" not in standard


@pytest.mark.asyncio
async def test_soar_worker_creates_or_recovers_container_without_expanded_authority(
    tmp_path,
):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)

    class SoarResponse:
        def __init__(self, status_code: int, value: dict[str, Any]):
            self.status_code = status_code
            self.value = value

        def json(self) -> dict[str, Any]:
            return self.value

    async def deliver(
        root: str, response: SoarResponse
    ) -> tuple[dict[str, Any], dict[str, Any], DeliveryStore]:
        calls: list[dict[str, Any]] = []

        class SoarClient(FakeDeliveryClient):
            async def post(
                self, url: str, *, content: bytes, headers: dict[str, str]
            ) -> SoarResponse:
                self.calls.append(
                    {
                        "url": url,
                        "content": content,
                        "headers": headers,
                        "client": self.kwargs,
                    }
                )
                return response

        store = DeliveryStore(tmp_path / root / "delivery.db")
        service = AssuranceDeliveryService(
            store,
            assurance,
            ConfigStore(tmp_path / root / "config"),
            AuditStore(tmp_path / root / "audit.db"),
            client_factory=lambda **kwargs: SoarClient(calls, **kwargs),
        )
        service.update_policy(soar_policy())
        preview = service.preview(package["id"])
        job = service.approve(package["id"], preview["payload_sha256"])
        await service._deliver(job)
        assert len(calls) == 1
        return store.get(job["id"]), calls[0], store

    created, create_call, create_store = await deliver(
        "created", SoarResponse(200, {"id": 52, "success": True})
    )
    assert created["status"] == "delivered"
    assert created["external_record"]["id"] == "52"
    assert created["external_record"]["key"] == "Container 52"
    assert created["external_record"]["url"] == (
        "https://soar.internal:8443/mission/52"
    )
    assert create_call["url"] == "https://soar.internal:8443/rest/container"
    assert create_call["headers"]["ph-auth-token"] == "soar-auth-token"
    assert "Authorization" not in create_call["headers"]
    assert "Idempotency-Key" not in create_call["headers"]
    assert create_call["client"]["verify"] is False
    sent = json.loads(create_call["content"])
    assert sent["run_automation"] is False
    assert "artifacts" not in sent

    duplicate, _, _ = await deliver(
        "duplicate",
        SoarResponse(
            409,
            {
                "failed": True,
                "existing_container_id": 87,
                "message": (
                    "duplicate container with matching source_data_identifier"
                ),
            },
        ),
    )
    assert duplicate["status"] == "delivered"
    assert duplicate["external_record"]["key"] == "Container 87"

    contradictory, _, _ = await deliver(
        "contradictory", SoarResponse(400, {"id": 99, "success": True})
    )
    assert contradictory["status"] == "failed"
    assert contradictory["external_record"] is None
    assert "contradictory success body" in contradictory["last_error"]

    with create_store.connect() as db:
        db.execute(
            "UPDATE delivery_jobs SET status='sending',delivered_at=NULL WHERE id=?",
            (created["id"],),
        )
    assert create_store.recover_interrupted() == {
        "correlated": 1,
        "uncertain": 0,
        "retrying": 0,
    }


@pytest.mark.asyncio
async def test_soar_ambiguous_create_uses_bounded_source_identifier_retry(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    package = package_fixture(assurance)
    store = DeliveryStore(tmp_path / "delivery.db")

    class UnknownSoarClient(FakeDeliveryClient):
        async def post(
            self, url: str, *, content: bytes, headers: dict[str, str]
        ) -> FakeResponse:
            raise httpx.ReadTimeout("response not received")

    service = AssuranceDeliveryService(
        store,
        assurance,
        ConfigStore(tmp_path / "config"),
        AuditStore(tmp_path / "audit.db"),
        client_factory=lambda **kwargs: UnknownSoarClient([], **kwargs),
    )
    service.update_policy(soar_policy(max_attempts=3))
    preview = service.preview(package["id"])
    job = service.approve(package["id"], preview["payload_sha256"])

    await service._deliver(job)

    retrying = store.get(job["id"])
    assert retrying["status"] == "retrying"
    assert retrying["attempt_count"] == 1
    assert retrying["next_attempt_at"]
    assert "same deterministic source data identifier" in retrying["last_error"]


@pytest.mark.asyncio
async def test_soar_destination_test_reads_options_without_creating_container(tmp_path):
    assurance = AssuranceStore(tmp_path / "assurance.db")
    calls: list[dict[str, Any]] = []

    class OptionsResponse:
        status_code = 200

        @staticmethod
        def json() -> dict[str, Any]:
            return {
                "label": ["events", "incident"],
                "status": [{"name": "new"}, {"name": "closed"}],
                "severity": [
                    {"name": "high"},
                    {"name": "medium"},
                    {"name": "low"},
                ],
                "sensitivity": [["amber", "TLP:Amber"], ["green", "TLP:Green"]],
            }

    class OptionsClient(FakeDeliveryClient):
        async def get(
            self, url: str, *, headers: dict[str, str]
        ) -> OptionsResponse:
            self.calls.append(
                {
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    "client": self.kwargs,
                }
            )
            return OptionsResponse()

        async def post(
            self, url: str, *, content: bytes, headers: dict[str, str]
        ) -> FakeResponse:
            raise AssertionError(
                "The destination test must not create a Splunk SOAR container"
            )

    service = AssuranceDeliveryService(
        DeliveryStore(tmp_path / "delivery.db"),
        assurance,
        ConfigStore(tmp_path / "config"),
        AuditStore(tmp_path / "audit.db"),
        client_factory=lambda **kwargs: OptionsClient(calls, **kwargs),
    )
    service.update_policy(soar_policy())

    result = await service.test_destination()

    assert result["ok"] is True
    assert result["authority"] == "read-container-options-only"
    assert result["availability"] == {
        "label": True,
        "status": True,
        "sensitivity": True,
        "severity_map": True,
    }
    assert calls[0]["method"] == "GET"
    assert calls[0]["url"].endswith("/rest/container_options")
    assert calls[0]["headers"]["ph-auth-token"] == "soar-auth-token"
    assert calls[0]["client"]["verify"] is False
    assert calls[0]["client"]["follow_redirects"] is False
