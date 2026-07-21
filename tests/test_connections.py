from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from splunk_security_agent.assurance import AssuranceStore
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.connections import ConnectionRegistryStore
from splunk_security_agent.discovery import DiscoveryJobService, DiscoveryJobStore
from splunk_security_agent.forecasting import TimeSeriesScheduleStore
from splunk_security_agent.schemas import (
    SplunkConnection,
    TimeSeriesForecastRequest,
    TimeSeriesScheduleCreate,
)


def _connection(
    *,
    url: str = "https://SPLUNK.example:8089/services/mcp/",
    verify: bool = True,
    ca_bundle: str | None = None,
    name: str = "Production",
) -> SplunkConnection:
    return SplunkConnection(name=name, url=url, verify_ssl=verify, ca_bundle=ca_bundle)


def _schedule() -> TimeSeriesScheduleCreate:
    return TimeSeriesScheduleCreate(
        title="Authentication volume",
        request=TimeSeriesForecastRequest(
            spl="index=auth | timechart span=5m count as value",
        ),
        enabled=True,
    )


def test_connection_identity_is_canonical_immutable_and_secret_free(tmp_path: Path):
    store = ConnectionRegistryStore(tmp_path / "connections.db")
    first = store.sync_primary(_connection(), demo_mode=False)
    renamed = store.sync_primary(
        _connection(
            url="https://splunk.example:8089/service/mcp",
            name="Renamed display label",
        ),
        demo_mode=False,
    )

    assert renamed["fingerprint"] == first["fingerprint"]
    assert renamed["endpoint"] == "https://splunk.example:8089/services/mcp"
    assert renamed["display_name"] == "Renamed display label"
    assert "token" not in str(store.overview()).lower()

    changed = store.sync_primary(_connection(verify=False), demo_mode=False)
    assert changed["fingerprint"] != first["fingerprint"]
    assert changed["supersedes_fingerprint"] == first["fingerprint"]
    valid, detail = store.validate(
        first["alias"],
        first["fingerprint"],
        first["tenant_scope_id"],
    )
    assert valid is False
    assert changed["fingerprint"][:12] in detail
    assert len(store.overview()["revisions"]) == 2


def test_additional_connection_requires_exact_diagnostics_before_admission(tmp_path: Path):
    store = ConnectionRegistryStore(tmp_path / "connections.db")
    store.sync_primary(_connection(), demo_mode=False)
    draft = store.upsert_managed(
        "eu-prod",
        "tenant.eu-prod",
        _connection(name="EU Production", url="https://eu.example:8089/services/mcp"),
        credentials_changed=True,
    )

    assert draft["enabled"] is False
    assert store.overview()["execution_scopes"] == [store.current("primary")]
    with pytest.raises(ValueError, match="successful diagnostics"):
        store.set_enabled("eu-prod", True)

    store.record_diagnostic(
        "eu-prod",
        draft["fingerprint"],
        ready=True,
        checked_at="2026-07-20T12:00:00+00:00",
    )
    admitted = store.set_enabled("eu-prod", True)
    assert admitted["enabled"] is True
    assert [item["alias"] for item in store.overview()["execution_scopes"]] == [
        "primary",
        "eu-prod",
    ]

    changed = store.upsert_managed(
        "eu-prod",
        "tenant.eu-prod",
        _connection(
            name="EU Production",
            url="https://eu.example:8089/services/mcp",
            verify=False,
        ),
    )
    assert changed["fingerprint"] != draft["fingerprint"]
    assert changed["enabled"] is False
    valid, detail = store.validate(
        "eu-prod", changed["fingerprint"], changed["tenant_scope_id"]
    )
    assert valid is False
    assert "disabled pending admission" in detail


def test_additional_connection_token_is_encrypted_and_archive_retains_identity(tmp_path: Path):
    config = ConfigStore(tmp_path / "data")
    config.update_secrets(**{"splunk_token:eu-prod": "mcp-secret-token"})
    assert config.secret("splunk_token:eu-prod") == "mcp-secret-token"
    assert b"mcp-secret-token" not in (tmp_path / "data" / "secrets.enc").read_bytes()

    store = ConnectionRegistryStore(tmp_path / "connections.db")
    store.sync_primary(_connection(), demo_mode=False)
    draft = store.upsert_managed(
        "eu-prod",
        "tenant.eu-prod",
        _connection(name="EU Production", url="https://eu.example:8089/services/mcp"),
    )
    archived = store.archive("eu-prod")
    assert archived["archived"] is True
    assert store.identity(draft["fingerprint"])["fingerprint"] == draft["fingerprint"]
    assert store.managed_connections() == []


def test_services_construct_alias_specific_client_and_agent(tmp_path: Path, monkeypatch) -> None:
    from splunk_security_agent import app as app_module

    created: list[tuple[str, str, bool, str | None]] = []

    class FakeSplunkClient:
        def __init__(self, url, token, verify_ssl, ca_bundle, **_kwargs):
            self.url = url
            self.token = token
            self.verify_ssl = verify_ssl
            self.ca_bundle = ca_bundle
            created.append((url, token, verify_ssl, ca_bundle))

    monkeypatch.setattr(app_module, "DATA", tmp_path / "service-data")
    monkeypatch.setattr(app_module, "SplunkMCPClient", FakeSplunkClient)
    services = app_module.Services()
    connection = _connection(
        name="EU Production",
        url="https://eu.example:8089/services/mcp",
    )
    draft = services.connection_registry.upsert_managed(
        "eu-prod", "tenant.eu-prod", connection, credentials_changed=True
    )
    services.config.update_secrets(**{"splunk_token:eu-prod": "alias-token"})
    services.connection_registry.record_diagnostic(
        "eu-prod",
        draft["fingerprint"],
        ready=True,
        checked_at="2026-07-20T12:00:00+00:00",
    )
    admitted = services.connection_registry.set_enabled("eu-prod", True)
    scope = services.resolve_scope(
        "eu-prod", admitted["fingerprint"], admitted["tenant_scope_id"]
    )

    client = services.splunk_for_scope(scope)
    agent = services.agent_for_scope(scope)

    assert client.client.url == "https://eu.example:8089/services/mcp"
    assert client.client.token == "alias-token"
    assert agent.splunk is client
    assert created[-1] == (
        "https://eu.example:8089/services/mcp",
        "alias-token",
        True,
        None,
    )


def test_connection_overview_includes_current_secret_free_diagnostic(tmp_path: Path, monkeypatch) -> None:
    from splunk_security_agent import app as app_module

    monkeypatch.setattr(app_module, "DATA", tmp_path / "service-data")
    services = app_module.Services()
    connection = _connection(
        name="Lab Splunk",
        url="http://192.168.1.52:8089/services/mcp",
        verify=False,
    )
    draft = services.connection_registry.upsert_managed(
        "lab-splunk", "tenant.lab", connection, credentials_changed=True
    )
    services.config.update_secrets(**{"splunk_token:lab-splunk": "encrypted-secret"})
    services.connection_diagnostics_store.record(
        {
            "checked_at": "2026-07-21T12:00:00+00:00",
            "endpoint": connection.url,
            "ready": False,
            "connection_alias": "lab-splunk",
            "connection_fingerprint": draft["fingerprint"],
            "blocking_stage": "mcp",
            "tool_count": 0,
            "stages": [
                {
                    "id": "mcp",
                    "label": "MCP initialization",
                    "status": "error",
                    "detail": "Protocol mismatch.",
                    "remediation": "Use HTTPS.",
                }
            ],
        }
    )

    item = services.connection_overview()["managed_splunk_connections"][0]

    assert item["latest_diagnostic"]["current_revision"] is True
    assert item["latest_diagnostic"]["blocking_stage"] == "mcp"
    assert item["latest_diagnostic"]["stages"][0]["remediation"] == "Use HTTPS."
    assert "encrypted-secret" not in str(item)


def test_rebinding_pauses_schedules_and_assurance_with_exact_concurrency(tmp_path: Path):
    registry = ConnectionRegistryStore(tmp_path / "connections.db")
    first = registry.sync_primary(_connection(), demo_mode=False)
    changed = registry.sync_primary(_connection(verify=False), demo_mode=False)

    schedules = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    schedule = schedules.create(_schedule(), actor="admin", binding=first)
    with pytest.raises(ValueError, match="changed"):
        schedules.rebind(
            schedule["id"],
            changed,
            expected_connection_fingerprint="0" * 64,
            expected_updated_at=schedule["updated_at"],
        )
    rebound = schedules.rebind(
        schedule["id"],
        changed,
        expected_connection_fingerprint=first["fingerprint"],
        expected_updated_at=schedule["updated_at"],
    )
    assert rebound is not None
    assert rebound["enabled"] is False
    assert rebound["next_run_at"] is None
    assert rebound["connection_fingerprint"] == changed["fingerprint"]

    assurance = AssuranceStore(tmp_path / "assurance.db")
    assurance.bind_unbound(first)
    policy = assurance.policy()
    rebound_policy = assurance.rebind_policy(
        changed,
        expected_connection_fingerprint=first["fingerprint"],
        expected_updated_at=policy["updated_at"],
    )
    assert rebound_policy["enabled"] is False
    assert rebound_policy["connection_fingerprint"] == changed["fingerprint"]


@pytest.mark.asyncio
async def test_stale_discovery_job_stops_before_client_creation(tmp_path: Path):
    registry = ConnectionRegistryStore(tmp_path / "connections.db")
    first = registry.sync_primary(_connection(), demo_mode=False)
    registry.sync_primary(_connection(verify=False), demo_mode=False)
    jobs = DiscoveryJobStore(tmp_path / "discovery.db")
    job = jobs.create_job("quick", "analyst", 4, first)
    client_creations = 0

    def client_factory():
        nonlocal client_creations
        client_creations += 1
        raise AssertionError("A stale job must stop before client creation")

    service = DiscoveryJobService(
        jobs,
        client_factory,
        lambda _client: None,
        validate_connection_binding=registry.validate,
        poll_seconds=0.01,
    )
    await service.start()
    service._wake.set()
    for _ in range(100):
        await asyncio.sleep(0.01)
        current = jobs.get_job(job.id)
        if current and current.status == "connection-blocked":
            break
    await service.stop()

    current = jobs.get_job(job.id)
    assert current is not None
    assert current.status == "connection-blocked"
    assert current.calls_used == 0
    assert client_creations == 0
