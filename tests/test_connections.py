from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from splunk_security_agent.assurance import AssuranceStore
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
