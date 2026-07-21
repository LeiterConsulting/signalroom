from __future__ import annotations

import pytest

from splunk_security_agent.schemas import SplunkConnection
from splunk_security_agent.splunk import ConnectionDiagnosticsStore, SplunkConnectionDiagnostics


def test_connection_diagnostic_store_keeps_secret_free_latest_and_success(tmp_path):
    store = ConnectionDiagnosticsStore(tmp_path / "connections.db")
    blocked = store.record(
        {
            "checked_at": "2026-07-16T10:00:00+00:00",
            "endpoint": "https://splunk:8089/services/mcp",
            "ready": False,
        }
    )
    ready = store.record(
        {
            "checked_at": "2026-07-16T10:01:00+00:00",
            "endpoint": "https://splunk:8089/services/mcp",
            "ready": True,
        }
    )

    assert store.latest()["id"] == ready["id"]
    assert store.last_success()["id"] == ready["id"]
    assert "token" not in str(blocked).lower()


def test_connection_tool_contract_reports_readiness_by_discovery_depth(tmp_path):
    diagnostics = SplunkConnectionDiagnostics(
        ConnectionDiagnosticsStore(tmp_path / "connections.db")
    )
    readiness, missing = diagnostics._tool_readiness(
        ["server_info", "list_indexes", "metadata"]
    )

    assert readiness == {"quick": True, "standard": False, "deep": False}
    assert missing["quick"] == []
    assert missing["standard"] == ["get_knowledge_objects", "run_query"]


@pytest.mark.asyncio
async def test_demo_diagnostic_is_explicitly_ready_without_network(tmp_path):
    diagnostics = SplunkConnectionDiagnostics(
        ConnectionDiagnosticsStore(tmp_path / "connections.db")
    )

    result = await diagnostics.run(
        SplunkConnection(url="https://splunk:8089/services/mcp"),
        "ignored-secret",
        demo_mode=True,
    )

    assert result["ready"] is True
    assert result["demo"] is True
    assert result["stages"][0]["id"] == "demo"
    assert all(result["depth_readiness"].values())


@pytest.mark.asyncio
async def test_invalid_endpoint_stops_before_network_and_is_durable(tmp_path):
    store = ConnectionDiagnosticsStore(tmp_path / "connections.db")
    diagnostics = SplunkConnectionDiagnostics(store)

    result = await diagnostics.run(SplunkConnection(url="not-an-endpoint"), "secret")

    assert result["ready"] is False
    assert result["blocking_stage"] == "configuration"
    assert len(result["stages"]) == 1
    assert store.latest()["id"] == result["id"]


def test_http_management_port_protocol_mismatch_has_actionable_remediation(tmp_path):
    diagnostics = SplunkConnectionDiagnostics(
        ConnectionDiagnosticsStore(tmp_path / "connections.db")
    )
    error = "Unable to reach the Splunk MCP endpoint: illegal request line"

    assert "protocol mismatch" in diagnostics._mcp_failure_detail(error, "http", 8089)
    remediation = diagnostics._mcp_remediation(
        error,
        "http",
        8089,
        "192.168.1.52",
        "/services/mcp",
    )
    assert "https://192.168.1.52:8089/services/mcp" in remediation
    assert "Disabling TLS verification does not disable HTTPS" in remediation
