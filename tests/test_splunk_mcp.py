from typing import Any

import httpx
import pytest

from splunk_security_agent.splunk import SplunkMCPClient


def test_mcp_client_can_disable_tls_verification():
    client = SplunkMCPClient("https://splunk-lab.example/services/mcp", verify_ssl=False)
    assert client.verify_ssl is False


def test_mcp_client_accepts_private_ca_bundle():
    client = SplunkMCPClient(
        "https://splunk.example/services/mcp",
        verify_ssl=True,
        ca_bundle="/etc/ssl/certs/organization-ca.pem",
    )
    assert client.verify_ssl == "/etc/ssl/certs/organization-ca.pem"


class FakeMCPTransport:
    calls: list[dict[str, Any]] = []

    def __init__(self, *args: Any, **kwargs: Any):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any):
        return None

    async def post(self, url: str, headers: dict[str, str], json: dict[str, Any]):
        self.calls.append({"method": json["method"], "headers": headers})
        request = httpx.Request("POST", url)
        if json["method"] == "initialize":
            return httpx.Response(
                200,
                headers={"Mcp-Session-Id": "session-123"},
                json={
                    "jsonrpc": "2.0",
                    "id": json["id"],
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "serverInfo": {"name": "splunk-mcp", "version": "1.2"},
                    },
                },
                request=request,
            )
        if json["method"] == "notifications/initialized":
            return httpx.Response(202, request=request)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": json["id"], "result": {"tools": [{"name": "run_query"}]}},
            request=request,
        )


@pytest.mark.asyncio
async def test_mcp_client_initializes_and_reuses_session(monkeypatch):
    FakeMCPTransport.calls = []
    monkeypatch.setattr("splunk_security_agent.splunk.mcp_client.httpx.AsyncClient", FakeMCPTransport)
    client = SplunkMCPClient("https://splunk.example:8089/services/mcp", token="encrypted")

    result = await client.health()

    assert result["ok"] is True
    assert [call["method"] for call in FakeMCPTransport.calls] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    assert FakeMCPTransport.calls[1]["headers"]["Mcp-Session-Id"] == "session-123"
    assert result["server"]["name"] == "splunk-mcp"


class MethodNotAllowedTransport(FakeMCPTransport):
    async def post(self, url: str, headers: dict[str, str], json: dict[str, Any]):
        return httpx.Response(405, request=httpx.Request("POST", url))


@pytest.mark.asyncio
async def test_mcp_client_explains_singular_splunk_path(monkeypatch):
    monkeypatch.setattr(
        "splunk_security_agent.splunk.mcp_client.httpx.AsyncClient",
        MethodNotAllowedTransport,
    )
    client = SplunkMCPClient("https://splunk.example:8089/service/mcp")

    result = await client.health()

    assert result["ok"] is False
    assert "/services/mcp (plural)" in result["error"]


@pytest.mark.asyncio
async def test_inventory_calls_use_short_lived_cache():
    client = SplunkMCPClient("https://splunk.example/services/mcp", cache_ttl=60)
    client._tools = [{"name": "splunk_get_indexes"}]
    calls = []

    async def fake_request(method, params):
        calls.append((method, params))
        return {"results": [{"title": "main"}]}

    client._request = fake_request

    first = await client.call("get_indexes", {"row_limit": 10})
    second = await client.call("get_indexes", {"row_limit": 10})

    assert first == second
    assert len(calls) == 1
