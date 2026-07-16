from splunk_security_agent.mcp_server import MCPServer
from splunk_security_agent.rag import EvidenceStore


class NeverCalled:
    def __getattr__(self, name):
        raise AssertionError(name)


async def test_mcp_initialize_and_tools_list(tmp_path):
    server = MCPServer(lambda: NeverCalled(), lambda: NeverCalled(), EvidenceStore(tmp_path / "evidence.db"))
    initialized = await server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    listed = await server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    assert initialized["result"]["serverInfo"]["name"] == "splunk-security-agent"
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert {"security_chat", "discover_splunk", "search_context"} <= names


async def test_mcp_unknown_method_returns_jsonrpc_error(tmp_path):
    server = MCPServer(lambda: NeverCalled(), lambda: NeverCalled(), EvidenceStore(tmp_path / "evidence.db"))
    result = await server.handle({"jsonrpc": "2.0", "id": 7, "method": "unknown", "params": {}})
    assert result["error"]["code"] == -32601
