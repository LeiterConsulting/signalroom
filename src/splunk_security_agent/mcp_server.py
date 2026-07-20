from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .schemas import ArtifactCreate, ChatRequest, DiscoveryRequest

SCOPE_PROPERTIES = {
    "connection_alias": {"type": "string", "default": "primary"},
    "connection_fingerprint": {
        "type": "string",
        "description": "Immutable revision of the selected Splunk connection.",
    },
    "tenant_scope_id": {"type": "string", "default": "workspace-primary"},
}

MCP_TOOLS = [
    {
        "name": "security_chat",
        "description": (
            "Discuss Splunk security evidence with model routing, RAG context, and traceable sources."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "conversation_id": {"type": "string"},
                "model_profile": {"type": "string"},
                "include_context": {"type": "boolean", "default": True},
                "huggingface_approved": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Per-query approval for Hugging Face cloud inference when the cloud "
                        "runtime is selected and workspace policy is set to ask. Local "
                        "Transformers specialists do not require approval."
                    ),
                },
                "huggingface_specialist": {
                    "type": "string",
                    "enum": ["embedding", "ner"],
                    "description": "Scope the approved or local specialist pass to one capability.",
                },
                **SCOPE_PROPERTIES,
            },
            "required": ["message"],
        },
    },
    {
        "name": "discover_splunk",
        "description": (
            "Build read-only Splunk security intelligence across telemetry, detections, data models, "
            "freshness, and knowledge objects; reason locally with Ollama and index reusable evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "depth": {"type": "string", "enum": ["quick", "standard", "deep"]},
                **SCOPE_PROPERTIES,
            },
        },
    },
    {
        "name": "search_context",
        "description": "Search local discovery, runbook, SPL, and threat-intelligence evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 6},
                **SCOPE_PROPERTIES,
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_artifacts",
        "description": "List managed contextual artifacts and discovery evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 50}, **SCOPE_PROPERTIES},
        },
    },
    {
        "name": "save_context",
        "description": (
            "Save a text artifact such as a runbook, threat note, or known-good SPL query to local context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "content": {"type": "string"},
                "kind": {"type": "string", "default": "reference"},
                "tags": {"type": "array", "items": {"type": "string"}},
                **SCOPE_PROPERTIES,
            },
            "required": ["title", "content"],
        },
    },
]


class MCPServer:
    def __init__(
        self,
        get_agent: Callable[[], Any],
        get_discovery: Callable[[], Any],
        evidence: Any,
        resolve_scope: Callable[[str, str, str], dict[str, Any]] | None = None,
    ):
        self.get_agent = get_agent
        self.get_discovery = get_discovery
        self.evidence = evidence
        self.resolve_scope = resolve_scope

    def _scope(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.resolve_scope is None:
            return {
                "alias": str(arguments.get("connection_alias") or "primary"),
                "fingerprint": str(arguments.get("connection_fingerprint") or ""),
                "tenant_scope_id": str(arguments.get("tenant_scope_id") or "workspace-primary"),
            }
        return self.resolve_scope(
            str(arguments.get("connection_alias") or "primary"),
            str(arguments.get("connection_fingerprint") or ""),
            str(arguments.get("tenant_scope_id") or "workspace-primary"),
        )

    async def handle(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        request_id = payload.get("id")
        method = payload.get("method", "")
        if method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "splunk-security-agent", "version": "0.1.0"},
                    "instructions": (
                        "Read-only by default. Use security_chat for evidence-led Splunk analysis."
                    ),
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": MCP_TOOLS}
            elif method == "tools/call":
                params = payload.get("params", {})
                output = await self.call_tool(params.get("name", ""), params.get("arguments", {}))
                result = {"content": [{"type": "text", "text": self._serialize(output)}], "isError": False}
            else:
                return self._error(request_id, -32601, f"Method not found: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:
            return self._error(request_id, -32000, str(exc))

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        scope = self._scope(arguments)
        if name == "security_chat":
            request = ChatRequest.model_validate(arguments).model_copy(
                update={
                    "connection_alias": scope["alias"],
                    "connection_fingerprint": scope["fingerprint"],
                    "tenant_scope_id": scope["tenant_scope_id"],
                }
            )
            return (await self.get_agent().chat(request)).model_dump(
                mode="json"
            )
        if name == "discover_splunk":
            request = DiscoveryRequest.model_validate(arguments or {})
            discovery = self.get_discovery()
            discovery.set_scope(scope)
            return await discovery.run(request.depth)
        if name == "search_context":
            return [
                item.model_dump(mode="json")
                for item in self.evidence.search(
                    arguments["query"],
                    arguments.get("limit", 6),
                    tenant_scope_id=scope["tenant_scope_id"],
                )
            ]
        if name == "list_artifacts":
            return [
                item.model_dump(mode="json")
                for item in self.evidence.list(
                    arguments.get("limit", 50),
                    tenant_scope_id=scope["tenant_scope_id"],
                )
            ]
        if name == "save_context":
            record = ArtifactCreate.model_validate(arguments).model_copy(
                update={
                    "connection_alias": scope["alias"],
                    "connection_fingerprint": scope["fingerprint"],
                    "tenant_scope_id": scope["tenant_scope_id"],
                }
            )
            return self.evidence.add(record).model_dump(mode="json")
        raise ValueError(f"Unknown tool: {name}")

    @staticmethod
    def _serialize(value: Any) -> str:
        import json

        return json.dumps(value, indent=2, default=str)

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
