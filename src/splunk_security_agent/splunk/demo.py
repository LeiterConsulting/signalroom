from __future__ import annotations

from typing import Any

DEMO_INDEXES = [
    {"title": "_internal", "currentDBSizeMB": 1840, "totalEventCount": 15_300_221},
    {"title": "main", "currentDBSizeMB": 6820, "totalEventCount": 48_829_033},
    {"title": "security", "currentDBSizeMB": 12_420, "totalEventCount": 82_104_911},
    {"title": "cloud", "currentDBSizeMB": 4910, "totalEventCount": 31_405_200},
    {"title": "network", "currentDBSizeMB": 9720, "totalEventCount": 66_182_101},
]


class DemoSplunkClient:
    """Safe first-run client that makes the entire product explorable without a Splunk instance."""

    async def list_tools(self, refresh: bool = False) -> list[dict[str, Any]]:
        return [
            {"name": "splunk_get_info", "description": "Get deployment information"},
            {"name": "splunk_get_indexes", "description": "List indexes"},
            {"name": "splunk_get_metadata", "description": "Get metadata"},
            {"name": "splunk_run_query", "description": "Run read-only SPL"},
        ]

    async def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "demo": True,
            "tool_count": 4,
            "tools": [item["name"] for item in await self.list_tools()],
        }

    async def call(self, logical_name: str, arguments: dict[str, Any] | None = None) -> Any:
        arguments = arguments or {}
        if logical_name == "get_info":
            return {
                "version": "9.3.1",
                "build": "demo",
                "server_roles": ["search_head"],
                "license_state": "VALID",
            }
        if logical_name == "get_indexes":
            return DEMO_INDEXES
        if logical_name == "get_metadata":
            metadata_type = arguments.get("type", "sourcetypes")
            values = {
                "sourcetypes": [
                    "WinEventLog:Security",
                    "aws:cloudtrail",
                    "pan:traffic",
                    "crowdstrike:events:sensor",
                ],
                "hosts": ["dc-01", "web-prod-04", "vpn-gw-01", "aws-org"],
                "sources": ["WinEventLog:Security", "cloudtrail", "pan:traffic", "falcon"],
            }
            return [
                {"value": value, "count": (index + 1) * 12000}
                for index, value in enumerate(values.get(metadata_type, []))
            ]
        if logical_name == "get_knowledge_objects":
            return {"saved_searches": 84, "alerts": 21, "dashboards": 17, "macros": 11}
        if logical_name == "run_query":
            query = arguments.get("query") or arguments.get("search") or ""
            return {
                "query": query,
                "results": [],
                "messages": ["Demo mode: query validated but not executed."],
            }
        raise ValueError(f"Unsupported demo tool: {logical_name}")
