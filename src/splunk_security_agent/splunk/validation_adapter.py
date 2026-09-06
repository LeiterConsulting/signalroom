from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from .context_engine import SplContextEngine
from .guardrails import validate_read_only_spl
from .mcp_client import TOOL_ALIASES


class SplValidationAdapter:
    """Bind optional Splunk parser/SAIA checks and result-shape validation to one query."""

    CONTRACT = "signalroom.spl-validation.v1"
    PARSER_NAMES = tuple(TOOL_ALIASES["validate_spl"])
    SAIA_NAMES = tuple(
        dict.fromkeys([*TOOL_ALIASES["optimize_spl"], *TOOL_ALIASES["explain_spl"]])
    )

    async def capabilities(self, client: Any) -> dict[str, Any]:
        discovery_client = getattr(client, "client", client)
        if not callable(getattr(discovery_client, "list_tools", None)):
            return {
                "status": "ready",
                "parser": {"available": False, "tool": "", "schema": {}},
                "saia": {"available": False, "tool": "", "schema": {}},
                "tool_count": 0,
                "contract": self.CONTRACT,
                "legacy_client": True,
            }
        try:
            tools = await discovery_client.list_tools()
        except Exception as exc:
            return {
                "status": "error",
                "error": f"Unable to discover Splunk MCP validation capabilities: {exc}",
                "parser": {"available": False, "tool": ""},
                "saia": {"available": False, "tool": ""},
                "tool_count": 0,
            }
        by_name = {
            str(item.get("name") or ""): item
            for item in tools
            if isinstance(item, dict) and item.get("name")
        }
        parser_name = self._first_available(by_name, self.PARSER_NAMES)
        saia_name = self._first_available(by_name, self.SAIA_NAMES)
        return {
            "status": "ready",
            "parser": self._capability(by_name, parser_name),
            "saia": self._capability(by_name, saia_name),
            "tool_count": len(by_name),
            "contract": self.CONTRACT,
        }

    async def preflight(
        self,
        task: Any,
        client: Any,
        *,
        include_saia: bool = False,
    ) -> dict[str, Any]:
        checked_at = datetime.now(UTC).isoformat()
        checks: list[dict[str, str]] = []
        try:
            validate_read_only_spl(str(task.spl))
            checks.append(self._check("local-read-only", "passed", "Local read-only policy passed."))
        except ValueError as exc:
            checks.append(self._check("local-read-only", "blocked", str(exc)))
            return self._receipt(task, "blocked", checked_at, checks)

        capabilities = await self.capabilities(client)
        if capabilities["status"] == "error":
            checks.append(self._check("mcp-capabilities", "blocked", capabilities["error"]))
            return self._receipt(
                task,
                "blocked",
                checked_at,
                checks,
                capabilities=capabilities,
            )
        checks.append(
            self._check(
                "mcp-capabilities",
                "passed",
                f"Inspected {capabilities['tool_count']} tools on the exact Splunk connection.",
            )
        )

        parser = capabilities["parser"]
        parser_result: dict[str, Any]
        if parser["available"]:
            parser_result = await self._invoke_check(client, parser, task, "parser")
            checks.append(
                self._check(
                    "splunk-parser",
                    (
                        "passed"
                        if parser_result["status"] == "passed"
                        else "blocked"
                        if parser_result["status"] == "blocked"
                        else "pending"
                    ),
                    parser_result["summary"],
                )
            )
        else:
            parser_result = {
                "status": "unavailable",
                "tool": "",
                "summary": (
                    "This MCP server does not advertise a compatible Splunk parser tool. "
                    "Runtime validation remains required."
                ),
            }
            checks.append(self._check("splunk-parser", "pending", parser_result["summary"]))

        saia_result: dict[str, Any]
        saia = capabilities["saia"]
        if include_saia and saia["available"]:
            saia_result = await self._invoke_check(client, saia, task, "saia")
            checks.append(
                self._check(
                    "saia-critique",
                    "passed" if saia_result["status"] == "passed" else "pending",
                    saia_result["summary"],
                )
            )
        elif include_saia:
            saia_result = {
                "status": "unavailable",
                "tool": "",
                "summary": "No compatible Splunk AI Assistant SPL tool is advertised.",
            }
            checks.append(self._check("saia-critique", "pending", saia_result["summary"]))
        else:
            saia_result = {
                "status": "not-requested",
                "tool": str(saia.get("tool") or ""),
                "summary": "Optional SAIA critique was not requested.",
            }

        status = (
            "blocked"
            if parser_result["status"] == "blocked"
            else "passed"
            if parser_result["status"] == "passed"
            else "advisory-only"
        )
        return self._receipt(
            task,
            status,
            checked_at,
            checks,
            capabilities=capabilities,
            parser=parser_result,
            saia=saia_result,
        )

    @classmethod
    def compare_result_shape(
        cls,
        task: Any,
        rows: list[Any],
    ) -> dict[str, Any]:
        profile = SplContextEngine.profile_result_shape(rows)
        contract = task.result_contract if isinstance(task.result_contract, dict) else {}
        expected = [
            str(value)
            for value in contract.get("expected_fields", [])
            if str(value).strip()
        ]
        observed = [
            str(item.get("name") or "")
            for item in profile.get("fields", [])
            if isinstance(item, dict) and item.get("name")
        ]
        observed_lookup = {value.lower(): value for value in observed}
        missing = [value for value in expected if value.lower() not in observed_lookup]
        expected_lookup = {value.lower() for value in expected}
        unexpected = [value for value in observed if value.lower() not in expected_lookup]
        over_limit = len(rows) > int(task.row_limit)
        if expected and not rows:
            status = "inconclusive-zero-rows"
        elif over_limit or missing:
            status = "mismatch"
        elif expected:
            status = "matched"
        else:
            status = "observed-no-field-contract"
        return {
            "contract": cls.CONTRACT,
            "status": status,
            "query_fingerprint": str(task.query_fingerprint),
            "expected_operation": str(contract.get("operation") or "unspecified"),
            "expected_fields": expected[:80],
            "observed_fields": observed[:160],
            "missing_fields": missing[:80],
            "unexpected_fields": unexpected[:80],
            "row_count": len(rows),
            "row_limit": int(task.row_limit),
            "row_limit_observed": not over_limit,
            "field_types": {
                str(item.get("name") or ""): list(item.get("types") or [])[:8]
                for item in profile.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            },
            "raw_values_included": False,
            "checked_at": datetime.now(UTC).isoformat(),
        }

    async def _invoke_check(
        self,
        client: Any,
        capability: dict[str, Any],
        task: Any,
        kind: str,
    ) -> dict[str, Any]:
        tool = str(capability["tool"])
        arguments = self._arguments(capability.get("schema") or {}, task, kind)
        try:
            result = await client.call(tool, arguments)
        except Exception as exc:
            return {
                "status": "blocked" if kind == "parser" else "error",
                "tool": tool,
                "summary": f"{tool} failed: {exc}",
            }
        validity = self._explicit_validity(result)
        if validity is False:
            status = "blocked" if kind == "parser" else "error"
        elif kind == "parser" and validity is None:
            status = "inconclusive"
        else:
            status = "passed"
        summary = self._safe_summary(result)
        if validity is False and not summary:
            summary = f"{tool} rejected the query."
        elif kind == "parser" and validity is None and not summary:
            summary = f"{tool} returned no explicit valid or invalid decision."
        elif not summary:
            summary = f"{tool} completed without returning event rows."
        return {"status": status, "tool": tool, "summary": summary[:4000]}

    @staticmethod
    def _arguments(schema: dict[str, Any], task: Any, kind: str) -> dict[str, Any]:
        properties = schema.get("properties") if isinstance(schema, dict) else {}
        properties = properties if isinstance(properties, dict) else {}
        query_keys = ("query", "spl", "search", "search_query")
        query_key = next((key for key in query_keys if key in properties), "query")
        arguments: dict[str, Any] = {query_key: str(task.spl)}
        optional = {
            "earliest_time": str(task.earliest_time),
            "latest_time": str(task.latest_time),
            "row_limit": int(task.row_limit),
        }
        for key, value in optional.items():
            if key in properties:
                arguments[key] = value
        if kind == "saia":
            for key in ("prompt", "instruction", "question"):
                if key in properties:
                    arguments[key] = (
                        "Critique this SPL for semantic correctness and likely field or command "
                        "issues. Do not execute it and do not use event samples."
                    )
                    break
        return arguments

    @classmethod
    def _safe_summary(cls, value: Any) -> str:
        text_keys = {
            "message",
            "messages",
            "summary",
            "detail",
            "details",
            "explanation",
            "recommendation",
            "recommendations",
            "warning",
            "warnings",
            "error",
            "errors",
        }
        status_keys = {"status", "valid", "is_valid", "ok", "success", "status_code"}
        values: list[str] = []

        def collect_text(item: Any, depth: int = 0) -> None:
            if depth > 4 or sum(len(value) for value in values) >= 4000:
                return
            if isinstance(item, str):
                values.append(item[:4000])
            elif isinstance(item, (int, float, bool)):
                values.append(str(item))
            elif isinstance(item, dict):
                for key, nested in list(item.items())[:40]:
                    normalized = str(key).lower()
                    if normalized in text_keys:
                        collect_text(nested, depth + 1)
            elif isinstance(item, list):
                for nested in item[:20]:
                    collect_text(nested, depth + 1)

        if isinstance(value, dict):
            for key, item in list(value.items())[:60]:
                normalized = str(key).lower()
                if normalized in text_keys:
                    collect_text(item)
                elif normalized in status_keys and isinstance(item, (str, int, float, bool)):
                    values.append(f"{key}: {str(item)[:1000]}")
        elif isinstance(value, str):
            values.append(value[:4000])
        return " · ".join(dict.fromkeys(item.strip() for item in values if item.strip()))[:4000]

    @classmethod
    def _explicit_validity(cls, value: Any) -> bool | None:
        if isinstance(value, list):
            decisions = [cls._explicit_validity(item) for item in value]
            return False if False in decisions else True if True in decisions else None
        if not isinstance(value, dict):
            if isinstance(value, str) and value.strip().lower().startswith(("invalid", "error")):
                return False
            return None
        status_code = value.get("status_code")
        if status_code is not None:
            try:
                if int(status_code) >= 400:
                    return False
            except (TypeError, ValueError):
                pass
        for key in ("valid", "is_valid", "ok", "success"):
            if isinstance(value.get(key), bool):
                return bool(value[key])
        status = str(value.get("status") or "").strip().lower()
        if status in {"invalid", "failed", "failure", "error", "rejected"}:
            return False
        if status in {"valid", "passed", "success", "ok"}:
            return True
        if value.get("error"):
            return False
        decisions = [cls._explicit_validity(item) for item in value.values()]
        return False if False in decisions else True if True in decisions else None

    @staticmethod
    def _first_available(tools: dict[str, dict[str, Any]], names: tuple[str, ...]) -> str:
        lowered = {name.lower(): name for name in tools}
        return next((lowered[name.lower()] for name in names if name.lower() in lowered), "")

    @staticmethod
    def _capability(tools: dict[str, dict[str, Any]], name: str) -> dict[str, Any]:
        tool = tools.get(name) or {}
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        return {
            "available": bool(name),
            "tool": name,
            "description": str(tool.get("description") or "")[:1000],
            "schema": schema if isinstance(schema, dict) else {},
        }

    @classmethod
    def _receipt(
        cls,
        task: Any,
        status: str,
        checked_at: str,
        checks: list[dict[str, str]],
        *,
        capabilities: dict[str, Any] | None = None,
        parser: dict[str, Any] | None = None,
        saia: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "contract": cls.CONTRACT,
            "status": status,
            "query_fingerprint": str(task.query_fingerprint),
            "connection_alias": str(task.connection_alias),
            "connection_fingerprint": str(task.connection_fingerprint),
            "tenant_scope_id": str(task.tenant_scope_id),
            "checked_at": checked_at,
            "input_contract": "SPL and execution bounds only; no event rows were supplied.",
            "capabilities": capabilities or {},
            "parser": parser or {},
            "saia": saia or {},
            "checks": checks,
            "trusted_for_execution": False,
            "receipt_sha256": cls._fingerprint(
                {
                    "query_fingerprint": str(task.query_fingerprint),
                    "connection_fingerprint": str(task.connection_fingerprint),
                    "status": status,
                    "checked_at": checked_at,
                    "checks": checks,
                }
            ),
        }

    @staticmethod
    def _check(name: str, status: str, detail: str) -> dict[str, str]:
        return {"name": name, "status": status, "detail": detail[:1000]}

    @staticmethod
    def _fingerprint(value: Any) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode()).hexdigest()
