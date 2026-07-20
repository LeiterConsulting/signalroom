from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
import ssl
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography import x509

from ..progress import ProgressCallback, report_progress
from ..schemas import SplunkConnection
from .demo import DemoSplunkClient
from .mcp_client import TOOL_ALIASES, SplunkMCPClient

DEPTH_TOOL_CONTRACTS = {
    "quick": {"get_info", "get_indexes", "get_metadata"},
    "standard": {
        "get_info",
        "get_indexes",
        "get_metadata",
        "get_knowledge_objects",
        "run_query",
    },
    "deep": {
        "get_info",
        "get_indexes",
        "get_metadata",
        "get_knowledge_objects",
        "run_query",
    },
}


class ConnectionDiagnosticsStore:
    """Durable, secret-free connection readiness history."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS connection_diagnostics (
                    id TEXT PRIMARY KEY, endpoint TEXT NOT NULL, ready INTEGER NOT NULL,
                    connection_alias TEXT NOT NULL DEFAULT 'primary',
                    connection_fingerprint TEXT NOT NULL DEFAULT '',
                    result TEXT NOT NULL, checked_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_connection_diagnostics_checked
                    ON connection_diagnostics(checked_at DESC);
                """
            )
            columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(connection_diagnostics)")
            }
            if "connection_alias" not in columns:
                db.execute(
                    """ALTER TABLE connection_diagnostics ADD COLUMN connection_alias
                    TEXT NOT NULL DEFAULT 'primary'"""
                )
            if "connection_fingerprint" not in columns:
                db.execute(
                    """ALTER TABLE connection_diagnostics ADD COLUMN connection_fingerprint
                    TEXT NOT NULL DEFAULT ''"""
                )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def record(self, result: dict[str, Any]) -> dict[str, Any]:
        value = {**result, "id": str(uuid4())}
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO connection_diagnostics
                (id,endpoint,ready,connection_alias,connection_fingerprint,result,checked_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    value["id"],
                    str(value.get("endpoint") or "")[:2000],
                    int(bool(value.get("ready"))),
                    str(value.get("connection_alias") or "primary")[:48],
                    str(value.get("connection_fingerprint") or "")[:64],
                    json.dumps(value, default=str),
                    value["checked_at"],
                ),
            )
            db.execute(
                """DELETE FROM connection_diagnostics WHERE id NOT IN
                (SELECT id FROM connection_diagnostics ORDER BY checked_at DESC LIMIT 50)"""
            )
        return value

    def latest(self, connection_alias: str = "") -> dict[str, Any] | None:
        with self.connect() as db:
            row = (
                db.execute(
                    """SELECT result FROM connection_diagnostics WHERE connection_alias=?
                    ORDER BY checked_at DESC LIMIT 1""",
                    (connection_alias,),
                ).fetchone()
                if connection_alias
                else db.execute(
                    "SELECT result FROM connection_diagnostics ORDER BY checked_at DESC LIMIT 1"
                ).fetchone()
            )
        return json.loads(row["result"]) if row else None

    def last_success(self, connection_alias: str = "") -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT result FROM connection_diagnostics WHERE ready=1
                AND (?='' OR connection_alias=?) ORDER BY checked_at DESC LIMIT 1""",
                (connection_alias, connection_alias),
            ).fetchone()
        return json.loads(row["result"]) if row else None


class SplunkConnectionDiagnostics:
    def __init__(self, store: ConnectionDiagnosticsStore):
        self.store = store

    async def run(
        self,
        connection: SplunkConnection,
        token: str,
        *,
        demo_mode: bool = False,
        progress: ProgressCallback | None = None,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        checked_at = datetime.now(UTC).isoformat()
        binding = binding or {"alias": "primary", "fingerprint": "", "tenant_scope_id": ""}
        if demo_mode:
            health = await DemoSplunkClient().health()
            result = {
                "checked_at": checked_at,
                "endpoint": "demo://local",
                "connection_name": connection.name,
                "ready": True,
                "demo": True,
                "stages": [
                    self._stage(
                        "demo",
                        "Demo client",
                        "complete",
                        "Synthetic read-only tools are available; no network connection is used.",
                    )
                ],
                "tool_count": health.get("tool_count", 0),
                "tools": health.get("tools", []),
                "depth_readiness": {depth: True for depth in DEPTH_TOOL_CONTRACTS},
                "last_success_at": checked_at,
                "connection_alias": binding.get("alias") or "primary",
                "connection_fingerprint": binding.get("fingerprint") or "",
                "tenant_scope_id": binding.get("tenant_scope_id") or "",
            }
            return self.store.record(result)

        stages: list[dict[str, Any]] = []
        await report_progress(
            progress,
            "connection:configuration",
            "Validating endpoint configuration",
            "SignalRoom is checking the URL, TLS policy, and target port without sending a token.",
            progress=8,
            metrics={"network_calls": 0},
        )
        parsed = urlsplit(connection.url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            stages.append(
                self._stage(
                    "configuration",
                    "Endpoint configuration",
                    "error",
                    "Use a complete http:// or https:// MCP endpoint URL.",
                    remediation="Copy the endpoint shown by the Splunk MCP Server app.",
                )
            )
            return self._finish(connection, checked_at, stages, binding=binding)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not parsed.path.rstrip("/").endswith("/services/mcp"):
            stages.append(
                self._stage(
                    "configuration",
                    "Endpoint configuration",
                    "warning",
                    f"The configured path is {parsed.path or '/'}; the common path is /services/mcp.",
                    remediation="Confirm the exact path in the Splunk MCP Server app.",
                )
            )
        else:
            stages.append(
                self._stage(
                    "configuration",
                    "Endpoint configuration",
                    "complete",
                    f"{parsed.scheme.upper()} endpoint · {host}:{port}{parsed.path}",
                    metadata={"verify_tls": connection.verify_ssl, "custom_ca": bool(connection.ca_bundle)},
                )
            )

        await report_progress(
            progress,
            "connection:dns",
            "Resolving the Splunk MCP hostname",
            f"Resolving {host} from the SignalRoom runtime.",
            progress=20,
            metrics={"host": host, "port": port},
        )
        started = time.monotonic()
        try:
            loop = asyncio.get_running_loop()
            addresses = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=5
            )
            ips = sorted({str(item[4][0]) for item in addresses})
            stages.append(
                self._stage(
                    "dns",
                    "DNS resolution",
                    "complete",
                    f"Resolved {host} to {', '.join(ips[:4])}.",
                    duration_ms=self._duration(started),
                    metadata={"addresses": ips[:8]},
                )
            )
        except Exception as exc:
            hint = (
                "This short hostname may only exist inside a Docker or Kubernetes network. "
                "Use a host-reachable DNS name, IP address, or publish the service port."
                if "." not in host and host not in {"localhost"}
                else "Confirm DNS, VPN, and the hostname configured for the Splunk MCP service."
            )
            stages.append(
                self._stage(
                    "dns",
                    "DNS resolution",
                    "error",
                    f"SignalRoom could not resolve {host}: {self._safe_error(exc)}",
                    duration_ms=self._duration(started),
                    remediation=hint,
                )
            )
            return self._finish(connection, checked_at, stages, binding=binding)

        await report_progress(
            progress,
            "connection:tcp",
            "Opening the network path",
            f"Testing TCP reachability to {host}:{port} without authenticating.",
            progress=36,
        )
        started = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            del reader
            writer.close()
            await writer.wait_closed()
            stages.append(
                self._stage(
                    "tcp",
                    "TCP reachability",
                    "complete",
                    f"Connected to {host}:{port}.",
                    duration_ms=self._duration(started),
                )
            )
        except Exception as exc:
            stages.append(
                self._stage(
                    "tcp",
                    "TCP reachability",
                    "error",
                    f"The host resolved, but port {port} was not reachable: {self._safe_error(exc)}",
                    duration_ms=self._duration(started),
                    remediation=(
                        "Confirm routing, firewall policy, published container ports, "
                        "and Splunk status."
                    ),
                )
            )
            return self._finish(connection, checked_at, stages, binding=binding)

        if parsed.scheme == "https":
            await report_progress(
                progress,
                "connection:tls",
                "Inspecting TLS identity",
                (
                    "Validating the configured certificate chain."
                    if connection.verify_ssl
                    else "Reading the peer certificate with verification explicitly disabled."
                ),
                progress=52,
                metrics={"verify_tls": connection.verify_ssl},
            )
            tls = await self._tls_stage(connection, host, port)
            stages.append(tls)
            if tls["status"] == "error":
                return self._finish(connection, checked_at, stages, binding=binding)
        else:
            stages.append(
                self._stage(
                    "tls",
                    "TLS identity",
                    "warning",
                    "This endpoint uses unencrypted HTTP.",
                    remediation="Prefer HTTPS for any endpoint carrying an MCP bearer token.",
                )
            )

        await report_progress(
            progress,
            "connection:mcp",
            "Negotiating MCP and authentication",
            "Initializing a short-lived MCP session and requesting its tool catalog.",
            progress=70,
            metrics={"token_present": bool(token)},
        )
        started = time.monotonic()
        client = SplunkMCPClient(
            connection.url,
            token,
            connection.verify_ssl,
            connection.ca_bundle,
            timeout=15,
        )
        health = await client.health()
        if not health.get("ok"):
            stages.append(
                self._stage(
                    "mcp",
                    "MCP initialization",
                    "error",
                    str(health.get("error") or "The MCP endpoint rejected initialization."),
                    duration_ms=self._duration(started),
                    remediation=self._mcp_remediation(str(health.get("error") or "")),
                )
            )
            return self._finish(connection, checked_at, stages, binding=binding)
        stages.append(
            self._stage(
                "mcp",
                "MCP initialization",
                "complete",
                f"Authenticated to {health.get('server') or 'the MCP server'}.",
                duration_ms=self._duration(started),
                metadata={"server": health.get("server", {})},
            )
        )

        tools = [str(item) for item in health.get("tools", []) if item]
        depth_readiness, missing = self._tool_readiness(tools)
        quick_missing = missing["quick"]
        stages.append(
            self._stage(
                "tools",
                "Tool compatibility",
                "complete" if not quick_missing else "error",
                (
                    f"Discovered {len(tools)} tools; quick, standard, and deep contracts are visible below."
                    if not quick_missing
                    else f"The server is missing quick-discovery tools: {', '.join(quick_missing)}."
                ),
                remediation=(
                    "Upgrade or reconfigure the Splunk MCP Server tool permissions."
                    if quick_missing
                    else ""
                ),
                metadata={"depth_readiness": depth_readiness, "missing_by_depth": missing},
            )
        )
        await report_progress(
            progress,
            "connection:complete",
            "Connection contract evaluated",
            (
                "The endpoint is ready for bounded assurance."
                if depth_readiness["quick"]
                else "The endpoint responded, but required discovery tools are unavailable."
            ),
            progress=100,
            status="complete",
            metrics={"tools": len(tools), "quick_ready": depth_readiness["quick"]},
        )
        return self._finish(
            connection,
            checked_at,
            stages,
            tools=tools,
            server=health.get("server", {}),
            depth_readiness=depth_readiness,
            missing_by_depth=missing,
            binding=binding,
        )

    async def _tls_stage(self, connection: SplunkConnection, host: str, port: int) -> dict[str, Any]:
        started = time.monotonic()
        try:
            if connection.verify_ssl:
                context = ssl.create_default_context(cafile=connection.ca_bundle or None)
            else:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout=8
            )
            del reader
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            cipher = ssl_object.cipher() if ssl_object else None
            metadata: dict[str, Any] = {
                "verified": connection.verify_ssl,
                "cipher": cipher[0] if cipher else "",
                "protocol": ssl_object.version() if ssl_object else "",
            }
            if certificate:
                parsed = x509.load_der_x509_certificate(certificate)
                metadata.update(
                    {
                        "subject": parsed.subject.rfc4514_string(),
                        "issuer": parsed.issuer.rfc4514_string(),
                        "not_before": parsed.not_valid_before_utc.isoformat(),
                        "not_after": parsed.not_valid_after_utc.isoformat(),
                        "serial": hex(parsed.serial_number),
                    }
                )
            writer.close()
            await writer.wait_closed()
            return self._stage(
                "tls",
                "TLS identity",
                "complete" if connection.verify_ssl else "warning",
                (
                    "Certificate chain and hostname verified."
                    if connection.verify_ssl
                    else "TLS is encrypted, but certificate identity verification is disabled."
                ),
                duration_ms=self._duration(started),
                remediation=(
                    "Install a trusted certificate or configure a private CA bundle."
                    if not connection.verify_ssl
                    else ""
                ),
                metadata=metadata,
            )
        except Exception as exc:
            return self._stage(
                "tls",
                "TLS identity",
                "error",
                f"TLS negotiation failed: {self._safe_error(exc)}",
                duration_ms=self._duration(started),
                remediation=(
                    "Verify the hostname and certificate chain, configure the private CA bundle, "
                    "or disable verification only for a trusted self-signed development endpoint."
                ),
            )

    def _finish(
        self,
        connection: SplunkConnection,
        checked_at: str,
        stages: list[dict[str, Any]],
        *,
        tools: list[str] | None = None,
        server: dict[str, Any] | None = None,
        depth_readiness: dict[str, bool] | None = None,
        missing_by_depth: dict[str, list[str]] | None = None,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        binding = binding or {"alias": "primary", "fingerprint": "", "tenant_scope_id": ""}
        ready = bool(depth_readiness and depth_readiness.get("quick"))
        last_success = self.store.last_success(str(binding.get("alias") or "primary"))
        result = {
            "checked_at": checked_at,
            "endpoint": connection.url,
            "connection_name": connection.name,
            "ready": ready,
            "demo": False,
            "stages": stages,
            "tool_count": len(tools or []),
            "tools": tools or [],
            "server": server or {},
            "depth_readiness": depth_readiness
            or {depth: False for depth in DEPTH_TOOL_CONTRACTS},
            "missing_by_depth": missing_by_depth
            or {depth: sorted(contract) for depth, contract in DEPTH_TOOL_CONTRACTS.items()},
            "last_success_at": checked_at if ready else (last_success or {}).get("checked_at"),
            "blocking_stage": next(
                (item["id"] for item in stages if item["status"] == "error"), None
            ),
            "connection_alias": binding.get("alias") or "primary",
            "connection_fingerprint": binding.get("fingerprint") or "",
            "tenant_scope_id": binding.get("tenant_scope_id") or "",
        }
        return self.store.record(result)

    @staticmethod
    def _tool_readiness(
        tools: list[str],
    ) -> tuple[dict[str, bool], dict[str, list[str]]]:
        names = set(tools)
        missing: dict[str, list[str]] = {}
        for depth, contract in DEPTH_TOOL_CONTRACTS.items():
            missing[depth] = sorted(
                logical
                for logical in contract
                if not any(candidate in names for candidate in TOOL_ALIASES.get(logical, [logical]))
            )
        return ({depth: not values for depth, values in missing.items()}, missing)

    @staticmethod
    def _stage(
        stage_id: str,
        label: str,
        status: str,
        detail: str,
        *,
        duration_ms: int = 0,
        remediation: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": stage_id,
            "label": label,
            "status": status,
            "detail": detail,
            "duration_ms": duration_ms,
            "remediation": remediation,
            "metadata": metadata or {},
        }

    @staticmethod
    def _duration(started: float) -> int:
        return max(1, round((time.monotonic() - started) * 1000))

    @staticmethod
    def _safe_error(exc: Exception) -> str:
        return str(exc).replace("\n", " ")[:500] or exc.__class__.__name__

    @staticmethod
    def _mcp_remediation(error: str) -> str:
        lowered = error.lower()
        if "authentication" in lowered or "401" in lowered or "403" in lowered:
            return "Replace the MCP token and confirm that its Splunk role can execute MCP tools."
        if "not found" in lowered or "404" in lowered or "post requests" in lowered:
            return "Copy the exact MCP endpoint from the Splunk MCP Server app."
        return "Inspect the endpoint response and confirm MCP initialization is enabled."
