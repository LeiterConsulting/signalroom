from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..schemas import SplunkConnection

PRIMARY_ALIAS = "primary"
PRIMARY_TENANT_SCOPE = "workspace-primary"

FUTURE_MCP_CONNECTIONS = [
    {
        "id": "additional-splunk",
        "label": "Additional Splunk MCP instance",
        "priority": "next",
        "purpose": (
            "Keep production, regional, business-unit, or regulated Splunk estates separate "
            "while allowing an analyst to choose the exact evidence boundary."
        ),
        "expected_value": (
            "Instance-aware discovery, comparison, investigation, and assurance without "
            "mixing evidence or silently moving durable work."
        ),
        "authority": "Read-only search and metadata tools first; each instance gets its own assignment.",
    },
    {
        "id": "asset-context",
        "label": "Asset inventory / CMDB MCP",
        "priority": "recommended",
        "purpose": "Resolve observed hosts, services, owners, criticality, and business purpose.",
        "expected_value": (
            "Turn technical observations into scoped risk and an accountable next action "
            "without treating an unfamiliar asset as malicious."
        ),
        "authority": "Read-only lookup; returned ownership remains contextual evidence.",
    },
    {
        "id": "identity-context",
        "label": "Identity and directory MCP",
        "priority": "recommended",
        "purpose": "Validate user, device, group, privilege, and lifecycle context.",
        "expected_value": (
            "Corroborate identity hypotheses and distinguish expected administration from "
            "unexpected privilege or account activity."
        ),
        "authority": "Read-only lookup; account changes require a separate approved response lane.",
    },
    {
        "id": "threat-intelligence",
        "label": "Threat intelligence MCP",
        "priority": "recommended",
        "purpose": "Enrich observed indicators with source, confidence, validity window, and sightings.",
        "expected_value": (
            "Prioritize indicator validation while preserving the rule that reputation is context, "
            "not proof of compromise."
        ),
        "authority": "Read-only enrichment with source attribution and expiry.",
    },
    {
        "id": "cloud-control-plane",
        "label": "Cloud security control-plane MCP",
        "priority": "later",
        "purpose": "Corroborate Splunk observations with bounded cloud identity and posture context.",
        "expected_value": (
            "Close visibility gaps around cloud assets, control changes, and audit collection "
            "without granting SignalRoom deployment authority."
        ),
        "authority": "Read-only inventory and posture APIs, scoped per account or subscription.",
    },
    {
        "id": "case-response",
        "label": "Case management / SOAR MCP",
        "priority": "later",
        "purpose": "Hand reviewed evidence and decisions to an existing response workflow.",
        "expected_value": (
            "Reduce duplicate transcription and preserve provenance after an analyst has decided "
            "that SignalRoom evidence is ready to leave the workspace."
        ),
        "authority": "Draft or preview first; every external mutation remains separately approved.",
    },
    {
        "id": "detection-content",
        "label": "Detection content repository MCP",
        "priority": "later",
        "purpose": "Read versioned rules, runbooks, tests, and review provenance.",
        "expected_value": (
            "Connect discovery gaps and investigation evidence to governed detection engineering "
            "without bypassing the repository review path."
        ),
        "authority": "Read-only by default; proposals use the existing explicit Git handoff controls.",
    },
]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _normalized_endpoint(value: str, demo_mode: bool) -> str:
    if demo_mode:
        return "demo://isolated"
    raw = (value or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    userinfo = ""
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo += f":{parts.password}"
        userinfo += "@"
    netloc = f"{userinfo}{hostname}{port}"
    path = (parts.path or "").rstrip("/")
    if path == "/service/mcp":
        path = "/services/mcp"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _ca_digest(path_value: str | None) -> str:
    if not path_value:
        return ""
    path = Path(path_value).expanduser()
    try:
        if path.is_file():
            return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    normalized = str(path).replace("\\", "/").lower()
    return hashlib.sha256(f"configured-path:{normalized}".encode()).hexdigest()


class ConnectionRegistryStore:
    """Immutable connection revisions and the mutable aliases that point to them."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        now = _now()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenant_scopes (
                    id TEXT PRIMARY KEY, label TEXT NOT NULL, purpose TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connection_identities (
                    fingerprint TEXT PRIMARY KEY, alias TEXT NOT NULL,
                    tenant_scope_id TEXT NOT NULL, transport TEXT NOT NULL,
                    endpoint TEXT NOT NULL, display_name TEXT NOT NULL,
                    verify_tls INTEGER NOT NULL, ca_bundle_digest TEXT NOT NULL,
                    mode TEXT NOT NULL, contract_json TEXT NOT NULL,
                    supersedes_fingerprint TEXT NOT NULL, created_at TEXT NOT NULL,
                    FOREIGN KEY(tenant_scope_id) REFERENCES tenant_scopes(id)
                );
                CREATE INDEX IF NOT EXISTS idx_connection_revisions_alias_created
                    ON connection_identities(alias,created_at DESC);
                CREATE TABLE IF NOT EXISTS connection_aliases (
                    alias TEXT PRIMARY KEY, tenant_scope_id TEXT NOT NULL,
                    current_fingerprint TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(tenant_scope_id) REFERENCES tenant_scopes(id),
                    FOREIGN KEY(current_fingerprint) REFERENCES connection_identities(fingerprint)
                );
                """
            )
            columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(connection_aliases)")
            }
            if "display_name" not in columns:
                db.execute(
                    "ALTER TABLE connection_aliases ADD COLUMN display_name TEXT NOT NULL DEFAULT ''"
                )
            db.execute(
                """INSERT OR IGNORE INTO tenant_scopes
                (id,label,purpose,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?)""",
                (
                    PRIMARY_TENANT_SCOPE,
                    "Primary security workspace",
                    (
                        "Default evidence and execution boundary for the configured Primary "
                        "Splunk connection."
                    ),
                    "active",
                    now,
                    now,
                ),
            )

    def sync_primary(
        self,
        value: SplunkConnection,
        *,
        demo_mode: bool,
    ) -> dict[str, Any]:
        contract = {
            "schema": 1,
            "alias": PRIMARY_ALIAS,
            "tenant_scope_id": PRIMARY_TENANT_SCOPE,
            "transport": "splunk-mcp",
            "endpoint": _normalized_endpoint(value.url, demo_mode),
            "verify_tls": bool(value.verify_ssl),
            "ca_bundle_digest": _ca_digest(value.ca_bundle) if value.verify_ssl else "",
            "mode": "demo" if demo_mode else "live",
        }
        canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        now = _now()
        with self._lock, self.connect() as db:
            alias = db.execute(
                "SELECT * FROM connection_aliases WHERE alias=?",
                (PRIMARY_ALIAS,),
            ).fetchone()
            previous = str(alias["current_fingerprint"]) if alias else ""
            db.execute(
                """INSERT OR IGNORE INTO connection_identities
                (fingerprint,alias,tenant_scope_id,transport,endpoint,display_name,
                verify_tls,ca_bundle_digest,mode,contract_json,supersedes_fingerprint,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fingerprint,
                    PRIMARY_ALIAS,
                    PRIMARY_TENANT_SCOPE,
                    "splunk-mcp",
                    contract["endpoint"],
                    (value.name or "Primary Splunk")[:240],
                    int(contract["verify_tls"]),
                    contract["ca_bundle_digest"],
                    contract["mode"],
                    canonical,
                    previous if previous != fingerprint else "",
                    now,
                ),
            )
            db.execute(
                """INSERT INTO connection_aliases
                (alias,tenant_scope_id,current_fingerprint,display_name,updated_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(alias) DO UPDATE SET tenant_scope_id=excluded.tenant_scope_id,
                current_fingerprint=excluded.current_fingerprint,
                display_name=excluded.display_name,updated_at=excluded.updated_at""",
                (
                    PRIMARY_ALIAS,
                    PRIMARY_TENANT_SCOPE,
                    fingerprint,
                    (value.name or "Primary Splunk")[:240],
                    now,
                ),
            )
        result = self.current(PRIMARY_ALIAS)
        assert result is not None
        return result

    def current(self, alias: str = PRIMARY_ALIAS) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT i.*,a.display_name AS alias_display_name
                FROM connection_aliases a
                JOIN connection_identities i ON i.fingerprint=a.current_fingerprint
                WHERE a.alias=?""",
                (alias,),
            ).fetchone()
        return self._identity(row) if row else None

    def identity(self, fingerprint: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM connection_identities WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
        return self._identity(row) if row else None

    def validate(
        self,
        alias: str,
        fingerprint: str,
        tenant_scope_id: str,
    ) -> tuple[bool, str]:
        current = self.current(alias)
        if current is None:
            return False, f"Connection alias {alias!r} is no longer configured."
        if tenant_scope_id != current["tenant_scope_id"]:
            return (
                False,
                "The workflow tenant scope no longer matches the connection alias. "
                "Rebind it explicitly before execution.",
            )
        if fingerprint != current["fingerprint"]:
            return (
                False,
                (
                    f"The {alias} alias now points to Splunk revision "
                    f"{current['fingerprint'][:12]}, but this workflow is bound to "
                    f"{fingerprint[:12] or 'a legacy blank revision'}. Rebind or recreate it."
                ),
            )
        return True, "The workflow is bound to the current immutable connection revision."

    def overview(self, workflow_bindings: dict[str, Any] | None = None) -> dict[str, Any]:
        with self.connect() as db:
            scopes = db.execute(
                "SELECT * FROM tenant_scopes ORDER BY created_at"
            ).fetchall()
            revisions = db.execute(
                """SELECT * FROM connection_identities
                ORDER BY created_at DESC LIMIT 25"""
            ).fetchall()
        return {
            "tenant_scopes": [dict(row) for row in scopes],
            "primary": self.current(),
            "revisions": [self._identity(row) for row in revisions],
            "workflow_bindings": workflow_bindings or {},
            "additional_mcp_connections": {
                "status": "architecture-preview",
                "executable": False,
                "mission": (
                    "Add corroborating context and governed handoffs around Splunk evidence, "
                    "not an unrestricted collection of agent tools."
                ),
                "admission_requirements": [
                    "A stable connection identity and tenant scope",
                    "Explicit least-privilege tool authority",
                    "Data-handling and trust-boundary documentation",
                    "Health, version, and capability checks",
                    "Evidence attribution to the exact connection revision",
                    "Separate approval for every external write capability",
                ],
                "suggestions": FUTURE_MCP_CONNECTIONS,
            },
            "contract": {
                "aliases_are_mutable": True,
                "identities_are_immutable": True,
                "credentials_in_fingerprint": False,
                "durable_workflows_fail_closed_on_drift": True,
                "tenant_scope_is_execution_and_evidence_metadata": True,
                "multi_tenant_database_isolation": False,
            },
        }

    @staticmethod
    def _identity(row: sqlite3.Row) -> dict[str, Any]:
        keys = set(row.keys())
        return {
            "fingerprint": row["fingerprint"],
            "alias": row["alias"],
            "tenant_scope_id": row["tenant_scope_id"],
            "transport": row["transport"],
            "endpoint": row["endpoint"],
            "display_name": (
                row["alias_display_name"]
                if "alias_display_name" in keys and row["alias_display_name"]
                else row["display_name"]
            ),
            "verify_tls": bool(row["verify_tls"]),
            "ca_bundle_bound": bool(row["ca_bundle_digest"]),
            "mode": row["mode"],
            "supersedes_fingerprint": row["supersedes_fingerprint"],
            "created_at": row["created_at"],
        }
