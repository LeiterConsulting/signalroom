from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

STATUS_PRIORITY = {"pass": 0, "attention": 1, "not-yet-drilled": 2, "blocked": 3}


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _worst(statuses: list[str]) -> str:
    return max(statuses or ["pass"], key=lambda item: STATUS_PRIORITY.get(item, 3))


class OperationalAcceptanceService:
    """Synthesize and retain payload-free operational acceptance evidence."""

    def __init__(self, root: Path | str, application_version: str):
        self.root = Path(root)
        self.application_version = application_version
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(parents=True, exist_ok=True)

    def overview(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        current = self._assess(snapshot)
        current["recent_receipts"] = self._recent_receipts()
        current["contract"] = {
            "live_splunk_calls_are_explicit": True,
            "restore_is_never_staged": True,
            "investigation_payloads_retained": False,
            "receipts_are_state_bound": True,
        }
        return current

    def capture(self, snapshot: dict[str, Any], actor: str) -> dict[str, Any]:
        report = self._assess(snapshot)
        receipt = {
            "id": str(uuid4()),
            "created_at": _now().isoformat(),
            "created_by": actor[:120],
            "application_version": self.application_version,
            "decision": report["decision"],
            "counts": report["counts"],
            "state_sha256": report["state_sha256"],
            "connection_revisions": report["connection_revisions"],
            "checks": [
                {
                    "id": item["id"],
                    "status": item["status"],
                    "summary": item["summary"],
                }
                for item in report["checks"]
            ],
            "payload_contract": "No tokens, secrets, SPL, evidence, cases, or model prompts retained.",
        }
        filename = f"{receipt['created_at'].replace(':', '-')}-{receipt['id']}.json"
        self._write_json(self.receipts / filename, receipt)
        self._trim_receipts(20)
        return receipt

    def _assess(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        checked_at = _now()
        connections = snapshot.get("connections") or {}
        recovery = snapshot.get("recovery") or {}
        tenant_data = snapshot.get("tenant_data") or {}
        auth = snapshot.get("auth") or {}
        workers = snapshot.get("workers") or []
        checks = [
            self._recovery_check(recovery, checked_at),
            self._connection_check(connections, checked_at),
            self._tenant_check(connections, tenant_data),
            self._authorization_check(auth),
            self._workflow_check(connections, workers),
        ]
        counts = {
            status: sum(item["status"] == status for item in checks)
            for status in STATUS_PRIORITY
        }
        statuses = [item["status"] for item in checks]
        decision = (
            "blocked"
            if "blocked" in statuses
            else "incomplete"
            if "not-yet-drilled" in statuses
            else "attention"
            if "attention" in statuses
            else "ready"
        )
        revisions = [
            {
                "alias": item.get("alias") or "primary",
                "tenant_scope_id": item.get("tenant_scope_id") or "",
                "fingerprint": item.get("fingerprint") or "",
            }
            for item in self._instances(connections)
        ]
        state = {
            "application_version": self.application_version,
            "decision": decision,
            "checks": [
                {"id": item["id"], "status": item["status"], "summary": item["summary"]}
                for item in checks
            ],
            "connection_revisions": revisions,
        }
        state_sha256 = hashlib.sha256(
            json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "decision": decision,
            "checked_at": checked_at.isoformat(),
            "application_version": self.application_version,
            "counts": counts,
            "checks": checks,
            "connection_revisions": revisions,
            "state_sha256": state_sha256,
        }

    def _recovery_check(self, recovery: dict[str, Any], checked_at: datetime) -> dict[str, Any]:
        rehearsals = recovery.get("recent_rehearsals") or []
        current = next(
            (
                item
                for item in rehearsals
                if item.get("status") == "pass"
                and item.get("application_version") == self.application_version
            ),
            None,
        )
        if not current:
            return {
                "id": "recovery-round-trip",
                "title": "Control-plane recovery rehearsal",
                "status": "not-yet-drilled",
                "summary": "No cryptographic recovery round trip has been retained for this release.",
                "detail": (
                    "Run the local rehearsal to snapshot, encrypt, decrypt, and validate every "
                    "control-plane contract. The temporary package is discarded and no restore is staged."
                ),
                "action": "rehearse-recovery",
            }
        rehearsed_at = _parse_time(current.get("created_at"))
        stale = not rehearsed_at or rehearsed_at < checked_at - timedelta(days=90)
        return {
            "id": "recovery-round-trip",
            "title": "Control-plane recovery rehearsal",
            "status": "attention" if stale else "pass",
            "summary": (
                "The latest successful rehearsal is older than 90 days."
                if stale
                else (
                    f"{len(current.get('components') or [])} components passed an in-memory "
                    "encrypted round trip."
                )
            ),
            "detail": (
                f"Rehearsed {current.get('created_at')} by {current.get('created_by') or 'unknown'}; "
                "the encrypted package and password were discarded and live state was unchanged."
            ),
            "action": "rehearse-recovery" if stale else "none",
            "evidence": current,
        }

    def _connection_check(self, connections: dict[str, Any], checked_at: datetime) -> dict[str, Any]:
        items = [self._instance_check(item, checked_at) for item in self._instances(connections)]
        status = _worst([item["status"] for item in items])
        ready = sum(item["status"] == "pass" for item in items)
        return {
            "id": "splunk-instances",
            "title": "Splunk instance acceptance",
            "status": status,
            "summary": f"{ready} of {len(items)} configured Splunk instances pass without attention.",
            "detail": (
                "Every instance is evaluated against its current immutable endpoint, TLS, token, "
                "MCP, tool-contract, admission, and diagnostic-age state."
            ),
            "action": "review-instances" if status != "pass" else "none",
            "items": items,
        }

    def _instance_check(self, item: dict[str, Any], checked_at: datetime) -> dict[str, Any]:
        alias = str(item.get("alias") or "primary")
        diagnostic = item.get("latest_diagnostic") or {}
        current = bool(
            diagnostic
            and (
                diagnostic.get("current_revision") is True
                or diagnostic.get("connection_fingerprint") == item.get("fingerprint")
            )
        )
        if item.get("managed") and not item.get("token_configured"):
            status, summary, next_action = (
                "blocked",
                "The encrypted MCP token is missing.",
                "Edit this instance and save a valid MCP token.",
            )
        elif not diagnostic or not current:
            status, summary, next_action = (
                "not-yet-drilled",
                "The current immutable revision has not completed diagnostics.",
                "Run live diagnostics for this exact revision.",
            )
        elif not diagnostic.get("ready"):
            failed = next(
                (stage for stage in diagnostic.get("stages") or [] if stage.get("status") == "error"),
                {},
            )
            status, summary, next_action = (
                "blocked",
                "Blocked at "
                f"{failed.get('label') or diagnostic.get('blocking_stage') or 'connection preflight'}.",
                failed.get("remediation") or "Correct the failed diagnostic stage and run it again.",
            )
        else:
            concerns: list[str] = []
            if item.get("managed") and not item.get("enabled"):
                concerns.append("Diagnostics passed but the execution scope is disabled")
            if not item.get("verify_tls", True):
                concerns.append("TLS certificate identity verification is disabled")
            diagnostic_at = _parse_time(diagnostic.get("checked_at"))
            if not diagnostic_at or diagnostic_at < checked_at - timedelta(days=7):
                concerns.append("Diagnostics are older than seven days")
            status = "attention" if concerns else "pass"
            summary = "; ".join(concerns) + "." if concerns else "Current revision is ready."
            next_action = (
                "Enable the scope after reviewing TLS and diagnostic age."
                if item.get("managed") and not item.get("enabled")
                else "Configure trusted TLS or rerun diagnostics if the accepted risk changes."
                if concerns
                else "No action required."
            )
        return {
            "alias": alias,
            "display_name": item.get("display_name") or alias,
            "tenant_scope_id": item.get("tenant_scope_id") or "",
            "fingerprint": item.get("fingerprint") or "",
            "status": status,
            "summary": summary,
            "next_action": next_action,
            "diagnostic_checked_at": diagnostic.get("checked_at"),
            "blocking_stage": diagnostic.get("blocking_stage"),
            "managed": bool(item.get("managed")),
            "enabled": bool(item.get("enabled", True)),
            "verify_tls": bool(item.get("verify_tls", True)),
        }

    def _tenant_check(
        self, connections: dict[str, Any], tenant_data: dict[str, Any]
    ) -> dict[str, Any]:
        instances = self._instances(connections)
        scopes: dict[str, list[str]] = {}
        for item in instances:
            scopes.setdefault(str(item.get("tenant_scope_id") or ""), []).append(
                str(item.get("alias") or "primary")
            )
        duplicates = {scope: aliases for scope, aliases in scopes.items() if scope and len(aliases) > 1}
        known_scopes = set(scopes)
        orphan_routes = [
            item.get("tenant_scope_id")
            for item in tenant_data.get("routes") or []
            if item.get("tenant_scope_id") not in known_scopes
        ]
        active_operations = [
            item
            for item in [
                *(tenant_data.get("migrations") or []),
                *(tenant_data.get("reverse_migrations") or []),
            ]
            if item.get("status") in {"copying", "applying"}
        ]
        if duplicates or orphan_routes:
            status = "blocked"
            summary = (
                f"{len(duplicates)} duplicate tenant scope(s) and {len(orphan_routes)} orphan route(s) "
                "break one-instance/one-scope ownership."
            )
        elif active_operations:
            status = "attention"
            summary = f"{len(active_operations)} tenant data operation(s) are in progress."
        else:
            isolated = sum(
                item.get("mode") == "isolated-routing" for item in tenant_data.get("routes") or []
            )
            status = "pass"
            summary = (
                f"{len(instances)} immutable instance scope(s) are unique; {isolated} use isolated routing."
            )
        return {
            "id": "tenant-routing",
            "title": "Tenant routing and ownership",
            "status": status,
            "summary": summary,
            "detail": (
                "Shared row-filtered routing is valid. Physical isolation is optional, but every "
                "active route must map to one configured immutable Splunk scope."
            ),
            "action": "review-routing" if status != "pass" else "none",
            "evidence": {
                "duplicate_scopes": duplicates,
                "orphan_routes": orphan_routes,
                "active_operation_count": len(active_operations),
            },
        }

    @staticmethod
    def _authorization_check(auth: dict[str, Any]) -> dict[str, Any]:
        enabled = bool((auth.get("policy") or {}).get("enabled"))
        local_admins = int(auth.get("active_local_admins") or 0)
        exposed = bool(auth.get("network_exposed"))
        if enabled and local_admins < 1:
            status = "blocked"
            summary = "RBAC is enabled without an active local break-glass administrator."
        elif not enabled and exposed:
            status = "blocked"
            summary = "Local single-user administrator mode is listening beyond localhost."
        elif not enabled:
            status = "attention"
            summary = "Optional RBAC is disabled; this is acceptable only on a trusted local host."
        else:
            status = "pass"
            summary = f"Named access is enabled with {local_admins} local break-glass administrator(s)."
        return {
            "id": "authorization",
            "title": "Authorization boundary",
            "status": status,
            "summary": summary,
            "detail": (
                f"{int(auth.get('active_admins') or 0)} active admin(s), "
                f"{int(auth.get('identity_count') or 0)} retained identity record(s), and runtime "
                f"binding {'is' if exposed else 'is not'} network-exposed."
            ),
            "action": "review-access" if status != "pass" else "none",
        }

    @staticmethod
    def _workflow_check(connections: dict[str, Any], workers: list[dict[str, Any]]) -> dict[str, Any]:
        bindings = connections.get("workflow_bindings") or {}
        values = [bindings.get("assurance_policy")]
        values.extend(bindings.get("forecast_schedules") or [])
        values.extend(bindings.get("recent_discovery_jobs") or [])
        drifted = [item for item in values if item and not item.get("binding_current", True)]
        offline = [item for item in workers if not item.get("online")]
        if drifted or offline:
            status = "blocked"
            summary = f"{len(drifted)} workflow binding(s) drifted and {len(offline)} worker(s) are offline."
        else:
            status = "pass"
            summary = f"{len(workers)} durable worker(s) are online and {len(values)} binding(s) fail closed."
        return {
            "id": "durable-work",
            "title": "Durable workflow restart safety",
            "status": status,
            "summary": summary,
            "detail": (
                "Discovery, assurance, forecasting, delivery, and audit-export workers retain local "
                "state and reject execution when an immutable Splunk revision or tenant scope drifts."
            ),
            "action": "review-workflows" if status != "pass" else "none",
            "evidence": {
                "workers": workers,
                "drifted_binding_count": len(drifted),
            },
        }

    @staticmethod
    def _instances(connections: dict[str, Any]) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        primary = connections.get("primary")
        if primary:
            values.append(primary)
        values.extend(connections.get("managed_splunk_connections") or [])
        return values

    def _recent_receipts(self) -> list[dict[str, Any]]:
        values = []
        for path in sorted(self.receipts.glob("*.json"), reverse=True)[:10]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                values.append(value)
        return values

    def _trim_receipts(self, keep: int) -> None:
        for path in sorted(self.receipts.glob("*.json"), reverse=True)[keep:]:
            path.unlink(missing_ok=True)

    @staticmethod
    def _write_json(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(temporary, path)
