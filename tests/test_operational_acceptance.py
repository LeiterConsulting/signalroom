from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.operational_acceptance import OperationalAcceptanceService


def _snapshot() -> dict:
    checked_at = datetime.now(UTC).isoformat()
    fingerprint = "a" * 64
    return {
        "connections": {
            "primary": {
                "alias": "primary",
                "display_name": "Primary Splunk",
                "tenant_scope_id": "workspace-primary",
                "fingerprint": fingerprint,
                "verify_tls": True,
                "managed": False,
                "enabled": True,
                "latest_diagnostic": {
                    "ready": True,
                    "checked_at": checked_at,
                    "connection_fingerprint": fingerprint,
                    "stages": [],
                },
            },
            "managed_splunk_connections": [],
            "workflow_bindings": {},
        },
        "recovery": {
            "recent_rehearsals": [
                {
                    "id": "rehearsal-1",
                    "status": "pass",
                    "created_at": checked_at,
                    "created_by": "admin",
                    "application_version": "0.1.0",
                    "components": [{"path": "config.json"}],
                }
            ]
        },
        "tenant_data": {"routes": [], "migrations": [], "reverse_migrations": []},
        "auth": {
            "policy": {"enabled": True},
            "identity_count": 2,
            "active_admins": 1,
            "active_local_admins": 1,
            "network_exposed": False,
        },
        "workers": [
            {"id": "discovery", "label": "Discovery", "online": True},
            {"id": "assurance", "label": "Assurance", "online": True},
        ],
    }


def test_operational_acceptance_distinguishes_attention_not_drilled_and_blocked(
    tmp_path: Path,
) -> None:
    service = OperationalAcceptanceService(tmp_path / "acceptance", "0.1.0")
    snapshot = _snapshot()

    ready = service.overview(snapshot)
    assert ready["decision"] == "ready"
    assert ready["counts"]["pass"] == 5

    snapshot["connections"]["managed_splunk_connections"] = [
        {
            "alias": "lab-two",
            "display_name": "Lab two",
            "tenant_scope_id": "lab.two",
            "fingerprint": "b" * 64,
            "verify_tls": False,
            "managed": True,
            "enabled": True,
            "token_configured": True,
            "latest_diagnostic": None,
        }
    ]
    incomplete = service.overview(snapshot)
    instances = next(item for item in incomplete["checks"] if item["id"] == "splunk-instances")
    assert incomplete["decision"] == "incomplete"
    assert instances["items"][1]["status"] == "not-yet-drilled"

    snapshot["connections"]["managed_splunk_connections"][0]["latest_diagnostic"] = {
        "ready": False,
        "checked_at": datetime.now(UTC).isoformat(),
        "connection_fingerprint": "b" * 64,
        "blocking_stage": "mcp",
        "stages": [
            {
                "status": "error",
                "label": "MCP initialization",
                "remediation": "Replace the MCP token.",
            }
        ],
    }
    blocked = service.overview(snapshot)
    blocked_instance = next(
        item for item in blocked["checks"] if item["id"] == "splunk-instances"
    )["items"][1]
    assert blocked["decision"] == "blocked"
    assert blocked_instance["status"] == "blocked"
    assert blocked_instance["next_action"] == "Replace the MCP token."


def test_operational_acceptance_blocks_exposed_local_admin_and_drifted_work(
    tmp_path: Path,
) -> None:
    service = OperationalAcceptanceService(tmp_path / "acceptance", "0.1.0")
    snapshot = _snapshot()
    snapshot["auth"] = {
        "policy": {"enabled": False},
        "identity_count": 0,
        "active_admins": 0,
        "active_local_admins": 0,
        "network_exposed": True,
    }
    snapshot["connections"]["workflow_bindings"] = {
        "forecast_schedules": [{"id": "schedule-1", "binding_current": False}]
    }
    snapshot["workers"][0]["online"] = False

    result = service.overview(snapshot)
    statuses = {item["id"]: item["status"] for item in result["checks"]}

    assert result["decision"] == "blocked"
    assert statuses["authorization"] == "blocked"
    assert statuses["durable-work"] == "blocked"


def test_acceptance_receipt_is_payload_free_and_api_is_not_cacheable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service = OperationalAcceptanceService(tmp_path / "acceptance", "0.1.0")
    snapshot = _snapshot()
    receipt = service.capture(snapshot, "security-admin")

    assert receipt["decision"] == "ready"
    assert "connections" not in receipt
    assert "workers" not in receipt
    assert service.overview(snapshot)["recent_receipts"][0]["id"] == receipt["id"]

    monkeypatch.setattr(app_module.services, "operational_acceptance", service)
    monkeypatch.setattr(app_module.services, "operational_acceptance_snapshot", lambda: snapshot)
    response = TestClient(app_module.app).get("/api/operational-acceptance")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["decision"] == "ready"
