from __future__ import annotations

import json
import zipfile
from typing import Any
from xml.etree import ElementTree

import pytest

from splunk_security_agent.audit import AuditStore
from splunk_security_agent.audit_export import (
    AuditExportStore,
    AuditOperationsService,
    SplunkAuditExportService,
)
from splunk_security_agent.audit_export.operations import AuditOperationsReconciliationError
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.schemas import (
    AuditExportPolicyUpdate,
    AuditOperationsPolicyUpdate,
)


def build_service(
    tmp_path: Any,
) -> tuple[AuditOperationsService, SplunkAuditExportService, AuditStore]:
    audit = AuditStore(tmp_path / "audit.db")
    store = AuditExportStore(tmp_path / "audit-export.db")
    config = ConfigStore(tmp_path / "config")
    audit_export = SplunkAuditExportService(store, audit, config)
    operations = AuditOperationsService(
        store,
        audit_export,
        audit,
        tmp_path / "operations-exports",
    )
    return operations, audit_export, audit


class ReconciliationSplunk:
    url = "https://splunk:8089/services/mcp"

    def __init__(self, operations: AuditOperationsService, *, drift_retention: bool = False):
        policy = operations.store.operations_policy()
        binding = operations._build(policy)["binding"]
        controls = operations._controls(policy)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.values = {
            "index": {
                "name": binding["index"],
                "frozenTimePeriodInSecs": (policy["retention_days"] * 86400 + (1 if drift_retention else 0)),
            },
            "apps": {
                "results": [
                    {"name": "signalroom_audit_operations", "version": "1.0.0"},
                    {"name": "signalroom_audit_retention", "version": "1.0.0"},
                ]
            },
            "saved_searches": {
                "results": [
                    {
                        "name": item["title"],
                        "app": "signalroom_audit_operations",
                        "search": item["search"],
                        "cron_schedule": item["schedule"],
                        "dispatch.earliest_time": item["earliest"],
                        "dispatch.latest_time": "now",
                        "disabled": "1",
                    }
                    for item in controls
                ]
            },
            "macros": {
                "results": [
                    {
                        "name": "signalroom_audit_base",
                        "app": "signalroom_audit_operations",
                        "definition": operations._base_search(binding),
                        "iseval": "0",
                    },
                    {
                        "name": "signalroom_audit_canonical",
                        "app": "signalroom_audit_operations",
                        "definition": ("`signalroom_audit_base` | dedup signalroom_event_id sortby - _time"),
                        "iseval": "0",
                    },
                ]
            },
            "views": {
                "results": [
                    {
                        "name": "signalroom_audit_operations",
                        "app": "signalroom_audit_operations",
                        "eai:data": operations._dashboard(policy),
                    }
                ]
            },
        }

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((name, arguments))
        if name == "get_index_info":
            return self.values["index"]
        return self.values[arguments["type"]]


def export_reconcilable_kit(
    operations: AuditOperationsService,
    audit_export: SplunkAuditExportService,
) -> None:
    audit_export.update_policy(
        AuditExportPolicyUpdate(
            index_name="signalroom_audit",
            hec_url="https://splunk:8088",
        )
    )
    operations.export()


def test_audit_operations_policy_is_durable_and_local_only_by_default(
    tmp_path: Any,
) -> None:
    operations, _, _ = build_service(tmp_path)

    overview = operations.overview()

    assert overview["policy"]["retention_days"] == 365
    assert overview["policy"]["deduplication_mode"] == "stable-event-id"
    assert overview["health"]["status"] == "local-only"
    assert overview["pack"]["scheduled_searches_enabled"] is False
    assert overview["pack"]["writes_to_splunk"] is False
    assert overview["pack"]["current_export"] is None
    assert len(overview["pack"]["controls"]) == 4


def test_audit_operations_preview_is_bound_and_review_gated(tmp_path: Any) -> None:
    operations, audit_export, audit = build_service(tmp_path)
    audit_export.update_policy(
        AuditExportPolicyUpdate(
            index_name="security_signalroom_audit",
            sourcetype="signalroom:control:audit",
            source="signalroom:control",
            host="signalroom-lab",
        )
    )
    operations.update_policy(
        AuditOperationsPolicyUpdate(
            retention_days=730,
            deduplication_mode="preserve-retries",
            expected_export_lag_minutes=30,
            source_silence_minutes=240,
            denied_request_threshold=12,
            dashboard_earliest="-7d",
        )
    )

    preview = operations.preview()

    assert preview["binding"]["index"] == "security_signalroom_audit"
    assert preview["binding"]["sourcetype"] == "signalroom:control:audit"
    assert preview["retention"]["seconds"] == 730 * 86400
    assert preview["authority"] == {
        "writes_to_splunk": False,
        "calls_splunk_api": False,
        "scheduled_searches_enabled": False,
        "alert_actions_configured": False,
        "changes_index_retention_if_deployed": True,
        "requires_human_review": True,
    }
    denial = next(item for item in preview["controls"] if item["id"] == "authorization-denials")
    assert "count >= 12" in denial["search"]
    assert any(name.endswith("/default/indexes.conf") for name in preview["files"])
    assert any(name.endswith("signalroom_audit_operations.xml") for name in preview["files"])
    assert audit.events()[0]["event_type"] == "audit.operations.policy.updated"


def test_audit_operations_export_contains_disabled_split_deployment_apps(
    tmp_path: Any,
) -> None:
    operations, _, audit = build_service(tmp_path)
    operations.update_policy(
        AuditOperationsPolicyUpdate(
            retention_days=180,
            deduplication_mode="stable-event-id",
        )
    )

    result = operations.export()
    path = operations.export_dir / result["filename"]

    assert path.is_file()
    assert result["url"].endswith(result["filename"])
    assert result["archive_sha256"]
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        savedsearches = archive.read(
            "search-head/signalroom_audit_operations/default/savedsearches.conf"
        ).decode()
        macros = archive.read("search-head/signalroom_audit_operations/default/macros.conf").decode()
        retention = archive.read("indexer/signalroom_audit_retention/default/indexes.conf").decode()
        dashboard = archive.read(
            "search-head/signalroom_audit_operations/default/data/ui/views/signalroom_audit_operations.xml"
        ).decode()
        manifest = json.loads(archive.read("manifest.json"))

    assert "README.md" in names
    assert savedsearches.count("disabled = 1") == 4
    assert "disabled = 0" not in savedsearches
    assert "action.email" not in savedsearches
    assert "signalroom_event_id" in savedsearches
    assert "dedup signalroom_event_id sortby - _time" in macros
    assert "frozenTimePeriodInSecs = 15552000" in retention
    ElementTree.fromstring(dashboard)
    assert manifest["authority"]["writes_to_splunk"] is False
    assert manifest["authority"]["scheduled_searches_enabled"] is False
    assert manifest["policy"]["retention_days"] == 180
    assert manifest["files"]["README.md"]["sha256"]
    assert operations.overview()["pack"]["current_export"]["filename"] == path.name
    assert audit.events()[0]["event_type"] == "audit.operations.pack.exported"


def test_audit_operations_reports_a_local_chain_break(tmp_path: Any) -> None:
    operations, _, audit = build_service(tmp_path)
    audit.record(
        "case.created",
        "create",
        target_type="case",
        target_id="case-1",
    )
    with audit.connect() as db:
        db.execute("UPDATE audit_events SET summary='changed' WHERE sequence=1")

    health = operations.overview()["health"]

    assert health["status"] == "chain-invalid"
    assert health["local_chain_valid"] is False
    assert "sequence 1" in health["detail"]


async def test_audit_operations_reconciliation_verifies_exact_read_only_contract(
    tmp_path: Any,
) -> None:
    operations, audit_export, audit = build_service(tmp_path)
    export_reconcilable_kit(operations, audit_export)
    client = ReconciliationSplunk(operations)
    scope = {
        "alias": "primary",
        "fingerprint": "a" * 64,
        "tenant_scope_id": "workspace-primary",
        "display_name": "Primary Splunk",
    }

    result = await operations.reconcile(scope, client)

    assert result["status"] == "verified"
    assert result["snapshot"]["counts"] == {
        "verified": 10,
        "drifted": 0,
        "not-observable": 0,
        "inconclusive": 0,
    }
    assert result["snapshot"]["authority"]["runs_spl"] is False
    assert len(client.calls) == 5
    assert all(name != "run_query" for name, _ in client.calls)
    assert operations.overview()["reconciliation"]["current"]["id"] == result["id"]
    assert audit.events()[0]["event_type"] == "audit.operations.pack.reconciled"


async def test_audit_operations_reconciliation_exposes_drift_and_scope_binding(
    tmp_path: Any,
) -> None:
    operations, audit_export, _ = build_service(tmp_path)
    export_reconcilable_kit(operations, audit_export)
    client = ReconciliationSplunk(operations, drift_retention=True)
    scope = {
        "alias": "east",
        "fingerprint": "b" * 64,
        "tenant_scope_id": "tenant-east",
        "display_name": "East Splunk",
    }

    result = await operations.reconcile(scope, client)

    assert result["status"] == "drifted"
    control = next(item for item in result["snapshot"]["controls"] if item["id"] == "index-retention")
    assert control["status"] == "drifted"
    assert result["connection_alias"] == "east"
    assert operations.overview(allowed_connection_ids={"primary"})["reconciliation"]["history"] == []


async def test_audit_operations_reconciliation_blocks_cross_instance_comparison(
    tmp_path: Any,
) -> None:
    operations, audit_export, _ = build_service(tmp_path)
    export_reconcilable_kit(operations, audit_export)
    client = ReconciliationSplunk(operations)
    client.url = "https://different-splunk:8089/services/mcp"

    result = await operations.reconcile(
        {
            "alias": "primary",
            "fingerprint": "a" * 64,
            "tenant_scope_id": "workspace-primary",
        },
        client,
    )

    assert result["status"] == "blocked"
    assert result["snapshot"]["destination_identity"]["host_match"] is False
    assert client.calls == []


async def test_audit_operations_reconciliation_retains_unobservable_fields(
    tmp_path: Any,
) -> None:
    operations, audit_export, _ = build_service(tmp_path)
    export_reconcilable_kit(operations, audit_export)
    client = ReconciliationSplunk(operations)
    client.values["views"]["results"][0].pop("eai:data")

    result = await operations.reconcile(
        {
            "alias": "primary",
            "fingerprint": "a" * 64,
            "tenant_scope_id": "workspace-primary",
        },
        client,
    )

    assert result["status"] == "inconclusive"
    dashboard = next(
        item for item in result["snapshot"]["controls"] if item["id"] == "view:signalroom_audit_operations"
    )
    assert dashboard["status"] == "not-observable"
    assert dashboard["fields"][1]["status"] == "not-observable"


async def test_audit_operations_reconciliation_rejects_a_tampered_archive(
    tmp_path: Any,
) -> None:
    operations, audit_export, _ = build_service(tmp_path)
    export_reconcilable_kit(operations, audit_export)
    current = operations.overview()["pack"]["current_export"]
    path = operations.export_dir / current["filename"]
    with path.open("ab") as handle:
        handle.write(b"tampered")
    client = ReconciliationSplunk(operations)

    with pytest.raises(AuditOperationsReconciliationError, match="archive failed SHA-256"):
        await operations.reconcile(
            {
                "alias": "primary",
                "fingerprint": "a" * 64,
                "tenant_scope_id": "workspace-primary",
            },
            client,
        )

    assert client.calls == []
