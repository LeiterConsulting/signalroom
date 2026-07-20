from __future__ import annotations

import json
import zipfile
from typing import Any
from xml.etree import ElementTree

from splunk_security_agent.audit import AuditStore
from splunk_security_agent.audit_export import (
    AuditExportStore,
    AuditOperationsService,
    SplunkAuditExportService,
)
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
