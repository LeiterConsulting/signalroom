import json
import sqlite3

import pytest

from splunk_security_agent.assurance import AssuranceStore
from splunk_security_agent.delivery import DeliveryStore
from splunk_security_agent.forecasting import TimeSeriesExperimentStore
from splunk_security_agent.tenancy import (
    TenantDataPlaneRegistry,
    TenantIsolationPlanner,
    TenantIsolationStore,
)


def create_scoped_evidence_database(path) -> None:
    with sqlite3.connect(path) as database:
        database.execute(
            """CREATE TABLE artifacts (
                id TEXT PRIMARY KEY,
                tenant_scope_id TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL
            )"""
        )
        database.executemany(
            "INSERT INTO artifacts VALUES (?,?,?,?)",
            [
                ("one", "tenant-east", "Sensitive east title", "secret east payload"),
                ("two", "tenant-west", "Sensitive west title", "secret west payload"),
                ("three", None, "Legacy unbound title", "secret unbound payload"),
            ],
        )


def create_unscoped_validation_database(path) -> None:
    with sqlite3.connect(path) as database:
        database.execute(
            """CREATE TABLE validation_tasks (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                result_json TEXT NOT NULL
            )"""
        )
        database.execute(
            "INSERT INTO validation_tasks VALUES (?,?,?)",
            ("validation-one", "Sensitive validation", '{"raw_event":"must not leak"}'),
        )


def binding() -> dict[str, str]:
    return {
        "alias": "east-prod",
        "fingerprint": "a" * 64,
        "tenant_scope_id": "tenant-east",
    }


def test_readiness_plan_counts_scope_without_reading_payload_content(tmp_path) -> None:
    create_scoped_evidence_database(tmp_path / "evidence.db")
    create_unscoped_validation_database(tmp_path / "validations.db")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "discovery-tenant-east.json").write_text(
        "extremely sensitive discovery content", encoding="utf-8"
    )
    (artifacts / "discovery-tenant-west.json").write_text(
        "other sensitive discovery content", encoding="utf-8"
    )

    registry = TenantDataPlaneRegistry(tmp_path / "tenant_isolation.db", tmp_path)
    registry.register_file("discovery-files", artifacts / "discovery-tenant-east.json", binding())
    registry.register_file(
        "discovery-files",
        artifacts / "discovery-tenant-west.json",
        {"alias": "west-prod", "fingerprint": "b" * 64, "tenant_scope_id": "tenant-west"},
    )
    planner = TenantIsolationPlanner(
        tmp_path,
        TenantIsolationStore(tmp_path / "tenant_isolation.db"),
        registry,
    )
    first = planner.preview(binding())
    second = planner.preview(binding())

    evidence = next(item for item in first["components"] if item["id"] == "evidence")
    validations = next(item for item in first["components"] if item["id"] == "validations")
    discovery_files = next(item for item in first["components"] if item["id"] == "discovery-files")
    serialized = json.dumps(first)

    assert first["plan_id"] == second["plan_id"]
    assert first["generated_at"] != ""
    assert first["migration_executable"] is False
    assert first["activation_available"] is False
    assert first["target_root"] == "tenants/tenant-east"
    assert evidence["scope_records"] == 1
    assert evidence["other_scope_records"] == 1
    assert evidence["unbound_records"] == 1
    assert validations["total_records"] == 1
    assert validations["readiness"] == "scope-key-required"
    assert discovery_files["scope_records"] == 1
    assert discovery_files["other_scope_records"] == 1
    assert "secret east payload" not in serialized
    assert "must not leak" not in serialized
    assert "extremely sensitive discovery content" not in serialized


def test_created_plan_is_review_only_and_retained_in_global_control_plane(tmp_path) -> None:
    store = TenantIsolationStore(tmp_path / "tenant_isolation.db")
    registry = TenantDataPlaneRegistry(tmp_path / "tenant_isolation.db", tmp_path)
    planner = TenantIsolationPlanner(tmp_path, store, registry)

    plan = planner.create_plan(binding(), "security-admin")
    overview = planner.overview()

    assert plan["created_by"] == "security-admin"
    assert overview["runtime"] == {
        "mode": "shared-row-filtered",
        "physical_isolation_enforced": False,
        "activation_available": True,
        "detail": (
            "Tenant predicates are enforced. Eight workflow databases and two manifested "
            "file roots can enter one digest-verified isolated generation."
        ),
    }
    assert overview["contract"]["plan_parses_payload_content"] is False
    assert overview["contract"]["plan_hashes_manifested_files"] is True
    assert overview["contract"]["plan_moves_data"] is False
    assert overview["contract"]["plan_changes_runtime_routing"] is False
    assert overview["latest_plans"][0]["plan_id"] == plan["plan_id"]
    assert overview["latest_plans"][0]["created_by"] == "security-admin"


def test_remaining_workflow_roots_expose_direct_copy_contracts(tmp_path) -> None:
    TimeSeriesExperimentStore(tmp_path / "time_series_experiments.db")
    AssuranceStore(tmp_path / "assurance.db")
    DeliveryStore(tmp_path / "delivery.db")
    planner = TenantIsolationPlanner(
        tmp_path,
        TenantIsolationStore(tmp_path / "tenant_isolation.db"),
    )

    plan = planner.preview(binding())
    components = {item["id"]: item for item in plan["components"]}

    for component_id in (
        "forecast-experiments",
        "assurance-responses",
        "outbound-delivery",
    ):
        assert components[component_id]["readiness"] == "copy-contract-ready"
        assert components[component_id]["schema_observed"] is True
        assert components[component_id]["unbound_records"] == 0


@pytest.mark.parametrize(
    "tenant_scope_id",
    ["", "UPPERCASE", "../escape", "a", "tenant/escape"],
)
def test_isolation_planning_rejects_unsafe_tenant_roots(tmp_path, tenant_scope_id: str) -> None:
    planner = TenantIsolationPlanner(
        tmp_path,
        TenantIsolationStore(tmp_path / "tenant_isolation.db"),
    )

    with pytest.raises(ValueError, match="not safe"):
        planner.preview({**binding(), "tenant_scope_id": tenant_scope_id})
