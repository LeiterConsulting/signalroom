import sqlite3

import pytest

from splunk_security_agent.cases import CaseStore
from splunk_security_agent.discovery import DiscoveryJobStore
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import (
    ArtifactCreate,
    CaseCreate,
    CaseItemCreate,
    CaseUpdate,
)
from splunk_security_agent.tenancy import (
    RoutedCaseStore,
    RoutedDiscoveryJobStore,
    RoutedEvidenceStore,
    TenantDataMigrationService,
    TenantDataPlaneRegistry,
)

EAST = {
    "alias": "east-prod",
    "fingerprint": "a" * 64,
    "tenant_scope_id": "tenant-east",
}
WEST = {
    "alias": "west-prod",
    "fingerprint": "b" * 64,
    "tenant_scope_id": "tenant-west",
}


def readiness_plan() -> dict:
    return {
        "plan_id": "c" * 64,
        "components": [
            {"id": component, "readiness": "copy-contract-ready"}
            for component in ("evidence", "cases", "manual-discovery")
        ],
    }


def artifact(binding: dict[str, str], title: str) -> ArtifactCreate:
    return ArtifactCreate(
        title=title,
        content=f"{title} content used to prove an exact tenant copy",
        kind="note",
        source="test",
        tags=[binding["tenant_scope_id"]],
        connection_alias=binding["alias"],
        connection_fingerprint=binding["fingerprint"],
        tenant_scope_id=binding["tenant_scope_id"],
    )


def seed_shared_stores(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.db")
    east_artifact = evidence.add(artifact(EAST, "East evidence"))
    west_artifact = evidence.add(artifact(WEST, "West evidence"))
    evidence.save_embeddings(
        "securebert",
        [
            (f"{east_artifact.id}:0", [1.0, 0.0]),
            (f"{west_artifact.id}:0", [0.0, 1.0]),
        ],
    )

    cases = CaseStore(tmp_path / "cases.db", tmp_path / "case_exports")
    east_case = cases.create(
        CaseCreate(
            title="East case",
            owner="East analyst",
            severity="high",
            summary="East-only case",
            tags=["east"],
            connection_alias=EAST["alias"],
            connection_fingerprint=EAST["fingerprint"],
            tenant_scope_id=EAST["tenant_scope_id"],
        )
    )
    cases.add_item(
        east_case.id,
        CaseItemCreate(
            kind="observation",
            title="East observation",
            content="East case payload",
            source="test",
            confidence="high",
            status="observed",
        ),
        EAST["tenant_scope_id"],
    )
    cases.create(
        CaseCreate(
            title="West case",
            owner="West analyst",
            severity="low",
            summary="West-only case",
            tags=["west"],
            connection_alias=WEST["alias"],
            connection_fingerprint=WEST["fingerprint"],
            tenant_scope_id=WEST["tenant_scope_id"],
        )
    )

    jobs = DiscoveryJobStore(tmp_path / "discovery_jobs.db")
    east_job = jobs.create_job("quick", "east-analyst", 8, EAST)
    jobs.complete_job(
        east_job.id,
        "complete",
        {"headline": "East complete", "findings": 1},
        {"run_id": "east-run", "summary": "East result payload"},
        3,
    )
    west_job = jobs.create_job("quick", "west-analyst", 8, WEST)
    jobs.complete_job(
        west_job.id,
        "complete",
        {"headline": "West complete", "findings": 0},
        {"run_id": "west-run", "summary": "West result payload"},
        2,
    )
    return east_artifact, west_artifact, east_case, east_job


def data_plane(tmp_path):
    registry = TenantDataPlaneRegistry(tmp_path / "tenant_isolation.db", tmp_path)
    return registry, TenantDataMigrationService(registry)


def test_stage_verifies_exact_tenant_rows_without_changing_routing(tmp_path) -> None:
    east_artifact, _, east_case, east_job = seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)

    migration = service.stage(EAST, readiness_plan(), "security-admin")

    assert migration["status"] == "verified"
    assert migration["source_digest"] == migration["target_digest"]
    assert registry.route(EAST["tenant_scope_id"])["mode"] == "shared"
    assert {item["id"] for item in migration["components"]} == {
        "evidence",
        "cases",
        "manual-discovery",
    }
    assert all(item["verified"] for item in migration["components"])
    root = registry.generation_root(EAST["tenant_scope_id"], migration["generation_id"])
    assert EvidenceStore(root / "evidence.db").get(east_artifact.id, EAST["tenant_scope_id"])
    assert CaseStore(root / "cases.db", root / "case_exports").get(east_case.id, EAST["tenant_scope_id"])
    assert DiscoveryJobStore(root / "discovery_jobs.db").get_job(east_job.id, EAST["tenant_scope_id"])
    assert EvidenceStore(root / "evidence.db").list(tenant_scope_id=WEST["tenant_scope_id"]) == []


def test_cutover_routes_each_store_and_blocks_lossy_rollback_after_a_write(
    tmp_path,
) -> None:
    east_artifact, west_artifact, east_case, east_job = seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")

    cutover = service.cutover(migration["id"], EAST)
    evidence = RoutedEvidenceStore(registry)
    cases = RoutedCaseStore(registry)
    jobs = RoutedDiscoveryJobStore(registry)

    assert cutover["status"] == "cutover"
    assert registry.route(EAST["tenant_scope_id"])["mode"] == "isolated-routing"
    assert evidence.get(east_artifact.id, EAST["tenant_scope_id"])
    assert evidence.get(west_artifact.id, WEST["tenant_scope_id"])
    assert cases.get(east_case.id, EAST["tenant_scope_id"])
    assert jobs.get_job(east_job.id, EAST["tenant_scope_id"])

    isolated_artifact = evidence.add(artifact(EAST, "Post-cutover evidence"))
    assert evidence.get(isolated_artifact.id, EAST["tenant_scope_id"])
    assert EvidenceStore(tmp_path / "evidence.db").get(isolated_artifact.id) is None

    isolated_case = cases.create(
        CaseCreate(
            title="Post-cutover case",
            owner="East analyst",
            severity="medium",
            summary="Created in the isolated generation",
            connection_alias=EAST["alias"],
            connection_fingerprint=EAST["fingerprint"],
            tenant_scope_id=EAST["tenant_scope_id"],
        )
    )
    cases.add_item(
        isolated_case.id,
        CaseItemCreate(
            kind="note",
            title="Isolated note",
            content="This item must remain in the isolated generation",
        ),
        EAST["tenant_scope_id"],
    )
    cases.update(
        isolated_case.id,
        CaseUpdate(status="investigating"),
        EAST["tenant_scope_id"],
    )
    assert cases.get(
        isolated_case.id, EAST["tenant_scope_id"]
    ).status == "investigating"
    assert CaseStore(tmp_path / "cases.db", tmp_path / "case_exports").get(
        isolated_case.id
    ) is None

    isolated_job = jobs.create_job("quick", "east-analyst", 8, EAST)
    jobs.mark_running(isolated_job.id)
    jobs.update_progress(
        isolated_job.id,
        {"phase": "inventory", "label": "Inventory", "progress": 50},
        1,
    )
    jobs.complete_job(
        isolated_job.id,
        "complete",
        {"headline": "Isolated complete", "findings": 0},
        {"run_id": "isolated-run"},
        2,
    )
    assert jobs.result(isolated_job.id)["run_id"] == "isolated-run"
    assert DiscoveryJobStore(tmp_path / "discovery_jobs.db").get_job(
        isolated_job.id
    ) is None

    assert registry.route(EAST["tenant_scope_id"])["writes_since_cutover"] >= 8
    with pytest.raises(ValueError, match="accepted writes"):
        service.rollback(migration["id"], EAST)


def test_zero_write_cutover_can_return_to_the_sealed_shared_source(tmp_path) -> None:
    east_artifact, *_ = seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)

    rolled_back = service.rollback(migration["id"], EAST)

    assert rolled_back["status"] == "rolled-back"
    assert registry.route(EAST["tenant_scope_id"])["mode"] == "shared"
    assert RoutedEvidenceStore(registry).get(east_artifact.id, EAST["tenant_scope_id"])


def test_cutover_fails_closed_when_shared_source_changes_after_staging(tmp_path) -> None:
    seed_shared_stores(tmp_path)
    _, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    EvidenceStore(tmp_path / "evidence.db").add(artifact(EAST, "Late evidence"))

    with pytest.raises(ValueError, match="changed after staging"):
        service.cutover(migration["id"], EAST)


def test_stage_rejects_active_discovery_and_unready_components(tmp_path) -> None:
    seed_shared_stores(tmp_path)
    jobs = DiscoveryJobStore(tmp_path / "discovery_jobs.db")
    active = jobs.create_job("quick", "east-analyst", 8, EAST)
    jobs.mark_running(active.id)
    _, service = data_plane(tmp_path)

    with pytest.raises(ValueError, match="must finish or be cancelled"):
        service.stage(EAST, readiness_plan(), "security-admin")
    with sqlite3.connect(tmp_path / "discovery_jobs.db") as database:
        assert (
            database.execute("SELECT status FROM discovery_jobs WHERE id=?", (active.id,)).fetchone()[0]
            == "running"
        )

    jobs.fail_job(active.id, "cancelled", "Cancelled for migration", 0)
    plan = readiness_plan()
    plan["components"][0]["readiness"] = "scope-key-required"
    with pytest.raises(ValueError, match="does not admit: evidence"):
        service.stage(EAST, plan, "security-admin")


def test_isolated_route_fails_closed_when_generation_database_is_missing(
    tmp_path,
) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    root = registry.generation_root(EAST["tenant_scope_id"], migration["generation_id"])
    assert (root / "evidence.db").is_file()
    with registry.connect() as database:
        database.execute(
            "UPDATE tenant_data_routes SET generation_id=? WHERE tenant_scope_id=?",
            ("f" * 32, EAST["tenant_scope_id"]),
        )

    with pytest.raises(RuntimeError, match="failed closed"):
        RoutedEvidenceStore(registry).list(tenant_scope_id=EAST["tenant_scope_id"])


def test_registry_does_not_expose_payloads_or_absolute_paths(tmp_path) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    serialized = str(registry.overview())

    assert migration["status"] == "verified"
    assert "East result payload" not in serialized
    assert "East case payload" not in serialized
    assert str(tmp_path) not in serialized
    with sqlite3.connect(tmp_path / "tenant_isolation.db") as database:
        assert database.execute("SELECT COUNT(*) FROM tenant_data_migrations").fetchone()[0] == 1
