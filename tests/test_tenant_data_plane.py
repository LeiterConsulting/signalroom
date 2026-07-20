import json
import sqlite3

import pytest

from splunk_security_agent.assurance import AssuranceStore
from splunk_security_agent.cases import CaseStore
from splunk_security_agent.delivery import DeliveryStore
from splunk_security_agent.detections import DetectionStore
from splunk_security_agent.discovery import DiscoveryJobStore
from splunk_security_agent.forecasting import TimeSeriesExperimentStore
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import (
    ArtifactCreate,
    CaseCreate,
    CaseItemCreate,
    CaseUpdate,
    ValidationTaskCreate,
)
from splunk_security_agent.tenancy import (
    RoutedAssuranceStore,
    RoutedCaseStore,
    RoutedDeliveryStore,
    RoutedDetectionStore,
    RoutedDiscoveryJobStore,
    RoutedEvidenceStore,
    RoutedTimeSeriesExperimentStore,
    RoutedValidationStore,
    TenantDataMigrationService,
    TenantDataPlaneRegistry,
)
from splunk_security_agent.validation import ValidationStore

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
            for component in (
                "evidence",
                "cases",
                "manual-discovery",
                "validations",
                "detections",
                "forecast-experiments",
                "assurance-responses",
                "outbound-delivery",
                "discovery-files",
                "case-exports",
            )
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
    ValidationStore(tmp_path / "validations.db")
    DetectionStore(tmp_path / "detections.db")
    TimeSeriesExperimentStore(tmp_path / "time_series_experiments.db")
    AssuranceStore(tmp_path / "assurance.db")
    DeliveryStore(tmp_path / "delivery.db")
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
        "validations",
        "detections",
        "forecast-experiments",
        "assurance-responses",
        "outbound-delivery",
        "discovery-files",
        "case-exports",
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
    assert cases.get(isolated_case.id, EAST["tenant_scope_id"]).status == "investigating"
    assert CaseStore(tmp_path / "cases.db", tmp_path / "case_exports").get(isolated_case.id) is None
    exported = cases.export(isolated_case.id, ["markdown", "json"], EAST["tenant_scope_id"])
    root = registry.generation_root(EAST["tenant_scope_id"], migration["generation_id"])
    assert {path.parent for path in exported} == {root / "case_exports"}
    export_manifests = registry.manifested_files(
        "case-exports", EAST, storage_generation_id=migration["generation_id"]
    )
    assert {item["relative_path"] for item in export_manifests} == {
        path.name for path in exported
    }

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
    assert DiscoveryJobStore(tmp_path / "discovery_jobs.db").get_job(isolated_job.id) is None

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


def test_cutover_routes_validation_detection_forecast_response_and_delivery_roots(
    tmp_path,
) -> None:
    seed_shared_stores(tmp_path)
    AssuranceStore(tmp_path / "assurance.db").bind_unbound(EAST)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)

    validations = RoutedValidationStore(registry)
    validation = validations.create(
        ValidationTaskCreate(
            title="Validate east telemetry",
            rationale="Prove routed validation ownership.",
            spl="index=east | head 10",
            earliest_time="-1h",
            latest_time="now",
            row_limit=10,
            connection_alias=EAST["alias"],
            connection_fingerprint=EAST["fingerprint"],
            tenant_scope_id=EAST["tenant_scope_id"],
        )
    )
    assert ValidationStore(tmp_path / "validations.db").get(validation.id) is None
    assert validations.get(validation.id, EAST["tenant_scope_id"]) is not None

    detections = RoutedDetectionStore(registry)
    detection = detections.create(
        "east-detection",
        validation.id,
        None,
        {"name": "East detection", "search": "index=east | head 10"},
        connection_alias=EAST["alias"],
        connection_fingerprint=EAST["fingerprint"],
        tenant_scope_id=EAST["tenant_scope_id"],
    )
    assert DetectionStore(tmp_path / "detections.db").get(detection["id"]) is None
    assert detections.get(detection["id"], EAST["tenant_scope_id"]) is not None

    forecasts = RoutedTimeSeriesExperimentStore(registry)
    forecast = forecasts.record(
        {"spl": "index=east | timechart count", "timestamp_field": "_time", "value_field": "count"},
        {
            "run_id": "east-forecast",
            "title": "East event volume",
            "status": "complete",
            "executed_at": "2026-07-20T12:00:00+00:00",
            "source": {
                "connection_alias": EAST["alias"],
                "connection_fingerprint": EAST["fingerprint"],
                "tenant_scope_id": EAST["tenant_scope_id"],
            },
            "series": {"end": "2026-07-20T12:00:00+00:00"},
            "promotion_gate": {"ready": False},
        },
        actor="east-analyst",
    )
    assert TimeSeriesExperimentStore(tmp_path / "time_series_experiments.db").get(forecast["id"]) is None
    assert forecasts.get(forecast["id"], EAST["tenant_scope_id"]) is not None

    assurance = RoutedAssuranceStore(registry)
    run = assurance.create_run("manual", "quick", 4)
    signal = assurance.correlate_signals(
        run.id,
        [
            {
                "fingerprint": "east-gap",
                "kind": "coverage",
                "severity": "high",
                "title": "East coverage gap",
                "detail": "A scoped response record.",
                "subject": "east",
                "source_ref": "D1",
            }
        ],
        authoritative=True,
    )[0]
    package = assurance.create_package(
        run.id,
        "high",
        "East response",
        "Review the east signal.",
        [signal["fingerprint"]],
        "2099-01-01T00:00:00+00:00",
    )
    assert AssuranceStore(tmp_path / "assurance.db").get_package(package["id"]) is None
    assert assurance.get_package(package["id"], EAST["tenant_scope_id"]) is not None

    delivery = RoutedDeliveryStore(registry)
    job = delivery.approve(
        package_id=package["id"],
        approval_mode="manual",
        destination_kind="generic-webhook",
        destination_label="Test",
        destination_fingerprint="d" * 64,
        payload={"package_id": package["id"]},
        payload_sha256="e" * 64,
        idempotency_key="east-delivery",
        max_attempts=3,
        binding={
            "connection_alias": EAST["alias"],
            "connection_fingerprint": EAST["fingerprint"],
            "tenant_scope_id": EAST["tenant_scope_id"],
        },
    )
    assert DeliveryStore(tmp_path / "delivery.db").get(job["id"]) is None
    assert delivery.get(job["id"], EAST["tenant_scope_id"]) is not None
    assert registry.route(EAST["tenant_scope_id"])["writes_since_cutover"] >= 5


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


def test_legacy_three_component_generation_keeps_new_workflows_on_shared_source(
    tmp_path,
) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    legacy_components = [
        item for item in migration["components"] if item["id"] in {"evidence", "cases", "manual-discovery"}
    ]
    with registry.connect() as database:
        database.execute(
            "UPDATE tenant_data_migrations SET components_json=? WHERE id=?",
            (json.dumps(legacy_components, sort_keys=True), migration["id"]),
        )

    validations = RoutedValidationStore(registry)
    task = validations.create(
        ValidationTaskCreate(
            title="Legacy-route validation",
            rationale="New workflow roots remain shared until a verified expanded migration.",
            spl="index=east | head 1",
            earliest_time="-15m",
            latest_time="now",
            row_limit=1,
            connection_alias=EAST["alias"],
            connection_fingerprint=EAST["fingerprint"],
            tenant_scope_id=EAST["tenant_scope_id"],
        )
    )

    assert registry.component_isolated("evidence", EAST["tenant_scope_id"]) is True
    assert registry.component_isolated("validations", EAST["tenant_scope_id"]) is False
    generation_root = registry.generation_root(
        EAST["tenant_scope_id"], migration["generation_id"]
    )
    assert registry.directory_for("discovery-files", EAST["tenant_scope_id"]) == tmp_path / "artifacts"
    assert registry.directory_for("case-exports", EAST["tenant_scope_id"]) == (
        generation_root / "case_exports"
    )
    assert ValidationStore(tmp_path / "validations.db").get(task.id) is not None
    assert registry.route(EAST["tenant_scope_id"])["writes_since_cutover"] == 0
    RoutedEvidenceStore(registry).add(artifact(EAST, "Legacy generation write"))
    discovery_file = tmp_path / "artifacts" / "legacy-expanded.json"
    discovery_file.write_text("legacy shared discovery file", encoding="utf-8")
    registry.register_file("discovery-files", discovery_file, EAST, source_id="legacy-run")
    case_export = generation_root / "case_exports" / "legacy-case.md"
    case_export.write_text("legacy isolated case export", encoding="utf-8")
    registry.register_file("case-exports", case_export, EAST, source_id="legacy-case")
    prior_writes = registry.route(EAST["tenant_scope_id"])["writes_since_cutover"]
    assert prior_writes == 2

    expanded = service.stage(EAST, readiness_plan(), "security-admin")
    assert expanded["source_generation_id"] == migration["generation_id"]
    assert expanded["source_writes_since_cutover"] == prior_writes
    expanded_root = registry.generation_root(EAST["tenant_scope_id"], expanded["generation_id"])
    assert (expanded_root / "artifacts" / discovery_file.name).is_file()
    assert (expanded_root / "case_exports" / case_export.name).is_file()
    service.cutover(expanded["id"], EAST)
    assert registry.component_isolated("validations", EAST["tenant_scope_id"]) is True
    assert validations.get(task.id, EAST["tenant_scope_id"]) is not None
    assert ValidationStore(tmp_path / "validations.db").get(task.id) is not None

    rolled_back = service.rollback(expanded["id"], EAST)
    assert rolled_back["status"] == "rolled-back"
    assert registry.route(EAST["tenant_scope_id"])["generation_id"] == migration["generation_id"]
    assert registry.route(EAST["tenant_scope_id"])["writes_since_cutover"] == prior_writes
    assert validations.get(task.id, EAST["tenant_scope_id"]) is not None
    with pytest.raises(ValueError, match="accepted writes"):
        service.rollback(migration["id"], EAST)


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


def test_manifested_files_are_digest_verified_and_routed_with_the_generation(tmp_path) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    artifact_root = registry.directory_for("discovery-files", EAST["tenant_scope_id"])
    export_root = registry.directory_for("case-exports", EAST["tenant_scope_id"])
    blueprint = artifact_root / "east-blueprint.json"
    handoff = export_root / "east-case.md"
    blueprint.write_text("tenant east discovery payload", encoding="utf-8")
    handoff.write_text("tenant east case handoff", encoding="utf-8")
    registry.register_file("discovery-files", blueprint, EAST, source_id="run-east")
    registry.register_file("case-exports", handoff, EAST, source_id="case-east")

    migration = service.stage(EAST, readiness_plan(), "security-admin")
    root = registry.generation_root(EAST["tenant_scope_id"], migration["generation_id"])

    assert (root / "artifacts" / blueprint.name).read_text(encoding="utf-8") == blueprint.read_text(
        encoding="utf-8"
    )
    assert (root / "case_exports" / handoff.name).is_file()
    assert next(item for item in migration["components"] if item["id"] == "discovery-files")[
        "verified"
    ]

    service.cutover(migration["id"], EAST)
    assert registry.directory_for("discovery-files", EAST["tenant_scope_id"]) == root / "artifacts"
    assert registry.directory_for("case-exports", EAST["tenant_scope_id"]) == root / "case_exports"


def test_manifested_file_change_blocks_cutover(tmp_path) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    artifact_root = registry.directory_for("discovery-files", EAST["tenant_scope_id"])
    blueprint = artifact_root / "east-blueprint.json"
    blueprint.write_text("verified discovery payload", encoding="utf-8")
    registry.register_file("discovery-files", blueprint, EAST, source_id="run-east")
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    blueprint.write_text("changed after staging", encoding="utf-8")

    with pytest.raises(ValueError, match="Shared tenant data changed"):
        service.cutover(migration["id"], EAST)


def test_legacy_reconciliation_adopts_only_exact_embedded_ownership(tmp_path) -> None:
    registry, _ = data_plane(tmp_path)
    artifact_root = registry.directory_for("discovery-files", EAST["tenant_scope_id"])
    export_root = registry.directory_for("case-exports", EAST["tenant_scope_id"])
    brief = artifact_root / "east-brief.md"
    brief.write_text("legacy east brief", encoding="utf-8")
    (artifact_root / "east-blueprint.json").write_text(
        json.dumps(
            {
                "run_id": "east-run",
                "provenance": {
                    "connection_alias": EAST["alias"],
                    "connection_fingerprint": EAST["fingerprint"],
                    "tenant_scope_id": EAST["tenant_scope_id"],
                },
                "artifacts": ["east-blueprint.json", brief.name],
            }
        ),
        encoding="utf-8",
    )
    (artifact_root / "ambiguous.json").write_text(
        json.dumps({"run_id": "unknown"}), encoding="utf-8"
    )
    case_json = export_root / "east-case.json"
    case_json.write_text(
        json.dumps(
            {
                "id": "case-east",
                "connection_alias": EAST["alias"],
                "connection_fingerprint": EAST["fingerprint"],
                "tenant_scope_id": EAST["tenant_scope_id"],
            }
        ),
        encoding="utf-8",
    )
    case_json.with_suffix(".md").write_text(
        f"- Splunk connection: {EAST['alias']}\n"
        f"- Tenant scope: `{EAST['tenant_scope_id']}`\n"
        f"- Connection revision: `{EAST['fingerprint']}`\n",
        encoding="utf-8",
    )

    result = registry.reconcile_legacy_files(EAST)

    assert result["adopted_total"] == 4
    assert result["unbound_remaining"] == 1
    assert result["contract"]["files_moved_or_deleted"] is False
    assert registry.reconcile_legacy_files(EAST)["adopted_total"] == 0
    assert registry.inspect_files("discovery-files", EAST)["unbound_records"] == 1


def test_verified_reverse_migration_preserves_isolated_writes_and_other_tenants(
    tmp_path,
) -> None:
    east_artifact, west_artifact, *_ = seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    evidence = RoutedEvidenceStore(registry)
    isolated = evidence.add(artifact(EAST, "East after cutover"))
    discovery_root = registry.directory_for("discovery-files", EAST["tenant_scope_id"])
    discovery_file = discovery_root / "east-after-cutover.json"
    discovery_file.write_text("isolated discovery payload", encoding="utf-8")
    registry.register_file("discovery-files", discovery_file, EAST, source_id="east-run")

    reverse = service.stage_reverse(EAST, "security-admin")

    assert reverse["status"] == "verified"
    assert reverse["source_digest"]
    assert reverse["shared_baseline_digest"] != reverse["shared_target_digest"]
    assert registry.route(EAST["tenant_scope_id"])["mode"] == "isolated-routing"

    applied = service.apply_reverse(
        reverse["id"],
        EAST,
        reverse["source_digest"],
        reverse["shared_target_digest"],
    )

    assert applied["status"] == "applied"
    assert registry.route(EAST["tenant_scope_id"])["mode"] == "shared"
    shared = EvidenceStore(tmp_path / "evidence.db")
    assert shared.get(east_artifact.id, EAST["tenant_scope_id"])
    assert shared.get(isolated.id, EAST["tenant_scope_id"])
    assert shared.get(west_artifact.id, WEST["tenant_scope_id"])
    assert (tmp_path / "artifacts" / discovery_file.name).read_text(encoding="utf-8") == (
        "isolated discovery payload"
    )
    assert registry.manifested_files("discovery-files", EAST, storage_generation_id="")


def test_shared_source_finalization_is_reversible_through_verified_snapshot(
    tmp_path,
) -> None:
    east_artifact, west_artifact, *_ = seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    isolated = RoutedEvidenceStore(registry).add(artifact(EAST, "Finalized east evidence"))
    reverse = service.stage_reverse(EAST, "security-admin")

    finalized = service.finalize_shared_source(
        reverse["id"],
        EAST,
        reverse["source_digest"],
        reverse["shared_target_digest"],
    )

    route = registry.route(EAST["tenant_scope_id"])
    shared = EvidenceStore(tmp_path / "evidence.db")
    assert finalized["status"] == "finalized-ready"
    assert finalized["pre_finalize_shared_digest"]
    assert route["mode"] == "isolated-routing"
    assert route["shared_source_purged"] == 1
    assert shared.get(east_artifact.id, EAST["tenant_scope_id"]) is None
    assert shared.get(isolated.id, EAST["tenant_scope_id"]) is None
    assert shared.get(west_artifact.id, WEST["tenant_scope_id"])
    assert RoutedEvidenceStore(registry).get(isolated.id, EAST["tenant_scope_id"])
    with pytest.raises(ValueError, match="verified reverse migration"):
        service.rollback(migration["id"], EAST)

    service.apply_reverse(
        reverse["id"],
        EAST,
        reverse["source_digest"],
        reverse["shared_target_digest"],
    )

    assert registry.route(EAST["tenant_scope_id"])["mode"] == "shared"
    assert EvidenceStore(tmp_path / "evidence.db").get(isolated.id, EAST["tenant_scope_id"])
    assert EvidenceStore(tmp_path / "evidence.db").get(west_artifact.id, WEST["tenant_scope_id"])


def test_reverse_apply_blocks_unrelated_shared_changes_and_wrong_confirmation(
    tmp_path,
) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    reverse = service.stage_reverse(EAST, "security-admin")

    with pytest.raises(ValueError, match="digest confirmation"):
        service.apply_reverse(
            reverse["id"], EAST, "0" * 64, reverse["shared_target_digest"]
        )

    EvidenceStore(tmp_path / "evidence.db").add(artifact(WEST, "West changed later"))
    with pytest.raises(ValueError, match="Shared evidence changed"):
        service.apply_reverse(
            reverse["id"],
            EAST,
            reverse["source_digest"],
            reverse["shared_target_digest"],
        )
    assert registry.route(EAST["tenant_scope_id"])["mode"] == "isolated-routing"


def test_failed_reverse_refresh_retains_last_verified_path(tmp_path, monkeypatch) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    verified = service.stage_reverse(EAST, "security-admin")

    monkeypatch.setattr(
        service,
        "_stage_reverse_component",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("copy failed")),
    )
    with pytest.raises(ValueError, match="copy failed"):
        service.stage_reverse(EAST, "security-admin")

    assert registry.reverse_migration(verified["id"])["status"] == "verified"


def test_interrupted_reverse_apply_recovers_as_resumable(tmp_path) -> None:
    seed_shared_stores(tmp_path)
    registry, service = data_plane(tmp_path)
    migration = service.stage(EAST, readiness_plan(), "security-admin")
    service.cutover(migration["id"], EAST)
    isolated = RoutedEvidenceStore(registry).add(artifact(EAST, "Write before interruption"))
    reverse = service.stage_reverse(EAST, "security-admin")
    applying, _ = registry.begin_reverse_apply(reverse["id"])
    service._apply_reverse_component(
        applying["components"][0],
        EAST,
        registry.reverse_root(EAST["tenant_scope_id"], reverse["id"]),
    )
    assert EvidenceStore(tmp_path / "evidence.db").get(
        isolated.id, EAST["tenant_scope_id"]
    )

    recovered = TenantDataPlaneRegistry(tmp_path / "tenant_isolation.db", tmp_path)

    value = recovered.reverse_migration(reverse["id"])
    assert value["status"] == "verified"
    assert "restarted during reverse apply" in value["error"]
    assert value["apply_available"] is True
    result = TenantDataMigrationService(recovered).apply_reverse(
        reverse["id"],
        EAST,
        reverse["source_digest"],
        reverse["shared_target_digest"],
    )
    assert result["status"] == "applied"
    assert recovered.route(EAST["tenant_scope_id"])["mode"] == "shared"
