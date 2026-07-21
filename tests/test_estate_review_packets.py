import json

import pytest
from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.audit import AuditStore
from splunk_security_agent.auth import AuthService, AuthStore
from splunk_security_agent.discovery import (
    EstateReviewPacketService,
    EstateReviewPacketStore,
)
from splunk_security_agent.tenancy import (
    RoutedDiscoveryJobStore,
    TenantDataPlaneRegistry,
)


def scope(alias: str, fingerprint: str, tenant: str) -> dict[str, str]:
    return {
        "alias": alias,
        "display_name": alias.replace("-", " ").title(),
        "fingerprint": fingerprint,
        "tenant_scope_id": tenant,
    }


def summary(run_id: str, observed_at: str, label: str) -> dict:
    return {
        "run_id": run_id,
        "generated_at": observed_at,
        "depth": "standard",
        "overview": {"indexes": 10, "sourcetypes": 20, "hosts": 30, "sources": 40},
        "coverage": {"score": 75, "domains": {"identity": True, "endpoint": False}},
        "collection_status": {"complete": True, "failed_calls": 0},
        "security_posture": {
            "telemetry": {"stale_over_24h": []},
            "detections": {
                "total": 4,
                "enabled": 3,
                "disabled": 1,
                "apps": [label],
                "disabled_names": [],
            },
            "data_models": {"total": 1, "accelerated": 0, "accelerated_names": []},
            "knowledge": {"macros": 1, "lookups": 2},
            "mltk_models": {"observed": 0},
        },
        "findings": [
            {
                "severity": "medium",
                "domain": "coverage",
                "title": f"{label} private finding",
                "evidence": f"{label} private evidence",
                "next_step": f"Validate only in {label}",
            }
        ],
    }


def harness(tmp_path):
    registry = TenantDataPlaneRegistry(tmp_path / "tenant_isolation.db", tmp_path)
    jobs = RoutedDiscoveryJobStore(registry)
    store = EstateReviewPacketStore(tmp_path / "estate_reviews.db")
    return jobs, store, EstateReviewPacketService(store, jobs)


def completed(jobs, binding, run_id, observed_at, label):
    job = jobs.create_job("standard", "analyst", 12, binding)
    jobs.complete_job(job.id, "complete", {"headline": "done"}, summary(run_id, observed_at, label), 8)
    return job


def test_review_packet_selects_closest_runs_without_copying_facts(tmp_path) -> None:
    jobs, store, service = harness(tmp_path)
    left = scope("east", "a" * 64, "tenant-east")
    right = scope("west", "b" * 64, "tenant-west")
    completed(jobs, left, "left-old", "2026-07-20T12:00:00+00:00", "left-old")
    completed(jobs, right, "right-old", "2026-07-20T12:45:00+00:00", "right-old")
    selected_left = completed(
        jobs, left, "left-aligned", "2026-07-20T20:00:00+00:00", "left-aligned"
    )
    selected_right = completed(
        jobs, right, "right-aligned", "2026-07-20T20:08:00+00:00", "right-aligned"
    )

    result = service.create(left, right, 60, "alice")
    packet = result["packet"]
    manifest = packet["manifest"]

    assert result["integrity_status"] == "verified"
    assert manifest["left"]["discovery_job_id"] == selected_left.id
    assert manifest["right"]["discovery_job_id"] == selected_right.id
    assert manifest["alignment"]["delta_seconds"] == 480
    assert manifest["contract"] == {
        "global_facts_persisted": False,
        "source_snapshots_copied": False,
        "splunk_queries": 0,
        "model_inference": False,
        "materialization": "on-demand-from-tenant-scoped-discovery-jobs",
    }
    assert result["comparison"]["findings"]["left"][0]["title"] == (
        "left-aligned private finding"
    )
    raw_manifest = store.path.read_bytes()
    assert b"private finding" not in raw_manifest
    assert b"private evidence" not in raw_manifest
    assert b'"metrics"' not in json.dumps(manifest).encode()

    rematerialized = service.get(packet["id"])
    assert rematerialized is not None
    assert rematerialized["comparison"]["comparison_id"] == manifest["comparison_id"]
    assert service.overview(allowed_connection_ids={"east"})["packets"] == []
    assert len(service.overview(allowed_connection_ids={"east", "west"})["packets"]) == 1

    reviewed = service.set_status(packet["id"], "reviewed", "bob")
    assert reviewed is not None
    assert reviewed["status"] == "reviewed"
    assert reviewed["reviewed_by"] == "bob"


def test_review_packet_rejects_misalignment_and_tampered_source(tmp_path) -> None:
    jobs, _, service = harness(tmp_path)
    left = scope("east", "a" * 64, "tenant-east")
    right = scope("west", "b" * 64, "tenant-west")
    left_job = completed(jobs, left, "left", "2026-07-20T10:00:00+00:00", "left")
    completed(jobs, right, "right", "2026-07-20T14:00:00+00:00", "right")

    with pytest.raises(ValueError, match="outside the 60-minute alignment window"):
        service.create(left, right, 60, "alice")

    packet = service.create(left, right, 360, "alice")["packet"]
    with jobs._shared().connect() as database:
        database.execute(
            "UPDATE discovery_jobs SET result=? WHERE id=?",
            (json.dumps(summary("left", "2026-07-20T10:00:00+00:00", "tampered")), left_job.id),
        )
    with pytest.raises(ValueError, match="failed its packet digest check"):
        service.get(packet["id"])


def test_review_packet_requires_durable_runs_for_both_scopes(tmp_path) -> None:
    jobs, _, service = harness(tmp_path)
    left = scope("east", "a" * 64, "tenant-east")
    right = scope("west", "b" * 64, "tenant-west")
    completed(jobs, left, "left", "2026-07-20T10:00:00+00:00", "left")

    with pytest.raises(ValueError, match="No completed durable discovery run exists"):
        service.create(left, right, 60, "alice")


def test_review_packet_api_creates_lists_opens_and_updates(tmp_path, monkeypatch) -> None:
    jobs, store, service = harness(tmp_path)
    left = scope("east", "a" * 64, "tenant-east")
    right = scope("west", "b" * 64, "tenant-west")
    completed(jobs, left, "left", "2026-07-20T10:00:00+00:00", "left")
    completed(jobs, right, "right", "2026-07-20T10:05:00+00:00", "right")
    audit = AuditStore(tmp_path / "audit.db")
    auth_store = AuthStore(tmp_path / "auth.db")
    auth = AuthService(auth_store, audit)
    scopes = {"east": left, "west": right}

    def resolve(alias, fingerprint, tenant):
        current = scopes.get(alias)
        if not current or current["fingerprint"] != fingerprint or current["tenant_scope_id"] != tenant:
            raise ValueError("Scope binding is not current")
        return current

    monkeypatch.setattr(app_module.services, "estate_review_store", store)
    monkeypatch.setattr(app_module.services, "estate_reviews", service)
    monkeypatch.setattr(app_module.services, "audit", audit)
    monkeypatch.setattr(app_module.services, "auth_store", auth_store)
    monkeypatch.setattr(app_module.services, "auth", auth)
    monkeypatch.setattr(app_module.services, "resolve_scope", resolve)
    client = TestClient(app_module.app)
    payload = {
        "left": {
            "connection_alias": "east",
            "connection_fingerprint": "a" * 64,
            "tenant_scope_id": "tenant-east",
        },
        "right": {
            "connection_alias": "west",
            "connection_fingerprint": "b" * 64,
            "tenant_scope_id": "tenant-west",
        },
        "alignment_window_minutes": 60,
    }

    created = client.post("/api/discovery/review-packets", json=payload)
    assert created.status_code == 201
    packet_id = created.json()["packet"]["id"]
    assert created.json()["integrity_status"] == "verified"
    listed = client.get("/api/discovery/review-packets")
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "no-store"
    assert [item["id"] for item in listed.json()["packets"]] == [packet_id]
    opened = client.get(f"/api/discovery/review-packets/{packet_id}")
    assert opened.status_code == 200
    assert opened.json()["comparison"]["findings"]["left"][0]["title"] == (
        "left private finding"
    )
    reviewed = client.patch(
        f"/api/discovery/review-packets/{packet_id}", json={"status": "reviewed"}
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "reviewed"
