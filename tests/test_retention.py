from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.audit import AuditStore
from splunk_security_agent.auth import AuthService, AuthStore
from splunk_security_agent.recovery import RecoveryPackageService
from splunk_security_agent.retention import RetentionService, RetentionStore
from splunk_security_agent.schemas import RetentionPolicyUpdate
from splunk_security_agent.tenancy import TenantDataPlaneRegistry


def _binding() -> dict[str, str]:
    return {
        "alias": "lab",
        "fingerprint": "a" * 64,
        "tenant_scope_id": "tenant.lab",
    }


def _old(days: int, offset: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days, minutes=offset)).isoformat()


def _service(tmp_path: Path) -> tuple[RetentionService, TenantDataPlaneRegistry]:
    data = tmp_path / "data"
    registry = TenantDataPlaneRegistry(data / "tenant_isolation.db", data)
    store = RetentionStore(data / "retention.db")
    recovery = RecoveryPackageService(data, "0.1.0")
    service = RetentionService(store, registry, recovery)
    service.update_policy(
        RetentionPolicyUpdate(
            generation_min_age_days=1,
            generation_keep_count=1,
            reverse_min_age_days=1,
            reverse_keep_count=1,
            recovery_export_min_age_days=1,
            recovery_export_keep_count=1,
            recovery_checkpoint_min_age_days=1,
            recovery_checkpoint_keep_count=1,
        ),
        "admin",
    )
    return service, registry


def _failed_generation(
    registry: TenantDataPlaneRegistry,
    *,
    days_old: int,
    offset: int,
) -> dict:
    migration = registry.begin_migration(_binding(), f"plan-{offset}", "admin")
    root = registry.generation_root("tenant.lab", migration["generation_id"])
    root.mkdir(parents=True)
    (root / "evidence.db").write_bytes(f"generation-{offset}".encode())
    registry.failed(migration["id"], "synthetic failure")
    timestamp = _old(days_old, offset)
    with registry.connect() as database:
        database.execute(
            """UPDATE tenant_data_migrations SET created_at=?,updated_at=? WHERE id=?""",
            (timestamp, timestamp, migration["id"]),
        )
    return {**migration, "root": root}


def test_retention_preview_keeps_latest_and_executes_exact_manifest(tmp_path: Path) -> None:
    service, registry = _service(tmp_path)
    generations = [
        _failed_generation(registry, days_old=60, offset=index) for index in range(3)
    ]

    preview = service.preview()

    assert preview["candidate_count"] == 2
    assert preview["by_kind"]["tenant-generation"]["count"] == 2
    assert all(item["kind"] == "tenant-generation" for item in preview["candidates"])
    with pytest.raises(ValueError, match="Type CLEAN"):
        service.execute(preview["preview_sha256"], "not-approved", "admin")
    assert all(item["root"].exists() for item in generations)

    result = service.execute(
        preview["preview_sha256"],
        preview["confirmation"],
        "admin",
    )

    assert result["run"]["status"] == "complete"
    assert result["run"]["item_count"] == 2
    assert sum(item["root"].exists() for item in generations) == 1
    assert len(registry.retention_migrations()) == 3
    assert service.store.recent_runs()[0]["preview_sha256"] == preview["preview_sha256"]


def test_retention_changed_candidate_fails_before_any_deletion(tmp_path: Path) -> None:
    service, registry = _service(tmp_path)
    generations = [
        _failed_generation(registry, days_old=60, offset=index) for index in range(3)
    ]
    preview = service.preview()
    candidate_path = service.data_root / preview["candidates"][0]["relative_path"]
    (candidate_path / "evidence.db").write_bytes(b"changed-after-preview")

    with pytest.raises(ValueError, match="inventory changed"):
        service.execute(preview["preview_sha256"], preview["confirmation"], "admin")

    assert all(item["root"].exists() for item in generations)
    assert service.store.recent_runs() == []


def test_active_tenant_generation_is_never_a_cleanup_candidate(tmp_path: Path) -> None:
    service, registry = _service(tmp_path)
    migration = registry.begin_migration(_binding(), "active-plan", "admin")
    root = registry.generation_root("tenant.lab", migration["generation_id"])
    root.mkdir(parents=True)
    (root / "evidence.db").write_bytes(b"active-generation")
    registry.verified(migration["id"], "same", "same", [])
    registry.cutover(migration["id"])
    with registry.connect() as database:
        database.execute(
            """UPDATE tenant_data_migrations SET created_at=?,updated_at=? WHERE id=?""",
            (_old(120), _old(120), migration["id"]),
        )

    preview = service.preview()

    assert preview["protected"]["active_generation_count"] == 1
    assert migration["generation_id"] not in {
        item["id"] for item in preview["candidates"]
    }
    assert root.exists()


def test_pending_recovery_files_are_never_cleanup_candidates(tmp_path: Path) -> None:
    service, _registry = _service(tmp_path)
    export_ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"]
    checkpoint_ids = [
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    ]
    old_time = (datetime.now(UTC) - timedelta(days=60)).timestamp()
    for package_id in export_ids:
        path = service.recovery.exports / f"signalroom-control-plane-{package_id}.signalroom-recovery"
        path.write_bytes(package_id.encode())
        os.utime(path, (old_time, old_time))
    for package_id in checkpoint_ids:
        path = service.recovery.rollbacks / f"pre-restore-{package_id}.signalroom-recovery"
        path.write_bytes(package_id.encode())
        os.utime(path, (old_time, old_time))
    service.recovery.pending_marker.write_text(
        __import__("json").dumps(
            {
                "package_id": export_ids[0],
                "checkpoint": {"package_id": checkpoint_ids[0]},
            }
        ),
        encoding="utf-8",
    )

    preview = service.preview()
    candidate_ids = {item["id"] for item in preview["candidates"]}

    assert export_ids[0] not in candidate_ids
    assert checkpoint_ids[0] not in candidate_ids
    assert preview["protected"]["pending_recovery_package"] == export_ids[0]
    assert preview["protected"]["pending_recovery_checkpoint"] == checkpoint_ids[0]


def test_admin_retention_api_updates_policy_and_never_caches_preview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _registry = _service(tmp_path)
    auth_store = AuthStore(tmp_path / "auth.db")
    audit = AuditStore(tmp_path / "audit.db")
    auth = AuthService(auth_store, audit)
    monkeypatch.setattr(app_module.services, "retention", service)
    monkeypatch.setattr(app_module.services, "auth_store", auth_store)
    monkeypatch.setattr(app_module.services, "auth", auth)
    monkeypatch.setattr(app_module.services, "audit", audit)
    client = TestClient(app_module.app)

    overview = client.get("/api/retention")
    assert overview.status_code == 200
    assert overview.headers["cache-control"] == "no-store"
    updated = client.put(
        "/api/retention/policy",
        json={
            "generation_min_age_days": 45,
            "generation_keep_count": 3,
            "reverse_min_age_days": 60,
            "reverse_keep_count": 2,
            "recovery_export_min_age_days": 90,
            "recovery_export_keep_count": 4,
            "recovery_checkpoint_min_age_days": 180,
            "recovery_checkpoint_keep_count": 5,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["policy"]["generation_min_age_days"] == 45
    assert updated.json()["policy"]["revision"] == 3

    def conflicting_update(*_args: object) -> dict:
        raise ValueError("The retention policy changed; reload it before saving.")

    monkeypatch.setattr(service, "update_policy", conflicting_update)
    conflicted = client.put(
        "/api/retention/policy",
        json={
            "generation_min_age_days": 45,
            "generation_keep_count": 3,
            "reverse_min_age_days": 60,
            "reverse_keep_count": 2,
            "recovery_export_min_age_days": 90,
            "recovery_export_keep_count": 4,
            "recovery_checkpoint_min_age_days": 180,
            "recovery_checkpoint_keep_count": 5,
        },
    )
    assert conflicted.status_code == 409
    assert "reload it before saving" in conflicted.json()["detail"]

    blocked = client.post(
        "/api/retention/cleanup",
        json={
            "expected_preview_sha256": updated.json()["preview"]["preview_sha256"],
            "confirmation": "CLEAN 0 ITEMS 000000000000",
        },
    )
    assert blocked.status_code == 409
    assert "No retained local storage" in blocked.json()["detail"]
