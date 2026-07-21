from __future__ import annotations

import gc
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.audit import AuditStore
from splunk_security_agent.auth import AuthStore
from splunk_security_agent.auth.service import AuthService
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.connections import ConnectionRegistryStore
from splunk_security_agent.model_trust.signing import ModelTrustSigningKey
from splunk_security_agent.model_trust.store import ModelTrustStore
from splunk_security_agent.recovery import (
    RecoveryPackageError,
    RecoveryPackageService,
    apply_pending_restore,
)
from splunk_security_agent.recovery.cli import main as recovery_main

PASSWORD = "correct horse battery staple recovery"


def control_plane(root: Path, endpoint: str = "https://splunk.example/services/mcp") -> ConfigStore:
    config = ConfigStore(root)
    settings = config.load()
    settings.configured = True
    settings.splunk.url = endpoint
    config.save(settings)
    config.update_secrets(splunk_token=f"token-for-{endpoint}")
    ConnectionRegistryStore(root / "connection_registry.db").sync_primary(
        settings.splunk,
        demo_mode=False,
    )
    AuthStore(root / "auth.db")
    ModelTrustStore(root / "model_trust.db")
    ModelTrustSigningKey(root / "model_trust_signing.key").key_id()
    return config


def test_recovery_package_is_encrypted_and_inspected_without_mutation(tmp_path: Path) -> None:
    root = tmp_path / "data"
    control_plane(root)
    service = RecoveryPackageService(root, "0.1.0")

    created = service.create(PASSWORD, "security-admin")
    package = service.export_path(created["package_id"]).read_bytes()

    assert b"token-for-" not in package
    assert b"splunk.example" not in package
    inspected = service.inspect(package, PASSWORD)
    assert inspected["inspection_is_read_only"] is True
    assert inspected["compatibility"]["compatible"] is True
    assert inspected["manifest"]["package_type"] == "operator-backup"
    assert inspected["validations"]["credential-vault"]["secret_entries"] == 1
    assert inspected["validations"]["auth.db"]["rbac_enabled"] is False
    assert not service.pending_marker.exists()
    assert service.overview()["pending_restore"] is None


def test_recovery_rehearsal_discards_package_password_and_restore_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    control_plane(root)
    service = RecoveryPackageService(root, "0.1.0")

    receipt = service.rehearse("security-admin")

    assert receipt["status"] == "pass"
    assert receipt["package_retained"] is False
    assert receipt["password_retained"] is False
    assert receipt["restore_staged"] is False
    assert receipt["live_state_changed"] is False
    assert len(receipt["components"]) >= 6
    assert list(service.exports.glob("*")) == []
    assert list(service.inspections.glob("*")) == []
    assert not service.pending_marker.exists()
    assert service.overview()["recent_rehearsals"][0]["id"] == receipt["id"]


def test_recovery_inspection_rejects_wrong_password_and_ciphertext_tampering(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    control_plane(root)
    service = RecoveryPackageService(root, "0.1.0")
    created = service.create(PASSWORD, "security-admin")
    package = service.export_path(created["package_id"]).read_bytes()

    with pytest.raises(RecoveryPackageError, match="password was not accepted"):
        service.inspect(package, "this password is definitely incorrect")

    envelope = json.loads(package)
    envelope["ciphertext_sha256"] = "0" * 64
    with pytest.raises(RecoveryPackageError, match="integrity preflight"):
        service.inspect(json.dumps(envelope).encode(), PASSWORD)


def test_staged_restore_applies_on_start_and_retains_encrypted_checkpoint(tmp_path: Path) -> None:
    root = tmp_path / "data"
    config = control_plane(root, "https://old.example/services/mcp")
    service = RecoveryPackageService(root, "0.1.0")
    created = service.create(PASSWORD, "security-admin")
    package = service.export_path(created["package_id"]).read_bytes()

    settings = config.load()
    settings.splunk.url = "https://current.example/services/mcp"
    config.save(settings)
    config.update_secrets(splunk_token="current-secret")

    inspected = service.inspect(package, PASSWORD)
    staged = service.stage_restore(
        inspected["inspection_id"],
        PASSWORD,
        inspected["confirmation"],
        "security-admin",
    )
    assert staged["status"] == "pending-restart"
    assert staged["mutation_freeze"] is True
    checkpoint_path = service.export_path(staged["checkpoint"]["package_id"], rollback=True)
    checkpoint = service.inspect(checkpoint_path.read_bytes(), PASSWORD)
    assert checkpoint["manifest"]["package_type"] == "automatic-pre-restore-checkpoint"

    # A real restore applies in a fresh process before stores open their Windows file handles.
    gc.collect()
    receipt = apply_pending_restore(root)
    assert receipt is not None
    assert receipt["package_id"] == created["package_id"]
    assert not service.pending_marker.exists()
    restored = ConfigStore(root)
    assert restored.load().splunk.url == "https://old.example/services/mcp"
    assert restored.secret("splunk_token") == "token-for-https://old.example/services/mcp"
    assert apply_pending_restore(root) is None


def test_incompatible_release_can_be_inspected_but_not_staged(tmp_path: Path) -> None:
    root = tmp_path / "data"
    control_plane(root)
    source = RecoveryPackageService(root, "0.1.0")
    created = source.create(PASSWORD, "security-admin")
    package = source.export_path(created["package_id"]).read_bytes()

    newer = RecoveryPackageService(root, "0.2.0")
    inspected = newer.inspect(package, PASSWORD)
    assert inspected["compatibility"]["compatible"] is False
    with pytest.raises(RecoveryPackageError, match="not compatible"):
        newer.stage_restore(
            inspected["inspection_id"],
            PASSWORD,
            inspected["confirmation"],
            "security-admin",
        )


def test_host_recovery_command_can_stage_a_checkpoint_when_web_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "data"
    control_plane(root)
    service = RecoveryPackageService(root, "0.1.0")
    created = service.create(PASSWORD, "security-admin")
    package = service.export_path(created["package_id"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: PASSWORD)
    monkeypatch.setattr("builtins.input", lambda _prompt: f"RESTORE {created['package_id']}")

    result = recovery_main(
        [
            "--data-dir",
            str(root),
            "restore",
            str(package),
            "--host-authorized",
        ]
    )

    assert result == 0
    assert service.pending_marker.exists()
    assert "Restore staged" in capsys.readouterr().out


def test_admin_api_downloads_inspects_stages_and_freezes_other_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "data"
    control_plane(root)
    recovery = RecoveryPackageService(root, "0.1.0")
    auth_store = AuthStore(root / "auth.db")
    audit = AuditStore(root / "audit.db")
    auth = AuthService(auth_store, audit)
    monkeypatch.setattr(app_module.services, "recovery", recovery)
    monkeypatch.setattr(app_module.services, "auth_store", auth_store)
    monkeypatch.setattr(app_module.services, "auth", auth)
    monkeypatch.setattr(app_module.services, "audit", audit)
    client = TestClient(app_module.app)

    created = client.post("/api/recovery/packages", json={"password": PASSWORD})
    assert created.status_code == 201
    package_id = created.json()["package_id"]
    downloaded = client.get(f"/api/recovery/packages/{package_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.headers["cache-control"] == "no-store"

    inspected = client.post(
        "/api/recovery/packages/inspect",
        files={"file": ("backup.signalroom-recovery", downloaded.content)},
        data={"password": PASSWORD},
    )
    assert inspected.status_code == 200
    inspection = inspected.json()
    assert inspection["inspection_is_read_only"] is True
    staged = client.post(
        "/api/recovery/restores",
        json={
            "inspection_id": inspection["inspection_id"],
            "password": PASSWORD,
            "confirmation": inspection["confirmation"],
        },
    )
    assert staged.status_code == 202
    frozen = client.post(
        "/api/feedback",
        json={
            "target_type": "chat",
            "target_id": "answer-1",
            "rating": "useful",
        },
    )
    assert frozen.status_code == 423
    assert "restore is pending" in frozen.json()["detail"]

    cancelled = client.delete("/api/recovery/restores/pending")
    assert cancelled.status_code == 200
    assert not recovery.pending_marker.exists()
