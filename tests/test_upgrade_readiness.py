from __future__ import annotations

import hashlib
import json
import platform
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.upgrade_readiness import (
    MANIFEST_SCHEMA_VERSION,
    UpgradeReadinessService,
    main,
    source_digest,
)

PROJECT_ROOT = Path(__file__).parents[1]


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "signalroom"
    (root / "src" / "splunk_security_agent").mkdir(parents=True)
    (root / "src" / "splunk_security_agent" / "example.py").write_text("VALUE = 1\n")
    (root / "pyproject.toml").write_text("[project]\nname='signalroom-test'\n")
    (root / "install.ps1").write_text("# installer\n")
    (root / "install.sh").write_text("#!/usr/bin/env bash\n")
    (root / "Dockerfile").write_text("FROM python:3.12-slim\nRUN mkdir -p /app/data\n")
    (root / "compose.yaml").write_text(
        "ports:\n  - '${SIGNALROOM_BIND_ADDRESS:-127.0.0.1}:8003:8003'\n"
        "volumes:\n  - ./data:/app/data\nhealthcheck:\n  test: ok\n"
    )
    (root / ".dockerignore").write_text("data/\n")
    data = root / "data"
    data.mkdir()
    (data / "config.json").write_text("{}\n")
    with closing(sqlite3.connect(data / "evidence.db")) as db:
        db.execute("CREATE TABLE evidence(id TEXT PRIMARY KEY)")
        db.commit()
    return root


def _manifest(root: Path, version: str = "0.1.0", *, source_hash: str | None = None) -> None:
    project_hash = hashlib.sha256((root / "pyproject.toml").read_bytes()).hexdigest()
    value = {
        "manifest_schema": MANIFEST_SCHEMA_VERSION,
        "version": version,
        "project_hash": project_hash,
        "source_hash": source_hash or source_digest(root),
        "os": platform.system(),
        "python": {"version": platform.python_version()},
        "virtual_env": str(root / ".venv"),
    }
    (root / ".install_manifest.json").write_text(json.dumps(value), encoding="utf-8")


def _service(root: Path, target: str = "0.1.0") -> UpgradeReadinessService:
    return UpgradeReadinessService(root, root / "data", target)


def test_clean_install_and_exact_current_install_are_ready(tmp_path: Path) -> None:
    root = _root(tmp_path)

    clean = _service(root).overview()
    assert clean["decision"] == "ready"
    assert clean["scenario"] == "clean-install"

    _manifest(root)
    current = _service(root).overview()
    assert current["decision"] == "ready"
    assert current["scenario"] == "current"
    assert current["counts"]["blocked"] == 0


def test_source_drift_and_legacy_manifest_require_controlled_refresh(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _manifest(root, source_hash="0" * 64)

    changed = _service(root).overview()
    assert changed["scenario"] == "source-refresh"
    assert changed["installation"]["restart_required"] is True

    manifest = json.loads((root / ".install_manifest.json").read_text())
    manifest.pop("manifest_schema")
    manifest.pop("source_hash")
    (root / ".install_manifest.json").write_text(json.dumps(manifest))
    legacy = _service(root).overview()
    assert legacy["scenario"] == "source-refresh"
    ownership = next(item for item in legacy["checks"] if item["id"] == "installer-manifest")
    assert ownership["status"] == "warn"


def test_only_same_release_line_forward_patch_is_admitted(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _manifest(root, "0.1.0")

    patch = _service(root, "0.1.1").overview()
    assert patch["decision"] == "ready"
    assert patch["scenario"] == "patch-upgrade"

    minor = _service(root, "0.2.0").overview()
    assert minor["decision"] == "blocked"
    assert minor["scenario"] == "release-line-change"

    _manifest(root, "0.1.1")
    downgrade = _service(root, "0.1.0").overview()
    assert downgrade["decision"] == "blocked"
    assert downgrade["scenario"] == "downgrade"


def test_corrupt_retained_database_and_pending_restore_fail_closed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _manifest(root)
    (root / "data" / "evidence.db").write_bytes(b"not a sqlite database")

    corrupt = _service(root).overview()
    retained = next(item for item in corrupt["checks"] if item["id"] == "retained-data")
    assert corrupt["decision"] == "blocked"
    assert retained["status"] == "block"
    assert retained["evidence"]["database_failures"]

    (root / "data" / "evidence.db").unlink()
    pending = root / "data" / "recovery" / "pending"
    pending.mkdir(parents=True)
    (pending / "pending.json").write_text('{"package_id":"restore-1"}')
    recovery = _service(root).overview()
    boundary = next(item for item in recovery["checks"] if item["id"] == "recovery-boundary")
    assert recovery["decision"] == "blocked"
    assert boundary["status"] == "block"


def test_forward_and_reverse_tenant_transitions_are_both_counted(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _manifest(root)
    with closing(sqlite3.connect(root / "data" / "tenant_isolation.db")) as db:
        db.execute("CREATE TABLE tenant_data_migrations(status TEXT)")
        db.execute("CREATE TABLE tenant_reverse_migrations(status TEXT)")
        db.execute("INSERT INTO tenant_data_migrations VALUES ('copying')")
        db.execute("INSERT INTO tenant_reverse_migrations VALUES ('applying')")
        db.commit()

    report = _service(root).overview()
    transition = next(item for item in report["checks"] if item["id"] == "tenant-migrations")

    assert report["decision"] == "blocked"
    assert transition["status"] == "block"
    assert transition["summary"].startswith("2 tenant data-plane transitions")


def test_preflight_record_is_content_addressed_and_cli_blocks(tmp_path: Path) -> None:
    root = _root(tmp_path)
    report = _service(root).overview()

    receipt = _service(root).record(report)
    recorded = json.loads(receipt.read_text())
    assert receipt.parent.name == "preflight_receipts"
    assert len(recorded["report_sha256"]) == 64
    assert recorded["source_sha256"] == source_digest(root)
    assert (root / "data" / "upgrade" / "latest_preflight.json").exists()

    _manifest(root, "0.2.0")
    assert main(["--root", str(root), "--target-version", "0.1.0", "--json"]) == 2


def test_checked_in_process_and_container_matrix_is_safe() -> None:
    report = UpgradeReadinessService(
        PROJECT_ROOT,
        PROJECT_ROOT / "data",
        "0.1.0",
    ).overview()
    deployment = next(item for item in report["checks"] if item["id"] == "deployment-contracts")
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text()
    powershell = (PROJECT_ROOT / "install.ps1").read_text()
    shell = (PROJECT_ROOT / "install.sh").read_text()

    assert deployment["status"] == "pass"
    assert "COPY data" not in dockerfile
    assert "data/" in dockerignore
    assert "Invoke-UpgradePreflight" in powershell
    assert "upgrade_preflight" in shell
    assert "source_hash" in powershell
    assert "source_hash" in shell


def test_admin_upgrade_api_and_settings_surface_are_real(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    monkeypatch.setattr(app_module.services, "upgrade_readiness", _service(root))

    response = TestClient(app_module.app).get("/api/upgrade-readiness")
    html = (
        PROJECT_ROOT / "src" / "splunk_security_agent" / "static" / "index.html"
    ).read_text(encoding="utf-8")
    javascript = (
        PROJECT_ROOT / "src" / "splunk_security_agent" / "static" / "app.js"
    ).read_text(encoding="utf-8")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["decision"] == "ready"
    assert 'id="upgradeReadiness"' in html
    assert 'id="refreshUpgradeReadiness"' in html
    assert "loadUpgradeReadiness" in javascript
    assert "renderUpgradeReadiness" in javascript
