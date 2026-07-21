from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.release_readiness import ReleaseReadinessService, source_digest

PROJECT_ROOT = Path(__file__).parents[1]
STATIC_ROOT = PROJECT_ROOT / "src" / "splunk_security_agent" / "static"


def _service(tmp_path: Path) -> ReleaseReadinessService:
    return ReleaseReadinessService(PROJECT_ROOT, STATIC_ROOT, tmp_path / "data", "0.1.0")


def test_static_release_gate_measures_ui_quality_and_function_ownership(tmp_path: Path) -> None:
    service = _service(tmp_path)

    checks = {item["id"]: item for item in service.static_checks()}

    assert all(item["status"] == "pass" for item in checks.values())
    assert checks["settings-density"]["evidence"]["controls_by_section"]["accessControlSection"] <= 32
    assert checks["contrast"]["evidence"]["failures"] == []
    assert checks["function-ownership"]["evidence"]["orphan_candidates"] == []
    assert checks["function-ownership"]["evidence"]["declared_interface_functions"] > 300
    assert checks["function-ownership"]["evidence"]["backend_modules_scanned"] > 50


def test_full_acceptance_receipt_must_match_source_and_named_ui_review(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.data_root.mkdir(parents=True)
    digest = source_digest(PROJECT_ROOT)
    receipt = {
        "status": "pass",
        "source_sha256": digest,
        "created_at": "2026-07-21T12:00:00+00:00",
        "commands": [{"status": "pass"}],
        "ui_review": {
            "reviewer": "Release reviewer",
            "note": "Reviewed desktop and compact Settings navigation and disclosures.",
        },
    }
    service.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    ready = service.overview()

    assert ready["decision"] == "ready"
    assert ready["counts"]["blocked"] == 0

    receipt["source_sha256"] = "0" * 64
    service.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    stale = service.overview()

    assert stale["decision"] == "blocked"
    assert stale["follow_up_slices"][0]["id"] == "acceptance-verification"


def test_admin_release_readiness_api_is_live_and_not_cacheable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module.services, "release_readiness", _service(tmp_path))
    response = TestClient(app_module.app).get("/api/release-readiness")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["decision"] == "blocked"
    assert response.json()["counts"]["passed"] == 8
