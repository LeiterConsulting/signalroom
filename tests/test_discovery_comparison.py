from copy import deepcopy

import pytest

from splunk_security_agent.discovery import DiscoveryComparisonService


def scope(alias: str, fingerprint: str, tenant: str) -> dict[str, str]:
    return {
        "alias": alias,
        "display_name": alias.replace("-", " ").title(),
        "fingerprint": fingerprint,
        "tenant_scope_id": tenant,
    }


def summary(run_id: str = "run-left") -> dict:
    return {
        "run_id": run_id,
        "generated_at": "2026-07-20T12:00:00+00:00",
        "depth": "standard",
        "overview": {
            "indexes": 10,
            "sourcetypes": 20,
            "hosts": 30,
            "sources": 40,
        },
        "coverage": {
            "score": 60,
            "domains": {
                "identity": True,
                "endpoint": False,
                "network": False,
            },
        },
        "collection_status": {"complete": True, "failed_calls": 0},
        "security_posture": {
            "telemetry": {
                "stale_over_24h": [
                    {"sourcetype": "shared:stale"},
                    {"sourcetype": "left:stale"},
                ]
            },
            "detections": {
                "total": 12,
                "enabled": 9,
                "disabled": 3,
                "disabled_names": ["Shared disabled", "Left disabled"],
                "missing_time_bounds_count": 1,
                "broad_searches_count": 2,
                "apps": ["Shared app", "Left app"],
            },
            "data_models": {
                "total": 4,
                "accelerated": 2,
                "accelerated_names": ["Endpoint", "Left model"],
            },
            "knowledge": {"macros": 5, "lookups": 6},
            "mltk_models": {"observed": 1},
        },
        "findings": [
            {
                "severity": "high",
                "domain": "coverage",
                "title": "Left source finding",
                "evidence": "Observed only in the left snapshot.",
                "next_step": "Validate on the left.",
            }
        ],
    }


def test_comparison_is_deterministic_source_preserving_and_query_free() -> None:
    service = DiscoveryComparisonService()
    left_summary = summary()
    right_summary = deepcopy(left_summary)
    right_summary["run_id"] = "run-right"
    right_summary["overview"]["indexes"] = 14
    right_summary["coverage"]["domains"]["endpoint"] = True
    right_summary["security_posture"]["detections"]["apps"] = [
        "Shared app",
        "Right app",
    ]
    right_summary["findings"][0]["title"] = "Right source finding"
    left_scope = scope("left-estate", "a" * 64, "tenant-left")
    right_scope = scope("right-estate", "b" * 64, "tenant-right")

    first = service.compare(left_scope, left_summary, right_scope, right_summary)
    second = service.compare(left_scope, left_summary, right_scope, right_summary)

    assert first["comparison_id"] == second["comparison_id"]
    assert first["contract"] == {
        "splunk_queries": 0,
        "model_inference": False,
        "raw_rows_persisted": False,
        "merged_evidence": False,
        "source_attribution_required": True,
        "basis": "Latest retained discovery summary for each exact immutable scope.",
    }
    assert first["left"]["tenant_scope_id"] == "tenant-left"
    assert first["right"]["tenant_scope_id"] == "tenant-right"
    assert first["findings"]["left"][0]["title"] == "Left source finding"
    assert first["findings"]["right"][0]["title"] == "Right source finding"
    indexes = next(item for item in first["metrics"] if item["key"] == "indexes")
    assert indexes["delta_right_minus_left"] == 4
    endpoint = next(item for item in first["domains"] if item["domain"] == "endpoint")
    assert endpoint == {
        "domain": "endpoint",
        "left": "gap-to-validate",
        "right": "observed",
        "relation": "different",
    }


def test_comparison_contrasts_shared_and_unique_labels_without_global_list() -> None:
    left_summary = summary()
    right_summary = deepcopy(left_summary)
    right_summary["run_id"] = "run-right"
    right_summary["security_posture"]["detections"]["apps"] = [
        "Shared app",
        "Right app",
    ]

    value = DiscoveryComparisonService().compare(
        scope("left", "a" * 64, "tenant"),
        left_summary,
        scope("right", "b" * 64, "tenant"),
        right_summary,
    )

    apps = next(item for item in value["contrasts"] if item["key"] == "detection_apps")
    assert apps["shared_count"] == 1
    assert apps["left_only"] == ["Left app"]
    assert apps["right_only"] == ["Right app"]
    assert "merged" not in apps


def test_comparison_reports_collection_and_depth_caveats() -> None:
    left_summary = summary()
    right_summary = deepcopy(left_summary)
    right_summary["run_id"] = "run-right"
    right_summary["depth"] = "quick"
    right_summary["collection_status"] = {"complete": False, "failed_calls": 2}

    value = DiscoveryComparisonService().compare(
        scope("left", "a" * 64, "tenant"),
        left_summary,
        scope("right", "b" * 64, "tenant"),
        right_summary,
    )

    assert any("depth differs" in item for item in value["caveats"])
    assert any("2 collection gap(s)" in item for item in value["caveats"])
    assert value["right"]["collection_complete"] is False


def test_comparison_rejects_same_scope_and_missing_snapshots() -> None:
    service = DiscoveryComparisonService()
    current = scope("primary", "a" * 64, "tenant")

    with pytest.raises(ValueError, match="different immutable"):
        service.compare(current, summary(), current, summary("run-right"))
    with pytest.raises(ValueError, match="No retained discovery snapshot"):
        service.compare(
            current,
            None,
            scope("right", "b" * 64, "tenant"),
            summary("run-right"),
        )
