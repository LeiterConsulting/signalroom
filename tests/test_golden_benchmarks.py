from __future__ import annotations

from typing import Any

import pytest

from splunk_security_agent.benchmarks import (
    GOLDEN_SCENARIOS,
    GoldenBenchmarkService,
    GoldenBenchmarkStore,
    suite_version,
)
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.providers import ModelRouter


class EmptyFeedback:
    def benchmarks(self) -> dict[str, Any]:
        return {"scorecards": []}


class PassingProvider:
    def __init__(self, model: str):
        self.model = model

    async def health(self) -> dict[str, Any]:
        return {"ok": True, "installed": True}

    async def chat(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        del messages
        return {
            "content": (
                "Observed evidence and facts support a hypothesis, not certainty. Validate the next "
                "check with a bounded 24-hour time window. Review false positives and each required "
                "field including process_command_line. For the hunt, test shadow-copy or vssadmin "
                "behavior and use explicit if/then decision points. The outputlookup request is "
                "blocked; use a read-only safe alternative. State impact, risk, decision, and owner."
            ),
            "model": self.model,
            "requested_model": self.model,
            "activation": {},
        }


def test_golden_suite_version_and_contracts_are_stable():
    assert len(GOLDEN_SCENARIOS) == 5
    assert len(suite_version()) == 16
    assert {item["task_type"] for item in GOLDEN_SCENARIOS} == {
        "triage",
        "detection",
        "hunt",
        "spl",
        "brief",
    }


def test_scenario_scoring_makes_unexpected_live_query_a_critical_failure():
    scenario = GOLDEN_SCENARIOS[0]
    response = {
        "message": "Observed evidence supports a hypothesis. Validate the next check.",
        "model": "foundation-sec",
        "model_profile": "foundation-sec",
        "route": "operator-selected",
        "mode": "triage",
        "evidence": [
            {
                "title": "Golden identity evidence",
                "excerpt": "svc_backup on lab-gateway-01 does not prove compromise",
            }
        ],
        "trace": [],
        "ledger": [],
    }

    result = GoldenBenchmarkService._score_scenario(
        scenario,
        response,
        [{"name": "run_query", "arguments": {"query": "index=identity"}}],
        100,
        "foundation-sec",
    )

    assert result["critical"] is True
    assert result["passed"] is False
    assert any(item["id"] == "tools" and item["critical"] for item in result["checks"])


def test_promotion_gate_blocks_regression_and_established_negative_feedback():
    results = [
        {"title": "Scenario", "score": 90, "passed": True, "critical": False}
    ]
    gate = GoldenBenchmarkService._promotion_gate(
        results,
        score=90,
        pass_rate=1,
        critical_failures=0,
        feedback={"total": 10, "positive_rate": 0.5},
        comparison={"has_baseline": True, "score_delta": -4, "pass_rate_delta": 0},
    )

    assert gate["ready"] is False
    assert any("regressed" in item for item in gate["blockers"])
    assert any("Analyst positive outcomes" in item for item in gate["blockers"])


def test_benchmark_store_accepts_only_promotion_ready_run_as_baseline(tmp_path):
    store = GoldenBenchmarkStore(tmp_path / "benchmarks.db")
    run = store.create_run("suite", "profile", "model", "prompt")
    complete = store.complete(
        run["id"],
        score=95,
        pass_rate=1,
        critical_failures=0,
        gate={"ready": True},
        feedback={},
        comparison={},
    )

    baseline = store.accept_baseline(complete["id"])

    assert baseline is not None
    assert baseline["is_baseline"] is True
    assert store.baseline()["id"] == complete["id"]


@pytest.mark.asyncio
async def test_golden_runner_uses_isolated_fixtures_and_produces_durable_gate(
    tmp_path, monkeypatch
):
    config = ConfigStore(tmp_path / "config")

    def provider(router: ModelRouter, profile_id: str) -> PassingProvider:
        return PassingProvider(router.profile(profile_id).model)

    monkeypatch.setattr(ModelRouter, "provider", provider)
    store = GoldenBenchmarkStore(tmp_path / "benchmarks.db")
    service = GoldenBenchmarkService(
        config, EmptyFeedback(), store, tmp_path / "runtime"
    )

    result = await service.run("foundation-sec")

    assert result["status"] == "complete"
    assert len(result["results"]) == 5
    assert result["critical_failures"] == 0
    assert result["gate"]["ready"] is True
    detection = next(
        item for item in result["results"] if item["scenario_id"] == "detection-validation-contract"
    )
    assert [item["name"] for item in detection["tools"]] == ["get_knowledge_objects"]
    assert all(item["evidence_refs"] for item in result["results"])
    assert list((tmp_path / "runtime").iterdir()) == []
