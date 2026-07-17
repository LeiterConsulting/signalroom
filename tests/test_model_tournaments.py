from __future__ import annotations

from typing import Any

import pytest

from splunk_security_agent.benchmarks import (
    GOLDEN_SCENARIOS,
    GoldenBenchmarkStore,
    ModelTournamentService,
    ModelTournamentStore,
)
from splunk_security_agent.config import ConfigStore


class FakeGoldenBenchmarks:
    SCORES = {
        "ollama-general": 82,
        "foundation-sec": 90,
        "foundation-sec-instruct": 95,
    }

    def __init__(self, config: ConfigStore, store: GoldenBenchmarkStore):
        self.config = config
        self.store = store

    @staticmethod
    def _prompt_version() -> str:
        return "prompt-contract"

    async def run(
        self,
        profile_id: str,
        progress: Any = None,
        *,
        raise_errors: bool = True,
    ) -> dict[str, Any]:
        del raise_errors
        profile = next(item for item in self.config.load().models if item.id == profile_id)
        run = self.store.create_run("suite-contract", profile.id, profile.model, "prompt-contract")
        score = self.SCORES[profile_id]
        for index, scenario in enumerate(GOLDEN_SCENARIOS):
            self.store.add_result(
                run["id"],
                {
                    "scenario_id": scenario["id"],
                    "title": scenario["title"],
                    "task_type": scenario["task_type"],
                    "score": score,
                    "passed": True,
                    "critical": False,
                    "checks": [],
                    "response": f"{profile.label} response for {scenario['title']}",
                    "model": profile.model,
                    "route": "operator-selected",
                    "tools": [],
                    "evidence_refs": [scenario["id"]],
                    "duration_ms": 100 + index * 10 + (100 - score),
                    "error": "",
                },
            )
        if progress:
            await progress(
                {
                    "phase": "fake:complete",
                    "label": f"{profile.label} complete",
                    "detail": "Synthetic test candidate completed.",
                    "progress": 100,
                    "status": "complete",
                }
            )
        return self.store.complete(
            run["id"],
            score=score,
            pass_rate=1,
            critical_failures=0,
            gate={"ready": True, "blockers": [], "warnings": []},
            feedback={"total": 0, "positive_rate": None},
            comparison={"has_baseline": False},
        )


def tournament_service(tmp_path):
    config = ConfigStore(tmp_path / "config")
    benchmark_store = GoldenBenchmarkStore(tmp_path / "benchmarks.db")
    tournaments = ModelTournamentStore(tmp_path / "tournaments.db")
    benchmarks = FakeGoldenBenchmarks(config, benchmark_store)
    service = ModelTournamentService(config, benchmarks, benchmark_store, tournaments)
    return config, benchmark_store, tournaments, service


async def complete_review(service: ModelTournamentService, store: ModelTournamentStore, value):
    raw = store.get(value["id"])
    assert raw is not None
    reviewed = value
    for pair in raw["review_pairs"]:
        choice = "a" if pair["a_profile_id"] == "foundation-sec-instruct" else "b"
        reviewed = service.review(value["id"], pair["id"], choice)
    return reviewed


@pytest.mark.asyncio
async def test_tournament_runs_shared_suite_and_requires_blind_review(tmp_path, monkeypatch):
    config, _benchmark_store, store, service = tournament_service(tmp_path)
    monkeypatch.setattr(
        "splunk_security_agent.benchmarks.tournament.suite_version",
        lambda: "suite-contract",
    )

    result = await service.run(
        ["ollama-general", "foundation-sec", "foundation-sec-instruct"],
        "security_reasoning_model",
    )

    assert result["status"] == "awaiting-review"
    assert result["fingerprint"] == ""
    assert result["recommendation"]["ready"] is False
    assert len(result["review_pairs"]) == len(GOLDEN_SCENARIOS)
    assert all("a_profile_id" not in pair for pair in result["review_pairs"])
    assert result["ranking"][0]["profile_id"] == "foundation-sec-instruct"
    assert result["ranking"][0]["task_wins"] == [
        "brief",
        "detection",
        "hunt",
        "spl",
        "triage",
    ]
    assert config.load().security_reasoning_model == "foundation-sec"

    reviewed = await complete_review(service, store, result)

    assert reviewed["status"] == "complete"
    assert reviewed["review_complete"] is True
    assert len(reviewed["fingerprint"]) == 64
    assert reviewed["recommendation"]["profile_id"] == "foundation-sec-instruct"
    assert reviewed["recommendation"]["ready"] is True
    assert all(pair["identity_revealed"] for pair in reviewed["review_pairs"])


@pytest.mark.asyncio
async def test_exact_tournament_promotion_and_rollback_restore_route_and_baseline(
    tmp_path, monkeypatch
):
    config, benchmark_store, store, service = tournament_service(tmp_path)
    monkeypatch.setattr(
        "splunk_security_agent.benchmarks.tournament.suite_version",
        lambda: "suite-contract",
    )
    tournament = await service.run(
        ["foundation-sec", "foundation-sec-instruct"],
        "security_reasoning_model",
    )
    tournament = await complete_review(service, store, tournament)

    with pytest.raises(ValueError, match="fingerprint"):
        service.promote(
            tournament["id"],
            "foundation-sec-instruct",
            "0" * 64,
        )

    promoted = service.promote(
        tournament["id"],
        "foundation-sec-instruct",
        tournament["fingerprint"],
    )

    assert config.load().security_reasoning_model == "foundation-sec-instruct"
    assert promoted["promotion"]["status"] == "active"
    assert promoted["promotion"]["previous_profile_id"] == "foundation-sec"
    assert benchmark_store.baseline()["profile_id"] == "foundation-sec-instruct"

    rolled_back = service.rollback(promoted["promotion"]["id"])

    assert rolled_back["promotion"]["status"] == "rolled-back"
    assert config.load().security_reasoning_model == "foundation-sec"
    assert benchmark_store.baseline() is None


@pytest.mark.asyncio
async def test_promotion_fails_closed_when_assignment_changes_after_tournament(
    tmp_path, monkeypatch
):
    config, _benchmark_store, store, service = tournament_service(tmp_path)
    monkeypatch.setattr(
        "splunk_security_agent.benchmarks.tournament.suite_version",
        lambda: "suite-contract",
    )
    tournament = await service.run(
        ["foundation-sec", "foundation-sec-instruct"],
        "security_reasoning_model",
    )
    tournament = await complete_review(service, store, tournament)
    settings = config.load()
    settings.security_reasoning_model = "ollama-general"
    config.save(settings)

    with pytest.raises(ValueError, match="changed after this tournament"):
        service.promote(
            tournament["id"],
            "foundation-sec-instruct",
            tournament["fingerprint"],
        )
