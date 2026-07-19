from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from statistics import mean
from typing import Any

from ..config import ConfigStore
from ..progress import ProgressCallback, report_progress
from .scenarios import GOLDEN_SCENARIOS, suite_version
from .service import GoldenBenchmarkService
from .store import GoldenBenchmarkStore
from .suites import BUILTIN_SUITE_ID
from .tournament_store import ModelTournamentStore

PROMOTION_TARGETS = {
    "default_chat_model": "General investigation route",
    "security_reasoning_model": "Security reasoning route",
}


class ModelTournamentService:
    """Compare local profiles, collect blind review, and control routing promotion."""

    def __init__(
        self,
        config: ConfigStore,
        benchmarks: GoldenBenchmarkService,
        benchmark_store: GoldenBenchmarkStore,
        store: ModelTournamentStore,
        model_trust: Any | None = None,
    ):
        self.config = config
        self.benchmarks = benchmarks
        self.benchmark_store = benchmark_store
        self.store = store
        self.model_trust = model_trust

    def overview(self) -> dict[str, Any]:
        settings = self.config.load()
        return {
            "targets": [
                {
                    "id": target,
                    "label": label,
                    "profile_id": getattr(settings, target),
                }
                for target, label in PROMOTION_TARGETS.items()
            ],
            "tournaments": [self._public(item) for item in self.store.list(10)],
            "promotions": self.store.list_promotions(10),
            "active_promotions": [
                promotion
                for target in PROMOTION_TARGETS
                if (promotion := self.store.active_promotion(target))
            ],
            "policy": {
                "minimum_candidates": 2,
                "blind_review_scenarios": len(GOLDEN_SCENARIOS),
                "quality_weight": 0.9,
                "latency_weight": 0.1,
                "established_feedback_weight": 0.1,
                "blind_review_adjustment": 5,
                "external_splunk_calls": 0,
                "promotion_requires_exact_fingerprint": True,
                "rollback_requires_unchanged_assignment": True,
            },
        }

    def _resolve_suite(self, suite_id: str) -> dict[str, Any]:
        resolver = getattr(self.benchmarks, "resolve_suite", None)
        if callable(resolver):
            return resolver(suite_id)
        if suite_id != BUILTIN_SUITE_ID:
            raise KeyError(f"Unknown evaluation suite: {suite_id}")
        return {
            "id": BUILTIN_SUITE_ID,
            "name": "SignalRoom core safety gate",
            "version": suite_version(),
            "scenarios": GOLDEN_SCENARIOS,
        }

    async def run(
        self,
        profile_ids: list[str],
        target: str,
        progress: ProgressCallback | None = None,
        suite_id: str = BUILTIN_SUITE_ID,
    ) -> dict[str, Any]:
        if target not in PROMOTION_TARGETS:
            raise ValueError(f"Unsupported model assignment target: {target}")
        unique_ids = list(dict.fromkeys(profile_ids))
        if len(unique_ids) < 2:
            raise ValueError("A model tournament requires at least two distinct profiles")
        if len(unique_ids) > 8:
            raise ValueError("A model tournament supports at most eight profiles")
        settings = self.config.load()
        profiles = {profile.id: profile for profile in settings.models}
        invalid = [
            profile_id
            for profile_id in unique_ids
            if profile_id not in profiles
            or profiles[profile_id].provider != "ollama"
            or profiles[profile_id].task not in {"chat", "security_reasoning"}
            or not profiles[profile_id].enabled
        ]
        if invalid:
            raise ValueError(
                "Tournament candidates must be enabled local Ollama chat profiles: "
                + ", ".join(invalid)
            )
        suite = self._resolve_suite(suite_id)
        scenarios = list(suite["scenarios"])
        tournament = self.store.create(
            target=target,
            profile_ids=unique_ids,
            assignment_before=getattr(settings, target),
            suite_id=suite_id,
            suite_version=str(suite["version"]),
            prompt_version=self.benchmarks._prompt_version(),
        )
        try:
            await report_progress(
                progress,
                "tournament:preflight",
                "Preparing the local model tournament",
                (
                    f"Running {len(unique_ids)} profiles through the same isolated golden "
                    "investigations; configured Splunk will not be contacted."
                ),
                progress=2,
                metrics={
                    "profiles": len(unique_ids),
                    "scenarios_per_profile": len(scenarios),
                    "suite": suite["name"],
                    "external_splunk_calls": 0,
                },
            )
            candidate_runs: list[dict[str, Any]] = []
            for index, profile_id in enumerate(unique_ids):
                profile = profiles[profile_id]
                await report_progress(
                    progress,
                    f"tournament:{profile_id}:start",
                    f"Candidate {index + 1}/{len(unique_ids)} · {profile.label}",
                    "Loading the profile and starting its isolated golden investigation suite.",
                    progress=4 + round(index / len(unique_ids) * 82),
                    metrics={"profile": profile_id, "model": profile.model},
                )

                async def candidate_progress(
                    event: dict[str, Any],
                    *,
                    candidate_index: int = index,
                    candidate_id: str = profile_id,
                ) -> None:
                    nested = max(0.0, min(100.0, float(event.get("progress", 0))))
                    overall = 4 + (
                        (candidate_index + nested / 100) / len(unique_ids) * 82
                    )
                    if progress is not None:
                        await progress(
                            {
                                **event,
                                "phase": (
                                    f"tournament:{candidate_id}:"
                                    f"{event.get('phase', 'working')}"
                                ),
                                "label": (
                                    f"{profiles[candidate_id].label} · "
                                    f"{event.get('label', 'Working')}"
                                ),
                                "progress": round(overall),
                                "metrics": {
                                    **dict(event.get("metrics") or {}),
                                    "candidate": candidate_index + 1,
                                    "candidate_count": len(unique_ids),
                                    "profile": candidate_id,
                                },
                            }
                        )

                result = await self.benchmarks.run(
                    profile_id,
                    candidate_progress,
                    raise_errors=False,
                    suite_id=suite_id,
                )
                candidate_runs.append(result)
                await report_progress(
                    progress,
                    f"tournament:{profile_id}:complete",
                    f"{profile.label} · {result['score']:.0f}/100",
                    (
                        "Candidate passed its deterministic promotion controls."
                        if result.get("gate", {}).get("ready")
                        else "Candidate completed with promotion blockers."
                    ),
                    progress=4 + round((index + 1) / len(unique_ids) * 82),
                    status=(
                        "complete"
                        if result.get("gate", {}).get("ready")
                        else "warning"
                    ),
                    metrics={
                        "profile": profile_id,
                        "score": result["score"],
                        "critical_failures": result["critical_failures"],
                    },
                )

            ranking = self._rank(candidate_runs, profiles)
            review_pairs = self._review_pairs(tournament["id"], candidate_runs, ranking)
            recommendation = self._recommendation(
                tournament, ranking, review_pairs, review_complete=False
            )
            status = "awaiting-review" if review_pairs else "hold"
            saved = self.store.save_evaluation(
                tournament["id"],
                status=status,
                candidate_run_ids=[run["id"] for run in candidate_runs],
                ranking=ranking,
                review_pairs=review_pairs,
                recommendation=recommendation,
                fingerprint="",
            )
            await report_progress(
                progress,
                "tournament:review",
                (
                    "Blind finalist review is ready"
                    if review_pairs
                    else "Tournament completed without two reviewable finalists"
                ),
                (
                    "Compare the finalist responses without model labels before SignalRoom "
                    "creates a promotion fingerprint."
                    if review_pairs
                    else recommendation["label"]
                ),
                progress=100,
                status="complete" if review_pairs else "warning",
                metrics={
                    "review_pairs": len(review_pairs),
                    "candidate_count": len(candidate_runs),
                    "promotion_ready": False,
                },
            )
            return self._public(saved)
        except Exception as exc:
            self.store.fail(tournament["id"], str(exc))
            raise

    def review(self, tournament_id: str, pair_id: str, choice: str) -> dict[str, Any]:
        if choice not in {"a", "b", "tie"}:
            raise ValueError("Blind review choice must be a, b, or tie")
        tournament = self.store.get(tournament_id)
        if tournament is None:
            raise KeyError(f"Unknown model tournament: {tournament_id}")
        if tournament["status"] not in {"awaiting-review", "complete", "hold"}:
            raise ValueError("This tournament is not available for blind review")
        if self._promotion_for_tournament(tournament_id):
            raise ValueError("A promoted tournament is immutable")
        pairs = deepcopy(tournament["review_pairs"])
        pair = next((item for item in pairs if item["id"] == pair_id), None)
        if pair is None:
            raise KeyError(f"Unknown blind review pair: {pair_id}")
        pair["choice"] = choice
        pair["reviewed_at"] = self._now()
        runs = self._candidate_runs(tournament)
        profiles = {profile.id: profile for profile in self.config.load().models}
        ranking = self._rank(runs, profiles, pairs)
        review_complete = bool(pairs) and all(item.get("choice") for item in pairs)
        recommendation = self._recommendation(
            tournament, ranking, pairs, review_complete=review_complete
        )
        fingerprint = (
            self._fingerprint(tournament, runs, ranking, pairs, recommendation)
            if review_complete
            else ""
        )
        status = (
            "complete"
            if review_complete and recommendation.get("ready")
            else "hold"
            if review_complete
            else "awaiting-review"
        )
        saved = self.store.save_evaluation(
            tournament_id,
            status=status,
            candidate_run_ids=tournament["candidate_run_ids"],
            ranking=ranking,
            review_pairs=pairs,
            recommendation=recommendation,
            fingerprint=fingerprint,
        )
        return self._public(saved)

    async def promote(
        self, tournament_id: str, profile_id: str, fingerprint: str
    ) -> dict[str, Any]:
        tournament = self.store.get(tournament_id)
        if tournament is None:
            raise KeyError(f"Unknown model tournament: {tournament_id}")
        recommendation = tournament.get("recommendation") or {}
        if tournament["status"] != "complete" or not recommendation.get("ready"):
            raise ValueError("Only a completed, promotion-ready tournament can change routing")
        if not tournament["fingerprint"] or fingerprint != tournament["fingerprint"]:
            raise ValueError("Tournament fingerprint does not match the reviewed comparison")
        if profile_id != recommendation.get("profile_id"):
            raise ValueError("Only the exact tournament winner can be promoted")
        if self._promotion_for_tournament(tournament_id):
            raise ValueError("This tournament has already produced a routing promotion")
        if tournament["suite_version"] != self._resolve_suite(
            tournament["suite_id"]
        )["version"]:
            raise ValueError("The evaluated scenario suite changed; run a new tournament")
        if tournament["prompt_version"] != self.benchmarks._prompt_version():
            raise ValueError("The agent prompt contract changed; run a new tournament")

        settings = self.config.load()
        target = tournament["target"]
        current_assignment = getattr(settings, target)
        if current_assignment != tournament["assignment_before"]:
            raise ValueError(
                "The routed assignment changed after this tournament; run a fresh comparison"
            )
        if current_assignment == profile_id:
            raise ValueError("The winning profile is already assigned to this route")
        candidate_run = self._winner_run(tournament, profile_id)
        profile = next(
            (
                item
                for item in settings.models
                if item.id == profile_id and item.enabled and item.provider == "ollama"
            ),
            None,
        )
        if profile is None or profile.model != candidate_run["model"]:
            raise ValueError("The winning model revision changed; run a fresh tournament")
        artifact_trust = None
        if self.model_trust is not None:
            artifact_trust = await self.model_trust.assert_binding(
                profile_id,
                candidate_run.get("artifact_binding") or {},
                "tournament promotion",
            )
        before_sha = self._settings_sha(settings)
        previous_baseline = self.benchmark_store.baseline(
            suite_id=tournament["suite_id"]
        )
        setattr(settings, target, profile_id)
        self.config.save(settings)
        accepted = self.benchmark_store.accept_baseline(candidate_run["id"])
        if accepted is None:
            setattr(settings, target, current_assignment)
            self.config.save(settings)
            raise ValueError("The winner is no longer eligible to become the benchmark baseline")
        after_sha = self._settings_sha(settings)
        promotion = self.store.create_promotion(
            tournament_id=tournament_id,
            target=target,
            profile_id=profile_id,
            previous_profile_id=current_assignment,
            tournament_fingerprint=fingerprint,
            promoted_run_id=candidate_run["id"],
            previous_baseline_run_id=(
                str(previous_baseline["id"]) if previous_baseline else ""
            ),
            config_before_sha256=before_sha,
            config_after_sha256=after_sha,
            artifact_fingerprint=str(
                (artifact_trust or candidate_run.get("artifact_binding") or {}).get(
                    "identity_fingerprint"
                )
                or ""
            ),
            attestation_id=str(
                ((artifact_trust or {}).get("attestation") or {}).get("id") or ""
            ),
        )
        return {
            "promotion": promotion,
            "tournament": self._public(tournament),
            "settings": self.config.public_payload(),
            "activation": {
                "deferred": True,
                "detail": (
                    "The routing assignment changed. Ollama will load the selected profile "
                    "on its next request."
                ),
            },
        }

    async def rollback(self, promotion_id: str) -> dict[str, Any]:
        promotion = self.store.get_promotion(promotion_id)
        if promotion is None:
            raise KeyError(f"Unknown model promotion: {promotion_id}")
        if promotion["status"] != "active":
            raise ValueError("Only the active model promotion can be rolled back")
        settings = self.config.load()
        target = promotion["target"]
        if getattr(settings, target) != promotion["profile_id"]:
            raise ValueError(
                "The routed assignment changed after promotion; automatic rollback is unsafe"
            )
        tournament = self.store.get(promotion["tournament_id"])
        if tournament is None:
            raise ValueError("The promotion's evaluation suite history is unavailable")
        suite_id = tournament["suite_id"]
        current_baseline = self.benchmark_store.baseline(suite_id=suite_id)
        if (
            current_baseline is None
            or current_baseline["id"] != promotion["promoted_run_id"]
        ):
            raise ValueError(
                "The accepted benchmark baseline changed after promotion; automatic rollback "
                "is unsafe"
            )
        previous = next(
            (
                item
                for item in settings.models
                if item.id == promotion["previous_profile_id"]
                and item.enabled
                and item.provider == "ollama"
            ),
            None,
        )
        if previous is None:
            raise ValueError("The previous routing profile is no longer available")
        if self.model_trust is not None:
            await self.model_trust.require_profile(
                previous.id, "tournament rollback"
            )
        setattr(settings, target, previous.id)
        self.config.save(settings)
        previous_baseline_id = promotion["previous_baseline_run_id"] or None
        restored = self.benchmark_store.set_baseline(
            previous_baseline_id, suite_id=suite_id
        )
        if previous_baseline_id and restored is None:
            setattr(settings, target, promotion["profile_id"])
            self.config.save(settings)
            self.benchmark_store.set_baseline(
                promotion["promoted_run_id"], suite_id=suite_id
            )
            raise ValueError("The previous benchmark baseline is no longer restorable")
        rolled_back = self.store.mark_rolled_back(promotion_id)
        return {
            "promotion": rolled_back,
            "settings": self.config.public_payload(),
            "baseline": restored,
        }

    def _candidate_runs(self, tournament: dict[str, Any]) -> list[dict[str, Any]]:
        runs = [
            run
            for run_id in tournament["candidate_run_ids"]
            if (run := self.benchmark_store.get(run_id)) is not None
        ]
        if len(runs) != len(tournament["candidate_run_ids"]):
            raise ValueError("One or more tournament benchmark runs are no longer available")
        return runs

    def _winner_run(
        self, tournament: dict[str, Any], profile_id: str
    ) -> dict[str, Any]:
        run = next(
            (
                item
                for item in self._candidate_runs(tournament)
                if item["profile_id"] == profile_id
            ),
            None,
        )
        if run is None or not run.get("gate", {}).get("ready"):
            raise ValueError("The tournament winner no longer has a passing promotion gate")
        return run

    def _promotion_for_tournament(self, tournament_id: str) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in self.store.list_promotions(100)
                if item["tournament_id"] == tournament_id
            ),
            None,
        )

    @staticmethod
    def _rank(
        runs: list[dict[str, Any]],
        profiles: dict[str, Any],
        review_pairs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        rows = []
        completed_durations = []
        for run in runs:
            task_values: dict[str, list[float]] = {}
            for result in run.get("results", []):
                task_values.setdefault(str(result["task_type"]), []).append(
                    float(result["score"])
                )
            durations = [
                int(result.get("duration_ms", 0))
                for result in run.get("results", [])
                if int(result.get("duration_ms", 0)) > 0
            ]
            average_duration = round(mean(durations)) if durations else 0
            if run["status"] == "complete" and average_duration:
                completed_durations.append(average_duration)
            feedback = run.get("feedback") or {}
            rows.append(
                {
                    "profile_id": run["profile_id"],
                    "label": getattr(
                        profiles.get(run["profile_id"]), "label", run["profile_id"]
                    ),
                    "model": run["model"],
                    "run_id": run["id"],
                    "status": run["status"],
                    "score": run["score"],
                    "pass_rate": run["pass_rate"],
                    "critical_failures": run["critical_failures"],
                    "average_duration_ms": average_duration,
                    "task_scores": {
                        task: round(mean(scores), 1)
                        for task, scores in task_values.items()
                    },
                    "feedback_total": int(feedback.get("total", 0)),
                    "feedback_positive_rate": feedback.get("positive_rate"),
                    "gate_ready": bool(run.get("gate", {}).get("ready")),
                    "artifact_fingerprint": str(
                        (run.get("artifact_binding") or {}).get(
                            "identity_fingerprint"
                        )
                        or ""
                    ),
                    "gate_blockers": list(run.get("gate", {}).get("blockers") or []),
                    "eligible": (
                        run["status"] == "complete"
                        and bool(run.get("gate", {}).get("ready"))
                    ),
                }
            )
        fastest = min(completed_durations) if completed_durations else 0
        review_pairs = review_pairs or []
        for row in rows:
            latency_score = (
                round(fastest / row["average_duration_ms"] * 100, 1)
                if fastest and row["average_duration_ms"]
                else 0
            )
            established_feedback = (
                row["feedback_total"] >= 10
                and row["feedback_positive_rate"] is not None
            )
            if established_feedback:
                base_score = (
                    row["score"] * 0.8
                    + latency_score * 0.1
                    + float(row["feedback_positive_rate"]) * 100 * 0.1
                )
            else:
                base_score = row["score"] * 0.9 + latency_score * 0.1
            choices = []
            for pair in review_pairs:
                if not pair.get("choice"):
                    continue
                if pair["a_profile_id"] == row["profile_id"]:
                    choices.append(
                        1
                        if pair["choice"] == "a"
                        else 0.5
                        if pair["choice"] == "tie"
                        else 0
                    )
                elif pair["b_profile_id"] == row["profile_id"]:
                    choices.append(
                        1
                        if pair["choice"] == "b"
                        else 0.5
                        if pair["choice"] == "tie"
                        else 0
                    )
            review_score = round(mean(choices) * 100, 1) if choices else None
            review_adjustment = (
                round((review_score - 50) * 0.1, 1) if review_score is not None else 0
            )
            row.update(
                latency_score=latency_score,
                established_feedback=established_feedback,
                base_score=round(base_score, 1),
                blind_review_score=review_score,
                blind_review_count=len(choices),
                review_adjustment=review_adjustment,
                final_score=round(base_score + review_adjustment, 1),
            )
        rows.sort(
            key=lambda item: (
                item["status"] != "complete",
                -item["final_score"],
                item["average_duration_ms"] or 10**12,
                item["profile_id"],
            )
        )
        for index, row in enumerate(rows, start=1):
            row["rank"] = index
        tasks = sorted(
            {
                str(result["task_type"])
                for run in runs
                for result in run.get("results", [])
            }
        )
        for task in tasks:
            task_rows = [row for row in rows if task in row["task_scores"]]
            if not task_rows:
                continue
            best = max(
                task_rows,
                key=lambda item: (
                    item["task_scores"][task],
                    -item["average_duration_ms"],
                ),
            )
            best.setdefault("task_wins", []).append(task)
        return rows

    @staticmethod
    def _review_pairs(
        tournament_id: str,
        runs: list[dict[str, Any]],
        ranking: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        finalists = [row for row in ranking if row["status"] == "complete"][:2]
        if len(finalists) < 2:
            return []
        run_by_profile = {run["profile_id"]: run for run in runs}
        first_id, second_id = finalists[0]["profile_id"], finalists[1]["profile_id"]
        first_results = run_by_profile[first_id].get("results", [])
        first_scenarios = {item["scenario_id"] for item in first_results}
        second_scenarios = {
            item["scenario_id"]
            for item in run_by_profile[second_id].get("results", [])
        }
        if not first_scenarios or first_scenarios != second_scenarios:
            return []
        pairs = []
        for scenario in first_results:
            scenario_id = str(scenario["scenario_id"])
            flip = int(
                hashlib.sha256(
                    f"{tournament_id}:{scenario_id}".encode()
                ).hexdigest(),
                16,
            ) % 2
            a_id, b_id = (second_id, first_id) if flip else (first_id, second_id)
            a_result = next(
                item
                for item in run_by_profile[a_id]["results"]
                if item["scenario_id"] == scenario_id
            )
            b_result = next(
                item
                for item in run_by_profile[b_id]["results"]
                if item["scenario_id"] == scenario_id
            )
            pair_id = hashlib.sha256(
                f"{tournament_id}:{scenario_id}:blind".encode()
            ).hexdigest()[:20]
            pairs.append(
                {
                    "id": pair_id,
                    "scenario_id": scenario_id,
                    "title": scenario["title"],
                    "task_type": scenario["task_type"],
                    "a_profile_id": a_id,
                    "b_profile_id": b_id,
                    "a_response": a_result["response"],
                    "b_response": b_result["response"],
                    "choice": "",
                    "reviewed_at": None,
                }
            )
        return pairs

    @staticmethod
    def _recommendation(
        tournament: dict[str, Any],
        ranking: list[dict[str, Any]],
        review_pairs: list[dict[str, Any]],
        *,
        review_complete: bool,
    ) -> dict[str, Any]:
        reviewed_profiles = {
            profile_id
            for pair in review_pairs
            for profile_id in (pair["a_profile_id"], pair["b_profile_id"])
        }
        finalists = [
            row for row in ranking if row["profile_id"] in reviewed_profiles
        ]
        winner = finalists[0] if finalists else ranking[0] if ranking else None
        if winner is None:
            return {
                "ready": False,
                "decision": "hold",
                "label": "No candidate completed enough evidence for a recommendation.",
                "blockers": ["No reviewable candidate run is available."],
            }
        blockers = []
        if not review_pairs:
            blockers.append("Two complete finalist runs are required for blind review.")
        elif not review_complete:
            remaining = sum(not pair.get("choice") for pair in review_pairs)
            blockers.append(f"Complete {remaining} remaining blind response comparison(s).")
        if not winner["gate_ready"]:
            blockers.extend(winner["gate_blockers"] or ["The winning profile did not pass its gate."])
        change_required = winner["profile_id"] != tournament["assignment_before"]
        ready = review_complete and not blockers
        return {
            "ready": ready,
            "decision": "ready-to-promote" if ready else "hold",
            "profile_id": winner["profile_id"],
            "label_name": winner["label"],
            "model": winner["model"],
            "run_id": winner["run_id"],
            "target": tournament["target"],
            "suite_id": tournament["suite_id"],
            "assignment_before": tournament["assignment_before"],
            "change_required": change_required,
            "score": winner["score"],
            "final_score": winner["final_score"],
            "label": (
                (
                    "The reviewed winner passed every promotion control and can be assigned "
                    "after explicit approval."
                )
                if ready and change_required
                else (
                    "The current routed profile remains the reviewed winner; no routing change "
                    "is required."
                )
                if ready
                else "Hold routing changes until the tournament controls are complete."
            ),
            "blockers": blockers,
            "review_complete": review_complete,
            "reviewed_pairs": sum(bool(pair.get("choice")) for pair in review_pairs),
            "review_pair_count": len(review_pairs),
        }

    @staticmethod
    def _fingerprint(
        tournament: dict[str, Any],
        runs: list[dict[str, Any]],
        ranking: list[dict[str, Any]],
        pairs: list[dict[str, Any]],
        recommendation: dict[str, Any],
    ) -> str:
        payload = {
            "target": tournament["target"],
            "suite_id": tournament["suite_id"],
            "assignment_before": tournament["assignment_before"],
            "suite_version": tournament["suite_version"],
            "prompt_version": tournament["prompt_version"],
            "candidates": [
                {
                    "run_id": run["id"],
                    "profile_id": run["profile_id"],
                    "model": run["model"],
                    "score": run["score"],
                    "pass_rate": run["pass_rate"],
                    "critical_failures": run["critical_failures"],
                    "gate_ready": bool(run.get("gate", {}).get("ready")),
                    "artifact_fingerprint": str(
                        (run.get("artifact_binding") or {}).get(
                            "identity_fingerprint"
                        )
                        or ""
                    ),
                }
                for run in sorted(runs, key=lambda item: item["profile_id"])
            ],
            "ranking": [
                {
                    "profile_id": row["profile_id"],
                    "final_score": row["final_score"],
                    "rank": row["rank"],
                }
                for row in ranking
            ],
            "blind_reviews": [
                {
                    "id": pair["id"],
                    "scenario_id": pair["scenario_id"],
                    "a_profile_id": pair["a_profile_id"],
                    "b_profile_id": pair["b_profile_id"],
                    "choice": pair["choice"],
                }
                for pair in sorted(pairs, key=lambda item: item["id"])
            ],
            "winner": recommendation.get("profile_id"),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _public(tournament: dict[str, Any]) -> dict[str, Any]:
        review_complete = bool(tournament.get("review_pairs")) and all(
            pair.get("choice") for pair in tournament["review_pairs"]
        )
        public = deepcopy(tournament)
        public["review_pairs"] = [
            {
                key: value
                for key, value in pair.items()
                if review_complete or key not in {"a_profile_id", "b_profile_id"}
            }
            | {"identity_revealed": review_complete}
            for pair in tournament["review_pairs"]
        ]
        public["review_complete"] = review_complete
        return public

    @staticmethod
    def _settings_sha(settings: Any) -> str:
        payload = json.dumps(
            settings.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _now() -> str:
        from datetime import UTC, datetime

        return datetime.now(UTC).isoformat()
