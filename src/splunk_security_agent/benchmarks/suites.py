from __future__ import annotations

import hashlib
from typing import Any

from ..schemas import EvaluationScenario, EvaluationSuiteCreate, EvaluationSuiteUpdate
from .scenarios import GOLDEN_SCENARIOS, suite_version
from .suite_store import EvaluationSuiteStore

BUILTIN_SUITE_ID = "builtin-core"


class EvaluationSuiteService:
    """Govern additive organization scenarios without weakening the built-in safety gate."""

    def __init__(self, store: EvaluationSuiteStore):
        self.store = store

    def overview(self) -> dict[str, Any]:
        custom = [self._public(item) for item in self.store.list()]
        return {
            "built_in": self._built_in(),
            "suites": [self._built_in(), *custom],
            "custom_count": len(custom),
            "contract": {
                "custom_is_additive": True,
                "built_in_scenarios_always_run": len(GOLDEN_SCENARIOS),
                "external_splunk_calls": 0,
                "hosted_inference_calls": 0,
                "maximum_custom_scenarios": 15,
                "publication_is_immutable": True,
                "synthetic_fixture_attestation_required": True,
            },
        }

    def get(self, suite_id: str) -> dict[str, Any]:
        if suite_id == BUILTIN_SUITE_ID:
            return self._built_in()
        value = self.store.get(suite_id)
        if value is None:
            raise KeyError(f"Unknown evaluation suite: {suite_id}")
        return self._public(value, include_draft=True)

    def create(self, value: EvaluationSuiteCreate, actor: str) -> dict[str, Any]:
        scenarios = [scenario.model_dump(mode="json") for scenario in value.scenarios]
        self._validate_draft(scenarios, require_publishable=False)
        return self._public(
            self.store.create(value.name, value.description, scenarios, actor),
            include_draft=True,
        )

    def update(
        self, suite_id: str, value: EvaluationSuiteUpdate
    ) -> dict[str, Any]:
        if suite_id == BUILTIN_SUITE_ID:
            raise ValueError("The built-in safety suite is immutable")
        scenarios = [scenario.model_dump(mode="json") for scenario in value.scenarios]
        self._validate_draft(scenarios, require_publishable=False)
        result = self.store.update(
            suite_id,
            expected_revision=value.expected_draft_revision,
            name=value.name,
            description=value.description,
            scenarios=scenarios,
        )
        return self._public(result, include_draft=True)

    def publish(
        self,
        suite_id: str,
        *,
        expected_revision: int,
        expected_fingerprint: str,
        synthetic_data_confirmed: bool,
        actor: str,
    ) -> dict[str, Any]:
        if suite_id == BUILTIN_SUITE_ID:
            raise ValueError("The built-in safety suite is immutable")
        if not synthetic_data_confirmed:
            raise ValueError(
                "Confirm that evaluation fixtures are synthetic and contain no credentials "
                "or live investigation data"
            )
        current = self.store.get(suite_id)
        if current is None:
            raise KeyError(f"Unknown evaluation suite: {suite_id}")
        if not current["draft_dirty"]:
            raise ValueError("Change the evaluation draft before publishing a new version")
        prior = next(
            (
                version
                for version in current["versions"]
                if version["fingerprint"] == expected_fingerprint
            ),
            None,
        )
        if prior is not None:
            raise ValueError(
                f"This exact evaluation draft is already retained as version {prior['version']}"
            )
        self._validate_draft(current["draft_scenarios"], require_publishable=True)
        result = self.store.publish(
            suite_id,
            expected_revision=expected_revision,
            expected_fingerprint=expected_fingerprint,
            actor=actor,
        )
        return self._public(result, include_draft=True)

    def archive(self, suite_id: str, archived: bool) -> dict[str, Any]:
        if suite_id == BUILTIN_SUITE_ID:
            raise ValueError("The built-in safety suite cannot be archived")
        return self._public(
            self.store.archive(suite_id, archived), include_draft=True
        )

    def delete(self, suite_id: str) -> bool:
        if suite_id == BUILTIN_SUITE_ID:
            raise ValueError("The built-in safety suite cannot be deleted")
        if self.store.get(suite_id) is None:
            raise KeyError(f"Unknown evaluation suite: {suite_id}")
        if not self.store.delete(suite_id):
            raise ValueError(
                "Only an unpublished evaluation suite can be deleted; archive published "
                "suite history instead"
            )
        return True

    def resolve(self, suite_id: str = BUILTIN_SUITE_ID) -> dict[str, Any]:
        if suite_id == BUILTIN_SUITE_ID:
            return {
                "id": BUILTIN_SUITE_ID,
                "name": "SignalRoom core safety gate",
                "version": suite_version(),
                "custom_version": 0,
                "scenarios": [dict(item) for item in GOLDEN_SCENARIOS],
            }
        suite = self.store.get(suite_id)
        if suite is None:
            raise KeyError(f"Unknown evaluation suite: {suite_id}")
        if suite["status"] != "active":
            raise ValueError("Archived evaluation suites cannot start new benchmark runs")
        version = self.store.version(suite_id)
        if version is None:
            raise ValueError("Publish the evaluation suite before running it")
        combined = [dict(item) for item in GOLDEN_SCENARIOS] + list(version["scenarios"])
        composite = self._composite_version(version["fingerprint"])
        return {
            "id": suite_id,
            "name": version["name"],
            "version": composite,
            "custom_version": version["version"],
            "custom_fingerprint": version["fingerprint"],
            "scenarios": combined,
        }

    def current_version(self, suite_id: str) -> str:
        return str(self.resolve(suite_id)["version"])

    @staticmethod
    def _composite_version(custom_fingerprint: str) -> str:
        payload = f"{suite_version()}:{custom_fingerprint}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @staticmethod
    def _validate_draft(
        scenarios: list[dict[str, Any]], *, require_publishable: bool
    ) -> None:
        if require_publishable and not scenarios:
            raise ValueError("Add at least one organization scenario before publication")
        if len(scenarios) > 15:
            raise ValueError("An evaluation suite supports at most 15 organization scenarios")
        ids = [str(item.get("id") or "") for item in scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("Evaluation scenario IDs must be unique within the suite")
        built_in_ids = {str(item["id"]) for item in GOLDEN_SCENARIOS}
        collisions = sorted(set(ids) & built_in_ids)
        if collisions:
            raise ValueError(
                "Custom scenario IDs cannot replace built-in controls: "
                + ", ".join(collisions)
            )
        total_fixture = sum(len(str(item.get("fixture_content") or "")) for item in scenarios)
        if total_fixture > 200_000:
            raise ValueError("Evaluation fixture content cannot exceed 200,000 characters")
        for item in scenarios:
            EvaluationScenario.model_validate(item)
            terms = [
                term
                for group_name in ("evidence_groups", "conclusion_groups")
                for group in item.get(group_name) or []
                for term in group
            ] + list(item.get("forbidden_claims") or [])
            if any(not str(term).strip() or len(str(term)) > 240 for term in terms):
                raise ValueError(
                    f"Scenario {item['id']} match terms must contain 1 to 240 characters"
                )
            overlap = set(item.get("expected_tools") or []) & set(
                item.get("forbidden_tools") or []
            )
            if overlap:
                raise ValueError(
                    f"Scenario {item['id']} cannot both expect and forbid: "
                    + ", ".join(sorted(overlap))
                )

    @staticmethod
    def _built_in() -> dict[str, Any]:
        return {
            "id": BUILTIN_SUITE_ID,
            "name": "SignalRoom core safety gate",
            "description": (
                "Five immutable safety, evidence, investigation, and leadership controls."
            ),
            "status": "built-in",
            "current_version": 1,
            "suite_version": suite_version(),
            "scenario_count": len(GOLDEN_SCENARIOS),
            "custom_scenario_count": 0,
            "draft_dirty": False,
            "immutable": True,
            "scenarios": [
                {
                    "id": item["id"],
                    "title": item["title"],
                    "task_type": item["task_type"],
                    "mode": item["mode"],
                }
                for item in GOLDEN_SCENARIOS
            ],
        }

    @classmethod
    def _public(
        cls, value: dict[str, Any], *, include_draft: bool = False
    ) -> dict[str, Any]:
        current = value["versions"][0] if value["versions"] else None
        scenario_source = current["scenarios"] if current else []
        result = {
            "id": value["id"],
            "name": value["name"],
            "description": value["description"],
            "status": value["status"],
            "current_version": value["current_version"],
            "current_fingerprint": value["current_fingerprint"],
            "suite_version": (
                cls._composite_version(value["current_fingerprint"])
                if value["current_fingerprint"]
                else ""
            ),
            "scenario_count": len(GOLDEN_SCENARIOS) + len(scenario_source),
            "custom_scenario_count": len(scenario_source),
            "draft_scenario_count": (
                len(GOLDEN_SCENARIOS) + len(value["draft_scenarios"])
            ),
            "draft_custom_scenario_count": len(value["draft_scenarios"]),
            "draft_revision": value["draft_revision"],
            "draft_fingerprint": value["draft_fingerprint"],
            "draft_dirty": value["draft_dirty"],
            "immutable": False,
            "created_by": value["created_by"],
            "created_at": value["created_at"],
            "updated_at": value["updated_at"],
            "archived_at": value["archived_at"],
            "versions": [
                {
                    key: version[key]
                    for key in (
                        "version",
                        "fingerprint",
                        "published_by",
                        "published_at",
                    )
                }
                for version in value["versions"]
            ],
            "scenarios": [
                {
                    "id": item["id"],
                    "title": item["title"],
                    "task_type": item["task_type"],
                    "mode": item["mode"],
                }
                for item in scenario_source
            ],
        }
        if include_draft:
            result["draft_scenarios"] = value["draft_scenarios"]
        return result
