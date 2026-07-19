from __future__ import annotations

import pytest

from splunk_security_agent.benchmarks import (
    GOLDEN_SCENARIOS,
    EvaluationSuiteService,
    EvaluationSuiteStore,
)
from splunk_security_agent.schemas import (
    EvaluationScenario,
    EvaluationSuiteCreate,
    EvaluationSuiteUpdate,
)


def scenario(identifier: str = "organization-identity-control") -> EvaluationScenario:
    return EvaluationScenario(
        id=identifier,
        title="Apply the organization identity escalation standard",
        task_type="triage",
        mode="triage",
        message="Assess the synthetic privileged identity observation.",
        fixture_title="Synthetic organization identity evidence",
        fixture_content=(
            "Synthetic fixture: org-admin on lab-host-07 requires owner confirmation. "
            "This observation does not prove compromise."
        ),
        expected_tools=[],
        forbidden_tools=["run_query"],
        evidence_groups=[["org-admin"], ["lab-host-07"]],
        conclusion_groups=[["observed", "fact"], ["validate", "confirm"]],
        forbidden_claims=["confirmed compromise"],
        expected_blocked=False,
    )


def create_service(tmp_path):
    return EvaluationSuiteService(EvaluationSuiteStore(tmp_path / "evaluation.db"))


def publish(service: EvaluationSuiteService, suite: dict, actor: str = "analyst"):
    return service.publish(
        suite["id"],
        expected_revision=suite["draft_revision"],
        expected_fingerprint=suite["draft_fingerprint"],
        synthetic_data_confirmed=True,
        actor=actor,
    )


def test_operator_suite_has_revisioned_draft_and_immutable_publication(tmp_path):
    service = create_service(tmp_path)
    created = service.create(
        EvaluationSuiteCreate(
            name="Identity response standard",
            description="Local synthetic tests for the identity team.",
            scenarios=[scenario()],
        ),
        "admin",
    )

    assert created["current_version"] == 0
    assert created["draft_dirty"] is True
    published = publish(service, created)
    resolved_v1 = service.resolve(created["id"])

    assert published["current_version"] == 1
    assert published["draft_dirty"] is False
    assert len(resolved_v1["scenarios"]) == len(GOLDEN_SCENARIOS) + 1
    assert resolved_v1["scenarios"][: len(GOLDEN_SCENARIOS)] == GOLDEN_SCENARIOS

    with pytest.raises(ValueError, match="Change the evaluation draft"):
        publish(service, published)

    updated = service.update(
        created["id"],
        EvaluationSuiteUpdate(
            expected_draft_revision=published["draft_revision"],
            name="Identity response standard",
            description="Version two of the local synthetic controls.",
            scenarios=[scenario(), scenario("organization-cloud-control")],
        ),
    )
    published_v2 = publish(service, updated)

    assert published_v2["current_version"] == 2
    assert service.store.version(created["id"], 1)["scenarios"] == [
        scenario().model_dump(mode="json")
    ]
    assert len(service.resolve(created["id"])["scenarios"]) == len(GOLDEN_SCENARIOS) + 2

    restored_old_draft = service.update(
        created["id"],
        EvaluationSuiteUpdate(
            expected_draft_revision=published_v2["draft_revision"],
            name=created["name"],
            description=created["description"],
            scenarios=[scenario()],
        ),
    )
    with pytest.raises(ValueError, match="already retained as version 1"):
        publish(service, restored_old_draft)


def test_suite_publication_requires_exact_fingerprint_and_synthetic_attestation(tmp_path):
    service = create_service(tmp_path)
    created = service.create(
        EvaluationSuiteCreate(name="SOC evaluation suite", scenarios=[scenario()]),
        "admin",
    )

    with pytest.raises(ValueError, match="Confirm that evaluation fixtures are synthetic"):
        service.publish(
            created["id"],
            expected_revision=created["draft_revision"],
            expected_fingerprint=created["draft_fingerprint"],
            synthetic_data_confirmed=False,
            actor="admin",
        )
    with pytest.raises(ValueError, match="fingerprint changed"):
        service.publish(
            created["id"],
            expected_revision=created["draft_revision"],
            expected_fingerprint="0" * 64,
            synthetic_data_confirmed=True,
            actor="admin",
        )


def test_suite_draft_rejects_stale_updates_and_built_in_control_collisions(tmp_path):
    service = create_service(tmp_path)
    created = service.create(
        EvaluationSuiteCreate(name="SOC evaluation suite", scenarios=[scenario()]),
        "admin",
    )
    service.update(
        created["id"],
        EvaluationSuiteUpdate(
            expected_draft_revision=created["draft_revision"],
            name=created["name"],
            scenarios=[scenario()],
        ),
    )
    with pytest.raises(ValueError, match="changed in another session"):
        service.update(
            created["id"],
            EvaluationSuiteUpdate(
                expected_draft_revision=created["draft_revision"],
                name=created["name"],
                scenarios=[scenario()],
            ),
        )

    collision = scenario(GOLDEN_SCENARIOS[0]["id"])
    with pytest.raises(ValueError, match="cannot replace built-in"):
        service.create(
            EvaluationSuiteCreate(name="Unsafe replacement", scenarios=[collision]),
            "admin",
        )


def test_archiving_retains_history_and_only_unpublished_drafts_can_be_deleted(tmp_path):
    service = create_service(tmp_path)
    draft = service.create(
        EvaluationSuiteCreate(name="Disposable draft"), "admin"
    )
    assert service.delete(draft["id"]) is True

    created = service.create(
        EvaluationSuiteCreate(name="Retained suite", scenarios=[scenario()]), "admin"
    )
    published = publish(service, created)
    archived = service.archive(published["id"], True)

    assert archived["status"] == "archived"
    assert service.store.version(published["id"], 1) is not None
    with pytest.raises(ValueError, match="Archived evaluation suites"):
        service.resolve(published["id"])
    with pytest.raises(ValueError, match="Only an unpublished"):
        service.delete(published["id"])
