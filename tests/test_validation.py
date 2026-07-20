from datetime import UTC, datetime, timedelta

import pytest

from splunk_security_agent.cases import CaseStore
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import (
    CaseCreate,
    ValidationTaskCreate,
    ValidationTaskUpdate,
)
from splunk_security_agent.validation import ValidationService, ValidationStore


def task_value(**updates):
    value = {
        "title": "Validate stale telemetry",
        "rationale": "Discovery D2 reported stale sourcetypes.",
        "spl": "| tstats latest(_time) as last_seen where earliest=-7d by sourcetype | head 100",
        "earliest_time": "-7d",
        "latest_time": "now",
        "row_limit": 100,
        "evidence_refs": ["D2"],
        "source_run_id": "run-123",
        "source_finding_ref": "D2",
    }
    value.update(updates)
    return ValidationTaskCreate(**value)


def test_validation_store_preserves_approval_and_recovers_interrupted_execution(tmp_path):
    path = tmp_path / "validations.db"
    store = ValidationStore(path)
    created = store.create(task_value())
    assert created.status == "draft"

    edited = store.update(created.id, ValidationTaskUpdate(row_limit=50))
    assert edited is not None and edited.row_limit == 50
    approved = store.approve(created.id)
    assert approved is not None and approved.status == "approved"
    running = store.mark_running(created.id)
    assert running is not None and running.status == "running"

    recovered = ValidationStore(path).get(created.id)
    assert recovered is not None and recovered.status == "approved"
    assert "restart" in recovered.error


async def test_validation_service_requires_approval_and_preserves_bounded_result(tmp_path):
    class RecordingSplunk:
        def __init__(self):
            self.calls = []

        async def call(self, name, arguments):
            self.calls.append((name, arguments))
            return {"results": [{"sourcetype": "audit", "age_hours": 72.5}]}

    store = ValidationStore(tmp_path / "validations.db")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    cases = CaseStore(tmp_path / "cases.db", tmp_path / "exports")
    case = cases.create(CaseCreate(title="Telemetry review"))
    splunk = RecordingSplunk()
    service = ValidationService(store, splunk, evidence, cases)
    created = service.create(task_value(case_id=case.id))

    with pytest.raises(ValueError, match="approved"):
        await service.execute(created.id)

    service.approve(created.id)
    completed = await service.execute(created.id)

    assert completed.status == "complete"
    assert completed.result_count == 1
    assert completed.result_preview[0]["sourcetype"] == "audit"
    assert completed.artifact_id
    assert splunk.calls[0][0] == "run_query"
    assert splunk.calls[0][1]["row_limit"] == 100
    assert evidence.get(completed.artifact_id).kind == "validation"
    saved_case = cases.get(case.id)
    assert saved_case is not None
    assert saved_case.items[0].metadata["validation_task_id"] == completed.id


async def test_validation_service_surfaces_mcp_error_payloads(tmp_path):
    class RejectingSplunk:
        async def call(self, name, arguments):
            return {"status_code": 400, "content": "Forbidden command found: rest"}

    store = ValidationStore(tmp_path / "validations.db")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    service = ValidationService(
        store,
        RejectingSplunk(),
        evidence,
        CaseStore(tmp_path / "cases.db", tmp_path / "exports"),
    )
    created = service.create(task_value())
    service.approve(created.id)

    with pytest.raises(ValueError, match="Forbidden command"):
        await service.execute(created.id)

    failed = store.get(created.id)
    assert failed is not None and failed.status == "error"
    assert "Forbidden command" in failed.error
    assert evidence.list() == []


def test_validation_service_rejects_unsafe_or_unbounded_contracts(tmp_path):
    service = ValidationService(
        ValidationStore(tmp_path / "validations.db"),
        object(),
        EvidenceStore(tmp_path / "evidence.db"),
        CaseStore(tmp_path / "cases.db", tmp_path / "exports"),
    )

    with pytest.raises(ValueError, match="high-risk"):
        service.create(task_value(spl="search index=main | outputlookup results.csv"))
    with pytest.raises(ValueError, match="30 days"):
        service.create(task_value(earliest_time="-31d"))
    with pytest.raises(ValueError, match="latest_time=now"):
        service.create(task_value(latest_time="+1h"))


def test_assurance_validation_drafts_expire_before_approval(tmp_path):
    store = ValidationStore(tmp_path / "validations.db")
    expired_at = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    created = store.create(
        task_value(
            expires_at=expired_at,
            assurance_package_id="package-1",
            approval_scope="single-execution",
        )
    )

    expired = store.get(created.id)

    assert expired is not None and expired.status == "expired"
    assert expired.assurance_package_id == "package-1"
    assert expired.approval_scope == "single-execution"
    with pytest.raises(ValueError, match="expired"):
        store.approve(created.id)


def test_validation_store_filters_reuse_and_records_by_tenant(tmp_path):
    store = ValidationStore(tmp_path / "validations.db")
    east = store.create(
        task_value(
            connection_alias="east",
            connection_fingerprint="a" * 64,
            tenant_scope_id="tenant-east",
        )
    )
    west = store.create(
        task_value(
            connection_alias="west",
            connection_fingerprint="b" * 64,
            tenant_scope_id="tenant-west",
        )
    )

    assert [item.id for item in store.list(tenant_scope_id="tenant-east")] == [east.id]
    assert store.get(west.id, "tenant-east") is None
    assert store.find_reusable(
        east.query_fingerprint, tenant_scope_id="tenant-east"
    ).id == east.id
    assert store.find_reusable(
        east.query_fingerprint, tenant_scope_id="tenant-west"
    ).id == west.id


async def test_validation_execution_uses_its_bound_splunk_scope(tmp_path):
    class RecordingSplunk:
        def __init__(self):
            self.calls = []

        async def call(self, name, arguments):
            self.calls.append((name, arguments))
            return {"results": []}

    selected = []
    scoped = RecordingSplunk()

    def factory(binding):
        selected.append(binding)
        return scoped

    service = ValidationService(
        ValidationStore(tmp_path / "validations.db"),
        object(),
        EvidenceStore(tmp_path / "evidence.db"),
        CaseStore(tmp_path / "cases.db", tmp_path / "exports"),
        splunk_factory=factory,
        binding_validator=lambda alias, fingerprint, tenant: (
            (alias, fingerprint, tenant) == ("east", "a" * 64, "tenant-east"),
            "stale binding",
        ),
    )
    task = service.create(
        task_value(
            connection_alias="east",
            connection_fingerprint="a" * 64,
            tenant_scope_id="tenant-east",
        )
    )
    service.approve(task.id)

    completed = await service.execute(task.id)

    assert completed.status == "complete"
    assert selected == [
        {
            "alias": "east",
            "fingerprint": "a" * 64,
            "tenant_scope_id": "tenant-east",
        }
    ]
    artifact = service.evidence.get(completed.artifact_id, "tenant-east")
    assert artifact is not None
    assert artifact.connection_fingerprint == "a" * 64
