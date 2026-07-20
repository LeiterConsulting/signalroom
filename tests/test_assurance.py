from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from splunk_security_agent.assurance import (
    AssuranceResponseService,
    AssuranceService,
    AssuranceStore,
    BudgetedSplunkClient,
)
from splunk_security_agent.cases import CaseStore
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import AssurancePolicyUpdate
from splunk_security_agent.validation import ValidationService, ValidationStore


class FakeSplunk:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, name: str, arguments: dict[str, Any]):
        self.calls.append((name, arguments))
        return []


@pytest.mark.asyncio
async def test_budgeted_client_enforces_hard_ceiling_during_parallel_calls():
    client = BudgetedSplunkClient(FakeSplunk(), limit=2)

    results = await asyncio.gather(
        client.call("one"),
        client.call("two"),
        client.call("three"),
        return_exceptions=True,
    )

    assert client.calls_used == 2
    assert client.exceeded is True
    assert sum(isinstance(item, RuntimeError) for item in results) == 1


def test_assurance_store_recovers_running_work_and_persists_cancellation(tmp_path):
    path = tmp_path / "assurance.db"
    store = AssuranceStore(path)
    policy = store.update_policy(
        AssurancePolicyUpdate(
            enabled=True,
            interval_minutes=15,
            discovery_depth="quick",
            max_splunk_calls_per_run=4,
            max_runs_per_day=2,
        )
    )
    assert policy["enabled"] is True
    assert policy["next_run_at"]

    running = store.create_run("manual", "quick", 4)
    assert store.mark_running(running.id).status == "running"

    recovered_store = AssuranceStore(path)
    recovered = recovered_store.get_run(running.id)
    assert recovered is not None
    assert recovered.status == "queued"
    assert recovered.trigger == "recovered"
    assert recovered.recovery_count == 1

    cancelled = recovered_store.request_cancel(running.id)
    assert cancelled is not None
    assert cancelled.status == "cancelled"

    first_notice = recovered_store.add_notification(
        running.id, "medium", "drift", "Coverage changed", "Identity coverage was removed."
    )
    duplicate = recovered_store.add_notification(
        running.id, "medium", "drift", "Coverage changed", "Identity coverage was removed."
    )
    assert duplicate["id"] == first_notice["id"]
    assert len(recovered_store.notifications()) == 1

    spent = recovered_store.create_run("manual", "quick", 4)
    recovered_store.mark_running(spent.id)
    recovered_store.update_progress(
        spent.id,
        {"phase": "inventory", "label": "Inventory", "progress": 25},
        calls_used=3,
    )
    recovered_store.request_cancel(spent.id)
    recovered_store.fail_run(spent.id, "cancelled", "Stopped", calls_used=3)
    assert recovered_store.usage_today() == {"runs": 1, "splunk_calls": 3}


@pytest.mark.asyncio
async def test_assurance_worker_preserves_progress_and_creates_drift_notifications(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    fake_splunk = FakeSplunk()

    class FakePipeline:
        def __init__(self, client):
            self.client = client

        async def run(self, depth: str, progress):
            await progress(
                {
                    "phase": "inventory",
                    "label": "Reading inventory",
                    "detail": "Two bounded calls",
                    "progress": 25,
                    "metrics": {"depth": depth},
                }
            )
            await asyncio.gather(
                self.client.call("get_indexes", {}),
                self.client.call("get_metadata", {"type": "sourcetypes"}),
            )
            await progress(
                {
                    "phase": "complete",
                    "label": "Discovery ready",
                    "detail": "Drift was found",
                    "progress": 100,
                    "status": "complete",
                }
            )
            return {
                "run_id": "discovery-1",
                "findings": [{"severity": "high", "title": "Identity coverage gap"}],
                "coverage": {"score": 80},
                "changes": {
                    "inventory": {"indexes": {"added": ["identity"], "removed": []}},
                    "coverage": {},
                },
                "collection_status": {"failed_calls": 0},
                "splunk_models": {"summary": {}},
            }

    service = AssuranceService(
        store,
        lambda: fake_splunk,
        lambda client: FakePipeline(client),
        poll_seconds=0.01,
    )
    run = service.enqueue("quick")
    await service.start()
    for _ in range(100):
        current = store.get_run(run.id)
        if current and current.status == "complete":
            break
        await asyncio.sleep(0.01)
    await service.stop()

    completed = store.get_run(run.id)
    assert completed is not None
    assert completed.status == "complete"
    assert completed.calls_used == 2
    assert completed.summary["inventory_drift"] == 1
    assert [item["phase"] for item in store.events(run.id)] == ["inventory", "complete"]
    assert {item["category"] for item in store.notifications()} == {"drift", "finding"}


@pytest.mark.asyncio
async def test_assurance_preflight_blocks_before_any_splunk_or_pipeline_call(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    fake_splunk = FakeSplunk()
    pipeline_started = False

    class ForbiddenPipeline:
        async def run(self, depth: str, progress):
            nonlocal pipeline_started
            pipeline_started = True
            raise AssertionError(f"pipeline must not start for blocked {depth} readiness")

    async def blocked_preflight(depth: str, progress):
        await progress(
            {
                "phase": "connection:dns",
                "label": "Resolving Splunk",
                "detail": "Hostname unavailable",
                "progress": 20,
            }
        )
        return {
            "ready": False,
            "blocking_stage": "dns",
            "depth_readiness": {"quick": False, "standard": False, "deep": False},
            "stages": [{"id": "dns", "status": "error", "detail": "Hostname unavailable"}],
        }

    service = AssuranceService(
        store,
        lambda: fake_splunk,
        lambda client: ForbiddenPipeline(),
        preflight=blocked_preflight,
        poll_seconds=0.01,
    )
    run = service.enqueue("quick")
    await service.start()
    for _ in range(100):
        current = store.get_run(run.id)
        if current and current.status == "connection-blocked":
            break
        await asyncio.sleep(0.01)
    await service.stop()

    completed = store.get_run(run.id)
    assert completed is not None
    assert completed.status == "connection-blocked"
    assert completed.calls_used == 0
    assert pipeline_started is False
    assert fake_splunk.calls == []


@pytest.mark.asyncio
async def test_assurance_execution_passes_immutable_secondary_binding_to_dependencies(
    tmp_path,
):
    store = AssuranceStore(tmp_path / "assurance.db")
    binding = {
        "alias": "soc-east",
        "fingerprint": "a" * 64,
        "tenant_scope_id": "tenant-east",
    }
    store.bind_unbound(binding)
    captured: dict[str, Any] = {}

    def client_factory(target):
        captured["client_binding"] = target
        return FakeSplunk()

    async def preflight(depth, progress, target):
        captured["preflight_binding"] = target
        return {
            "ready": True,
            "blocking_stage": "",
            "depth_readiness": {"quick": True},
            "stages": [],
        }

    class Pipeline:
        async def run(self, depth: str, progress):
            return {
                "run_id": "discovery-secondary",
                "findings": [],
                "coverage": {"score": 100},
                "changes": {"inventory": {}, "coverage": {}},
                "collection_status": {"failed_calls": 0},
                "splunk_models": {"summary": {}},
            }

    service = AssuranceService(
        store,
        client_factory,
        lambda _client: Pipeline(),
        preflight=preflight,
    )
    run = service.enqueue("quick")

    await service._execute(run.id)

    completed = store.get_run(run.id)
    assert completed is not None and completed.status == "complete"
    assert completed.connection_alias == "soc-east"
    assert captured == {
        "client_binding": binding,
        "preflight_binding": binding,
    }


def test_assurance_policy_rejects_a_budget_below_selected_depth(tmp_path):
    service = AssuranceService(
        AssuranceStore(tmp_path / "assurance.db"),
        FakeSplunk,
        lambda client: None,
    )

    with pytest.raises(ValueError, match="requires up to 12"):
        service.update_policy(
            AssurancePolicyUpdate(
                discovery_depth="deep",
                max_splunk_calls_per_run=4,
            )
        )


@pytest.mark.asyncio
async def test_active_assurance_cancellation_is_terminal(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    started = asyncio.Event()

    class SlowPipeline:
        async def run(self, depth: str, progress):
            await progress(
                {
                    "phase": "inventory",
                    "label": "Reading inventory",
                    "detail": depth,
                    "progress": 10,
                }
            )
            started.set()
            await asyncio.Event().wait()

    service = AssuranceService(
        store,
        FakeSplunk,
        lambda client: SlowPipeline(),
        poll_seconds=0.01,
    )
    run = service.enqueue("quick")
    await service.start()
    await asyncio.wait_for(started.wait(), timeout=1)

    cancelled = await service.cancel(run.id)
    await service.stop()

    assert cancelled is not None
    assert cancelled.status == "cancelled"
    assert store.get_run(run.id).status == "cancelled"
    assert store.usage_today()["runs"] == 0


def test_assurance_correlates_transient_persistent_and_resolved_signals(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    signal = {
        "fingerprint": "telemetry-index-added",
        "kind": "inventory",
        "severity": "medium",
        "title": "Telemetry index added",
        "detail": "index=identity",
        "subject": "identity",
        "source_ref": "",
    }

    first = store.correlate_signals("run-1", [signal], authoritative=True, authoritative_kinds={"inventory"})[
        0
    ]
    second = store.correlate_signals(
        "run-2", [signal], authoritative=True, authoritative_kinds={"inventory"}
    )[0]
    duplicate = store.correlate_signals(
        "run-2", [signal], authoritative=True, authoritative_kinds={"inventory"}
    )[0]
    store.correlate_signals("run-partial", [], authoritative=False, authoritative_kinds={"inventory"})
    unresolved = store.get_signal(signal["fingerprint"])
    store.correlate_signals("run-3", [], authoritative=True, authoritative_kinds={"inventory"})
    resolved = store.get_signal(signal["fingerprint"])

    assert first["status"] == "watching"
    assert second["status"] == "persistent" and second["consecutive_count"] == 2
    assert duplicate["occurrence_count"] == 2
    assert unresolved is not None and unresolved["status"] == "persistent"
    assert resolved is not None and resolved["status"] == "resolved"


def test_assurance_recurrence_and_resolution_are_isolated_by_connection_scope(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    signal = {
        "fingerprint": "shared-finding-content",
        "kind": "finding",
        "severity": "medium",
        "title": "Same title in two estates",
        "detail": "The observation text is intentionally identical.",
        "subject": "identity",
        "source_ref": "D1",
    }
    east_scope = f"soc-east|{'a' * 64}|tenant-east"
    west_scope = f"soc-west|{'b' * 64}|tenant-west"

    east = store.correlate_signals(
        "east-1",
        [signal],
        authoritative=True,
        scope_key=east_scope,
    )[0]
    west = store.correlate_signals(
        "west-1",
        [signal],
        authoritative=True,
        scope_key=west_scope,
    )[0]
    store.correlate_signals(
        "east-2",
        [],
        authoritative=True,
        scope_key=east_scope,
    )

    assert east["fingerprint"] != west["fingerprint"]
    assert east["connection_alias"] == "soc-east"
    assert east["connection_fingerprint"] == "a" * 64
    assert east["tenant_scope_id"] == "tenant-east"
    assert west["tenant_scope_id"] == "tenant-west"
    assert [item["fingerprint"] for item in store.signals(tenant_scope_id="tenant-east")] == [
        east["fingerprint"]
    ]
    assert [item["fingerprint"] for item in store.signals(tenant_scope_id="tenant-west")] == [
        west["fingerprint"]
    ]
    assert east["status"] == "watching"
    assert west["status"] == "watching"
    assert store.get_signal(east["fingerprint"])["status"] == "resolved"
    assert store.get_signal(west["fingerprint"])["status"] == "watching"


def test_assurance_response_package_inherits_exact_run_scope(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    binding = {
        "alias": "soc-east",
        "fingerprint": "a" * 64,
        "tenant_scope_id": "tenant-east",
    }
    store.bind_unbound(binding)
    run = store.create_run("manual", "quick", 8)
    signal = store.correlate_signals(
        run.id,
        [
            {
                "fingerprint": "scoped-package-signal",
                "kind": "coverage",
                "severity": "high",
                "title": "Scoped response signal",
                "detail": "Direct ownership must follow the source run.",
                "subject": "identity",
                "source_ref": "D1",
            }
        ],
        authoritative=True,
        scope_key=f"soc-east|{'a' * 64}|tenant-east",
    )[0]
    package = store.create_package(
        run.id,
        "high",
        "Scoped assurance package",
        "Exact run ownership",
        [signal["fingerprint"]],
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )

    assert package["connection_alias"] == "soc-east"
    assert package["connection_fingerprint"] == "a" * 64
    assert package["tenant_scope_id"] == "tenant-east"
    assert store.get_package(package["id"], "tenant-east") is not None
    assert store.get_package(package["id"], "tenant-west") is None
    assert [item["id"] for item in store.packages(tenant_scope_id="tenant-east")] == [package["id"]]


def test_partial_observations_do_not_accumulate_recurrence(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    signal = {
        "fingerprint": "absence-derived-from-partial-read",
        "kind": "finding",
        "severity": "high",
        "title": "Telemetry absent",
        "detail": "Collection was incomplete.",
        "subject": "telemetry",
        "source_ref": "D1",
        "authoritative": "false",
    }

    first = store.correlate_signals("run-1", [signal], authoritative=False)[0]
    second = store.correlate_signals("run-2", [signal], authoritative=False)[0]
    signal["authoritative"] = "true"
    authoritative = store.correlate_signals("run-3", [signal], authoritative=True)[0]

    assert first["status"] == "watching" and first["consecutive_count"] == 0
    assert second["status"] == "watching" and second["consecutive_count"] == 0
    assert authoritative["status"] == "persistent"
    assert authoritative["consecutive_count"] == 1


def test_response_service_creates_one_local_expiring_draft_and_deduplicates(tmp_path):
    assurance_store = AssuranceStore(tmp_path / "assurance.db")
    validation_store = ValidationStore(tmp_path / "validations.db")
    validation_service = ValidationService(
        validation_store,
        FakeSplunk(),
        EvidenceStore(tmp_path / "evidence.db"),
        CaseStore(tmp_path / "cases.db", tmp_path / "exports"),
    )
    response = AssuranceResponseService(assurance_store, lambda: validation_service)
    result = {
        "run_id": "discovery-1",
        "depth": "standard",
        "findings": [
            {
                "severity": "high",
                "domain": "telemetry-coverage",
                "title": "Identity telemetry is missing",
                "evidence": "No identity sourcetypes were observed.",
            }
        ],
        "changes": {"inventory": {}, "coverage": {}},
        "collection_status": {"failed_calls": 0},
        "splunk_models": {"summary": {}},
        "validation_candidates": [
            {
                "id": "D1",
                "title": "Validate identity telemetry",
                "rationale": "Observe current identity activity.",
                "spl": "| tstats count where earliest=-24h by index sourcetype | head 100",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 100,
                "evidence_refs": ["D1"],
                "source_run_id": "discovery-1",
                "source_finding_ref": "D1",
            }
        ],
    }

    package = response.process("assurance-1", result)
    duplicate = response.process("assurance-2", result)
    tasks = validation_store.list()

    assert package is not None and package["status"] == "review"
    assert package["validation_task_ids"] == [tasks[0].id]
    assert duplicate is None
    assert len(tasks) == 1
    assert tasks[0].status == "draft"
    assert tasks[0].expires_at
    assert tasks[0].assurance_package_id == package["id"]
    assert tasks[0].approval_scope == "single-execution"
    assert assurance_store.signal_counts() == {
        "actionable": 1,
        "repeated": 1,
        "severity_elevated": 0,
        "watching": 0,
        "resolved": 0,
    }


def test_response_service_names_failed_collection_paths():
    signals = AssuranceResponseService._signals(
        {
            "findings": [
                {
                    "severity": "high",
                    "domain": "telemetry-coverage",
                    "title": "Telemetry was not observed",
                    "evidence": "No sourcetypes were returned.",
                }
            ],
            "changes": {"inventory": {}, "coverage": {}},
            "splunk_models": {"summary": {}},
            "collection_status": {
                "failed_calls": 2,
                "errors": {
                    "indexes": "Connection refused",
                    "sourcetypes": "Connection refused",
                },
            },
        }
    )

    collection_signals = [item for item in signals if item["kind"] == "collection"]
    finding = next(item for item in signals if item["kind"] == "finding")
    assert {item["subject"] for item in collection_signals} == {"indexes", "sourcetypes"}
    assert all("Connection refused" in item["detail"] for item in collection_signals)
    assert finding["severity"] == "medium"
    assert finding["authoritative"] == "false"
    assert "treat this derived finding as unverified" in finding["detail"]


def test_assurance_response_package_lifecycle_is_durable(tmp_path):
    store = AssuranceStore(tmp_path / "assurance.db")
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    package = store.create_package("run-1", "medium", "Review drift", "Needs analyst review.", [], future)
    closed = store.close_package(package["id"])
    expired = store.create_package(
        "run-2",
        "medium",
        "Expired drift",
        "Window elapsed.",
        [],
        (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    )

    assert closed is not None and closed["status"] == "closed"
    assert store.get_package(expired["id"])["status"] == "expired"
