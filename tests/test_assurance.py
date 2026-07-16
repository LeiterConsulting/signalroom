from __future__ import annotations

import asyncio
from typing import Any

import pytest

from splunk_security_agent.assurance import (
    AssuranceService,
    AssuranceStore,
    BudgetedSplunkClient,
)
from splunk_security_agent.schemas import AssurancePolicyUpdate


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
