from __future__ import annotations

import asyncio
from typing import Any

import pytest

from splunk_security_agent.discovery import DiscoveryJobService, DiscoveryJobStore


class FakeSplunk:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, name: str, arguments: dict[str, Any] | None = None):
        self.calls.append((name, arguments or {}))
        return []


class FakeAudit:
    def __init__(self):
        self.records: list[dict[str, Any]] = []

    def record(self, event_type: str, action: str, **value: Any):
        self.records.append({"event_type": event_type, "action": action, **value})


async def wait_for_status(store: DiscoveryJobStore, job_id: str, statuses: set[str]):
    for _ in range(150):
        current = store.get_job(job_id)
        if current and current.status in statuses:
            return current
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {job_id} did not reach {statuses}")


def test_discovery_job_store_recovers_work_and_retains_results(tmp_path):
    path = tmp_path / "discovery_jobs.db"
    store = DiscoveryJobStore(path)
    job = store.create_job("standard", "analyst-one", call_budget=9)
    running = store.mark_running(job.id)
    assert running is not None and running.status == "running"
    store.update_progress(
        job.id,
        {
            "phase": "inventory",
            "label": "Reading inventory",
            "detail": "Bounded metadata collection",
            "progress": 35,
            "metrics": {"indexes": 4},
        },
        calls_used=2,
    )

    recovered_store = DiscoveryJobStore(path)
    recovered = recovered_store.get_job(job.id)
    assert recovered is not None
    assert recovered.status == "queued"
    assert recovered.recovery_count == 1
    assert recovered.requested_by == "analyst-one"

    recovered_store.mark_running(job.id)
    retained = {"run_id": "discovery-one", "overview": {"indexes": 4}}
    recovered_store.complete_job(
        job.id,
        "complete",
        {"discovery_run_id": "discovery-one", "headline": "Ready"},
        retained,
        calls_used=4,
    )
    completed = recovered_store.get_job(job.id)
    assert completed is not None
    assert completed.result_run_id == "discovery-one"
    assert completed.calls_used == 4
    assert recovered_store.result(job.id) == retained
    assert [event["phase"] for event in recovered_store.events(job.id)][-2:] == [
        "starting",
        "complete",
    ]


@pytest.mark.asyncio
async def test_discovery_worker_persists_progress_result_and_operator_audit(tmp_path):
    store = DiscoveryJobStore(tmp_path / "discovery_jobs.db")
    splunk = FakeSplunk()
    audit = FakeAudit()
    completed_callbacks: list[str] = []

    class FakePipeline:
        def __init__(self, client: Any):
            self.client = client
            self.result: dict[str, Any] = {}

        async def run(self, depth: str, progress: Any):
            await progress(
                {
                    "phase": "inventory",
                    "label": "Reading Splunk inventory",
                    "detail": "One bounded call",
                    "progress": 30,
                    "metrics": {"depth": depth},
                }
            )
            await self.client.call("get_indexes", {})
            self.result = {
                "run_id": "manual-discovery-1",
                "depth": depth,
                "overview": {"indexes": 3, "sourcetypes": 5, "hosts": 2},
                "security_posture": {"telemetry": {}},
                "coverage": {"score": 84},
                "findings": [{"severity": "high", "title": "Identity gap"}],
                "changes": {"inventory": {}, "coverage": {}},
                "collection_status": {"failed_calls": 0},
            }
            await progress(
                {
                    "phase": "complete",
                    "label": "Discovery ready",
                    "detail": "Local result retained",
                    "progress": 100,
                    "status": "complete",
                }
            )
            return self.result

        def latest_summary(self):
            return self.result

    async def on_complete(job_id: str, _result: dict[str, Any]):
        completed_callbacks.append(job_id)

    service = DiscoveryJobService(
        store,
        lambda: splunk,
        lambda client: FakePipeline(client),
        on_complete=on_complete,
        audit=audit,
        poll_seconds=0.01,
    )
    job = service.enqueue("quick", "tier-two")
    await service.start()
    completed = await wait_for_status(store, job.id, {"complete"})
    await service.stop()

    assert completed.calls_used == 1
    assert completed.summary["findings"] == 1
    assert store.result(job.id)["run_id"] == "manual-discovery-1"
    assert completed_callbacks == [job.id]
    audit_event = next(item for item in audit.records if item["event_type"] == "discovery.job.completed")
    assert audit_event["actor"] == "tier-two"
    assert audit_event["metadata"]["splunk_calls"] == 1


@pytest.mark.asyncio
async def test_discovery_worker_cancellation_is_terminal(tmp_path):
    store = DiscoveryJobStore(tmp_path / "discovery_jobs.db")
    started = asyncio.Event()

    class SlowPipeline:
        async def run(self, depth: str, progress: Any):
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

    service = DiscoveryJobService(
        store,
        FakeSplunk,
        lambda client: SlowPipeline(),
        poll_seconds=0.01,
    )
    job = service.enqueue("quick", "local-operator")
    await service.start()
    await asyncio.wait_for(started.wait(), timeout=1)
    cancelled = await service.cancel(job.id)
    await service.stop()

    assert cancelled is not None and cancelled.status == "cancelled"
    assert store.get_job(job.id).status == "cancelled"


@pytest.mark.asyncio
async def test_discovery_worker_requeues_shutdown_and_completes_after_restart(tmp_path):
    store = DiscoveryJobStore(tmp_path / "discovery_jobs.db")
    started = asyncio.Event()

    class InterruptedPipeline:
        async def run(self, depth: str, progress: Any):
            started.set()
            await asyncio.Event().wait()

    first = DiscoveryJobService(
        store,
        FakeSplunk,
        lambda client: InterruptedPipeline(),
        poll_seconds=0.01,
    )
    job = first.enqueue("quick", "restart-analyst")
    await first.start()
    await asyncio.wait_for(started.wait(), timeout=1)
    await first.stop()

    recovered = store.get_job(job.id)
    assert recovered is not None
    assert recovered.status == "queued"
    assert recovered.recovery_count == 1

    class RecoveredPipeline:
        def __init__(self):
            self.result = {
                "run_id": "recovered-result",
                "depth": "quick",
                "findings": [],
                "changes": {"inventory": {}, "coverage": {}},
                "coverage": {"score": 100},
                "collection_status": {"failed_calls": 0},
            }

        async def run(self, depth: str, progress: Any):
            return self.result

        def latest_summary(self):
            return self.result

    second = DiscoveryJobService(
        store,
        FakeSplunk,
        lambda client: RecoveredPipeline(),
        poll_seconds=0.01,
    )
    await second.start()
    completed = await wait_for_status(store, job.id, {"complete"})
    await second.stop()

    assert completed.result_run_id == "recovered-result"
    assert completed.recovery_count == 1


@pytest.mark.asyncio
async def test_discovery_preflight_blocks_before_pipeline_or_splunk_call(tmp_path):
    store = DiscoveryJobStore(tmp_path / "discovery_jobs.db")
    splunk = FakeSplunk()
    pipeline_started = False

    class ForbiddenPipeline:
        async def run(self, depth: str, progress: Any):
            nonlocal pipeline_started
            pipeline_started = True
            raise AssertionError(f"pipeline must not start for blocked {depth} readiness")

    async def blocked_preflight(depth: str, progress: Any):
        await progress(
            {
                "phase": "connection:tls",
                "label": "Checking TLS",
                "detail": "Certificate validation failed",
                "progress": 10,
            }
        )
        return {
            "ready": False,
            "blocking_stage": "tls",
            "depth_readiness": {"quick": False, "standard": False, "deep": False},
            "stages": [
                {
                    "id": "tls",
                    "status": "error",
                    "detail": "Certificate validation failed",
                }
            ],
        }

    service = DiscoveryJobService(
        store,
        lambda: splunk,
        lambda client: ForbiddenPipeline(),
        preflight=blocked_preflight,
        poll_seconds=0.01,
    )
    job = service.enqueue("quick", "local-operator")
    await service.start()
    blocked = await wait_for_status(store, job.id, {"connection-blocked"})
    await service.stop()

    assert blocked.calls_used == 0
    assert blocked.summary["blocking_stage"] == "tls"
    assert pipeline_started is False
    assert splunk.calls == []


def test_discovery_queue_allows_only_one_active_manual_job(tmp_path):
    service = DiscoveryJobService(
        DiscoveryJobStore(tmp_path / "discovery_jobs.db"),
        FakeSplunk,
        lambda client: None,
    )
    service.enqueue("quick", "first")

    with pytest.raises(ValueError, match="already queued or running"):
        service.enqueue("standard", "second")


def test_discovery_ui_uses_durable_jobs_and_exposes_cancellation():
    html = (
        __import__("pathlib").Path("src/splunk_security_agent/static/index.html").read_text(encoding="utf-8")
    )
    script = __import__("pathlib").Path("src/splunk_security_agent/static/app.js").read_text(encoding="utf-8")

    assert 'id="discoveryJobHistory"' in html
    assert 'id="cancelDiscoveryJob"' in html
    assert "api('/api/discovery/jobs'" in script
    assert (
        "/api/discovery/stream"
        not in script[script.index("async function runDiscovery()") : script.index("function assuranceTime")]
    )
