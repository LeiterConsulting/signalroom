import asyncio
import sqlite3

import pytest

from splunk_security_agent.schemas import WorkloadPolicyUpdate
from splunk_security_agent.workload import (
    SplunkWorkloadService,
    WorkloadControlledSplunkClient,
    WorkloadPolicyBlocked,
    WorkloadStore,
)


class RecordingSplunk:
    def __init__(self, delay: float = 0):
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.calls = []

    async def call(self, name, arguments):
        self.calls.append((name, arguments))
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            return {"ok": True, "name": name}
        finally:
            self.active -= 1


def workload(tmp_path):
    service = SplunkWorkloadService(WorkloadStore(tmp_path / "workload.db"))
    instance_id = service.set_current_instance(
        {"url": "https://splunk.example/services/mcp", "verify_tls": True}
    )
    return service, instance_id


async def test_audit_mode_warns_but_allows_high_cost_query(tmp_path):
    service, instance_id = workload(tmp_path)
    raw = RecordingSplunk()
    client = WorkloadControlledSplunkClient(raw, service, instance_id)
    arguments = {
        "query": "search error | transaction user | stats count by host",
        "earliest_time": "-30d",
        "latest_time": "now",
        "row_limit": 500,
    }

    assessment = service.assess_query(**{
        "spl": arguments["query"],
        "earliest_time": arguments["earliest_time"],
        "latest_time": arguments["latest_time"],
        "row_limit": arguments["row_limit"],
    })
    result = await client.call("run_query", arguments)

    assert assessment["decision"] == "audit-warning"
    assert result["ok"] is True
    assert raw.calls[0][0] == "run_query"
    assert service.overview()["events"][0]["decision"] == "audit-warning"


async def test_enforce_mode_blocks_risk_and_daily_budget_before_splunk(tmp_path):
    service, instance_id = workload(tmp_path)
    await service.update_policy(
        WorkloadPolicyUpdate(
            mode="enforce",
            max_query_risk_score=40,
            max_query_cost_units=100,
            daily_query_cost_units=50,
        )
    )
    raw = RecordingSplunk()
    client = WorkloadControlledSplunkClient(raw, service, instance_id)

    with pytest.raises(WorkloadPolicyBlocked, match="blocked"):
        await client.call(
            "run_query",
            {
                "query": "search error | stats count",
                "earliest_time": "-30d",
                "latest_time": "now",
                "row_limit": 100,
            },
        )

    assert raw.calls == []
    event = service.overview()["events"][0]
    assert event["status"] == "blocked"
    assert event["query_fingerprint"]


async def test_shared_instance_concurrency_queues_calls_and_reports_position(tmp_path):
    service, instance_id = workload(tmp_path)
    await service.update_policy(
        WorkloadPolicyUpdate(
            max_concurrent_calls=1,
            max_concurrent_queries=1,
            queue_timeout_seconds=5,
        )
    )
    raw = RecordingSplunk(delay=0.05)
    client = WorkloadControlledSplunkClient(raw, service, instance_id)
    progress = []

    async def publish(event):
        progress.append(event)

    async with service.scope("concurrency-test", publish):
        await asyncio.gather(
            client.call("list_indexes", {}),
            client.call("list_sourcetypes", {}),
        )

    assert raw.max_active == 1
    assert any(event["phase"] == "workload:queue" for event in progress)
    assert any(
        event["metrics"].get("queue_position", 0) >= 1
        for event in progress
        if event["phase"] == "workload:queue"
    )


async def test_workload_history_never_persists_raw_spl(tmp_path):
    service, instance_id = workload(tmp_path)
    raw = RecordingSplunk()
    client = WorkloadControlledSplunkClient(raw, service, instance_id)
    secret_query = "index=private marker=DO_NOT_PERSIST | head 5"

    await client.call(
        "run_query",
        {
            "query": secret_query,
            "earliest_time": "-1h",
            "latest_time": "now",
            "row_limit": 5,
        },
    )

    with sqlite3.connect(service.store.path) as db:
        rows = db.execute(
            "SELECT operation,logical_name,query_fingerprint,reasons,error FROM workload_events"
        ).fetchall()
    assert rows
    assert all("DO_NOT_PERSIST" not in str(row) for row in rows)
    assert "DO_NOT_PERSIST" not in service.store.path.read_bytes().decode(
        "utf-8", errors="ignore"
    )


def test_workload_store_recovers_interrupted_admissions(tmp_path):
    store = WorkloadStore(tmp_path / "workload.db")
    event_id = store.create_event(
        instance_id="instance",
        operation="test",
        logical_name="run_query",
        lane="query",
        query_fingerprint="abc",
        risk="low",
        risk_score=0,
        cost_units=5,
        decision="allow",
        status="queued",
        reasons=[],
        policy_generation=1,
    )
    recovered = WorkloadStore(store.path)

    event = next(item for item in recovered.recent() if item["id"] == event_id)
    assert event["status"] == "interrupted"
    assert recovered.daily_usage("instance") == 5
