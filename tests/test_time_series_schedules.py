from __future__ import annotations

from datetime import UTC, datetime

import pytest

from splunk_security_agent.audit import AuditStore
from splunk_security_agent.forecasting import (
    TimeSeriesScheduleService,
    TimeSeriesScheduleStore,
)
from splunk_security_agent.schemas import (
    TimeSeriesForecastRequest,
    TimeSeriesReviewDecision,
    TimeSeriesScheduleCreate,
    TimeSeriesScheduleUpdate,
)


def forecast_request() -> TimeSeriesForecastRequest:
    return TimeSeriesForecastRequest(
        title="Authentication event-rate forecast",
        spl="index=security | timechart span=5m count as value",
        earliest_time="-7d",
        row_limit=200,
        interval_seconds=300,
        horizon=12,
        backtest_points=12,
    )


def schedule_value(**updates) -> TimeSeriesScheduleCreate:
    values = {
        "title": "Authentication shadow",
        "request": forecast_request(),
        "enabled": False,
        "interval_minutes": 360,
        "max_runs_per_day": 4,
        "seasonal_comparison": True,
    }
    values.update(updates)
    return TimeSeriesScheduleCreate(**values)


class FakeForecast:
    def __init__(self, decision: str = "material-drift"):
        self.decision = decision
        self.calls = []

    async def run(
        self,
        request,
        progress,
        *,
        actor,
        seasonal_comparison=True,
    ):
        self.calls.append((request, actor, seasonal_comparison))
        await progress(
            {
                "phase": "forecast:splunk",
                "label": "Extracting bounded series",
                "detail": "One read-only query.",
                "progress": 40,
                "metrics": {"splunk_calls": 1},
            }
        )
        run_id = f"forecast-{len(self.calls)}"
        return {
            "run_id": run_id,
            "promotion_gate": {"ready": True},
            "experiment": {
                "run_fingerprint": f"{len(self.calls):064x}",
                "comparison": {
                    "decision": self.decision,
                    "reasons": ["Series moved from its reviewed reference."],
                },
            },
        }


def test_schedule_is_opt_in_and_enablement_starts_at_next_interval(tmp_path):
    store = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    paused = store.create(schedule_value(), actor="tier-two")

    assert paused["enabled"] is False
    assert paused["next_run_at"] is None
    assert store.due() is None

    enabled = store.update(
        paused["id"],
        TimeSeriesScheduleUpdate(
            expected_updated_at=paused["updated_at"],
            enabled=True,
        ),
    )
    assert enabled is not None
    assert enabled["enabled"] is True
    assert datetime.fromisoformat(enabled["next_run_at"]) > datetime.now(UTC)
    assert store.due() is None


def test_schedule_enforces_daily_budget_and_recovers_interrupted_attempt(tmp_path):
    path = tmp_path / "schedules.db"
    store = TimeSeriesScheduleStore(path)
    schedule = store.create(
        schedule_value(max_runs_per_day=1),
        actor="tier-two",
    )
    attempt = store.enqueue(schedule["id"], trigger="manual")
    store.mark_running(attempt["id"])

    restarted = TimeSeriesScheduleStore(path)
    assert restarted.recover_interrupted() == 1
    recovered = restarted.attempt(attempt["id"])
    assert recovered["status"] == "queued"
    assert recovered["trigger"] == "recovered"
    assert recovered["recovery_count"] == 1

    restarted.fail(attempt["id"], "test complete")
    with pytest.raises(ValueError, match="daily budget"):
        restarted.enqueue(schedule["id"], trigger="manual")


@pytest.mark.asyncio
async def test_shadow_execution_creates_review_without_alert_side_effects(tmp_path):
    store = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    schedule = store.create(schedule_value(), actor="tier-two")
    attempt = store.enqueue(schedule["id"], trigger="manual")
    forecast = FakeForecast()
    service = TimeSeriesScheduleService(
        store,
        forecast,
        AuditStore(tmp_path / "audit.db"),
        lambda _owner: (True, ""),
        poll_seconds=0.01,
    )

    await service._execute(attempt["id"])

    completed = store.attempt(attempt["id"])
    assert completed["status"] == "complete"
    assert completed["experiment_run_id"] == "forecast-1"
    reviews = store.reviews()
    assert len(reviews) == 1
    assert reviews[0]["state"] == "pending"
    assert reviews[0]["comparison_decision"] == "material-drift"
    assert store.overview()["contract"]["automatic_alerting"] is False
    assert forecast.calls[0][2] is True

    with pytest.raises(ValueError, match="fingerprint"):
        store.decide_review(
            reviews[0]["id"],
            TimeSeriesReviewDecision(
                expected_run_fingerprint="0" * 64,
                decision="acknowledge",
                note="Reviewed against expected operating change.",
            ),
            actor="tier-two",
        )
    decided = store.decide_review(
        reviews[0]["id"],
        TimeSeriesReviewDecision(
            expected_run_fingerprint=reviews[0]["run_fingerprint"],
            decision="acknowledge",
            note="Reviewed against expected operating change.",
        ),
        actor="tier-two",
    )
    assert decided["state"] == "acknowledged"
    assert decided["reviewed_by"] == "tier-two"


@pytest.mark.asyncio
async def test_manual_shadow_run_streams_durable_worker_progress(tmp_path):
    store = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    schedule = store.create(schedule_value(), actor="tier-two")
    service = TimeSeriesScheduleService(
        store,
        FakeForecast(decision="stable"),
        AuditStore(tmp_path / "audit.db"),
        lambda _owner: (True, ""),
        poll_seconds=0.01,
    )
    progress = []

    async def collect(event):
        progress.append(event)

    await service.start()
    try:
        result = await service.run_now(schedule["id"], collect)
    finally:
        await service.stop()

    assert result["attempt"]["status"] == "complete"
    assert result["review"] is None
    assert [item["phase"] for item in progress] == [
        "schedule:queued",
        "schedule:preflight",
        "forecast:splunk",
        "schedule:complete",
    ]
    assert progress[-1]["progress"] == 100


@pytest.mark.asyncio
async def test_stable_shadow_execution_does_not_create_review_noise(tmp_path):
    store = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    schedule = store.create(schedule_value(), actor="tier-two")
    attempt = store.enqueue(schedule["id"], trigger="manual")
    service = TimeSeriesScheduleService(
        store,
        FakeForecast(decision="stable"),
        AuditStore(tmp_path / "audit.db"),
        lambda _owner: (True, ""),
    )

    await service._execute(attempt["id"])

    assert store.attempt(attempt["id"])["status"] == "complete"
    assert store.reviews() == []


@pytest.mark.asyncio
async def test_shadow_execution_revalidates_owner_and_builds_secondary_client(tmp_path):
    store = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    binding = {
        "alias": "soc-west",
        "fingerprint": "b" * 64,
        "tenant_scope_id": "tenant-west",
    }
    schedule = store.create(schedule_value(), actor="tier-two", binding=binding)
    attempt = store.enqueue(schedule["id"], trigger="manual")
    captured = {}

    class ScopedForecast(FakeForecast):
        async def run(
            self,
            request,
            progress,
            *,
            actor,
            seasonal_comparison=True,
            splunk_client=None,
            binding=None,
        ):
            captured["binding"] = binding
            captured["splunk_client"] = splunk_client
            return await super().run(
                request,
                progress,
                actor=actor,
                seasonal_comparison=seasonal_comparison,
            )

    def authorize(owner, alias):
        captured["authorization"] = (owner, alias)
        return True, ""

    def splunk_factory(target):
        captured["factory_binding"] = target
        return {"client": target["alias"]}

    service = TimeSeriesScheduleService(
        store,
        ScopedForecast(decision="stable"),
        AuditStore(tmp_path / "audit.db"),
        authorize,
        splunk_factory=splunk_factory,
    )

    await service._execute(attempt["id"])

    assert store.attempt(attempt["id"])["status"] == "complete"
    assert captured["authorization"] == ("tier-two", "soc-west")
    assert captured["factory_binding"] == binding
    assert captured["binding"] == binding
    assert captured["splunk_client"] == {"client": "soc-west"}


@pytest.mark.asyncio
async def test_shadow_preflight_denies_deprovisioned_owner_before_forecast(tmp_path):
    store = TimeSeriesScheduleStore(tmp_path / "schedules.db")
    schedule = store.create(schedule_value(), actor="former-analyst")
    attempt = store.enqueue(schedule["id"], trigger="manual")
    forecast = FakeForecast()
    service = TimeSeriesScheduleService(
        store,
        forecast,
        AuditStore(tmp_path / "audit.db"),
        lambda _owner: (False, "Owner no longer has Primary Splunk access."),
    )

    await service._execute(attempt["id"])

    failed = store.attempt(attempt["id"])
    assert failed["status"] == "error"
    assert "Primary Splunk" in failed["error"]
    assert forecast.calls == []
