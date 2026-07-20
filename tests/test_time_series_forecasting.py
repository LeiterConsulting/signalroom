from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta

import pytest

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.forecasting import (
    TimeSeriesExperimentStore,
    TimeSeriesForecastService,
)
from splunk_security_agent.forecasting.provider import CiscoTimeSeriesProvider
from splunk_security_agent.schemas import (
    TimeSeriesAlertCandidateCreate,
    TimeSeriesForecastRequest,
    TimeSeriesRuntimeUpdate,
)
from splunk_security_agent.validation import ValidationStore


class FakeSplunk:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def call(self, name, arguments):
        self.calls.append((name, arguments))
        return {"results": self.rows}


class FakeProvider:
    endpoint = "http://127.0.0.1:8080"

    def __init__(self):
        self.calls = []

    async def health(self):
        return {
            "ok": True,
            "network_scope": "loopback",
            "service": "signalroom-cisco-tsm",
            "model_repo": "cisco-ai/cisco-time-series-model-1.0",
            "model_revision": "038831104abace772bd50bffe76da0c77c364c51",
            "inference_backend": "cpu",
        }

    async def forecast(self, values, horizon, *, request_id=None):
        self.calls.append((list(values), horizon, request_id))
        mean = [values[-1] + index + 1 for index in range(horizon)]
        return {
            "request_id": request_id,
            "model": "CDTSM",
            "mean": mean,
            "quantiles": {
                "p10": [value - 1 for value in mean],
                "p50": mean,
                "p90": [value + 1 for value in mean],
            },
            "context": {"coarse_points": 1, "fine_points": min(512, len(values))},
            "network_scope": "loopback",
        }


def rows(count: int, *, interval: int = 300):
    start = datetime(2026, 7, 1, tzinfo=UTC)
    return [
        {
            "_time": (start + timedelta(seconds=index * interval)).isoformat(),
            "value": index,
        }
        for index in range(count)
    ]


def request(**updates):
    values = {
        "title": "Authentication event-rate forecast",
        "spl": "index=security | timechart span=5m count as value",
        "earliest_time": "-7d",
        "latest_time": "now",
        "row_limit": 200,
        "interval_seconds": 300,
        "horizon": 12,
        "backtest_points": 12,
    }
    values.update(updates)
    return TimeSeriesForecastRequest(**values)


def test_provider_builds_aligned_multiresolution_context_and_blocks_public_service(
    monkeypatch,
):
    values = [float(index) for index in range(130)]
    coarse, fine = CiscoTimeSeriesProvider._contexts(values)

    assert coarse == [39.5, 99.5]
    assert fine == values
    assert CiscoTimeSeriesProvider.network_scope("http://127.0.0.1:8080") == "loopback"
    assert CiscoTimeSeriesProvider.network_scope("https://8.8.8.8") == "public-network"
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    assert CiscoTimeSeriesProvider.network_scope("https://forecast.example") == "public-network"


@pytest.mark.asyncio
async def test_forecast_runs_exact_read_only_series_backtest_and_promotion_gate(tmp_path):
    splunk = FakeSplunk(rows(96))
    model = FakeProvider()
    service = TimeSeriesForecastService(ConfigStore(tmp_path), lambda: splunk)
    service.provider = lambda: model
    progress = []

    async def collect(event):
        progress.append(event)

    result = await service.run(request(), collect)

    assert result["status"] == "complete"
    assert result["promotion_gate"]["ready"] is True
    assert result["backtest"]["mase_vs_last_value"] == 0
    assert result["forecast"]["horizon"] == 12
    assert result["runtime"]["network_inference"] is False
    assert result["contract"]["automatic_alerting"] is False
    assert len(model.calls) == 2
    assert [item["phase"] for item in progress] == [
        "forecast:runtime",
        "forecast:guardrail",
        "forecast:splunk",
        "forecast:prepare",
        "forecast:backtest",
        "forecast:forecast",
        "forecast:gate",
    ]
    assert splunk.calls[0][0] == "run_query"
    assert splunk.calls[0][1]["query"] == request().spl


@pytest.mark.asyncio
async def test_forecast_stops_before_model_when_imputation_exceeds_publisher_limit(tmp_path):
    source = rows(21)
    sparse = [source[0], source[10], source[20]]
    splunk = FakeSplunk(sparse)
    model = FakeProvider()
    service = TimeSeriesForecastService(ConfigStore(tmp_path), lambda: splunk)
    service.provider = lambda: model

    result = await service.run(request(row_limit=100, horizon=8, backtest_points=8))

    assert result["status"] == "blocked-data-quality"
    assert result["series"]["imputation_ratio"] > 0.30
    assert result["promotion_gate"]["decision"] == "blocked"
    assert model.calls == []


def test_forecast_contract_rejects_non_timechart_and_irregular_buckets(tmp_path):
    service = TimeSeriesForecastService(ConfigStore(tmp_path), lambda: FakeSplunk([]))
    with pytest.raises(ValueError, match="timechart"):
        service.validate_contract(request(spl="index=security | stats count as value"))
    with pytest.raises(ValueError, match="Selected interval"):
        service.validate_contract(request(spl="index=security | timechart span=10m count as value"))

    source = rows(30)
    source[8]["_time"] = (datetime(2026, 7, 1, tzinfo=UTC) + timedelta(seconds=8 * 300 + 90)).isoformat()
    with pytest.raises(ValueError, match="not regular"):
        service.prepare_series(source, request())


def test_bundled_runtime_port_probe_does_not_claim_an_occupied_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        assert TimeSeriesForecastService._port_available(port) is False


@pytest.mark.asyncio
async def test_runtime_configuration_refuses_public_inference_endpoint(tmp_path):
    service = TimeSeriesForecastService(ConfigStore(tmp_path), lambda: FakeSplunk([]))

    with pytest.raises(ValueError, match="Public"):
        await service.configure(
            TimeSeriesRuntimeUpdate(
                endpoint="https://8.8.8.8",
                token="secret",
            )
        )


@pytest.mark.asyncio
async def test_forecast_registry_accepts_exact_baseline_and_tracks_drift(tmp_path):
    splunk = FakeSplunk(rows(96))
    model = FakeProvider()
    experiments = TimeSeriesExperimentStore(tmp_path / "experiments.db")
    service = TimeSeriesForecastService(
        ConfigStore(tmp_path / "config"),
        lambda: splunk,
        experiment_store=experiments,
    )
    service.provider = lambda: model

    first = await service.run(request(), actor="forecast-analyst")

    assert first["contract"]["experiment_persisted"] is True
    assert first["experiment"]["comparison"]["decision"] == "no-baseline"
    stored = experiments.get(first["run_id"])
    assert stored is not None
    assert "values" not in stored["series"]
    with pytest.raises(ValueError, match="fingerprint"):
        service.accept_baseline(
            first["run_id"],
            expected_fingerprint="0" * 64,
            actor="forecast-analyst",
            review_note="Known representative week",
        )

    baseline = service.accept_baseline(
        first["run_id"],
        expected_fingerprint=first["experiment"]["run_fingerprint"],
        actor="forecast-analyst",
        review_note="Known representative week",
    )
    assert baseline["is_baseline"] is True
    assert baseline["baseline_accepted_by"] == "forecast-analyst"

    for item in splunk.rows:
        item["value"] = float(item["value"]) + 100
    drifted = await service.run(
        request(earliest_time="-14d"),
        actor="forecast-analyst",
    )

    assert drifted["experiment"]["series_key"] == first["experiment"]["series_key"]
    assert drifted["experiment"]["comparison"]["decision"] == "material-drift"
    assert drifted["experiment"]["comparison"]["metrics"]["window_changed"] is True
    assert drifted["experiment"]["comparison"]["metrics"]["series_mean_change_percent"] > 50
    overview = service.experiments()
    assert len(overview["runs"]) == 2
    assert overview["series"][0]["baseline_run_id"] == first["run_id"]
    assert overview["contract"]["source_rows_persisted"] is False


@pytest.mark.asyncio
async def test_forecast_baselines_are_isolated_by_splunk_identity_revision(tmp_path):
    splunk = FakeSplunk(rows(96))
    model = FakeProvider()
    experiments = TimeSeriesExperimentStore(tmp_path / "experiments.db")
    service = TimeSeriesForecastService(
        ConfigStore(tmp_path / "config"),
        lambda: splunk,
        experiment_store=experiments,
    )
    service.provider = lambda: model
    east = {
        "alias": "soc-east",
        "fingerprint": "a" * 64,
        "tenant_scope_id": "tenant-east",
    }
    west = {
        "alias": "soc-west",
        "fingerprint": "b" * 64,
        "tenant_scope_id": "tenant-west",
    }

    first = await service.run(request(), actor="analyst", binding=east)
    service.accept_baseline(
        first["run_id"],
        expected_fingerprint=first["experiment"]["run_fingerprint"],
        actor="analyst",
        review_note="Representative east-coast series",
    )
    second = await service.run(request(), actor="analyst", binding=west)

    assert first["source"]["connection_alias"] == "soc-east"
    assert second["source"]["connection_alias"] == "soc-west"
    assert first["experiment"]["series_key"] != second["experiment"]["series_key"]
    assert second["experiment"]["comparison"]["decision"] == "no-baseline"


@pytest.mark.asyncio
async def test_forecast_prefers_matching_weekday_baseline_and_retains_general_reference(
    tmp_path,
):
    splunk = FakeSplunk(rows(96))
    model = FakeProvider()
    experiments = TimeSeriesExperimentStore(tmp_path / "experiments.db")
    service = TimeSeriesForecastService(
        ConfigStore(tmp_path / "config"),
        lambda: splunk,
        experiment_store=experiments,
    )
    service.provider = lambda: model

    general = await service.run(request(), actor="forecast-analyst")
    service.accept_baseline(
        general["run_id"],
        expected_fingerprint=general["experiment"]["run_fingerprint"],
        actor="forecast-analyst",
        review_note="Representative cross-week reference",
    )
    weekday = await service.run(request(), actor="forecast-analyst")
    accepted = service.accept_baseline(
        weekday["run_id"],
        expected_fingerprint=weekday["experiment"]["run_fingerprint"],
        actor="forecast-analyst",
        review_note="Representative matching weekday",
        baseline_scope="matching-weekday",
    )
    seasonal_slot = experiments.seasonal_slot(accepted["result"])
    assert accepted["baseline_slots"] == [seasonal_slot]

    compared = await service.run(request(), actor="forecast-analyst")
    comparison = compared["experiment"]["comparison"]

    assert comparison["selected_slot"] == seasonal_slot
    assert comparison["seasonal_comparison"] is True
    assert {item["slot"] for item in comparison["references"]} == {
        "general",
        seasonal_slot,
    }
    assert "matching-weekday" not in comparison["selection_reason"]
    assert experiments.baseline(general["experiment"]["series_key"])["id"] == general["run_id"]


@pytest.mark.asyncio
async def test_reviewed_forecast_handoff_creates_draft_not_alert(tmp_path):
    splunk = FakeSplunk(rows(96))
    model = FakeProvider()
    experiments = TimeSeriesExperimentStore(tmp_path / "experiments.db")
    validations = ValidationStore(tmp_path / "validations.db")
    service = TimeSeriesForecastService(
        ConfigStore(tmp_path / "config"),
        lambda: splunk,
        experiment_store=experiments,
        validations=validations,
    )
    service.provider = lambda: model
    result = await service.run(request(), actor="tier-two")

    value = TimeSeriesAlertCandidateCreate(
        expected_run_fingerprint=result["experiment"]["run_fingerprint"],
        title="Review elevated authentication volume",
        rationale="Measure how often the accepted upper boundary would trigger.",
        direction="above",
    )
    with pytest.raises(ValueError, match="baseline"):
        service.create_alert_candidate(result["run_id"], value, actor="tier-two")
    assert validations.list() == []

    service.accept_baseline(
        result["run_id"],
        expected_fingerprint=result["experiment"]["run_fingerprint"],
        actor="tier-two",
        review_note="Representative source quality and backtest",
    )
    handoff = service.create_alert_candidate(
        result["run_id"],
        value,
        actor="tier-two",
    )

    assert handoff["contract"] == {
        "splunk_executed": False,
        "alert_created": False,
        "validation_status": "draft",
        "separate_approval_required": True,
    }
    assert handoff["reused"] is False
    assert handoff["candidate"]["threshold_source"] == "maximum forecast p90"
    assert "| where value >" in handoff["candidate"]["proposed_spl"]
    validation = validations.get(handoff["candidate"]["validation_task_id"])
    assert validation is not None
    assert validation.status == "draft"
    assert validation.source_run_id == f"forecast:{result['run_id']}"
    assert experiments.list_alert_candidates()[0]["id"] == handoff["candidate"]["id"]
    repeated = service.create_alert_candidate(
        result["run_id"],
        value,
        actor="tier-two",
    )
    assert repeated["reused"] is True
    assert len(validations.list()) == 1
