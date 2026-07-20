from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta

import pytest

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.forecasting import TimeSeriesForecastService
from splunk_security_agent.forecasting.provider import CiscoTimeSeriesProvider
from splunk_security_agent.schemas import (
    TimeSeriesForecastRequest,
    TimeSeriesRuntimeUpdate,
)


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
    assert (
        CiscoTimeSeriesProvider.network_scope("http://127.0.0.1:8080")
        == "loopback"
    )
    assert (
        CiscoTimeSeriesProvider.network_scope("https://8.8.8.8")
        == "public-network"
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )
    assert (
        CiscoTimeSeriesProvider.network_scope("https://forecast.example")
        == "public-network"
    )


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

    result = await service.run(
        request(row_limit=100, horizon=8, backtest_points=8)
    )

    assert result["status"] == "blocked-data-quality"
    assert result["series"]["imputation_ratio"] > 0.30
    assert result["promotion_gate"]["decision"] == "blocked"
    assert model.calls == []


def test_forecast_contract_rejects_non_timechart_and_irregular_buckets(tmp_path):
    service = TimeSeriesForecastService(ConfigStore(tmp_path), lambda: FakeSplunk([]))
    with pytest.raises(ValueError, match="timechart"):
        service.validate_contract(
            request(spl="index=security | stats count as value")
        )
    with pytest.raises(ValueError, match="Selected interval"):
        service.validate_contract(
            request(spl="index=security | timechart span=10m count as value")
        )

    source = rows(30)
    source[8]["_time"] = (
        datetime(2026, 7, 1, tzinfo=UTC) + timedelta(seconds=8 * 300 + 90)
    ).isoformat()
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
