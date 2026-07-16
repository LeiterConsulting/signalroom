from __future__ import annotations

from typing import Any

import pytest

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.splunk_models import SplunkModelInventoryService


class FakeSplunkClient:
    def __init__(self, rows: list[dict[str, Any]]):
        self.rows = rows
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, name: str, arguments: dict[str, Any]):
        self.calls.append((name, arguments))
        return self.rows


class FakeResponse:
    def __init__(self, models: list[str]):
        self.models = models

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"models": [{"name": name} for name in self.models]}


class FakeHTTPClient:
    models: list[str] = []

    def __init__(self, *args: Any, **kwargs: Any):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any):
        return None

    async def get(self, url: str) -> FakeResponse:
        assert url.endswith("/api/tags")
        return FakeResponse(self.models)


def model_row(name: str, backing_model: str, prompt: str = "Hello") -> dict[str, Any]:
    return {
        "name": name,
        "type": "MLTKContainer",
        "owner": "analyst",
        "app": "mltk-container",
        "sharing": "global",
        "options": (
            '{"algo_name":"MLTKContainer","params":'
            f'{{"llm_service":"ollama","model_name":"{backing_model}",'
            f'"prompt":"{prompt}"}}}}'
        ),
    }


@pytest.mark.asyncio
async def test_mltk_scan_is_read_only_and_tracks_definition_drift(monkeypatch, tmp_path):
    FakeHTTPClient.models = ["llama3.2:1b"]
    monkeypatch.setattr("splunk_security_agent.splunk_models.httpx.AsyncClient", FakeHTTPClient)
    client = FakeSplunkClient(
        [
            model_row("ollama_model_manager", "llama3.2:1b"),
            model_row("ollama_text_processing", "llama3.2:1b"),
        ]
    )
    service = SplunkModelInventoryService(ConfigStore(tmp_path), client)

    first = await service.scan()

    assert first["summary"] == {
        "observed": 2,
        "new": 2,
        "changed": 0,
        "unchanged": 0,
        "missing": 0,
        "ollama_dependencies": 2,
        "dependencies_not_observed": 0,
    }
    assert all(item["dependency"]["observation"] == "observed" for item in first["models"])
    assert client.calls == [
        (
            "run_query",
            {
                "query": "| listmodels | head 500",
                "earliest_time": "-1h",
                "latest_time": "now",
                "row_limit": 500,
            },
        )
    ]
    assert first["collection"]["writes_performed"] == 0

    client.rows = [model_row("ollama_model_manager", "llama3.2:1b", prompt="Review")]
    second = await service.scan()

    assert second["summary"]["changed"] == 1
    assert second["summary"]["missing"] == 1
    assert {item["status"] for item in second["models"]} == {"changed", "missing"}

    third = await service.scan()

    assert third["summary"]["unchanged"] == 1
    assert third["summary"]["missing"] == 1
    assert len(third["models"]) == 2


@pytest.mark.asyncio
async def test_mltk_dependency_mismatch_is_endpoint_scoped(monkeypatch, tmp_path):
    FakeHTTPClient.models = ["foundation-sec:latest"]
    monkeypatch.setattr("splunk_security_agent.splunk_models.httpx.AsyncClient", FakeHTTPClient)
    service = SplunkModelInventoryService(
        ConfigStore(tmp_path),
        FakeSplunkClient([model_row("ollama_text_processing", "llama3.2:1b")]),
    )

    result = await service.scan()
    dependency = result["models"][0]["dependency"]

    assert dependency["observation"] == "not-observed"
    assert result["summary"]["dependencies_not_observed"] == 1
    assert "only SignalRoom's configured Ollama endpoint" in dependency["caveat"]
    assert "not model accuracy" in result["freshness_contract"]


def test_mltk_options_accept_structured_and_invalid_values():
    assert SplunkModelInventoryService._options({"algo_name": "StateSpaceForecast"}) == {
        "algo_name": "StateSpaceForecast"
    }
    assert SplunkModelInventoryService._options("not-json") == {"raw": "not-json"}
