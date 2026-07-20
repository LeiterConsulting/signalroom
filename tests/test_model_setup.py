from __future__ import annotations

import json
import sys
import types
from typing import Any

import httpx
import pytest

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.model_setup import (
    ModelSetupService,
    _huggingface_repo,
    _model_installed,
)
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import ArtifactCreate


class FakeResponse:
    def __init__(self, payload: dict[str, Any]):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeClient:
    last_instance = None

    def __init__(self, *args: Any, **kwargs: Any):
        self.loaded = ["llama3.1:8b"]
        self.posts = []
        FakeClient.last_instance = self

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        if url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": "llama3.1:8b"}]})
        if url.endswith("/api/version"):
            return FakeResponse({"version": "0.12.0"})
        if url.endswith("/api/ps"):
            return FakeResponse({"models": [{"name": name} for name in self.loaded]})
        raise AssertionError(f"Unexpected URL: {url}")

    async def post(self, url: str, json: dict[str, Any], **kwargs: Any) -> FakeResponse:
        self.posts.append((url, json))
        model = json["model"]
        if json.get("keep_alive") == 0:
            self.loaded = [name for name in self.loaded if name != model]
        elif model not in self.loaded:
            self.loaded.append(model)
        return FakeResponse({"model": model, "done": True})


def test_model_installed_accepts_implicit_latest_only():
    assert _model_installed("llama3.2", ["llama3.2:latest"])
    assert _model_installed("LLAMA3.1:8B", ["llama3.1:8b"])
    assert not _model_installed("llama3.1:70b", ["llama3.1:8b"])


@pytest.mark.asyncio
async def test_readiness_reports_each_ollama_profile(monkeypatch, tmp_path):
    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", FakeClient)
    result = await ModelSetupService(ConfigStore(tmp_path)).readiness()

    assert result["ollama"]["ok"] is True
    assert result["ollama"]["version"] == "0.12.0"
    profiles = {profile["id"]: profile for profile in result["ollama"]["profiles"]}
    assert profiles["ollama-general"]["installed"] is True
    assert profiles["ollama-general"]["loaded"] is True
    assert profiles["foundation-sec"]["installed"] is False
    assert result["huggingface"]["token_configured"] is False
    assert result["local_transformers"]["selected"] is True
    assert result["huggingface"]["selected"] is False
    assert {profile["id"] for profile in result["local_transformers"]["profiles"]} == {
        "securebert-embed",
        "securebert-ner",
        "securebert-rerank",
        "securebert-code-vulnerability",
    }


@pytest.mark.asyncio
async def test_readiness_reports_offline_ollama_profiles_without_crashing(
    monkeypatch, tmp_path
):
    class OfflineClient(FakeClient):
        async def get(self, url: str, **kwargs: Any) -> FakeResponse:
            raise httpx.ConnectError(f"Offline: {url}")

    monkeypatch.setattr(
        "splunk_security_agent.model_setup.httpx.AsyncClient", OfflineClient
    )
    result = await ModelSetupService(ConfigStore(tmp_path)).readiness()

    assert result["ollama"]["ok"] is False
    assert result["ollama"]["models"] == []
    assert result["ollama"]["loaded_models"] == []
    assert all(
        not profile["installed"] and not profile["loaded"]
        for profile in result["ollama"]["profiles"]
    )


def test_huggingface_repo_extracts_explicit_ollama_hub_source():
    assert _huggingface_repo(
        "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M"
    ) == "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF"
    assert _huggingface_repo("llama3.1:8b") == ""


@pytest.mark.asyncio
async def test_update_check_is_read_only_and_does_not_claim_untracked_ollama_is_current(
    monkeypatch, tmp_path
):
    class UpdateClient(FakeClient):
        async def get(self, url: str, **kwargs: Any) -> FakeResponse:
            if url.endswith("/api/tags"):
                return FakeResponse(
                    {
                        "models": [
                            {"name": "llama3.1:8b", "digest": "general-digest"},
                            {
                                "name": (
                                    "hf.co/fdtn-ai/"
                                    "Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M"
                                ),
                                "digest": "security-digest",
                            },
                        ]
                    }
                )
            if url.startswith("https://huggingface.co/api/models/"):
                return FakeResponse(
                    {
                        "sha": "remote-immutable-sha",
                        "lastModified": "2026-07-01T00:00:00Z",
                        "pipeline_tag": "sentence-similarity",
                    }
                )
            return await super().get(url, **kwargs)

    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", UpdateClient)
    service = ModelSetupService(ConfigStore(tmp_path))

    result = await service.check_updates()
    profiles = {item["profile_id"]: item for item in result["profiles"]}

    assert result["downloads_started"] == 0
    assert profiles["ollama-general"]["status"] == "check-unavailable"
    assert profiles["foundation-sec"]["status"] == "untracked"
    assert profiles["securebert-rerank"]["status"] == "not-installed"
    candidate_sources = {
        item["candidate_id"]: item for item in result["candidate_sources"]
    }
    assert candidate_sources["cisco-time-series-1"]["status"] == "source-observed"
    assert FakeClient.last_instance.posts == []


def test_candidate_catalog_distinguishes_bounded_admitted_capabilities(tmp_path):
    catalog = ModelSetupService(ConfigStore(tmp_path)).catalog()
    candidates = {item["id"]: item for item in catalog["evaluated_candidates"]}

    code = candidates["securebert-code-vulnerability"]
    assert code["configured"] is True
    assert code["automatic_use"] is False
    assert {gate["status"] for gate in code["admission_gates"]} == {"pass", "blocked"}

    forecast = candidates["cisco-time-series-1"]
    assert forecast["configured"] is False
    assert forecast["status"] == "admitted-preview"
    assert {gate["status"] for gate in forecast["admission_gates"]} == {"pass"}
    assert any(
        gate["name"] == "Backtest and promotion gate"
        for gate in forecast["admission_gates"]
    )
    assert any(
        gate["name"] == "Durable experiment and alert-draft boundary"
        for gate in forecast["admission_gates"]
    )


@pytest.mark.asyncio
async def test_code_screen_rejects_splunk_text_before_model_load(tmp_path):
    service = ModelSetupService(ConfigStore(tmp_path))

    with pytest.raises(ValueError, match="source-code contract"):
        await service.screen_code_vulnerability(
            "index=main sourcetype=syslog | stats count by host", "python"
        )


@pytest.mark.asyncio
async def test_code_screen_is_local_bounded_and_does_not_return_source(
    monkeypatch, tmp_path
):
    class FakeCodeProvider:
        def __init__(self, profile, model_path):
            assert profile.id == "securebert-code-vulnerability"
            assert model_path.name == "securebert-code-vulnerability"

        async def health(self):
            return {"ok": True, "network_inference": False}

        async def classify(self, code):
            assert "strcpy" in code
            return {
                "predictions": [
                    {"class_id": 1, "label": "LABEL_1", "score": 0.91},
                    {"class_id": 0, "label": "LABEL_0", "score": 0.09},
                ],
                "input_tokens": 48,
                "evaluated_tokens": 48,
                "token_limit": 1024,
                "truncated": False,
            }

    monkeypatch.setattr(
        "splunk_security_agent.model_setup.LocalTransformersProvider",
        FakeCodeProvider,
    )
    result = await ModelSetupService(ConfigStore(tmp_path)).screen_code_vulnerability(
        "#include <string.h>\nint copy(char *dst, char *src) { strcpy(dst, src); return 0; }",
        "c",
    )

    assert result["prediction"]["signal"] == "potential-vulnerability-review"
    assert result["network_inference"] is False
    assert result["contract"]["source_persisted"] is False
    assert result["contract"]["finding"] is False
    assert "code" not in result
    assert len(result["input_sha256"]) == 64


def test_pull_accepts_securebert_as_local_transformers_install(monkeypatch, tmp_path):
    service = ModelSetupService(ConfigStore(tmp_path))

    def capture(coroutine):
        coroutine.close()
        return None

    monkeypatch.setattr("splunk_security_agent.model_setup.asyncio.create_task", capture)
    job = service.start_pull("securebert-ner")

    assert job["kind"] == "local-transformers"
    assert job["endpoint"] == "huggingface-hub"
    assert job["path"].endswith("models\\securebert-ner") or job["path"].endswith(
        "models/securebert-ner"
    )


@pytest.mark.asyncio
async def test_local_install_records_immutable_revision_and_manifest(monkeypatch, tmp_path):
    config = ConfigStore(tmp_path / "data")
    service = ModelSetupService(config)
    fake_hub = types.ModuleType("huggingface_hub")

    class FakeInfo:
        sha = "abc123immutable"

    class FakeApi:
        def __init__(self, token=None):
            self.token = token

        def model_info(self, model):
            assert model == "cisco-ai/SecureBERT2.0-NER"
            return FakeInfo()

    def fake_snapshot_download(**kwargs):
        assert kwargs["revision"] == "abc123immutable"
        path = kwargs["local_dir"]
        (path / "config.json").write_text("{}", encoding="utf-8")
        (path / "model.safetensors").write_bytes(b"synthetic safe weights")
        return str(path)

    fake_hub.HfApi = FakeApi
    fake_hub.snapshot_download = fake_snapshot_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
    monkeypatch.setattr("splunk_security_agent.model_setup.local_runtime_available", lambda: True)
    original_sleep = __import__("asyncio").sleep

    async def fast_sleep(_seconds):
        await original_sleep(0)

    monkeypatch.setattr("splunk_security_agent.model_setup.asyncio.sleep", fast_sleep)
    job = {
        "profile_id": "securebert-ner",
        "model": "cisco-ai/SecureBERT2.0-NER",
        "status": "queued",
        "detail": "Queued",
        "progress": 0,
    }

    await service._install_local_specialist(job)

    manifest = json.loads(
        (config.local_model_path("securebert-ner") / ".signalroom-model.json").read_text(
            encoding="utf-8"
        )
    )
    assert job["status"] == "complete"
    assert job["progress"] == 100
    assert manifest["revision"] == "abc123immutable"
    assert manifest["runtime"] == "local-transformers"


@pytest.mark.asyncio
async def test_embedding_install_backfills_local_context_index(monkeypatch, tmp_path):
    config = ConfigStore(tmp_path / "data")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    evidence.add(
        ArtifactCreate(
            title="Endpoint response",
            content="Validate process and network evidence before containment.",
            kind="runbook",
        )
    )

    class FakeLocalProvider:
        def __init__(self, profile, model_path):
            assert profile.id == "securebert-embed"
            assert model_path == config.local_model_path(profile.id)

        async def document_embeddings(self, texts):
            return [[1.0, float(index)] for index, _text in enumerate(texts)]

    monkeypatch.setattr(
        "splunk_security_agent.model_setup.LocalTransformersProvider",
        FakeLocalProvider,
    )
    service = ModelSetupService(config, evidence)
    profile = next(
        item for item in config.load().models if item.id == "securebert-embed"
    )
    job = {}

    status = await service._backfill_embeddings(profile, job)

    assert status == {"total_chunks": 1, "indexed_chunks": 1, "pending_chunks": 0}
    assert job["indexed_chunks"] == 1
    assert job["context_chunks"] == 1
    assert evidence.semantic_search([1.0, 0.0], profile.id)[0].title == "Endpoint response"


@pytest.mark.asyncio
async def test_activate_swaps_configured_ollama_profiles(monkeypatch, tmp_path):
    class BothModelsClient(FakeClient):
        async def get(self, url: str, **kwargs: Any) -> FakeResponse:
            if url.endswith("/api/tags"):
                return FakeResponse(
                    {
                        "models": [
                            {"name": "llama3.1:8b"},
                            {
                                "name": (
                                    "hf.co/fdtn-ai/"
                                    "Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M"
                                )
                            },
                        ]
                    }
                )
            return await super().get(url, **kwargs)

    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", BothModelsClient)
    result = await ModelSetupService(ConfigStore(tmp_path)).activate("foundation-sec")

    assert result["ok"] is True
    assert result["executed_model"].startswith("hf.co/fdtn-ai/Foundation-Sec")
    assert result["unloaded_models"] == ["llama3.1:8b"]
    assert result["loaded_models"] == [result["executed_model"]]


@pytest.mark.asyncio
async def test_activate_fails_before_ollama_when_model_trust_blocks(tmp_path):
    class BlockingTrust:
        async def require_profile(self, profile_id, purpose):
            raise PermissionError(f"blocked {purpose} for {profile_id}")

    service = ModelSetupService(
        ConfigStore(tmp_path), model_trust=BlockingTrust()
    )
    with pytest.raises(PermissionError, match="blocked model activation"):
        await service.activate("foundation-sec")
