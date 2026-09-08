from __future__ import annotations

import json
import os
import sys
import types
from typing import Any

import httpx
import pytest

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.model_setup import (
    ModelSetupService,
    _candidate_runtime_installed,
    _huggingface_repo,
    _model_installed,
    _next_local_install_strategy,
    _safe_setup_detail,
    _setup_failure,
    _should_retry_public_source,
)
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import ArtifactCreate


class FakeResponse:
    def __init__(self, payload: Any):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
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


def test_setup_diagnostics_redact_secrets_and_classify_macos_architecture():
    detail = _safe_setup_detail(
        "Authorization: Bearer secret-value\ntoken=another-secret\n"
        "https://private-user:private-pass@packages.example/simple\n"
        "No matching distribution found"
    )
    failure = _setup_failure(
        "local-transformers",
        "runtime-install",
        detail,
        {
            "system": "Darwin",
            "machine": "x86_64",
            "apple_silicon": True,
            "architecture_ok": False,
        },
    )

    assert "secret-value" not in detail
    assert "another-secret" not in detail
    assert "private-user" not in detail
    assert "private-pass" not in detail
    assert detail.count("[REDACTED]") == 3
    assert failure["code"] == "macos-rosetta-python"
    assert any(action.get("command") == "./install.sh" for action in failure["actions"])


def test_public_source_retry_is_limited_to_resolution_failures():
    assert _should_retry_public_source(
        "ERROR: Could not find a version that satisfies the requirement torch"
    )
    assert _should_retry_public_source("401 Client Error: Unauthorized")
    assert not _should_retry_public_source(
        "No matching distribution found",
        elapsed_seconds=46,
    )
    assert not _should_retry_public_source("CERTIFICATE_VERIFY_FAILED")
    assert not _should_retry_public_source("No space left on device")

    ollama_failure = _setup_failure(
        "ollama",
        "model-validation",
        "Ollama returned no assistant content",
        {
            "system": "Darwin",
            "apple_silicon": True,
            "architecture_ok": False,
        },
    )
    assert ollama_failure["code"] == "ollama-inference-failed"


def test_ollama_digest_mismatch_is_classified_with_integrity_evidence():
    expected = "a" * 64
    observed = "b" * 64
    failure = _setup_failure(
        "ollama",
        "ollama-download",
        (
            "digest mismatch, file must be downloaded again: "
            f"want sha256:{expected}, got sha256:{observed}"
        ),
        {
            "system": "Darwin",
            "apple_silicon": True,
            "architecture_ok": False,
        },
    )

    assert failure["code"] == "ollama-digest-mismatch"
    assert failure["integrity"] == {
        "expected_sha256": expected,
        "observed_sha256": observed,
    }
    assert failure["actions"][0]["title"] == "Retry this model download"
    assert all("clear the entire" not in item["title"].lower() for item in failure["actions"])


def test_ollama_digest_mismatch_without_hashes_is_still_classified():
    failure = _setup_failure(
        "ollama",
        "ollama-download",
        "SHA256 mismatch while verifying the downloaded layer",
        {"system": "Linux", "architecture_ok": True},
    )

    assert failure["code"] == "ollama-digest-mismatch"
    assert "integrity" not in failure


def test_local_install_retry_strategy_changes_with_failure_and_prior_attempts():
    assert _next_local_install_strategy("tls-trust", ["auto"]) == "direct-http"
    assert _next_local_install_strategy("model-artifact-invalid", ["auto"]) == (
        "clean-download"
    )
    assert _next_local_install_strategy(
        "network",
        ["auto", "direct-http", "clean-download"],
    ) == "public-only"


def test_macos_tls_failure_distinguishes_native_keychain_from_missing_runtime_support():
    native_failure = _setup_failure(
        "local-transformers",
        "model-download",
        "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate",
        {
            "system": "Darwin",
            "architecture_ok": True,
            "outbound_tls_trust": {"active": True, "mode": "native-system"},
        },
    )
    fallback_failure = _setup_failure(
        "local-transformers",
        "model-download",
        "SSL certificate verify failed",
        {
            "system": "Darwin",
            "architecture_ok": True,
            "outbound_tls_trust": {"active": False, "mode": "python-default"},
        },
    )

    assert native_failure["code"] == "tls-trust"
    assert native_failure["actions"][0]["title"] == (
        "Repair the certificate chain in macOS Keychain"
    )
    assert fallback_failure["actions"][0]["command"] == "./install.sh --restart"
    assert all("disable certificate" not in item["detail"].lower() for item in native_failure["actions"])
    assert any("Never disable verification" in item["detail"] for item in native_failure["actions"])

    missing_bundle = _setup_failure(
        "local-transformers",
        "model-download",
        "No such file or directory",
        {
            "system": "Darwin",
            "architecture_ok": True,
            "outbound_tls_trust": {
                "active": True,
                "environment_bundle": True,
                "environment_bundle_exists": False,
            },
        },
    )
    assert missing_bundle["code"] == "tls-ca-bundle-missing"


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
async def test_readiness_persists_ollama_digest_retry_and_escalates_repeats(
    monkeypatch, tmp_path
):
    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", FakeClient)
    service = ModelSetupService(ConfigStore(tmp_path))
    for observed in ("b" * 64, "c" * 64):
        service._record_install_outcome(
            {
                "profile_id": "foundation-sec",
                "kind": "ollama",
                "strategy": "auto",
                "status": "error",
                "stage": "ollama-download",
                "failure": {
                    "code": "ollama-digest-mismatch",
                    "summary": "Ollama rejected a downloaded layer",
                    "integrity": {
                        "expected_sha256": "a" * 64,
                        "observed_sha256": observed,
                    },
                },
            }
        )

    result = await service.readiness()
    profile = next(
        item for item in result["ollama"]["profiles"] if item["id"] == "foundation-sec"
    )
    action = profile["install_action"]

    assert action["label"] == "Retry"
    assert action["strategy"] == "auto"
    assert action["integrity_failures"] == 2
    assert "failed 2 times" in action["reason"]
    assert action["previous_failure"]["integrity"]["observed_sha256"] == "c" * 64


@pytest.mark.asyncio
async def test_ollama_pull_digest_failure_returns_retry_action_and_safe_receipt(
    monkeypatch, tmp_path
):
    expected = "a" * 64
    observed = "b" * 64

    class PullErrorStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def raise_for_status(self):
            return None

        async def aiter_lines(self):
            yield json.dumps({"status": "pulling model", "completed": 1, "total": 2})
            yield json.dumps(
                {
                    "error": (
                        "digest mismatch, file must be downloaded again: "
                        f"want sha256:{expected}, got sha256:{observed}"
                    )
                }
            )

    class PullErrorClient(FakeClient):
        def stream(self, method, url, **kwargs):
            assert method == "POST"
            assert url.endswith("/api/pull")
            assert kwargs["json"]["stream"] is True
            return PullErrorStream()

    service = ModelSetupService(ConfigStore(tmp_path))

    def capture(coroutine):
        coroutine.close()
        return None

    monkeypatch.setattr("splunk_security_agent.model_setup.asyncio.create_task", capture)
    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", PullErrorClient)
    job = service.start_pull("foundation-sec")

    await service._pull(job["id"])

    assert job["status"] == "error"
    assert job["stage"] == "ollama-download"
    assert job["failure"]["code"] == "ollama-digest-mismatch"
    assert job["failure"]["integrity"]["expected_sha256"] == expected
    assert job["retry_action"]["label"] == "Retry"
    receipt = service._load_install_history()["profiles"]["foundation-sec"][-1]
    assert receipt["failure_code"] == "ollama-digest-mismatch"
    assert receipt["integrity"]["observed_sha256"] == observed


@pytest.mark.asyncio
async def test_readiness_reports_apple_mps_for_local_transformers(monkeypatch, tmp_path):
    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.local_runtime_available", lambda: True
    )
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.local_transformers_device", lambda: "mps"
    )

    result = await ModelSetupService(ConfigStore(tmp_path)).readiness()

    assert result["local_transformers"]["device"] == "Apple MPS"
    assert result["local_transformers"]["device_id"] == "mps"


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
            if url == "https://huggingface.co/api/models":
                publisher = kwargs["params"]["author"]
                if publisher == "cisco-ai":
                    return FakeResponse(
                        [
                            {
                                "id": "cisco-ai/new-security-model",
                                "sha": "new-model-sha",
                                "lastModified": "2026-09-04T00:00:00Z",
                                "pipeline_tag": "text-classification",
                            }
                        ]
                    )
                return FakeResponse([])
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
    publisher_catalogs = {
        item["publisher"]: item for item in result["publisher_catalogs"]
    }
    assert publisher_catalogs["cisco-ai"]["status"] == "review-required"
    assert [
        item["model"] for item in publisher_catalogs["cisco-ai"]["unreviewed_models"]
    ] == ["cisco-ai/new-security-model"]
    assert FakeClient.last_instance.posts == []


@pytest.mark.asyncio
async def test_publisher_check_detects_revision_change_without_repository_rename(
    monkeypatch, tmp_path
):
    class RevisionClient(FakeClient):
        async def get(self, url: str, **kwargs: Any) -> FakeResponse:
            if url.endswith("/api/tags"):
                return FakeResponse({"models": [{"name": "llama3.1:8b", "digest": "local"}]})
            if url.startswith("https://huggingface.co/api/models/"):
                return FakeResponse(
                    {
                        "sha": "individual-source-sha",
                        "lastModified": "2026-09-05T00:00:00Z",
                        "pipeline_tag": "token-classification",
                    }
                )
            if url == "https://huggingface.co/api/models":
                if kwargs["params"]["author"] == "cisco-ai":
                    return FakeResponse(
                        [
                            {
                                "id": "cisco-ai/SecureBERT2.0-NER",
                                "sha": "changed-with-the-same-repository-id",
                                "lastModified": "2026-09-05T00:00:00Z",
                                "pipeline_tag": "token-classification",
                                "gated": False,
                            }
                        ]
                    )
                return FakeResponse([])
            return await super().get(url, **kwargs)

    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", RevisionClient)
    result = await ModelSetupService(ConfigStore(tmp_path)).check_updates()
    cisco = next(item for item in result["publisher_catalogs"] if item["publisher"] == "cisco-ai")

    assert cisco["status"] == "review-required"
    changed = next(
        item
        for item in cisco["changed_reviewed_models"]
        if item["model"] == "cisco-ai/SecureBERT2.0-NER"
    )
    assert changed["reviewed_revision"] != changed["revision"]
    assert any(item["field"] == "revision" for item in changed["changes"])


@pytest.mark.asyncio
async def test_installed_ollama_model_can_be_staged_and_discarded_without_routing(
    monkeypatch, tmp_path
):
    class CandidateClient(FakeClient):
        async def get(self, url: str, **kwargs: Any) -> FakeResponse:
            if url.endswith("/api/tags"):
                return FakeResponse(
                    {
                        "models": [
                            {"name": "llama3.1:8b", "digest": "baseline"},
                            {"name": "qwen3.5:4b", "digest": "candidate-digest"},
                        ]
                    }
                )
            return await super().get(url, **kwargs)

    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", CandidateClient)
    config = ConfigStore(tmp_path)
    service = ModelSetupService(config)
    before = config.load()

    result = await service.stage_ollama_candidate(
        "qwen3.5:4b", task="chat", label="Qwen evaluation"
    )
    profile = result["profile"]

    assert result["routing_unchanged"] == {
        "default_chat_model": before.default_chat_model,
        "security_reasoning_model": before.security_reasoning_model,
    }
    assert profile["lifecycle"] == "candidate"
    assert profile["model"] == "qwen3.5:4b"
    assert config.load().default_chat_model == before.default_chat_model

    discarded = service.discard_ollama_candidate(profile["id"])
    assert discarded["discarded"] is True
    assert all(item.id != profile["id"] for item in config.load().models)


@pytest.mark.asyncio
async def test_publisher_intake_is_durable_and_never_downloads(monkeypatch, tmp_path):
    service = ModelSetupService(ConfigStore(tmp_path))

    async def metadata(_client, repo):
        return {
            "revision": "immutable-source-revision",
            "last_modified": "2026-09-05T00:00:00Z",
            "pipeline_tag": "text-generation",
            "source_url": f"https://huggingface.co/{repo}",
        }

    monkeypatch.setattr(service, "_hub_metadata", metadata)
    entry = await service.stage_publisher_intake("fdtn-ai/antares-1b")

    assert entry["status"] == "pending-review"
    assert entry["downloads_started"] == 0
    assert service.catalog()["intake_queue"][0]["model"] == "fdtn-ai/antares-1b"

    discarded = service.discard_publisher_intake("fdtn-ai/antares-1b")
    assert discarded["discarded"] is True
    assert service.catalog()["intake_queue"] == []


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

    antares = candidates["antares-vulnerability-localization"]
    assert antares["configured"] is False
    assert antares["runtime_installed"] is False
    assert antares["status"] == "research-candidate"
    assert antares["automatic_use"] is False
    assert {gate["status"] for gate in antares["admission_gates"]} == {
        "pass",
        "blocked",
    }
    assert catalog["publisher_review"]["reviewed_at"] == "2026-09-05"
    assert any(
        finding["label"] == "Cisco Time Series Model"
        and "supersedes" in finding["detail"]
        for finding in catalog["publisher_review"]["findings"]
    )


def test_unknown_candidate_runtime_is_not_mistaken_for_time_series_runtime(monkeypatch):
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.importlib.util.find_spec", lambda _: object()
    )

    assert _candidate_runtime_installed("dedicated-time-series") is True
    assert _candidate_runtime_installed("dedicated-repository-agent") is False


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


def test_pull_accepts_explicit_local_recovery_strategy(monkeypatch, tmp_path):
    service = ModelSetupService(ConfigStore(tmp_path))

    def capture(coroutine):
        coroutine.close()
        return None

    monkeypatch.setattr("splunk_security_agent.model_setup.asyncio.create_task", capture)
    job = service.start_pull("securebert-ner", "direct-http")

    assert job["strategy"] == "direct-http"
    assert "disable the accelerated Xet" in job["strategy_plan"]["change"]


@pytest.mark.asyncio
async def test_readiness_persists_failure_and_offers_different_retry(monkeypatch, tmp_path):
    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.local_runtime_available", lambda: True
    )
    service = ModelSetupService(ConfigStore(tmp_path))
    service._record_install_outcome(
        {
            "profile_id": "securebert-ner",
            "strategy": "auto",
            "status": "error",
            "stage": "model-download",
            "detail": "TLS certificate validation blocked the model download",
            "failure": {
                "code": "tls-trust",
                "summary": "TLS certificate validation blocked the model download",
            },
        }
    )

    result = await service.readiness()
    profile = next(
        item
        for item in result["local_transformers"]["profiles"]
        if item["id"] == "securebert-ner"
    )

    assert profile["install_action"]["label"] == "Retry"
    assert profile["install_action"]["strategy"] == "direct-http"
    assert "Retry changes method" in profile["install_action"]["reason"]
    assert result["local_transformers"]["preflight"].startswith("Host, runtime")


def test_guided_setup_queues_one_profile_for_each_local_runtime(monkeypatch, tmp_path):
    service = ModelSetupService(ConfigStore(tmp_path))

    def capture(coroutine):
        coroutine.close()
        return None

    monkeypatch.setattr("splunk_security_agent.model_setup.asyncio.create_task", capture)
    job = service.start_troubleshooting("ollama-general", "securebert-ner")

    assert job["kind"] == "guided-model-setup"
    assert job["downloads_started"] == 0
    assert [attempt["provider"] for attempt in job["attempts"]] == [
        "ollama",
        "local-transformers",
    ]
    assert "no route" in job["contract"].lower()
    assert any(item["kind"] == "local-fallback" for item in job["alternatives"])


@pytest.mark.asyncio
async def test_guided_setup_checks_second_runtime_after_first_failure(monkeypatch, tmp_path):
    service = ModelSetupService(ConfigStore(tmp_path))

    def capture(coroutine):
        coroutine.close()
        return None

    monkeypatch.setattr("splunk_security_agent.model_setup.asyncio.create_task", capture)
    job = service.start_troubleshooting("ollama-general", "securebert-ner")
    called: list[str] = []

    async def fake_attempt(_job, attempt, _index):
        called.append(attempt["provider"])
        if attempt["provider"] == "ollama":
            raise RuntimeError("connection refused")
        attempt.update(status="complete", stage="complete", detail="Synthetic check passed")

    monkeypatch.setattr(service, "_run_setup_attempt", fake_attempt)
    await service._run_troubleshooting(job["id"])

    assert called == ["ollama", "local-transformers"]
    assert job["attempts"][0]["failure"]["code"] == "network"
    assert job["attempts"][1]["status"] == "complete"
    assert job["status"] == "attention"


@pytest.mark.asyncio
async def test_ollama_smoke_probe_is_synthetic_and_retains_no_output(
    monkeypatch, tmp_path
):
    class ProbeClient(FakeClient):
        async def post(self, url: str, json: dict[str, Any], **kwargs: Any) -> FakeResponse:
            assert url == "http://localhost:11434/api/chat"
            assert json["messages"] == [
                {
                    "role": "user",
                    "content": "Synthetic SignalRoom setup probe. Reply with the single word READY.",
                }
            ]
            assert json["options"] == {"temperature": 0, "num_predict": 8}
            return FakeResponse({"message": {"content": "READY"}, "done": True})

    monkeypatch.setattr("splunk_security_agent.model_setup.httpx.AsyncClient", ProbeClient)
    service = ModelSetupService(ConfigStore(tmp_path))
    profile = next(
        item for item in service.config.load().models if item.id == "ollama-general"
    )

    proof = await service._smoke_ollama_profile(profile)

    assert proof == {
        "runtime": "ollama",
        "capability": "chat",
        "response_received": True,
        "output_retained": False,
    }
    assert "READY" not in proof.values()


@pytest.mark.asyncio
async def test_local_install_records_immutable_revision_and_manifest(monkeypatch, tmp_path):
    config = ConfigStore(tmp_path / "data")
    service = ModelSetupService(config)
    fake_hub = types.ModuleType("huggingface_hub")

    class FakeInfo:
        sha = "abc123immutable"

    class FakeApi:
        def __init__(self, endpoint=None, token=None):
            assert endpoint == "https://huggingface.co"
            assert token is False
            self.endpoint = endpoint
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
    assert job["tls_trust"]["certificate_verification"] is True
    assert manifest["revision"] == "abc123immutable"
    assert manifest["runtime"] == "local-transformers"


@pytest.mark.asyncio
async def test_admitted_public_hub_is_credential_free_on_first_attempt(monkeypatch, tmp_path):
    config = ConfigStore(tmp_path / "data")
    config.update_secrets(huggingface_token="stale-private-token")
    service = ModelSetupService(config)
    fake_hub = types.ModuleType("huggingface_hub")
    calls: list[dict[str, Any]] = []

    class FakeInfo:
        sha = "public-revision"

    class FakeApi:
        def __init__(self, endpoint=None, token=None):
            calls.append({"operation": "model_info", "endpoint": endpoint, "token": token})
            self.endpoint = endpoint
            self.token = token

        def model_info(self, _model):
            return FakeInfo()

    def fake_snapshot_download(**kwargs):
        calls.append({"operation": "snapshot", **kwargs})
        assert kwargs["endpoint"] == "https://huggingface.co"
        assert kwargs["token"] is False
        path = kwargs["local_dir"]
        (path / "config.json").write_text("{}", encoding="utf-8")
        (path / "model.safetensors").write_bytes(b"synthetic safe weights")
        return str(path)

    fake_hub.HfApi = FakeApi
    fake_hub.snapshot_download = fake_snapshot_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
    monkeypatch.setattr("splunk_security_agent.model_setup.local_runtime_available", lambda: True)
    job = {
        "profile_id": "securebert-ner",
        "model": "cisco-ai/SecureBERT2.0-NER",
        "status": "queued",
        "detail": "Queued",
        "progress": 0,
    }

    await service._install_local_specialist(job)

    assert job["status"] == "complete"
    assert "public_retry" not in job
    assert job["source_policy"]["mode"] == "credential-free-public"
    assert job["source_policy"]["first_attempt"] is True
    assert job["source_policy"]["credentials_sent"] is False
    assert calls[0]["endpoint"] == "https://huggingface.co"
    assert calls[0]["token"] is False
    assert calls[-1]["token"] is False


@pytest.mark.asyncio
async def test_clean_download_retry_bypasses_xet_and_removes_only_partial_model(
    monkeypatch, tmp_path
):
    config = ConfigStore(tmp_path / "data")
    service = ModelSetupService(config)
    model_path = config.local_model_path("securebert-ner")
    model_path.mkdir(parents=True)
    (model_path / "incomplete.part").write_bytes(b"partial")
    fake_hub = types.ModuleType("huggingface_hub")
    fake_hub.constants = types.SimpleNamespace(HF_HUB_DISABLE_XET=False)
    observed: dict[str, Any] = {}

    class FakeInfo:
        sha = "clean-revision"

    class FakeApi:
        def __init__(self, endpoint=None, token=None):
            assert endpoint == "https://huggingface.co"
            assert token is False

        def model_info(self, _model):
            return FakeInfo()

    def fake_snapshot_download(**kwargs):
        observed["xet"] = os.environ.get("HF_HUB_DISABLE_XET")
        observed["force_download"] = kwargs["force_download"]
        assert not (model_path / "incomplete.part").exists()
        (model_path / "config.json").write_text("{}", encoding="utf-8")
        (model_path / "model.safetensors").write_bytes(b"synthetic safe weights")
        return str(model_path)

    fake_hub.HfApi = FakeApi
    fake_hub.snapshot_download = fake_snapshot_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.local_runtime_available", lambda: True
    )
    monkeypatch.delenv("HF_HUB_DISABLE_XET", raising=False)
    job = {
        "profile_id": "securebert-ner",
        "model": "cisco-ai/SecureBERT2.0-NER",
        "strategy": "clean-download",
        "status": "queued",
        "detail": "Queued",
        "progress": 0,
    }

    await service._install_local_specialist(job)

    assert job["status"] == "complete"
    assert observed == {"xet": "1", "force_download": True}
    assert "HF_HUB_DISABLE_XET" not in os.environ
    assert fake_hub.constants.HF_HUB_DISABLE_XET is False


@pytest.mark.asyncio
async def test_pip_resolution_failure_retries_public_pypi_in_isolated_mode(
    monkeypatch, tmp_path
):
    config = ConfigStore(tmp_path / "data")
    service = ModelSetupService(config)
    fake_hub = types.ModuleType("huggingface_hub")
    process_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    class FakeInfo:
        sha = "runtime-revision"

    class FakeApi:
        def __init__(self, endpoint=None, token=None):
            self.endpoint = endpoint
            self.token = token

        def model_info(self, _model):
            return FakeInfo()

    def fake_snapshot_download(**kwargs):
        path = kwargs["local_dir"]
        (path / "config.json").write_text("{}", encoding="utf-8")
        (path / "model.safetensors").write_bytes(b"synthetic safe weights")
        return str(path)

    class FakeOutput:
        def __init__(self, lines):
            self.lines = iter(lines)

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self.lines)
            except StopIteration as exc:
                raise StopAsyncIteration from exc

    class FakeProcess:
        def __init__(self, return_code, lines):
            self.return_code = return_code
            self.stdout = FakeOutput(lines)

        async def wait(self):
            return self.return_code

    async def fake_create_subprocess_exec(*args, **kwargs):
        process_calls.append((tuple(str(value) for value in args), kwargs))
        if len(process_calls) == 1:
            return FakeProcess(
                1,
                [b"ERROR: Could not find a version that satisfies the requirement torch\n"],
            )
        return FakeProcess(0, [b"Successfully installed the public runtime\n"])

    fake_hub.HfApi = FakeApi
    fake_hub.snapshot_download = fake_snapshot_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(
        "splunk_security_agent.model_setup.local_runtime_available",
        lambda: len(process_calls) >= 2,
    )
    job = {
        "profile_id": "securebert-ner",
        "model": "cisco-ai/SecureBERT2.0-NER",
        "status": "queued",
        "detail": "Queued",
        "progress": 0,
    }

    await service._install_local_specialist(job)

    assert job["status"] == "complete"
    assert len(process_calls) == 2
    public_command, public_options = process_calls[1]
    assert "--isolated" in public_command
    assert public_command[public_command.index("--index-url") + 1] == "https://pypi.org/simple"
    assert "--no-cache-dir" in public_command
    assert "--no-input" in public_command
    assert public_options["env"]["PIP_CONFIG_FILE"] == os.devnull
    assert not any(
        key.upper().startswith("PIP_") and key != "PIP_CONFIG_FILE"
        for key in public_options["env"]
    )
    assert job["public_retry"]["credentials_sent"] is False
    assert job["public_retry"]["trigger"] == "fail-fast-source-resolution"
    assert job["public_retry"]["succeeded"] is True


@pytest.mark.asyncio
async def test_direct_runtime_retry_uses_isolated_pypi_and_native_truststore(
    monkeypatch, tmp_path
):
    service = ModelSetupService(ConfigStore(tmp_path / "data"))
    observed: dict[str, Any] = {}

    class FakeProcess:
        stdout = None

        async def wait(self):
            return 1

    async def fake_create_subprocess_exec(*args, **kwargs):
        observed["args"] = args
        observed["env"] = kwargs.get("env")
        return FakeProcess()

    monkeypatch.setattr(
        "splunk_security_agent.model_setup.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    await service._run_runtime_install(
        {"detail": "Queued"},
        public_only=True,
        native_trust=True,
    )

    args = observed["args"]
    assert "--isolated" in args
    assert args[args.index("--index-url") + 1] == "https://pypi.org/simple"
    assert args[args.index("--use-feature") + 1] == "truststore"
    assert observed["env"]["PIP_CONFIG_FILE"] == os.devnull


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
