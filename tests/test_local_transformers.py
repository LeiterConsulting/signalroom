from splunk_security_agent.config import ConfigStore
from splunk_security_agent.providers.huggingface import HuggingFaceProvider
from splunk_security_agent.providers.local_transformers import (
    LocalTransformersProvider,
    local_model_installed,
)
from splunk_security_agent.providers.router import ModelRouter


def _write_model_sentinel(path):
    path.mkdir(parents=True)
    (path / "config.json").write_text("{}", encoding="utf-8")
    (path / "model.safetensors").write_bytes(b"synthetic weights")
    (path / ".signalroom-model.json").write_text("{}", encoding="utf-8")


def test_local_model_requires_completed_manifest_config_and_weights(tmp_path):
    model_path = tmp_path / "securebert"
    model_path.mkdir()
    (model_path / "config.json").write_text("{}", encoding="utf-8")

    assert local_model_installed(model_path) is False

    (model_path / "model.safetensors").write_bytes(b"partial")
    assert local_model_installed(model_path) is False

    (model_path / ".signalroom-model.json").write_text("{}", encoding="utf-8")
    assert local_model_installed(model_path) is True


def test_router_prefers_local_transformers_and_allows_explicit_cloud(tmp_path):
    config = ConfigStore(tmp_path / "data")
    router = ModelRouter(config)

    local_provider = router.provider("securebert-ner")
    assert isinstance(local_provider, LocalTransformersProvider)
    assert local_provider.model_path == config.local_model_path("securebert-ner")

    settings = config.load()
    settings.specialist_runtime = "cloud"
    config.save(settings)

    assert isinstance(router.provider("securebert-ner"), HuggingFaceProvider)


async def test_local_provider_health_never_claims_network_inference(tmp_path, monkeypatch):
    config = ConfigStore(tmp_path / "data")
    model_path = config.local_model_path("securebert-embed")
    _write_model_sentinel(model_path)
    monkeypatch.setattr(
        "splunk_security_agent.providers.local_transformers.local_runtime_available",
        lambda: True,
    )

    provider = ModelRouter(config).provider("securebert-embed")
    health = await provider.health()

    assert health["ok"] is True
    assert health["runtime"] == "local-transformers"
    assert health["network_inference"] is False


def test_entity_normalization_recovers_offsets_and_merges_indicator_fragments():
    text = "source_ip=192.168.1.203 device=esp32_temp"
    values = [
        {"entity_group": "INDICATOR", "word": "192", "start": 10, "end": 13, "score": 0.99},
        {"entity_group": "INDICATOR", "word": "[UNK]", "start": 14, "end": 17, "score": 0.98},
        {"entity_group": "INDICATOR", "word": "1", "start": 18, "end": 19, "score": 0.97},
        {"entity_group": "INDICATOR", "word": "203", "start": 20, "end": 23, "score": 0.96},
        {"entity_group": "INDICATOR", "word": "esp", "start": 31, "end": 34, "score": 0.95},
        {"entity_group": "INDICATOR", "word": "32", "start": 34, "end": 36, "score": 0.94},
        {"entity_group": "INDICATOR", "word": "temp", "start": 37, "end": 41, "score": 0.93},
    ]

    result = LocalTransformersProvider._normalize_entities(text, values)

    assert [item["word"] for item in result] == ["192.168.1.203", "esp32_temp"]
    assert result[0]["score"] == 0.96
