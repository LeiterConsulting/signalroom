from typing import Any

from splunk_security_agent.providers.ollama import OllamaProvider
from splunk_security_agent.schemas import ModelProfile


class FakeResponse:
    def __init__(self, payload: dict[str, Any]):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeOllamaClient:
    def __init__(self, *args: Any, **kwargs: Any):
        self.loaded = ["llama3.1:8b"]
        self.posts: list[tuple[str, dict[str, Any]]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, url: str) -> FakeResponse:
        assert url.endswith("/api/ps")
        return FakeResponse({"models": [{"name": name} for name in self.loaded]})

    async def post(self, url: str, json: dict[str, Any]) -> FakeResponse:
        self.posts.append((url, json))
        model = json["model"]
        if url.endswith("/api/chat"):
            return FakeResponse(
                {"model": model, "message": {"content": "Foundation response"}}
            )
        if json.get("keep_alive") == 0:
            self.loaded = [name for name in self.loaded if name != model]
        else:
            self.loaded = [model]
        return FakeResponse({"model": model, "done": True})


async def test_chat_swaps_managed_ollama_model_and_proves_executed_identity(monkeypatch):
    foundation = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M"
    client = FakeOllamaClient()
    monkeypatch.setattr(
        "splunk_security_agent.providers.ollama.httpx.AsyncClient",
        lambda *args, **kwargs: client,
    )
    OllamaProvider._endpoint_locks.clear()
    provider = OllamaProvider(
        ModelProfile(
            id="foundation-sec",
            label="Foundation-Sec",
            provider="ollama",
            model=foundation,
            task="security_reasoning",
            endpoint="http://localhost:11434",
            max_output_tokens=640,
        ),
        managed_models=["llama3.1:8b", foundation],
    )

    result = await provider.chat([{"role": "user", "content": "Triage this."}])

    assert result["model"] == foundation
    assert result["requested_model"] == foundation
    assert result["activation"]["activated"] is True
    assert result["activation"]["unloaded_models"] == ["llama3.1:8b"]
    assert client.posts[0][1]["keep_alive"] == 0
    assert client.posts[1][1]["keep_alive"] == "15m"
    assert client.posts[2][0].endswith("/api/chat")
    assert client.posts[2][1]["options"]["num_predict"] == 640


async def test_structured_chat_sends_json_schema_and_deterministic_runtime_options(monkeypatch):
    client = FakeOllamaClient()
    monkeypatch.setattr(
        "splunk_security_agent.providers.ollama.httpx.AsyncClient",
        lambda *args, **kwargs: client,
    )
    OllamaProvider._endpoint_locks.clear()
    provider = OllamaProvider(
        ModelProfile(
            id="ollama-general",
            label="General",
            provider="ollama",
            model="llama3.1:8b",
            endpoint="http://localhost:11434",
        )
    )
    schema = {
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"],
    }

    await provider.structured_chat(
        [{"role": "user", "content": "Summarize."}],
        schema,
        keep_alive=0,
        max_output_tokens=512,
    )

    payload = client.posts[-1][1]
    assert payload["format"] == schema
    assert payload["options"]["temperature"] == 0
    assert payload["options"]["num_predict"] == 512
    assert payload["options"]["seed"] == 0
    assert payload["keep_alive"] == 0
