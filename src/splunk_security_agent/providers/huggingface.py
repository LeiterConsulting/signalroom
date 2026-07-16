from __future__ import annotations

from typing import Any

import httpx

from .base import BaseModelProvider, ModelProviderError


class HuggingFaceProvider(BaseModelProvider):
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @property
    def inference_url(self) -> str:
        base = (self.profile.endpoint or "https://router.huggingface.co/hf-inference/models").rstrip("/")
        if "router.huggingface.co" in base:
            return f"{base}/{self.profile.model}"
        return base

    async def chat(
        self, messages: list[dict[str, str]], tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        endpoint = self.profile.endpoint.rstrip("/") if self.profile.endpoint else "https://router.huggingface.co/v1"
        if "router.huggingface.co" in endpoint and not endpoint.endswith("/v1"):
            endpoint = "https://router.huggingface.co/v1"
        payload: dict[str, Any] = {
            "model": self.profile.model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": min(2048, self.profile.context_window // 2),
        }
        if tools:
            payload["tools"] = tools
        try:
            async with httpx.AsyncClient(timeout=180) as client:
                response = await client.post(
                    f"{endpoint}/chat/completions", headers=self._headers(), json=payload
                )
                response.raise_for_status()
                data = response.json()
            message = data["choices"][0]["message"]
            return {
                "content": message.get("content", ""),
                "tool_calls": message.get("tool_calls", []),
                "model": data.get("model", self.profile.model),
                "raw": data,
            }
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise ModelProviderError(f"Hugging Face chat request failed: {exc}") from exc

    async def embeddings(self, texts: list[str]) -> list[list[float]]:
        try:
            async with httpx.AsyncClient(timeout=180) as client:
                response = await client.post(
                    self.inference_url,
                    headers=self._headers(),
                    json={"inputs": texts, "normalize": True},
                )
                response.raise_for_status()
                data = response.json()
            return data if isinstance(data, list) else []
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelProviderError(f"Hugging Face embedding request failed: {exc}") from exc

    async def entities(self, text: str) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                response = await client.post(
                    self.inference_url,
                    headers=self._headers(),
                    json={"inputs": text, "options": {"wait_for_model": True}},
                )
                response.raise_for_status()
                data = response.json()
            return data if isinstance(data, list) else []
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelProviderError(f"Hugging Face NER request failed: {exc}") from exc

    async def similarities(self, source: str, sentences: list[str]) -> list[float]:
        if not sentences:
            return []
        try:
            async with httpx.AsyncClient(timeout=180) as client:
                response = await client.post(
                    self.inference_url,
                    headers=self._headers(),
                    json={
                        "inputs": {
                            "source_sentence": source,
                            "sentences": sentences,
                        }
                    },
                )
                response.raise_for_status()
                data = response.json()
            return [float(value) for value in data] if isinstance(data, list) else []
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            raise ModelProviderError(f"Hugging Face similarity request failed: {exc}") from exc

    async def rerank(self, query: str, documents: list[str]) -> list[float]:
        return await self.similarities(query, documents)

    async def health(self) -> dict[str, Any]:
        if not self.token:
            return {"ok": False, "error": "No Hugging Face token configured", "model": self.profile.model}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"https://huggingface.co/api/models/{self.profile.model}", headers=self._headers()
                )
                response.raise_for_status()
                data = response.json()
            return {
                "ok": True,
                "model": self.profile.model,
                "pipeline_tag": data.get("pipeline_tag"),
                "private": data.get("private", False),
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"ok": False, "error": str(exc), "model": self.profile.model}
