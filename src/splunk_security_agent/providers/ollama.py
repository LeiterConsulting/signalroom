from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..schemas import ModelProfile
from .base import BaseModelProvider, ModelProviderError


class OllamaProvider(BaseModelProvider):
    _endpoint_locks: dict[str, asyncio.Lock] = {}

    def __init__(
        self,
        profile: ModelProfile,
        token: str = "",
        managed_models: list[str] | None = None,
    ):
        super().__init__(profile, token)
        self.managed_models = managed_models or [profile.model]

    @property
    def base_url(self) -> str:
        value = (self.profile.endpoint or "http://localhost:11434").rstrip("/")
        for suffix in ("/api/chat", "/api/tags", "/v1"):
            if value.endswith(suffix):
                value = value[: -len(suffix)]
        return value

    async def chat(
        self, messages: list[dict[str, str]], tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        return await self._request(messages, tools=tools)

    async def structured_chat(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | str,
        *,
        keep_alive: str | int = "15m",
        max_output_tokens: int | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            messages,
            response_format=schema,
            temperature=0,
            keep_alive=keep_alive,
            max_output_tokens=max_output_tokens,
            seed=0,
        )

    async def _request(
        self,
        messages: list[dict[str, str]],
        *,
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | str | None = None,
        temperature: float = 0.2,
        keep_alive: str | int = "15m",
        max_output_tokens: int | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.profile.model,
            "messages": messages,
            "stream": False,
            "keep_alive": keep_alive,
            "options": {"temperature": temperature},
        }
        if max_output_tokens is not None:
            payload["options"]["num_predict"] = max_output_tokens
        if seed is not None:
            payload["options"]["seed"] = seed
        if tools:
            payload["tools"] = tools
        if response_format:
            payload["format"] = response_format
        try:
            lock = self._endpoint_locks.setdefault(self.base_url, asyncio.Lock())
            async with lock:
                async with httpx.AsyncClient(timeout=180) as client:
                    activation = await self._ensure_active(client)
                    response = await client.post(f"{self.base_url}/api/chat", json=payload)
                    response.raise_for_status()
                    data = response.json()
        except httpx.HTTPStatusError as exc:
            detail = " ".join(exc.response.text.split())[:800]
            suffix = f" · {detail}" if detail else ""
            raise ModelProviderError(f"Ollama request failed: {exc}{suffix}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelProviderError(f"Ollama request failed: {exc}") from exc
        executed_model = str(data.get("model") or self.profile.model)
        if not self._models_match(self.profile.model, executed_model):
            raise ModelProviderError(
                f"Ollama executed '{executed_model}' instead of requested '{self.profile.model}'"
            )
        message = data.get("message", {})
        return {
            "content": message.get("content", ""),
            "tool_calls": message.get("tool_calls", []),
            "model": executed_model,
            "requested_model": self.profile.model,
            "activation": activation,
            "raw": data,
        }

    async def _ensure_active(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Load the requested model when it is not already resident in Ollama."""
        try:
            response = await client.get(f"{self.base_url}/api/ps")
            response.raise_for_status()
            loaded = [item.get("name", "") for item in response.json().get("models", [])]
        except (httpx.HTTPError, ValueError):
            loaded = []
        unloaded: list[str] = []
        for loaded_name in loaded:
            is_requested = self._models_match(self.profile.model, loaded_name)
            is_managed_peer = any(
                self._models_match(managed, loaded_name)
                for managed in self.managed_models
                if not self._models_match(self.profile.model, managed)
            )
            if not is_requested and is_managed_peer:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": loaded_name,
                        "prompt": "",
                        "stream": False,
                        "keep_alive": 0,
                    },
                )
                response.raise_for_status()
                unloaded.append(loaded_name)
        if any(self._models_match(self.profile.model, name) for name in loaded):
            return {
                "activated": False,
                "already_loaded": True,
                "loaded_models": [self.profile.model],
                "unloaded_models": unloaded,
            }
        response = await client.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.profile.model,
                "prompt": "",
                "stream": False,
                "keep_alive": "15m",
            },
        )
        response.raise_for_status()
        executed_model = str(response.json().get("model") or self.profile.model)
        if not self._models_match(self.profile.model, executed_model):
            raise ModelProviderError(
                f"Ollama loaded '{executed_model}' instead of requested '{self.profile.model}'"
            )
        return {
            "activated": True,
            "already_loaded": False,
            "loaded_models": [executed_model],
            "unloaded_models": unloaded,
        }

    @staticmethod
    def _models_match(requested: str, actual: str) -> bool:
        requested_lower = requested.lower()
        actual_lower = actual.lower()
        return requested_lower == actual_lower or (
            ":" not in requested_lower and actual_lower == f"{requested_lower}:latest"
        )

    async def health(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
                models = [item.get("name") for item in response.json().get("models", [])]
                try:
                    running = await client.get(f"{self.base_url}/api/ps")
                    running.raise_for_status()
                    loaded_models = [
                        item.get("name") for item in running.json().get("models", [])
                    ]
                except (httpx.HTTPError, ValueError):
                    loaded_models = []
            requested = self.profile.model
            installed = requested in models or any(
                name and name.split(":")[0] == requested for name in models
            )
            loaded = any(
                name and self._models_match(requested, name) for name in loaded_models
            )
            return {
                "ok": True,
                "installed": installed,
                "loaded": loaded,
                "models": models,
                "loaded_models": loaded_models,
                "endpoint": self.base_url,
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"ok": False, "error": str(exc), "endpoint": self.base_url}
