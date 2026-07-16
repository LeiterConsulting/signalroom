from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..schemas import ModelProfile


class ModelProviderError(RuntimeError):
    pass


class BaseModelProvider(ABC):
    def __init__(self, profile: ModelProfile, token: str = ""):
        self.profile = profile
        self.token = token

    @abstractmethod
    async def chat(
        self, messages: list[dict[str, str]], tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        raise NotImplementedError

    async def embeddings(self, texts: list[str]) -> list[list[float]]:
        raise ModelProviderError(f"{self.profile.label} does not support embeddings")

    async def structured_chat(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | str,
        *,
        keep_alive: str | int = "15m",
        max_output_tokens: int | None = None,
    ) -> dict[str, Any]:
        return await self.chat(messages)

    async def entities(self, text: str) -> list[dict[str, Any]]:
        raise ModelProviderError(f"{self.profile.label} does not support entity extraction")

    async def similarities(self, source: str, sentences: list[str]) -> list[float]:
        raise ModelProviderError(f"{self.profile.label} does not support sentence similarity")

    async def rerank(self, query: str, documents: list[str]) -> list[float]:
        raise ModelProviderError(f"{self.profile.label} does not support evidence reranking")
