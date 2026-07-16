from __future__ import annotations

import asyncio
import importlib.util
import math
import re
import threading
from pathlib import Path
from typing import Any

from .base import BaseModelProvider, ModelProviderError

LOCAL_RUNTIME_MODULES = ("huggingface_hub", "sentence_transformers", "torch", "transformers")


def local_runtime_available() -> bool:
    return all(importlib.util.find_spec(module) is not None for module in LOCAL_RUNTIME_MODULES)


def local_model_installed(path: Path) -> bool:
    return (
        (path / ".signalroom-model.json").is_file()
        and (path / "config.json").is_file()
        and any(path.glob("*.safetensors"))
    )


class LocalTransformersProvider(BaseModelProvider):
    """Runs downloaded Hugging Face specialists without making inference network calls."""

    _models: dict[tuple[str, str], Any] = {}
    _load_lock = threading.RLock()

    def __init__(self, profile: Any, model_path: Path):
        super().__init__(profile)
        self.model_path = model_path

    def _require_ready(self) -> None:
        if not local_runtime_available():
            raise ModelProviderError(
                "Local Transformers runtime is not installed. Install it from Workspace setup."
            )
        if not local_model_installed(self.model_path):
            raise ModelProviderError(
                f"Local specialist is not installed: {self.profile.label}. Install it from Workspace setup."
            )

    @staticmethod
    def _device() -> str:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"

    def _embedding_model(self) -> Any:
        self._require_ready()
        cache_key = (self.profile.id, "embedding")
        with self._load_lock:
            if cache_key not in self._models:
                from sentence_transformers import SentenceTransformer

                self._models[cache_key] = SentenceTransformer(
                    str(self.model_path),
                    device=self._device(),
                    local_files_only=True,
                    trust_remote_code=False,
                )
            return self._models[cache_key]

    def _entity_pipeline(self) -> Any:
        self._require_ready()
        cache_key = (self.profile.id, "ner")
        with self._load_lock:
            if cache_key not in self._models:
                from transformers import (
                    AutoModelForTokenClassification,
                    AutoTokenizer,
                    pipeline,
                )

                tokenizer = AutoTokenizer.from_pretrained(
                    self.model_path, local_files_only=True, trust_remote_code=False
                )
                model = AutoModelForTokenClassification.from_pretrained(
                    self.model_path, local_files_only=True, trust_remote_code=False
                )
                self._models[cache_key] = pipeline(
                    "token-classification",
                    model=model,
                    tokenizer=tokenizer,
                    aggregation_strategy="simple",
                    device=0 if self._device() == "cuda" else -1,
                )
            return self._models[cache_key]

    async def chat(
        self, messages: list[dict[str, str]], tools: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        raise ModelProviderError("Local SecureBERT specialists do not provide chat generation")

    async def embeddings(self, texts: list[str]) -> list[list[float]]:
        return await self._encode(texts, "generic")

    async def query_embedding(self, text: str) -> list[float]:
        vectors = await self._encode([text], "query")
        return vectors[0] if vectors else []

    async def document_embeddings(self, texts: list[str]) -> list[list[float]]:
        return await self._encode(texts, "document")

    async def _encode(self, texts: list[str], kind: str) -> list[list[float]]:
        if not texts:
            return []

        def encode() -> list[list[float]]:
            model = self._embedding_model()
            encoder = (
                getattr(model, "encode_query", model.encode)
                if kind == "query"
                else getattr(model, "encode_document", model.encode)
                if kind == "document"
                else model.encode
            )
            vectors = encoder(
                texts,
                normalize_embeddings=True,
                convert_to_numpy=True,
                show_progress_bar=False,
                batch_size=32 if self._device() == "cuda" else 8,
            )
            return [[float(value) for value in row] for row in vectors]

        return await asyncio.to_thread(encode)

    async def similarities(self, source: str, sentences: list[str]) -> list[float]:
        if not sentences:
            return []
        source_vector, candidate_vectors = await asyncio.gather(
            self.query_embedding(source),
            self.document_embeddings(sentences),
        )
        scores: list[float] = []
        for candidate in candidate_vectors:
            score = sum(left * right for left, right in zip(source_vector, candidate, strict=False))
            if not math.isfinite(score):
                score = 0.0
            scores.append(float(score))
        return scores

    async def entities(self, text: str) -> list[dict[str, Any]]:
        def extract() -> list[dict[str, Any]]:
            values = self._entity_pipeline()(text)
            return self._normalize_entities(
                text,
                [dict(value) for value in values if isinstance(value, dict)],
            )

        return await asyncio.to_thread(extract)

    @staticmethod
    def _normalize_entities(text: str, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Recover source text from offsets and join token fragments inside one observable."""
        normalized: list[dict[str, Any]] = []
        for value in values:
            item = dict(value)
            start, end = item.get("start"), item.get("end")
            if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text):
                observed = text[start:end].strip()
                if observed:
                    item["word"] = observed
            normalized.append(item)
        normalized.sort(
            key=lambda item: (
                item.get("start") if isinstance(item.get("start"), int) else len(text) + 1
            )
        )
        merged: list[dict[str, Any]] = []
        for item in normalized:
            if merged:
                previous = merged[-1]
                previous_end, start = previous.get("end"), item.get("start")
                previous_group = previous.get("entity_group") or previous.get("entity")
                current_group = item.get("entity_group") or item.get("entity")
                if (
                    previous_group == current_group
                    and isinstance(previous_end, int)
                    and isinstance(start, int)
                    and previous_end <= start
                    and re.fullmatch(r"[.:/_-]*", text[previous_end:start]) is not None
                ):
                    end = item.get("end")
                    if isinstance(end, int):
                        previous["end"] = end
                        previous["word"] = text[previous.get("start", 0) : end].strip()
                        previous["score"] = min(
                            float(previous.get("score") or 0),
                            float(item.get("score") or 0),
                        )
                        continue
            merged.append(item)
        return merged

    async def health(self) -> dict[str, Any]:
        return {
            "ok": local_runtime_available() and local_model_installed(self.model_path),
            "runtime": "local-transformers",
            "runtime_installed": local_runtime_available(),
            "installed": local_model_installed(self.model_path),
            "model": self.profile.model,
            "path": str(self.model_path),
            "network_inference": False,
        }
