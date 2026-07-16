from __future__ import annotations

from ..config import ConfigStore
from ..schemas import ModelProfile
from .base import BaseModelProvider
from .huggingface import HuggingFaceProvider
from .local_transformers import LocalTransformersProvider
from .ollama import OllamaProvider

SECURITY_TERMS = {
    "attack",
    "cve",
    "detection",
    "exploit",
    "incident",
    "ioc",
    "malware",
    "mitre",
    "phishing",
    "ransomware",
    "risk",
    "threat",
    "ttp",
    "vulnerability",
    "zero-day",
}

MODE_TERMS = {
    "discovery": {"coverage", "discover", "environment", "inventory", "sourcetype", "topology"},
    "detection": {"alert", "correlation", "detect", "detection", "rule", "scheduled"},
    "hunt": {"hunt", "hypothesis", "ttp", "threat"},
    "triage": {"incident", "investigate", "malware", "phishing", "ransomware", "triage"},
    "spl": {"explain", "optimize", "search", "spl", "stats", "tstats"},
    "brief": {"brief", "executive", "leadership", "summarize", "summary"},
}

SPECIALIST_MODES = {"detection", "hunt", "triage", "brief"}


class ModelRouter:
    def __init__(self, config: ConfigStore):
        self.config = config

    def profile(self, profile_id: str) -> ModelProfile:
        settings = self.config.load()
        for profile in settings.models:
            if profile.id == profile_id:
                return profile
        raise KeyError(f"Unknown model profile: {profile_id}")

    def provider(self, profile_id: str) -> BaseModelProvider:
        profile = self.profile(profile_id)
        settings = self.config.load()
        if profile.provider == "ollama":
            managed_models = [
                candidate.model
                for candidate in settings.models
                if candidate.provider == "ollama" and candidate.enabled
            ]
            return OllamaProvider(profile, managed_models=managed_models)
        if settings.specialist_runtime == "local" and profile.task in {
            "embedding",
            "ner",
            "reranking",
            "classification",
        }:
            return LocalTransformersProvider(profile, self.config.local_model_path(profile.id))
        return HuggingFaceProvider(profile, self.config.secret("huggingface_token"))

    @staticmethod
    def classify_mode(message: str, requested: str = "auto") -> str:
        if requested != "auto":
            return requested
        tokens = {token.strip(".,:;!?()[]{}|`").lower() for token in message.split()}
        scores = {mode: len(tokens & terms) for mode, terms in MODE_TERMS.items()}
        best = max(scores, key=scores.get)
        return best if scores[best] else "general"

    def route_chat(
        self, message: str, requested: str | None = None, mode: str = "auto"
    ) -> tuple[str, str]:
        settings = self.config.load()
        if requested:
            return requested, "operator-selected"
        tokens = {token.strip(".,:;!?()[]{}").lower() for token in message.split()}
        resolved_mode = self.classify_mode(message, mode)
        if resolved_mode in SPECIALIST_MODES or tokens & SECURITY_TERMS:
            return settings.security_reasoning_model, f"security-specialist:{resolved_mode}"
        return settings.default_chat_model, "general-agent"
