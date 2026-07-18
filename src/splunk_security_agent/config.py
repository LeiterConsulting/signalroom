from __future__ import annotations

import json
import os
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .schemas import AppSettings, ModelProfile

DEFAULT_MODELS = [
    ModelProfile(
        id="ollama-general",
        label="Local general agent",
        provider="ollama",
        model="llama3.1:8b",
        task="chat",
        endpoint="http://localhost:11434",
        description="Fast local orchestration, tool selection, and plain-language answers.",
        provenance="Operator-selected Ollama model",
    ),
    ModelProfile(
        id="foundation-sec",
        label="Foundation-Sec reasoning",
        provider="ollama",
        model="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M",
        task="security_reasoning",
        endpoint="http://localhost:11434",
        description="Cybersecurity-specialized reasoning for triage, hypotheses, TTPs, and findings.",
        provenance="Foundation AI at Cisco / fdtn-ai",
    ),
    ModelProfile(
        id="foundation-sec-instruct",
        label="Foundation-Sec 1.1 Instruct",
        provider="ollama",
        model="hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M",
        task="security_reasoning",
        endpoint="http://localhost:11434",
        description=(
            "Faster cybersecurity instruction following for concise analysis, extraction, and "
            "analyst-facing summaries. Available as an explicit local Ollama profile."
        ),
        provenance="Foundation AI at Cisco / fdtn-ai",
    ),
    ModelProfile(
        id="securebert-embed",
        label="SecureBERT retrieval",
        provider="huggingface",
        model="cisco-ai/SecureBERT2.0-biencoder",
        task="embedding",
        endpoint="https://router.huggingface.co/hf-inference/models",
        description="Cybersecurity-domain embeddings for artifacts and RAG retrieval.",
        provenance="Cisco AI",
        context_window=1024,
    ),
    ModelProfile(
        id="securebert-ner",
        label="SecureBERT entity extraction",
        provider="huggingface",
        model="cisco-ai/SecureBERT2.0-NER",
        task="ner",
        endpoint="https://router.huggingface.co/hf-inference/models",
        description="Extracts malware, vulnerabilities, indicators, products, and security entities.",
        provenance="Cisco AI",
        context_window=1024,
    ),
    ModelProfile(
        id="securebert-rerank",
        label="SecureBERT evidence reranker",
        provider="huggingface",
        model="cisco-ai/SecureBERT2.0-cross_encoder",
        task="reranking",
        endpoint="https://router.huggingface.co/hf-inference/models",
        description=(
            "Second-stage cybersecurity relevance scoring that reranks retrieved Context before "
            "it reaches discovery or the chat agent."
        ),
        provenance="Cisco AI",
        context_window=1024,
    ),
]


def _merge_default_models(models: list[ModelProfile]) -> list[ModelProfile]:
    """Add newly shipped capabilities without overwriting operator-edited profiles."""
    merged = list(models)
    existing = {profile.id for profile in merged}
    merged.extend(profile.model_copy(deep=True) for profile in DEFAULT_MODELS if profile.id not in existing)
    return merged


class SecretVault:
    """Small encrypted secret store; the key and ciphertext are never committed."""

    def __init__(self, root: Path):
        self.key_path = root / ".vault.key"
        self.secret_path = root / "secrets.enc"
        root.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            self.key_path.write_bytes(Fernet.generate_key())
            if os.name != "nt":
                self.key_path.chmod(0o600)
        self.fernet = Fernet(self.key_path.read_bytes())

    def load(self) -> dict[str, str]:
        if not self.secret_path.exists():
            return {}
        try:
            return json.loads(self.fernet.decrypt(self.secret_path.read_bytes()).decode("utf-8"))
        except (InvalidToken, json.JSONDecodeError):
            return {}

    def save(self, secrets: dict[str, str]) -> None:
        payload = json.dumps(secrets, sort_keys=True).encode("utf-8")
        self.secret_path.write_bytes(self.fernet.encrypt(payload))
        if os.name != "nt":
            self.secret_path.chmod(0o600)


class ConfigStore:
    def __init__(self, root: Path | str = "data"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "config.json"
        self.vault = SecretVault(self.root)
        self._lock = RLock()
        if not self.path.exists():
            self.save(AppSettings(models=DEFAULT_MODELS))

    def load(self) -> AppSettings:
        with self._lock:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            settings = AppSettings.model_validate(data)
            if not settings.models:
                settings.models = [profile.model_copy(deep=True) for profile in DEFAULT_MODELS]
            else:
                settings.models = _merge_default_models(settings.models)
            return settings

    def save(self, settings: AppSettings) -> AppSettings:
        with self._lock:
            self.path.write_text(json.dumps(settings.model_dump(mode="json"), indent=2), encoding="utf-8")
        return settings

    def update_secrets(self, **values: str | None) -> None:
        with self._lock:
            secrets = self.vault.load()
            for key, value in values.items():
                if value and value != "***":
                    secrets[key] = value
            self.vault.save(secrets)

    def delete_secrets(self, *names: str) -> None:
        with self._lock:
            secrets = self.vault.load()
            for name in names:
                secrets.pop(name, None)
            self.vault.save(secrets)

    def secret_is_environment_managed(self, name: str) -> bool:
        env_names = {
            "splunk_token": "SPLUNK_MCP_TOKEN",
            "huggingface_token": "HF_TOKEN",
            "delivery_webhook_url": "SIGNALROOM_WEBHOOK_URL",
            "delivery_authorization": "SIGNALROOM_WEBHOOK_AUTHORIZATION",
            "delivery_jira_email": "SIGNALROOM_JIRA_EMAIL",
            "delivery_jira_api_token": "SIGNALROOM_JIRA_API_TOKEN",
        }
        env_name = env_names.get(name, "")
        return bool(env_name and os.getenv(env_name, ""))

    def secret(self, name: str) -> str:
        env_names = {
            "splunk_token": "SPLUNK_MCP_TOKEN",
            "huggingface_token": "HF_TOKEN",
            "delivery_webhook_url": "SIGNALROOM_WEBHOOK_URL",
            "delivery_authorization": "SIGNALROOM_WEBHOOK_AUTHORIZATION",
            "delivery_jira_email": "SIGNALROOM_JIRA_EMAIL",
            "delivery_jira_api_token": "SIGNALROOM_JIRA_API_TOKEN",
        }
        return os.getenv(env_names.get(name, ""), "") or self.vault.load().get(name, "")

    @property
    def local_models_root(self) -> Path:
        path = self.root / "models"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def local_model_path(self, profile_id: str) -> Path:
        safe_id = "".join(character for character in profile_id if character.isalnum() or character in "-_")
        if not safe_id or safe_id != profile_id:
            raise ValueError(f"Unsafe model profile id: {profile_id}")
        return self.local_models_root / safe_id

    def public_payload(self) -> dict[str, Any]:
        settings = self.load().model_dump(mode="json")
        settings["secrets"] = {
            "splunk_token": bool(self.secret("splunk_token")),
            "huggingface_token": bool(self.secret("huggingface_token")),
        }
        return settings
