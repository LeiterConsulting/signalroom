from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .config import ConfigStore
from .progress import ProgressCallback, report_progress


def _ollama_base(endpoint: str) -> str:
    value = (endpoint or "http://localhost:11434").rstrip("/")
    for suffix in ("/api/chat", "/api/tags", "/v1"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    return value


class SplunkModelInventoryService:
    """Read-only inventory drift tracking for models stored inside Splunk MLTK."""

    QUERY = "| listmodels | head 500"

    def __init__(self, config: ConfigStore, client: Any):
        self.config = config
        self.client = client
        self.path = Path(config.root) / "splunk_model_inventory.json"

    def latest(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "available": False,
                "status": "not-scanned",
                "models": [],
                "summary": {},
                "detail": "Run a read-only MLTK scan to establish the first inventory baseline.",
            }
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {
                "available": False,
                "status": "invalid-snapshot",
                "models": [],
                "summary": {},
                "detail": "The saved MLTK inventory could not be read; run a new scan.",
            }

    async def scan(self, progress: ProgressCallback | None = None) -> dict[str, Any]:
        checked_at = datetime.now(UTC).isoformat()
        if self.config.load().demo_mode:
            return {
                "available": False,
                "status": "demo",
                "checked_at": checked_at,
                "models": [],
                "summary": {},
                "detail": "Demo mode never executes listmodels against Splunk.",
            }
        await report_progress(
            progress,
            "mltk-command",
            "Querying Splunk MLTK",
            "Running the read-only listmodels command through the configured Splunk MCP server.",
            progress=15,
            metrics={"row_limit": 500, "splunk_writes": 0},
        )
        try:
            result = await self.client.call(
                "run_query",
                {
                    "query": self.QUERY,
                    "earliest_time": "-1h",
                    "latest_time": "now",
                    "row_limit": 500,
                },
            )
        except Exception as exc:
            latest = self.latest()
            return {
                **latest,
                "available": False,
                "status": "unavailable",
                "checked_at": checked_at,
                "error": str(exc),
                "detail": (
                    "Splunk did not execute listmodels. Confirm MLTK is installed and the MCP "
                    "identity can run its read-only search command."
                ),
            }

        rows = self._rows(result)
        await report_progress(
            progress,
            "mltk-normalize",
            "Normalizing model contracts",
            (
                f"Splunk returned {len(rows)} model definition"
                f"{'s' if len(rows) != 1 else ''}; parsing algorithms and declared dependencies."
            ),
            progress=45,
            status="complete",
            metrics={"models_returned": len(rows)},
        )
        ollama = await self._ollama_observation()
        previous = self.latest()
        previous_models = {
            item.get("id"): item
            for item in previous.get("models", [])
            if isinstance(item, dict) and item.get("id")
        }
        models: list[dict[str, Any]] = []
        current_ids: set[str] = set()
        for row in rows:
            model = self._normalize(row, ollama)
            current_ids.add(model["id"])
            prior = previous_models.get(model["id"])
            model["first_seen_at"] = prior.get("first_seen_at", checked_at) if prior else checked_at
            model["last_seen_at"] = checked_at
            if prior is None or prior.get("status") == "missing":
                model["status"] = "new"
            elif prior.get("fingerprint") != model["fingerprint"]:
                model["status"] = "changed"
                model["previous_fingerprint"] = prior.get("fingerprint", "")
            else:
                model["status"] = "unchanged"
            models.append(model)
        for model_id, prior in previous_models.items():
            if model_id in current_ids:
                continue
            models.append(
                {
                    **prior,
                    "status": "missing",
                    "missing_since": prior.get("missing_since", checked_at),
                }
            )
        models.sort(key=lambda item: (item["status"] == "missing", item["name"].lower()))
        counts = {
            status: sum(1 for item in models if item.get("status") == status)
            for status in ("new", "changed", "unchanged", "missing")
        }
        dependency_count = sum(
            1
            for item in models
            if item.get("status") != "missing"
            and item.get("dependency", {}).get("service") == "ollama"
        )
        not_observed = sum(
            1
            for item in models
            if item.get("status") != "missing"
            and item.get("dependency", {}).get("observation") == "not-observed"
        )
        summary = {
            "observed": len(rows),
            **counts,
            "ollama_dependencies": dependency_count,
            "dependencies_not_observed": not_observed,
        }
        snapshot = {
            "available": True,
            "status": "complete",
            "checked_at": checked_at,
            "models": models,
            "summary": summary,
            "collection": {
                "source": "Splunk MCP · listmodels",
                "query": self.QUERY,
                "mode": "read-only",
                "row_limit": 500,
                "truncated": bool(result.get("truncated")) if isinstance(result, dict) else False,
                "writes_performed": 0,
            },
            "freshness_contract": (
                "MLTK listmodels does not expose a universal training timestamp. SignalRoom "
                "therefore reports definition drift since its previous scan, not model accuracy "
                "or training-data freshness."
            ),
            "ollama_observation": ollama,
        }
        self.path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        await report_progress(
            progress,
            "mltk-drift",
            "MLTK model inventory ready",
            (
                f"{len(rows)} observed · {counts['new']} new · {counts['changed']} changed · "
                f"{counts['missing']} missing · {not_observed} Ollama dependencies not observed."
            ),
            progress=100,
            status="complete",
            metrics=summary,
        )
        return snapshot

    async def _ollama_observation(self) -> dict[str, Any]:
        settings = self.config.load()
        profile = next((item for item in settings.models if item.provider == "ollama"), None)
        endpoint = _ollama_base(profile.endpoint if profile else "")
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{endpoint}/api/tags")
                response.raise_for_status()
            names = [
                str(item.get("name") or "")
                for item in response.json().get("models", [])
                if item.get("name")
            ]
            return {
                "available": True,
                "endpoint": endpoint,
                "models": names,
                "caveat": (
                    "This comparison covers only SignalRoom's configured Ollama endpoint. An MLTK "
                    "connection may intentionally target another service."
                ),
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {
                "available": False,
                "endpoint": endpoint,
                "models": [],
                "error": str(exc),
                "caveat": "The declared MLTK dependency could not be compared with local Ollama.",
            }

    @classmethod
    def _normalize(cls, row: dict[str, Any], ollama: dict[str, Any]) -> dict[str, Any]:
        name = str(row.get("name") or row.get("model_name") or "unnamed-model").strip()
        app = str(row.get("app") or "").strip()
        owner = str(row.get("owner") or "").strip()
        identity = hashlib.sha256(f"{app}\0{owner}\0{name}".encode()).hexdigest()[:16]
        options = cls._options(row.get("options"))
        params = options.get("params") if isinstance(options.get("params"), dict) else {}
        service = cls._clean(params.get("llm_service")).lower()
        backing_model = cls._clean(params.get("model_name"))
        installed = {value.lower() for value in ollama.get("models", [])}
        aliases = set(installed)
        aliases.update(value.removesuffix(":latest") for value in installed)
        if service != "ollama":
            observation = "not-applicable"
        elif not backing_model:
            observation = "not-declared"
        elif not ollama.get("available"):
            observation = "unknown"
        elif backing_model.lower() in aliases:
            observation = "observed"
        else:
            observation = "not-observed"
        canonical = {
            "name": name,
            "type": str(row.get("type") or ""),
            "owner": owner,
            "app": app,
            "sharing": str(row.get("sharing") or ""),
            "options": options,
        }
        fingerprint = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "id": identity,
            **canonical,
            "algorithm": str(options.get("algo_name") or params.get("algo") or row.get("type") or ""),
            "fingerprint": fingerprint,
            "dependency": {
                "service": service,
                "model": backing_model,
                "observation": observation,
                "endpoint": ollama.get("endpoint", "") if service == "ollama" else "",
                "caveat": ollama.get("caveat", "") if service == "ollama" else "",
            },
        }

    @staticmethod
    def _rows(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            for key in ("results", "items", "data"):
                if isinstance(value.get(key), list):
                    return SplunkModelInventoryService._rows(value[key])
        return []

    @staticmethod
    def _options(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {}
            except ValueError:
                return {"raw": value[:4000]}
        return {}

    @staticmethod
    def _clean(value: Any) -> str:
        return str(value or "").strip().strip('"').strip("'")
