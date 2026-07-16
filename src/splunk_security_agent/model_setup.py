from __future__ import annotations

import asyncio
import importlib
import json
import os
import platform
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .config import ConfigStore
from .providers.local_transformers import (
    LocalTransformersProvider,
    local_model_installed,
    local_runtime_available,
)
from .rag import EvidenceStore
from .schemas import ModelProfile

OLLAMA_DOWNLOAD_URL = "https://ollama.com/download"
HF_TOKEN_URL = "https://huggingface.co/settings/tokens"
LOCAL_RUNTIME_PACKAGES = (
    "huggingface-hub>=0.27,<2",
    "sentence-transformers>=3.4,<6",
    "torch>=2.5",
    "transformers>=4.48,<6",
)

EVALUATED_MODEL_CANDIDATES: tuple[dict[str, str], ...] = (
    {
        "id": "securebert-code-vulnerability",
        "label": "SecureBERT 2.0 code vulnerability detection",
        "model": "cisco-ai/SecureBERT2.0-code-vuln-detection",
        "owner": "Cisco AI",
        "status": "evaluated-next",
        "runtime": "local-transformers",
        "purpose": "Assistive binary vulnerability screening for uploaded source-code snippets.",
        "constraint": (
            "Not suitable for SPL, event text, dynamic analysis, or autonomous remediation; "
            "needs a code-artifact workflow and analyst-visible confidence contract first."
        ),
        "source_url": "https://huggingface.co/cisco-ai/SecureBERT2.0-code-vuln-detection",
    },
    {
        "id": "cisco-time-series-1",
        "label": "Cisco Time Series Model 1.0",
        "model": "cisco-ai/cisco-time-series-model-1.0",
        "owner": "Cisco AI",
        "status": "adapter-required",
        "runtime": "dedicated-time-series",
        "purpose": "Zero-shot forecasting for event-rate and observability time series.",
        "constraint": (
            "Requires numeric series extraction, resampling, evaluation, and its dedicated runtime; "
            "it is not a chat, embedding, or standard Transformers pipeline."
        ),
        "source_url": "https://huggingface.co/cisco-ai/cisco-time-series-model-1.0",
    },
)


def _huggingface_repo(model: str) -> str:
    """Return the Hub repo behind an hf.co Ollama model, if one is explicit."""
    match = re.match(r"^hf\.co/([^/]+/[^:]+)(?::[^:]+)?$", model, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def _ollama_base(profile: ModelProfile) -> str:
    value = (profile.endpoint or "http://localhost:11434").rstrip("/")
    for suffix in ("/api/chat", "/api/tags", "/v1"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    return value


def _model_installed(requested: str, installed: list[str]) -> bool:
    requested_lower = requested.lower()
    aliases = {name.lower() for name in installed if name}
    if requested_lower in aliases:
        return True
    if ":" not in requested_lower and f"{requested_lower}:latest" in aliases:
        return True
    return False


def _models_match(requested: str, actual: str) -> bool:
    return _model_installed(requested, [actual])


class ModelSetupService:
    """Readiness checks and explicit, profile-scoped local model downloads."""

    def __init__(self, config: ConfigStore, evidence: EvidenceStore | None = None):
        self.config = config
        self.evidence = evidence
        self.jobs: dict[str, dict[str, Any]] = {}
        self.context_index_job: dict[str, Any] = {"status": "idle"}
        self.revision_state_path = self.config.root / "model_revisions.json"

    def catalog(self) -> dict[str, Any]:
        """Describe shipped capabilities and researched candidates without overstating support."""
        settings = self.config.load()
        return {
            "configured": [profile.model_dump(mode="json") for profile in settings.models],
            "evaluated_candidates": list(EVALUATED_MODEL_CANDIDATES),
            "policy": (
                "SignalRoom only promotes first-party model sources. Candidate status means the "
                "runtime and analyst workflow still need validation before installation is offered."
            ),
        }

    def _load_revision_state(self) -> dict[str, Any]:
        if not self.revision_state_path.exists():
            return {"profiles": {}}
        try:
            value = json.loads(self.revision_state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"profiles": {}}
        except (OSError, ValueError):
            return {"profiles": {}}

    def _save_revision_state(self, value: dict[str, Any]) -> None:
        self.revision_state_path.write_text(json.dumps(value, indent=2), encoding="utf-8")

    async def _hub_metadata(
        self, client: httpx.AsyncClient, repo: str
    ) -> dict[str, Any]:
        headers = {}
        token = self.config.secret("huggingface_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await client.get(f"https://huggingface.co/api/models/{repo}", headers=headers)
        response.raise_for_status()
        metadata = response.json()
        return {
            "revision": str(metadata.get("sha") or ""),
            "last_modified": metadata.get("lastModified"),
            "pipeline_tag": metadata.get("pipeline_tag"),
            "source_url": f"https://huggingface.co/{repo}",
        }

    async def check_updates(self) -> dict[str, Any]:
        """Compare immutable local provenance with current first-party source revisions."""
        settings = self.config.load()
        tracking = self._load_revision_state().get("profiles", {})
        ollama_profiles = [profile for profile in settings.models if profile.provider == "ollama"]
        endpoints = {_ollama_base(profile) for profile in ollama_profiles}
        tags_by_endpoint: dict[str, dict[str, dict[str, Any]]] = {}
        endpoint_errors: dict[str, str] = {}
        repos = {
            profile.model if profile.provider == "huggingface" else _huggingface_repo(profile.model)
            for profile in settings.models
        } - {""}
        hub_metadata: dict[str, dict[str, Any]] = {}
        hub_errors: dict[str, str] = {}

        async with httpx.AsyncClient(timeout=12) as client:
            async def load_tags(endpoint: str) -> None:
                try:
                    response = await client.get(f"{endpoint}/api/tags")
                    response.raise_for_status()
                    tags_by_endpoint[endpoint] = {
                        str(item.get("name") or "").lower(): item
                        for item in response.json().get("models", [])
                    }
                except (httpx.HTTPError, ValueError) as exc:
                    endpoint_errors[endpoint] = str(exc)

            async def load_hub(repo: str) -> None:
                try:
                    hub_metadata[repo] = await self._hub_metadata(client, repo)
                except (httpx.HTTPError, ValueError) as exc:
                    hub_errors[repo] = str(exc)

            await asyncio.gather(
                *(load_tags(endpoint) for endpoint in endpoints),
                *(load_hub(repo) for repo in repos),
            )

        results: list[dict[str, Any]] = []
        for profile in settings.models:
            base = {
                "profile_id": profile.id,
                "label": profile.label,
                "model": profile.model,
                "provider": profile.provider,
                "task": profile.task,
                "checked_at": datetime.now(UTC).isoformat(),
            }
            repo = profile.model if profile.provider == "huggingface" else _huggingface_repo(
                profile.model
            )
            remote = hub_metadata.get(repo, {})
            base.update(remote_revision=remote.get("revision", ""), **remote)
            if profile.provider == "huggingface":
                manifest_path = self.config.local_model_path(profile.id) / ".signalroom-model.json"
                manifest: dict[str, Any] = {}
                if manifest_path.exists():
                    try:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        manifest = {}
                installed = local_model_installed(self.config.local_model_path(profile.id))
                local_revision = str(manifest.get("revision") or "")
                base.update(installed=installed, local_revision=local_revision)
                if not installed:
                    base.update(status="not-installed", detail="Available for an explicit local install.")
                elif repo in hub_errors:
                    base.update(status="error", detail=hub_errors[repo])
                elif not local_revision:
                    base.update(
                        status="untracked",
                        detail=(
                            "Installed files predate immutable revision tracking; reinstall to "
                            "establish provenance."
                        ),
                    )
                elif local_revision != remote.get("revision"):
                    base.update(
                        status="update-available",
                        detail="The first-party Hub repository has a newer immutable revision.",
                    )
                else:
                    base.update(status="current", detail="Installed revision matches the Hub.")
                results.append(base)
                continue

            endpoint = _ollama_base(profile)
            tag = tags_by_endpoint.get(endpoint, {}).get(profile.model.lower())
            if tag is None and ":" not in profile.model:
                tag = tags_by_endpoint.get(endpoint, {}).get(f"{profile.model.lower()}:latest")
            installed = tag is not None
            local_digest = str((tag or {}).get("digest") or "")
            base.update(installed=installed, local_digest=local_digest)
            if endpoint in endpoint_errors:
                base.update(status="error", detail=endpoint_errors[endpoint])
            elif not installed:
                base.update(status="not-installed", detail="Available for an explicit Ollama download.")
            elif not repo:
                base.update(
                    status="check-unavailable",
                    detail=(
                        "Ollama exposes the local digest but no non-mutating registry freshness API; "
                        "use an explicit download to refresh."
                    ),
                )
            elif repo in hub_errors:
                base.update(status="error", detail=hub_errors[repo])
            else:
                installed_state = tracking.get(profile.id, {})
                tracked_revision = str(installed_state.get("source_revision") or "")
                tracked_digest = str(installed_state.get("local_digest") or "")
                base["local_revision"] = tracked_revision
                if (
                    not tracked_revision
                    or not tracked_digest
                    or not local_digest
                    or tracked_digest != local_digest
                ):
                    base.update(
                        status="untracked",
                        detail=(
                            "The model is installed, but SignalRoom did not perform the download that "
                            "would bind its Ollama digest to a Hub revision. Refresh once to begin tracking."
                        ),
                    )
                elif tracked_revision != remote.get("revision"):
                    base.update(
                        status="update-available",
                        detail="The first-party GGUF repository has a newer immutable revision.",
                    )
                else:
                    base.update(status="current", detail="Tracked Ollama digest matches the Hub revision.")
            results.append(base)

        counts = {
            status: sum(1 for item in results if item["status"] == status)
            for status in {
                "current",
                "update-available",
                "not-installed",
                "untracked",
                "check-unavailable",
                "error",
            }
        }
        return {
            "checked_at": datetime.now(UTC).isoformat(),
            "profiles": results,
            "counts": counts,
            "downloads_started": 0,
            "policy": "Read-only check. SignalRoom never downloads, updates, or swaps a model here.",
        }

    async def _record_ollama_revision(self, profile: ModelProfile) -> dict[str, Any]:
        """Bind a completed explicit Ollama pull to its immutable Hub source revision."""
        repo = _huggingface_repo(profile.model)
        if not repo:
            return {"tracked": False, "reason": "No explicit Hugging Face source repository."}
        endpoint = _ollama_base(profile)
        async with httpx.AsyncClient(timeout=12) as client:
            tags_response, remote = await asyncio.gather(
                client.get(f"{endpoint}/api/tags"),
                self._hub_metadata(client, repo),
            )
            tags_response.raise_for_status()
        tag = next(
            (
                item
                for item in tags_response.json().get("models", [])
                if _model_installed(profile.model, [str(item.get("name") or "")])
            ),
            None,
        )
        if not tag:
            return {"tracked": False, "reason": "Ollama did not report the completed model."}
        local_digest = str(tag.get("digest") or "")
        if not local_digest:
            return {"tracked": False, "reason": "Ollama did not report a content digest."}
        state = self._load_revision_state()
        profiles = state.setdefault("profiles", {})
        profiles[profile.id] = {
            "model": profile.model,
            "source_repo": repo,
            "source_revision": remote["revision"],
            "local_digest": local_digest,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        self._save_revision_state(state)
        return {"tracked": True, **profiles[profile.id]}

    async def readiness(self) -> dict[str, Any]:
        settings = self.config.load()
        ollama_profiles = [profile for profile in settings.models if profile.provider == "ollama"]
        hf_profiles = [profile for profile in settings.models if profile.provider == "huggingface"]
        endpoint = _ollama_base(ollama_profiles[0]) if ollama_profiles else "http://localhost:11434"
        ollama: dict[str, Any] = {
            "ok": False,
            "endpoint": endpoint,
            "version": None,
            "models": [],
            "loaded_models": [],
            "profiles": [],
            "download_url": OLLAMA_DOWNLOAD_URL,
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                tags_response, version_response = await asyncio.gather(
                    client.get(f"{endpoint}/api/tags"),
                    client.get(f"{endpoint}/api/version"),
                )
                tags_response.raise_for_status()
                version_response.raise_for_status()
                try:
                    running_response = await client.get(f"{endpoint}/api/ps")
                    running_response.raise_for_status()
                    loaded = [
                        item.get("name", "")
                        for item in running_response.json().get("models", [])
                    ]
                except (httpx.HTTPError, ValueError):
                    loaded = []
            installed = [item.get("name", "") for item in tags_response.json().get("models", [])]
            ollama.update(
                ok=True,
                version=version_response.json().get("version"),
                models=installed,
                loaded_models=loaded,
            )
        except (httpx.HTTPError, ValueError) as exc:
            ollama["error"] = str(exc)
            installed = []
        ollama["profiles"] = [
            {
                "id": profile.id,
                "label": profile.label,
                "model": profile.model,
                "installed": _model_installed(profile.model, installed),
                "loaded": _model_installed(profile.model, loaded),
                "pullable": bool(profile.enabled),
            }
            for profile in ollama_profiles
        ]

        local_profiles: list[dict[str, Any]] = []
        for profile in hf_profiles:
            model_path = self.config.local_model_path(profile.id)
            manifest_path = model_path / ".signalroom-model.json"
            manifest: dict[str, Any] = {}
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    manifest = {}
            local_profiles.append(
                {
                    "id": profile.id,
                    "label": profile.label,
                    "model": profile.model,
                    "task": profile.task,
                    "installed": local_model_installed(model_path),
                    "path": str(model_path),
                    "bytes": int(manifest.get("bytes") or 0),
                    "downloaded_at": manifest.get("downloaded_at"),
                    "revision": manifest.get("revision"),
                    "context_index": (
                        self.evidence.embedding_status(profile.id)
                        if self.evidence is not None and profile.task == "embedding"
                        else None
                    ),
                }
            )
        local_transformers: dict[str, Any] = {
            "selected": settings.specialist_runtime == "local",
            "runtime_installed": local_runtime_available(),
            "model_root": str(self.config.local_models_root),
            "profiles": local_profiles,
            "network_inference": False,
            "device": "available after runtime install",
            "index_job": self.context_index_job,
        }
        if local_transformers["runtime_installed"]:
            try:
                import torch

                local_transformers["device"] = "CUDA GPU" if torch.cuda.is_available() else "CPU"
            except Exception:
                local_transformers["device"] = "CPU"

        token = self.config.secret("huggingface_token")
        huggingface: dict[str, Any] = {
            "selected": settings.specialist_runtime == "cloud",
            "policy": settings.huggingface_policy,
            "token_configured": bool(token),
            "token_valid": None,
            "profiles": [],
            "token_url": HF_TOKEN_URL,
        }
        hf_enabled = (
            settings.specialist_runtime == "cloud"
            and settings.huggingface_policy != "disabled"
        )
        if token and hf_enabled:
            headers = {"Authorization": f"Bearer {token}"}
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    whoami = await client.get("https://huggingface.co/api/whoami-v2", headers=headers)
                    whoami.raise_for_status()
                huggingface["token_valid"] = True
            except (httpx.HTTPError, ValueError) as exc:
                huggingface["token_valid"] = False
                huggingface["error"] = str(exc)
        for profile in hf_profiles:
            item: dict[str, Any] = {
                "id": profile.id,
                "label": profile.label,
                "model": profile.model,
                "task": profile.task,
                "reachable": None,
            }
            if token and hf_enabled:
                try:
                    async with httpx.AsyncClient(timeout=8) as client:
                        response = await client.get(
                            f"https://huggingface.co/api/models/{profile.model}"
                            "?expand=inferenceProviderMapping",
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        response.raise_for_status()
                    metadata = response.json()
                    item["reachable"] = True
                    item["pipeline_tag"] = metadata.get("pipeline_tag")
                    item["inference_available"] = bool(metadata.get("inferenceProviderMapping"))
                except (httpx.HTTPError, ValueError) as exc:
                    item.update(reachable=False, error=str(exc))
            huggingface["profiles"].append(item)

        return {
            "host_os": platform.system(),
            "ollama": ollama,
            "local_transformers": local_transformers,
            "huggingface": huggingface,
            "ready": ollama["ok"] and any(item["installed"] for item in ollama["profiles"]),
        }

    async def activate(
        self, profile_id: str, unload_other_signalroom_models: bool = True
    ) -> dict[str, Any]:
        """Explicitly load one configured Ollama profile and optionally unload its peers."""
        settings = self.config.load()
        profile = next(
            (
                candidate
                for candidate in settings.models
                if candidate.id == profile_id
                and candidate.provider == "ollama"
                and candidate.enabled
            ),
            None,
        )
        if not profile:
            raise KeyError(f"Enabled Ollama profile not found: {profile_id}")
        endpoint = _ollama_base(profile)
        timeout = httpx.Timeout(connect=10, read=180, write=30, pool=10)
        unloaded: list[str] = []
        async with httpx.AsyncClient(timeout=timeout) as client:
            tags_response = await client.get(f"{endpoint}/api/tags")
            tags_response.raise_for_status()
            installed = [
                item.get("name", "") for item in tags_response.json().get("models", [])
            ]
            if not _model_installed(profile.model, installed):
                raise RuntimeError(f"Ollama model is not installed: {profile.model}")
            if unload_other_signalroom_models:
                try:
                    running_response = await client.get(f"{endpoint}/api/ps")
                    running_response.raise_for_status()
                    loaded = [
                        item.get("name", "")
                        for item in running_response.json().get("models", [])
                    ]
                except (httpx.HTTPError, ValueError):
                    loaded = []
                peers = [
                    candidate
                    for candidate in settings.models
                    if candidate.provider == "ollama"
                    and candidate.id != profile.id
                    and _model_installed(candidate.model, loaded)
                ]
                for peer in peers:
                    response = await client.post(
                        f"{endpoint}/api/generate",
                        json={
                            "model": peer.model,
                            "prompt": "",
                            "stream": False,
                            "keep_alive": 0,
                        },
                    )
                    response.raise_for_status()
                    unloaded.append(peer.model)
            response = await client.post(
                f"{endpoint}/api/generate",
                json={
                    "model": profile.model,
                    "prompt": "",
                    "stream": False,
                    "keep_alive": "15m",
                },
            )
            response.raise_for_status()
            activated = response.json()
            executed_model = str(activated.get("model") or profile.model)
            if not _models_match(profile.model, executed_model):
                raise RuntimeError(
                    f"Ollama loaded '{executed_model}' instead of requested '{profile.model}'"
                )
            try:
                running_response = await client.get(f"{endpoint}/api/ps")
                running_response.raise_for_status()
                loaded_after = [
                    item.get("name", "")
                    for item in running_response.json().get("models", [])
                ]
            except (httpx.HTTPError, ValueError):
                loaded_after = [executed_model]
        return {
            "ok": True,
            "profile_id": profile.id,
            "requested_model": profile.model,
            "executed_model": executed_model,
            "loaded_models": loaded_after,
            "unloaded_models": unloaded,
            "endpoint": endpoint,
        }

    def start_pull(self, profile_id: str) -> dict[str, Any]:
        profile = next(
            (
                candidate
                for candidate in self.config.load().models
                if candidate.id == profile_id and candidate.enabled
            ),
            None,
        )
        if not profile:
            raise KeyError(f"Enabled model profile not found: {profile_id}")
        if profile.provider == "huggingface" and profile.task not in {
            "embedding",
            "ner",
            "reranking",
            "classification",
        }:
            raise KeyError(f"Profile cannot be installed as a local specialist: {profile_id}")
        existing = next(
            (
                job
                for job in self.jobs.values()
                if job["profile_id"] == profile_id and job["status"] in {"queued", "pulling"}
            ),
            None,
        )
        if existing:
            return existing
        job_id = uuid.uuid4().hex
        job = {
            "id": job_id,
            "profile_id": profile.id,
            "model": profile.model,
            "kind": "ollama" if profile.provider == "ollama" else "local-transformers",
            "endpoint": _ollama_base(profile) if profile.provider == "ollama" else "huggingface-hub",
            "path": (
                "" if profile.provider == "ollama" else str(self.config.local_model_path(profile.id))
            ),
            "status": "queued",
            "detail": "Queued",
            "completed": 0,
            "total": 0,
            "progress": 0,
            "created_at": datetime.now(UTC).isoformat(),
        }
        self.jobs[job_id] = job
        asyncio.create_task(self._pull(job_id))
        return job

    def get_job(self, job_id: str) -> dict[str, Any]:
        if job_id not in self.jobs:
            raise KeyError(f"Model pull job not found: {job_id}")
        return self.jobs[job_id]

    async def _pull(self, job_id: str) -> None:
        job = self.jobs[job_id]
        if job["kind"] == "local-transformers":
            await self._install_local_specialist(job)
            return
        job.update(status="pulling", detail="Contacting Ollama")
        try:
            timeout = httpx.Timeout(connect=10, read=None, write=30, pool=10)
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    f"{job['endpoint']}/api/pull",
                    json={"model": job["model"], "stream": True},
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        event = json.loads(line)
                        if event.get("error"):
                            raise RuntimeError(event["error"])
                        completed = int(event.get("completed") or job["completed"])
                        total = int(event.get("total") or job["total"])
                        job.update(
                            detail=event.get("status", job["detail"]),
                            completed=completed,
                            total=total,
                            progress=round(completed * 100 / total) if total else job["progress"],
                        )
            profile = next(
                item for item in self.config.load().models if item.id == job["profile_id"]
            )
            try:
                job["revision_tracking"] = await self._record_ollama_revision(profile)
            except Exception as exc:
                job["revision_tracking"] = {"tracked": False, "reason": str(exc)}
            job.update(status="complete", detail="Model ready", progress=100)
        except (httpx.HTTPError, ValueError, RuntimeError) as exc:
            job.update(status="error", detail=str(exc))

    async def _install_local_specialist(self, job: dict[str, Any]) -> None:
        job.update(status="pulling", detail="Checking the local Transformers runtime", progress=5)
        try:
            if not local_runtime_available():
                job.update(detail="Installing the local inference runtime", progress=10)
                creationflags = 0x08000000 if os.name == "nt" else 0
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    *LOCAL_RUNTIME_PACKAGES,
                    "--disable-pip-version-check",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    creationflags=creationflags,
                )
                if process.stdout:
                    async for line in process.stdout:
                        detail = line.decode("utf-8", errors="replace").strip()
                        if detail:
                            job["detail"] = detail[-240:]
                return_code = await process.wait()
                importlib.invalidate_caches()
                if return_code != 0 or not local_runtime_available():
                    raise RuntimeError("Local Transformers runtime installation failed")

            job.update(
                detail=f"Downloading {job['model']} from Hugging Face to local storage",
                progress=30,
            )
            profile = next(
                profile
                for profile in self.config.load().models
                if profile.id == job["profile_id"]
            )
            model_path = self.config.local_model_path(profile.id)
            model_path.mkdir(parents=True, exist_ok=True)
            token = self.config.secret("huggingface_token") or None

            def download() -> tuple[str, str]:
                from huggingface_hub import HfApi, snapshot_download

                revision = HfApi(token=token).model_info(profile.model).sha

                snapshot = snapshot_download(
                    repo_id=profile.model,
                    revision=revision,
                    local_dir=model_path,
                    token=token,
                    ignore_patterns=[
                        "*.bin",
                        "*.h5",
                        "*.msgpack",
                        "*.onnx",
                        "*.ot",
                    ],
                )
                return snapshot, revision

            download_task = asyncio.create_task(asyncio.to_thread(download))
            elapsed = 0
            while not download_task.done():
                await asyncio.sleep(1)
                elapsed += 1
                job.update(
                    detail=(
                        f"Downloading {profile.label} into SignalRoom local storage · "
                        f"{elapsed}s elapsed"
                    ),
                    progress=min(85, 30 + elapsed // 10),
                )
            _, revision = await download_task
            job.update(detail="Validating the downloaded model", progress=92)
            if not (model_path / "config.json").exists() or not any(
                model_path.glob("*.safetensors")
            ):
                raise RuntimeError("Downloaded snapshot is missing model configuration or weights")
            size = sum(
                item.stat().st_size
                for item in model_path.rglob("*")
                if item.is_file() and ".cache" not in item.parts
            )
            (model_path / ".signalroom-model.json").write_text(
                json.dumps(
                    {
                        "profile_id": profile.id,
                        "model": profile.model,
                        "task": profile.task,
                        "revision": revision,
                        "bytes": size,
                        "downloaded_at": datetime.now(UTC).isoformat(),
                        "runtime": "local-transformers",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            if not local_model_installed(model_path):
                raise RuntimeError("Local model validation failed")
            if profile.task == "embedding" and self.evidence is not None:
                job.update(detail="Indexing SignalRoom Context locally", progress=95)
                await self._backfill_embeddings(profile, job)
            job.update(
                status="complete",
                detail="Local specialist ready · no cloud inference required",
                progress=100,
                total=size,
                completed=size,
            )
        except Exception as exc:
            job.update(status="error", detail=str(exc))

    async def _backfill_embeddings(
        self, profile: ModelProfile, job: dict[str, Any]
    ) -> dict[str, int]:
        if self.evidence is None:
            return {"total_chunks": 0, "indexed_chunks": 0, "pending_chunks": 0}
        provider = LocalTransformersProvider(profile, self.config.local_model_path(profile.id))
        status = self.evidence.embedding_status(profile.id)
        total = status["total_chunks"]
        while True:
            pending = self.evidence.pending_embeddings(profile.id, limit=64)
            if not pending:
                break
            vectors = await provider.document_embeddings([content for _, content in pending])
            values = [
                (chunk_id, vector)
                for (chunk_id, _), vector in zip(pending, vectors, strict=False)
                if vector
            ]
            if not values:
                raise RuntimeError("The local embedding model returned no Context vectors")
            self.evidence.save_embeddings(profile.id, values)
            status = self.evidence.embedding_status(profile.id)
            indexed = status["indexed_chunks"]
            job.update(
                detail=f"Indexed {indexed} of {total} local Context chunks",
                progress=min(99, 95 + round(4 * indexed / max(total, 1))),
                indexed_chunks=indexed,
                context_chunks=total,
            )
        return self.evidence.embedding_status(profile.id)

    def schedule_context_index(self) -> bool:
        """Queue incremental local Context indexing without delaying artifact writes."""
        if self.evidence is None or self.context_index_job.get("status") in {
            "queued",
            "pulling",
        }:
            return False
        settings = self.config.load()
        if settings.specialist_runtime != "local":
            return False
        profile = next(
            (
                item
                for item in settings.models
                if item.id == settings.embedding_model
                and item.enabled
                and item.task == "embedding"
            ),
            None,
        )
        if profile is None or not local_model_installed(self.config.local_model_path(profile.id)):
            return False
        self.context_index_job = {
            "status": "queued",
            "profile_id": profile.id,
            "detail": "Queued incremental Context indexing",
            "progress": 0,
        }
        asyncio.create_task(self._run_context_index(profile, self.context_index_job))
        return True

    async def _run_context_index(
        self, profile: ModelProfile, job: dict[str, Any]
    ) -> None:
        job.update(status="pulling", detail="Indexing new Context locally", progress=5)
        try:
            status = await self._backfill_embeddings(profile, job)
            job.update(
                status="complete",
                detail=f"Indexed {status['indexed_chunks']} local Context chunks",
                progress=100,
                **status,
            )
        except Exception as exc:
            job.update(status="error", detail=str(exc))


async def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Check or download SignalRoom model profiles")
    parser.add_argument("command", choices=["status", "pull"])
    parser.add_argument("profiles", nargs="*", help="Profile IDs; pull defaults to all Ollama profiles")
    args = parser.parse_args()
    root = Path(os.getenv("SIGNALROOM_ROOT", Path.cwd())).resolve()
    data = Path(os.getenv("SIGNALROOM_DATA_DIR", root / "data")).resolve()
    service = ModelSetupService(ConfigStore(data))
    if args.command == "status":
        print(json.dumps(await service.readiness(), indent=2))
        return 0
    settings = service.config.load()
    profile_ids = args.profiles or list(
        dict.fromkeys([settings.default_chat_model, settings.security_reasoning_model])
    )
    for profile_id in profile_ids:
        job = service.start_pull(profile_id)
        while job["status"] in {"queued", "pulling"}:
            print(f"{profile_id}: {job['detail']} ({job['progress']}%)", flush=True)
            await asyncio.sleep(1)
        print(f"{profile_id}: {job['detail']}")
        if job["status"] != "complete":
            return 1
    return 0


def run() -> None:
    raise SystemExit(asyncio.run(_cli()))


if __name__ == "__main__":
    run()
