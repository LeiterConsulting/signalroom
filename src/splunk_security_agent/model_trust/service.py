from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from ..config import ConfigStore
from ..providers.local_transformers import local_model_installed
from ..schemas import ModelProfile, ModelTrustPolicyUpdate
from .signing import ModelTrustSigningKey
from .store import ModelTrustStore


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _ollama_base(profile: ModelProfile) -> str:
    value = (profile.endpoint or "http://localhost:11434").rstrip("/")
    for suffix in ("/api/chat", "/api/tags", "/v1"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    return value


def _huggingface_repo(model: str) -> str:
    lowered = model.lower()
    if lowered.startswith("hf.co/"):
        value = model[6:].split(":", 1)[0]
        return value if value.count("/") == 1 else ""
    return model if model.count("/") == 1 else ""


def _source(profile: ModelProfile) -> dict[str, str]:
    repo = _huggingface_repo(profile.model)
    if repo:
        return {
            "source_repo": repo,
            "publisher": repo.split("/", 1)[0].lower(),
            "publisher_basis": "explicit-huggingface-repository",
        }
    if profile.provider == "ollama":
        name = profile.model.split(":", 1)[0]
        return {
            "source_repo": f"ollama-library/{name}",
            "publisher": "ollama-library",
            "publisher_basis": "configured-ollama-library-namespace",
        }
    return {
        "source_repo": "",
        "publisher": "unknown",
        "publisher_basis": "unresolved",
    }


class ModelTrustService:
    """Observe, approve, sign, and enforce exact local model artifact identities."""

    def __init__(
        self,
        config: ConfigStore,
        store: ModelTrustStore,
        signing_key_path: Path | str,
        attestation_dir: Path | str,
    ):
        self.config = config
        self.store = store
        self.signing_key = ModelTrustSigningKey(signing_key_path)
        self.attestation_dir = Path(attestation_dir)
        self.attestation_dir.mkdir(parents=True, exist_ok=True)
        self._ollama_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._ollama_locks: dict[str, asyncio.Lock] = {}

    def policy(self) -> dict[str, Any]:
        value = self.store.policy()
        return {
            **value,
            "key_id": self.signing_key.key_id(),
            "algorithm": "Ed25519",
            "default_mode": "audit",
            "enforcement_points": [
                "model activation",
                "golden baseline acceptance",
                "tournament promotion",
                "tournament rollback",
            ],
        }

    async def overview(self, *, verify_files: bool = False) -> dict[str, Any]:
        settings = self.config.load()
        if verify_files:
            endpoints = {
                _ollama_base(profile)
                for profile in settings.models
                if profile.provider == "ollama"
            }
            await asyncio.gather(
                *(
                    self._ollama_tags(endpoint, fresh=True)
                    for endpoint in endpoints
                ),
                return_exceptions=True,
            )
        observations = await asyncio.gather(
            *(
                self.observe(
                    profile.id,
                    verify_files=(
                        verify_files and profile.provider == "huggingface"
                    ),
                )
                for profile in settings.models
            ),
            return_exceptions=True,
        )
        profiles = []
        for profile, observed in zip(settings.models, observations, strict=True):
            if isinstance(observed, Exception):
                identity = self._base_identity(profile)
                assessment = self.assess(identity)
                assessment.update(status="error", detail=str(observed), allowed=False)
            else:
                assessment = self.assess(observed)
            profiles.append(assessment)
        counts = {
            status: sum(1 for item in profiles if item["status"] == status)
            for status in {
                "approved",
                "unapproved",
                "drifted",
                "unverifiable",
                "publisher-blocked",
                "invalid-attestation",
                "not-installed",
                "error",
            }
        }
        return {
            "policy": self.policy(),
            "profiles": profiles,
            "counts": counts,
            "attestations": [
                self._public_attestation(item)
                for item in self.store.list_attestations(50)
            ],
            "verified_files": verify_files,
            "checked_at": datetime.now(UTC).isoformat(),
            "contract": (
                "A SignalRoom signature proves local operator approval of an exact observed "
                "artifact. It is not a publisher signature or a software-vulnerability verdict."
            ),
        }

    async def observe(
        self, profile_id: str, *, verify_files: bool = False
    ) -> dict[str, Any]:
        profile = self._profile(profile_id)
        identity = self._base_identity(profile)
        if profile.provider == "huggingface":
            model_path = self.config.local_model_path(profile.id)
            manifest_path = model_path / ".signalroom-model.json"
            installed = local_model_installed(model_path)
            identity["installed"] = installed
            if not installed:
                return self._fingerprinted(identity)
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                manifest = {}
            identity["source_revision"] = str(manifest.get("revision") or "")
            identity["runtime"] = str(
                manifest.get("runtime") or "local-transformers"
            )
            artifact_digest = str(manifest.get("artifact_sha256") or "")
            if verify_files or not artifact_digest:
                artifact = await asyncio.to_thread(self.hash_local_artifact, model_path)
                artifact_digest = artifact["artifact_sha256"]
                identity["file_count"] = artifact["file_count"]
                recorded = str(manifest.get("artifact_sha256") or "")
                identity["integrity"] = (
                    "verified"
                    if not recorded or recorded == artifact_digest
                    else "mismatch"
                )
            else:
                identity["integrity"] = "manifest-only"
                identity["file_count"] = int(manifest.get("file_count") or 0)
            identity["artifact_digest"] = artifact_digest
            identity["verifiable"] = bool(
                identity["source_revision"]
                and artifact_digest
                and identity["integrity"] != "mismatch"
            )
            return self._fingerprinted(identity)

        endpoint = _ollama_base(profile)
        tags = await self._ollama_tags(endpoint, fresh=verify_files)
        tag = next(
            (
                item
                for item in tags
                if self._models_match(
                    profile.model, str(item.get("name") or "")
                )
            ),
            None,
        )
        identity["installed"] = tag is not None
        identity["runtime"] = "ollama"
        if tag:
            identity["artifact_digest"] = str(tag.get("digest") or "")
            tracking = self._revision_state().get("profiles", {}).get(
                profile.id, {}
            )
            identity["source_revision"] = str(
                tracking.get("source_revision") or ""
            )
            identity["tracked_digest"] = str(tracking.get("local_digest") or "")
            identity["integrity"] = (
                "verified"
                if identity["artifact_digest"]
                and (
                    not identity["tracked_digest"]
                    or identity["tracked_digest"] == identity["artifact_digest"]
                )
                else "mismatch"
                if identity["tracked_digest"]
                else "unverifiable"
            )
            identity["verifiable"] = bool(
                identity["artifact_digest"] and identity["integrity"] != "mismatch"
            )
        return self._fingerprinted(identity)

    async def _ollama_tags(
        self, endpoint: str, *, fresh: bool = False
    ) -> list[dict[str, Any]]:
        lock = self._ollama_locks.setdefault(endpoint, asyncio.Lock())
        async with lock:
            cached = self._ollama_cache.get(endpoint)
            if not fresh and cached and time.monotonic() - cached[0] < 3:
                return cached[1]
            async with httpx.AsyncClient(timeout=8) as client:
                response = await client.get(f"{endpoint}/api/tags")
                response.raise_for_status()
            tags = [
                item
                for item in response.json().get("models", [])
                if isinstance(item, dict)
            ]
            self._ollama_cache[endpoint] = (time.monotonic(), tags)
            return tags

    def assess(self, identity: dict[str, Any]) -> dict[str, Any]:
        policy = self.store.policy()
        profile_id = str(identity.get("profile_id") or "")
        fingerprint = str(identity.get("identity_fingerprint") or "")
        publisher = str(identity.get("publisher") or "").lower()
        publisher_allowed = publisher in policy["allowed_publishers"]
        attestation = (
            self.store.active_for_fingerprint(profile_id, fingerprint)
            if fingerprint
            else None
        )
        signature_valid = bool(
            attestation and self._verify_attestation(attestation)
        )
        any_active = self.store.active_for_profile(profile_id)
        trusted = bool(
            identity.get("installed")
            and identity.get("verifiable")
            and publisher_allowed
            and signature_valid
        )
        if not identity.get("installed"):
            status = "not-installed"
            detail = "No local artifact is installed for this profile."
        elif not identity.get("verifiable"):
            status = "unverifiable"
            detail = (
                "The local artifact does not expose a trustworthy immutable digest "
                "or its recorded integrity does not match."
            )
        elif not publisher_allowed:
            status = "publisher-blocked"
            detail = f"Publisher '{publisher}' is not on the local allowlist."
        elif trusted:
            status = "approved"
            detail = "The exact current artifact matches a valid operator-signed attestation."
        elif attestation and not signature_valid:
            status = "invalid-attestation"
            detail = (
                "The exact artifact has an approval record, but its local signature "
                "does not verify. Re-approve only after investigating local state."
            )
        elif any_active:
            status = "drifted"
            detail = (
                "The installed digest or revision differs from the active signed "
                "attestation. Re-evaluate before approving the new artifact."
            )
        else:
            status = "unapproved"
            detail = "The exact local artifact has not been approved and signed."
        allowed = trusted or policy["mode"] == "audit"
        return {
            **identity,
            "status": status,
            "detail": detail,
            "trusted": trusted,
            "allowed": allowed,
            "policy_mode": policy["mode"],
            "publisher_allowed": publisher_allowed,
            "attestation": (
                self._public_attestation(attestation) if attestation else None
            ),
            "signature_valid": signature_valid,
        }

    async def approve(
        self, profile_id: str, expected_fingerprint: str, actor: str
    ) -> dict[str, Any]:
        identity = await self.observe(profile_id, verify_files=True)
        if identity.get("identity_fingerprint") != expected_fingerprint:
            raise ValueError(
                "The model artifact changed after review; refresh trust status and try again"
            )
        assessment = self.assess(identity)
        if not identity.get("installed") or not identity.get("verifiable"):
            raise ValueError("Only an installed, exactly verifiable artifact can be approved")
        if not assessment["publisher_allowed"]:
            raise ValueError(
                f"Publisher '{identity.get('publisher')}' is not on the allowlist"
            )
        approved_at = datetime.now(UTC).isoformat()
        payload = {
            "schema_version": "signalroom-model-attestation/v1",
            "identity": identity,
            "identity_fingerprint": expected_fingerprint,
            "approved_by": actor or "local-operator",
            "approved_at": approved_at,
            "policy_generation": self.store.policy()["generation"],
            "signing": {
                "algorithm": "Ed25519",
                "key_id": self.signing_key.key_id(),
            },
            "authority": {
                "local_operator_approval": True,
                "publisher_signature": False,
                "vulnerability_assessment": False,
            },
        }
        signature = self.signing_key.sign(_canonical(payload))
        existing = self.store.active_for_fingerprint(
            profile_id, expected_fingerprint
        )
        if existing and not self._verify_attestation(existing):
            self.store.revoke(existing["id"])
        attestation = self.store.create_attestation(
            profile_id=profile_id,
            identity_fingerprint=expected_fingerprint,
            identity=identity,
            payload=payload,
            signature=signature,
            key_id=self.signing_key.key_id(),
            approved_by=actor or "local-operator",
        )
        self._write_attestation(attestation)
        return self.assess(identity)

    def revoke(self, attestation_id: str) -> dict[str, Any]:
        value = self.store.revoke(attestation_id)
        if value is None:
            raise KeyError("Active model artifact attestation not found")
        payload = {
            "schema_version": "signalroom-model-attestation-revocation/v1",
            "attestation_id": value["id"],
            "profile_id": value["profile_id"],
            "identity_fingerprint": value["identity_fingerprint"],
            "revoked_at": value["revoked_at"],
            "signing": {
                "algorithm": "Ed25519",
                "key_id": self.signing_key.key_id(),
            },
        }
        root = self.attestation_dir / value["profile_id"]
        root.mkdir(parents=True, exist_ok=True)
        (root / f"{value['identity_fingerprint']}.revocation.json").write_text(
            json.dumps(
                {
                    "payload": payload,
                    "signature": self.signing_key.sign(_canonical(payload)),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return self._public_attestation(value)

    async def update_policy(
        self, value: ModelTrustPolicyUpdate
    ) -> dict[str, Any]:
        if value.mode == "enforce":
            settings = self.config.load()
            required = {
                settings.default_chat_model,
                settings.security_reasoning_model,
            }
            try:
                observations = [
                    self.assess(await self.observe(profile_id, verify_files=True))
                    for profile_id in sorted(required)
                ]
            except Exception as exc:
                raise ValueError(
                    f"Enforcement preflight could not verify the active routes: {exc}"
                ) from exc
            blockers = [
                f"{item['profile_id']}: {item['detail']}"
                for item in observations
                if not item["trusted"]
                or item["publisher"] not in {
                    publisher.lower() for publisher in value.allowed_publishers
                }
            ]
            if blockers:
                raise ValueError(
                    "Enforcement requires trusted current routing artifacts: "
                    + "; ".join(blockers)
                )
        return self.store.update_policy(value)

    async def require_profile(
        self, profile_id: str, purpose: str
    ) -> dict[str, Any]:
        try:
            identity = await self.observe(profile_id, verify_files=True)
        except KeyError:
            raise
        except Exception as exc:
            raise ValueError(
                f"Model trust could not verify {profile_id} for {purpose}: {exc}"
            ) from exc
        assessment = self.assess(identity)
        if self.store.policy()["mode"] == "enforce" and not assessment["trusted"]:
            raise PermissionError(
                f"Model trust blocked {purpose}: {assessment['detail']}"
            )
        return assessment

    async def assert_binding(
        self,
        profile_id: str,
        recorded_binding: dict[str, Any],
        purpose: str,
    ) -> dict[str, Any]:
        current = await self.require_profile(profile_id, purpose)
        recorded = str(recorded_binding.get("identity_fingerprint") or "")
        if recorded and recorded != current.get("identity_fingerprint"):
            raise ValueError(
                f"Model artifact changed after evaluation; run a fresh {purpose}"
            )
        if self.store.policy()["mode"] == "enforce" and not recorded:
            raise PermissionError(
                f"Model trust blocked {purpose}: evaluation has no artifact binding"
            )
        return current

    def validate_source(self, profile: ModelProfile, purpose: str) -> dict[str, Any]:
        source = _source(profile)
        policy = self.store.policy()
        allowed = source["publisher"] in policy["allowed_publishers"]
        if policy["mode"] == "enforce" and not allowed:
            raise PermissionError(
                f"Model trust blocked {purpose}: publisher "
                f"'{source['publisher']}' is not allowed"
            )
        return {**source, "publisher_allowed": allowed, "policy_mode": policy["mode"]}

    def gate(
        self, gate: dict[str, Any], binding: dict[str, Any]
    ) -> dict[str, Any]:
        result = {
            **gate,
            "blockers": list(gate.get("blockers") or []),
            "warnings": list(gate.get("warnings") or []),
            "model_trust": {
                key: binding.get(key)
                for key in (
                    "status",
                    "trusted",
                    "policy_mode",
                    "identity_fingerprint",
                    "publisher",
                    "source_revision",
                    "artifact_digest",
                )
            },
        }
        if binding.get("policy_mode") == "enforce" and not binding.get("trusted"):
            result["blockers"].append(
                f"Model artifact trust is not satisfied: {binding.get('detail', 'unapproved')}."
            )
        elif not binding.get("trusted"):
            result["warnings"].append(
                f"Audit-only model trust: {binding.get('detail', 'unapproved artifact')}."
            )
        result["ready"] = not result["blockers"]
        result["decision"] = "ready-to-promote" if result["ready"] else "hold"
        result["label"] = (
            "All promotion controls passed; analyst acceptance is still explicit."
            if result["ready"]
            else "Promotion is blocked until every required control passes."
        )
        return result

    @staticmethod
    def hash_local_artifact(model_path: Path) -> dict[str, Any]:
        files: dict[str, str] = {}
        for path in sorted(model_path.rglob("*")):
            if (
                not path.is_file()
                or ".cache" in path.parts
                or path.name.startswith(".signalroom-")
            ):
                continue
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            files[path.relative_to(model_path).as_posix()] = digest.hexdigest()
        artifact_sha256 = hashlib.sha256(_canonical(files)).hexdigest()
        return {
            "artifact_sha256": artifact_sha256,
            "file_count": len(files),
            "files": files,
        }

    def _base_identity(self, profile: ModelProfile) -> dict[str, Any]:
        return {
            "schema_version": "signalroom-model-identity/v1",
            "profile_id": profile.id,
            "provider": profile.provider,
            "model": profile.model,
            "task": profile.task,
            **_source(profile),
            "runtime": "",
            "installed": False,
            "source_revision": "",
            "artifact_digest": "",
            "integrity": "unverifiable",
            "verifiable": False,
        }

    @staticmethod
    def _fingerprinted(identity: dict[str, Any]) -> dict[str, Any]:
        value = dict(identity)
        payload = {
            key: value.get(key)
            for key in (
                "schema_version",
                "profile_id",
                "provider",
                "model",
                "task",
                "source_repo",
                "publisher",
                "publisher_basis",
                "runtime",
                "source_revision",
                "artifact_digest",
            )
        }
        value["identity_fingerprint"] = (
            hashlib.sha256(_canonical(payload)).hexdigest()
            if value.get("installed") and value.get("artifact_digest")
            else ""
        )
        return value

    def _profile(self, profile_id: str) -> ModelProfile:
        profile = next(
            (
                item
                for item in self.config.load().models
                if item.id == profile_id and item.enabled
            ),
            None,
        )
        if profile is None:
            raise KeyError(f"Enabled model profile not found: {profile_id}")
        return profile

    def _revision_state(self) -> dict[str, Any]:
        path = self.config.root / "model_revisions.json"
        if not path.exists():
            return {"profiles": {}}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"profiles": {}}
        except (OSError, ValueError):
            return {"profiles": {}}

    def _verify_attestation(self, value: dict[str, Any]) -> bool:
        payload = value.get("payload") or {}
        return bool(
            value.get("key_id") == self.signing_key.key_id()
            and payload.get("identity_fingerprint")
            == value.get("identity_fingerprint")
            and payload.get("signing", {}).get("key_id") == value.get("key_id")
            and self.signing_key.verify(
                _canonical(payload), str(value.get("signature") or "")
            )
        )

    def _write_attestation(self, value: dict[str, Any]) -> None:
        root = self.attestation_dir / value["profile_id"]
        root.mkdir(parents=True, exist_ok=True)
        stem = value["identity_fingerprint"]
        (root / f"{stem}.json").write_text(
            json.dumps(value["payload"], indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (root / f"{stem}.sig").write_text(
            f"{value['signature']}\n", encoding="ascii"
        )
        public_path = self.attestation_dir / "signalroom-model-trust.pub"
        if not public_path.exists():
            public_path.write_bytes(self.signing_key.public_pem())

    @staticmethod
    def _public_attestation(value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value.get(key)
            for key in (
                "id",
                "profile_id",
                "identity_fingerprint",
                "key_id",
                "status",
                "approved_by",
                "approved_at",
                "revoked_at",
            )
        } | {
            "publisher": value.get("identity", {}).get("publisher", ""),
            "source_revision": value.get("identity", {}).get(
                "source_revision", ""
            ),
            "artifact_digest": value.get("identity", {}).get(
                "artifact_digest", ""
            ),
        }

    @staticmethod
    def _models_match(requested: str, actual: str) -> bool:
        requested_lower = requested.lower()
        actual_lower = actual.lower()
        return requested_lower == actual_lower or (
            ":" not in requested_lower
            and actual_lower == f"{requested_lower}:latest"
        )
