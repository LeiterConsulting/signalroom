from __future__ import annotations

import hashlib
import json

import pytest

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.model_trust import ModelTrustService, ModelTrustStore
from splunk_security_agent.schemas import ModelTrustPolicyUpdate


def artifact_identity(
    profile_id: str,
    *,
    digest: str = "a" * 64,
    publisher: str | None = None,
) -> dict:
    publisher = publisher or (
        "ollama-library" if profile_id == "ollama-general" else "fdtn-ai"
    )
    model = (
        "llama3.1:8b"
        if profile_id == "ollama-general"
        else "hf.co/fdtn-ai/Foundation-Sec-8B-GGUF:Q4"
    )
    identity = {
        "schema_version": "signalroom-model-identity/v1",
        "profile_id": profile_id,
        "provider": "ollama",
        "model": model,
        "task": "chat" if profile_id == "ollama-general" else "security_reasoning",
        "source_repo": f"{publisher}/model",
        "publisher": publisher,
        "publisher_basis": "synthetic-test-identity",
        "runtime": "ollama",
        "installed": True,
        "source_revision": "1" * 40,
        "artifact_digest": digest,
        "integrity": "verified",
        "verifiable": True,
    }
    payload = {
        key: identity.get(key)
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
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    identity["identity_fingerprint"] = hashlib.sha256(canonical).hexdigest()
    return identity


def trust_service(tmp_path):
    config = ConfigStore(tmp_path / "config")
    store = ModelTrustStore(tmp_path / "model_trust.db")
    service = ModelTrustService(
        config,
        store,
        tmp_path / "model_trust.key",
        tmp_path / "attestations",
    )
    return config, store, service


@pytest.mark.asyncio
async def test_exact_artifact_approval_is_signed_and_drift_is_detected(
    tmp_path, monkeypatch
):
    _config, store, service = trust_service(tmp_path)
    current = artifact_identity("foundation-sec")

    async def observe(_profile_id, *, verify_files=False):
        assert verify_files is True
        return current

    monkeypatch.setattr(service, "observe", observe)
    result = await service.approve(
        "foundation-sec", current["identity_fingerprint"], "security-admin"
    )

    assert result["status"] == "approved"
    assert result["trusted"] is True
    assert result["signature_valid"] is True
    assert result["attestation"]["approved_by"] == "security-admin"
    attestation = store.get_attestation(result["attestation"]["id"])
    assert attestation is not None
    assert service._verify_attestation(attestation) is True
    assert (
        tmp_path
        / "attestations"
        / "foundation-sec"
        / f"{current['identity_fingerprint']}.sig"
    ).exists()
    revoked = service.revoke(result["attestation"]["id"])
    assert revoked["status"] == "revoked"
    assert (
        tmp_path
        / "attestations"
        / "foundation-sec"
        / f"{current['identity_fingerprint']}.revocation.json"
    ).exists()
    result = await service.approve(
        "foundation-sec", current["identity_fingerprint"], "security-admin"
    )
    assert result["trusted"] is True

    current = artifact_identity("foundation-sec", digest="b" * 64)
    drifted = service.assess(current)
    assert drifted["status"] == "drifted"
    assert drifted["trusted"] is False


@pytest.mark.asyncio
async def test_enforcement_requires_approved_routing_artifacts_and_blocks_drift(
    tmp_path, monkeypatch
):
    _config, _store, service = trust_service(tmp_path)
    identities = {
        profile_id: artifact_identity(profile_id)
        for profile_id in ("ollama-general", "foundation-sec")
    }

    async def observe(profile_id, *, verify_files=False):
        return identities[profile_id]

    monkeypatch.setattr(service, "observe", observe)
    with pytest.raises(ValueError, match="trusted current routing artifacts"):
        await service.update_policy(
            ModelTrustPolicyUpdate(mode="enforce")
        )

    for profile_id, identity in identities.items():
        await service.approve(
            profile_id, identity["identity_fingerprint"], "security-admin"
        )
    policy = await service.update_policy(
        ModelTrustPolicyUpdate(mode="enforce")
    )
    assert policy["mode"] == "enforce"
    assert (await service.require_profile("foundation-sec", "activation"))[
        "trusted"
    ]

    identities["foundation-sec"] = artifact_identity(
        "foundation-sec", digest="c" * 64
    )
    with pytest.raises(PermissionError, match="blocked activation"):
        await service.require_profile("foundation-sec", "activation")


@pytest.mark.asyncio
async def test_tampered_attestation_is_not_trusted(tmp_path, monkeypatch):
    _config, store, service = trust_service(tmp_path)
    identity = artifact_identity("foundation-sec")

    async def observe(_profile_id, *, verify_files=False):
        return identity

    monkeypatch.setattr(service, "observe", observe)
    approved = await service.approve(
        "foundation-sec", identity["identity_fingerprint"], "security-admin"
    )
    with store.connect() as db:
        db.execute(
            "UPDATE model_artifact_attestations SET signature=? WHERE id=?",
            ("not-a-valid-signature", approved["attestation"]["id"]),
        )
    assessment = service.assess(identity)
    assert assessment["trusted"] is False
    assert assessment["signature_valid"] is False
    assert assessment["status"] == "invalid-attestation"


def test_publisher_allowlist_blocks_unknown_sources_only_in_enforcement(
    tmp_path,
):
    config, store, service = trust_service(tmp_path)
    profile = next(
        item for item in config.load().models if item.provider == "huggingface"
    ).model_copy(
        update={"model": "unknown-org/custom-model:latest"}
    )
    audit = service.validate_source(profile, "installation")
    assert audit["publisher_allowed"] is False
    assert audit["policy_mode"] == "audit"

    store.update_policy(
        ModelTrustPolicyUpdate(
            mode="enforce",
            allowed_publishers=["fdtn-ai", "cisco-ai"],
        )
    )
    with pytest.raises(PermissionError, match="publisher"):
        service.validate_source(profile, "installation")


def test_local_artifact_hash_excludes_signalroom_metadata(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_text('{"model":"test"}', encoding="utf-8")
    (model / "weights.safetensors").write_bytes(b"weights")
    first = ModelTrustService.hash_local_artifact(model)
    (model / ".signalroom-model.json").write_text('{"revision":"x"}', encoding="utf-8")
    second = ModelTrustService.hash_local_artifact(model)
    assert first == second
    (model / "weights.safetensors").write_bytes(b"changed")
    assert ModelTrustService.hash_local_artifact(model)["artifact_sha256"] != first[
        "artifact_sha256"
    ]
