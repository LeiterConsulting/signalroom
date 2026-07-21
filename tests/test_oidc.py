from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from splunk_security_agent.audit import AuditStore
from splunk_security_agent.auth import AuthService, AuthStore, OIDCError, OIDCService
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.schemas import AuthOIDCPolicyUpdate, AuthUserUpdate


def identity_services(tmp_path):
    store = AuthStore(tmp_path / "auth.db")
    audit = AuditStore(tmp_path / "audit.db")
    auth = AuthService(store, audit)
    config = ConfigStore(tmp_path / "config")
    oidc = OIDCService(store, auth, config, audit)
    session = auth.bootstrap(
        username="local-admin",
        display_name="Local Admin",
        password="local recovery password",
        source="127.0.0.1",
    )
    return store, auth, config, oidc, session


def policy(**overrides) -> AuthOIDCPolicyUpdate:
    values = {
        "enabled": True,
        "provider_label": "Security identity",
        "issuer_url": "https://identity.example",
        "client_id": "signalroom-client",
        "redirect_uri": "http://localhost:8000/api/auth/oidc/callback",
        "username_claim": "preferred_username",
        "display_name_claim": "name",
        "groups_claim": "groups",
        "tenant_claim": "tid",
        "allowed_tenant_values": ["tenant-security"],
        "allowed_groups": ["signalroom-users"],
        "analyst_groups": ["soc-analysts"],
        "admin_groups": ["signalroom-admins"],
        "default_role": "viewer",
        "grant_primary_connection": True,
        "required_amr_values": ["mfa"],
    }
    values.update(overrides)
    return AuthOIDCPolicyUpdate(**values)


@pytest.mark.asyncio
async def test_oidc_pkce_token_validation_and_subject_binding(tmp_path, monkeypatch) -> None:
    store, auth, config, oidc, local_session = identity_services(tmp_path)
    config.update_secrets(oidc_client_secret="client-secret")
    await oidc.update_policy(policy(), actor=local_session["user"])

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "signing-key-1", "alg": "RS256", "use": "sig"})
    metadata = {
        "issuer": "https://identity.example",
        "authorization_endpoint": "https://identity.example/authorize",
        "token_endpoint": "https://identity.example/token",
        "jwks_uri": "https://identity.example/keys",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }
    oidc._metadata_cache = (time.monotonic() + 600, metadata)
    oidc._jwks_cache = (time.monotonic() + 600, {"keys": [public_jwk]})
    transaction = await oidc.begin(source="127.0.0.1")
    query = parse_qs(urlparse(transaction["authorization_url"]).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]
    assert query["state"] == [transaction["state"]]

    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://identity.example",
            "aud": "signalroom-client",
            "sub": "immutable-provider-subject",
            "iat": now,
            "exp": now + 300,
            "nonce": query["nonce"][0],
            "preferred_username": "alice",
            "name": "Alice Analyst",
            "groups": ["signalroom-users", "soc-analysts"],
            "tid": "tenant-security",
            "amr": ["pwd", "mfa"],
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "signing-key-1"},
    )

    async def exchange(*_args, **_kwargs):
        return {"id_token": token, "access_token": "never-persist-this"}

    monkeypatch.setattr(oidc, "_exchange", exchange)
    session = await oidc.complete(
        code="single-use-code",
        state=transaction["state"],
        state_cookie=transaction["state"],
        source="127.0.0.1",
    )
    assert session["user"]["role"] == "analyst"
    assert session["user"]["connection_ids"] == ["primary"]
    assert session["user"]["auth_source"] == "oidc"
    assert session["user"]["username"].startswith("alice-")
    external = store.get_user_by_external_identity(
        "https://identity.example", "immutable-provider-subject"
    )
    assert external is not None
    assert external["username"] != "alice"
    assert auth.authenticate(session["token"])["user"]["auth_source"] == "oidc"

    with pytest.raises(OIDCError, match="already used"):
        await oidc.complete(
            code="replayed-code",
            state=transaction["state"],
            state_cookie=transaction["state"],
            source="127.0.0.1",
        )

    denied_transaction = await oidc.begin(source="127.0.0.1")
    denied_query = parse_qs(urlparse(denied_transaction["authorization_url"]).query)
    denied_token = jwt.encode(
        {
            "iss": "https://identity.example",
            "aud": "signalroom-client",
            "sub": "immutable-provider-subject",
            "iat": now,
            "exp": now + 300,
            "nonce": denied_query["nonce"][0],
            "preferred_username": "alice",
            "name": "Alice Analyst",
            "groups": ["group-no-longer-admitted"],
            "tid": "tenant-security",
            "amr": ["mfa"],
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "signing-key-1"},
    )

    async def denied_exchange(*_args, **_kwargs):
        return {"id_token": denied_token}

    monkeypatch.setattr(oidc, "_exchange", denied_exchange)
    with pytest.raises(OIDCError, match="admitted SignalRoom group"):
        await oidc.complete(
            code="newly-denied-code",
            state=denied_transaction["state"],
            state_cookie=denied_transaction["state"],
            source="127.0.0.1",
        )
    assert auth.authenticate(session["token"]) is None
    assert any(
        event["event_type"] == "auth.oidc.identity.deauthorized"
        for event in oidc.audit.events(limit=20)
    )


@pytest.mark.asyncio
async def test_oidc_policy_requires_mfa_and_local_recovery_admin(tmp_path) -> None:
    store, auth, config, oidc, local_session = identity_services(tmp_path)
    config.update_secrets(oidc_client_secret="client-secret")
    with pytest.raises(ValueError, match="ACR or AMR"):
        await oidc.update_policy(
            policy(required_amr_values=[], required_acr_values=[]),
            actor=local_session["user"],
        )

    external = store.upsert_external_user(
        issuer="https://identity.example",
        subject="admin-subject",
        username="enterprise-admin-1234567890",
        display_name="Enterprise Admin",
        role="admin",
        connection_ids=["primary"],
        claims={"groups": ["signalroom-admins"]},
    )
    with pytest.raises(ValueError, match="local break-glass"):
        auth.update_user(
            local_session["user"]["id"],
            AuthUserUpdate(role="analyst"),
            actor=local_session["user"],
        )
    with pytest.raises(ValueError, match="managed by enterprise group policy"):
        auth.update_user(
            external["id"],
            AuthUserUpdate(role="viewer"),
            actor=local_session["user"],
        )
    updated = auth.update_user(
        external["id"],
        AuthUserUpdate(active=False),
        actor=local_session["user"],
    )
    assert updated["active"] is False


def test_oidc_admission_fails_closed_on_tenant_group_and_mfa() -> None:
    current = policy().model_dump()
    valid_claims = {
        "groups": ["signalroom-users", "signalroom-admins"],
        "tid": "tenant-security",
        "amr": ["pwd", "mfa"],
    }
    admitted = OIDCService._admit(valid_claims, current)
    assert admitted["role"] == "admin"
    assert admitted["connection_ids"] == ["primary"]

    with pytest.raises(OIDCError, match="admitted SignalRoom group"):
        OIDCService._admit({**valid_claims, "groups": ["other"]}, current)
    with pytest.raises(OIDCError, match="admitted tenant"):
        OIDCService._admit({**valid_claims, "tid": "other"}, current)
    with pytest.raises(OIDCError, match="required MFA"):
        OIDCService._admit({**valid_claims, "amr": ["pwd"]}, current)


def test_oidc_groups_map_independently_to_current_splunk_aliases() -> None:
    current = policy(
        grant_primary_connection=False,
        connection_group_mappings=[
            {"connection_alias": "primary", "groups": ["tier-one-soc"]},
            {"connection_alias": "eu-prod", "groups": ["eu-hunters"]},
        ],
    ).model_dump()
    claims = {
        "groups": ["signalroom-users", "soc-analysts", "tier-one-soc", "eu-hunters"],
        "tid": "tenant-security",
        "amr": ["mfa"],
    }

    admitted = OIDCService._admit(
        claims,
        current,
        available_connection_ids=["primary", "eu-prod"],
    )

    assert admitted["role"] == "analyst"
    assert admitted["connection_ids"] == ["primary", "eu-prod"]
    assert admitted["matched_connection_groups"] == {
        "primary": ["tier-one-soc"],
        "eu-prod": ["eu-hunters"],
    }
    filtered = OIDCService._admit(
        claims,
        current,
        available_connection_ids=["primary"],
    )
    assert filtered["connection_ids"] == ["primary"]


@pytest.mark.asyncio
async def test_oidc_connection_policy_validates_aliases_and_previews_last_claims(
    tmp_path,
) -> None:
    store = AuthStore(tmp_path / "mapped-auth.db")
    audit = AuditStore(tmp_path / "mapped-audit.db")
    auth = AuthService(
        store,
        audit,
        lambda: [
            {"id": "primary", "label": "Primary Splunk"},
            {"id": "eu-prod", "label": "EU Production"},
        ],
    )
    config = ConfigStore(tmp_path / "mapped-config")
    oidc = OIDCService(store, auth, config, audit)
    local = auth.bootstrap(
        username="mapped-admin",
        display_name="Mapped Admin",
        password="local mapped recovery password",
        source="127.0.0.1",
    )
    config.update_secrets(oidc_client_secret="client-secret")
    with pytest.raises(ValueError, match="not currently configured"):
        await oidc.update_policy(
            policy(
                connection_group_mappings=[
                    {"connection_alias": "retired", "groups": ["retired-team"]}
                ]
            ),
            actor=local["user"],
        )

    external = store.upsert_external_user(
        issuer="https://identity.example",
        subject="eu-analyst-subject",
        username="eu-analyst-1234567890",
        display_name="EU Analyst",
        role="viewer",
        connection_ids=[],
        claims={
            "groups": ["signalroom-users", "soc-analysts", "eu-hunters"],
            "tenant": "tenant-security",
            "acr": "",
            "amr": ["mfa"],
        },
    )
    external_session = auth.federated_session(external)
    status = await oidc.update_policy(
        policy(
            grant_primary_connection=False,
            connection_group_mappings=[
                {
                    "connection_alias": "eu-prod",
                    "groups": ["eu-hunters", "eu-hunters"],
                }
            ],
        ),
        actor=local["user"],
    )

    assert auth.authenticate(external_session["token"]) is None
    assert status["policy"]["connection_group_mappings"] == [
        {"connection_alias": "eu-prod", "groups": ["eu-hunters"]}
    ]
    assert status["connection_catalog"][1] == {
        "id": "eu-prod",
        "label": "EU Production",
        "groups": ["eu-hunters"],
        "available": True,
    }
    preview = status["assignment_preview"]["rows"][0]
    assert preview["admitted"] is True
    assert preview["projected_role"] == "analyst"
    assert preview["projected_connection_ids"] == ["eu-prod"]
    assert preview["current_connection_ids"] == []


def test_host_recovery_is_local_only_and_revokes_sessions(tmp_path) -> None:
    store, auth, _config, _oidc, local_session = identity_services(tmp_path)
    external = store.upsert_external_user(
        issuer="https://identity.example",
        subject="external-subject",
        username="external-user-1234567890",
        display_name="External User",
        role="viewer",
        connection_ids=[],
        claims={},
    )
    with pytest.raises(ValueError, match="active local account"):
        auth.recover_local_password(external["username"], "replacement password")
    recovered = auth.recover_local_password(
        local_session["user"]["username"], "replacement local password"
    )
    assert recovered["auth_source"] == "local"
    assert auth.authenticate(local_session["token"]) is None
    replacement = auth.login(
        local_session["user"]["username"],
        "replacement local password",
        "127.0.0.1",
    )
    assert replacement["user"]["id"] == local_session["user"]["id"]
