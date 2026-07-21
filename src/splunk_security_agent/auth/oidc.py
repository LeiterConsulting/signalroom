from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt

from ..audit import AuditStore
from ..config import ConfigStore
from ..schemas import AuthOIDCPolicyUpdate
from .service import AuthService
from .store import AuthStore

OIDC_STATE_COOKIE = "signalroom_oidc_state"
ALLOWED_SIGNING_ALGORITHMS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}
CLAIM_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")


class OIDCError(RuntimeError):
    """A bounded identity-provider or admission failure safe to present to an operator."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _csv_values(values: list[str], *, limit: int = 160) -> list[str]:
    normalized: list[str] = []
    for item in values:
        value = " ".join(str(item).replace("\x00", "").split())[:limit]
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def _safe_url(value: str, *, label: str, allow_loopback_http: bool) -> str:
    raw = value.strip()
    parsed = urlparse(raw)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{label} must be an absolute URL without credentials or a fragment")
    loopback = False
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.casefold() == "localhost"
    if parsed.scheme != "https" and not (allow_loopback_http and parsed.scheme == "http" and loopback):
        raise ValueError(f"{label} must use HTTPS; loopback HTTP is accepted for local testing")
    return raw


class OIDCService:
    """Single-issuer OIDC login with PKCE, exact claim admission, and local authorization."""

    def __init__(
        self,
        store: AuthStore,
        auth: AuthService,
        config: ConfigStore,
        audit: AuditStore,
    ):
        self.store = store
        self.auth = auth
        self.config = config
        self.audit = audit
        self._metadata_cache: tuple[float, dict[str, Any]] | None = None
        self._jwks_cache: tuple[float, dict[str, Any]] | None = None

    def public_status(self, *, include_policy: bool = False) -> dict[str, Any]:
        policy = self.store.oidc_policy()
        value: dict[str, Any] = {
            "enabled": bool(policy["enabled"] and self.store.policy()["enabled"]),
            "provider_label": policy["provider_label"],
            "login_path": "/api/auth/oidc/start",
        }
        if include_policy:
            value["policy"] = {
                **policy,
                "client_secret_configured": bool(self.config.secret("oidc_client_secret")),
                "client_secret_environment_managed": self.config.secret_is_environment_managed(
                    "oidc_client_secret"
                ),
            }
            value["connection_catalog"] = self._connection_catalog(policy)
            value["assignment_preview"] = self._assignment_preview(policy)
        return value

    async def update_policy(
        self, value: AuthOIDCPolicyUpdate, *, actor: dict[str, Any]
    ) -> dict[str, Any]:
        if not self.store.policy()["enabled"]:
            raise ValueError("Enable named access before configuring enterprise sign-in")
        if self.store.active_local_admin_count() < 1:
            raise ValueError("An active local break-glass administrator is required")
        issuer = _safe_url(
            value.issuer_url,
            label="Issuer URL",
            allow_loopback_http=True,
        ) if value.issuer_url else ""
        redirect_uri = _safe_url(
            value.redirect_uri,
            label="Redirect URI",
            allow_loopback_http=True,
        ) if value.redirect_uri else ""
        for name, claim in (
            ("Username", value.username_claim),
            ("Display-name", value.display_name_claim),
            ("Groups", value.groups_claim),
        ):
            if not CLAIM_NAME.fullmatch(claim):
                raise ValueError(f"{name} claim must be a simple top-level claim name")
        if value.tenant_claim and not CLAIM_NAME.fullmatch(value.tenant_claim):
            raise ValueError("Tenant claim must be a simple top-level claim name")
        tenants = _csv_values(value.allowed_tenant_values)
        allowed_groups = _csv_values(value.allowed_groups)
        analyst_groups = _csv_values(value.analyst_groups)
        admin_groups = _csv_values(value.admin_groups)
        available_connections = self.auth.available_connections()
        available_ids = {item["id"] for item in available_connections}
        connection_mappings: list[dict[str, Any]] = []
        mapped_aliases: set[str] = set()
        for mapping in value.connection_group_mappings:
            alias = mapping.connection_alias.strip()
            if alias in mapped_aliases:
                raise ValueError(f"Connection alias {alias!r} is mapped more than once")
            if alias not in available_ids:
                raise ValueError(
                    f"Connection alias {alias!r} is not currently configured in SignalRoom"
                )
            groups = _csv_values(mapping.groups)
            if not groups:
                raise ValueError(f"Connection alias {alias!r} requires at least one exact group")
            mapped_aliases.add(alias)
            connection_mappings.append({"connection_alias": alias, "groups": groups})
        required_acr = _csv_values(value.required_acr_values)
        required_amr = [item.casefold() for item in _csv_values(value.required_amr_values)]
        if tenants and not value.tenant_claim:
            raise ValueError("A tenant claim is required when tenant values are restricted")
        if value.enabled:
            if not issuer or not value.client_id.strip() or not redirect_uri:
                raise ValueError("Issuer URL, client ID, and exact redirect URI are required")
            if not required_acr and not required_amr:
                raise ValueError("Require at least one ACR or AMR value as MFA evidence")
            environment_secret = self.config.secret_is_environment_managed(
                "oidc_client_secret"
            )
            if value.clear_client_secret and environment_secret:
                raise ValueError(
                    "Remove SIGNALROOM_OIDC_CLIENT_SECRET from the service environment"
                )
            if value.clear_client_secret and value.client_secret:
                raise ValueError("Choose either client-secret replacement or removal")
            current_secret = self.config.secret("oidc_client_secret")
            if value.clear_client_secret:
                current_secret = ""
            if value.client_secret and value.client_secret != "***":
                current_secret = value.client_secret.strip()
            if not current_secret:
                raise ValueError("A client secret is required for this confidential web client")
        if value.clear_client_secret:
            self.config.delete_secrets("oidc_client_secret")
        if value.client_secret and value.client_secret != "***":
            self.config.update_secrets(oidc_client_secret=value.client_secret.strip())
        policy = self.store.update_oidc_policy(
            {
                "enabled": value.enabled,
                "provider_label": (
                    " ".join(value.provider_label.split())[:120] or "Enterprise identity"
                ),
                "issuer_url": issuer,
                "client_id": value.client_id.strip(),
                "redirect_uri": redirect_uri,
                "username_claim": value.username_claim,
                "display_name_claim": value.display_name_claim,
                "groups_claim": value.groups_claim,
                "tenant_claim": value.tenant_claim,
                "allowed_tenant_values": tenants,
                "allowed_groups": allowed_groups,
                "analyst_groups": analyst_groups,
                "admin_groups": admin_groups,
                "default_role": value.default_role,
                "grant_primary_connection": value.grant_primary_connection,
                "connection_group_mappings": connection_mappings,
                "required_acr_values": required_acr,
                "required_amr_values": required_amr,
            }
        )
        revoked = self.store.revoke_external_sessions()
        self._metadata_cache = None
        self._jwks_cache = None
        self.audit.record(
            "auth.oidc.policy.updated",
            "update",
            target_type="oidc-policy",
            target_id=issuer or "disabled",
            summary=(
                "Enterprise OIDC sign-in was enabled."
                if value.enabled
                else "Enterprise OIDC sign-in was disabled."
            ),
            metadata={
                "enabled": value.enabled,
                "issuer": issuer,
                "provider_label": policy["provider_label"],
                "tenant_restrictions": len(tenants),
                "group_admission_rules": len(allowed_groups),
                "analyst_group_rules": len(analyst_groups),
                "admin_group_rules": len(admin_groups),
                "connection_group_mappings": len(connection_mappings),
                "mapped_connection_aliases": [
                    item["connection_alias"] for item in connection_mappings
                ],
                "required_acr_values": required_acr,
                "required_amr_values": required_amr,
                "external_sessions_revoked": revoked,
            },
            actor=actor["username"],
        )
        return self.public_status(include_policy=True)

    async def probe(self) -> dict[str, Any]:
        policy = self._enabled_policy()
        metadata = await self._metadata(policy, force=True)
        jwks = await self._jwks(metadata, force=True)
        algorithms = sorted(
            set(metadata.get("id_token_signing_alg_values_supported") or [])
            & ALLOWED_SIGNING_ALGORITHMS
        )
        if not algorithms:
            raise OIDCError("The provider does not advertise a supported asymmetric ID-token algorithm")
        return {
            "ok": True,
            "issuer": metadata["issuer"],
            "authorization_endpoint": metadata["authorization_endpoint"],
            "token_endpoint": metadata["token_endpoint"],
            "jwks_uri": metadata["jwks_uri"],
            "signing_algorithms": algorithms,
            "signing_keys": len(jwks.get("keys") or []),
            "pkce_s256": "S256" in set(metadata.get("code_challenge_methods_supported") or ["S256"]),
        }

    async def begin(self, *, source: str) -> dict[str, str]:
        policy = self._enabled_policy()
        metadata = await self._metadata(policy)
        methods = set(metadata.get("code_challenge_methods_supported") or ["S256"])
        if "S256" not in methods:
            raise OIDCError("The provider does not advertise S256 PKCE")
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        try:
            self.store.create_oidc_transaction(
                state_sha256=_digest(state),
                nonce_sha256=_digest(nonce),
                code_verifier=verifier,
                source=source,
            )
        except RuntimeError as exc:
            raise OIDCError(str(exc)) from exc
        query = urlencode(
            {
                "response_type": "code",
                "client_id": policy["client_id"],
                "redirect_uri": policy["redirect_uri"],
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
                "code_challenge_method": "S256",
                "response_mode": "query",
            }
        )
        separator = "&" if "?" in metadata["authorization_endpoint"] else "?"
        return {
            "authorization_url": f"{metadata['authorization_endpoint']}{separator}{query}",
            "state": state,
        }

    async def complete(
        self,
        *,
        code: str,
        state: str,
        state_cookie: str,
        source: str,
    ) -> dict[str, Any]:
        policy = self._enabled_policy()
        if not code or len(code) > 4096 or not state or len(state) > 512:
            raise OIDCError("The enterprise sign-in callback values were invalid")
        if not state or not state_cookie or not hmac.compare_digest(state, state_cookie):
            raise OIDCError("The enterprise sign-in state did not match this browser")
        transaction = self.store.consume_oidc_transaction(_digest(state))
        if not transaction:
            raise OIDCError("The enterprise sign-in transaction expired or was already used")
        metadata = await self._metadata(policy)
        token_payload = await self._exchange(
            metadata,
            policy,
            code=code,
            verifier=transaction["code_verifier"],
        )
        id_token = str(token_payload.get("id_token") or "")
        if not id_token:
            raise OIDCError("The provider did not return an ID token")
        claims = await self._validate_id_token(
            id_token,
            metadata=metadata,
            policy=policy,
            nonce_sha256=transaction["nonce_sha256"],
        )
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise OIDCError("The ID token subject was not a valid immutable identifier")
        try:
            admission = self._admit(
                claims,
                policy,
                available_connection_ids=[
                    item["id"] for item in self.auth.available_connections()
                ],
            )
        except OIDCError:
            existing = self.store.get_user_by_external_identity(
                policy["issuer_url"], subject
            )
            if existing:
                revoked = self.store.revoke_user_sessions(existing["id"])
                self.audit.record(
                    "auth.oidc.identity.deauthorized",
                    "revoke",
                    target_type="auth-user",
                    target_id=existing["id"],
                    outcome="warning",
                    summary=(
                        "A newly verified provider identity no longer satisfied OIDC "
                        "admission; its existing SignalRoom sessions were revoked."
                    ),
                    metadata={
                        "provider_label": policy["provider_label"],
                        "issuer": policy["issuer_url"],
                        "sessions_revoked": revoked,
                    },
                    actor=existing["username"],
                )
            raise
        existing = self.store.get_user_by_external_identity(policy["issuer_url"], subject)
        username = existing["username"] if existing else self._external_username(
            str(claims.get(policy["username_claim"]) or subject),
            policy["issuer_url"],
            subject,
        )
        display_name = AuthService._display_name(
            str(
                claims.get(policy["display_name_claim"])
                or claims.get(policy["username_claim"])
                or username
            )
        )
        safe_claims = {
            "tenant": admission["tenant"],
            "groups": admission["groups"],
            "acr": str(claims.get("acr") or ""),
            "amr": admission["amr"],
        }
        try:
            user = self.store.upsert_external_user(
                issuer=policy["issuer_url"],
                subject=subject,
                username=username,
                display_name=display_name,
                role=admission["role"],
                connection_ids=admission["connection_ids"],
                claims=safe_claims,
            )
        except sqlite3.IntegrityError as exc:
            raise OIDCError("The external identity could not be assigned a unique local handle") from exc
        if not user["active"]:
            raise OIDCError("This SignalRoom identity is inactive")
        session = self.auth.federated_session(user)
        self.audit.record(
            "auth.oidc.session.created",
            "login",
            target_type="auth-user",
            target_id=user["id"],
            summary="A verified enterprise identity established a SignalRoom browser session.",
            metadata={
                "provider_label": policy["provider_label"],
                "issuer": policy["issuer_url"],
                "role": user["role"],
                "connection_ids": user["connection_ids"],
                "tenant": admission["tenant"],
                "matched_groups": admission["matched_groups"],
                "matched_connection_groups": admission["matched_connection_groups"],
                "acr": str(claims.get("acr") or ""),
                "amr": admission["amr"],
                "source_match": source == transaction["source"],
            },
            actor=user["username"],
        )
        return session

    def _enabled_policy(self) -> dict[str, Any]:
        policy = self.store.oidc_policy()
        if not self.store.policy()["enabled"] or not policy["enabled"]:
            raise OIDCError("Enterprise sign-in is not enabled")
        return policy

    async def _metadata(
        self, policy: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        if not force and self._metadata_cache and self._metadata_cache[0] > time.monotonic():
            return self._metadata_cache[1]
        url = f"{policy['issuer_url'].rstrip('/')}/.well-known/openid-configuration"
        payload = await self._get_json(url, "provider discovery")
        if payload.get("issuer") != policy["issuer_url"]:
            raise OIDCError("Provider discovery returned a different issuer")
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            endpoint = str(payload.get(field) or "")
            try:
                payload[field] = _safe_url(
                    endpoint,
                    label=field.replace("_", " ").title(),
                    allow_loopback_http=True,
                )
            except ValueError as exc:
                raise OIDCError(str(exc)) from exc
        if "code" not in set(payload.get("response_types_supported") or ["code"]):
            raise OIDCError("The provider does not advertise the authorization-code flow")
        self._metadata_cache = (time.monotonic() + 600, payload)
        return payload

    async def _jwks(
        self, metadata: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        if not force and self._jwks_cache and self._jwks_cache[0] > time.monotonic():
            return self._jwks_cache[1]
        payload = await self._get_json(metadata["jwks_uri"], "provider signing keys")
        if not isinstance(payload.get("keys"), list):
            raise OIDCError("The provider signing-key response was invalid")
        self._jwks_cache = (time.monotonic() + 300, payload)
        return payload

    @staticmethod
    async def _get_json(url: str, purpose: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            if len(response.content) > 2_000_000:
                raise OIDCError(f"The {purpose} response exceeded the size limit")
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OIDCError(f"Could not read {purpose}: {exc}") from exc
        if not isinstance(payload, dict):
            raise OIDCError(f"The {purpose} response was not an object")
        return payload

    async def _exchange(
        self,
        metadata: dict[str, Any],
        policy: dict[str, Any],
        *,
        code: str,
        verifier: str,
    ) -> dict[str, Any]:
        secret = self.config.secret("oidc_client_secret")
        if not secret:
            raise OIDCError("The OIDC client secret is not configured")
        methods = set(metadata.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"])
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": policy["redirect_uri"],
            "client_id": policy["client_id"],
            "code_verifier": verifier,
        }
        auth: httpx.BasicAuth | None = None
        if "client_secret_basic" in methods:
            auth = httpx.BasicAuth(policy["client_id"], secret)
        elif "client_secret_post" in methods:
            data["client_secret"] = secret
        else:
            raise OIDCError("The provider does not support client_secret_basic or client_secret_post")
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                response = await client.post(
                    metadata["token_endpoint"],
                    data=data,
                    auth=auth,
                    headers={"Accept": "application/json"},
                )
            response.raise_for_status()
            if len(response.content) > 2_000_000:
                raise OIDCError("The token response exceeded the size limit")
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OIDCError(f"The authorization code could not be exchanged: {exc}") from exc
        if not isinstance(payload, dict):
            raise OIDCError("The token response was invalid")
        return payload

    async def _validate_id_token(
        self,
        value: str,
        *,
        metadata: dict[str, Any],
        policy: dict[str, Any],
        nonce_sha256: str,
    ) -> dict[str, Any]:
        if len(value) > 1_000_000:
            raise OIDCError("The ID token exceeded the size limit")
        try:
            header = jwt.get_unverified_header(value)
        except jwt.PyJWTError as exc:
            raise OIDCError("The ID token header was invalid") from exc
        algorithm = str(header.get("alg") or "")
        key_id = str(header.get("kid") or "")
        provider_algorithms = set(metadata.get("id_token_signing_alg_values_supported") or [])
        if algorithm not in ALLOWED_SIGNING_ALGORITHMS or (
            provider_algorithms and algorithm not in provider_algorithms
        ):
            raise OIDCError("The ID token did not use an approved asymmetric signature")
        if not key_id:
            raise OIDCError("The ID token did not identify a signing key")
        jwks = await self._jwks(metadata)
        candidates = [
            item
            for item in jwks["keys"]
            if str(item.get("kid") or "") == key_id
            and item.get("use", "sig") == "sig"
            and "verify" in set(item.get("key_ops") or ["verify"])
        ]
        if not candidates:
            jwks = await self._jwks(metadata, force=True)
            candidates = [
                item
                for item in jwks["keys"]
                if str(item.get("kid") or "") == key_id
                and item.get("use", "sig") == "sig"
                and "verify" in set(item.get("key_ops") or ["verify"])
            ]
        if len(candidates) != 1:
            raise OIDCError("The provider signing key could not be selected uniquely")
        try:
            signing_key = jwt.PyJWK.from_dict(candidates[0], algorithm=algorithm)
            claims = jwt.decode(
                value,
                key=signing_key,
                algorithms=[algorithm],
                audience=policy["client_id"],
                issuer=policy["issuer_url"],
                leeway=30,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub", "nonce"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise OIDCError(f"The ID token failed verification: {exc}") from exc
        if not hmac.compare_digest(_digest(str(claims.get("nonce") or "")), nonce_sha256):
            raise OIDCError("The ID token nonce did not match the sign-in transaction")
        audiences = claims.get("aud")
        if isinstance(audiences, list) and len(audiences) > 1:
            if claims.get("azp") != policy["client_id"]:
                raise OIDCError("The ID token authorized-party claim did not match this client")
        return claims

    @staticmethod
    def _admit(
        claims: dict[str, Any],
        policy: dict[str, Any],
        available_connection_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        raw_groups = claims.get(policy["groups_claim"], [])
        if isinstance(raw_groups, str):
            groups = [raw_groups]
        elif isinstance(raw_groups, list):
            if len(raw_groups) > 500:
                raise OIDCError("The enterprise group claim exceeded the size limit")
            groups = [str(item) for item in raw_groups if isinstance(item, (str, int))]
        else:
            groups = []
        if any(len(item) > 256 for item in groups):
            raise OIDCError("An enterprise group identifier exceeded the size limit")
        group_set = set(groups)
        allowed_groups = set(policy["allowed_groups"])
        if allowed_groups and not group_set.intersection(allowed_groups):
            raise OIDCError("The enterprise identity is not in an admitted SignalRoom group")
        tenant = ""
        if policy["tenant_claim"]:
            tenant = str(claims.get(policy["tenant_claim"]) or "")
        if len(tenant) > 256:
            raise OIDCError("The enterprise tenant identifier exceeded the size limit")
        if policy["allowed_tenant_values"] and tenant not in set(policy["allowed_tenant_values"]):
            raise OIDCError("The enterprise identity did not match an admitted tenant")
        acr = str(claims.get("acr") or "")
        if policy["required_acr_values"] and acr not in set(policy["required_acr_values"]):
            raise OIDCError("The sign-in did not provide an accepted ACR assurance value")
        raw_amr = claims.get("amr") or []
        amr = [str(item).casefold() for item in raw_amr] if isinstance(raw_amr, list) else []
        if not set(policy["required_amr_values"]).issubset(set(amr)):
            raise OIDCError("The sign-in did not provide the required MFA method evidence")
        admin_matches = group_set.intersection(set(policy["admin_groups"]))
        analyst_matches = group_set.intersection(set(policy["analyst_groups"]))
        if admin_matches:
            role = "admin"
            matched = sorted(admin_matches)
        elif analyst_matches:
            role = "analyst"
            matched = sorted(analyst_matches)
        else:
            role = policy["default_role"]
            matched = sorted(group_set.intersection(allowed_groups))
        available = (
            set(available_connection_ids)
            if available_connection_ids is not None
            else None
        )
        connection_ids: list[str] = []
        connection_matches: dict[str, list[str]] = {}
        if policy.get("grant_primary_connection") and (
            available is None or "primary" in available
        ):
            connection_ids.append("primary")
            connection_matches["primary"] = ["all-admitted-identities"]
        for mapping in policy.get("connection_group_mappings") or []:
            if not isinstance(mapping, dict):
                continue
            alias = str(mapping.get("connection_alias") or "")
            if not alias or (available is not None and alias not in available):
                continue
            matches = sorted(group_set.intersection(set(mapping.get("groups") or [])))
            if matches:
                if alias not in connection_ids:
                    connection_ids.append(alias)
                connection_matches[alias] = matches
        return {
            "groups": sorted(groups),
            "tenant": tenant,
            "amr": sorted(amr),
            "role": role,
            "matched_groups": matched,
            "connection_ids": connection_ids,
            "matched_connection_groups": connection_matches,
        }

    def _connection_catalog(self, policy: dict[str, Any]) -> list[dict[str, Any]]:
        current = self.auth.available_connections()
        current_ids = {item["id"] for item in current}
        mapped = {
            str(item.get("connection_alias") or ""): list(item.get("groups") or [])
            for item in policy.get("connection_group_mappings") or []
            if isinstance(item, dict)
        }
        values = [
            {
                **item,
                "groups": mapped.get(item["id"], []),
                "available": True,
            }
            for item in current
        ]
        values.extend(
            {
                "id": alias,
                "label": alias,
                "groups": groups,
                "available": False,
            }
            for alias, groups in mapped.items()
            if alias not in current_ids
        )
        return values

    def _assignment_preview(self, policy: dict[str, Any]) -> dict[str, Any]:
        available = [item["id"] for item in self.auth.available_connections()]
        rows: list[dict[str, Any]] = []
        for user in self.store.external_policy_subjects():
            safe = user.get("external_claims") or {}
            claims: dict[str, Any] = {
                policy["groups_claim"]: safe.get("groups") or [],
                "acr": safe.get("acr") or "",
                "amr": safe.get("amr") or [],
            }
            if policy["tenant_claim"]:
                claims[policy["tenant_claim"]] = safe.get("tenant") or ""
            try:
                projected = self._admit(
                    claims,
                    policy,
                    available_connection_ids=available,
                )
                rows.append(
                    {
                        "user_id": user["id"],
                        "username": user["username"],
                        "active": user["active"],
                        "admitted": True,
                        "current_role": user["role"],
                        "projected_role": projected["role"],
                        "current_connection_ids": user["connection_ids"],
                        "projected_connection_ids": projected["connection_ids"],
                        "matched_connection_groups": projected[
                            "matched_connection_groups"
                        ],
                        "reason": "Last verified claims satisfy the saved policy.",
                    }
                )
            except OIDCError as exc:
                rows.append(
                    {
                        "user_id": user["id"],
                        "username": user["username"],
                        "active": user["active"],
                        "admitted": False,
                        "current_role": user["role"],
                        "projected_role": "",
                        "current_connection_ids": user["connection_ids"],
                        "projected_connection_ids": [],
                        "matched_connection_groups": {},
                        "reason": str(exc),
                    }
                )
        return {
            "identity_count": len(rows),
            "rows": rows,
            "claims_source": "last-verified-id-token",
            "requires_fresh_sign_in": True,
        }

    @staticmethod
    def _external_username(raw: str, issuer: str, subject: str) -> str:
        slug = re.sub(r"[^a-z0-9._-]+", "-", raw[:500].casefold()).strip(".-_")
        if len(slug) < 3:
            slug = "enterprise-user"
        suffix = hashlib.sha256(f"{issuer}\x00{subject}".encode()).hexdigest()[:10]
        return f"{slug[:52]}-{suffix}"[:64]
