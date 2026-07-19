from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
from typing import Any

from ..audit import AuditStore
from ..schemas import AuthUserCreate, AuthUserUpdate
from .store import AuthStore

SESSION_COOKIE = "signalroom_session"
CSRF_COOKIE = "signalroom_csrf"
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ROLES = {"viewer", "analyst", "admin"}
CONNECTION_IDS = {"primary"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ADMIN_MUTATION_PREFIXES = (
    "/api/auth/users",
    "/api/auth/oidc/",
    "/api/model-setup/pull",
    "/api/model-setup/activate",
    "/api/model-trust",
    "/api/benchmarks/suites",
    "/api/detection-repository/",
    "/api/workload/",
    "/api/audit-export/",
)
ADMIN_MUTATION_PATHS = {
    "/api/auth/disable",
    "/api/settings",
    "/api/assurance/policy",
    "/api/delivery/policy",
    "/api/delivery/test",
}
CONNECTION_MUTATION_PREFIXES = (
    "/api/chat",
    "/api/discovery",
    "/api/connection/diagnostics",
    "/api/splunk-models/scan",
    "/api/assurance/runs",
)


class AuthService:
    """Optional local RBAC with durable users and opaque browser sessions."""

    def __init__(self, store: AuthStore, audit: AuditStore):
        self.store = store
        self.audit = audit

    def status(
        self, token: str = "", *, include_users: bool = False
    ) -> dict[str, Any]:
        policy = self.store.policy()
        identity_count = self.store.user_count()
        if not policy["enabled"]:
            return {
                "enabled": False,
                "mode": "local-single-user",
                "authenticated": True,
                "bootstrap_required": identity_count == 0,
                "reenable_required": identity_count > 0,
                "identity_count": identity_count,
                "principal": {
                    "id": "local-operator",
                    "username": "local-operator",
                    "display_name": "Local operator",
                    "role": "admin",
                    "active": True,
                    "connection_ids": ["primary"],
                },
                "permissions": self._permissions("admin", ["primary"]),
                "session": None,
                "users": self.store.users() if include_users else [],
                "available_connections": [{"id": "primary", "label": "Primary Splunk"}],
            }
        session = self.authenticate(token)
        if not session:
            return {
                "enabled": True,
                "mode": "rbac",
                "authenticated": False,
                "bootstrap_required": False,
                "reenable_required": False,
                "identity_count": identity_count,
                "principal": None,
                "permissions": self._permissions("", []),
                "session": None,
                "users": [],
                "available_connections": [],
            }
        user = session["user"]
        is_admin = user["role"] == "admin"
        return {
            "enabled": True,
            "mode": "rbac",
            "authenticated": True,
            "bootstrap_required": False,
            "reenable_required": False,
            "identity_count": identity_count,
            "principal": self._public_user(user),
            "permissions": self._permissions(
                user["role"], user["connection_ids"]
            ),
            "session": {
                "expires_at": session["expires_at"],
            },
            "users": self.store.users() if include_users and is_admin else [],
            "available_connections": (
                [{"id": "primary", "label": "Primary Splunk"}] if is_admin else []
            ),
        }

    def bootstrap(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        source: str,
    ) -> dict[str, Any]:
        if self.store.policy()["enabled"]:
            raise ValueError("RBAC is already enabled")
        username = self._username(username)
        display_name = self._display_name(display_name)
        self._validate_password(password)
        existing_count = self.store.user_count()
        if existing_count:
            user = self._verify_credentials(username, password, source)
            if user["role"] != "admin":
                raise PermissionError("Only an existing admin can re-enable RBAC")
        else:
            salt, password_hash = self._password_hash(password)
            try:
                user = self.store.create_user(
                    username=username,
                    display_name=display_name,
                    role="admin",
                    password_salt=salt,
                    password_hash=password_hash,
                    connection_ids=["primary"],
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("That username is already in use") from exc
        self.store.set_enabled(True)
        session = self._new_session(user)
        self.audit.record(
            "auth.rbac.enabled",
            "enable",
            target_type="access-policy",
            target_id="primary",
            summary=(
                "Named-user RBAC was enabled. Local single-user mode is no longer active."
            ),
            metadata={
                "admin_user_id": user["id"],
                "admin_username": user["username"],
                "existing_identity_reused": bool(existing_count),
            },
            actor=user["username"],
        )
        return session

    def disable(self, user_id: str, password: str) -> None:
        user = self.store.get_user(user_id)
        if not user or user["role"] != "admin" or not user["active"]:
            raise PermissionError("An active admin is required to disable RBAC")
        if not self._password_matches(
            password, user["password_salt"], user["password_hash"]
        ):
            raise PermissionError("The admin password was not accepted")
        self.store.set_enabled(False)
        self.audit.record(
            "auth.rbac.disabled",
            "disable",
            target_type="access-policy",
            target_id="primary",
            outcome="warning",
            summary=(
                "Named-user RBAC was disabled; SignalRoom returned to local "
                "single-user mode."
            ),
            actor=user["username"],
        )

    def login(self, username: str, password: str, source: str) -> dict[str, Any]:
        if not self.store.policy()["enabled"]:
            raise ValueError("RBAC is disabled; no login is required")
        username = self._username(username)
        user = self._verify_credentials(username, password, source)
        session = self._new_session(user)
        self.audit.record(
            "auth.session.created",
            "login",
            target_type="auth-user",
            target_id=user["id"],
            summary="A named SignalRoom user established a local browser session.",
            metadata={"username": user["username"], "role": user["role"]},
            actor=user["username"],
        )
        return session

    def federated_session(self, user: dict[str, Any]) -> dict[str, Any]:
        if not self.store.policy()["enabled"]:
            raise ValueError("Named access is disabled")
        if user.get("auth_source") != "oidc" or not user.get("active"):
            raise PermissionError("The enterprise identity is not active")
        return self._new_session(user)

    def recover_local_password(
        self, username: str, password: str
    ) -> dict[str, Any]:
        username = self._username(username)
        self._validate_password(password)
        user = self.store.get_user_by_username(username)
        if not user or user.get("auth_source") != "local" or not user.get("active"):
            raise ValueError("An active local account with that username was not found")
        salt, password_hash = self._password_hash(password)
        recovered = self.store.recover_local_password(
            user["id"],
            password_salt=salt,
            password_hash=password_hash,
        )
        if not recovered:
            raise ValueError("The local account could not be recovered")
        self.audit.record(
            "auth.local.password.recovered",
            "recover",
            target_type="auth-user",
            target_id=user["id"],
            outcome="warning",
            summary="A host-authorized recovery replaced a local account password.",
            metadata={"username": username, "sessions_revoked": True},
            actor="host-recovery",
        )
        return self._public_user(recovered)

    def logout(self, token: str, user: dict[str, Any] | None) -> None:
        if token:
            self.store.revoke_session(self._digest(token))
        if user:
            self.audit.record(
                "auth.session.revoked",
                "logout",
                target_type="auth-user",
                target_id=user["id"],
                summary="The local browser session was explicitly ended.",
                actor=user["username"],
            )

    def authenticate(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        return self.store.session(self._digest(token))

    def verify_csrf(self, session: dict[str, Any], csrf_token: str) -> bool:
        if not csrf_token:
            return False
        return hmac.compare_digest(
            session["csrf_sha256"], self._digest(csrf_token)
        )

    def users(self) -> list[dict[str, Any]]:
        return self.store.users()

    def create_user(
        self, value: AuthUserCreate, *, actor: dict[str, Any]
    ) -> dict[str, Any]:
        username = self._username(value.username)
        display_name = self._display_name(value.display_name)
        connections = self._connections(value.connection_ids)
        self._validate_password(value.password)
        salt, password_hash = self._password_hash(value.password)
        try:
            user = self.store.create_user(
                username=username,
                display_name=display_name,
                role=value.role,
                password_salt=salt,
                password_hash=password_hash,
                connection_ids=connections,
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That username is already in use") from exc
        self.audit.record(
            "auth.user.created",
            "create",
            target_type="auth-user",
            target_id=user["id"],
            summary=f"Created named SignalRoom {user['role']} user {user['username']}.",
            metadata={
                "username": user["username"],
                "role": user["role"],
                "connection_ids": user["connection_ids"],
            },
            actor=actor["username"],
        )
        return self._public_user(user)

    def update_user(
        self, user_id: str, value: AuthUserUpdate, *, actor: dict[str, Any]
    ) -> dict[str, Any]:
        current = self.store.get_user(user_id)
        if not current:
            raise KeyError(user_id)
        display_name = (
            self._display_name(value.display_name)
            if value.display_name is not None
            else current["display_name"]
        )
        role = value.role or current["role"]
        active = value.active if value.active is not None else current["active"]
        connections = (
            self._connections(value.connection_ids)
            if value.connection_ids is not None
            else current["connection_ids"]
        )
        losing_admin = current["role"] == "admin" and (
            role != "admin" or not active
        )
        if losing_admin and self.store.active_admin_count() <= 1:
            raise ValueError("SignalRoom must retain at least one active admin")
        if (
            losing_admin
            and current.get("auth_source") == "local"
            and self.store.active_local_admin_count() <= 1
        ):
            raise ValueError("SignalRoom must retain one active local break-glass admin")
        if current.get("auth_source") == "oidc" and any(
            item is not None for item in (value.role, value.password, value.connection_ids)
        ):
            raise ValueError(
                "OIDC role and connection access are managed by enterprise group policy"
            )
        password_salt: str | None = None
        password_hash: str | None = None
        if value.password is not None:
            self._validate_password(value.password)
            password_salt, password_hash = self._password_hash(value.password)
        updated = self.store.update_user(
            user_id,
            display_name=display_name,
            role=role,
            active=active,
            connection_ids=connections,
            password_salt=password_salt,
            password_hash=password_hash,
        )
        assert updated is not None
        if role != current["role"] or connections != current["connection_ids"]:
            self.store.revoke_user_sessions(user_id)
        self.audit.record(
            "auth.user.updated",
            "update",
            target_type="auth-user",
            target_id=user_id,
            summary=f"Updated access for SignalRoom user {updated['username']}.",
            metadata={
                "role": updated["role"],
                "active": updated["active"],
                "connection_ids": updated["connection_ids"],
                "password_replaced": value.password is not None,
            },
            actor=actor["username"],
        )
        return self._public_user(updated)

    def authorize(
        self, user: dict[str, Any], method: str, path: str
    ) -> tuple[bool, str]:
        role = str(user.get("role") or "")
        method = method.upper()
        if role not in ROLES:
            return False, "The session role is invalid"
        if path == "/api/auth/logout":
            return True, ""
        if path.startswith("/api/auth/users") and role != "admin":
            return False, "Admin access is required for user administration"
        if method in {"GET", "HEAD", "OPTIONS"}:
            return True, ""
        if role == "viewer":
            return False, "Viewer access is read only"
        if self._admin_required(method, path) and role != "admin":
            return False, "Admin access is required for this operation"
        if self._connection_required(method, path) and "primary" not in set(
            user.get("connection_ids") or []
        ):
            return False, "This user is not assigned to the Primary Splunk connection"
        return True, ""

    @staticmethod
    def _admin_required(method: str, path: str) -> bool:
        if method not in UNSAFE_METHODS:
            return False
        if path in ADMIN_MUTATION_PATHS:
            return True
        if any(path.startswith(prefix) for prefix in ADMIN_MUTATION_PREFIXES):
            return True
        if (
            path.startswith("/api/benchmarks/")
            and any(part in path for part in ("/baseline", "/promote", "/rollback"))
        ):
            return True
        if path.startswith("/api/detections/") and any(
            part in path
            for part in (
                "/repository-",
                "/git-export",
                "/export",
                "/retire",
            )
        ):
            return True
        return False

    @staticmethod
    def _connection_required(method: str, path: str) -> bool:
        if method not in UNSAFE_METHODS:
            return False
        if any(path.startswith(prefix) for prefix in CONNECTION_MUTATION_PREFIXES):
            return True
        return (
            path.startswith("/api/validations/")
            and path.endswith("/run/stream")
        ) or (
            path.startswith("/api/detections/")
            and "/deployment-verification/refresh" in path
        ) or path in {"/api/test-connection", "/mcp"}

    @staticmethod
    def _permissions(role: str, connections: list[str]) -> dict[str, bool]:
        return {
            "can_read": role in ROLES,
            "can_change": role in {"analyst", "admin"},
            "can_administer": role == "admin",
            "can_use_primary_connection": "primary" in connections,
        }

    def _verify_credentials(
        self, username: str, password: str, source: str
    ) -> dict[str, Any]:
        if self.store.login_blocked(username, source):
            raise RuntimeError(
                "Too many failed login attempts. Wait 15 minutes before retrying."
            )
        user = self.store.get_user_by_username(username)
        accepted = bool(
            user
            and user["active"]
            and user.get("auth_source") == "local"
            and self._password_matches(
                password, user["password_salt"], user["password_hash"]
            )
        )
        self.store.record_login_attempt(username, source, succeeded=accepted)
        if not accepted or not user:
            raise PermissionError("The username or password was not accepted")
        return user

    def _new_session(self, user: dict[str, Any]) -> dict[str, Any]:
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = self.store.create_session(
            user_id=user["id"],
            token_sha256=self._digest(token),
            csrf_sha256=self._digest(csrf_token),
            session_hours=self.store.policy()["session_hours"],
        )
        return {
            "token": token,
            "csrf_token": csrf_token,
            "expires_at": expires_at,
            "user": self._public_user(user),
        }

    @staticmethod
    def _password_hash(password: str) -> tuple[str, str]:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        return (
            base64.urlsafe_b64encode(salt).decode(),
            base64.urlsafe_b64encode(digest).decode(),
        )

    @staticmethod
    def _password_matches(password: str, salt: str, expected: str) -> bool:
        try:
            salt_bytes = base64.urlsafe_b64decode(salt.encode())
            expected_bytes = base64.urlsafe_b64decode(expected.encode())
            actual = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt_bytes,
                n=2**14,
                r=8,
                p=1,
                dklen=32,
            )
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(actual, expected_bytes)

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def _username(value: str) -> str:
        normalized = str(value).strip().casefold()
        if not USERNAME_PATTERN.fullmatch(normalized):
            raise ValueError(
                "Usernames must be 3-64 lowercase letters, numbers, dots, "
                "underscores, or hyphens"
            )
        return normalized

    @staticmethod
    def _display_name(value: str) -> str:
        normalized = " ".join(str(value).replace("\x00", "").split())[:120]
        if not normalized:
            raise ValueError("A display name is required")
        return normalized

    @staticmethod
    def _validate_password(value: str) -> None:
        if len(value) < 12:
            raise ValueError("Passwords must contain at least 12 characters")
        if value.isspace() or "\x00" in value:
            raise ValueError("The password is not valid")

    @staticmethod
    def _connections(values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(str(item).strip() for item in values))
        if any(item not in CONNECTION_IDS for item in normalized):
            raise ValueError("The connection assignment is not recognized")
        return normalized

    @staticmethod
    def _public_user(value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value[key]
            for key in (
                "id",
                "username",
                "display_name",
                "role",
                "active",
                "connection_ids",
                "created_at",
                "updated_at",
                "last_login_at",
                "auth_source",
                "external_issuer",
            )
            if key in value
        }
