from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AuthStore:
    """Durable optional access policy, users, sessions, and login throttling."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        now = _now()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_policy (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    enabled INTEGER NOT NULL,
                    session_hours INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    connection_ids TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_auth_users_role
                    ON auth_users(role, active, username);
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_sha256 TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    csrf_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES auth_users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
                    ON auth_sessions(user_id, expires_at);
                CREATE TABLE IF NOT EXISTS auth_login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    source TEXT NOT NULL,
                    succeeded INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auth_attempts_identity
                    ON auth_login_attempts(username, source, created_at);
                CREATE TABLE IF NOT EXISTS auth_oidc_policy (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    enabled INTEGER NOT NULL,
                    provider_label TEXT NOT NULL,
                    issuer_url TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    username_claim TEXT NOT NULL,
                    display_name_claim TEXT NOT NULL,
                    groups_claim TEXT NOT NULL,
                    tenant_claim TEXT NOT NULL,
                    allowed_tenant_values TEXT NOT NULL,
                    allowed_groups TEXT NOT NULL,
                    analyst_groups TEXT NOT NULL,
                    admin_groups TEXT NOT NULL,
                    default_role TEXT NOT NULL,
                    grant_primary_connection INTEGER NOT NULL,
                    connection_group_mappings TEXT NOT NULL DEFAULT '[]',
                    required_acr_values TEXT NOT NULL,
                    required_amr_values TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_oidc_transactions (
                    state_sha256 TEXT PRIMARY KEY,
                    nonce_sha256 TEXT NOT NULL,
                    code_verifier TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_auth_oidc_transactions_expiry
                    ON auth_oidc_transactions(expires_at, consumed_at);
                """
            )
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(auth_users)").fetchall()
            }
            if "auth_source" not in columns:
                db.execute(
                    "ALTER TABLE auth_users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local'"
                )
            if "external_issuer" not in columns:
                db.execute("ALTER TABLE auth_users ADD COLUMN external_issuer TEXT")
            if "external_subject" not in columns:
                db.execute("ALTER TABLE auth_users ADD COLUMN external_subject TEXT")
            if "external_claims" not in columns:
                db.execute(
                    "ALTER TABLE auth_users ADD COLUMN external_claims TEXT NOT NULL DEFAULT '{}'"
                )
            oidc_columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(auth_oidc_policy)").fetchall()
            }
            if "connection_group_mappings" not in oidc_columns:
                db.execute(
                    """ALTER TABLE auth_oidc_policy ADD COLUMN
                    connection_group_mappings TEXT NOT NULL DEFAULT '[]'"""
                )
            db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_external_identity
                ON auth_users(external_issuer, external_subject)
                WHERE external_issuer IS NOT NULL AND external_subject IS NOT NULL"""
            )
            db.execute(
                """INSERT OR IGNORE INTO auth_policy
                (id,enabled,session_hours,updated_at) VALUES (1,0,12,?)""",
                (now,),
            )
            db.execute(
                """INSERT OR IGNORE INTO auth_oidc_policy
                (id,enabled,provider_label,issuer_url,client_id,redirect_uri,
                username_claim,display_name_claim,groups_claim,tenant_claim,
                allowed_tenant_values,allowed_groups,analyst_groups,admin_groups,
                default_role,grant_primary_connection,connection_group_mappings,required_acr_values,
                required_amr_values,updated_at)
                VALUES (1,0,'Enterprise identity','','','',
                'preferred_username','name','groups','',
                '[]','[]','[]','[]','viewer',0,'[]','[]','["mfa"]',?)""",
                (now,),
            )

    def policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM auth_policy WHERE id=1").fetchone()
        assert row is not None
        return {
            "enabled": bool(row["enabled"]),
            "session_hours": int(row["session_hours"]),
            "updated_at": row["updated_at"],
        }

    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            db.execute(
                "UPDATE auth_policy SET enabled=?,updated_at=? WHERE id=1",
                (int(enabled), _now()),
            )
            if not enabled:
                db.execute(
                    "UPDATE auth_sessions SET revoked_at=? WHERE revoked_at IS NULL",
                    (_now(),),
                )
                db.execute(
                    "UPDATE auth_oidc_policy SET enabled=0,updated_at=? WHERE id=1",
                    (_now(),),
                )
        return self.policy()

    def user_count(self) -> int:
        with self.connect() as db:
            row = db.execute("SELECT COUNT(*) AS count FROM auth_users").fetchone()
        return int(row["count"])

    def active_admin_count(self) -> int:
        with self.connect() as db:
            row = db.execute(
                """SELECT COUNT(*) AS count FROM auth_users
                WHERE active=1 AND role='admin'"""
            ).fetchone()
        return int(row["count"])

    def active_local_admin_count(self) -> int:
        with self.connect() as db:
            row = db.execute(
                """SELECT COUNT(*) AS count FROM auth_users
                WHERE active=1 AND role='admin' AND auth_source='local'"""
            ).fetchone()
        return int(row["count"])

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        role: str,
        password_salt: str,
        password_hash: str,
        connection_ids: list[str],
    ) -> dict[str, Any]:
        user_id = str(uuid4())
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO auth_users
                (id,username,display_name,role,password_salt,password_hash,active,
                connection_ids,created_at,updated_at,last_login_at)
                VALUES (?,?,?,?,?,?,1,?,?,?,NULL)""",
                (
                    user_id,
                    username,
                    display_name,
                    role,
                    password_salt,
                    password_hash,
                    json.dumps(connection_ids),
                    now,
                    now,
                ),
            )
        user = self.get_user(user_id)
        assert user is not None
        return user

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM auth_users WHERE id=?", (user_id,)
            ).fetchone()
        return self._user(row, include_password=True) if row else None

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM auth_users WHERE username=?", (username,)
            ).fetchone()
        return self._user(row, include_password=True) if row else None

    def get_user_by_external_identity(
        self, issuer: str, subject: str
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM auth_users
                WHERE external_issuer=? AND external_subject=?""",
                (issuer, subject),
            ).fetchone()
        return self._user(row, include_password=True) if row else None

    def upsert_external_user(
        self,
        *,
        issuer: str,
        subject: str,
        username: str,
        display_name: str,
        role: str,
        connection_ids: list[str],
        claims: dict[str, Any],
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            current = db.execute(
                """SELECT id,active FROM auth_users
                WHERE external_issuer=? AND external_subject=?""",
                (issuer, subject),
            ).fetchone()
            if current:
                db.execute(
                    """UPDATE auth_users SET display_name=?,role=?,connection_ids=?,
                    external_claims=?,updated_at=? WHERE id=?""",
                    (
                        display_name,
                        role,
                        json.dumps(connection_ids),
                        json.dumps(claims, sort_keys=True),
                        now,
                        current["id"],
                    ),
                )
                user_id = current["id"]
            else:
                user_id = str(uuid4())
                db.execute(
                    """INSERT INTO auth_users
                    (id,username,display_name,role,password_salt,password_hash,active,
                    connection_ids,created_at,updated_at,last_login_at,auth_source,
                    external_issuer,external_subject,external_claims)
                    VALUES (?,?,?,?,?,?,1,?,?,?,NULL,'oidc',?,?,?)""",
                    (
                        user_id,
                        username,
                        display_name,
                        role,
                        "",
                        "",
                        json.dumps(connection_ids),
                        now,
                        now,
                        issuer,
                        subject,
                        json.dumps(claims, sort_keys=True),
                    ),
                )
        user = self.get_user(user_id)
        assert user is not None
        return user

    def users(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM auth_users
                ORDER BY active DESC, role='admin' DESC, username"""
            ).fetchall()
        return [self._user(row, include_password=False) for row in rows]

    def external_policy_subjects(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM auth_users WHERE auth_source='oidc'
                ORDER BY active DESC,updated_at DESC LIMIT ?""",
                (max(1, min(500, int(limit))),),
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            value = self._user(row, include_password=False)
            try:
                claims = json.loads(str(row["external_claims"] or "{}"))
            except (TypeError, ValueError):
                claims = {}
            value["external_claims"] = claims if isinstance(claims, dict) else {}
            values.append(value)
        return values

    def update_user(
        self,
        user_id: str,
        *,
        display_name: str,
        role: str,
        active: bool,
        connection_ids: list[str],
        password_salt: str | None = None,
        password_hash: str | None = None,
    ) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            current = db.execute(
                "SELECT role,active FROM auth_users WHERE id=?", (user_id,)
            ).fetchone()
            if not current:
                return None
            losing_active_admin = (
                current["role"] == "admin"
                and bool(current["active"])
                and (role != "admin" or not active)
            )
            if losing_active_admin:
                admins = db.execute(
                    """SELECT COUNT(*) AS count FROM auth_users
                    WHERE active=1 AND role='admin'"""
                ).fetchone()
                if int(admins["count"]) <= 1:
                    raise ValueError(
                        "SignalRoom must retain at least one active admin"
                    )
                source = db.execute(
                    "SELECT auth_source FROM auth_users WHERE id=?", (user_id,)
                ).fetchone()
                if (
                    source
                    and source["auth_source"] == "local"
                    and self.active_local_admin_count() <= 1
                ):
                    raise ValueError(
                        "SignalRoom must retain one active local break-glass admin"
                    )
            if password_salt and password_hash:
                changed = db.execute(
                    """UPDATE auth_users SET display_name=?,role=?,active=?,
                    connection_ids=?,password_salt=?,password_hash=?,updated_at=?
                    WHERE id=?""",
                    (
                        display_name,
                        role,
                        int(active),
                        json.dumps(connection_ids),
                        password_salt,
                        password_hash,
                        now,
                        user_id,
                    ),
                ).rowcount
                if changed:
                    db.execute(
                        """UPDATE auth_sessions SET revoked_at=?
                        WHERE user_id=? AND revoked_at IS NULL""",
                        (now, user_id),
                    )
            else:
                changed = db.execute(
                    """UPDATE auth_users SET display_name=?,role=?,active=?,
                    connection_ids=?,updated_at=? WHERE id=?""",
                    (
                        display_name,
                        role,
                        int(active),
                        json.dumps(connection_ids),
                        now,
                        user_id,
                    ),
                ).rowcount
                if changed and not active:
                    db.execute(
                        """UPDATE auth_sessions SET revoked_at=?
                        WHERE user_id=? AND revoked_at IS NULL""",
                        (now, user_id),
                    )
        return self.get_user(user_id) if changed else None

    def create_session(
        self,
        *,
        user_id: str,
        token_sha256: str,
        csrf_sha256: str,
        session_hours: int,
    ) -> str:
        now = datetime.now(UTC)
        expires_at = (now + timedelta(hours=session_hours)).isoformat()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO auth_sessions
                (token_sha256,user_id,csrf_sha256,created_at,expires_at,revoked_at)
                VALUES (?,?,?,?,?,NULL)""",
                (
                    token_sha256,
                    user_id,
                    csrf_sha256,
                    now.isoformat(),
                    expires_at,
                ),
            )
            db.execute(
                "UPDATE auth_users SET last_login_at=?,updated_at=? WHERE id=?",
                (now.isoformat(), now.isoformat(), user_id),
            )
            db.execute(
                "DELETE FROM auth_sessions WHERE expires_at<? OR revoked_at IS NOT NULL",
                ((now - timedelta(days=1)).isoformat(),),
            )
        return expires_at

    def session(self, token_sha256: str) -> dict[str, Any] | None:
        now = _now()
        with self.connect() as db:
            row = db.execute(
                """SELECT s.*,u.username,u.display_name,u.role,u.active,
                u.connection_ids,u.auth_source,u.external_issuer FROM auth_sessions s
                JOIN auth_users u ON u.id=s.user_id
                WHERE s.token_sha256=? AND s.revoked_at IS NULL
                AND s.expires_at>? AND u.active=1""",
                (token_sha256, now),
            ).fetchone()
        if not row:
            return None
        return {
            "token_sha256": row["token_sha256"],
            "csrf_sha256": row["csrf_sha256"],
            "expires_at": row["expires_at"],
            "user": {
                "id": row["user_id"],
                "username": row["username"],
                "display_name": row["display_name"],
                "role": row["role"],
                "active": bool(row["active"]),
                "connection_ids": json.loads(row["connection_ids"]),
                "auth_source": row["auth_source"],
                "external_issuer": row["external_issuer"],
            },
        }

    def revoke_session(self, token_sha256: str) -> bool:
        with self._lock, self.connect() as db:
            return bool(
                db.execute(
                    """UPDATE auth_sessions SET revoked_at=?
                    WHERE token_sha256=? AND revoked_at IS NULL""",
                    (_now(), token_sha256),
                ).rowcount
            )

    def revoke_user_sessions(self, user_id: str) -> int:
        with self._lock, self.connect() as db:
            return int(
                db.execute(
                    """UPDATE auth_sessions SET revoked_at=?
                    WHERE user_id=? AND revoked_at IS NULL""",
                    (_now(), user_id),
                ).rowcount
            )

    def revoke_external_sessions(self) -> int:
        with self._lock, self.connect() as db:
            return int(
                db.execute(
                    """UPDATE auth_sessions SET revoked_at=?
                    WHERE revoked_at IS NULL AND user_id IN
                    (SELECT id FROM auth_users WHERE auth_source='oidc')""",
                    (_now(),),
                ).rowcount
            )

    def recover_local_password(
        self, user_id: str, *, password_salt: str, password_hash: str
    ) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            current = db.execute(
                "SELECT auth_source,active FROM auth_users WHERE id=?", (user_id,)
            ).fetchone()
            if not current or current["auth_source"] != "local" or not current["active"]:
                return None
            db.execute(
                """UPDATE auth_users SET password_salt=?,password_hash=?,updated_at=?
                WHERE id=?""",
                (password_salt, password_hash, now, user_id),
            )
            db.execute(
                """UPDATE auth_sessions SET revoked_at=?
                WHERE user_id=? AND revoked_at IS NULL""",
                (now, user_id),
            )
        return self.get_user(user_id)

    def oidc_policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM auth_oidc_policy WHERE id=1").fetchone()
        assert row is not None
        return {
            "enabled": bool(row["enabled"]),
            "provider_label": row["provider_label"],
            "issuer_url": row["issuer_url"],
            "client_id": row["client_id"],
            "redirect_uri": row["redirect_uri"],
            "username_claim": row["username_claim"],
            "display_name_claim": row["display_name_claim"],
            "groups_claim": row["groups_claim"],
            "tenant_claim": row["tenant_claim"],
            "allowed_tenant_values": json.loads(row["allowed_tenant_values"]),
            "allowed_groups": json.loads(row["allowed_groups"]),
            "analyst_groups": json.loads(row["analyst_groups"]),
            "admin_groups": json.loads(row["admin_groups"]),
            "default_role": row["default_role"],
            "grant_primary_connection": bool(row["grant_primary_connection"]),
            "connection_group_mappings": json.loads(row["connection_group_mappings"]),
            "required_acr_values": json.loads(row["required_acr_values"]),
            "required_amr_values": json.loads(row["required_amr_values"]),
            "updated_at": row["updated_at"],
        }

    def update_oidc_policy(self, value: dict[str, Any]) -> dict[str, Any]:
        fields = (
            "enabled",
            "provider_label",
            "issuer_url",
            "client_id",
            "redirect_uri",
            "username_claim",
            "display_name_claim",
            "groups_claim",
            "tenant_claim",
            "allowed_tenant_values",
            "allowed_groups",
            "analyst_groups",
            "admin_groups",
            "default_role",
            "grant_primary_connection",
            "connection_group_mappings",
            "required_acr_values",
            "required_amr_values",
        )
        lists = {
            "allowed_tenant_values",
            "allowed_groups",
            "analyst_groups",
            "admin_groups",
            "connection_group_mappings",
            "required_acr_values",
            "required_amr_values",
        }
        stored = [
            json.dumps(value[name]) if name in lists else int(value[name])
            if name in {"enabled", "grant_primary_connection"}
            else value[name]
            for name in fields
        ]
        with self._lock, self.connect() as db:
            db.execute(
                f"""UPDATE auth_oidc_policy SET
                {','.join(f'{name}=?' for name in fields)},updated_at=? WHERE id=1""",
                (*stored, _now()),
            )
        return self.oidc_policy()

    def create_oidc_transaction(
        self,
        *,
        state_sha256: str,
        nonce_sha256: str,
        code_verifier: str,
        source: str,
    ) -> None:
        now = datetime.now(UTC)
        with self._lock, self.connect() as db:
            per_source = db.execute(
                """SELECT COUNT(*) AS count FROM auth_oidc_transactions
                WHERE source=? AND consumed_at IS NULL AND expires_at>?""",
                (source, now.isoformat()),
            ).fetchone()
            global_pending = db.execute(
                """SELECT COUNT(*) AS count FROM auth_oidc_transactions
                WHERE consumed_at IS NULL AND expires_at>?""",
                (now.isoformat(),),
            ).fetchone()
            if int(per_source["count"]) >= 30 or int(global_pending["count"]) >= 1000:
                raise RuntimeError("Too many enterprise sign-in transactions are pending")
            db.execute(
                """INSERT INTO auth_oidc_transactions
                (state_sha256,nonce_sha256,code_verifier,source,created_at,
                expires_at,consumed_at) VALUES (?,?,?,?,?,?,NULL)""",
                (
                    state_sha256,
                    nonce_sha256,
                    code_verifier,
                    source,
                    now.isoformat(),
                    (now + timedelta(minutes=10)).isoformat(),
                ),
            )
            db.execute(
                "DELETE FROM auth_oidc_transactions WHERE expires_at<? OR consumed_at IS NOT NULL",
                ((now - timedelta(hours=1)).isoformat(),),
            )

    def consume_oidc_transaction(self, state_sha256: str) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            row = db.execute(
                """SELECT * FROM auth_oidc_transactions
                WHERE state_sha256=? AND consumed_at IS NULL AND expires_at>?""",
                (state_sha256, now),
            ).fetchone()
            if not row:
                return None
            changed = db.execute(
                """UPDATE auth_oidc_transactions SET consumed_at=?
                WHERE state_sha256=? AND consumed_at IS NULL""",
                (now, state_sha256),
            ).rowcount
        return dict(row) if changed else None

    def login_blocked(self, username: str, source: str) -> bool:
        since = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
        with self.connect() as db:
            row = db.execute(
                """SELECT COUNT(*) AS count FROM auth_login_attempts
                WHERE username=? AND source=? AND succeeded=0 AND created_at>=?""",
                (username, source, since),
            ).fetchone()
        return int(row["count"]) >= 5

    def record_login_attempt(
        self, username: str, source: str, *, succeeded: bool
    ) -> None:
        now = _now()
        with self._lock, self.connect() as db:
            if succeeded:
                db.execute(
                    "DELETE FROM auth_login_attempts WHERE username=? AND source=?",
                    (username, source),
                )
            else:
                db.execute(
                    """INSERT INTO auth_login_attempts
                    (username,source,succeeded,created_at) VALUES (?,?,0,?)""",
                    (username, source, now),
                )
            db.execute(
                "DELETE FROM auth_login_attempts WHERE created_at<?",
                ((datetime.now(UTC) - timedelta(days=1)).isoformat(),),
            )

    @staticmethod
    def _user(row: sqlite3.Row, *, include_password: bool) -> dict[str, Any]:
        value = {
            "id": row["id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "role": row["role"],
            "active": bool(row["active"]),
            "connection_ids": json.loads(row["connection_ids"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_login_at": row["last_login_at"],
            "auth_source": row["auth_source"],
            "external_issuer": row["external_issuer"],
            "external_subject": row["external_subject"],
        }
        if include_password:
            value["password_salt"] = row["password_salt"]
            value["password_hash"] = row["password_hash"]
        return value
