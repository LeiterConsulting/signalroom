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
                """
            )
            db.execute(
                """INSERT OR IGNORE INTO auth_policy
                (id,enabled,session_hours,updated_at) VALUES (1,0,12,?)""",
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

    def users(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM auth_users
                ORDER BY active DESC, role='admin' DESC, username"""
            ).fetchall()
        return [self._user(row, include_password=False) for row in rows]

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
                u.connection_ids FROM auth_sessions s
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
        }
        if include_password:
            value["password_salt"] = row["password_salt"]
            value["password_hash"] = row["password_hash"]
        return value
