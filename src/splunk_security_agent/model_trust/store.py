from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ..schemas import ModelTrustPolicyUpdate

DEFAULT_PUBLISHERS = ["cisco-ai", "fdtn-ai", "ollama-library"]


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ModelTrustStore:
    """Durable model trust policy and immutable local artifact attestations."""

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
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS model_trust_policy (
                    id INTEGER PRIMARY KEY CHECK (id=1), mode TEXT NOT NULL,
                    allowed_publishers TEXT NOT NULL, generation INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_artifact_attestations (
                    id TEXT PRIMARY KEY, profile_id TEXT NOT NULL,
                    identity_fingerprint TEXT NOT NULL, identity TEXT NOT NULL,
                    payload TEXT NOT NULL, signature TEXT NOT NULL, key_id TEXT NOT NULL,
                    status TEXT NOT NULL, approved_by TEXT NOT NULL,
                    approved_at TEXT NOT NULL, revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_model_attestation_profile_status
                    ON model_artifact_attestations(profile_id,status,approved_at DESC);
                CREATE INDEX IF NOT EXISTS idx_model_attestation_fingerprint
                    ON model_artifact_attestations(identity_fingerprint,status);
                """
            )
            db.execute(
                """INSERT OR IGNORE INTO model_trust_policy
                (id,mode,allowed_publishers,generation,updated_at)
                VALUES (1,'audit',?,1,?)""",
                (json.dumps(DEFAULT_PUBLISHERS), _now()),
            )

    def policy(self) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM model_trust_policy WHERE id=1"
            ).fetchone()
        assert row is not None
        return {
            "mode": row["mode"],
            "allowed_publishers": json.loads(row["allowed_publishers"]),
            "generation": int(row["generation"]),
            "updated_at": row["updated_at"],
        }

    def update_policy(self, value: ModelTrustPolicyUpdate) -> dict[str, Any]:
        publishers = sorted(
            {
                str(item).strip().lower()
                for item in value.allowed_publishers
                if str(item).strip()
            }
        )
        if not publishers:
            raise ValueError("At least one approved model publisher is required")
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE model_trust_policy SET mode=?,allowed_publishers=?,
                generation=generation+1,updated_at=? WHERE id=1""",
                (value.mode, json.dumps(publishers), now),
            )
        return self.policy()

    def create_attestation(
        self,
        *,
        profile_id: str,
        identity_fingerprint: str,
        identity: dict[str, Any],
        payload: dict[str, Any],
        signature: str,
        key_id: str,
        approved_by: str,
    ) -> dict[str, Any]:
        existing = self.active_for_fingerprint(profile_id, identity_fingerprint)
        if existing:
            return existing
        attestation_id = str(uuid4())
        approved_at = str(payload["approved_at"])
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE model_artifact_attestations SET status='superseded'
                WHERE profile_id=? AND status='active'""",
                (profile_id,),
            )
            db.execute(
                """INSERT INTO model_artifact_attestations
                (id,profile_id,identity_fingerprint,identity,payload,signature,key_id,
                status,approved_by,approved_at,revoked_at)
                VALUES (?,?,?,?,?,?,?,'active',?,?,NULL)""",
                (
                    attestation_id,
                    profile_id,
                    identity_fingerprint,
                    json.dumps(identity, sort_keys=True, default=str),
                    json.dumps(payload, sort_keys=True, default=str),
                    signature,
                    key_id,
                    approved_by[:120],
                    approved_at,
                ),
            )
        result = self.get_attestation(attestation_id)
        assert result is not None
        return result

    def get_attestation(self, attestation_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM model_artifact_attestations WHERE id=?",
                (attestation_id,),
            ).fetchone()
        return self._attestation(row) if row else None

    def active_for_fingerprint(
        self, profile_id: str, identity_fingerprint: str
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM model_artifact_attestations
                WHERE profile_id=? AND identity_fingerprint=? AND status='active'
                ORDER BY approved_at DESC LIMIT 1""",
                (profile_id, identity_fingerprint),
            ).fetchone()
        return self._attestation(row) if row else None

    def active_for_profile(self, profile_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM model_artifact_attestations
                WHERE profile_id=? AND status='active'
                ORDER BY approved_at DESC LIMIT 1""",
                (profile_id,),
            ).fetchone()
        return self._attestation(row) if row else None

    def list_attestations(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM model_artifact_attestations
                ORDER BY approved_at DESC LIMIT ?""",
                (max(1, min(500, limit)),),
            ).fetchall()
        return [self._attestation(row) for row in rows]

    def revoke(self, attestation_id: str) -> dict[str, Any] | None:
        now = _now()
        with self._lock, self.connect() as db:
            updated = db.execute(
                """UPDATE model_artifact_attestations
                SET status='revoked',revoked_at=?
                WHERE id=? AND status='active'""",
                (now, attestation_id),
            )
        if not updated.rowcount:
            return None
        return self.get_attestation(attestation_id)

    @staticmethod
    def _attestation(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "profile_id": row["profile_id"],
            "identity_fingerprint": row["identity_fingerprint"],
            "identity": json.loads(row["identity"]),
            "payload": json.loads(row["payload"]),
            "signature": row["signature"],
            "key_id": row["key_id"],
            "status": row["status"],
            "approved_by": row["approved_by"],
            "approved_at": row["approved_at"],
            "revoked_at": row["revoked_at"],
        }
