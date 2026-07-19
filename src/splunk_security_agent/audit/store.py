from __future__ import annotations

import hashlib
import json
import sqlite3
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

SENSITIVE_KEY_PARTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
    "webhook_url",
)
_AUDIT_ACTOR: ContextVar[str] = ContextVar(
    "signalroom_audit_actor", default="local-operator"
)


def bind_audit_actor(actor: str) -> Token[str]:
    return _AUDIT_ACTOR.set(str(actor)[:120] or "local-operator")


def reset_audit_actor(token: Token[str]) -> None:
    _AUDIT_ACTOR.reset(token)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AuditStore:
    """Append-only, hash-chained local control-plane audit events."""

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
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_created
                    ON audit_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_events_target
                    ON audit_events(target_type, target_id, sequence DESC);
                """
            )

    def record(
        self,
        event_type: str,
        action: str,
        *,
        target_type: str,
        target_id: str = "",
        outcome: str = "success",
        summary: str = "",
        metadata: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        event_id = str(uuid4())
        created_at = _now()
        safe_metadata = self._redact(metadata or {})
        canonical = {
            "id": event_id,
            "event_type": str(event_type)[:120],
            "action": str(action)[:120],
            "actor": str(actor or _AUDIT_ACTOR.get())[:120],
            "target_type": str(target_type)[:120],
            "target_id": str(target_id)[:240],
            "outcome": str(outcome)[:40],
            "summary": str(summary)[:1000],
            "metadata": safe_metadata,
            "created_at": created_at,
        }
        with self._lock, self.connect() as db:
            prior = db.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = str(prior["event_hash"]) if prior else ""
            event_hash = self._hash(previous_hash, canonical)
            db.execute(
                """INSERT INTO audit_events
                (id,event_type,action,actor,target_type,target_id,outcome,summary,metadata,
                created_at,previous_hash,event_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    canonical["id"],
                    canonical["event_type"],
                    canonical["action"],
                    canonical["actor"],
                    canonical["target_type"],
                    canonical["target_id"],
                    canonical["outcome"],
                    canonical["summary"],
                    json.dumps(safe_metadata, sort_keys=True, default=str),
                    created_at,
                    previous_hash,
                    event_hash,
                ),
            )
            row = db.execute(
                "SELECT * FROM audit_events WHERE id=?", (event_id,)
            ).fetchone()
        assert row is not None
        return self._event(row)

    def events(
        self,
        limit: int = 100,
        *,
        event_type: str = "",
        target_type: str = "",
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        arguments: list[Any] = []
        if event_type:
            clauses.append("event_type=?")
            arguments.append(event_type)
        if target_type:
            clauses.append("target_type=?")
            arguments.append(target_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(min(max(limit, 1), 500))
        with self.connect() as db:
            rows = db.execute(
                f"SELECT * FROM audit_events {where} ORDER BY sequence DESC LIMIT ?",
                arguments,
            ).fetchall()
        return [self._event(row) for row in rows]

    def events_after(self, sequence: int, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM audit_events WHERE sequence>?
                ORDER BY sequence LIMIT ?""",
                (max(int(sequence), 0), min(max(limit, 1), 500)),
            ).fetchall()
        return [self._event(row) for row in rows]

    def latest_sequence(self) -> int:
        with self.connect() as db:
            row = db.execute(
                "SELECT COALESCE(MAX(sequence),0) AS sequence FROM audit_events"
            ).fetchone()
        return int(row["sequence"]) if row else 0

    def verify(self) -> dict[str, Any]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        previous_hash = ""
        for row in rows:
            event = self._event(row)
            canonical = {
                key: event[key]
                for key in (
                    "id",
                    "event_type",
                    "action",
                    "actor",
                    "target_type",
                    "target_id",
                    "outcome",
                    "summary",
                    "metadata",
                    "created_at",
                )
            }
            expected = self._hash(previous_hash, canonical)
            if event["previous_hash"] != previous_hash or event["event_hash"] != expected:
                return {
                    "valid": False,
                    "event_count": len(rows),
                    "broken_sequence": event["sequence"],
                    "head_hash": previous_hash,
                }
            previous_hash = event["event_hash"]
        return {
            "valid": True,
            "event_count": len(rows),
            "broken_sequence": None,
            "head_hash": previous_hash,
        }

    def overview(self, limit: int = 30) -> dict[str, Any]:
        return {"chain": self.verify(), "events": self.events(limit)}

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {
                str(item_key)[:160]: cls._redact(item_value, str(item_key))
                for item_key, item_value in list(value.items())[:100]
            }
        if isinstance(value, list):
            return [cls._redact(item) for item in value[:100]]
        if isinstance(value, str):
            return value[:4000]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:4000]

    @staticmethod
    def _hash(previous_hash: str, canonical: dict[str, Any]) -> str:
        payload = json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(f"{previous_hash}\n{payload}".encode()).hexdigest()

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": int(row["sequence"]),
            "id": row["id"],
            "event_type": row["event_type"],
            "action": row["action"],
            "actor": row["actor"],
            "target_type": row["target_type"],
            "target_id": row["target_id"],
            "outcome": row["outcome"],
            "summary": row["summary"],
            "metadata": json.loads(row["metadata"]),
            "created_at": row["created_at"],
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
        }
