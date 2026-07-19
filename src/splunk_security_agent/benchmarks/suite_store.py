from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


def _now() -> str:
    return datetime.now(UTC).isoformat()


def draft_fingerprint(name: str, description: str, scenarios: list[dict[str, Any]]) -> str:
    payload = {
        "name": name.strip(),
        "description": description.strip(),
        "scenarios": scenarios,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


class EvaluationSuiteStore:
    """Editable drafts plus immutable published operator evaluation versions."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS evaluation_suites (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
                    status TEXT NOT NULL, draft_scenarios TEXT NOT NULL,
                    draft_revision INTEGER NOT NULL, current_version INTEGER NOT NULL,
                    current_fingerprint TEXT NOT NULL, created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT
                );
                CREATE TABLE IF NOT EXISTS evaluation_suite_versions (
                    id TEXT PRIMARY KEY, suite_id TEXT NOT NULL, version INTEGER NOT NULL,
                    name TEXT NOT NULL, description TEXT NOT NULL, scenarios TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, published_by TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    UNIQUE(suite_id, version),
                    UNIQUE(suite_id, fingerprint),
                    FOREIGN KEY(suite_id) REFERENCES evaluation_suites(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_evaluation_suites_updated
                    ON evaluation_suites(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_evaluation_suite_versions
                    ON evaluation_suite_versions(suite_id, version DESC);
                """
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def create(
        self,
        name: str,
        description: str,
        scenarios: list[dict[str, Any]],
        actor: str,
    ) -> dict[str, Any]:
        suite_id = str(uuid4())
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO evaluation_suites
                (id,name,description,status,draft_scenarios,draft_revision,current_version,
                current_fingerprint,created_by,created_at,updated_at,archived_at)
                VALUES (?,?,?,'active',?,1,0,'',?,?,?,NULL)""",
                (
                    suite_id,
                    name.strip(),
                    description.strip(),
                    json.dumps(scenarios, separators=(",", ":"), ensure_ascii=False),
                    actor[:160],
                    now,
                    now,
                ),
            )
        result = self.get(suite_id)
        assert result is not None
        return result

    def update(
        self,
        suite_id: str,
        *,
        expected_revision: int,
        name: str,
        description: str,
        scenarios: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE evaluation_suites SET name=?,description=?,draft_scenarios=?,
                draft_revision=draft_revision+1,updated_at=?
                WHERE id=? AND status='active' AND draft_revision=?""",
                (
                    name.strip(),
                    description.strip(),
                    json.dumps(scenarios, separators=(",", ":"), ensure_ascii=False),
                    now,
                    suite_id,
                    expected_revision,
                ),
            )
            if result.rowcount != 1:
                current = db.execute(
                    "SELECT status,draft_revision FROM evaluation_suites WHERE id=?",
                    (suite_id,),
                ).fetchone()
                if current is None:
                    raise KeyError(f"Unknown evaluation suite: {suite_id}")
                if current["status"] != "active":
                    raise ValueError("Archived evaluation suites cannot be edited")
                raise ValueError(
                    "The evaluation draft changed in another session; reload before saving"
                )
        updated = self.get(suite_id)
        assert updated is not None
        return updated

    def publish(
        self,
        suite_id: str,
        *,
        expected_revision: int,
        expected_fingerprint: str,
        actor: str,
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            row = db.execute(
                "SELECT * FROM evaluation_suites WHERE id=?", (suite_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown evaluation suite: {suite_id}")
            if row["status"] != "active":
                raise ValueError("Archived evaluation suites cannot publish new versions")
            if int(row["draft_revision"]) != expected_revision:
                raise ValueError(
                    "The evaluation draft changed in another session; reload before publishing"
                )
            scenarios = json.loads(row["draft_scenarios"])
            fingerprint = draft_fingerprint(
                str(row["name"]), str(row["description"]), scenarios
            )
            if fingerprint != expected_fingerprint:
                raise ValueError("The evaluation draft fingerprint changed before publication")
            version = int(row["current_version"]) + 1
            db.execute(
                """INSERT INTO evaluation_suite_versions
                (id,suite_id,version,name,description,scenarios,fingerprint,published_by,published_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid4()),
                    suite_id,
                    version,
                    row["name"],
                    row["description"],
                    row["draft_scenarios"],
                    fingerprint,
                    actor[:160],
                    now,
                ),
            )
            db.execute(
                """UPDATE evaluation_suites SET current_version=?,current_fingerprint=?,
                updated_at=? WHERE id=?""",
                (version, fingerprint, now, suite_id),
            )
        published = self.get(suite_id)
        assert published is not None
        return published

    def archive(self, suite_id: str, archived: bool) -> dict[str, Any]:
        now = _now()
        status = "archived" if archived else "active"
        with self._lock, self.connect() as db:
            result = db.execute(
                """UPDATE evaluation_suites SET status=?,archived_at=?,updated_at=?
                WHERE id=?""",
                (status, now if archived else None, now, suite_id),
            )
            if result.rowcount != 1:
                raise KeyError(f"Unknown evaluation suite: {suite_id}")
        value = self.get(suite_id)
        assert value is not None
        return value

    def delete(self, suite_id: str) -> bool:
        with self._lock, self.connect() as db:
            result = db.execute(
                "DELETE FROM evaluation_suites WHERE id=? AND current_version=0",
                (suite_id,),
            )
        return bool(result.rowcount)

    def get(self, suite_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM evaluation_suites WHERE id=?", (suite_id,)
            ).fetchone()
            if row is None:
                return None
            versions = db.execute(
                """SELECT * FROM evaluation_suite_versions WHERE suite_id=?
                ORDER BY version DESC""",
                (suite_id,),
            ).fetchall()
        return self._suite(row, versions)

    def list(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM evaluation_suites
                ORDER BY status='active' DESC, updated_at DESC"""
            ).fetchall()
            versions = db.execute(
                "SELECT * FROM evaluation_suite_versions ORDER BY version DESC"
            ).fetchall()
        grouped: dict[str, list[sqlite3.Row]] = {}
        for version in versions:
            grouped.setdefault(str(version["suite_id"]), []).append(version)
        return [self._suite(row, grouped.get(str(row["id"]), [])) for row in rows]

    def version(self, suite_id: str, version: int | None = None) -> dict[str, Any] | None:
        with self.connect() as db:
            if version is None:
                row = db.execute(
                    """SELECT * FROM evaluation_suite_versions WHERE suite_id=?
                    ORDER BY version DESC LIMIT 1""",
                    (suite_id,),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT * FROM evaluation_suite_versions
                    WHERE suite_id=? AND version=?""",
                    (suite_id, version),
                ).fetchone()
        return self._version(row) if row else None

    @staticmethod
    def _version(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "suite_id": row["suite_id"],
            "version": int(row["version"]),
            "name": row["name"],
            "description": row["description"],
            "scenarios": json.loads(row["scenarios"]),
            "fingerprint": row["fingerprint"],
            "published_by": row["published_by"],
            "published_at": row["published_at"],
        }

    @classmethod
    def _suite(
        cls, row: sqlite3.Row, versions: list[sqlite3.Row]
    ) -> dict[str, Any]:
        scenarios = json.loads(row["draft_scenarios"])
        fingerprint = draft_fingerprint(
            str(row["name"]), str(row["description"]), scenarios
        )
        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "status": row["status"],
            "draft_scenarios": scenarios,
            "draft_revision": int(row["draft_revision"]),
            "draft_fingerprint": fingerprint,
            "current_version": int(row["current_version"]),
            "current_fingerprint": row["current_fingerprint"],
            "draft_dirty": (
                int(row["current_version"]) == 0
                or fingerprint != str(row["current_fingerprint"])
            ),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "archived_at": row["archived_at"],
            "versions": [cls._version(version) for version in versions],
        }
