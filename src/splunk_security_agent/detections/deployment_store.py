from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


class DetectionDeploymentStore:
    """Immutable, digest-addressed observations of deployed Splunk definitions."""

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
                CREATE TABLE IF NOT EXISTS detection_deployment_snapshots (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL UNIQUE,
                    snapshot TEXT NOT NULL,
                    case_item_id TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detection_deployment_latest
                    ON detection_deployment_snapshots(
                        detection_id, content_sha256, observed_at DESC
                    );
                """
            )

    def record(
        self,
        detection_id: str,
        version: int,
        content_sha256: str,
        snapshot_sha256: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        snapshot_id = str(uuid4())
        observed_at = str(snapshot["observed_at"])
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO detection_deployment_snapshots
                (id,detection_id,version,content_sha256,snapshot_sha256,
                snapshot,observed_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    snapshot_id,
                    detection_id,
                    version,
                    content_sha256,
                    snapshot_sha256,
                    self.canonical(snapshot),
                    observed_at,
                ),
            )
        result = self.get(snapshot_id)
        assert result is not None
        return result

    def get(self, snapshot_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_deployment_snapshots
                WHERE id=?""",
                (snapshot_id,),
            ).fetchone()
        return self._snapshot(row) if row else None

    def latest(
        self,
        detection_id: str,
        content_sha256: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_deployment_snapshots
                WHERE detection_id=? AND content_sha256=?
                ORDER BY observed_at DESC LIMIT 1""",
                (detection_id, content_sha256),
            ).fetchone()
        return self._snapshot(row) if row else None

    def by_sha256(
        self,
        detection_id: str,
        snapshot_sha256: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_deployment_snapshots
                WHERE detection_id=? AND snapshot_sha256=?""",
                (detection_id, snapshot_sha256),
            ).fetchone()
        return self._snapshot(row) if row else None

    def mark_preserved(
        self,
        snapshot_id: str,
        case_item_id: str,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_deployment_snapshots
                SET case_item_id=?
                WHERE id=? AND case_item_id=''""",
                (case_item_id, snapshot_id),
            )
            if cursor.rowcount != 1:
                raise ValueError(
                    "Deployment verification snapshot is already preserved"
                )
        result = self.get(snapshot_id)
        assert result is not None
        return result

    @staticmethod
    def canonical(value: dict[str, Any]) -> str:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> dict[str, Any]:
        value = json.loads(row["snapshot"])
        value.update(
            {
                "id": row["id"],
                "detection_id": row["detection_id"],
                "version": int(row["version"]),
                "content_sha256": row["content_sha256"],
                "snapshot_sha256": row["snapshot_sha256"],
                "case_item_id": row["case_item_id"],
                "observed_at": row["observed_at"],
            }
        )
        return value
