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
                CREATE TABLE IF NOT EXISTS detection_runtime_checks (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    deployment_snapshot_id TEXT NOT NULL,
                    deployment_snapshot_sha256 TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    validation_task_id TEXT NOT NULL UNIQUE,
                    query_fingerprint TEXT NOT NULL,
                    check_sha256 TEXT NOT NULL UNIQUE,
                    check_contract TEXT NOT NULL,
                    assessment_sha256 TEXT NOT NULL DEFAULT '',
                    assessment TEXT NOT NULL DEFAULT '',
                    case_item_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    assessed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_detection_runtime_latest
                    ON detection_runtime_checks(
                        deployment_snapshot_id, created_at DESC
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

    def record_runtime_check(
        self,
        detection_id: str,
        deployment_snapshot_id: str,
        deployment_snapshot_sha256: str,
        content_sha256: str,
        validation_task_id: str,
        query_fingerprint: str,
        check_sha256: str,
        check_contract: dict[str, Any],
    ) -> dict[str, Any]:
        check_id = str(uuid4())
        created_at = str(check_contract["created_at"])
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO detection_runtime_checks
                (id,detection_id,deployment_snapshot_id,deployment_snapshot_sha256,
                content_sha256,validation_task_id,query_fingerprint,check_sha256,
                check_contract,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    check_id,
                    detection_id,
                    deployment_snapshot_id,
                    deployment_snapshot_sha256,
                    content_sha256,
                    validation_task_id,
                    query_fingerprint,
                    check_sha256,
                    self.canonical(check_contract),
                    created_at,
                ),
            )
        result = self.get_runtime_check(check_id)
        assert result is not None
        return result

    def get_runtime_check(self, check_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM detection_runtime_checks WHERE id=?",
                (check_id,),
            ).fetchone()
        return self._runtime_check(row) if row else None

    def latest_runtime_check(
        self,
        deployment_snapshot_id: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_runtime_checks
                WHERE deployment_snapshot_id=?
                ORDER BY created_at DESC LIMIT 1""",
                (deployment_snapshot_id,),
            ).fetchone()
        return self._runtime_check(row) if row else None

    def runtime_check_by_sha256(
        self,
        detection_id: str,
        check_sha256: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_runtime_checks
                WHERE detection_id=? AND check_sha256=?""",
                (detection_id, check_sha256),
            ).fetchone()
        return self._runtime_check(row) if row else None

    def runtime_check_by_assessment(
        self,
        detection_id: str,
        assessment_sha256: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_runtime_checks
                WHERE detection_id=? AND assessment_sha256=?""",
                (detection_id, assessment_sha256),
            ).fetchone()
        return self._runtime_check(row) if row else None

    def record_runtime_assessment(
        self,
        check_id: str,
        assessment_sha256: str,
        assessment: dict[str, Any],
    ) -> dict[str, Any]:
        assessed_at = str(assessment["assessed_at"])
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_runtime_checks
                SET assessment_sha256=?, assessment=?, assessed_at=?
                WHERE id=? AND assessment_sha256=''""",
                (
                    assessment_sha256,
                    self.canonical(assessment),
                    assessed_at,
                    check_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Runtime evidence has already been interpreted")
        result = self.get_runtime_check(check_id)
        assert result is not None
        return result

    def mark_runtime_preserved(
        self,
        check_id: str,
        case_item_id: str,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_runtime_checks SET case_item_id=?
                WHERE id=? AND case_item_id=''""",
                (case_item_id, check_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Runtime assessment is already preserved")
        result = self.get_runtime_check(check_id)
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

    @staticmethod
    def _runtime_check(row: sqlite3.Row) -> dict[str, Any]:
        value = json.loads(row["check_contract"])
        value.update(
            {
                "id": row["id"],
                "detection_id": row["detection_id"],
                "deployment_snapshot_id": row["deployment_snapshot_id"],
                "deployment_snapshot_sha256": row[
                    "deployment_snapshot_sha256"
                ],
                "content_sha256": row["content_sha256"],
                "validation_task_id": row["validation_task_id"],
                "query_fingerprint": row["query_fingerprint"],
                "check_sha256": row["check_sha256"],
                "assessment_sha256": row["assessment_sha256"],
                "assessment": (
                    json.loads(row["assessment"])
                    if row["assessment"]
                    else None
                ),
                "case_item_id": row["case_item_id"],
                "created_at": row["created_at"],
                "assessed_at": row["assessed_at"],
            }
        )
        return value
