from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


def _now() -> str:
    return datetime.now(UTC).isoformat()


class DetectionRepositoryStore:
    """Durable preview and handoff state bound to exact repository commits."""

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
                CREATE TABLE IF NOT EXISTS detection_repository_handoffs (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    repository_path TEXT NOT NULL,
                    base_ref TEXT NOT NULL,
                    base_commit TEXT NOT NULL,
                    branch_name TEXT NOT NULL UNIQUE,
                    archive_path TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    signing_key_sha256 TEXT NOT NULL,
                    preview_contract TEXT NOT NULL,
                    preview_sha256 TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    commit_sha TEXT NOT NULL DEFAULT '',
                    remote_name TEXT NOT NULL,
                    pull_request_url TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    applied_at TEXT,
                    pushed_at TEXT,
                    pull_request_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_detection_repository_latest
                    ON detection_repository_handoffs(detection_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS detection_repository_review_snapshots (
                    id TEXT PRIMARY KEY,
                    handoff_id TEXT NOT NULL,
                    detection_id TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL UNIQUE,
                    snapshot TEXT NOT NULL,
                    case_item_id TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detection_repository_review_latest
                    ON detection_repository_review_snapshots(
                        handoff_id, observed_at DESC
                    );
                """
            )

    def create(self, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO detection_repository_handoffs
                (id,detection_id,version,content_sha256,repository_path,base_ref,
                base_commit,branch_name,archive_path,archive_sha256,
                signing_key_sha256,preview_contract,preview_sha256,status,
                remote_name,created_at,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    value["id"],
                    value["detection_id"],
                    value["version"],
                    value["content_sha256"],
                    value["repository_path"],
                    value["base_ref"],
                    value["base_commit"],
                    value["branch_name"],
                    value["archive_path"],
                    value["archive_sha256"],
                    value["signing_key_sha256"],
                    self.canonical(value["preview_contract"]),
                    value["preview_sha256"],
                    "previewed",
                    value["remote_name"],
                    value["created_at"],
                    value["expires_at"],
                ),
            )
        result = self.get(value["id"])
        assert result is not None
        return result

    def get(self, handoff_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM detection_repository_handoffs WHERE id=?",
                (handoff_id,),
            ).fetchone()
        return self._record(row) if row else None

    def latest(self, detection_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_repository_handoffs
                WHERE detection_id=? ORDER BY created_at DESC LIMIT 1""",
                (detection_id,),
            ).fetchone()
        return self._record(row) if row else None

    def mark_applied(
        self,
        handoff_id: str,
        preview_sha256: str,
        commit_sha: str,
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_repository_handoffs
                SET status='applied',commit_sha=?,applied_at=?
                WHERE id=? AND preview_sha256=? AND status='previewed'""",
                (commit_sha, now, handoff_id, preview_sha256),
            )
            if cursor.rowcount != 1:
                raise ValueError("Repository preview is no longer eligible to apply")
        result = self.get(handoff_id)
        assert result is not None
        return result

    def mark_pushed(
        self,
        handoff_id: str,
        commit_sha: str,
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_repository_handoffs
                SET status='pushed',pushed_at=?
                WHERE id=? AND commit_sha=? AND status IN ('applied','pushed')""",
                (now, handoff_id, commit_sha),
            )
            if cursor.rowcount != 1:
                raise ValueError("Repository handoff is not eligible to push")
        result = self.get(handoff_id)
        assert result is not None
        return result

    def mark_pull_request(
        self,
        handoff_id: str,
        commit_sha: str,
        url: str,
    ) -> dict[str, Any]:
        now = _now()
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_repository_handoffs
                SET status='pull-request-opened',pull_request_url=?,
                pull_request_at=?
                WHERE id=? AND commit_sha=?
                AND status IN ('pushed','pull-request-opened')""",
                (url, now, handoff_id, commit_sha),
            )
            if cursor.rowcount != 1:
                raise ValueError("Repository handoff is not eligible for a pull request")
        result = self.get(handoff_id)
        assert result is not None
        return result

    def record_review(
        self,
        handoff_id: str,
        detection_id: str,
        commit_sha: str,
        snapshot_sha256: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        review_id = str(uuid4())
        observed_at = str(snapshot["observed_at"])
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO detection_repository_review_snapshots
                (id,handoff_id,detection_id,commit_sha,snapshot_sha256,
                snapshot,observed_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    review_id,
                    handoff_id,
                    detection_id,
                    commit_sha,
                    snapshot_sha256,
                    self.canonical(snapshot),
                    observed_at,
                ),
            )
        result = self.review(review_id)
        assert result is not None
        return result

    def review(self, review_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_repository_review_snapshots
                WHERE id=?""",
                (review_id,),
            ).fetchone()
        return self._review(row) if row else None

    def latest_review(self, handoff_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_repository_review_snapshots
                WHERE handoff_id=? ORDER BY observed_at DESC LIMIT 1""",
                (handoff_id,),
            ).fetchone()
        return self._review(row) if row else None

    def review_by_sha256(
        self,
        handoff_id: str,
        snapshot_sha256: str,
    ) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_repository_review_snapshots
                WHERE handoff_id=? AND snapshot_sha256=?""",
                (handoff_id, snapshot_sha256),
            ).fetchone()
        return self._review(row) if row else None

    def mark_review_preserved(
        self,
        review_id: str,
        case_item_id: str,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as db:
            cursor = db.execute(
                """UPDATE detection_repository_review_snapshots
                SET case_item_id=?
                WHERE id=? AND case_item_id=''""",
                (case_item_id, review_id),
            )
            if cursor.rowcount != 1:
                raise ValueError(
                    "Repository review snapshot is already preserved"
                )
        result = self.review(review_id)
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
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "detection_id": row["detection_id"],
            "version": int(row["version"]),
            "content_sha256": row["content_sha256"],
            "repository_path": row["repository_path"],
            "base_ref": row["base_ref"],
            "base_commit": row["base_commit"],
            "branch_name": row["branch_name"],
            "archive_path": row["archive_path"],
            "archive_sha256": row["archive_sha256"],
            "signing_key_sha256": row["signing_key_sha256"],
            "preview_contract": json.loads(row["preview_contract"]),
            "preview_sha256": row["preview_sha256"],
            "status": row["status"],
            "commit_sha": row["commit_sha"],
            "remote_name": row["remote_name"],
            "pull_request_url": row["pull_request_url"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "applied_at": row["applied_at"],
            "pushed_at": row["pushed_at"],
            "pull_request_at": row["pull_request_at"],
        }

    @staticmethod
    def _review(row: sqlite3.Row) -> dict[str, Any]:
        value = json.loads(row["snapshot"])
        value.update(
            {
                "id": row["id"],
                "handoff_id": row["handoff_id"],
                "detection_id": row["detection_id"],
                "commit_sha": row["commit_sha"],
                "snapshot_sha256": row["snapshot_sha256"],
                "case_item_id": row["case_item_id"],
                "observed_at": row["observed_at"],
            }
        )
        return value
