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


class DetectionStore:
    """Versioned local detection projects with exact-content review decisions."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS detections (
                    id TEXT PRIMARY KEY,
                    source_validation_id TEXT NOT NULL UNIQUE,
                    case_id TEXT,
                    status TEXT NOT NULL,
                    current_version INTEGER NOT NULL,
                    current_sha256 TEXT NOT NULL,
                    approved_sha256 TEXT NOT NULL,
                    reviewed_by TEXT NOT NULL,
                    reviewed_at TEXT,
                    review_note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS detection_versions (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(detection_id) REFERENCES detections(id) ON DELETE CASCADE,
                    UNIQUE(detection_id, version)
                );
                CREATE TABLE IF NOT EXISTS detection_reviews (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    note TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(detection_id) REFERENCES detections(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS detection_exports (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(detection_id) REFERENCES detections(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS detection_gate_runs (
                    id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    validation_task_id TEXT NOT NULL,
                    baseline_gate_id TEXT NOT NULL,
                    result_count INTEGER NOT NULL,
                    baseline_result_count INTEGER,
                    result_delta_percent REAL,
                    controls TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    accepted_at TEXT,
                    FOREIGN KEY(detection_id) REFERENCES detections(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_detections_updated
                    ON detections(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_detection_versions
                    ON detection_versions(detection_id, version DESC);
                CREATE INDEX IF NOT EXISTS idx_detection_reviews
                    ON detection_reviews(detection_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_detection_gate_runs
                    ON detection_gate_runs(detection_id, created_at DESC);
                """
            )

    def create(
        self,
        detection_id: str,
        source_validation_id: str,
        case_id: str | None,
        content: dict[str, Any],
    ) -> dict[str, Any]:
        now = _now()
        fingerprint = self.fingerprint(content)
        with self._lock, self.connect() as db:
            try:
                db.execute(
                    """INSERT INTO detections
                    (id,source_validation_id,case_id,status,current_version,current_sha256,
                    approved_sha256,reviewed_by,reviewed_at,review_note,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        detection_id,
                        source_validation_id,
                        case_id,
                        "draft",
                        1,
                        fingerprint,
                        "",
                        "",
                        None,
                        "",
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    "This completed validation already has a detection project"
                ) from exc
            db.execute(
                """INSERT INTO detection_versions
                (id,detection_id,version,content,content_sha256,created_at)
                VALUES (?,?,?,?,?,?)""",
                (
                    str(uuid4()),
                    detection_id,
                    1,
                    self.canonical(content),
                    fingerprint,
                    now,
                ),
            )
        result = self.get(detection_id)
        assert result is not None
        return result

    def list(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT d.*, v.content,
                (SELECT COUNT(*) FROM detection_versions x WHERE x.detection_id=d.id)
                    AS version_count,
                (SELECT COUNT(*) FROM detection_reviews r WHERE r.detection_id=d.id)
                    AS review_count,
                (SELECT COUNT(*) FROM detection_exports e WHERE e.detection_id=d.id)
                    AS export_count
                FROM detections d JOIN detection_versions v
                  ON v.detection_id=d.id AND v.version=d.current_version
                ORDER BY d.updated_at DESC LIMIT ?""",
                (min(max(limit, 1), 500),),
            ).fetchall()
        values = [self._summary(row) for row in rows]
        for value in values:
            value["latest_gate"] = self.latest_gate(
                value["id"], value["current_sha256"]
            )
        return values

    def get(self, detection_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT d.*, v.content,
                (SELECT COUNT(*) FROM detection_versions x WHERE x.detection_id=d.id)
                    AS version_count,
                (SELECT COUNT(*) FROM detection_reviews r WHERE r.detection_id=d.id)
                    AS review_count,
                (SELECT COUNT(*) FROM detection_exports e WHERE e.detection_id=d.id)
                    AS export_count
                FROM detections d JOIN detection_versions v
                  ON v.detection_id=d.id AND v.version=d.current_version
                WHERE d.id=?""",
                (detection_id,),
            ).fetchone()
            if row is None:
                return None
            versions = db.execute(
                """SELECT id,version,content_sha256,created_at
                FROM detection_versions WHERE detection_id=? ORDER BY version DESC""",
                (detection_id,),
            ).fetchall()
            reviews = db.execute(
                """SELECT * FROM detection_reviews WHERE detection_id=?
                ORDER BY created_at DESC""",
                (detection_id,),
            ).fetchall()
            exports = db.execute(
                """SELECT * FROM detection_exports WHERE detection_id=?
                ORDER BY created_at DESC""",
                (detection_id,),
            ).fetchall()
            gate_runs = db.execute(
                """SELECT * FROM detection_gate_runs WHERE detection_id=?
                ORDER BY created_at DESC""",
                (detection_id,),
            ).fetchall()
        value = self._summary(row)
        value["versions"] = [dict(item) for item in versions]
        value["reviews"] = [dict(item) for item in reviews]
        value["exports"] = [dict(item) for item in exports]
        value["gate_runs"] = [self._gate(item) for item in gate_runs]
        value["latest_gate"] = next(
            (
                item
                for item in value["gate_runs"]
                if item["content_sha256"] == value["current_sha256"]
            ),
            None,
        )
        return value

    def find_by_source(self, validation_task_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT id FROM detections WHERE source_validation_id=?",
                (validation_task_id,),
            ).fetchone()
        return self.get(str(row["id"])) if row else None

    def add_version(self, detection_id: str, content: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get(detection_id)
        if current is None:
            return None
        if current["status"] == "in-review":
            raise ValueError("A detection in review must receive a decision before it can be edited")
        if current["status"] == "retired":
            raise ValueError("A retired detection cannot be edited")
        fingerprint = self.fingerprint(content)
        if fingerprint == current["current_sha256"]:
            return current
        version = int(current["current_version"]) + 1
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO detection_versions
                (id,detection_id,version,content,content_sha256,created_at)
                VALUES (?,?,?,?,?,?)""",
                (
                    str(uuid4()),
                    detection_id,
                    version,
                    self.canonical(content),
                    fingerprint,
                    now,
                ),
            )
            db.execute(
                """UPDATE detections SET status='draft',current_version=?,current_sha256=?,
                approved_sha256='',reviewed_by='',reviewed_at=NULL,review_note='',updated_at=?
                WHERE id=?""",
                (version, fingerprint, now, detection_id),
            )
        return self.get(detection_id)

    def submit(self, detection_id: str) -> dict[str, Any] | None:
        current = self.get(detection_id)
        if current is None:
            return None
        if current["status"] not in {"draft", "changes-requested"}:
            raise ValueError("Only a draft or changes-requested detection can enter review")
        with self._lock, self.connect() as db:
            db.execute(
                "UPDATE detections SET status='in-review',updated_at=? WHERE id=?",
                (_now(), detection_id),
            )
        return self.get(detection_id)

    def review(
        self,
        detection_id: str,
        *,
        decision: str,
        expected_sha256: str,
        reviewer: str,
        note: str,
        accepted_gate_id: str = "",
    ) -> dict[str, Any] | None:
        current = self.get(detection_id)
        if current is None:
            return None
        if current["status"] != "in-review":
            raise ValueError("Only a detection currently in review can receive a decision")
        if current["current_sha256"] != expected_sha256:
            raise ValueError("Detection content changed; review the current version before deciding")
        status = "approved" if decision == "approve" else "changes-requested"
        now = _now()
        with self._lock, self.connect() as db:
            if decision == "approve":
                gate = db.execute(
                    """UPDATE detection_gate_runs SET accepted_at=?
                    WHERE id=? AND detection_id=? AND content_sha256=?
                    AND status='pass' AND accepted_at IS NULL""",
                    (
                        now,
                        accepted_gate_id,
                        detection_id,
                        expected_sha256,
                    ),
                )
                if not gate.rowcount:
                    raise ValueError(
                        "The exact passing promotion gate could not be accepted"
                    )
            db.execute(
                """INSERT INTO detection_reviews
                (id,detection_id,version,decision,reviewer,note,content_sha256,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (
                    str(uuid4()),
                    detection_id,
                    current["current_version"],
                    decision,
                    reviewer,
                    note,
                    expected_sha256,
                    now,
                ),
            )
            db.execute(
                """UPDATE detections SET status=?,approved_sha256=?,reviewed_by=?,
                reviewed_at=?,review_note=?,updated_at=?
                WHERE id=? AND status='in-review' AND current_sha256=?""",
                (
                    status,
                    expected_sha256 if decision == "approve" else "",
                    reviewer,
                    now,
                    note,
                    now,
                    detection_id,
                    expected_sha256,
                ),
            )
            changed = db.execute("SELECT changes()").fetchone()
            if changed is None or int(changed[0]) != 1:
                raise ValueError(
                    "Detection content changed; review the current version before deciding"
                )
        return self.get(detection_id)

    def retire(self, detection_id: str) -> dict[str, Any] | None:
        current = self.get(detection_id)
        if current is None:
            return None
        if current["status"] != "approved":
            raise ValueError("Only an approved detection can be retired")
        with self._lock, self.connect() as db:
            db.execute(
                "UPDATE detections SET status='retired',updated_at=? WHERE id=?",
                (_now(), detection_id),
            )
        return self.get(detection_id)

    def delete(self, detection_id: str) -> bool:
        current = self.get(detection_id)
        if current is None:
            return False
        if any(review["decision"] == "approve" for review in current["reviews"]):
            raise ValueError("A previously approved detection must be retained and retired")
        if current["status"] not in {"draft", "changes-requested"}:
            raise ValueError("Only unapproved draft detections can be deleted")
        with self._lock, self.connect() as db:
            result = db.execute("DELETE FROM detections WHERE id=?", (detection_id,))
        return bool(result.rowcount)

    def record_export(
        self,
        detection_id: str,
        filename: str,
        content_sha256: str,
        archive_sha256: str,
    ) -> dict[str, Any] | None:
        current = self.get(detection_id)
        if current is None:
            return None
        now = _now()
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO detection_exports
                (id,detection_id,version,filename,content_sha256,archive_sha256,created_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    str(uuid4()),
                    detection_id,
                    current["current_version"],
                    filename,
                    content_sha256,
                    archive_sha256,
                    now,
                ),
            )
            db.execute("UPDATE detections SET updated_at=? WHERE id=?", (now, detection_id))
        return self.get(detection_id)

    def record_gate(
        self,
        detection_id: str,
        *,
        content_sha256: str,
        status: str,
        score: int,
        validation_task_id: str,
        baseline_gate_id: str,
        result_count: int,
        baseline_result_count: int | None,
        result_delta_percent: float | None,
        controls: list[dict[str, Any]],
    ) -> dict[str, Any]:
        gate_id = str(uuid4())
        now = _now()
        with self._lock, self.connect() as db:
            current = db.execute(
                """SELECT current_version,current_sha256 FROM detections
                WHERE id=?""",
                (detection_id,),
            ).fetchone()
            if current is None:
                raise KeyError("Detection not found")
            if current["current_sha256"] != content_sha256:
                raise ValueError("Detection content changed while the gate was running")
            db.execute(
                """INSERT INTO detection_gate_runs
                (id,detection_id,version,content_sha256,status,score,validation_task_id,
                baseline_gate_id,result_count,baseline_result_count,result_delta_percent,
                controls,created_at,accepted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                (
                    gate_id,
                    detection_id,
                    int(current["current_version"]),
                    content_sha256,
                    status,
                    score,
                    validation_task_id,
                    baseline_gate_id,
                    result_count,
                    baseline_result_count,
                    result_delta_percent,
                    json.dumps(controls, sort_keys=True, default=str),
                    now,
                ),
            )
            db.execute("UPDATE detections SET updated_at=? WHERE id=?", (now, detection_id))
            row = db.execute(
                "SELECT * FROM detection_gate_runs WHERE id=?", (gate_id,)
            ).fetchone()
        assert row is not None
        return self._gate(row)

    def latest_gate(
        self, detection_id: str, content_sha256: str = ""
    ) -> dict[str, Any] | None:
        clause = "AND content_sha256=?" if content_sha256 else ""
        arguments: tuple[Any, ...] = (
            (detection_id, content_sha256) if content_sha256 else (detection_id,)
        )
        with self.connect() as db:
            row = db.execute(
                f"""SELECT * FROM detection_gate_runs WHERE detection_id=? {clause}
                ORDER BY created_at DESC LIMIT 1""",
                arguments,
            ).fetchone()
        return self._gate(row) if row else None

    def accepted_gate(self, detection_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM detection_gate_runs WHERE detection_id=?
                AND accepted_at IS NOT NULL ORDER BY accepted_at DESC LIMIT 1""",
                (detection_id,),
            ).fetchone()
        return self._gate(row) if row else None

    @staticmethod
    def canonical(content: dict[str, Any]) -> str:
        return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def fingerprint(cls, content: dict[str, Any]) -> str:
        return hashlib.sha256(cls.canonical(content).encode()).hexdigest()

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "source_validation_id": row["source_validation_id"],
            "case_id": row["case_id"],
            "status": row["status"],
            "current_version": int(row["current_version"]),
            "current_sha256": row["current_sha256"],
            "approved_sha256": row["approved_sha256"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "review_note": row["review_note"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version_count": int(row["version_count"]),
            "review_count": int(row["review_count"]),
            "export_count": int(row["export_count"]),
            "content": json.loads(row["content"]),
        }

    @staticmethod
    def _gate(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "detection_id": row["detection_id"],
            "version": int(row["version"]),
            "content_sha256": row["content_sha256"],
            "status": row["status"],
            "score": int(row["score"]),
            "validation_task_id": row["validation_task_id"],
            "baseline_gate_id": row["baseline_gate_id"],
            "result_count": int(row["result_count"]),
            "baseline_result_count": (
                int(row["baseline_result_count"])
                if row["baseline_result_count"] is not None
                else None
            ),
            "result_delta_percent": (
                float(row["result_delta_percent"])
                if row["result_delta_percent"] is not None
                else None
            ),
            "controls": json.loads(row["controls"]),
            "created_at": row["created_at"],
            "accepted_at": row["accepted_at"],
        }
