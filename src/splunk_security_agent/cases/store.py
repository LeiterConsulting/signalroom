from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import uuid4

from ..schemas import (
    CaseCreate,
    CaseItemCreate,
    CaseItemRecord,
    CaseItemUpdate,
    CaseRecord,
    CaseUpdate,
)


class CaseStore:
    """Durable local investigation cases and chronological analyst timelines."""

    def __init__(self, path: Path | str, export_dir: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
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
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL,
                    status TEXT NOT NULL, severity TEXT NOT NULL, owner TEXT NOT NULL,
                    tags TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_items (
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL, kind TEXT NOT NULL,
                    title TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL,
                    confidence TEXT NOT NULL, status TEXT NOT NULL, occurred_at TEXT,
                    metadata TEXT NOT NULL, created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_case_items_case_created
                    ON case_items(case_id, created_at);
                """
            )

    def create(self, value: CaseCreate) -> CaseRecord:
        now = datetime.now(UTC).isoformat()
        case_id = str(uuid4())
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO cases
                (id,title,summary,status,severity,owner,tags,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    case_id,
                    value.title.strip(),
                    value.summary.strip(),
                    "open",
                    value.severity,
                    value.owner.strip() or "Unassigned",
                    json.dumps(sorted(set(value.tags))),
                    now,
                    now,
                ),
            )
        result = self.get(case_id)
        assert result is not None
        return result

    def list(self, limit: int = 100) -> list[CaseRecord]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT c.*, COUNT(i.id) item_count FROM cases c
                LEFT JOIN case_items i ON i.case_id = c.id
                GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._case(row) for row in rows]

    def get(self, case_id: str) -> CaseRecord | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT c.*, COUNT(i.id) item_count FROM cases c
                LEFT JOIN case_items i ON i.case_id = c.id
                WHERE c.id = ? GROUP BY c.id""",
                (case_id,),
            ).fetchone()
            if not row:
                return None
            items = db.execute(
                """SELECT * FROM case_items WHERE case_id = ?
                ORDER BY COALESCE(occurred_at, created_at), created_at""",
                (case_id,),
            ).fetchall()
        case = self._case(row)
        case.items = [self._item(item) for item in items]
        return case

    def update(self, case_id: str, value: CaseUpdate) -> CaseRecord | None:
        fields = value.model_dump(exclude_none=True)
        if not fields:
            return self.get(case_id)
        if "tags" in fields:
            fields["tags"] = json.dumps(sorted(set(fields["tags"])))
        fields["updated_at"] = datetime.now(UTC).isoformat()
        assignments = ", ".join(f"{name} = ?" for name in fields)
        with self._lock, self.connect() as db:
            result = db.execute(
                f"UPDATE cases SET {assignments} WHERE id = ?",
                (*fields.values(), case_id),
            )
        return self.get(case_id) if result.rowcount else None

    def delete(self, case_id: str) -> bool:
        with self._lock, self.connect() as db:
            result = db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        return bool(result.rowcount)

    def add_item(self, case_id: str, value: CaseItemCreate) -> CaseItemRecord | None:
        if not self.get(case_id):
            return None
        now = datetime.now(UTC).isoformat()
        item_id = str(uuid4())
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO case_items
                (id,case_id,kind,title,content,source,confidence,status,occurred_at,metadata,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item_id,
                    case_id,
                    value.kind,
                    value.title.strip(),
                    value.content.strip(),
                    value.source.strip() or "analyst",
                    value.confidence,
                    value.status,
                    value.occurred_at,
                    json.dumps(value.metadata, default=str),
                    now,
                ),
            )
            db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
            row = db.execute("SELECT * FROM case_items WHERE id = ?", (item_id,)).fetchone()
        return self._item(row) if row else None

    def update_item(
        self, case_id: str, item_id: str, value: CaseItemUpdate
    ) -> CaseItemRecord | None:
        fields = value.model_dump(exclude_none=True)
        if not fields:
            with self.connect() as db:
                row = db.execute(
                    "SELECT * FROM case_items WHERE id = ? AND case_id = ?", (item_id, case_id)
                ).fetchone()
            return self._item(row) if row else None
        if "metadata" in fields:
            fields["metadata"] = json.dumps(fields["metadata"], default=str)
        assignments = ", ".join(f"{name} = ?" for name in fields)
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as db:
            result = db.execute(
                f"UPDATE case_items SET {assignments} WHERE id = ? AND case_id = ?",
                (*fields.values(), item_id, case_id),
            )
            if not result.rowcount:
                return None
            db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
            row = db.execute("SELECT * FROM case_items WHERE id = ?", (item_id,)).fetchone()
        return self._item(row) if row else None

    def delete_item(self, case_id: str, item_id: str) -> bool:
        with self._lock, self.connect() as db:
            result = db.execute(
                "DELETE FROM case_items WHERE id = ? AND case_id = ?", (item_id, case_id)
            )
            if result.rowcount:
                db.execute(
                    "UPDATE cases SET updated_at = ? WHERE id = ?",
                    (datetime.now(UTC).isoformat(), case_id),
                )
        return bool(result.rowcount)

    def export(self, case_id: str, formats: list[str]) -> list[Path]:
        case = self.get(case_id)
        if not case:
            return []
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        stem = f"signalroom_case_{case.id[:8]}_{stamp}"
        paths: list[Path] = []
        if "json" in formats:
            path = self.export_dir / f"{stem}.json"
            path.write_text(json.dumps(case.model_dump(mode="json"), indent=2), encoding="utf-8")
            paths.append(path)
        if "markdown" in formats:
            path = self.export_dir / f"{stem}.md"
            path.write_text(self._markdown(case), encoding="utf-8")
            paths.append(path)
        return paths

    @staticmethod
    def _markdown(case: CaseRecord) -> str:
        lines = [
            f"# {case.title}",
            "",
            f"- Case ID: `{case.id}`",
            f"- Status: {case.status}",
            f"- Severity: {case.severity}",
            f"- Owner: {case.owner}",
            f"- Updated: {case.updated_at}",
            f"- Tags: {', '.join(case.tags) or 'none'}",
            "",
            "## Executive summary",
            "",
            case.summary or "No case summary has been recorded.",
            "",
            "## Investigation timeline",
            "",
        ]
        for item in case.items:
            timestamp = item.occurred_at or item.created_at
            quoted_content = "\n".join(f"> {line}" if line else ">" for line in item.content.splitlines())
            lines.extend(
                [
                    f"### {timestamp} · {item.kind.title()} · {item.title}",
                    "",
                    f"Source: {item.source}  ",
                    f"Confidence: {item.confidence}  ",
                    f"Status: {item.status}",
                    "",
                    quoted_content,
                    "",
                ]
            )
        lines.extend(
            [
                "## Handoff note",
                "",
                "This package preserves analyst-entered notes and SignalRoom evidence references. "
                "Revalidate material findings in Splunk before taking action.",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _case(row: sqlite3.Row) -> CaseRecord:
        return CaseRecord(
            id=row["id"],
            title=row["title"],
            summary=row["summary"],
            status=row["status"],
            severity=row["severity"],
            owner=row["owner"],
            tags=json.loads(row["tags"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            item_count=int(row["item_count"]),
        )

    @staticmethod
    def _item(row: sqlite3.Row) -> CaseItemRecord:
        return CaseItemRecord(
            id=row["id"],
            case_id=row["case_id"],
            kind=row["kind"],
            title=row["title"],
            content=row["content"],
            source=row["source"],
            confidence=row["confidence"],
            status=row["status"],
            occurred_at=row["occurred_at"],
            metadata=json.loads(row["metadata"]),
            created_at=row["created_at"],
        )
