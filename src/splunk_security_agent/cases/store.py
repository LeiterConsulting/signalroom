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
        self._default_binding: dict[str, str] = {}
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
                    tags TEXT NOT NULL,
                    connection_alias TEXT NOT NULL DEFAULT 'primary',
                    connection_fingerprint TEXT NOT NULL DEFAULT '',
                    tenant_scope_id TEXT NOT NULL DEFAULT 'workspace-primary',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
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
            self._ensure_column(db, "cases", "connection_alias", "TEXT NOT NULL DEFAULT 'primary'")
            self._ensure_column(db, "cases", "connection_fingerprint", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                db, "cases", "tenant_scope_id", "TEXT NOT NULL DEFAULT 'workspace-primary'"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_scope_updated "
                "ON cases(tenant_scope_id, connection_alias, updated_at DESC)"
            )

    @staticmethod
    def _ensure_column(
        db: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def bind_unbound(self, binding: dict[str, object]) -> None:
        """Attach legacy cases to the configured Primary Splunk identity once."""
        self._default_binding = {
            "connection_alias": str(binding.get("alias") or "primary"),
            "connection_fingerprint": str(binding.get("fingerprint") or ""),
            "tenant_scope_id": str(binding.get("tenant_scope_id") or "workspace-primary"),
        }
        with self._lock, self.connect() as db:
            db.execute(
                """UPDATE cases SET connection_alias=?, connection_fingerprint=?,
                tenant_scope_id=? WHERE connection_fingerprint=''""",
                (
                    str(binding.get("alias") or "primary"),
                    str(binding.get("fingerprint") or ""),
                    str(binding.get("tenant_scope_id") or "workspace-primary"),
                ),
            )

    def create(self, value: CaseCreate) -> CaseRecord:
        if not value.connection_fingerprint and self._default_binding:
            value = value.model_copy(update=self._default_binding)
        now = datetime.now(UTC).isoformat()
        case_id = str(uuid4())
        with self._lock, self.connect() as db:
            db.execute(
                """INSERT INTO cases
                (id,title,summary,status,severity,owner,tags,connection_alias,
                connection_fingerprint,tenant_scope_id,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    case_id,
                    value.title.strip(),
                    value.summary.strip(),
                    "open",
                    value.severity,
                    value.owner.strip() or "Unassigned",
                    json.dumps(sorted(set(value.tags))),
                    value.connection_alias,
                    value.connection_fingerprint,
                    value.tenant_scope_id,
                    now,
                    now,
                ),
            )
        result = self.get(case_id, value.tenant_scope_id)
        assert result is not None
        return result

    def list(self, limit: int = 100, tenant_scope_id: str | None = None) -> list[CaseRecord]:
        with self.connect() as db:
            sql = """SELECT c.*, COUNT(i.id) item_count FROM cases c
                LEFT JOIN case_items i ON i.case_id = c.id"""
            params: list[object] = []
            if tenant_scope_id is not None:
                sql += " WHERE c.tenant_scope_id=?"
                params.append(tenant_scope_id)
            sql += " GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ?"
            params.append(limit)
            rows = db.execute(sql, params).fetchall()
        return [self._case(row) for row in rows]

    def get(self, case_id: str, tenant_scope_id: str | None = None) -> CaseRecord | None:
        with self.connect() as db:
            sql = """SELECT c.*, COUNT(i.id) item_count FROM cases c
                LEFT JOIN case_items i ON i.case_id = c.id
                WHERE c.id = ?"""
            params: list[object] = [case_id]
            if tenant_scope_id is not None:
                sql += " AND c.tenant_scope_id=?"
                params.append(tenant_scope_id)
            sql += " GROUP BY c.id"
            row = db.execute(sql, params).fetchone()
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

    def update(
        self, case_id: str, value: CaseUpdate, tenant_scope_id: str | None = None
    ) -> CaseRecord | None:
        fields = value.model_dump(exclude_none=True)
        if not fields:
            return self.get(case_id, tenant_scope_id)
        if "tags" in fields:
            fields["tags"] = json.dumps(sorted(set(fields["tags"])))
        fields["updated_at"] = datetime.now(UTC).isoformat()
        assignments = ", ".join(f"{name} = ?" for name in fields)
        with self._lock, self.connect() as db:
            where = "id = ?"
            params: list[object] = [*fields.values(), case_id]
            if tenant_scope_id is not None:
                where += " AND tenant_scope_id=?"
                params.append(tenant_scope_id)
            result = db.execute(f"UPDATE cases SET {assignments} WHERE {where}", params)
        return self.get(case_id, tenant_scope_id) if result.rowcount else None

    def delete(self, case_id: str, tenant_scope_id: str | None = None) -> bool:
        with self._lock, self.connect() as db:
            if tenant_scope_id is None:
                result = db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            else:
                result = db.execute(
                    "DELETE FROM cases WHERE id=? AND tenant_scope_id=?",
                    (case_id, tenant_scope_id),
                )
        return bool(result.rowcount)

    def add_item(
        self, case_id: str, value: CaseItemCreate, tenant_scope_id: str | None = None
    ) -> CaseItemRecord | None:
        if not self.get(case_id, tenant_scope_id):
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
        self,
        case_id: str,
        item_id: str,
        value: CaseItemUpdate,
        tenant_scope_id: str | None = None,
    ) -> CaseItemRecord | None:
        if not self.get(case_id, tenant_scope_id):
            return None
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

    def delete_item(
        self, case_id: str, item_id: str, tenant_scope_id: str | None = None
    ) -> bool:
        if not self.get(case_id, tenant_scope_id):
            return False
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

    def export(
        self, case_id: str, formats: list[str], tenant_scope_id: str | None = None
    ) -> list[Path]:
        case = self.get(case_id, tenant_scope_id)
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
            f"- Splunk connection: {case.connection_alias}",
            f"- Tenant scope: `{case.tenant_scope_id}`",
            f"- Connection revision: `{case.connection_fingerprint}`",
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
            connection_alias=row["connection_alias"],
            connection_fingerprint=row["connection_fingerprint"],
            tenant_scope_id=row["tenant_scope_id"],
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
