from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..schemas import ArtifactCreate, ArtifactRecord, ArtifactUpdate, EvidenceRef

STOPWORDS = {
    "about",
    "after",
    "also",
    "and",
    "are",
    "from",
    "have",
    "into",
    "show",
    "splunk",
    "that",
    "the",
    "their",
    "these",
    "this",
    "what",
    "when",
    "where",
    "which",
    "with",
}


class EvidenceStore:
    """SQLite FTS evidence library with stable chunk references and no external dependency."""

    def __init__(self, path: Path | str = "data/evidence.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._default_binding: dict[str, str] = {}
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL,
                    tags TEXT NOT NULL, content TEXT NOT NULL, metadata TEXT NOT NULL,
                    connection_alias TEXT NOT NULL DEFAULT 'primary',
                    connection_fingerprint TEXT NOT NULL DEFAULT '',
                    tenant_scope_id TEXT NOT NULL DEFAULT 'workspace-primary',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chunks (
                    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
                    title TEXT NOT NULL, content TEXT NOT NULL,
                    FOREIGN KEY(artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                    chunk_id UNINDEXED, artifact_id UNINDEXED, title, content, tokenize='porter unicode61'
                );
                CREATE TABLE IF NOT EXISTS embeddings (
                    chunk_id TEXT NOT NULL, model_profile TEXT NOT NULL, vector TEXT NOT NULL,
                    updated_at TEXT NOT NULL, PRIMARY KEY(chunk_id, model_profile)
                );
                """
            )
            self._ensure_column(
                db, "artifacts", "connection_alias", "TEXT NOT NULL DEFAULT 'primary'"
            )
            self._ensure_column(
                db, "artifacts", "connection_fingerprint", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(
                db, "artifacts", "tenant_scope_id", "TEXT NOT NULL DEFAULT 'workspace-primary'"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_scope_updated "
                "ON artifacts(tenant_scope_id, connection_alias, updated_at DESC)"
            )

    @staticmethod
    def _ensure_column(
        db: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def bind_unbound(self, binding: dict[str, Any]) -> None:
        """Attach pre-scope artifacts to the configured Primary identity once."""
        alias = str(binding.get("alias") or "primary")
        fingerprint = str(binding.get("fingerprint") or "")
        tenant_scope_id = str(binding.get("tenant_scope_id") or "workspace-primary")
        self._default_binding = {
            "connection_alias": alias,
            "connection_fingerprint": fingerprint,
            "tenant_scope_id": tenant_scope_id,
        }
        with self.connect() as db:
            db.execute(
                """UPDATE artifacts SET connection_alias=?, connection_fingerprint=?,
                tenant_scope_id=? WHERE connection_fingerprint=''""",
                (alias, fingerprint, tenant_scope_id),
            )

    @staticmethod
    def _chunks(content: str, size: int = 1100, overlap: int = 160) -> list[str]:
        blocks = [part.strip() for part in re.split(r"\n\s*\n", content) if part.strip()]
        chunks: list[str] = []
        current = ""
        for block in blocks:
            if current and len(current) + len(block) + 2 > size:
                chunks.append(current)
                tail = current[-overlap:]
                sentence_breaks = [tail.find(marker) for marker in (". ", "! ", "? ", "\n")]
                sentence_breaks = [position for position in sentence_breaks if position >= 0]
                if sentence_breaks:
                    tail = tail[min(sentence_breaks) + 1 :].lstrip()
                else:
                    word_break = re.search(r"\s+", tail)
                    tail = tail[word_break.end() :] if word_break else tail
                current = f"{tail}\n\n{block}".strip()
            else:
                current = f"{current}\n\n{block}".strip()
        if current:
            chunks.append(current)
        return chunks or [content[:size]]

    def add(self, record: ArtifactCreate, metadata: dict[str, Any] | None = None) -> ArtifactRecord:
        if not record.connection_fingerprint and self._default_binding:
            record = record.model_copy(update=self._default_binding)
        now = datetime.now(UTC).isoformat()
        artifact_id = hashlib.sha256(
            f"{record.tenant_scope_id}\0{record.connection_alias}\0"
            f"{record.connection_fingerprint}\0{record.title}\0{record.content}".encode()
        ).hexdigest()[:16]
        payload = ArtifactRecord(
            id=artifact_id,
            title=record.title.strip(),
            kind=record.kind,
            source=record.source,
            tags=sorted(set(record.tags)),
            content=record.content.strip(),
            metadata=metadata or {},
            connection_alias=record.connection_alias,
            connection_fingerprint=record.connection_fingerprint,
            tenant_scope_id=record.tenant_scope_id,
            created_at=now,
            updated_at=now,
        )
        with self.connect() as db:
            existing = db.execute("SELECT created_at FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
            if existing:
                payload.created_at = existing["created_at"]
            db.execute(
                """INSERT OR REPLACE INTO artifacts
                (id,title,kind,source,tags,content,metadata,connection_alias,
                connection_fingerprint,tenant_scope_id,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    payload.id,
                    payload.title,
                    payload.kind,
                    payload.source,
                    json.dumps(payload.tags),
                    payload.content,
                    json.dumps(payload.metadata),
                    payload.connection_alias,
                    payload.connection_fingerprint,
                    payload.tenant_scope_id,
                    payload.created_at,
                    payload.updated_at,
                ),
            )
            db.execute("DELETE FROM chunks WHERE artifact_id = ?", (artifact_id,))
            db.execute("DELETE FROM chunks_fts WHERE artifact_id = ?", (artifact_id,))
            for ordinal, content in enumerate(self._chunks(payload.content)):
                chunk_id = f"{artifact_id}:{ordinal}"
                db.execute(
                    "INSERT INTO chunks (id,artifact_id,ordinal,title,content) VALUES (?,?,?,?,?)",
                    (chunk_id, artifact_id, ordinal, payload.title, content),
                )
                db.execute(
                    "INSERT INTO chunks_fts (chunk_id,artifact_id,title,content) VALUES (?,?,?,?)",
                    (chunk_id, artifact_id, payload.title, content),
                )
        return payload

    def list(self, limit: int = 100, tenant_scope_id: str | None = None) -> list[ArtifactRecord]:
        with self.connect() as db:
            if tenant_scope_id is None:
                rows = db.execute(
                    "SELECT * FROM artifacts ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM artifacts WHERE tenant_scope_id=?
                    ORDER BY updated_at DESC LIMIT ?""",
                    (tenant_scope_id, limit),
                ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get(self, artifact_id: str, tenant_scope_id: str | None = None) -> ArtifactRecord | None:
        with self.connect() as db:
            if tenant_scope_id is None:
                row = db.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM artifacts WHERE id=? AND tenant_scope_id=?",
                    (artifact_id, tenant_scope_id),
                ).fetchone()
        return self._row_to_record(row) if row else None

    def update(
        self, artifact_id: str, value: ArtifactUpdate, tenant_scope_id: str | None = None
    ) -> ArtifactRecord | None:
        current = self.get(artifact_id, tenant_scope_id)
        if not current:
            return None
        changes = value.model_dump(exclude_none=True)
        if not changes:
            return current
        payload = current.model_copy(update=changes)
        payload.title = payload.title.strip()
        payload.content = payload.content.strip()
        payload.source = payload.source.strip() or "operator"
        payload.tags = sorted(set(payload.tags))
        payload.updated_at = datetime.now(UTC).isoformat()
        with self.connect() as db:
            chunk_ids = [
                row["id"]
                for row in db.execute("SELECT id FROM chunks WHERE artifact_id = ?", (artifact_id,))
            ]
            if chunk_ids:
                placeholders = ",".join("?" for _ in chunk_ids)
                db.execute(f"DELETE FROM embeddings WHERE chunk_id IN ({placeholders})", chunk_ids)
            db.execute("DELETE FROM chunks_fts WHERE artifact_id = ?", (artifact_id,))
            db.execute("DELETE FROM chunks WHERE artifact_id = ?", (artifact_id,))
            db.execute(
                """UPDATE artifacts SET title=?,kind=?,source=?,tags=?,content=?,metadata=?,updated_at=?
                WHERE id=?""",
                (
                    payload.title,
                    payload.kind,
                    payload.source,
                    json.dumps(payload.tags),
                    payload.content,
                    json.dumps(payload.metadata),
                    payload.updated_at,
                    artifact_id,
                ),
            )
            for ordinal, content in enumerate(self._chunks(payload.content)):
                chunk_id = f"{artifact_id}:{ordinal}"
                db.execute(
                    "INSERT INTO chunks (id,artifact_id,ordinal,title,content) VALUES (?,?,?,?,?)",
                    (chunk_id, artifact_id, ordinal, payload.title, content),
                )
                db.execute(
                    "INSERT INTO chunks_fts (chunk_id,artifact_id,title,content) VALUES (?,?,?,?)",
                    (chunk_id, artifact_id, payload.title, content),
                )
        return payload

    def delete(self, artifact_id: str, tenant_scope_id: str | None = None) -> bool:
        current = self.get(artifact_id, tenant_scope_id)
        if current is None:
            return False
        with self.connect() as db:
            chunk_ids = [
                row["id"] for row in db.execute("SELECT id FROM chunks WHERE artifact_id = ?", (artifact_id,))
            ]
            if chunk_ids:
                placeholders = ",".join("?" for _ in chunk_ids)
                db.execute(f"DELETE FROM embeddings WHERE chunk_id IN ({placeholders})", chunk_ids)
            db.execute("DELETE FROM chunks_fts WHERE artifact_id = ?", (artifact_id,))
            db.execute("DELETE FROM chunks WHERE artifact_id = ?", (artifact_id,))
            result = db.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))
        return result.rowcount > 0

    def search(
        self, query: str, limit: int = 6, tenant_scope_id: str | None = None
    ) -> list[EvidenceRef]:
        terms = []
        for token in re.findall(r"[a-zA-Z0-9_\-.]{3,}", query.lower()):
            if token not in STOPWORDS and token not in terms:
                terms.append(token)
        if not terms:
            return []
        expression = " OR ".join(f'"{term.replace(chr(34), "")}"' for term in terms[:10])
        sql = """
            SELECT f.chunk_id, f.artifact_id, f.title, c.content,
                   bm25(chunks_fts, 2.0, 1.0) rank, a.source, a.kind,
                   a.connection_alias, a.connection_fingerprint, a.tenant_scope_id
            FROM chunks_fts f
            JOIN chunks c ON c.id = f.chunk_id
            JOIN artifacts a ON a.id = f.artifact_id
            WHERE chunks_fts MATCH ?
        """
        params: list[Any] = [expression]
        if tenant_scope_id is not None:
            sql += " AND a.tenant_scope_id=?"
            params.append(tenant_scope_id)
        sql += " ORDER BY rank LIMIT ?"
        params.append(limit)
        try:
            with self.connect() as db:
                rows = db.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return []
        results = []
        for row in rows:
            rank = abs(float(row["rank"] or 0))
            score = round(1 - math.exp(-rank), 4) if rank else 0.25
            results.append(
                EvidenceRef(
                    id=row["chunk_id"],
                    source=row["source"],
                    title=row["title"],
                    excerpt=self._coherent_excerpt(row["content"], terms),
                    score=score,
                    kind=row["kind"],
                    connection_alias=row["connection_alias"],
                    connection_fingerprint=row["connection_fingerprint"],
                    tenant_scope_id=row["tenant_scope_id"],
                )
            )
        return results

    @staticmethod
    def _coherent_excerpt(content: str, terms: list[str], max_chars: int = 520) -> str:
        """Return a word-safe, sentence-aware excerpt around the earliest matched term."""
        normalized = re.sub(r"\s+", " ", content).strip()
        if len(normalized) <= max_chars:
            return normalized
        lowered = normalized.lower()
        positions = [lowered.find(term.lower()) for term in terms]
        positions = [position for position in positions if position >= 0]
        match_at = min(positions) if positions else 0
        start = max(0, match_at - 140)
        if start:
            sentence_start = max(
                normalized.rfind(". ", 0, match_at),
                normalized.rfind("! ", 0, match_at),
                normalized.rfind("? ", 0, match_at),
            )
            if sentence_start >= max(0, match_at - 240):
                start = sentence_start + 2
            else:
                next_space = normalized.find(" ", start)
                start = next_space + 1 if next_space >= 0 else start
        end = min(len(normalized), start + max_chars)
        if end < len(normalized):
            sentence_end = min(
                (
                    position
                    for marker in (". ", "! ", "? ")
                    if (position := normalized.find(marker, max(start, end - 100), end + 80)) >= 0
                ),
                default=-1,
            )
            if sentence_end >= 0:
                end = sentence_end + 1
            else:
                last_space = normalized.rfind(" ", start, end)
                end = last_space if last_space > start else end
        excerpt = normalized[start:end].strip()
        return ("… " if start else "") + excerpt + (" …" if end < len(normalized) else "")

    def pending_embeddings(
        self, model_profile: str, limit: int = 32, tenant_scope_id: str | None = None
    ) -> list[tuple[str, str]]:
        scope_sql = ""
        params: list[Any] = [model_profile]
        if tenant_scope_id is not None:
            scope_sql = " AND a.tenant_scope_id=?"
            params.append(tenant_scope_id)
        params.append(limit)
        with self.connect() as db:
            rows = db.execute(
                f"""
                SELECT c.id, c.content FROM chunks c
                JOIN artifacts a ON a.id = c.artifact_id
                LEFT JOIN embeddings e ON e.chunk_id = c.id AND e.model_profile = ?
                WHERE e.chunk_id IS NULL{scope_sql} ORDER BY c.id LIMIT ?
                """,
                params,
            ).fetchall()
        return [(row["id"], row["content"]) for row in rows]

    def embedding_status(
        self, model_profile: str, tenant_scope_id: str | None = None
    ) -> dict[str, int]:
        with self.connect() as db:
            if tenant_scope_id is None:
                total = int(db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])
                indexed = int(
                    db.execute(
                        "SELECT COUNT(*) FROM embeddings WHERE model_profile = ?",
                        (model_profile,),
                    ).fetchone()[0]
                )
            else:
                total = int(
                    db.execute(
                        """SELECT COUNT(*) FROM chunks c JOIN artifacts a ON a.id=c.artifact_id
                        WHERE a.tenant_scope_id=?""",
                        (tenant_scope_id,),
                    ).fetchone()[0]
                )
                indexed = int(
                    db.execute(
                        """SELECT COUNT(*) FROM embeddings e JOIN chunks c ON c.id=e.chunk_id
                        JOIN artifacts a ON a.id=c.artifact_id
                        WHERE e.model_profile=? AND a.tenant_scope_id=?""",
                        (model_profile, tenant_scope_id),
                    ).fetchone()[0]
                )
        return {
            "total_chunks": total,
            "indexed_chunks": min(indexed, total),
            "pending_chunks": max(0, total - indexed),
        }

    def semantic_candidates(
        self, limit: int = 24, tenant_scope_id: str | None = None
    ) -> list[EvidenceRef]:
        sql = """
                SELECT c.id, c.title, c.content, a.source, a.kind,
                       a.connection_alias, a.connection_fingerprint, a.tenant_scope_id
                FROM chunks c JOIN artifacts a ON a.id = c.artifact_id
                """
        params: list[Any] = []
        if tenant_scope_id is not None:
            sql += " WHERE a.tenant_scope_id=?"
            params.append(tenant_scope_id)
        sql += " ORDER BY a.updated_at DESC, c.ordinal LIMIT ?"
        params.append(limit)
        with self.connect() as db:
            rows = db.execute(sql, params).fetchall()
        return [
            EvidenceRef(
                id=row["id"],
                source=row["source"],
                title=row["title"],
                excerpt=self._coherent_excerpt(row["content"], [], 520),
                kind=row["kind"],
                connection_alias=row["connection_alias"],
                connection_fingerprint=row["connection_fingerprint"],
                tenant_scope_id=row["tenant_scope_id"],
            )
            for row in rows
        ]

    def save_embeddings(self, model_profile: str, values: list[tuple[str, list[float]]]) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            db.executemany(
                """INSERT OR REPLACE INTO embeddings
                (chunk_id,model_profile,vector,updated_at) VALUES (?,?,?,?)""",
                [(chunk_id, model_profile, json.dumps(vector), now) for chunk_id, vector in values if vector],
            )

    def semantic_search(
        self,
        query_vector: list[float],
        model_profile: str,
        limit: int = 6,
        tenant_scope_id: str | None = None,
    ) -> list[EvidenceRef]:
        if not query_vector:
            return []
        with self.connect() as db:
            sql = """
                SELECT c.id, c.title, c.content, a.source, a.kind, e.vector,
                       a.connection_alias, a.connection_fingerprint, a.tenant_scope_id
                FROM embeddings e JOIN chunks c ON c.id = e.chunk_id
                JOIN artifacts a ON a.id = c.artifact_id
                WHERE e.model_profile = ?
                """
            params: list[Any] = [model_profile]
            if tenant_scope_id is not None:
                sql += " AND a.tenant_scope_id=?"
                params.append(tenant_scope_id)
            rows = db.execute(sql, params).fetchall()
        query_norm = math.sqrt(sum(value * value for value in query_vector)) or 1
        scored: list[tuple[float, sqlite3.Row]] = []
        for row in rows:
            try:
                vector = [float(value) for value in json.loads(row["vector"])]
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if len(vector) != len(query_vector):
                continue
            norm = math.sqrt(sum(value * value for value in vector)) or 1
            score = sum(a * b for a, b in zip(query_vector, vector, strict=True)) / (query_norm * norm)
            scored.append((score, row))
        return [
            EvidenceRef(
                id=row["id"],
                source=row["source"],
                title=row["title"],
                excerpt=self._coherent_excerpt(row["content"], [], 520),
                score=round(score, 4),
                kind=row["kind"],
                connection_alias=row["connection_alias"],
                connection_fingerprint=row["connection_fingerprint"],
                tenant_scope_id=row["tenant_scope_id"],
            )
            for score, row in sorted(scored, key=lambda item: item[0], reverse=True)[:limit]
            if score > 0
        ]

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ArtifactRecord:
        return ArtifactRecord(
            id=row["id"],
            title=row["title"],
            kind=row["kind"],
            source=row["source"],
            tags=json.loads(row["tags"]),
            content=row["content"],
            metadata=json.loads(row["metadata"]),
            connection_alias=row["connection_alias"],
            connection_fingerprint=row["connection_fingerprint"],
            tenant_scope_id=row["tenant_scope_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
