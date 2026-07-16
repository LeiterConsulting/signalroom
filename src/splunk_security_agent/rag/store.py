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
        now = datetime.now(UTC).isoformat()
        artifact_id = hashlib.sha256(f"{record.title}\0{record.content}".encode()).hexdigest()[:16]
        payload = ArtifactRecord(
            id=artifact_id,
            title=record.title.strip(),
            kind=record.kind,
            source=record.source,
            tags=sorted(set(record.tags)),
            content=record.content.strip(),
            metadata=metadata or {},
            created_at=now,
            updated_at=now,
        )
        with self.connect() as db:
            existing = db.execute("SELECT created_at FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
            if existing:
                payload.created_at = existing["created_at"]
            db.execute(
                """INSERT OR REPLACE INTO artifacts
                (id,title,kind,source,tags,content,metadata,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    payload.id,
                    payload.title,
                    payload.kind,
                    payload.source,
                    json.dumps(payload.tags),
                    payload.content,
                    json.dumps(payload.metadata),
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

    def list(self, limit: int = 100) -> list[ArtifactRecord]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM artifacts ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get(self, artifact_id: str) -> ArtifactRecord | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def update(self, artifact_id: str, value: ArtifactUpdate) -> ArtifactRecord | None:
        current = self.get(artifact_id)
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

    def delete(self, artifact_id: str) -> bool:
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

    def search(self, query: str, limit: int = 6) -> list[EvidenceRef]:
        terms = []
        for token in re.findall(r"[a-zA-Z0-9_\-.]{3,}", query.lower()):
            if token not in STOPWORDS and token not in terms:
                terms.append(token)
        if not terms:
            return []
        expression = " OR ".join(f'"{term.replace(chr(34), "")}"' for term in terms[:10])
        sql = """
            SELECT f.chunk_id, f.artifact_id, f.title, c.content,
                   bm25(chunks_fts, 2.0, 1.0) rank, a.source, a.kind
            FROM chunks_fts f
            JOIN chunks c ON c.id = f.chunk_id
            JOIN artifacts a ON a.id = f.artifact_id
            WHERE chunks_fts MATCH ? ORDER BY rank LIMIT ?
        """
        try:
            with self.connect() as db:
                rows = db.execute(sql, (expression, limit)).fetchall()
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

    def pending_embeddings(self, model_profile: str, limit: int = 32) -> list[tuple[str, str]]:
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT c.id, c.content FROM chunks c
                LEFT JOIN embeddings e ON e.chunk_id = c.id AND e.model_profile = ?
                WHERE e.chunk_id IS NULL ORDER BY c.id LIMIT ?
                """,
                (model_profile, limit),
            ).fetchall()
        return [(row["id"], row["content"]) for row in rows]

    def embedding_status(self, model_profile: str) -> dict[str, int]:
        with self.connect() as db:
            total = int(db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])
            indexed = int(
                db.execute(
                    "SELECT COUNT(*) FROM embeddings WHERE model_profile = ?",
                    (model_profile,),
                ).fetchone()[0]
            )
        return {
            "total_chunks": total,
            "indexed_chunks": min(indexed, total),
            "pending_chunks": max(0, total - indexed),
        }

    def semantic_candidates(self, limit: int = 24) -> list[EvidenceRef]:
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT c.id, c.title, c.content, a.source, a.kind
                FROM chunks c JOIN artifacts a ON a.id = c.artifact_id
                ORDER BY a.updated_at DESC, c.ordinal LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            EvidenceRef(
                id=row["id"],
                source=row["source"],
                title=row["title"],
                excerpt=self._coherent_excerpt(row["content"], [], 520),
                kind=row["kind"],
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
        self, query_vector: list[float], model_profile: str, limit: int = 6
    ) -> list[EvidenceRef]:
        if not query_vector:
            return []
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT c.id, c.title, c.content, a.source, a.kind, e.vector
                FROM embeddings e JOIN chunks c ON c.id = e.chunk_id
                JOIN artifacts a ON a.id = c.artifact_id
                WHERE e.model_profile = ?
                """,
                (model_profile,),
            ).fetchall()
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
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
