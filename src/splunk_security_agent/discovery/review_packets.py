from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from itertools import product
from pathlib import Path
from threading import RLock
from typing import Any

from .comparison import DiscoveryComparisonService


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _digest(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class EstateReviewPacketStore:
    """Content-free index of immutable cross-estate discovery references."""

    SCHEMA_VERSION = "signalroom.estate-review-packet.v1"
    STATUSES = {"open", "reviewed", "archived"}

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
        with self.connect() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS estate_review_packets (
                    id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    manifest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    reviewed_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_estate_review_packets_created
                    ON estate_review_packets(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_estate_review_packets_status
                    ON estate_review_packets(status,updated_at DESC);
                """
            )

    def create(self, manifest: dict[str, Any], actor: str) -> dict[str, Any]:
        packet_id = str(manifest.get("packet_id") or "")
        if len(packet_id) != 64:
            raise ValueError("The review packet identity is invalid.")
        now = _now()
        with self._lock, self.connect() as database:
            database.execute(
                """INSERT OR IGNORE INTO estate_review_packets
                (id,schema_version,manifest,status,created_by,reviewed_by,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (
                    packet_id,
                    self.SCHEMA_VERSION,
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                    "open",
                    actor[:120] or "local-operator",
                    "",
                    now,
                    now,
                ),
            )
        result = self.get(packet_id)
        assert result is not None
        return result

    def get(self, packet_id: str) -> dict[str, Any] | None:
        with self.connect() as database:
            row = database.execute(
                "SELECT * FROM estate_review_packets WHERE id=?", (packet_id,)
            ).fetchone()
        return self._record(row) if row else None

    def list(
        self,
        limit: int = 50,
        allowed_connection_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(200, int(limit)))
        with self.connect() as database:
            rows = database.execute(
                "SELECT * FROM estate_review_packets ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        values = [self._record(row) for row in rows]
        if allowed_connection_ids is None:
            return values
        return [
            item
            for item in values
            if {
                str(item["manifest"]["left"]["connection_alias"]),
                str(item["manifest"]["right"]["connection_alias"]),
            }.issubset(allowed_connection_ids)
        ]

    def set_status(self, packet_id: str, status: str, actor: str) -> dict[str, Any] | None:
        if status not in self.STATUSES:
            raise ValueError("Review packet status must be open, reviewed, or archived.")
        now = _now()
        with self._lock, self.connect() as database:
            result = database.execute(
                """UPDATE estate_review_packets SET status=?,reviewed_by=?,updated_at=?
                WHERE id=?""",
                (status, actor[:120] or "local-operator", now, packet_id),
            )
        return self.get(packet_id) if result.rowcount else None

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "manifest": json.loads(row["manifest"]),
            "status": row["status"],
            "created_by": row["created_by"],
            "reviewed_by": row["reviewed_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


class EstateReviewPacketService:
    """Select, retain, and rematerialize time-aligned discovery comparisons."""

    CANDIDATE_LIMIT = 100

    def __init__(
        self,
        store: EstateReviewPacketStore,
        discovery_jobs: Any,
        comparison: DiscoveryComparisonService | None = None,
    ):
        self.store = store
        self.discovery_jobs = discovery_jobs
        self.comparison = comparison or DiscoveryComparisonService()

    def create(
        self,
        left_scope: dict[str, Any],
        right_scope: dict[str, Any],
        alignment_window_minutes: int,
        actor: str,
    ) -> dict[str, Any]:
        window = max(15, min(10_080, int(alignment_window_minutes)))
        if self._scope_key(left_scope) == self._scope_key(right_scope):
            raise ValueError("Choose two different immutable Splunk scopes to review.")
        left_candidates = self._candidates(left_scope)
        right_candidates = self._candidates(right_scope)
        if not left_candidates:
            raise ValueError(
                f"No completed durable discovery run exists for {self._scope_label(left_scope)}."
            )
        if not right_candidates:
            raise ValueError(
                f"No completed durable discovery run exists for {self._scope_label(right_scope)}."
            )
        selected_left, selected_right, delta_seconds = self._closest_pair(
            left_candidates, right_candidates
        )
        if delta_seconds > window * 60:
            delta_minutes = round(delta_seconds / 60)
            raise ValueError(
                f"The closest retained discovery runs are {delta_minutes:,} minutes apart, "
                f"outside the {window:,}-minute alignment window. Run durable discovery on "
                "both scopes closer together or widen the window."
            )
        comparison = self.comparison.compare(
            left_scope,
            selected_left["result"],
            right_scope,
            selected_right["result"],
        )
        identity = {
            "schema_version": EstateReviewPacketStore.SCHEMA_VERSION,
            "left": self._reference(left_scope, selected_left, comparison["left"]),
            "right": self._reference(right_scope, selected_right, comparison["right"]),
            "comparison_id": comparison["comparison_id"],
            "alignment": {
                "window_minutes": window,
                "delta_seconds": delta_seconds,
                "status": "within-window",
                "selection": "minimum-observation-time-distance",
            },
            "contract": {
                "global_facts_persisted": False,
                "source_snapshots_copied": False,
                "splunk_queries": 0,
                "model_inference": False,
                "materialization": "on-demand-from-tenant-scoped-discovery-jobs",
            },
        }
        manifest = {**identity, "packet_id": _digest(identity)}
        packet = self.store.create(manifest, actor)
        return self._materialized(packet, comparison=comparison)

    def get(self, packet_id: str) -> dict[str, Any] | None:
        packet = self.store.get(packet_id)
        return self._materialized(packet) if packet else None

    def overview(
        self,
        limit: int = 50,
        allowed_connection_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        packets = self.store.list(limit, allowed_connection_ids)
        return {
            "packets": packets,
            "count": len(packets),
            "contract": {
                "global_index": "immutable bindings, timestamps, digests, and lifecycle only",
                "source_facts": "remain in each tenant-scoped durable discovery store",
                "materialization": "requires both exact source snapshots and matching digests",
            },
        }

    def set_status(self, packet_id: str, status: str, actor: str) -> dict[str, Any] | None:
        return self.store.set_status(packet_id, status, actor)

    def _materialized(
        self,
        packet: dict[str, Any],
        *,
        comparison: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        manifest = packet["manifest"]
        expected_identity = {key: value for key, value in manifest.items() if key != "packet_id"}
        if _digest(expected_identity) != manifest["packet_id"]:
            raise ValueError("The review packet manifest failed its identity check.")
        if comparison is None:
            left_result = self._resolve_reference(manifest["left"])
            right_result = self._resolve_reference(manifest["right"])
            comparison = self.comparison.compare(
                self._scope_from_reference(manifest["left"]),
                left_result,
                self._scope_from_reference(manifest["right"]),
                right_result,
            )
        if comparison["comparison_id"] != manifest["comparison_id"]:
            raise ValueError("The rematerialized comparison no longer matches the packet manifest.")
        return {
            "packet": packet,
            "comparison": comparison,
            "integrity_status": "verified",
            "materialized_at": _now(),
        }

    def _candidates(self, scope: dict[str, Any]) -> list[dict[str, Any]]:
        tenant = str(scope["tenant_scope_id"])
        candidates: list[dict[str, Any]] = []
        for job in self.discovery_jobs.list_jobs(self.CANDIDATE_LIMIT, tenant_scope_id=tenant):
            if job.status not in {"complete", "partial"} or not job.result_run_id:
                continue
            if (
                job.connection_alias != str(scope["alias"])
                or job.connection_fingerprint != str(scope["fingerprint"])
                or job.tenant_scope_id != tenant
            ):
                continue
            result = self.discovery_jobs.result(job.id, tenant_scope_id=tenant)
            if not result or str(result.get("run_id") or "") != job.result_run_id:
                continue
            observed_at = str(result.get("generated_at") or job.completed_at or "")
            try:
                observed = _timestamp(observed_at)
            except (TypeError, ValueError):
                continue
            candidates.append(
                {
                    "job": job,
                    "result": result,
                    "observed_at": observed_at,
                    "observed": observed,
                    "snapshot_sha256": _digest(result),
                }
            )
        return candidates

    @staticmethod
    def _closest_pair(
        left: list[dict[str, Any]], right: list[dict[str, Any]]
    ) -> tuple[dict[str, Any], dict[str, Any], int]:
        pairs = []
        for left_item, right_item in product(left, right):
            delta = int(abs((left_item["observed"] - right_item["observed"]).total_seconds()))
            newest = max(left_item["observed"], right_item["observed"])
            pairs.append(
                (
                    delta,
                    -newest.timestamp(),
                    left_item["job"].id,
                    right_item["job"].id,
                    left_item,
                    right_item,
                )
            )
        selected = min(pairs, key=lambda item: item[:4])
        return selected[4], selected[5], selected[0]

    @staticmethod
    def _reference(
        scope: dict[str, Any],
        candidate: dict[str, Any],
        source: dict[str, Any],
    ) -> dict[str, Any]:
        job = candidate["job"]
        return {
            "connection_alias": str(scope["alias"]),
            "display_name": str(scope.get("display_name") or scope["alias"]),
            "connection_fingerprint": str(scope["fingerprint"]),
            "tenant_scope_id": str(scope["tenant_scope_id"]),
            "discovery_job_id": job.id,
            "discovery_run_id": job.result_run_id,
            "observed_at": candidate["observed_at"],
            "depth": job.depth,
            "completion_status": job.status,
            "snapshot_sha256": source["snapshot_sha256"],
        }

    def _resolve_reference(self, reference: dict[str, Any]) -> dict[str, Any]:
        tenant = str(reference["tenant_scope_id"])
        job_id = str(reference["discovery_job_id"])
        job = self.discovery_jobs.get_job(job_id, tenant_scope_id=tenant)
        if not job:
            raise ValueError(
                f"The retained discovery job {job_id} is unavailable in tenant {tenant}."
            )
        expected_binding = (
            str(reference["connection_alias"]),
            str(reference["connection_fingerprint"]),
            tenant,
        )
        actual_binding = (
            job.connection_alias,
            job.connection_fingerprint,
            job.tenant_scope_id,
        )
        if actual_binding != expected_binding or job.result_run_id != reference["discovery_run_id"]:
            raise ValueError("A retained discovery job no longer matches its immutable packet binding.")
        result = self.discovery_jobs.result(job_id, tenant_scope_id=tenant)
        if not result or _digest(result) != reference["snapshot_sha256"]:
            raise ValueError("A retained discovery snapshot failed its packet digest check.")
        return result

    @staticmethod
    def _scope_from_reference(reference: dict[str, Any]) -> dict[str, Any]:
        return {
            "alias": reference["connection_alias"],
            "display_name": reference["display_name"],
            "fingerprint": reference["connection_fingerprint"],
            "tenant_scope_id": reference["tenant_scope_id"],
        }

    @staticmethod
    def _scope_key(scope: dict[str, Any]) -> str:
        return "|".join(
            (
                str(scope["alias"]),
                str(scope["fingerprint"]),
                str(scope["tenant_scope_id"]),
            )
        )

    @staticmethod
    def _scope_label(scope: dict[str, Any]) -> str:
        return f"{scope.get('display_name') or scope['alias']} · {scope['tenant_scope_id']}"
