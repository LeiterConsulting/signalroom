from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import UTC, datetime
from html import escape as xml_escape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ..audit import AuditStore
from ..schemas import AuditOperationsPolicyUpdate
from .service import SplunkAuditExportService
from .store import AuditExportStore

APP_ID = "signalroom_audit_operations"
INDEXER_APP_ID = "signalroom_audit_retention"
SCHEMA_VERSION = "signalroom.audit-operations.v1"
RECONCILIATION_SCHEMA_VERSION = "signalroom.audit-operations-reconciliation.v1"


class AuditOperationsReconciliationError(ValueError):
    pass


class AuditOperationsService:
    """Generate reviewable Splunk operations content for the dedicated audit stream."""

    def __init__(
        self,
        store: AuditExportStore,
        audit_export: SplunkAuditExportService,
        audit: AuditStore,
        export_dir: Path | str,
    ):
        self.store = store
        self.audit_export = audit_export
        self.audit = audit
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def overview(
        self,
        export_overview: dict[str, Any] | None = None,
        allowed_connection_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        policy = self.store.operations_policy()
        preview = self._build(policy)
        export = export_overview or self.audit_export.overview()
        exports = self.store.operations_exports()
        current = next(
            (
                item
                for item in exports
                if item["policy_sha256"] == preview["policy_sha256"]
                and item["destination_fingerprint"] == preview["destination_fingerprint"]
            ),
            None,
        )
        reconciliations = self.store.operations_reconciliations(
            allowed_connection_ids=allowed_connection_ids,
        )
        current_reconciliation = next(
            (item for item in reconciliations if current and item["export_id"] == current["id"]),
            None,
        )
        return {
            "policy": policy,
            "health": self._health(policy, export),
            "pack": {
                "schema_version": SCHEMA_VERSION,
                "policy_sha256": preview["policy_sha256"],
                "destination_fingerprint": preview["destination_fingerprint"],
                "current_export": current,
                "review_required": True,
                "scheduled_searches_enabled": False,
                "writes_to_splunk": False,
                "file_count": len(preview["files"]),
                "controls": [
                    {
                        "id": item["id"],
                        "title": item["title"],
                        "purpose": item["purpose"],
                    }
                    for item in preview["controls"]
                ],
            },
            "exports": exports,
            "reconciliation": {
                "available": bool(current and preview["binding"]["origin"]),
                "detail": (
                    "Select an admitted Splunk scope to compare the current exported kit "
                    "with read-only MCP configuration observations."
                    if current and preview["binding"]["origin"]
                    else "Configure a HEC destination and export the current review kit before reconciling."
                    if not preview["binding"]["origin"]
                    else "Export the current review kit before reconciling its deployed state."
                ),
                "authority": {
                    "read_only": True,
                    "calls": [
                        "get_index_info",
                        "get_knowledge_objects(saved_searches)",
                        "get_knowledge_objects(macros)",
                        "get_knowledge_objects(views)",
                        "get_knowledge_objects(apps)",
                    ],
                    "runs_spl": False,
                    "changes_splunk": False,
                },
                "current": current_reconciliation,
                "history": reconciliations,
            },
        }

    def update_policy(self, value: AuditOperationsPolicyUpdate) -> dict[str, Any]:
        previous = self.store.operations_policy()
        policy = self.store.update_operations_policy(value)
        self.audit.record(
            "audit.operations.policy.updated",
            "update",
            target_type="audit-operations-policy",
            target_id="primary",
            summary="The deployment-specific audit operations policy was updated.",
            metadata={
                "previous": previous,
                "current": policy,
                "alerts_enabled_by_signalroom": False,
                "splunk_configuration_written": False,
            },
        )
        return self.overview()

    def preview(self) -> dict[str, Any]:
        policy = self.store.operations_policy()
        built = self._build(policy)
        return {
            "schema_version": SCHEMA_VERSION,
            "policy": policy,
            "binding": built["binding"],
            "policy_sha256": built["policy_sha256"],
            "destination_fingerprint": built["destination_fingerprint"],
            "files": built["manifest"]["files"],
            "controls": built["controls"],
            "retention": {
                "days": policy["retention_days"],
                "seconds": policy["retention_days"] * 86400,
                "warning": (
                    "Buckets can freeze earlier when a size limit is reached. Without "
                    "a cold-to-frozen archive policy, frozen data is deleted."
                ),
            },
            "authority": built["manifest"]["authority"],
            "review_steps": [
                "Review the search-head and indexer packages separately.",
                "Confirm role access, retention, storage sizing, and archive policy.",
                "Install through the deployment process appropriate to this Splunk topology.",
                "Run each alert search manually, then enable only approved schedules and actions.",
            ],
        }

    def export(self) -> dict[str, Any]:
        policy = self.store.operations_policy()
        built = self._build(policy)
        export_id = str(uuid4())
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"signalroom_audit_operations_{stamp}_{export_id[:8]}.zip"
        path = self.export_dir / filename
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in built["files"].items():
                archive.writestr(name, body)
            archive.writestr(
                "manifest.json",
                json.dumps(built["manifest"], indent=2, sort_keys=True) + "\n",
            )
        archive_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_sha256 = hashlib.sha256(self._canonical(built["manifest"]).encode()).hexdigest()
        record = self.store.record_operations_export(
            export_id=export_id,
            filename=filename,
            archive_sha256=archive_sha256,
            manifest_sha256=manifest_sha256,
            policy_sha256=built["policy_sha256"],
            destination_fingerprint=built["destination_fingerprint"],
        )
        self.audit.record(
            "audit.operations.pack.exported",
            "export",
            target_type="audit-operations-pack",
            target_id=export_id,
            summary="A review-only Splunk audit operations deployment kit was exported.",
            metadata={
                "filename": filename,
                "archive_sha256": archive_sha256,
                "manifest_sha256": manifest_sha256,
                "policy_sha256": built["policy_sha256"],
                "destination_fingerprint": built["destination_fingerprint"],
                "scheduled_searches_enabled": False,
                "splunk_configuration_written": False,
            },
        )
        return {
            **record,
            "url": f"/api/audit-operations/exports/{filename}",
            "authority": built["manifest"]["authority"],
        }

    async def reconcile(
        self,
        scope: dict[str, Any],
        client: Any,
    ) -> dict[str, Any]:
        """Compare one immutable exported kit with one admitted Splunk scope."""
        policy = self.store.operations_policy()
        built = self._build(policy)
        export, manifest = self._validated_current_export(built)
        observed_at = datetime.now(UTC).isoformat()
        endpoint = str(getattr(getattr(client, "client", client), "url", "") or "")
        destination_host = (urlsplit(str(manifest["binding"].get("origin") or "")).hostname or "").lower()
        mcp_host = (urlsplit(endpoint).hostname or "").lower()
        common = {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "subject": {
                "export_id": export["id"],
                "manifest_sha256": export["manifest_sha256"],
                "archive_sha256": export["archive_sha256"],
                "policy_sha256": export["policy_sha256"],
                "destination_fingerprint": export["destination_fingerprint"],
            },
            "scope": {
                "connection_alias": str(scope.get("alias") or "primary"),
                "connection_fingerprint": str(scope.get("fingerprint") or ""),
                "tenant_scope_id": str(scope.get("tenant_scope_id") or "workspace-primary"),
                "display_name": str(scope.get("display_name") or scope.get("alias") or "Primary Splunk"),
            },
            "destination_identity": {
                "hec_host": destination_host,
                "mcp_host": mcp_host,
                "host_match": bool(destination_host and mcp_host and destination_host == mcp_host),
                "ports_may_differ": True,
            },
            "authority": {
                "read_only": True,
                "runs_spl": False,
                "changes_splunk": False,
                "installs_apps": False,
                "enables_searches": False,
                "stores_full_catalogs": False,
            },
            "observed_at": observed_at,
        }
        if not destination_host or not mcp_host or destination_host != mcp_host:
            detail = (
                "The selected MCP endpoint host does not match the exported kit's HEC host. "
                "SignalRoom will not compare configuration across different Splunk identities."
                if destination_host and mcp_host
                else "SignalRoom could not establish both the HEC and MCP destination hosts."
            )
            return self._record_reconciliation(
                export,
                {
                    **common,
                    "status": "blocked",
                    "summary": detail,
                    "controls": [],
                    "sources": [],
                    "limitations": self._reconciliation_limitations(),
                },
            )

        source_specs = [
            ("index", "get_index_info", {"index_name": manifest["binding"]["index"]}, 1),
            ("saved_searches", "get_knowledge_objects", {"type": "saved_searches", "row_limit": 1000}, 1000),
            ("macros", "get_knowledge_objects", {"type": "macros", "row_limit": 1000}, 1000),
            ("views", "get_knowledge_objects", {"type": "views", "row_limit": 1000}, 1000),
            ("apps", "get_knowledge_objects", {"type": "apps", "row_limit": 1000}, 1000),
        ]
        collections: dict[str, list[dict[str, Any]]] = {}
        collection_meta: dict[str, dict[str, Any]] = {}
        sources: list[dict[str, Any]] = []
        for source_id, tool, arguments, row_limit in source_specs:
            try:
                raw = await client.call(tool, arguments)
                rows, meta = self._reconciliation_collection(raw, row_limit, source_id)
                collections[source_id] = rows
                collection_meta[source_id] = meta
                sources.append(meta)
            except Exception as exc:
                collections[source_id] = []
                meta = {
                    "id": source_id,
                    "tool": tool,
                    "status": "unavailable",
                    "returned": 0,
                    "exhaustive": False,
                    "detail": str(exc).strip()[:600] or "The MCP read failed.",
                }
                collection_meta[source_id] = meta
                sources.append(meta)

        controls: list[dict[str, Any]] = []
        controls.append(
            self._compare_object(
                control_id="index-retention",
                label="Dedicated audit index retention",
                kind="index",
                name=str(manifest["binding"]["index"]),
                app="",
                expected={"retention_seconds": int(manifest["policy"]["retention_days"]) * 86400},
                field_aliases={
                    "retention_seconds": (
                        "frozenTimePeriodInSecs",
                        "frozen_time_period_in_secs",
                        "frozen_time_period",
                        "retention_seconds",
                    )
                },
                rows=collections["index"],
                collection=collection_meta["index"],
                normalizers={"retention_seconds": self._optional_int},
            )
        )
        for app_id in (APP_ID, INDEXER_APP_ID):
            controls.append(
                self._compare_object(
                    control_id=f"app:{app_id}",
                    label=f"Splunk app {app_id}",
                    kind="app",
                    name=app_id,
                    app="",
                    expected={"version": "1.0.0"},
                    field_aliases={"version": ("version", "app_version")},
                    rows=collections["apps"],
                    collection=collection_meta["apps"],
                )
            )
        for expected in self._controls(policy):
            controls.append(
                self._compare_object(
                    control_id=f"saved-search:{expected['id']}",
                    label=expected["title"],
                    kind="saved-search",
                    name=expected["title"],
                    app=APP_ID,
                    expected={
                        "search": self._normalize_text(expected["search"]),
                        "cron_schedule": expected["schedule"],
                        "earliest_time": expected["earliest"],
                        "latest_time": "now",
                        "disabled": True,
                    },
                    field_aliases={
                        "search": ("search", "definition"),
                        "cron_schedule": ("cron_schedule", "cron"),
                        "earliest_time": (
                            "dispatch.earliest_time",
                            "dispatch_earliest_time",
                            "earliest_time",
                        ),
                        "latest_time": (
                            "dispatch.latest_time",
                            "dispatch_latest_time",
                            "latest_time",
                        ),
                        "disabled": ("disabled",),
                    },
                    rows=collections["saved_searches"],
                    collection=collection_meta["saved_searches"],
                    normalizers={
                        "search": self._normalize_text,
                        "disabled": self._optional_bool,
                    },
                )
            )
        base_macro = self._base_search(manifest["binding"])
        canonical_macro = (
            "`signalroom_audit_base` | dedup signalroom_event_id sortby - _time"
            if manifest["policy"]["deduplication_mode"] == "stable-event-id"
            else "`signalroom_audit_base`"
        )
        for macro_name, definition in (
            ("signalroom_audit_base", base_macro),
            ("signalroom_audit_canonical", canonical_macro),
        ):
            controls.append(
                self._compare_object(
                    control_id=f"macro:{macro_name}",
                    label=f"Macro {macro_name}",
                    kind="macro",
                    name=macro_name,
                    app=APP_ID,
                    expected={"definition": self._normalize_text(definition), "iseval": False},
                    field_aliases={"definition": ("definition", "search"), "iseval": ("iseval", "is_eval")},
                    rows=collections["macros"],
                    collection=collection_meta["macros"],
                    normalizers={"definition": self._normalize_text, "iseval": self._optional_bool},
                )
            )
        controls.append(
            self._compare_object(
                control_id="view:signalroom_audit_operations",
                label="SignalRoom audit operations dashboard",
                kind="view",
                name="signalroom_audit_operations",
                app=APP_ID,
                expected={"definition": self._normalize_text(self._dashboard(policy))},
                field_aliases={"definition": ("eai:data", "xml", "definition", "data")},
                rows=collections["views"],
                collection=collection_meta["views"],
                normalizers={"definition": self._normalize_text},
            )
        )

        successful_sources = sum(item["status"] == "observed" for item in sources)
        if not successful_sources:
            status = "blocked"
            summary = "Every required MCP configuration read failed; no deployment conclusion was made."
        elif any(item["status"] == "drifted" for item in controls):
            status = "drifted"
            summary = "One or more explicitly observed deployment values differ from the exported kit."
        elif controls and all(item["status"] == "verified" for item in controls):
            status = "verified"
            summary = "Every required observable deployment value exactly matches the exported kit."
        else:
            status = "inconclusive"
            summary = (
                "No explicit drift was required for this result, but one or more values were "
                "not observable or a bounded catalog was not exhaustive."
            )
        snapshot = {
            **common,
            "status": status,
            "summary": summary,
            "controls": controls,
            "sources": sources,
            "limitations": self._reconciliation_limitations(),
            "counts": {
                name: sum(item["status"] == name for item in controls)
                for name in ("verified", "drifted", "not-observable", "inconclusive")
            },
        }
        return self._record_reconciliation(export, snapshot)

    def _validated_current_export(
        self,
        built: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        export = next(
            (
                item
                for item in self.store.operations_exports(100)
                if item["policy_sha256"] == built["policy_sha256"]
                and item["destination_fingerprint"] == built["destination_fingerprint"]
            ),
            None,
        )
        if export is None:
            raise AuditOperationsReconciliationError(
                "Export the current audit operations kit before reconciling it."
            )
        path = (self.export_dir / export["filename"]).resolve()
        if path.parent != self.export_dir.resolve() or not path.is_file():
            raise AuditOperationsReconciliationError("The current exported kit archive is unavailable.")
        if hashlib.sha256(path.read_bytes()).hexdigest() != export["archive_sha256"]:
            raise AuditOperationsReconciliationError(
                "The current exported kit archive failed SHA-256 verification."
            )
        try:
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                manifest_sha256 = hashlib.sha256(self._canonical(manifest).encode()).hexdigest()
                if manifest_sha256 != export["manifest_sha256"]:
                    raise AuditOperationsReconciliationError(
                        "The exported kit manifest failed SHA-256 verification."
                    )
                if (
                    manifest.get("policy_sha256") != built["policy_sha256"]
                    or manifest.get("destination_fingerprint") != built["destination_fingerprint"]
                ):
                    raise AuditOperationsReconciliationError(
                        "The exported kit is not bound to the current policy and destination."
                    )
                for name, expected in (manifest.get("files") or {}).items():
                    body = archive.read(name)
                    if hashlib.sha256(body).hexdigest() != expected.get("sha256"):
                        raise AuditOperationsReconciliationError(
                            f"Exported kit file failed verification: {name}"
                        )
        except AuditOperationsReconciliationError:
            raise
        except (OSError, KeyError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
            raise AuditOperationsReconciliationError(
                f"The exported kit could not be verified: {exc}"
            ) from exc
        return export, manifest

    def _record_reconciliation(
        self,
        export: dict[str, Any],
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        snapshot_sha256 = hashlib.sha256(self._canonical(snapshot).encode()).hexdigest()
        scope = snapshot["scope"]
        result = self.store.record_operations_reconciliation(
            reconciliation_id=str(uuid4()),
            status=snapshot["status"],
            policy_sha256=export["policy_sha256"],
            destination_fingerprint=export["destination_fingerprint"],
            export_id=export["id"],
            manifest_sha256=export["manifest_sha256"],
            connection_alias=scope["connection_alias"],
            connection_fingerprint=scope["connection_fingerprint"],
            tenant_scope_id=scope["tenant_scope_id"],
            snapshot_sha256=snapshot_sha256,
            snapshot=snapshot,
        )
        self.audit.record(
            "audit.operations.pack.reconciled",
            "verify",
            target_type="audit-operations-pack",
            target_id=export["id"],
            outcome="success" if snapshot["status"] == "verified" else "warning",
            summary=snapshot["summary"],
            metadata={
                "reconciliation_id": result["id"],
                "status": result["status"],
                "snapshot_sha256": snapshot_sha256,
                "connection_alias": scope["connection_alias"],
                "connection_fingerprint": scope["connection_fingerprint"],
                "tenant_scope_id": scope["tenant_scope_id"],
                "read_only": True,
                "spl_executed": False,
            },
        )
        return result

    @classmethod
    def _reconciliation_collection(
        cls,
        value: Any,
        row_limit: int,
        source_id: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if isinstance(value, dict) and value.get("error"):
            raise AuditOperationsReconciliationError(str(value["error"]))
        if isinstance(value, dict) and value.get("success") is False:
            raise AuditOperationsReconciliationError(
                str(value.get("message") or value.get("detail") or "The MCP read failed.")
            )
        total_rows = None
        truncated_value = None
        if isinstance(value, list):
            source = value
        elif isinstance(value, dict):
            source = next(
                (
                    value[key]
                    for key in (source_id, "results", "items", "data", "entries")
                    if isinstance(value.get(key), list)
                ),
                None,
            )
            if source is None:
                list_values = [item for item in value.values() if isinstance(item, list)]
                source = list_values[0] if len(list_values) == 1 else None
            if source is None:
                nested = value.get("index") or value.get("result") or value.get("data")
                source = [nested] if isinstance(nested, dict) else [value]
            total_rows = cls._optional_int(value.get("total_rows") or value.get("total"))
            truncated_value = cls._optional_bool(value.get("truncated"))
        else:
            raise AuditOperationsReconciliationError("The MCP tool returned an invalid collection.")
        rows = [cls._flatten_row(item) for item in source if isinstance(item, dict)]
        point_read = source_id == "index"
        truncated = (
            False
            if point_read
            else (
                truncated_value
                if truncated_value is not None
                else bool(len(rows) >= row_limit or (total_rows is not None and total_rows > len(rows)))
            )
        )
        exhaustive = point_read or (
            not truncated and (total_rows <= len(rows) if total_rows is not None else len(rows) < row_limit)
        )
        return rows, {
            "id": source_id,
            "tool": "get_index_info" if source_id == "index" else "get_knowledge_objects",
            "status": "observed",
            "returned": len(rows),
            "row_limit": row_limit,
            "total_rows": total_rows,
            "truncated": truncated,
            "exhaustive": exhaustive,
            "detail": (
                "The returned catalog is bounded and may omit matching objects."
                if truncated
                else "The MCP response was normalized without retaining unrelated catalog rows."
            ),
        }

    @classmethod
    def _compare_object(
        cls,
        *,
        control_id: str,
        label: str,
        kind: str,
        name: str,
        app: str,
        expected: dict[str, Any],
        field_aliases: dict[str, tuple[str, ...]],
        rows: list[dict[str, Any]],
        collection: dict[str, Any],
        normalizers: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalizers = normalizers or {}
        name_matches = [row for row in rows if cls._row_name(row) == name]
        scoped_matches = [row for row in name_matches if not app or cls._row_app(row) == app]
        candidates = scoped_matches
        if not candidates and len(name_matches) == 1 and app and not cls._row_app(name_matches[0]):
            candidates = name_matches
        base = {
            "id": control_id,
            "label": label,
            "kind": kind,
            "source": collection["id"],
            "expected_identity": {"name": name, "app": app},
        }
        if collection["status"] != "observed":
            return {**base, "status": "not-observable", "detail": collection["detail"], "fields": []}
        if not candidates:
            status = "drifted" if collection.get("exhaustive") else "inconclusive"
            return {
                **base,
                "status": status,
                "detail": (
                    "The expected object was absent from an exhaustive MCP response."
                    if status == "drifted"
                    else "The expected object was not returned, but the bounded catalog was not exhaustive."
                ),
                "fields": [],
            }
        if len(candidates) != 1:
            return {
                **base,
                "status": "inconclusive",
                "detail": "Multiple objects matched the expected identity; SignalRoom will not choose one.",
                "fields": [],
            }
        row = candidates[0]
        fields: list[dict[str, Any]] = []
        if app:
            observed_app = cls._row_app(row)
            fields.append(
                {
                    "id": "app",
                    "expected": app,
                    "observed": observed_app or None,
                    "status": "verified"
                    if observed_app == app
                    else "drifted"
                    if observed_app
                    else "not-observable",
                }
            )
        normalized_observed: dict[str, Any] = {}
        for field, expected_value in expected.items():
            found, observed_value = cls._first_present(row, field_aliases[field])
            normalizer = normalizers.get(field, lambda value: str(value).strip())
            normalized = normalizer(observed_value) if found else None
            if normalized is None:
                field_status = "not-observable"
            else:
                field_status = "verified" if normalized == expected_value else "drifted"
            normalized_observed[field] = normalized
            fields.append(
                {
                    "id": field,
                    "expected": expected_value,
                    "observed": normalized,
                    "status": field_status,
                }
            )
        statuses = {item["status"] for item in fields}
        status = (
            "drifted"
            if "drifted" in statuses
            else "not-observable"
            if "not-observable" in statuses
            else "verified"
        )
        return {
            **base,
            "status": status,
            "detail": (
                "An explicitly observed value differs from the exported contract."
                if status == "drifted"
                else "The object was found, but the MCP response omitted a required field."
                if status == "not-observable"
                else "The object identity and every required exposed field match exactly."
            ),
            "observed_identity": {"name": cls._row_name(row), "app": cls._row_app(row)},
            "observed": normalized_observed,
            "fields": fields,
        }

    @staticmethod
    def _flatten_row(row: dict[str, Any]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key in ("content", "fields", "settings", "configuration", "properties", "data"):
            if isinstance(row.get(key), dict):
                value.update(row[key])
        if isinstance(row.get("acl"), dict):
            value.setdefault("eai:acl.app", row["acl"].get("app"))
        value.update({key: item for key, item in row.items() if key not in {"content", "fields", "acl"}})
        return value

    @staticmethod
    def _row_name(row: dict[str, Any]) -> str:
        return str(
            row.get("name")
            or row.get("title")
            or row.get("index_name")
            or row.get("index")
            or row.get("stanza")
            or ""
        ).strip()

    @staticmethod
    def _row_app(row: dict[str, Any]) -> str:
        return str(row.get("app") or row.get("eai:acl.app") or row.get("eai_acl_app") or "").strip()

    @staticmethod
    def _first_present(row: dict[str, Any], aliases: tuple[str, ...]) -> tuple[bool, Any]:
        for name in aliases:
            if name in row and row[name] is not None:
                return True, row[name]
        return False, None

    @staticmethod
    def _normalize_text(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value or "").strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return None

    @staticmethod
    def _optional_int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _reconciliation_limitations() -> list[dict[str, str]]:
        return [
            {
                "id": "app-conf",
                "status": "not-observable",
                "detail": (
                    "The MCP contract can list apps but does not expose complete app.conf file content."
                ),
            },
            {
                "id": "navigation",
                "status": "not-observable",
                "detail": "The generated navigation XML is not exposed by the available MCP tools.",
            },
            {
                "id": "metadata-acl",
                "status": "not-observable",
                "detail": "The complete default.meta ACL file is not exposed by the available MCP tools.",
            },
            {
                "id": "deployment-topology",
                "status": "not-observable",
                "detail": (
                    "MCP observations do not prove bundle replication across every "
                    "search head or indexer peer."
                ),
            },
        ]

    def _health(self, policy: dict[str, Any], export: dict[str, Any]) -> dict[str, Any]:
        export_policy = export["policy"]
        state = export["state"]
        chain = export["chain"]
        cursor = int(state["cursor_sequence"])
        first_pending = self.audit.events_after(cursor, 1)
        oldest_pending_at = first_pending[0]["created_at"] if first_pending else None
        oldest_pending_minutes = 0
        if oldest_pending_at:
            try:
                created = datetime.fromisoformat(oldest_pending_at)
                oldest_pending_minutes = max(0, int((datetime.now(UTC) - created).total_seconds() // 60))
            except (TypeError, ValueError):
                oldest_pending_minutes = 0
        if not chain["valid"]:
            status = "chain-invalid"
            detail = (
                f"Local chain verification failed at sequence {chain['broken_sequence']}; export is blocked."
            )
        elif not export_policy["enabled"]:
            status = "local-only"
            detail = (
                "Remote export is disabled. The local chain remains authoritative, "
                "and destination controls cannot observe it."
            )
        elif state["status"] in {"failed", "chain-invalid", "config-error"}:
            status = "breached"
            detail = state["last_error"] or "The remote audit exporter needs attention."
        elif first_pending and oldest_pending_minutes > policy["expected_export_lag_minutes"]:
            status = "breached"
            detail = (
                f"The oldest pending event is {oldest_pending_minutes} minutes old; "
                f"the local expectation is {policy['expected_export_lag_minutes']} minutes."
            )
        elif state["pending_events"]:
            status = "catching-up"
            detail = f"{state['pending_events']} verified event(s) are queued after sequence {cursor}."
        else:
            status = "current"
            detail = f"The remote cursor is current through sequence {cursor}."
        return {
            "status": status,
            "detail": detail,
            "oldest_pending_at": oldest_pending_at,
            "oldest_pending_minutes": oldest_pending_minutes,
            "expected_export_lag_minutes": policy["expected_export_lag_minutes"],
            "pending_events": state["pending_events"],
            "cursor_sequence": cursor,
            "latest_sequence": state["latest_sequence"],
            "last_success_at": state["last_success_at"],
            "local_chain_valid": chain["valid"],
            "remote_observation": (
                "Not verified by SignalRoom; the generated Splunk searches perform "
                "destination-side observation after deployment."
            ),
        }

    def _build(self, policy: dict[str, Any]) -> dict[str, Any]:
        export_policy = self.store.policy()
        hec_url = self.audit_export.config.secret("audit_hec_url")
        binding = {
            "index": export_policy["index_name"],
            "sourcetype": export_policy["sourcetype"],
            "source": export_policy["source"],
            "host": export_policy["host"],
            "origin": self.audit_export._origin(hec_url) if hec_url else "",
            "event_schema": "signalroom.audit.v1",
        }
        destination_fingerprint = hashlib.sha256(self._canonical(binding).encode()).hexdigest()
        policy_material = {
            "operations": {key: value for key, value in policy.items() if key != "updated_at"},
            "binding": binding,
            "destination_fingerprint": destination_fingerprint,
        }
        policy_sha256 = hashlib.sha256(self._canonical(policy_material).encode()).hexdigest()
        controls = self._controls(policy)
        files = self._files(policy, binding, controls)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "policy_sha256": policy_sha256,
            "destination_fingerprint": destination_fingerprint,
            "binding": binding,
            "policy": policy_material["operations"],
            "authority": {
                "writes_to_splunk": False,
                "calls_splunk_api": False,
                "scheduled_searches_enabled": False,
                "alert_actions_configured": False,
                "changes_index_retention_if_deployed": True,
                "requires_human_review": True,
            },
            "files": {
                name: {
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "bytes": len(body.encode()),
                }
                for name, body in files.items()
            },
        }
        return {
            "binding": binding,
            "destination_fingerprint": destination_fingerprint,
            "policy_sha256": policy_sha256,
            "controls": controls,
            "files": files,
            "manifest": manifest,
        }

    def _files(
        self,
        policy: dict[str, Any],
        binding: dict[str, Any],
        controls: list[dict[str, str]],
    ) -> dict[str, str]:
        search_root = f"search-head/{APP_ID}"
        indexer_root = f"indexer/{INDEXER_APP_ID}"
        return {
            "README.md": self._readme(policy, binding),
            f"{search_root}/default/app.conf": self._app_conf("SignalRoom Audit Operations"),
            f"{search_root}/default/macros.conf": self._macros(policy, binding),
            f"{search_root}/default/savedsearches.conf": self._saved_searches(controls),
            (f"{search_root}/default/data/ui/views/signalroom_audit_operations.xml"): self._dashboard(policy),
            f"{search_root}/default/data/ui/nav/default.xml": (
                '<nav search_view="search">\n'
                '  <view name="signalroom_audit_operations" default="true" />\n'
                "</nav>\n"
            ),
            f"{search_root}/metadata/default.meta": (
                "[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n"
            ),
            f"{indexer_root}/default/app.conf": self._app_conf("SignalRoom Audit Retention"),
            f"{indexer_root}/default/indexes.conf": (
                f"[{binding['index']}]\nfrozenTimePeriodInSecs = {policy['retention_days'] * 86400}\n"
            ),
        }

    @staticmethod
    def _app_conf(label: str) -> str:
        return (
            "[install]\n"
            "is_configured = 0\n\n"
            "[ui]\n"
            f"label = {label}\n"
            "is_visible = 1\n\n"
            "[launcher]\n"
            "author = Leiter Consulting\n"
            "description = Review-gated operations content for SignalRoom audit events\n"
            "version = 1.0.0\n"
        )

    def _macros(self, policy: dict[str, Any], binding: dict[str, Any]) -> str:
        base = self._base_search(binding)
        canonical = (
            "`signalroom_audit_base` | dedup signalroom_event_id sortby - _time"
            if policy["deduplication_mode"] == "stable-event-id"
            else "`signalroom_audit_base`"
        )
        return (
            "[signalroom_audit_base]\n"
            f"definition = {base}\n"
            "iseval = 0\n\n"
            "[signalroom_audit_canonical]\n"
            f"definition = {canonical}\n"
            "iseval = 0\n"
        )

    def _controls(self, policy: dict[str, Any]) -> list[dict[str, str]]:
        threshold = policy["denied_request_threshold"]
        silence_seconds = policy["source_silence_minutes"] * 60
        return [
            {
                "id": "duplicate-event-id",
                "title": "SignalRoom audit duplicate delivery IDs",
                "purpose": ("Expose at-least-once HEC retries without deleting either copy."),
                "schedule": "3,18,33,48 * * * *",
                "earliest": "-24h",
                "search": (
                    "`signalroom_audit_base` earliest=-24h "
                    "| stats count min(_time) as first_seen max(_time) as last_seen "
                    "by signalroom_event_id signalroom_sequence "
                    "| where count > 1"
                ),
            },
            {
                "id": "chain-discontinuity",
                "title": "SignalRoom audit chain or sequence discontinuity",
                "purpose": ("Detect a gap or previous-hash mismatch after stable-ID deduplication."),
                "schedule": "8,38 * * * *",
                "earliest": "-7d",
                "search": (
                    "`signalroom_audit_base` earliest=-7d "
                    "| dedup signalroom_event_id sortby - _time "
                    "| sort 0 signalroom_sequence "
                    "| streamstats current=f window=1 "
                    "last(signalroom_sequence) as prior_sequence "
                    "last(signalroom_event_hash) as expected_previous_hash "
                    "| where isnotnull(prior_sequence) AND "
                    "(signalroom_sequence != prior_sequence + 1 OR "
                    "signalroom_previous_hash != expected_previous_hash)"
                ),
            },
            {
                "id": "authorization-denials",
                "title": "SignalRoom repeated authorization denials",
                "purpose": (f"Surface {threshold} or more denied API requests in 15 minutes."),
                "schedule": "6,21,36,51 * * * *",
                "earliest": "-15m",
                "search": (
                    "`signalroom_audit_canonical` earliest=-15m "
                    'signalroom_event_type="auth.request.denied" '
                    "| stats count values(signalroom_actor) as actors "
                    "values(signalroom_target_type) as target_types "
                    f"| where count >= {threshold}"
                ),
            },
            {
                "id": "source-silence",
                "title": "SignalRoom audit source silence",
                "purpose": (
                    "Detect an absent destination stream. Enable only where SignalRoom "
                    "activity is expected inside this interval."
                ),
                "schedule": "11,26,41,56 * * * *",
                "earliest": "-30d",
                "search": (
                    "| tstats latest(_time) as latest where "
                    f"{self._base_search_terms()} "
                    "| append [| makeresults | eval latest=0] "
                    "| stats max(latest) as latest "
                    "| eval silence_seconds=if(latest=0,now(),now()-latest) "
                    f"| where silence_seconds > {silence_seconds}"
                ),
            },
        ]

    @staticmethod
    def _saved_searches(controls: list[dict[str, str]]) -> str:
        stanzas: list[str] = []
        for control in controls:
            stanzas.append(
                f"[{control['title']}]\n"
                f"description = {control['purpose']}\n"
                f"search = {control['search']}\n"
                f"dispatch.earliest_time = {control['earliest']}\n"
                "dispatch.latest_time = now\n"
                f"cron_schedule = {control['schedule']}\n"
                "allow_skew = 20%\n"
                "enableSched = 1\n"
                "disabled = 1\n"
                "alert.track = 1\n"
                "counttype = number of events\n"
                "quantity = 0\n"
                "relation = greater than\n"
                "alert.suppress = 1\n"
                "alert.suppress.period = 30m\n"
            )
        return "\n".join(stanzas)

    @staticmethod
    def _dashboard(policy: dict[str, Any]) -> str:
        earliest = policy["dashboard_earliest"]

        def query(value: str) -> str:
            return xml_escape(value, quote=False)

        denied_query = '| search signalroom_event_type="auth.request.denied" | stats count'
        duplicate_query = (
            "`signalroom_audit_base` "
            "| stats count min(_time) as first_seen max(_time) as last_seen "
            "by signalroom_event_id signalroom_sequence | where count > 1"
        )
        latest_query = (
            "| sort 0 - signalroom_sequence "
            "| table _time signalroom_sequence signalroom_event_type "
            "signalroom_actor signalroom_outcome signalroom_target_type "
            "signalroom_event_id | head 50"
        )
        return (
            '<form version="1.1" theme="light">\n'
            "  <label>SignalRoom Audit Operations</label>\n"
            "  <description>Destination-side visibility for the verified "
            "SignalRoom control-plane audit stream.</description>\n"
            '  <fieldset submitButton="false">\n'
            '    <input type="time" token="time">\n'
            "      <label>Time range</label>\n"
            f"      <default><earliest>{earliest}</earliest>"
            "<latest>now</latest></default>\n"
            "    </input>\n"
            "  </fieldset>\n"
            '  <search id="canonical">\n'
            f"    <query>{query('`signalroom_audit_canonical`')}</query>\n"
            "    <earliest>$time.earliest$</earliest>\n"
            "    <latest>$time.latest$</latest>\n"
            "  </search>\n"
            "  <row>\n"
            "    <panel><single><title>Canonical events</title>"
            '<search base="canonical"><query>| stats count</query></search>'
            "</single></panel>\n"
            "    <panel><single><title>Denied requests</title>"
            '<search base="canonical"><query>'
            f"{query(denied_query)}"
            "</query></search></single></panel>\n"
            "    <panel><single><title>Unique actors</title>"
            '<search base="canonical"><query>'
            f"{query('| stats dc(signalroom_actor) as actors')}"
            "</query></search></single></panel>\n"
            "  </row>\n"
            "  <row>\n"
            "    <panel><chart><title>Audit outcomes over time</title>"
            '<search base="canonical"><query>'
            f"{query('| timechart count by signalroom_outcome limit=8')}"
            "</query></search></chart></panel>\n"
            "    <panel><table><title>Top control-plane events</title>"
            '<search base="canonical"><query>'
            f"{query('| stats count by signalroom_event_type | sort - count | head 15')}"
            "</query></search></table></panel>\n"
            "  </row>\n"
            "  <row>\n"
            "    <panel><table><title>At-least-once delivery duplicates</title>"
            "<search><query>"
            f"{query(duplicate_query)}"
            "</query><earliest>$time.earliest$</earliest>"
            "<latest>$time.latest$</latest></search></table></panel>\n"
            "  </row>\n"
            "  <row>\n"
            "    <panel><table><title>Latest canonical decisions</title>"
            '<search base="canonical"><query>'
            f"{query(latest_query)}"
            "</query></search></table></panel>\n"
            "  </row>\n"
            "</form>\n"
        )

    def _readme(self, policy: dict[str, Any], binding: dict[str, Any]) -> str:
        return f"""# SignalRoom audit operations deployment kit

This review-only kit is bound to `index={binding["index"]}` and
`sourcetype={binding["sourcetype"]}`. SignalRoom did not call Splunk, install an
app, enable a schedule, or configure an alert action while creating it.

## Split deployment

- `search-head/{APP_ID}` contains the dashboard, macros, and four disabled
  scheduled-alert definitions. Install it through the normal search-head or
  Splunk Cloud app-review process.
- `indexer/{INDEXER_APP_ID}` contains the dedicated index retention stanza.
  Deploy it only to the indexer tier (or the appropriate indexer-cluster
  manager path) after storage and archive review. Splunk Cloud customers should
  apply retention through their supported administrative process.

The proposed searchable retention is {policy["retention_days"]} days
(`frozenTimePeriodInSecs={policy["retention_days"] * 86400}`). A bucket can
freeze earlier when size limits are reached. If no cold-to-frozen archive is
configured, frozen data is deleted. Confirm both time and size policy.

## Review gate

1. Confirm index, sourcetype, role access, storage sizing, and archive policy.
2. Install the search-head and indexer components only where their configuration
   belongs in this deployment topology.
3. Run every saved search manually against representative data.
4. Configure approved alert actions in Splunk.
5. Change `disabled = 1` only for controls approved by the security and Splunk
   owners. The source-silence alert assumes regular SignalRoom activity and can
   be noisy in low-activity proof-of-concept deployments.

## Delivery semantics

HEC export is at-least-once. The canonical macro uses
`signalroom_event_id` for search-time deduplication when the local policy is
`stable-event-id`; the raw base macro always preserves retries for inspection.
Search-time deduplication does not delete indexed events.

## Vendor references

- https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/indexes.conf
- https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.2/configuration-file-reference/10.2.2-configuration-file-reference/savedsearches.conf
- https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/9.0/simple-xml-reference/simple-xml-reference
"""

    def _base_search(self, binding: dict[str, Any]) -> str:
        return (
            f'index="{self._spl_literal(binding["index"])}" '
            f'sourcetype="{self._spl_literal(binding["sourcetype"])}" '
            'signalroom_schema="signalroom.audit.v1"'
        )

    def _base_search_terms(self) -> str:
        policy = self.store.policy()
        return (
            f'index="{self._spl_literal(policy["index_name"])}" '
            f'sourcetype="{self._spl_literal(policy["sourcetype"])}" '
            'signalroom_schema="signalroom.audit.v1"'
        )

    @staticmethod
    def _spl_literal(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _canonical(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
