from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from html import escape as xml_escape
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..audit import AuditStore
from ..schemas import AuditOperationsPolicyUpdate
from .service import SplunkAuditExportService
from .store import AuditExportStore

APP_ID = "signalroom_audit_operations"
INDEXER_APP_ID = "signalroom_audit_retention"
SCHEMA_VERSION = "signalroom.audit-operations.v1"


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

    def overview(self, export_overview: dict[str, Any] | None = None) -> dict[str, Any]:
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
