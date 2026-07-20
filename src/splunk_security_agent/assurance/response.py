from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ..schemas import ValidationTaskCreate
from ..validation import ValidationService
from .store import AssuranceStore

PACKAGE_LIFETIME = timedelta(days=7)
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class AssuranceResponseService:
    """Turn correlated assurance signals into local, review-only response work."""

    def __init__(
        self,
        store: AssuranceStore,
        validation_service: Callable[[], ValidationService],
    ):
        self.store = store
        self.validation_service = validation_service

    def process(
        self,
        run_id: str,
        result: dict[str, Any],
        *,
        scope_key: str = "",
    ) -> dict[str, Any] | None:
        signals = self._signals(result)
        collection = result.get("collection_status", {})
        failed_calls = int(collection.get("failed_calls") or 0)
        depth = str(result.get("depth") or "standard")
        authoritative_kinds = {"inventory", "collection"}
        if depth in {"standard", "deep"}:
            authoritative_kinds.update({"coverage", "finding", "mltk"})
        correlated = self.store.correlate_signals(
            run_id,
            signals,
            authoritative=failed_calls == 0,
            authoritative_kinds=authoritative_kinds,
            scope_key=scope_key,
        )
        source_run = self.store.get_run(run_id)
        tenant_scope_id = source_run.tenant_scope_id if source_run else ""
        covered = self.store.covered_signal_fingerprints(tenant_scope_id=tenant_scope_id)
        authoritative = {
            self.store.scoped_signal_fingerprint(scope_key, item["fingerprint"]): str(
                item.get("authoritative", "true")
            ).lower()
            != "false"
            for item in signals
        }
        eligible = [
            item
            for item in correlated
            if item["status"] == "persistent"
            and item["fingerprint"] not in covered
            and authoritative.get(item["fingerprint"], True)
        ]
        if not eligible:
            return None

        eligible.sort(
            key=lambda item: (
                -SEVERITY_RANK.get(str(item.get("severity")), 0),
                -int(item.get("consecutive_count", 0)),
                str(item.get("title", "")),
            )
        )
        eligible = eligible[:12]
        expires_at = (datetime.now(UTC) + PACKAGE_LIFETIME).isoformat()
        severity = max(
            (str(item.get("severity") or "medium") for item in eligible),
            key=lambda value: SEVERITY_RANK.get(value, 0),
        )
        repeated = sum(int(item.get("consecutive_count", 0)) >= 2 for item in eligible)
        urgent = len(eligible) - repeated
        title = f"Assurance response · {len(eligible)} actionable signal{'s' if len(eligible) != 1 else ''}"
        summary_parts = []
        if repeated:
            summary_parts.append(f"{repeated} repeated across consecutive runs")
        if urgent:
            summary_parts.append(f"{urgent} elevated immediately by severity")
        summary_parts.append(
            "Any proposed SPL remains a local draft until an analyst approves the exact contract"
        )
        package = self.store.create_package(
            run_id,
            severity,
            title,
            ". ".join(summary_parts) + ".",
            [item["fingerprint"] for item in eligible],
            expires_at,
        )
        task_ids = self._validation_drafts(package["id"], expires_at, eligible, result, package)
        package = self.store.update_package_validations(package["id"], task_ids) or package
        self.store.add_notification(
            run_id,
            severity,
            "response-package",
            title,
            (
                f"{len(task_ids)} deduplicated validation draft(s) are ready for review and "
                f"expire {expires_at}. No SPL was approved or executed."
            ),
        )
        return package

    def _validation_drafts(
        self,
        package_id: str,
        expires_at: str,
        signals: list[dict[str, Any]],
        result: dict[str, Any],
        binding: dict[str, Any],
    ) -> list[str]:
        service = self.validation_service()
        candidates = {
            str(item.get("source_finding_ref") or item.get("id") or ""): item
            for item in result.get("validation_candidates", [])
            if isinstance(item, dict)
        }
        selected: list[dict[str, Any]] = []
        for signal in signals:
            candidate = candidates.get(str(signal.get("source_ref") or ""))
            if candidate:
                selected.append(candidate)
        if any(item.get("kind") in {"inventory", "coverage"} for item in signals):
            selected.append(
                {
                    "title": "Validate · Current telemetry inventory after assurance drift",
                    "rationale": (
                        "A repeated inventory or coverage change needs a current, bounded "
                        "observation before escalation or ownership decisions."
                    ),
                    "spl": (
                        "| tstats count where earliest=-24h by index sourcetype | sort - count | head 100"
                    ),
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 100,
                    "evidence_refs": [],
                    "source_run_id": str(result.get("run_id") or ""),
                    "source_finding_ref": "DRIFT",
                }
            )

        task_ids: list[str] = []
        seen_fingerprints: set[str] = set()
        for candidate in selected:
            fingerprint = service.store.fingerprint(
                str(candidate.get("spl") or ""),
                str(candidate.get("earliest_time") or "-24h"),
                str(candidate.get("latest_time") or "now"),
                int(candidate.get("row_limit") or 100),
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            reusable = service.store.find_reusable(
                fingerprint,
                tenant_scope_id=str(binding.get("tenant_scope_id") or "workspace-primary"),
            )
            if reusable:
                task_ids.append(reusable.id)
                continue
            evidence_refs = sorted(
                {
                    *[str(value) for value in candidate.get("evidence_refs", []) if value],
                    *[str(item.get("source_ref")) for item in signals if item.get("source_ref")],
                }
            )[:16]
            task = service.create(
                ValidationTaskCreate(
                    title=str(candidate.get("title") or "Assurance validation")[:240],
                    rationale=(
                        f"Continuous assurance response package {package_id[:8]}. "
                        f"{candidate.get('rationale') or 'Validate the correlated signal.'}"
                    )[:4000],
                    spl=str(candidate.get("spl") or ""),
                    earliest_time=str(candidate.get("earliest_time") or "-24h"),
                    latest_time=str(candidate.get("latest_time") or "now"),
                    row_limit=int(candidate.get("row_limit") or 100),
                    evidence_refs=evidence_refs,
                    source_run_id=str(candidate.get("source_run_id") or result.get("run_id") or ""),
                    source_finding_ref=str(candidate.get("source_finding_ref") or "ASSURANCE")[:40],
                    expires_at=expires_at,
                    assurance_package_id=package_id,
                    approval_scope="single-execution",
                    connection_alias=str(binding.get("connection_alias") or "primary"),
                    connection_fingerprint=str(binding.get("connection_fingerprint") or ""),
                    tenant_scope_id=str(binding.get("tenant_scope_id") or "workspace-primary"),
                )
            )
            task_ids.append(task.id)
        return task_ids

    @classmethod
    def _signals(cls, result: dict[str, Any]) -> list[dict[str, str]]:
        values: list[dict[str, str]] = []
        collection = result.get("collection_status", {})
        failed_calls = int(collection.get("failed_calls") or 0)
        for index, finding in enumerate(result.get("findings", []), 1):
            if not isinstance(finding, dict):
                continue
            domain = str(finding.get("domain") or "posture")
            title = str(finding.get("title") or "Discovery finding")
            severity = str(finding.get("severity") or "medium")
            detail = str(finding.get("evidence") or finding.get("next_step") or "")
            if failed_calls:
                severity = "medium" if severity in {"critical", "high"} else severity
                detail = f"Collection was incomplete; treat this derived finding as unverified. {detail}"
            values.append(
                cls._signal(
                    "finding",
                    severity,
                    title,
                    detail,
                    domain,
                    f"D{index}",
                    [domain, title],
                    authoritative=failed_calls == 0,
                )
            )

        inventory = result.get("changes", {}).get("inventory", {})
        if isinstance(inventory, dict):
            for category, change in inventory.items():
                if not isinstance(change, dict):
                    continue
                for direction in ("added", "removed"):
                    for item in change.get(direction, []) or []:
                        subject = cls._subject(item)
                        values.append(
                            cls._signal(
                                "inventory",
                                "medium",
                                f"{str(category).replace('_', ' ').title()} {direction}",
                                f"{subject} was {direction} in deterministic discovery inventory.",
                                subject,
                                "",
                                [str(category), direction, subject],
                                authoritative=failed_calls == 0,
                            )
                        )

        coverage = result.get("changes", {}).get("coverage", {})
        if isinstance(coverage, dict):
            for domain, change in coverage.items():
                detail = json.dumps(change, sort_keys=True, default=str)
                values.append(
                    cls._signal(
                        "coverage",
                        "medium",
                        f"{str(domain).replace('_', ' ').title()} coverage changed",
                        detail,
                        str(domain),
                        "",
                        [str(domain)],
                        authoritative=failed_calls == 0,
                    )
                )

        mltk = result.get("splunk_models", {}).get("summary", {})
        changed = int(mltk.get("changed") or 0)
        missing = int(mltk.get("missing") or 0)
        if changed or missing:
            values.append(
                cls._signal(
                    "mltk",
                    "medium",
                    "Splunk MLTK model definitions drifted",
                    f"{changed} changed and {missing} missing model definitions.",
                    "mltk-model-catalog",
                    "",
                    ["definitions"],
                    authoritative=failed_calls == 0,
                )
            )

        if failed_calls:
            errors = collection.get("errors") if isinstance(collection.get("errors"), dict) else {}
            tools = collection.get("failed_tools") or list(errors) or ["unknown MCP collection"]
            for item in tools:
                subject = cls._subject(item)
                error = str(errors.get(item) or "")
                values.append(
                    cls._signal(
                        "collection",
                        "high",
                        "Assurance collection path failed",
                        (f"The bounded read-only collection path failed: {subject}. {error}").strip(),
                        subject,
                        "",
                        [subject],
                    )
                )
        return values

    @staticmethod
    def _subject(value: Any) -> str:
        if isinstance(value, dict):
            for key in ("name", "id", "title", "tool"):
                if value.get(key):
                    return str(value[key])[:500]
            return json.dumps(value, sort_keys=True, default=str)[:500]
        return str(value)[:500]

    @staticmethod
    def _signal(
        kind: str,
        severity: str,
        title: str,
        detail: str,
        subject: str,
        source_ref: str,
        identity: list[str],
        authoritative: bool = True,
    ) -> dict[str, str]:
        payload = json.dumps([kind, *identity], sort_keys=True, separators=(",", ":"))
        return {
            "fingerprint": hashlib.sha256(payload.encode()).hexdigest(),
            "kind": kind,
            "severity": severity if severity in SEVERITY_RANK else "medium",
            "title": title[:240],
            "detail": detail[:4000],
            "subject": subject[:500],
            "source_ref": source_ref[:40],
            "authoritative": "true" if authoritative else "false",
        }
