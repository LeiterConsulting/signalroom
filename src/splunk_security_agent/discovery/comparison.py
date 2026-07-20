from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


class DiscoveryComparisonService:
    """Compare two retained discovery summaries without merging their evidence."""

    SCHEMA_VERSION = "signalroom.discovery-comparison.v1"
    ITEM_LIMIT = 25
    FINDING_LIMIT = 8
    METRICS = (
        ("coverage_score", "Security-domain coverage", ("coverage", "score"), "percent"),
        ("indexes", "Indexes inventoried", ("overview", "indexes"), "count"),
        ("sourcetypes", "Sourcetypes observed", ("overview", "sourcetypes"), "count"),
        ("hosts", "Hosts represented", ("overview", "hosts"), "count"),
        ("sources", "Sources represented", ("overview", "sources"), "count"),
        (
            "stale_sourcetypes",
            "Sourcetypes stale over 24h",
            ("security_posture", "telemetry", "stale_over_24h"),
            "list-count",
        ),
        (
            "detections_total",
            "Detections inventoried",
            ("security_posture", "detections", "total"),
            "count",
        ),
        (
            "detections_enabled",
            "Enabled detections",
            ("security_posture", "detections", "enabled"),
            "count",
        ),
        (
            "detections_disabled",
            "Disabled detections",
            ("security_posture", "detections", "disabled"),
            "count",
        ),
        (
            "missing_time_bounds",
            "Detections missing time bounds",
            ("security_posture", "detections", "missing_time_bounds_count"),
            "count",
        ),
        (
            "broad_searches",
            "Broad detection searches",
            ("security_posture", "detections", "broad_searches_count"),
            "count",
        ),
        (
            "data_models_total",
            "Data models",
            ("security_posture", "data_models", "total"),
            "count",
        ),
        (
            "data_models_accelerated",
            "Accelerated data models",
            ("security_posture", "data_models", "accelerated"),
            "count",
        ),
        ("macros", "Macros", ("security_posture", "knowledge", "macros"), "count"),
        ("lookups", "Lookups", ("security_posture", "knowledge", "lookups"), "count"),
        (
            "mltk_models",
            "MLTK models observed",
            ("security_posture", "mltk_models", "observed"),
            "count",
        ),
        (
            "failed_calls",
            "Discovery collection gaps",
            ("collection_status", "failed_calls"),
            "count",
        ),
    )
    SETS = (
        (
            "detection_apps",
            "Detection apps",
            ("security_posture", "detections", "apps"),
            ("name", "app", "title"),
        ),
        (
            "stale_sourcetypes",
            "Sourcetypes stale over 24h",
            ("security_posture", "telemetry", "stale_over_24h"),
            ("sourcetype", "name", "title"),
        ),
        (
            "disabled_detections",
            "Disabled detections",
            ("security_posture", "detections", "disabled_names"),
            ("name", "title"),
        ),
        (
            "accelerated_data_models",
            "Accelerated data models",
            ("security_posture", "data_models", "accelerated_names"),
            ("name", "title"),
        ),
    )

    def compare(
        self,
        left_scope: dict[str, Any],
        left_summary: dict[str, Any] | None,
        right_scope: dict[str, Any],
        right_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        left_binding = self._binding(left_scope)
        right_binding = self._binding(right_scope)
        if self._binding_key(left_binding) == self._binding_key(right_binding):
            raise ValueError("Choose two different immutable Splunk scopes to compare.")
        if not left_summary or not left_summary.get("run_id"):
            raise ValueError(
                f"No retained discovery snapshot exists for {self._scope_label(left_binding)}."
            )
        if not right_summary or not right_summary.get("run_id"):
            raise ValueError(
                f"No retained discovery snapshot exists for {self._scope_label(right_binding)}."
            )

        left = self._source("left", left_binding, left_summary)
        right = self._source("right", right_binding, right_summary)
        comparison_identity = {
            "schema_version": self.SCHEMA_VERSION,
            "left": {
                "binding": self._binding_key(left_binding),
                "run_id": left["run_id"],
                "snapshot_sha256": left["snapshot_sha256"],
            },
            "right": {
                "binding": self._binding_key(right_binding),
                "run_id": right["run_id"],
                "snapshot_sha256": right["snapshot_sha256"],
            },
        }
        comparison_id = self._digest(comparison_identity)

        return {
            "schema_version": self.SCHEMA_VERSION,
            "comparison_id": comparison_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "contract": {
                "splunk_queries": 0,
                "model_inference": False,
                "raw_rows_persisted": False,
                "merged_evidence": False,
                "source_attribution_required": True,
                "basis": "Latest retained discovery summary for each exact immutable scope.",
            },
            "left": left,
            "right": right,
            "metrics": self._metrics(left_summary, right_summary),
            "domains": self._domains(left_summary, right_summary),
            "contrasts": self._contrasts(left_summary, right_summary),
            "findings": {
                "left": self._findings(left_summary),
                "right": self._findings(right_summary),
            },
            "caveats": self._caveats(left_summary, right_summary),
        }

    @classmethod
    def _binding(cls, value: dict[str, Any]) -> dict[str, str]:
        return {
            "alias": str(value.get("alias") or value.get("connection_alias") or "primary"),
            "display_name": str(
                value.get("display_name")
                or value.get("alias")
                or value.get("connection_alias")
                or "Primary Splunk"
            ),
            "fingerprint": str(
                value.get("fingerprint") or value.get("connection_fingerprint") or ""
            ),
            "tenant_scope_id": str(value.get("tenant_scope_id") or "workspace-primary"),
        }

    @staticmethod
    def _binding_key(value: dict[str, str]) -> str:
        return "|".join(
            (value["alias"], value["fingerprint"], value["tenant_scope_id"])
        )

    @staticmethod
    def _scope_label(value: dict[str, str]) -> str:
        return f"{value['display_name']} · {value['tenant_scope_id']}"

    @classmethod
    def _source(
        cls,
        side: str,
        binding: dict[str, str],
        summary: dict[str, Any],
    ) -> dict[str, Any]:
        collection = summary.get("collection_status") or {}
        failed_calls = int(cls._numeric(collection.get("failed_calls")) or 0)
        return {
            "side": side,
            "connection_alias": binding["alias"],
            "display_name": binding["display_name"],
            "connection_fingerprint": binding["fingerprint"],
            "tenant_scope_id": binding["tenant_scope_id"],
            "run_id": str(summary.get("run_id") or ""),
            "generated_at": str(summary.get("generated_at") or ""),
            "depth": str(summary.get("depth") or "unknown"),
            "snapshot_sha256": cls._digest(summary),
            "collection_complete": bool(collection.get("complete", failed_calls == 0)),
            "failed_calls": failed_calls,
        }

    @classmethod
    def _metrics(
        cls, left: dict[str, Any], right: dict[str, Any]
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for key, label, path, kind in cls.METRICS:
            left_value = cls._path(left, path)
            right_value = cls._path(right, path)
            if kind == "list-count":
                left_value = len(left_value) if isinstance(left_value, list) else 0
                right_value = len(right_value) if isinstance(right_value, list) else 0
            left_number = cls._numeric(left_value)
            right_number = cls._numeric(right_value)
            if left_number is None and right_number is None:
                continue
            result.append(
                {
                    "key": key,
                    "label": label,
                    "unit": "percent" if kind == "percent" else "count",
                    "left": left_number,
                    "right": right_number,
                    "delta_right_minus_left": (
                        right_number - left_number
                        if left_number is not None and right_number is not None
                        else None
                    ),
                }
            )
        return result

    @classmethod
    def _domains(
        cls, left: dict[str, Any], right: dict[str, Any]
    ) -> list[dict[str, str]]:
        left_domains = cls._path(left, ("coverage", "domains"))
        right_domains = cls._path(right, ("coverage", "domains"))
        left_domains = left_domains if isinstance(left_domains, dict) else {}
        right_domains = right_domains if isinstance(right_domains, dict) else {}
        result = []
        for domain in sorted(set(left_domains) | set(right_domains), key=str.casefold):
            left_status = cls._domain_status(left_domains.get(domain))
            right_status = cls._domain_status(right_domains.get(domain))
            result.append(
                {
                    "domain": str(domain),
                    "left": left_status,
                    "right": right_status,
                    "relation": "same" if left_status == right_status else "different",
                }
            )
        return result

    @classmethod
    def _contrasts(
        cls, left: dict[str, Any], right: dict[str, Any]
    ) -> list[dict[str, Any]]:
        result = []
        for key, label, path, label_keys in cls.SETS:
            left_values = cls._labels(cls._path(left, path), label_keys)
            right_values = cls._labels(cls._path(right, path), label_keys)
            left_map = {item.casefold(): item for item in left_values}
            right_map = {item.casefold(): item for item in right_values}
            left_only = [left_map[item] for item in sorted(left_map.keys() - right_map.keys())]
            right_only = [right_map[item] for item in sorted(right_map.keys() - left_map.keys())]
            result.append(
                {
                    "key": key,
                    "label": label,
                    "left_only_count": len(left_only),
                    "right_only_count": len(right_only),
                    "shared_count": len(left_map.keys() & right_map.keys()),
                    "left_only": left_only[: cls.ITEM_LIMIT],
                    "right_only": right_only[: cls.ITEM_LIMIT],
                    "truncated": len(left_only) > cls.ITEM_LIMIT
                    or len(right_only) > cls.ITEM_LIMIT,
                }
            )
        return result

    @classmethod
    def _findings(cls, summary: dict[str, Any]) -> list[dict[str, str]]:
        findings = summary.get("findings")
        if not isinstance(findings, list):
            return []
        result = []
        for item in findings[: cls.FINDING_LIMIT]:
            if not isinstance(item, dict):
                continue
            result.append(
                {
                    "severity": str(item.get("severity") or "info"),
                    "domain": str(item.get("domain") or ""),
                    "title": str(item.get("title") or "Untitled observation"),
                    "evidence": str(item.get("evidence") or ""),
                    "next_step": str(item.get("next_step") or ""),
                }
            )
        return result

    @classmethod
    def _caveats(
        cls, left: dict[str, Any], right: dict[str, Any]
    ) -> list[str]:
        caveats = [
            (
                "This is a cross-estate snapshot comparison, not a temporal trend. A difference "
                "does not by itself mean that either estate is safer, less safe, improved, or regressed."
            )
        ]
        left_depth = str(left.get("depth") or "unknown")
        right_depth = str(right.get("depth") or "unknown")
        if left_depth != right_depth:
            caveats.append(
                f"Discovery depth differs ({left_depth} versus {right_depth}); "
                "some inventory may not be comparable."
            )
        for side, summary in (("Left", left), ("Right", right)):
            collection = summary.get("collection_status") or {}
            failed = int(cls._numeric(collection.get("failed_calls")) or 0)
            if failed:
                caveats.append(
                    f"{side} snapshot reports {failed} collection gap(s); "
                    "absence may mean uncollected, not absent."
                )
        return caveats

    @staticmethod
    def _path(value: dict[str, Any], path: tuple[str, ...]) -> Any:
        current: Any = value
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    @staticmethod
    def _numeric(value: Any) -> int | float | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, list):
            return len(value)
        if isinstance(value, (int, float)):
            return value
        try:
            number = float(str(value))
        except (TypeError, ValueError):
            return None
        return int(number) if number.is_integer() else number

    @staticmethod
    def _domain_status(value: Any) -> str:
        if isinstance(value, bool):
            return "observed" if value else "gap-to-validate"
        if isinstance(value, dict):
            value = value.get("status")
        normalized = str(value or "unknown").strip().lower()
        return normalized if normalized else "unknown"

    @staticmethod
    def _labels(value: Any, keys: tuple[str, ...]) -> list[str]:
        if not isinstance(value, list):
            return []
        labels: set[str] = set()
        for item in value:
            if isinstance(item, str):
                label = item.strip()
            elif isinstance(item, dict):
                label = next(
                    (str(item.get(key) or "").strip() for key in keys if item.get(key)),
                    "",
                )
            else:
                label = str(item).strip()
            if label:
                labels.add(label)
        return sorted(labels, key=str.casefold)

    @staticmethod
    def _digest(value: Any) -> str:
        payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=str
        ).encode()
        return hashlib.sha256(payload).hexdigest()
