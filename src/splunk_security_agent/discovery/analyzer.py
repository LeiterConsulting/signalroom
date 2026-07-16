from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

DOMAIN_TERMS = {
    "identity": ("wineventlog", "authentication", "okta", "azure:aad", "entra", "duo", "ldap"),
    "endpoint": ("sysmon", "crowdstrike", "falcon", "defender", "edr", "carbonblack"),
    "network": ("pan:", "firewall", "zeek", "suricata", "dns", "netflow", "proxy"),
    "cloud": ("cloudtrail", "aws:", "azure:", "gcp:", "kubernetes", "o365:management"),
    "email": ("exchange", "proofpoint", "mimecast", "messagetracking", "email", "o365"),
}


class SecurityDiscoveryAnalyzer:
    """Turn collected Splunk inventory into deterministic, attributable security posture signals."""

    @classmethod
    def analyze(cls, inventory: dict[str, Any]) -> dict[str, Any]:
        sourcetypes = cls._list(inventory.get("sourcetypes"))
        indexes = cls._list(inventory.get("indexes"))
        activity = cls._list(inventory.get("telemetry_activity"))
        knowledge = inventory.get("knowledge_objects") or {}
        saved = cls._list(knowledge.get("saved_searches"))
        alerts = cls._list(knowledge.get("alerts"))
        data_models = cls._list(knowledge.get("data_models"))
        macros = cls._list(knowledge.get("macros"))
        lookups = cls._list(knowledge.get("lookups"))

        telemetry = cls._telemetry(sourcetypes, activity)
        detections = cls._detections(saved, alerts)
        models = cls._data_models(data_models)
        posture = {
            "telemetry": telemetry,
            "detections": detections,
            "data_models": models,
            "knowledge": {"macros": len(macros), "lookups": len(lookups)},
        }
        findings = cls._findings(posture, indexes)
        return {"posture": posture, "findings": findings, "tracks": cls._tracks(findings)}

    @classmethod
    def _telemetry(cls, sourcetypes: list[dict[str, Any]], activity: list[dict[str, Any]]) -> dict[str, Any]:
        names = sorted(
            {cls._name(item, "sourcetype") for item in sourcetypes if cls._name(item, "sourcetype")}
        )
        domains: dict[str, dict[str, Any]] = {}
        joined = [(name, name.lower()) for name in names]
        for domain, terms in DOMAIN_TERMS.items():
            matches = [name for name, lowered in joined if any(term in lowered for term in terms)]
            domains[domain] = {"status": "observed" if matches else "gap-to-validate", "sourcetypes": matches}

        now = datetime.now(UTC).timestamp()
        stale: list[dict[str, Any]] = []
        active: list[dict[str, Any]] = []
        for row in activity:
            name = cls._name(row, "sourcetype")
            recent = cls._number(row, "recentTime", "latest")
            count = cls._number(row, "totalCount", "count")
            age_hours = round(max(0, now - recent) / 3600, 1) if recent else None
            record = {"sourcetype": name, "total_count": int(count), "age_hours": age_hours}
            active.append(record)
            if age_hours is not None and age_hours > 24:
                stale.append(record)
        stale.sort(key=lambda item: item["age_hours"] or 0, reverse=True)
        return {
            "catalogued_sourcetypes": len(names),
            "domains": domains,
            "coverage_score": round(
                sum(value["status"] == "observed" for value in domains.values()) / len(domains) * 100
            ),
            "activity_profiled": len(active),
            "stale_over_24h": stale,
            "highest_volume": sorted(active, key=lambda item: item["total_count"], reverse=True)[:10],
        }

    @classmethod
    def _detections(cls, saved: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> dict[str, Any]:
        combined: dict[str, dict[str, Any]] = {}
        for item in [*saved, *alerts]:
            name = cls._name(item)
            if name:
                combined.setdefault(name, item)
        records = list(combined.values())
        disabled = [cls._name(item) for item in records if cls._truthy(item.get("disabled"))]
        scheduled = [item for item in records if str(item.get("cron_schedule") or "").strip()]
        missing_bounds = []
        broad_searches = []
        actionless = []
        apps: set[str] = set()
        catalog: list[dict[str, Any]] = []
        for item in records:
            name = cls._name(item)
            search = str(item.get("search") or "").strip()
            earliest = str(item.get("dispatch.earliest_time") or item.get("earliest_time") or "").strip()
            latest = str(item.get("dispatch.latest_time") or item.get("latest_time") or "").strip()
            actions = str(item.get("actions") or "").strip()
            app = str(item.get("app") or item.get("eai:acl.app") or "").strip()
            if app:
                apps.add(app)
            if search and not earliest and not latest:
                missing_bounds.append(name)
            if re.search(r"(?i)(?:^|\s)index\s*=\s*\*", search) or (
                search and not re.search(r"(?i)\b(index\s*=|tstats|from\s+datamodel|datamodel\s*=)", search)
            ):
                broad_searches.append(name)
            if item in scheduled and not actions:
                actionless.append(name)
            catalog.append(
                {
                    "name": name,
                    "app": app,
                    "disabled": cls._truthy(item.get("disabled")),
                    "scheduled": item in scheduled,
                    "schedule": str(item.get("cron_schedule") or ""),
                    "earliest": earliest,
                    "latest": latest,
                    "actions": actions,
                    "search": search[:1200],
                }
            )
        return {
            "total": len(records),
            "enabled": len(records) - len(disabled),
            "disabled": len(disabled),
            "disabled_names": disabled[:50],
            "scheduled": len(scheduled),
            "missing_time_bounds_count": len(missing_bounds),
            "missing_time_bounds": missing_bounds[:50],
            "broad_searches_count": len(broad_searches),
            "broad_searches": broad_searches[:50],
            "scheduled_without_actions_count": len(actionless),
            "scheduled_without_actions": actionless[:50],
            "apps": sorted(apps),
            "catalog": catalog,
        }

    @classmethod
    def _data_models(cls, values: list[dict[str, Any]]) -> dict[str, Any]:
        disabled = [cls._name(item) for item in values if cls._truthy(item.get("disabled"))]
        accelerated = []
        for item in values:
            value = item.get("acceleration")
            text = str(value).lower()
            if cls._truthy(value) or '"enabled": true' in text or "enabled=1" in text:
                accelerated.append(cls._name(item))
        return {
            "total": len(values),
            "enabled": len(values) - len(disabled),
            "disabled": len(disabled),
            "disabled_names": disabled,
            "accelerated": len([name for name in accelerated if name]),
            "accelerated_names": [name for name in accelerated if name],
            "catalog": [
                {
                    "name": cls._name(item),
                    "app": str(item.get("eai:acl.app") or ""),
                    "owner": str(item.get("eai:acl.owner") or ""),
                    "disabled": cls._truthy(item.get("disabled")),
                    "acceleration": str(item.get("acceleration") or "")[:500],
                }
                for item in values
            ],
        }

    @staticmethod
    def _findings(posture: dict[str, Any], indexes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        telemetry = posture["telemetry"]
        missing = [name for name, value in telemetry["domains"].items() if value["status"] != "observed"]
        if missing:
            findings.append(
                SecurityDiscoveryAnalyzer._finding(
                    "high" if len(missing) >= 3 else "medium",
                    "telemetry-coverage",
                    "Security telemetry domains need validation",
                    f"No matching sourcetypes were observed for: {', '.join(missing)}.",
                    "Confirm onboarding and field extraction for each missing domain before "
                    "relying on coverage claims.",
                    "medium",
                )
            )
        stale = telemetry["stale_over_24h"]
        if stale:
            findings.append(
                SecurityDiscoveryAnalyzer._finding(
                    "high" if any((item["age_hours"] or 0) > 72 for item in stale) else "medium",
                    "telemetry-health",
                    "Stale telemetry detected",
                    f"{len(stale)} sourcetype(s) have not reported in more than 24 hours.",
                    "Validate collection health for the oldest sources before running investigations "
                    "that depend on them.",
                    "high",
                )
            )
        detections = posture["detections"]
        if detections["disabled"]:
            findings.append(
                SecurityDiscoveryAnalyzer._finding(
                    "medium",
                    "detection-health",
                    "Disabled detections require ownership review",
                    f"{detections['disabled']} of {detections['total']} discovered detections are disabled.",
                    "Confirm whether each disabled rule is intentional, superseded, or awaiting "
                    "required telemetry.",
                    "high",
                )
            )
        if detections["missing_time_bounds_count"] or detections["broad_searches_count"]:
            findings.append(
                SecurityDiscoveryAnalyzer._finding(
                    "medium",
                    "detection-quality",
                    "Detection searches have reviewable scope risks",
                    f"{detections['missing_time_bounds_count']} lack explicit time bounds and "
                    f"{detections['broad_searches_count']} use broad or unclear data scope.",
                    "Review SPL cost, time windows, index constraints, and false-positive behavior.",
                    "medium",
                )
            )
        models = posture["data_models"]
        if models["total"] and models["accelerated"] < models["total"]:
            findings.append(
                SecurityDiscoveryAnalyzer._finding(
                    "low",
                    "cim-readiness",
                    "Data-model acceleration is incomplete",
                    f"{models['accelerated']} of {models['total']} discovered data models "
                    "report acceleration.",
                    "Identify the models used by priority detections and validate their acceleration "
                    "and field coverage.",
                    "medium",
                )
            )
        if not findings:
            findings.append(
                SecurityDiscoveryAnalyzer._finding(
                    "info",
                    "posture",
                    "No deterministic posture exception was raised",
                    f"Reviewed {len(indexes)} indexes and the available security knowledge objects.",
                    "Continue with model-assisted review and validate freshness before relying "
                    "on this baseline.",
                    "medium",
                )
            )
        return findings

    @staticmethod
    def _finding(
        severity: str, domain: str, title: str, evidence: str, next_step: str, confidence: str
    ) -> dict[str, Any]:
        return {
            "severity": severity,
            "domain": domain,
            "title": title,
            "evidence": evidence,
            "next_step": next_step,
            "confidence": confidence,
            "basis": "deterministic-analysis",
        }

    @staticmethod
    def _tracks(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        return [
            {
                "hypothesis": finding["title"],
                "why": finding["evidence"],
                "validation": finding["next_step"],
                "status": "open",
                "domain": finding["domain"],
            }
            for finding in findings
            if finding["severity"] != "info"
        ]

    @staticmethod
    def _list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item if isinstance(item, dict) else {"value": item} for item in value]
        if isinstance(value, dict):
            for key in ("results", "items", "data"):
                if isinstance(value.get(key), list):
                    return SecurityDiscoveryAnalyzer._list(value[key])
        return []

    @staticmethod
    def _name(item: dict[str, Any], preferred: str = "") -> str:
        return str(
            item.get(preferred) or item.get("name") or item.get("title") or item.get("value") or ""
        ).strip()

    @staticmethod
    def _truthy(value: Any) -> bool:
        return value is True or str(value).strip().lower() in {"1", "true", "yes", "enabled"}

    @staticmethod
    def _number(item: dict[str, Any], *keys: str) -> float:
        for key in keys:
            try:
                if item.get(key) not in (None, ""):
                    return float(item[key])
            except (TypeError, ValueError):
                continue
        return 0
