from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError

from ..config import ConfigStore
from ..progress import ProgressCallback, report_progress
from ..providers import ModelRouter
from ..providers.local_transformers import local_model_installed
from ..rag import EvidenceStore
from ..schemas import ArtifactCreate
from .analyzer import SecurityDiscoveryAnalyzer


class DiscoveryDomainInterpretation(BaseModel):
    domain: str
    status: Literal["observed", "gap-to-validate", "unknown"] = "unknown"
    evidence: str = ""


class GeneralDiscoverySynthesis(BaseModel):
    environment_summary: str = Field(min_length=1, max_length=4000)
    material_observations: list[str] = Field(default_factory=list, max_length=10)
    coverage_interpretation: list[DiscoveryDomainInterpretation] = Field(
        default_factory=list, max_length=8
    )
    change_summary: list[str] = Field(default_factory=list, max_length=8)
    questions_for_security_review: list[str] = Field(default_factory=list, max_length=8)
    caveats: list[str] = Field(default_factory=list, max_length=8)


class DiscoveryPriority(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    why: str = Field(min_length=1, max_length=2000)
    owner: str = Field(default="Unassigned", max_length=160)
    next_step: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=8)


class DiscoveryHypothesis(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    basis: str = Field(min_length=1, max_length=2000)
    validation: str = Field(min_length=1, max_length=2000)
    confidence: Literal["high", "medium", "low"] = "low"
    evidence_refs: list[str] = Field(default_factory=list, max_length=8)


class DiscoveryDetectionOpportunity(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    rationale: str = Field(min_length=1, max_length=2000)
    required_telemetry: list[str] = Field(default_factory=list, max_length=10)
    validation: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=8)


class SecurityDiscoveryAssessment(BaseModel):
    executive_summary: str = Field(min_length=1, max_length=4000)
    priorities: list[DiscoveryPriority] = Field(default_factory=list, max_length=8)
    risk_hypotheses: list[DiscoveryHypothesis] = Field(default_factory=list, max_length=8)
    detection_opportunities: list[DiscoveryDetectionOpportunity] = Field(
        default_factory=list, max_length=8
    )
    caveats: list[str] = Field(default_factory=list, max_length=10)


class DiscoveryPipeline:
    """Purposeful, read-only Splunk discovery that produces reusable evidence artifacts."""

    def __init__(
        self,
        client: Any,
        evidence: EvidenceStore,
        output_dir: Path | str = "data/artifacts",
        config: ConfigStore | None = None,
    ):
        self.client = client
        self.evidence = evidence
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config
        self.router = ModelRouter(config) if config else None

    KNOWLEDGE_ROW_LIMIT = 1000
    KNOWLEDGE_PAGE_SIZE = 100

    def latest_summary(self) -> dict[str, Any] | None:
        """Return the latest renderable result without the large raw inventory catalogs."""
        blueprint = self._read_blueprint(self.output_dir / "security_blueprint_latest.json")
        if not blueprint:
            return None
        posture = blueprint.get("security_posture", {})
        posture_summary = {
            **posture,
            "detections": {
                key: value
                for key, value in posture.get("detections", {}).items()
                if key != "catalog"
            },
            "data_models": {
                key: value
                for key, value in posture.get("data_models", {}).items()
                if key != "catalog"
            },
        }
        keys = (
            "schema_version",
            "run_id",
            "depth",
            "generated_at",
            "overview",
            "findings",
            "coverage",
            "investigation_tracks",
            "validation_candidates",
            "changes",
            "collection_status",
            "model_analysis",
            "fingerprints",
            "artifacts",
            "knowledge_artifacts",
        )
        return {
            **{key: blueprint.get(key) for key in keys},
            "security_posture": posture_summary,
        }

    async def run(
        self, depth: str = "standard", progress: ProgressCallback | None = None
    ) -> dict[str, Any]:
        run_id = str(uuid4())
        started_at = datetime.now(UTC)
        await report_progress(
            progress,
            "inventory",
            "Reading core Splunk inventory",
            (
                "Collecting server information, indexes, sourcetypes, and hosts in parallel "
                "through read-only MCP tools."
            ),
            progress=6,
            metrics={"depth": depth, "parallel_calls": 4},
        )
        info_result, indexes_result, sourcetypes_result, hosts_result = await asyncio.gather(
            self._safe_call("get_info", {}),
            self._safe_call("get_indexes", {}),
            self._safe_call("get_metadata", {"type": "sourcetypes"}),
            self._safe_call("get_metadata", {"type": "hosts"}),
        )
        info = info_result
        indexes = self._as_list(indexes_result)
        sourcetypes = self._as_list(sourcetypes_result)
        hosts = self._as_list(hosts_result)
        await report_progress(
            progress,
            "inventory",
            "Core inventory collected",
            f"{len(indexes)} indexes · {len(sourcetypes)} sourcetypes · {len(hosts)} hosts.",
            progress=20,
            status="complete",
            metrics={"indexes": len(indexes), "sourcetypes": len(sourcetypes), "hosts": len(hosts)},
        )
        sources = []
        telemetry_activity: Any = []
        knowledge: Any = {}
        knowledge_pagination: dict[str, Any] = {}
        collection_results = {
            "info": info_result,
            "indexes": indexes_result,
            "sourcetypes": sourcetypes_result,
            "hosts": hosts_result,
        }
        if depth in {"standard", "deep"}:
            knowledge_types = ["saved_searches", "alerts"]
            if depth == "deep":
                knowledge_types.extend(["data_models", "macros", "lookups"])
            await report_progress(
                progress,
                "security-content",
                "Profiling telemetry and security content",
                (
                    "Reading sources, 30-day sourcetype activity, and "
                    f"{len(knowledge_types)} knowledge-object collections."
                ),
                progress=26,
                metrics={"knowledge_types": len(knowledge_types)},
            )
            extended = await asyncio.gather(
                self._safe_call("get_metadata", {"type": "sources"}),
                self._safe_call(
                    "run_query",
                    {
                        "query": (
                            "| metadata type=sourcetypes index=* "
                            "| eval age_seconds=now()-recentTime "
                            "| sort -totalCount | head 500"
                        ),
                        "earliest_time": "-30d",
                        "latest_time": "now",
                        "row_limit": 500,
                    },
                ),
                *(self._collect_knowledge(object_type, progress) for object_type in knowledge_types),
            )
            sources_result, telemetry_activity_result, *knowledge_results = extended
            sources = self._as_list(sources_result)
            telemetry_activity = self._as_list(telemetry_activity_result)
            for object_type, (items, page_info, raw_result) in zip(
                knowledge_types, knowledge_results, strict=True
            ):
                knowledge[object_type] = items
                knowledge_pagination[object_type] = page_info
                collection_results[f"knowledge:{object_type}"] = raw_result
            collection_results["sources"] = sources_result
            collection_results["telemetry_activity"] = telemetry_activity_result
            await report_progress(
                progress,
                "security-content",
                "Telemetry and security content collected",
                f"{len(sources)} sources · {len(telemetry_activity)} activity rows · "
                f"{sum(len(items) for items in knowledge.values())} knowledge objects.",
                progress=58,
                status="complete",
                metrics={
                    "sources": len(sources),
                    "activity_rows": len(telemetry_activity),
                    "knowledge_objects": sum(len(items) for items in knowledge.values()),
                },
            )

        inventory = {
            "indexes": indexes,
            "sourcetypes": sourcetypes,
            "hosts": hosts,
            "sources": sources,
            "telemetry_activity": telemetry_activity,
            "knowledge_objects": knowledge,
        }
        analysis = SecurityDiscoveryAnalyzer.analyze(inventory)
        await report_progress(
            progress,
            "analysis",
            "Deterministic security analysis complete",
            (
                "Mapped telemetry coverage, freshness, detection health, data-model readiness, "
                "and investigation tracks without an LLM."
            ),
            progress=68,
            status="complete",
            metrics={"findings": len(analysis["findings"]), "tracks": len(analysis["tracks"])},
        )
        findings = analysis["findings"]
        coverage = {
            "domains": {
                name: value["status"] == "observed"
                for name, value in analysis["posture"]["telemetry"]["domains"].items()
            },
            "score": analysis["posture"]["telemetry"]["coverage_score"],
        }
        blueprint = {
            "schema_version": "3.0",
            "run_id": run_id,
            "depth": depth,
            "generated_at": datetime.now(UTC).isoformat(),
            "overview": {
                "splunk_version": self._value(info, "version", "unknown"),
                "license_state": self._value(info, "license_state", "unknown"),
                "indexes": len(indexes),
                "sourcetypes": len(sourcetypes),
                "hosts": len(hosts),
                "sources": len(sources),
                "data_size_mb": round(sum(self._number(item, "currentDBSizeMB") for item in indexes), 2),
            },
            "inventory": inventory,
            "findings": findings,
            "coverage": coverage,
            "security_posture": analysis["posture"],
            "investigation_tracks": analysis["tracks"],
            "validation_candidates": self._validation_candidates(findings, run_id),
            "changes": {},
            "collection_status": {
                **self._collection_status(collection_results),
                "pagination": knowledge_pagination,
            },
            "provenance": {
                "source": "Splunk MCP tools",
                "mode": "read-only",
                "collection_seconds": round((datetime.now(UTC) - started_at).total_seconds(), 2),
            },
        }
        latest_path = self.output_dir / "security_blueprint_latest.json"
        previous = self._read_blueprint(latest_path)
        blueprint["changes"] = self._compare(previous, blueprint)
        blueprint["fingerprints"] = self._discovery_fingerprints(blueprint)
        model_started = datetime.now(UTC)
        blueprint["model_analysis"] = await self._model_team_analysis(
            blueprint, progress, previous
        )
        blueprint["model_analysis"]["duration_seconds"] = round(
            (datetime.now(UTC) - model_started).total_seconds(), 2
        )
        reconciled_tracks = blueprint["model_analysis"].get("reconciliation", {}).get(
            "investigation_tracks", []
        )
        blueprint["investigation_tracks"] = self._merge_tracks(
            blueprint["investigation_tracks"], reconciled_tracks
        )
        blueprint["provenance"]["duration_seconds"] = round(
            (datetime.now(UTC) - started_at).total_seconds(), 2
        )
        stamp = started_at.strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"security_blueprint_{stamp}.json"
        brief_path = self.output_dir / f"security_brief_{stamp}.md"
        knowledge_artifacts = self._index_knowledge(blueprint)
        await report_progress(
            progress,
            "artifacts",
            "Indexing reusable discovery knowledge",
            f"Created {len(knowledge_artifacts)} focused local RAG documents and the discovery brief.",
            progress=96,
            metrics={"knowledge_artifacts": len(knowledge_artifacts)},
        )
        blueprint["artifacts"] = [json_path.name, brief_path.name]
        blueprint["knowledge_artifacts"] = knowledge_artifacts
        json_path.write_text(json.dumps(blueprint, indent=2, default=str), encoding="utf-8")
        latest_path.write_text(json.dumps(blueprint, indent=2, default=str), encoding="utf-8")
        brief = self._markdown(blueprint)
        brief_path.write_text(brief, encoding="utf-8")
        self.evidence.add(
            ArtifactCreate(
                title=f"Splunk security discovery {stamp}",
                content=brief,
                kind="discovery",
                source="Splunk MCP discovery",
                tags=["splunk", "discovery", depth],
            ),
            metadata={"run_id": run_id, "blueprint": json_path.name},
        )
        await report_progress(
            progress,
            "complete",
            "Discovery ready for investigation",
            f"{len(findings)} findings · {len(blueprint['investigation_tracks'])} "
            "investigation tracks · "
            f"{len(knowledge_artifacts)} reusable knowledge artifacts.",
            progress=100,
            status="complete",
            metrics={
                "findings": len(findings),
                "tracks": len(blueprint["investigation_tracks"]),
                "knowledge_artifacts": len(knowledge_artifacts),
            },
        )
        return blueprint

    async def _model_team_analysis(
        self,
        blueprint: dict[str, Any],
        progress: ProgressCallback | None = None,
        previous: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.config or not self.router or blueprint["depth"] == "quick":
            await report_progress(
                progress,
                "model-team",
                "Deterministic discovery complete",
                "Quick discovery intentionally skips model passes to preserve baseline speed.",
                progress=92,
                status="complete",
                metrics={"model_passes": 0, "network_inference": 0},
            )
            return {
                "status": "not-run",
                "strategy": "deterministic-only",
                "reason": "Quick discovery uses deterministic analysis only.",
                "passes": [],
                "specialist_enrichment": {"status": "not-run", "passes": []},
                "reconciliation": {"investigation_tracks": []},
            }

        settings = self.config.load()
        evidence_map = self._evidence_map(blueprint)
        compact = self._compact_blueprint(blueprint, evidence_map)
        specialist_fingerprint = self._fingerprint(
            {
                "contract": "securebert-discovery-v1",
                "deterministic": blueprint["fingerprints"]["deterministic"],
                "context": self._context_revision(),
                "runtime": settings.specialist_runtime,
                "embedding": self._model_signature(settings, settings.embedding_model),
                "ner": self._model_signature(settings, settings.ner_model),
            }
        )
        cached_specialist = (
            previous.get("model_analysis", {}).get("specialist_enrichment", {})
            if previous
            else {}
        )
        if (
            cached_specialist.get("status") == "complete"
            and cached_specialist.get("input_fingerprint") == specialist_fingerprint
        ):
            specialist = self._reuse_specialist(
                cached_specialist, previous or {}, specialist_fingerprint
            )
            await report_progress(
                progress,
                "securebert",
                "Reused unchanged SecureBERT enrichment",
                (
                    "The deterministic evidence, local specialist profiles, and managed Context "
                    "revision are unchanged, so no new inference was needed."
                ),
                progress=76,
                status="complete",
                metrics={"roles_reused": len(specialist.get("passes", []))},
            )
        else:
            specialist = await self._specialist_enrichment(compact, settings, progress)
            specialist["input_fingerprint"] = specialist_fingerprint
            specialist["reused"] = False
            for item in specialist.get("passes", []):
                item["input_fingerprint"] = specialist_fingerprint
                item["reused"] = False
        for index, match in enumerate(specialist.get("context_matches", []), 1):
            evidence_map[f"C{index}"] = (
                f"Context: {match.get('title', 'artifact')} / {match.get('source', 'local')} — "
                f"{match.get('excerpt', '')[:320]}"
            )
        compact["evidence_map"] = evidence_map
        compact["securebert_enrichment"] = {
            "entities": specialist.get("entities", [])[:30],
            "context_matches": specialist.get("context_matches", [])[:6],
        }

        general_fingerprint = self._fingerprint(
            {
                "contract": "environment-synthesis-v2",
                "deterministic": blueprint["fingerprints"]["deterministic"],
                "specialists": specialist_fingerprint,
                "profile": self._model_signature(settings, settings.default_chat_model),
            }
        )
        general_pass = await self._run_discovery_model_pass(
            role="environment-synthesis",
            profile_id=settings.default_chat_model,
            schema=GeneralDiscoverySynthesis,
            system_prompt=(
                "You are SignalRoom's local Splunk environment analyst. Compress the supplied "
                "deterministic inventory into a factual environment synthesis. Use only supplied "
                "evidence, preserve uncertainty, distinguish collection failures from real gaps, "
                "and give the security reviewer focused questions. Do not make risk, incident, "
                "compliance, or attacker claims. Return no more than eight material observations "
                "and five review questions. Return only the requested JSON structure."
            ),
            payload=compact,
            progress=progress,
            progress_value=78,
            keep_alive=0,
            max_output_tokens=700,
            input_fingerprint=general_fingerprint,
            cached_pass=self._previous_pass(previous, "environment-synthesis"),
            cache_source=previous,
        )
        general_output = general_pass.get("output", {})
        security_payload = self._security_assessment_payload(compact, general_output)
        security_fingerprint = self._fingerprint(
            {
                "contract": "security-assessment-v2",
                "deterministic": blueprint["fingerprints"]["deterministic"],
                "general": general_fingerprint,
                "profile": self._model_signature(settings, settings.security_reasoning_model),
            }
        )
        security_pass = await self._run_discovery_model_pass(
            role="security-assessment",
            profile_id=settings.security_reasoning_model,
            schema=SecurityDiscoveryAssessment,
            system_prompt=(
                "You are SignalRoom's local senior cybersecurity architect. Assess security "
                "relevance from deterministic Splunk discovery and the bounded environment "
                "synthesis. Cite evidence_map keys exactly. Do not invent incidents, fields, "
                "telemetry, ownership, compliance conclusions, or adversary activity. Treat risk "
                "statements as hypotheses and propose only bounded read-only validation. Return "
                "only the requested JSON structure. Rank and return at most three priorities, "
                "two hypotheses, and two detection opportunities; prefer fewer, stronger, "
                "evidence-linked items. Keep the executive summary under 100 words, titles under "
                "12 words, and every explanatory or validation field under 45 words."
            ),
            payload=security_payload,
            progress=progress,
            progress_value=86,
            keep_alive="15m",
            max_output_tokens=1200,
            input_fingerprint=security_fingerprint,
            cached_pass=self._previous_pass(previous, "security-assessment"),
            cache_source=previous,
        )
        reconciliation = self._reconcile_model_team(
            blueprint,
            evidence_map,
            general_pass,
            security_pass,
        )
        passes = [general_pass, security_pass]
        successful = sum(item.get("status") == "complete" for item in passes)
        specialist_successful = sum(
            item.get("status") == "complete" for item in specialist.get("passes", [])
        )
        total_roles = len(passes) + len(specialist.get("passes", []))
        roles_reused = sum(
            bool(item.get("reused"))
            for item in [*passes, *specialist.get("passes", [])]
            if item.get("status") == "complete"
        )
        status = (
            "complete"
            if successful == len(passes) and specialist.get("status") == "complete"
            else "partial"
            if successful or specialist_successful
            else "unavailable"
        )
        await report_progress(
            progress,
            "reconciliation",
            "Local model-team reconciliation complete",
            (
                f"Completed {successful + specialist_successful} of {total_roles} specialist roles "
                f"({roles_reused} reused); "
                f"linked {reconciliation['linked_priorities']} priorities to deterministic evidence."
            ),
            progress=93,
            status="complete",
            metrics={
                "roles_complete": successful + specialist_successful,
                "roles_total": total_roles,
                "roles_reused": roles_reused,
                "roles_executed": successful + specialist_successful - roles_reused,
                "linked_priorities": reconciliation["linked_priorities"],
                "hosted_calls": 0,
            },
        )
        security_output = security_pass.get("output", {})
        general_summary = general_output.get("environment_summary", "")
        return {
            "status": status,
            "strategy": "local-role-based",
            "provider": "local",
            "executive_summary": security_output.get("executive_summary") or general_summary,
            "priorities": reconciliation["priorities"],
            "caveats": reconciliation["caveats"],
            "general_synthesis": general_output,
            "security_assessment": security_output,
            "specialist_enrichment": specialist,
            "passes": passes,
            "reconciliation": reconciliation,
            "evidence_map": evidence_map,
            "models_used": successful + specialist_successful,
            "roles_reused": roles_reused,
            "roles_executed": successful + specialist_successful - roles_reused,
            "network_inference": False,
        }

    @classmethod
    def _discovery_fingerprints(cls, blueprint: dict[str, Any]) -> dict[str, str]:
        posture = blueprint.get("security_posture", {})
        telemetry = posture.get("telemetry", {})
        detections = posture.get("detections", {})
        data_models = posture.get("data_models", {})
        inventory = blueprint.get("inventory", {})
        sections: dict[str, Any] = {
            "inventory": {
                "overview": {
                    key: blueprint.get("overview", {}).get(key)
                    for key in (
                        "splunk_version",
                        "license_state",
                        "indexes",
                        "sourcetypes",
                        "hosts",
                        "sources",
                    )
                },
                "indexes": sorted(cls._item_names(inventory.get("indexes", []))),
                "sourcetypes": sorted(cls._item_names(inventory.get("sourcetypes", []))),
                "hosts": sorted(cls._item_names(inventory.get("hosts", []))),
                "sources": sorted(cls._item_names(inventory.get("sources", []))),
            },
            "telemetry": {
                "catalogued_sourcetypes": telemetry.get("catalogued_sourcetypes"),
                "domains": telemetry.get("domains", {}),
                "coverage_score": telemetry.get("coverage_score"),
                "activity_profiled": telemetry.get("activity_profiled"),
                "stale_sourcetypes": sorted(
                    str(item.get("sourcetype") or "")
                    for item in telemetry.get("stale_over_24h", [])
                    if isinstance(item, dict)
                ),
            },
            "detections": {
                key: value
                for key, value in detections.items()
                if key
                in {
                    "total",
                    "enabled",
                    "disabled",
                    "disabled_names",
                    "scheduled",
                    "missing_time_bounds_count",
                    "missing_time_bounds",
                    "broad_searches_count",
                    "broad_searches",
                    "scheduled_without_actions_count",
                    "scheduled_without_actions",
                    "apps",
                    "catalog",
                }
            },
            "data_models": data_models,
            "knowledge": {
                name: cls._canonical_knowledge(items)
                for name, items in inventory.get("knowledge_objects", {}).items()
            },
            "findings": blueprint.get("findings", []),
            "changes": blueprint.get("changes", {}),
            "collection": {
                "complete": blueprint.get("collection_status", {}).get("complete"),
                "failed_tools": blueprint.get("collection_status", {}).get("failed_tools", []),
                "pagination": blueprint.get("collection_status", {}).get("pagination", {}),
            },
        }
        fingerprints = {name: cls._fingerprint(value) for name, value in sections.items()}
        fingerprints["deterministic"] = cls._fingerprint(
            {
                "contract": "deterministic-discovery-v1",
                "depth": blueprint.get("depth"),
                "sections": fingerprints,
            }
        )
        return fingerprints

    @staticmethod
    def _validation_candidates(
        findings: list[dict[str, Any]], run_id: str
    ) -> list[dict[str, Any]]:
        templates = {
            "telemetry-coverage": {
                "title": "Validate · Observed telemetry by index and sourcetype",
                "spl": (
                    "| tstats count where earliest=-24h by index sourcetype "
                    "| sort - count | head 100"
                ),
                "earliest_time": "-24h",
            },
            "telemetry-health": {
                "title": "Validate · Stale sourcetypes over seven days",
                "spl": (
                    "| tstats latest(_time) as last_seen count where earliest=-7d by index "
                    "sourcetype | eval age_hours=round((now()-last_seen)/3600,1) "
                    "| where age_hours>24 | sort - age_hours | head 100"
                ),
                "earliest_time": "-7d",
            },
            "detection-health": {
                "title": "Validate · Scheduled-search execution coverage",
                "rationale": (
                    "Use allowed scheduler telemetry to observe which saved searches actually ran "
                    "in the last 24 hours. This compensating check does not prove why a detection "
                    "is disabled; complete that ownership decision from the discovery catalog."
                ),
                "spl": (
                    "search index=_internal source=*scheduler.log* earliest=-24h "
                    "| stats count latest(_time) as last_run values(status) as statuses "
                    "by savedsearch_name | eval last_run=strftime(last_run,\"%Y-%m-%d "
                    "%H:%M:%S %Z\") | sort last_run | head 100"
                ),
                "earliest_time": "-24h",
            },
            "detection-quality": {
                "title": "Validate · Scheduled-search runtime and failures",
                "rationale": (
                    "Measure observed scheduler runtime and non-success outcomes over 24 hours. "
                    "Configuration scope and time-bound concerns still require review in the "
                    "discovery catalog."
                ),
                "spl": (
                    "search index=_internal source=*scheduler.log* earliest=-24h "
                    "| stats count avg(run_time) as avg_run_seconds "
                    "max(run_time) as max_run_seconds "
                    'count(eval(status!="success")) as non_success by savedsearch_name '
                    "| eval avg_run_seconds=round(avg_run_seconds,2), "
                    "max_run_seconds=round(max_run_seconds,2) "
                    "| sort - max_run_seconds | head 100"
                ),
                "earliest_time": "-24h",
            },
            "cim-readiness": {
                "title": "Validate · Data-model acceleration activity",
                "rationale": (
                    "Look for observed acceleration or data-model scheduler activity over seven "
                    "days. Absence is evidence to investigate, not proof that every data model is "
                    "disabled."
                ),
                "spl": (
                    "search index=_internal source=*scheduler.log* earliest=-7d "
                    "(savedsearch_name=*Acceleration* OR savedsearch_name=*datamodel*) "
                    "| stats count latest(_time) as last_run values(status) as statuses "
                    "by savedsearch_name | eval last_run=strftime(last_run,\"%Y-%m-%d "
                    "%H:%M:%S %Z\") | sort last_run | head 100"
                ),
                "earliest_time": "-7d",
            },
            "posture": {
                "title": "Validate · Current telemetry posture",
                "spl": "| tstats count where earliest=-24h by index sourcetype | head 100",
                "earliest_time": "-24h",
            },
        }
        candidates = []
        for index, finding in enumerate(findings, 1):
            template = templates.get(finding.get("domain"), templates["posture"])
            evidence_ref = f"D{index}"
            candidates.append(
                {
                    "id": evidence_ref,
                    "title": template["title"],
                    "rationale": (
                        f"{finding['evidence']} "
                        f"{template.get('rationale') or finding['next_step']}"
                    ),
                    "spl": template["spl"],
                    "earliest_time": template["earliest_time"],
                    "latest_time": "now",
                    "row_limit": 100,
                    "evidence_refs": [evidence_ref],
                    "source_run_id": run_id,
                    "source_finding_ref": evidence_ref,
                }
            )
        return candidates

    @classmethod
    def _canonical_knowledge(cls, items: Any) -> Any:
        volatile = {
            "next_scheduled_time",
            "published",
            "updated",
            "modtime",
            "last_success_time",
            "last_run_time",
        }
        if not isinstance(items, list):
            return items
        return [
            {
                str(key): value
                for key, value in item.items()
                if str(key).lower() not in volatile
            }
            if isinstance(item, dict)
            else item
            for item in items
        ]

    @classmethod
    def _fingerprint(cls, value: Any) -> str:
        canonical = cls._stable_value(value)
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    @classmethod
    def _stable_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): cls._stable_value(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, list):
            normalized = [cls._stable_value(item) for item in value]
            return sorted(
                normalized,
                key=lambda item: json.dumps(item, sort_keys=True, default=str),
            )
        return value

    def _context_revision(self) -> str:
        artifacts = [
            {
                "id": item.id,
                "kind": item.kind,
                "updated_at": item.updated_at,
            }
            for item in self.evidence.list(limit=1000)
            if not item.kind.startswith("discovery")
        ]
        return self._fingerprint(artifacts)

    @staticmethod
    def _model_signature(settings: Any, profile_id: str) -> dict[str, Any]:
        profile = next((item for item in settings.models if item.id == profile_id), None)
        if profile is None:
            return {"id": profile_id, "available": False}
        return {
            "id": profile.id,
            "provider": profile.provider,
            "model": profile.model,
            "task": profile.task,
            "endpoint": profile.endpoint,
            "enabled": profile.enabled,
        }

    @staticmethod
    def _previous_pass(
        previous: dict[str, Any] | None, role: str
    ) -> dict[str, Any] | None:
        if not previous:
            return None
        return next(
            (
                item
                for item in previous.get("model_analysis", {}).get("passes", [])
                if item.get("role") == role
            ),
            None,
        )

    @staticmethod
    def _reuse_specialist(
        cached: dict[str, Any], previous: dict[str, Any], input_fingerprint: str
    ) -> dict[str, Any]:
        source = {
            "cache_source_run_id": previous.get("run_id", ""),
            "cache_source_generated_at": previous.get("generated_at", ""),
        }
        return {
            **cached,
            **source,
            "input_fingerprint": input_fingerprint,
            "reused": True,
            "passes": [
                {
                    **item,
                    **source,
                    "duration_seconds": 0.0,
                    "input_fingerprint": input_fingerprint,
                    "reused": True,
                }
                for item in cached.get("passes", [])
            ],
        }

    async def _run_discovery_model_pass(
        self,
        *,
        role: str,
        profile_id: str,
        schema: type[BaseModel],
        system_prompt: str,
        payload: dict[str, Any],
        progress: ProgressCallback | None,
        progress_value: int,
        keep_alive: str | int,
        max_output_tokens: int,
        input_fingerprint: str = "",
        cached_pass: dict[str, Any] | None = None,
        cache_source: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        assert self.config is not None and self.router is not None
        profile = next(
            (
                item
                for item in self.config.load().models
                if item.id == profile_id and item.enabled and item.provider == "ollama"
            ),
            None,
        )
        if profile is None:
            return {
                "role": role,
                "status": "unavailable",
                "profile": profile_id,
                "reason": "The configured local Ollama profile is unavailable.",
            }
        if (
            cached_pass
            and cached_pass.get("status") == "complete"
            and cached_pass.get("input_fingerprint") == input_fingerprint
            and cached_pass.get("profile") == profile.id
        ):
            reused = {
                **cached_pass,
                "duration_seconds": 0.0,
                "input_fingerprint": input_fingerprint,
                "reused": True,
                "cache_source_run_id": (cache_source or {}).get("run_id", ""),
                "cache_source_generated_at": (cache_source or {}).get("generated_at", ""),
            }
            await report_progress(
                progress,
                f"model:{role}",
                f"Reused unchanged {profile.label} result",
                (
                    "The normalized evidence contract and configured model signature match the "
                    "last completed pass; no new Ollama generation was needed."
                ),
                progress=progress_value + 5,
                status="complete",
                metrics={"profile": profile.id, "reused": True, "seconds": 0},
            )
            return reused
        await report_progress(
            progress,
            f"model:{role}",
            f"Running local {role.replace('-', ' ')} · {profile.label}",
            (
                "Ollama is processing a bounded evidence contract. Model switching is serialized "
                "to avoid local accelerator contention."
            ),
            progress=progress_value,
            metrics={"provider": "ollama", "profile": profile.id, "role": role},
        )
        started = datetime.now(UTC)
        generation_schema = self._ollama_generation_schema(schema.model_json_schema())
        contract = json.dumps(generation_schema, separators=(",", ":"))
        payload_json = self._bounded_model_payload(payload)
        messages = [
            {
                "role": "system",
                "content": (
                    f"{system_prompt}\n\nOUTPUT CONTRACT: {contract}\n"
                    "Populate every required field. Use empty arrays for optional collections "
                    "when evidence is absent. Required strings must be concise and non-empty."
                ),
            },
            {"role": "user", "content": payload_json},
        ]
        attempts: list[dict[str, Any]] = []
        try:
            provider = self.router.provider(profile.id)
            result: dict[str, Any] = {}
            parsed: BaseModel | None = None
            response_format: dict[str, Any] | str = generation_schema
            for attempt in range(1, 3):
                mode = "schema" if isinstance(response_format, dict) else "json"
                try:
                    result = await provider.structured_chat(
                        messages,
                        response_format,
                        keep_alive=keep_alive,
                        max_output_tokens=max_output_tokens,
                    )
                except Exception as exc:
                    attempts.append(
                        {
                            "attempt": attempt,
                            "mode": mode,
                            "status": "provider-error",
                            "reason": str(exc)[:800],
                        }
                    )
                    if attempt == 2:
                        raise
                    await report_progress(
                        progress,
                        f"model:{role}:repair",
                        f"Retrying {profile.label} with JSON fallback",
                        (
                            "The local schema grammar was rejected by the model runner. "
                            "SignalRoom is retrying in JSON mode and will enforce the same "
                            "contract locally before accepting the result."
                        ),
                        progress=progress_value + 2,
                        metrics={"profile": profile.id, "attempt": 2, "mode": "json"},
                    )
                    response_format = "json"
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "The schema-mode request failed. Return one JSON object matching "
                                "the OUTPUT CONTRACT exactly; do not omit required fields."
                            ),
                        }
                    )
                    continue
                content = str(result.get("content") or "")
                try:
                    parsed = schema.model_validate(self._json_object(content))
                except (ValidationError, ValueError) as exc:
                    attempts.append(
                        {
                            "attempt": attempt,
                            "mode": mode,
                            "status": "validation-error",
                            "reason": str(exc)[:1200],
                        }
                    )
                    if attempt == 2:
                        raise
                    await report_progress(
                        progress,
                        f"model:{role}:repair",
                        f"Repairing {profile.label}'s structured result",
                        (
                            "The first local response did not satisfy SignalRoom's strict "
                            "discovery contract. A single bounded repair pass is running."
                        ),
                        progress=progress_value + 2,
                        metrics={"profile": profile.id, "attempt": 2, "mode": "schema-repair"},
                    )
                    messages.extend(
                        [
                            {"role": "assistant", "content": content[:8000]},
                            {
                                "role": "user",
                                "content": (
                                    "Repair the prior JSON. Validation errors follow:\n"
                                    f"{str(exc)[:1600]}\n"
                                    "Return only the complete corrected JSON object matching the "
                                    "OUTPUT CONTRACT."
                                ),
                            },
                        ]
                    )
                    continue
                attempts.append(
                    {"attempt": attempt, "mode": mode, "status": "accepted"}
                )
                break
            if parsed is None:
                raise ValueError("The local model did not produce a valid discovery contract")
            raw = result.get("raw") if isinstance(result.get("raw"), dict) else {}
            response = {
                "role": role,
                "status": "complete",
                "provider": "ollama",
                "profile": profile.id,
                "label": profile.label,
                "model": result.get("model", profile.model),
                "duration_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
                "structured_mode": attempts[-1]["mode"],
                "attempt_count": len(attempts),
                "attempts": attempts,
                "input_chars": len(payload_json),
                "output_token_limit": max_output_tokens,
                "input_fingerprint": input_fingerprint,
                "reused": False,
                "metrics": self._ollama_metrics(raw),
                "activation": result.get("activation", {}),
                "output": parsed.model_dump(mode="json"),
            }
            await report_progress(
                progress,
                f"model:{role}",
                f"{profile.label} completed {role.replace('-', ' ')}",
                (
                    f"Produced schema-validated local output in "
                    f"{response['duration_seconds']:.1f}s across {len(attempts)} attempt(s)."
                ),
                progress=progress_value + 5,
                status="complete",
                metrics={
                    "profile": profile.id,
                    "seconds": response["duration_seconds"],
                    "output_tokens": response["metrics"].get("output_tokens", 0),
                    "attempts": len(attempts),
                    "structured_mode": response["structured_mode"],
                    "input_chars": len(payload_json),
                    "output_token_limit": max_output_tokens,
                },
            )
            return response
        except Exception as exc:
            return {
                "role": role,
                "status": "error",
                "provider": "ollama",
                "profile": profile.id,
                "label": profile.label,
                "duration_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
                "reason": str(exc),
                "attempt_count": len(attempts),
                "attempts": attempts,
                "input_chars": len(payload_json),
                "output_token_limit": max_output_tokens,
                "input_fingerprint": input_fingerprint,
                "reused": False,
            }

    @staticmethod
    def _bounded_model_payload(payload: dict[str, Any], limit: int = 24000) -> str:
        """Return valid, progressively compacted JSON instead of slicing it mid-document."""

        def cap(value: Any, list_limit: int, string_limit: int, dict_limit: int) -> Any:
            if isinstance(value, str):
                return value if len(value) <= string_limit else f"{value[:string_limit]}…"
            if isinstance(value, list):
                return [cap(item, list_limit, string_limit, dict_limit) for item in value[:list_limit]]
            if isinstance(value, dict):
                return {
                    str(key): cap(item, list_limit, string_limit, dict_limit)
                    for key, item in list(value.items())[:dict_limit]
                }
            return value

        compacted: Any = payload
        for list_limit, string_limit, dict_limit in (
            (24, 1600, 80),
            (16, 1000, 60),
            (12, 700, 44),
            (8, 480, 32),
        ):
            serialized = json.dumps(compacted, default=str, separators=(",", ":"))
            if len(serialized) <= limit:
                return serialized
            compacted = cap(payload, list_limit, string_limit, dict_limit)
        serialized = json.dumps(compacted, default=str, separators=(",", ":"))
        if len(serialized) <= limit:
            return serialized
        emergency = {
            "compaction_notice": "The source packet exceeded the local model input budget.",
            "bounded_payload": cap(payload, 4, 280, 20),
        }
        return json.dumps(emergency, default=str, separators=(",", ":"))

    @staticmethod
    def _security_assessment_payload(
        compact: dict[str, Any], general_output: dict[str, Any]
    ) -> dict[str, Any]:
        """Build a non-duplicative, evidence-addressable packet for Foundation-Sec."""
        detections = compact.get("detections", {})
        telemetry = compact.get("telemetry", {})
        knowledge = compact.get("knowledge_summary", {})
        specialists = compact.get("securebert_enrichment", {})
        return {
            "deterministic_discovery": {
                "depth": compact.get("depth"),
                "overview": compact.get("overview", {}),
                "telemetry": {
                    "coverage_score": telemetry.get("coverage_score"),
                    "domains": telemetry.get("domains", {}),
                    "activity_profiled": telemetry.get("activity_profiled"),
                    "stale_over_24h": telemetry.get("stale_over_24h", [])[:10],
                },
                "detection_posture": {
                    key: value[:8] if isinstance(value, list) else value
                    for key, value in detections.items()
                },
                "data_models": compact.get("data_models", {}),
                "findings": compact.get("findings", []),
                "detection_review_sample": [
                    {
                        key: item.get(key)
                        for key in (
                            "evidence_ref",
                            "name",
                            "app",
                            "disabled",
                            "earliest",
                            "latest",
                            "review_flags",
                        )
                    }
                    for item in compact.get("detection_sample", [])[:8]
                ],
                "knowledge_summary": {
                    name: {
                        "count": value.get("count", 0),
                        "sample": value.get("sample", [])[:5],
                    }
                    for name, value in knowledge.items()
                    if isinstance(value, dict)
                },
                "change_summary": compact.get("change_summary", []),
                "collection_status": compact.get("collection_status", {}),
                "evidence_map": compact.get("evidence_map", {}),
                "securebert_entities": specialists.get("entities", [])[:12],
            },
            "environment_synthesis": general_output,
            "instructions": (
                "Every priority, hypothesis, and detection opportunity must cite one or more "
                "keys from evidence_map. Put uncited interpretations in caveats."
            ),
        }

    @staticmethod
    def _ollama_generation_schema(schema: dict[str, Any]) -> dict[str, Any]:
        """Flatten Pydantic's schema into the stable subset Ollama needs for generation.

        Length and item-count constraints remain enforced by Pydantic after generation. Keeping
        those validation-only keywords out of Ollama's grammar avoids runner failures observed
        with otherwise valid nested discovery contracts.
        """
        definitions = schema.get("$defs", {})
        validation_only = {
            "$defs",
            "default",
            "description",
            "maxItems",
            "maxLength",
            "minItems",
            "minLength",
            "title",
        }

        def simplify(value: Any, *, property_map: bool = False) -> Any:
            if isinstance(value, dict):
                reference = value.get("$ref")
                if isinstance(reference, str):
                    name = reference.rsplit("/", 1)[-1]
                    target = definitions.get(name)
                    if isinstance(target, dict):
                        return simplify(target)
                result = {
                    key: simplify(item, property_map=key == "properties")
                    for key, item in value.items()
                    if property_map or (key not in validation_only and key != "$ref")
                }
                if result.get("type") == "object":
                    result["additionalProperties"] = False
                return result
            if isinstance(value, list):
                return [simplify(item) for item in value]
            return value

        simplified = simplify(schema)
        return simplified if isinstance(simplified, dict) else {"type": "object"}

    async def _specialist_enrichment(
        self,
        compact: dict[str, Any],
        settings: Any,
        progress: ProgressCallback | None,
    ) -> dict[str, Any]:
        if settings.specialist_runtime != "local" or not self.config or not self.router:
            return {
                "status": "unavailable",
                "reason": "Discovery specialists require the local Transformers runtime.",
                "entities": [],
                "context_matches": [],
                "passes": [],
            }
        await report_progress(
            progress,
            "securebert",
            "Running local SecureBERT enrichment",
            (
                "Entity extraction and semantic correlation are running against bounded discovery "
                "evidence. No hosted inference is permitted in this stage."
            ),
            progress=71,
            metrics={"roles": 2, "provider": "local-transformers"},
        )
        ner_text = json.dumps(
            {
                "findings": compact.get("findings", []),
                "detections": compact.get("detection_sample", []),
                "knowledge": compact.get("knowledge_summary", {}),
            },
            default=str,
        )[:12000]
        correlation_query = " ".join(
            [
                *(item.get("title", "") for item in compact.get("findings", [])),
                *(item.get("evidence", "") for item in compact.get("findings", [])),
                *(compact.get("change_summary", []) or []),
            ]
        )[:5000]
        ner_result, retrieval_result = await asyncio.gather(
            self._discovery_entities(settings.ner_model, ner_text),
            self._discovery_context_matches(settings.embedding_model, correlation_query),
        )
        passes = [ner_result["pass"], retrieval_result["pass"]]
        complete = sum(item.get("status") == "complete" for item in passes)
        status = "complete" if complete == len(passes) else "partial" if complete else "unavailable"
        await report_progress(
            progress,
            "securebert",
            "SecureBERT enrichment complete",
            (
                f"Extracted {len(ner_result['entities'])} security entities and correlated "
                f"{len(retrieval_result['matches'])} distinct local artifacts."
            ),
            progress=76,
            status="complete",
            metrics={
                "entities": len(ner_result["entities"]),
                "context_matches": len(retrieval_result["matches"]),
                "hosted_calls": 0,
            },
        )
        return {
            "status": status,
            "provider": "local-transformers",
            "entities": ner_result["entities"],
            "context_matches": retrieval_result["matches"],
            "passes": passes,
            "network_inference": False,
        }

    async def _discovery_entities(
        self, profile_id: str, text: str
    ) -> dict[str, Any]:
        assert self.config is not None and self.router is not None
        started = datetime.now(UTC)
        if not local_model_installed(self.config.local_model_path(profile_id)):
            return {
                "entities": [],
                "pass": {
                    "role": "security-entity-extraction",
                    "status": "unavailable",
                    "profile": profile_id,
                    "reason": "The local NER profile is not installed.",
                },
            }
        try:
            values: list[dict[str, Any]] = []
            provider = self.router.provider(profile_id)
            for chunk in self._text_chunks(text, 2800)[:4]:
                values.extend(await provider.entities(chunk))
            entities = self._normalize_discovery_entities(values)
            return {
                "entities": entities,
                "pass": {
                    "role": "security-entity-extraction",
                    "status": "complete",
                    "provider": "local-transformers",
                    "profile": profile_id,
                    "duration_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
                    "result_count": len(entities),
                },
            }
        except Exception as exc:
            return {
                "entities": [],
                "pass": {
                    "role": "security-entity-extraction",
                    "status": "error",
                    "profile": profile_id,
                    "reason": str(exc),
                },
            }

    async def _discovery_context_matches(
        self, profile_id: str, query: str
    ) -> dict[str, Any]:
        assert self.config is not None and self.router is not None
        started = datetime.now(UTC)
        if not query or not local_model_installed(self.config.local_model_path(profile_id)):
            return {
                "matches": [],
                "pass": {
                    "role": "historical-context-correlation",
                    "status": "unavailable",
                    "profile": profile_id,
                    "reason": "The local embedding profile or correlation query is unavailable.",
                },
            }
        try:
            provider = self.router.provider(profile_id)
            pending = self.evidence.pending_embeddings(profile_id, limit=64)
            query_encoder = getattr(provider, "query_embedding", None)
            document_encoder = getattr(provider, "document_embeddings", None)
            if callable(query_encoder) and callable(document_encoder):
                query_vector, document_vectors = await asyncio.gather(
                    query_encoder(query),
                    document_encoder([content for _, content in pending]),
                )
            else:
                vectors = await provider.embeddings(
                    [query, *(content for _, content in pending)]
                )
                query_vector, document_vectors = vectors[0], vectors[1:]
            if pending:
                self.evidence.save_embeddings(
                    profile_id,
                    [
                        (chunk_id, vector)
                        for (chunk_id, _), vector in zip(
                            pending, document_vectors, strict=False
                        )
                        if vector
                    ],
                )
            candidates = self.evidence.semantic_search(query_vector, profile_id, limit=16)
            settings = self.config.load()
            reranker_id = settings.reranker_model
            reranked = False
            if (
                settings.specialist_runtime == "local"
                and reranker_id
                and local_model_installed(self.config.local_model_path(reranker_id))
            ):
                try:
                    reranker = self.router.provider(reranker_id)
                    scores = await reranker.rerank(
                        query, [candidate.excerpt for candidate in candidates]
                    )
                    if len(scores) == len(candidates):
                        for candidate, score in zip(candidates, scores, strict=True):
                            candidate.score = round(float(score), 4)
                        candidates.sort(key=lambda candidate: candidate.score, reverse=True)
                        reranked = True
                except Exception:
                    reranked = False
            matches = []
            seen_artifacts = set()
            for item in candidates:
                artifact_id = item.id.split(":", 1)[0]
                if artifact_id in seen_artifacts:
                    continue
                seen_artifacts.add(artifact_id)
                matches.append(item.model_dump(mode="json"))
                if len(matches) >= 6:
                    break
            return {
                "matches": matches,
                "pass": {
                    "role": "historical-context-correlation",
                    "status": "complete",
                    "provider": "local-transformers",
                    "profile": profile_id,
                    "reranker_profile": reranker_id if reranked else "",
                    "duration_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
                    "result_count": len(matches),
                },
            }
        except Exception as exc:
            return {
                "matches": [],
                "pass": {
                    "role": "historical-context-correlation",
                    "status": "error",
                    "profile": profile_id,
                    "reason": str(exc),
                },
            }

    @staticmethod
    def _evidence_map(blueprint: dict[str, Any]) -> dict[str, str]:
        posture = blueprint["security_posture"]
        telemetry = posture["telemetry"]
        detections = posture["detections"]
        data_models = posture["data_models"]
        references = {
            f"D{index}": (
                f"Deterministic finding [{finding['severity']}]: {finding['title']} — "
                f"{finding['evidence']}"
            )
            for index, finding in enumerate(blueprint["findings"], 1)
        }
        references.update(
            {
                "P1": (
                    f"Telemetry coverage is {telemetry['coverage_score']}%; "
                    f"{len(telemetry['stale_over_24h'])} sourcetypes are stale over 24 hours."
                ),
                "P2": (
                    f"Detections: {detections['total']} total, {detections['enabled']} enabled, "
                    f"{detections['disabled']} disabled, "
                    f"{detections['missing_time_bounds_count']} missing time bounds."
                ),
                "P3": (
                    f"Data models: {data_models['total']} total, "
                    f"{data_models['enabled']} enabled, "
                    f"{data_models['accelerated']} accelerated."
                ),
                "P4": (
                    f"Collection: {blueprint['collection_status']['successful_calls']} successful "
                    f"and {blueprint['collection_status']['failed_calls']} failed read-only calls."
                ),
            }
        )
        sample_limit = 18 if blueprint["depth"] == "deep" else 10
        for index, item in enumerate(
            DiscoveryPipeline._ranked_detection_sample(detections, sample_limit), 1
        ):
            flags = DiscoveryPipeline._detection_review_flags(item, detections)
            references[f"K{index}"] = (
                f"Detection {item['name']} in app {item['app'] or 'unknown'}; "
                f"review_flags={','.join(flags) or 'sampled'}; "
                f"disabled={item['disabled']}; earliest={item['earliest'] or 'unset'}; "
                f"latest={item['latest'] or 'unset'}; SPL={item['search'][:160]}"
            )
        changes = blueprint.get("changes", {})
        if changes.get("baseline_available"):
            references["B1"] = "Changes since the previous baseline: " + "; ".join(
                DiscoveryPipeline._change_statements(changes)
            )
        return references

    @staticmethod
    def _compact_blueprint(
        blueprint: dict[str, Any], evidence_map: dict[str, str]
    ) -> dict[str, Any]:
        posture = blueprint["security_posture"]
        detections = posture["detections"]
        data_models = posture["data_models"]
        telemetry = posture["telemetry"]
        sample_limit = 18 if blueprint["depth"] == "deep" else 10
        detail_limit = 20 if blueprint["depth"] == "deep" else 12
        stale_limit = 35 if blueprint["depth"] == "deep" else 20
        knowledge_limit = 15 if blueprint["depth"] == "deep" else 10
        knowledge = blueprint["inventory"].get("knowledge_objects", {})
        detection_sample = []
        for index, item in enumerate(
            DiscoveryPipeline._ranked_detection_sample(detections, sample_limit), 1
        ):
            detection_sample.append(
                {
                    "evidence_ref": f"K{index}",
                    "name": item["name"],
                    "app": item["app"],
                    "disabled": item["disabled"],
                    "schedule": item["schedule"],
                    "earliest": item["earliest"],
                    "latest": item["latest"],
                    "actions": item["actions"],
                    "review_flags": DiscoveryPipeline._detection_review_flags(
                        item, detections
                    ),
                    "search_preview": item["search"][:160],
                }
            )
        return {
            "depth": blueprint["depth"],
            "overview": blueprint["overview"],
            "telemetry": {
                "coverage_score": telemetry["coverage_score"],
                "domains": telemetry["domains"],
                "activity_profiled": telemetry["activity_profiled"],
                "stale_over_24h": telemetry["stale_over_24h"][:stale_limit],
            },
            "detections": {
                key: value[:detail_limit] if isinstance(value, list) else value
                for key, value in detections.items()
                if key != "catalog"
            },
            "data_models": {
                key: value for key, value in data_models.items() if key != "catalog"
            },
            "findings": [
                {"evidence_ref": f"D{index}", **finding}
                for index, finding in enumerate(blueprint["findings"], 1)
            ],
            "detection_sample": detection_sample,
            "knowledge_summary": {
                name: {
                    "count": len(items),
                    "sample": [
                        str(item.get("name") or item.get("title") or item.get("value") or "")
                        for item in items[:knowledge_limit]
                        if isinstance(item, dict)
                    ],
                }
                for name, items in knowledge.items()
            },
            "change_summary": DiscoveryPipeline._change_statements(
                blueprint.get("changes", {})
            ),
            "collection_status": blueprint["collection_status"],
            "evidence_map": evidence_map,
        }

    @staticmethod
    def _ranked_detection_sample(
        detections: dict[str, Any], limit: int
    ) -> list[dict[str, Any]]:
        catalog = [item for item in detections.get("catalog", []) if isinstance(item, dict)]
        indexed = list(enumerate(catalog))
        indexed.sort(
            key=lambda pair: (
                -len(DiscoveryPipeline._detection_review_flags(pair[1], detections)),
                -int(bool(pair[1].get("disabled"))),
                pair[0],
            )
        )
        return [item for _, item in indexed[:limit]]

    @staticmethod
    def _detection_review_flags(
        item: dict[str, Any], detections: dict[str, Any]
    ) -> list[str]:
        name = str(item.get("name") or "")

        def names(key: str) -> set[str]:
            values = detections.get(key, [])
            return {
                str(value.get("name") or value.get("title") or "")
                if isinstance(value, dict)
                else str(value)
                for value in values
            }

        flags = []
        if bool(item.get("disabled")) or name in names("disabled_names"):
            flags.append("disabled")
        if name in names("missing_time_bounds"):
            flags.append("missing-time-bounds")
        if name in names("broad_searches"):
            flags.append("broad-search")
        if name in names("scheduled_without_actions"):
            flags.append("scheduled-without-actions")
        return flags

    @staticmethod
    def _change_statements(changes: dict[str, Any]) -> list[str]:
        if not changes.get("baseline_available"):
            return ["No previous discovery baseline is available."]
        statements = []
        for category, values in changes.get("inventory", {}).items():
            added, removed = values.get("added", []), values.get("removed", [])
            if added or removed:
                statements.append(
                    f"{category}: {len(added)} added ({', '.join(added[:10]) or 'none'}); "
                    f"{len(removed)} removed ({', '.join(removed[:10]) or 'none'})"
                )
        for domain, values in changes.get("coverage", {}).items():
            statements.append(f"{domain} coverage changed from {values['from']} to {values['to']}")
        return statements or ["No inventory or coverage changes were detected."]

    @staticmethod
    def _reconcile_model_team(
        blueprint: dict[str, Any],
        evidence_map: dict[str, str],
        general_pass: dict[str, Any],
        security_pass: dict[str, Any],
    ) -> dict[str, Any]:
        security = security_pass.get("output", {})
        known_refs = set(evidence_map)
        caveats = [
            *general_pass.get("output", {}).get("caveats", []),
            *security.get("caveats", []),
        ]
        priorities = []
        invalid_reference_count = 0
        source_priorities = security.get("priorities", [])
        if not source_priorities:
            source_priorities = [
                {
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "why": finding["evidence"],
                    "owner": "Unassigned",
                    "next_step": finding["next_step"],
                    "evidence_refs": [f"D{index}"],
                }
                for index, finding in enumerate(blueprint["findings"][:8], 1)
            ]
        for item in source_priorities[:8]:
            requested_refs = [str(value) for value in item.get("evidence_refs", [])]
            valid_refs = [value for value in requested_refs if value in known_refs]
            invalid_refs = [value for value in requested_refs if value not in known_refs]
            invalid_reference_count += len(invalid_refs)
            priorities.append(
                {
                    **item,
                    "evidence_refs": valid_refs,
                    "invalid_evidence_refs": invalid_refs,
                    "validation_status": (
                        "evidence-linked" if valid_refs else "needs-validation"
                    ),
                }
            )
        tracks = []
        hypotheses = []
        rejected_hypotheses = 0
        for item in security.get("risk_hypotheses", [])[:8]:
            refs = [str(value) for value in item.get("evidence_refs", []) if value in known_refs]
            value = {
                **item,
                "evidence_refs": refs,
                "validation_status": "evidence-linked" if refs else "needs-validation",
            }
            hypotheses.append(value)
            if not refs:
                rejected_hypotheses += 1
                continue
            tracks.append(
                {
                    "hypothesis": item["title"],
                    "why": item["basis"],
                    "validation": item["validation"],
                    "status": "open",
                    "source": "Foundation-Sec model-assisted",
                    "confidence": item.get("confidence", "low"),
                    "evidence_refs": refs,
                }
            )
        opportunities = []
        for item in security.get("detection_opportunities", [])[:8]:
            refs = [str(value) for value in item.get("evidence_refs", []) if value in known_refs]
            opportunities.append(
                {
                    **item,
                    "evidence_refs": refs,
                    "validation_status": "evidence-linked" if refs else "needs-validation",
                }
            )
        if invalid_reference_count:
            caveats.append(
                f"The deterministic reconciler rejected {invalid_reference_count} unknown model "
                "evidence reference(s)."
            )
        if rejected_hypotheses:
            caveats.append(
                f"{rejected_hypotheses} model hypothesis/hypotheses lacked deterministic evidence "
                "links and were not promoted into investigation tracks."
            )
        return {
            "status": "complete",
            "known_evidence_refs": len(known_refs),
            "linked_priorities": sum(
                item["validation_status"] == "evidence-linked" for item in priorities
            ),
            "priorities": priorities,
            "risk_hypotheses": hypotheses,
            "detection_opportunities": opportunities,
            "investigation_tracks": tracks,
            "invalid_reference_count": invalid_reference_count,
            "rejected_hypotheses": rejected_hypotheses,
            "caveats": list(dict.fromkeys(str(value) for value in caveats if value)),
        }

    @staticmethod
    def _normalize_discovery_entities(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        recognized_indicator = re.compile(
            r"(?i)^(?:CVE-\d{4}-\d{4,}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|"
            r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{32,64}|"
            r"(?:[a-z0-9-]+\.)+[a-z]{2,63}|https?://\S+)$"
        )
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for item in values:
            value = re.sub(r"\s*##", "", str(item.get("word") or "")).strip(" \"'[]{}(),")
            entity_type = str(item.get("entity_group") or item.get("entity") or "entity").lower()
            score = float(item.get("score") or 0)
            if (
                len(value) < 4
                or score < 0.55
                or value.lower() in {"none", "null", "splunk", "unknown"}
                or any(marker in value for marker in ("\\", '"', "{", "}", "[", "]", ","))
            ):
                continue
            if entity_type in {"entity", "indicator", "ioc"} and not recognized_indicator.fullmatch(
                value
            ):
                continue
            key = (entity_type, value.lower())
            candidate = {
                "value": value[:240],
                "type": entity_type,
                "confidence": round(score, 3),
                "source": "local-transformers",
            }
            if key not in merged or candidate["confidence"] > merged[key]["confidence"]:
                merged[key] = candidate
        return sorted(merged.values(), key=lambda item: item["confidence"], reverse=True)[:40]

    @staticmethod
    def _text_chunks(text: str, size: int) -> list[str]:
        normalized = re.sub(r"\s+", " ", text).strip()
        chunks = []
        start = 0
        while start < len(normalized):
            end = min(len(normalized), start + size)
            if end < len(normalized):
                word_end = normalized.rfind(" ", start, end)
                end = word_end if word_end > start else end
            chunks.append(normalized[start:end])
            start = end + 1
        return chunks

    @staticmethod
    def _ollama_metrics(raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "input_tokens": int(raw.get("prompt_eval_count") or 0),
            "output_tokens": int(raw.get("eval_count") or 0),
            "load_seconds": round(float(raw.get("load_duration") or 0) / 1_000_000_000, 3),
            "generation_seconds": round(
                float(raw.get("eval_duration") or 0) / 1_000_000_000, 3
            ),
            "total_seconds": round(
                float(raw.get("total_duration") or 0) / 1_000_000_000, 3
            ),
        }

    @staticmethod
    def _merge_tracks(
        deterministic: list[dict[str, Any]], model_assisted: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        merged = list(deterministic)
        titles = {str(item.get("hypothesis", "")).strip().lower() for item in merged}
        for item in model_assisted:
            title = str(item.get("hypothesis", "")).strip().lower()
            if title and title not in titles:
                titles.add(title)
                merged.append(item)
        return merged

    async def _collect_knowledge(
        self, object_type: str, progress: ProgressCallback | None
    ) -> tuple[list[dict[str, Any]], dict[str, Any], Any]:
        """Collect the MCP's bounded response and page it locally for transparent processing."""
        await report_progress(
            progress,
            f"knowledge:{object_type}",
            f"Reading {object_type.replace('_', ' ')}",
            f"Requesting up to {self.KNOWLEDGE_ROW_LIMIT:,} objects from Splunk MCP.",
            progress=34,
        )
        raw_result = await self._safe_call(
            "get_knowledge_objects",
            {"type": object_type, "row_limit": self.KNOWLEDGE_ROW_LIMIT},
        )
        items = self._as_list(raw_result)
        pages = max(1, math.ceil(len(items) / self.KNOWLEDGE_PAGE_SIZE))
        for page_number in range(1, pages + 1):
            collected = min(page_number * self.KNOWLEDGE_PAGE_SIZE, len(items))
            await report_progress(
                progress,
                f"knowledge:{object_type}",
                f"Processed {object_type.replace('_', ' ')} · page {page_number}/{pages}",
                f"{collected:,} of {len(items):,} returned objects normalized for analysis.",
                progress=42,
                metrics={
                    "object_type": object_type,
                    "page": page_number,
                    "pages": pages,
                    "collected": collected,
                },
            )
        possibly_capped = len(items) >= self.KNOWLEDGE_ROW_LIMIT
        page_info = {
            "returned": len(items),
            "local_page_size": self.KNOWLEDGE_PAGE_SIZE,
            "local_pages": pages,
            "server_row_limit": self.KNOWLEDGE_ROW_LIMIT,
            "server_cursor_supported": False,
            "possibly_capped": possibly_capped,
            "status": "server-limit-reached" if possibly_capped else "complete-within-response",
        }
        await report_progress(
            progress,
            f"knowledge:{object_type}",
            f"{object_type.replace('_', ' ').title()} ready",
            (
                f"{len(items):,} objects returned; the MCP limit was reached, so additional "
                "server-side rows may exist."
                if possibly_capped
                else f"{len(items):,} objects returned and normalized."
            ),
            progress=50,
            status="complete",
            metrics={"object_type": object_type, "returned": len(items), "possibly_capped": possibly_capped},
        )
        return items, page_info, raw_result

    @staticmethod
    def _json_object(content: str) -> dict[str, Any]:
        cleaned = content.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start >= 0 and end > start:
            value = json.loads(cleaned[start : end + 1])
            if isinstance(value, dict):
                return value
        raise ValueError("The local model did not return a JSON discovery assessment")

    def _index_knowledge(self, blueprint: dict[str, Any]) -> list[str]:
        if blueprint["depth"] == "quick":
            return []
        for artifact in self.evidence.list(limit=500):
            if artifact.kind == "discovery-knowledge":
                self.evidence.delete(artifact.id)
        posture = blueprint["security_posture"]
        telemetry = posture["telemetry"]
        detection = posture["detections"]
        generated = blueprint["generated_at"]
        documents = [
            ArtifactCreate(
                title="Latest Splunk telemetry and coverage catalog",
                kind="discovery-knowledge",
                source="Splunk discovery knowledge",
                tags=["splunk", "discovery", "telemetry", "latest"],
                content=self._telemetry_document(blueprint, telemetry),
            ),
            ArtifactCreate(
                title="Latest Splunk detection and data-model catalog",
                kind="discovery-knowledge",
                source="Splunk discovery knowledge",
                tags=["splunk", "discovery", "detections", "cim", "latest"],
                content=self._detection_document(detection, posture["data_models"]),
            ),
            ArtifactCreate(
                title="Latest Splunk security posture assessment",
                kind="discovery-knowledge",
                source="Splunk discovery knowledge",
                tags=["splunk", "discovery", "posture", "latest"],
                content=self._posture_document(blueprint),
            ),
        ]
        return [
            self.evidence.add(
                document, metadata={"run_id": blueprint["run_id"], "generated_at": generated}
            ).id
            for document in documents
        ]

    @staticmethod
    def _telemetry_document(blueprint: dict[str, Any], telemetry: dict[str, Any]) -> str:
        inventory = blueprint["inventory"]
        lines = [
            "# Latest Splunk telemetry and coverage catalog",
            f"Generated: {blueprint['generated_at']}",
            f"Indexes ({len(inventory['indexes'])}): "
            f"{', '.join(DiscoveryPipeline._item_names(inventory['indexes']))}",
            f"Sourcetypes ({len(inventory['sourcetypes'])}): "
            f"{', '.join(DiscoveryPipeline._item_names(inventory['sourcetypes']))}",
            f"Hosts: {len(inventory['hosts'])}; Sources: {len(inventory['sources'])}",
            f"Coverage score: {telemetry['coverage_score']}%",
            "## Security domains",
        ]
        for name, value in telemetry["domains"].items():
            lines.append(
                f"- {name}: {value['status']}; sourcetypes: {', '.join(value['sourcetypes']) or 'none'}"
            )
        lines.append("## Telemetry older than 24 hours")
        lines.extend(
            f"- {item['sourcetype']}: {item['age_hours']} hours; {item['total_count']} events"
            for item in telemetry["stale_over_24h"][:100]
        )
        return "\n".join(lines)

    @staticmethod
    def _detection_document(detection: dict[str, Any], models: dict[str, Any]) -> str:
        lines = [
            "# Latest Splunk detection and data-model catalog",
            f"Detections: {detection['total']} total; {detection['enabled']} enabled; "
            f"{detection['disabled']} disabled; {detection['scheduled']} scheduled.",
            f"Data models: {models['total']} total; {models['enabled']} enabled; "
            f"{models['accelerated']} accelerated.",
            "## Detections",
        ]
        for item in detection["catalog"]:
            lines.append(
                f"- {item['name']} | app={item['app'] or 'unknown'} | disabled={item['disabled']} | "
                f"schedule={item['schedule'] or 'none'} | earliest={item['earliest'] or 'unset'} | "
                f"latest={item['latest'] or 'unset'} | actions={item['actions'] or 'none'} | "
                f"SPL={item['search']}"
            )
        lines.append("## Data models")
        lines.extend(
            f"- {item['name']} | app={item['app'] or 'unknown'} | "
            f"disabled={item['disabled']} | acceleration={item['acceleration'] or 'not reported'}"
            for item in models["catalog"]
        )
        return "\n".join(lines)

    @staticmethod
    def _posture_document(blueprint: dict[str, Any]) -> str:
        lines = ["# Latest Splunk security posture assessment", f"Generated: {blueprint['generated_at']}"]
        model = blueprint.get("model_analysis", {})
        if model.get("executive_summary"):
            lines.extend(["## Reconciled local model-team assessment", str(model["executive_summary"])])
            lines.append("## Model-team provenance")
            for item in [
                *model.get("specialist_enrichment", {}).get("passes", []),
                *model.get("passes", []),
            ]:
                lines.append(
                    f"- {item.get('role', 'specialist')}: {item.get('status', 'unknown')} via "
                    f"{item.get('profile', item.get('provider', 'local'))}"
                )
        lines.append("## Deterministic findings")
        for finding in blueprint["findings"]:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['title']}",
                    f"Domain: {finding['domain']}; confidence: {finding['confidence']}",
                    finding["evidence"],
                    f"Next: {finding['next_step']}",
                ]
            )
        return "\n".join(lines)

    @staticmethod
    def _read_blueprint(path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    @classmethod
    def _compare(cls, previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
        if not previous:
            return {"baseline_available": False, "inventory": {}, "coverage": {}}
        changes: dict[str, Any] = {}
        for key in ("indexes", "sourcetypes", "hosts", "sources"):
            before = cls._item_names(previous.get("inventory", {}).get(key, []))
            after = cls._item_names(current.get("inventory", {}).get(key, []))
            changes[key] = {"added": sorted(after - before), "removed": sorted(before - after)}
        previous_domains = previous.get("coverage", {}).get("domains", {})
        current_domains = current.get("coverage", {}).get("domains", {})
        coverage = {
            name: {"from": bool(previous_domains.get(name)), "to": bool(value)}
            for name, value in current_domains.items()
            if bool(previous_domains.get(name)) != bool(value)
        }
        return {"baseline_available": True, "inventory": changes, "coverage": coverage}

    @staticmethod
    def _item_names(items: Any) -> set[str]:
        if not isinstance(items, list):
            return set()
        return {
            str(item.get("title") or item.get("name") or item.get("value", ""))
            for item in items
            if isinstance(item, dict) and (item.get("title") or item.get("name") or item.get("value"))
        }

    @staticmethod
    def _collection_status(results: dict[str, Any]) -> dict[str, Any]:
        errors = {
            name: str(result["error"])
            for name, result in results.items()
            if isinstance(result, dict) and result.get("error")
        }
        return {
            "complete": not errors,
            "successful_calls": len(results) - len(errors),
            "failed_calls": len(errors),
            "errors": errors,
        }

    async def _safe_call(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            return await self.client.call(name, arguments)
        except Exception as exc:
            return {"error": str(exc)}

    @staticmethod
    def _as_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item if isinstance(item, dict) else {"value": item} for item in value]
        if isinstance(value, dict):
            for key in ("results", "items", "indexes", "data"):
                if isinstance(value.get(key), list):
                    return [item if isinstance(item, dict) else {"value": item} for item in value[key]]
        return []

    @staticmethod
    def _value(value: Any, key: str, default: Any = None) -> Any:
        if isinstance(value, dict):
            if key in value:
                return value[key]
            results = value.get("results")
            if isinstance(results, list) and results and isinstance(results[0], dict):
                return results[0].get(key, default)
        return default

    @staticmethod
    def _number(item: Any, key: str) -> float:
        try:
            return float(item.get(key, 0)) if isinstance(item, dict) else 0
        except (TypeError, ValueError):
            return 0

    def _findings(
        self, indexes: list[dict[str, Any]], sourcetypes: list[dict[str, Any]], hosts: list[dict[str, Any]]
    ) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        names = {
            str(item.get("title") or item.get("name") or item.get("value", "")).lower() for item in indexes
        }
        security_names = {"security", "notable", "risk", "threat", "endpoint", "network"}
        if not names & security_names:
            findings.append(
                {
                    "severity": "medium",
                    "domain": "data-architecture",
                    "title": "No explicit security index detected",
                    "evidence": f"Observed indexes: {', '.join(sorted(names)) or 'none'}",
                    "next_step": "Confirm where security telemetry and notable events are retained.",
                }
            )
        if len(sourcetypes) < 4:
            findings.append(
                {
                    "severity": "medium",
                    "domain": "telemetry-coverage",
                    "title": "Narrow sourcetype coverage",
                    "evidence": f"Only {len(sourcetypes)} sourcetypes were returned.",
                    "next_step": (
                        "Validate endpoint, identity, network, cloud, and email telemetry onboarding."
                    ),
                }
            )
        if not hosts:
            findings.append(
                {
                    "severity": "high",
                    "domain": "data-quality",
                    "title": "No host metadata returned",
                    "evidence": "Host metadata inventory was empty.",
                    "next_step": "Check host field extraction, forwarder health, and metadata permissions.",
                }
            )
        largest = sorted(indexes, key=lambda item: self._number(item, "currentDBSizeMB"), reverse=True)[:1]
        if largest:
            title = largest[0].get("title") or largest[0].get("name") or "unknown"
            findings.append(
                {
                    "severity": "info",
                    "domain": "capacity",
                    "title": f"Largest index: {title}",
                    "evidence": f"{self._number(largest[0], 'currentDBSizeMB'):,.0f} MB currently reported.",
                    "next_step": (
                        "Compare retention, ingestion rate, and detection value for this data source."
                    ),
                }
            )
        return findings

    @staticmethod
    def _coverage(sourcetypes: list[dict[str, Any]]) -> dict[str, Any]:
        text = " ".join(str(item).lower() for item in sourcetypes)
        domains = {
            "identity": ["wineventlog", "okta", "azure:aad", "authentication"],
            "endpoint": ["crowdstrike", "sysmon", "defender", "edr"],
            "network": ["pan:", "firewall", "zeek", "suricata", "dns"],
            "cloud": ["cloudtrail", "aws:", "azure:", "gcp:"],
            "email": ["o365", "exchange", "proofpoint", "mimecast"],
        }
        present = {domain: any(term in text for term in terms) for domain, terms in domains.items()}
        return {"domains": present, "score": round(sum(present.values()) / len(present) * 100)}

    @staticmethod
    def _tracks(findings: list[dict[str, str]]) -> list[dict[str, str]]:
        tracks = []
        for finding in findings:
            if finding["severity"] == "info":
                continue
            tracks.append(
                {
                    "hypothesis": finding["title"],
                    "why": finding["evidence"],
                    "validation": finding["next_step"],
                    "status": "open",
                }
            )
        return tracks

    @staticmethod
    def _markdown(blueprint: dict[str, Any]) -> str:
        overview = blueprint["overview"]
        lines = [
            "# Splunk Security Discovery Brief",
            "",
            f"Run: `{blueprint['run_id']}`",
            "",
            "## Environment",
            "",
            f"- Splunk version: {overview['splunk_version']}",
            f"- Indexes: {overview['indexes']}",
            f"- Sourcetypes: {overview['sourcetypes']}",
            f"- Hosts: {overview['hosts']}",
            f"- Estimated indexed size: {overview['data_size_mb']:,.0f} MB",
            "",
            "## Coverage",
            "",
            f"Coverage score: **{blueprint['coverage']['score']}%**",
            "",
        ]
        for domain, present in blueprint["coverage"]["domains"].items():
            lines.append(f"- {domain.title()}: {'observed' if present else 'gap to validate'}")
        posture = blueprint.get("security_posture", {})
        detections = posture.get("detections", {})
        models = posture.get("data_models", {})
        telemetry = posture.get("telemetry", {})
        lines.extend(
            [
                "",
                "## Security posture",
                "",
                f"- Telemetry profiled: {telemetry.get('activity_profiled', 0)} sourcetypes; "
                f"{len(telemetry.get('stale_over_24h', []))} stale over 24 hours",
                f"- Detections: {detections.get('total', 0)} total; "
                f"{detections.get('enabled', 0)} enabled; {detections.get('disabled', 0)} disabled",
                f"- Detection scope review: {detections.get('missing_time_bounds_count', 0)} "
                f"missing time bounds; {detections.get('broad_searches_count', 0)} broad searches",
                f"- Data models: {models.get('total', 0)} total; "
                f"{models.get('accelerated', 0)} accelerated",
                "",
            ]
        )
        model_analysis = blueprint.get("model_analysis", {})
        if model_analysis.get("status") in {"complete", "partial"}:
            model_passes = [
                *model_analysis.get("specialist_enrichment", {}).get("passes", []),
                *model_analysis.get("passes", []),
            ]
            lines.extend(
                [
                    "## Reconciled local model-team assessment",
                    "",
                    f"Strategy: {model_analysis.get('strategy', 'local-role-based')}",
                    "",
                    str(model_analysis.get("executive_summary") or ""),
                    "",
                    "### Specialist provenance",
                    "",
                    *[
                        f"- {item.get('role', 'specialist')}: {item.get('status', 'unknown')} via "
                        f"{item.get('profile', item.get('provider', 'local'))}"
                        for item in model_passes
                    ],
                    "",
                ]
            )
            priorities = model_analysis.get("priorities", [])
            if priorities:
                lines.extend(["### Evidence-linked priorities", ""])
                for item in priorities:
                    refs = ", ".join(item.get("evidence_refs", [])) or "needs validation"
                    lines.append(
                        f"- [{str(item.get('severity', 'medium')).upper()}] "
                        f"{item.get('title', 'Priority')} ({refs}): {item.get('next_step', 'Validate')}"
                    )
                lines.append("")
        lines.extend(["", "## Findings", ""])
        for finding in blueprint["findings"]:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['title']}",
                    "",
                    finding["evidence"],
                    "",
                    f"Next: {finding['next_step']}",
                    "",
                ]
            )
        changes = blueprint.get("changes", {})
        if changes.get("baseline_available"):
            lines.extend(["## Changes since previous discovery", ""])
            changed = False
            for category, values in changes.get("inventory", {}).items():
                added = values.get("added", [])
                removed = values.get("removed", [])
                if added or removed:
                    changed = True
                    lines.append(f"- {category.title()}: +{len(added)} added, -{len(removed)} removed")
            for domain, values in changes.get("coverage", {}).items():
                changed = True
                lines.append(f"- {domain.title()} coverage: {values['from']} → {values['to']}")
            if not changed:
                lines.append("- No inventory or coverage changes detected.")
            lines.append("")
        collection = blueprint.get("collection_status", {})
        if collection.get("failed_calls"):
            lines.extend(
                [
                    "## Collection limitations",
                    "",
                    f"- {collection['failed_calls']} read-only MCP call(s) failed; "
                    "inspect collection_status.",
                    "",
                ]
            )
        lines.extend(
            [
                "## Evidence provenance",
                "",
                "Inventory was collected through configured read-only Splunk MCP tools.",
            ]
        )
        return "\n".join(lines)
