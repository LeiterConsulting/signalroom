from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from .guardrails import validate_read_only_spl

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,159}$")
PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]{1,63}>")
INDEX_REFERENCE = re.compile(
    r"(?i)(?:^|[\s(])index\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z0-9_.:-]+))"
)
SOURCETYPE_REFERENCE = re.compile(
    r"(?i)(?:^|[\s(])sourcetype\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z0-9_.:-]+))"
)
FIELD_COMPARISON = re.compile(
    r"(?i)(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]{0,159})\s*(?:=|!=|<=|>=|<|>)"
)

BUILTIN_FIELDS = {
    "_bkt",
    "_cd",
    "_indextime",
    "_raw",
    "_si",
    "_time",
    "host",
    "index",
    "linecount",
    "punct",
    "source",
    "sourcetype",
    "splunk_server",
}
RESERVED_WORDS = {
    "and",
    "as",
    "by",
    "count",
    "dc",
    "dedup",
    "eval",
    "eventstats",
    "false",
    "fields",
    "from",
    "head",
    "in",
    "index",
    "like",
    "max",
    "metadata",
    "min",
    "not",
    "null",
    "or",
    "rename",
    "search",
    "sort",
    "sourcetype",
    "stats",
    "sum",
    "table",
    "timechart",
    "true",
    "values",
    "where",
}


class SplContextFilter(BaseModel):
    field: str = Field(min_length=1, max_length=160)
    operator: Literal["=", "!=", "<", "<=", ">", ">=", "contains", "in", "exists"] = "="
    value: str | int | float | bool | list[str | int | float | bool] | None = None

    @model_validator(mode="after")
    def value_matches_operator(self) -> SplContextFilter:
        if self.operator == "exists":
            return self
        if self.operator == "in" and not isinstance(self.value, list):
            raise ValueError("The 'in' operator requires a list value")
        if self.operator == "in" and not self.value:
            raise ValueError("The 'in' operator requires at least one value")
        if self.value is None:
            raise ValueError(f"The {self.operator!r} operator requires a value")
        return self


class SplContextMetric(BaseModel):
    function: Literal["count", "dc", "values", "sum", "avg", "min", "max"] = "count"
    field: str = Field(default="", max_length=160)
    alias: str = Field(default="", max_length=160)


class SplContextSort(BaseModel):
    field: str = Field(min_length=1, max_length=160)
    direction: Literal["ascending", "descending"] = "descending"


class SplSearchIntent(BaseModel):
    """A model may propose this plan; only the deterministic compiler may emit trusted SPL."""

    purpose: str = Field(min_length=1, max_length=1000)
    index: str = Field(default="", max_length=160)
    sourcetypes: list[str] = Field(default_factory=list, max_length=8)
    filters: list[SplContextFilter] = Field(default_factory=list, max_length=16)
    operation: Literal["events", "count", "aggregate", "timechart"] = "events"
    metrics: list[SplContextMetric] = Field(default_factory=list, max_length=8)
    group_by: list[str] = Field(default_factory=list, max_length=8)
    output_fields: list[str] = Field(default_factory=list, max_length=24)
    sort: SplContextSort | None = None
    span: Literal["1m", "5m", "10m", "15m", "30m", "1h", "4h", "1d"] = "5m"
    earliest_time: str = Field(default="-24h", pattern=r"^-[1-9][0-9]{0,3}[smhdw]$")
    latest_time: Literal["now"] = "now"
    limit: int = Field(default=100, ge=1, le=500)


class SplSearchPlan(BaseModel):
    """One analyst request may legitimately require several separately reviewable searches."""

    intents: list[SplSearchIntent] = Field(min_length=1, max_length=4)


class SplContextCompileRequest(BaseModel):
    intent: SplSearchIntent
    connection_alias: str = Field(default="primary", min_length=1, max_length=120)
    connection_fingerprint: str = Field(default="", max_length=64)
    tenant_scope_id: str = Field(default="workspace-primary", min_length=1, max_length=160)


class SplContextEngine:
    """Build schema-only Splunk context and deterministically compile constrained search plans."""

    CONTRACT = "signalroom.spl-context.v1"
    DATA_EXPOSURE = "schema-and-synthetic-only"

    def __init__(
        self,
        output_dir: Path | str,
        binding: dict[str, Any] | None = None,
        data_registry: Any | None = None,
    ):
        binding = binding or {}
        self.connection_alias = str(binding.get("alias") or "primary")
        self.connection_fingerprint = str(binding.get("fingerprint") or "")
        self.tenant_scope_id = str(binding.get("tenant_scope_id") or "workspace-primary")
        shared = Path(output_dir)
        self.output_dir = (
            data_registry.directory_for("discovery-files", self.tenant_scope_id)
            if data_registry
            else shared
        )
        self._snapshot_cache_key: tuple[int, int] | None = None
        self._snapshot_cache: dict[str, Any] | None = None

    def latest_path(self) -> Path:
        safe_scope = re.sub(r"[^a-zA-Z0-9_.-]+", "-", self.tenant_scope_id).strip("-")
        revision = self.connection_fingerprint[:12] or "legacy"
        return self.output_dir / f"security_blueprint_latest_{safe_scope}_{revision}.json"

    def snapshot(self) -> dict[str, Any]:
        path = self.latest_path()
        try:
            stat = path.stat()
            cache_key = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            cache_key = None
        if cache_key is not None and cache_key == self._snapshot_cache_key:
            return self._snapshot_cache or self._unavailable_snapshot("Context cache is empty.")
        blueprint, error = self._load_blueprint()
        if blueprint is None:
            return self._unavailable_snapshot(error)

        inventory = blueprint.get("inventory") if isinstance(blueprint.get("inventory"), dict) else {}
        knowledge = (
            inventory.get("knowledge_objects")
            if isinstance(inventory.get("knowledge_objects"), dict)
            else {}
        )
        indexes = self._catalog_names(inventory.get("indexes"), ("title", "name", "value"))
        sourcetypes = self._catalog_names(
            inventory.get("sourcetypes"), ("sourcetype", "value", "name", "title")
        )
        data_models = self._catalog_names(
            knowledge.get("data_models"), ("name", "title", "value")
        )
        macros = self._catalog_names(knowledge.get("macros"), ("name", "title", "value"))
        lookups = self._catalog_names(knowledge.get("lookups"), ("name", "title", "value"))
        relationships, fields = self._knowledge_graph(knowledge, indexes, sourcetypes)
        observed_fields = {item["name"].lower() for item in fields}
        fields.extend(
            {
                "name": field,
                "evidence": "splunk-builtin",
                "referenced_by": [],
            }
            for field in sorted(BUILTIN_FIELDS, key=str.lower)
            if field.lower() not in observed_fields
        )
        fields.sort(key=lambda item: item["name"].lower())
        synthetic_examples = self._synthetic_examples(indexes, sourcetypes, relationships, fields)
        safe_payload = {
            "contract": self.CONTRACT,
            "data_exposure": self.DATA_EXPOSURE,
            "connection_alias": self.connection_alias,
            "connection_fingerprint": self.connection_fingerprint,
            "tenant_scope_id": self.tenant_scope_id,
            "source_run_id": str(blueprint.get("run_id") or ""),
            "source_generated_at": str(blueprint.get("generated_at") or ""),
            "splunk_version": str((blueprint.get("overview") or {}).get("splunk_version") or "unknown"),
            "catalog": {
                "indexes": indexes,
                "sourcetypes": sourcetypes,
                "fields": fields,
                "data_models": data_models,
                "macros": macros,
                "lookups": lookups,
            },
            "relationships": relationships,
            "synthetic_examples": synthetic_examples,
            "limitations": [
                "Field names inferred from knowledge objects are references, not proof of recent values.",
                "Synthetic examples are generated from field semantics and never copy event values.",
                "Parser validation and bounded execution are separate trust stages.",
            ],
        }
        safe_payload["context_revision"] = self._fingerprint(safe_payload)
        result = {"status": "ready", **safe_payload}
        self._snapshot_cache_key = cache_key
        self._snapshot_cache = result
        return result

    def summary(self) -> dict[str, Any]:
        """Return UI readiness without transferring the potentially large schema graph."""
        snapshot = self.snapshot()
        catalog = snapshot.get("catalog") or {}
        relationships = snapshot.get("relationships") or []
        examples = snapshot.get("synthetic_examples") or []
        return {
            "status": snapshot.get("status"),
            "reason": snapshot.get("reason", ""),
            "contract": snapshot.get("contract", self.CONTRACT),
            "data_exposure": snapshot.get("data_exposure", self.DATA_EXPOSURE),
            "connection_alias": snapshot.get("connection_alias", self.connection_alias),
            "connection_fingerprint": snapshot.get(
                "connection_fingerprint", self.connection_fingerprint
            ),
            "tenant_scope_id": snapshot.get("tenant_scope_id", self.tenant_scope_id),
            "context_revision": snapshot.get("context_revision", ""),
            "source_run_id": snapshot.get("source_run_id", ""),
            "source_generated_at": snapshot.get("source_generated_at", ""),
            "splunk_version": snapshot.get("splunk_version", "unknown"),
            "catalog_counts": {
                "indexes": len(catalog.get("indexes") or []),
                "sourcetypes": len(catalog.get("sourcetypes") or []),
                "fields": len(catalog.get("fields") or []),
                "data_models": len(catalog.get("data_models") or []),
                "macros": len(catalog.get("macros") or []),
                "lookups": len(catalog.get("lookups") or []),
                "relationships": len(relationships),
                "synthetic_examples": len(examples),
            },
            "limitations": snapshot.get("limitations") or [],
        }

    def modeling_packet(
        self,
        evidence: list[Any] | None = None,
        tool_result: Any = None,
        query: str = "",
    ) -> dict[str, Any]:
        """Return a bounded packet that cannot contain raw event values or evidence excerpts."""
        snapshot = self.snapshot()
        catalog = snapshot.get("catalog") if snapshot.get("status") == "ready" else {}
        all_fields = list((catalog or {}).get("fields") or [])
        selected_fields = [
            {
                "name": item.get("name", ""),
                "evidence": item.get("evidence", "context-reference"),
                "referenced_by": list(item.get("referenced_by") or [])[:3],
            }
            for item in self._rank_context_items(query, all_fields, "name", 32)
        ]
        all_relationships = list(snapshot.get("relationships") or [])
        selected_relationships = self._rank_context_items(
            query,
            all_relationships,
            "source",
            24,
            secondary_keys=("target", "predicate"),
        )
        packet = {
            "contract": self.CONTRACT,
            "data_exposure": self.DATA_EXPOSURE,
            "status": snapshot.get("status"),
            "connection": {
                "alias": self.connection_alias,
                "fingerprint": self.connection_fingerprint,
                "tenant_scope_id": self.tenant_scope_id,
            },
            "context_revision": snapshot.get("context_revision", ""),
            "source_run_id": snapshot.get("source_run_id", ""),
            "catalog": {
                "indexes": list((catalog or {}).get("indexes") or [])[:200],
                "sourcetypes": list((catalog or {}).get("sourcetypes") or [])[:300],
                "fields": selected_fields,
                "data_models": list((catalog or {}).get("data_models") or [])[:10],
                "macros": list((catalog or {}).get("macros") or [])[:10],
                "lookups": list((catalog or {}).get("lookups") or [])[:10],
            },
            "relationships": selected_relationships,
            "synthetic_examples": [],
            "synthetic_example_policy": (
                "Event examples are intentionally omitted from model planning. Schema names and "
                "field/type shapes are sufficient; never create filter values from examples."
            ),
            "result_shape": self.profile_result_shape(tool_result),
            "evidence_provenance": [
                {
                    "id": str(getattr(item, "id", "")),
                    "kind": str(getattr(item, "kind", "context")),
                    "score": round(float(getattr(item, "score", 0) or 0), 4),
                }
                for item in (evidence or [])[:16]
            ],
            "privacy_contract": [
                "No _raw content or source event value is present.",
                "No evidence excerpt is present.",
                "Examples are deterministically synthetic and marked synthetic.",
                "This packet must never be treated as model-training consent.",
            ],
            "context_selection": {
                "query_ranked": bool(query.strip()),
                "fields_selected": len(selected_fields),
                "fields_available": len(all_fields),
                "relationships_selected": len(selected_relationships),
                "relationships_available": len(all_relationships),
            },
            "limitations": snapshot.get("limitations") or [snapshot.get("reason", "Context unavailable")],
        }
        return packet

    def compile(self, intent: SplSearchIntent) -> dict[str, Any]:
        snapshot = self.snapshot()
        checks: list[dict[str, str]] = []
        errors: list[str] = []
        warnings: list[str] = []

        if snapshot.get("status") != "ready":
            errors.append(str(snapshot.get("reason") or "No exact-scope discovery context is available."))
            checks.append(self._check("context", "blocked", errors[-1]))
            return self._compile_result(intent, "blocked", "", snapshot, checks, errors, warnings)
        checks.append(
            self._check(
                "context",
                "passed",
                f"Bound to discovery run {snapshot.get('source_run_id') or 'unknown'}.",
            )
        )

        unresolved_parameters = self._intent_placeholders(intent)
        if unresolved_parameters:
            errors.append(
                "The typed plan contains unresolved parameters: "
                + ", ".join(unresolved_parameters)
            )
            checks.append(self._check("parameter-binding", "blocked", errors[-1]))
            return self._compile_result(intent, "blocked", "", snapshot, checks, errors, warnings)
        checks.append(
            self._check(
                "parameter-binding",
                "passed",
                "Interactive literals were rebound by application code after model planning.",
            )
        )

        catalog = snapshot["catalog"]
        index = self._canonical(intent.index, catalog["indexes"])
        if not index:
            errors.append(
                f"Index {intent.index!r} is not proven by the exact-scope discovery catalog."
                if intent.index
                else "A proven index is required before SignalRoom can compile this search."
            )
        sourcetypes: list[str] = []
        for value in intent.sourcetypes:
            canonical = self._canonical(value, catalog["sourcetypes"])
            if canonical:
                sourcetypes.append(canonical)
            else:
                errors.append(f"Sourcetype {value!r} is not proven by the discovery catalog.")
        if errors:
            checks.append(self._check("dataset-identifiers", "blocked", " ".join(errors)))
            return self._compile_result(intent, "blocked", "", snapshot, checks, errors, warnings)
        checks.append(
            self._check(
                "dataset-identifiers",
                "passed",
                f"Resolved index {index!r} and {len(sourcetypes)} sourcetype constraint(s).",
            )
        )

        known_fields = {item["name"].lower(): item["name"] for item in catalog["fields"]}
        known_fields.update({name.lower(): name for name in BUILTIN_FIELDS})
        requested_fields = self._intent_fields(intent)
        unresolved_fields = sorted(
            name for name in requested_fields if name.lower() not in known_fields
        )
        if unresolved_fields:
            errors.append(
                "Fields are not proven by the current context: " + ", ".join(unresolved_fields)
            )
            checks.append(self._check("field-identifiers", "blocked", errors[-1]))
            return self._compile_result(intent, "blocked", "", snapshot, checks, errors, warnings)
        checks.append(
            self._check(
                "field-identifiers",
                "passed",
                f"Resolved {len(requested_fields)} referenced field(s) without sampled values.",
            )
        )

        try:
            spl = self._compile_spl(intent, index, sourcetypes, known_fields)
            spl = validate_read_only_spl(spl)
        except ValueError as exc:
            errors.append(str(exc))
            checks.append(self._check("deterministic-compiler", "blocked", errors[-1]))
            return self._compile_result(intent, "blocked", "", snapshot, checks, errors, warnings)
        checks.extend(
            [
                self._check(
                    "data-exposure",
                    "passed",
                    "Compilation used schema metadata; source event rows were omitted, and any "
                    "analyst-pasted samples were synthesized before planning.",
                ),
                self._check(
                    "deterministic-compiler",
                    "passed",
                    "SignalRoom emitted SPL from an allowlisted typed plan.",
                ),
                self._check("read-only-policy", "passed", "Local read-only screening passed."),
                self._check(
                    "splunk-parser",
                    "pending",
                    "The selected Splunk instance has not parsed this query yet.",
                ),
                self._check(
                    "bounded-execution",
                    "pending",
                    "Analyst approval and a bounded validation execution are still required.",
                ),
            ]
        )
        return self._compile_result(
            intent, "context-compiled", spl, snapshot, checks, errors, warnings
        )

    def assess_spl(self, spl: str) -> dict[str, Any]:
        snapshot = self.snapshot()
        checks: list[dict[str, str]] = []
        blockers: list[str] = []
        warnings: list[str] = []
        try:
            validate_read_only_spl(spl)
            checks.append(self._check("read-only-policy", "passed", "Local read-only screening passed."))
        except ValueError as exc:
            blockers.append(str(exc))
            checks.append(self._check("read-only-policy", "blocked", str(exc)))

        if PLACEHOLDER.search(spl):
            reason = "The SPL contains unresolved synthetic or parameter placeholders."
            blockers.append(reason)
            checks.append(self._check("parameter-binding", "blocked", reason))

        if snapshot.get("status") != "ready":
            warnings.append(str(snapshot.get("reason") or "Exact-scope context is unavailable."))
            checks.append(self._check("context", "pending", warnings[-1]))
            status = "blocked" if blockers else "model-proposed"
            return self._assessment(status, snapshot, checks, blockers, warnings)

        checks.append(
            self._check(
                "context",
                "passed",
                f"Compared with context revision {snapshot['context_revision'][:12]}.",
            )
        )
        index_refs = self._references(INDEX_REFERENCE, spl)
        sourcetype_refs = self._references(SOURCETYPE_REFERENCE, spl)
        unknown_indexes = self._unknown(index_refs, snapshot["catalog"]["indexes"])
        unknown_sourcetypes = self._unknown(sourcetype_refs, snapshot["catalog"]["sourcetypes"])
        if unknown_indexes:
            blockers.append("Unproven indexes: " + ", ".join(unknown_indexes))
        if unknown_sourcetypes:
            blockers.append("Unproven sourcetypes: " + ", ".join(unknown_sourcetypes))
        if not index_refs and not re.match(r"(?is)^\s*\|\s*(makeresults|metadata|rest)\b", spl):
            warnings.append("No explicit index constraint was found.")
        checks.append(
            self._check(
                "dataset-identifiers",
                "blocked" if unknown_indexes or unknown_sourcetypes else "passed",
                "All referenced indexes and sourcetypes were found in the exact-scope catalog."
                if not unknown_indexes and not unknown_sourcetypes
                else " ".join(blockers[-2:]),
            )
        )

        known_fields = {item["name"].lower() for item in snapshot["catalog"]["fields"]}
        known_fields.update(name.lower() for name in BUILTIN_FIELDS)
        field_refs = self._extract_fields(spl)
        unresolved = sorted(field for field in field_refs if field.lower() not in known_fields)
        if unresolved:
            warnings.append(
                "Fields require an exact-scope field profile: " + ", ".join(unresolved[:20])
            )
            checks.append(self._check("field-identifiers", "pending", warnings[-1]))
        else:
            checks.append(
                self._check(
                    "field-identifiers",
                    "passed",
                    f"All {len(field_refs)} detected field reference(s) are context-known.",
                )
            )
        checks.append(
            self._check(
                "data-exposure",
                "passed",
                "Assessment used schema metadata only; no raw sample was provided to a model.",
            )
        )
        status = "blocked" if blockers else "needs-context-validation" if warnings else "context-grounded"
        return self._assessment(status, snapshot, checks, blockers, warnings)

    async def plan_and_compile(self, message: str, provider: Any) -> dict[str, Any]:
        """Ask a local model for a typed plan, then reject anything the context cannot prove."""
        synthetic_request, sample_sanitization = self.sanitize_authoring_request(message)
        sanitized_request, parameters, parameter_receipt = self._parameterize_request(
            synthetic_request
        )
        sanitization = {
            **sample_sanitization,
            "parameters_replaced": parameter_receipt["parameters_replaced"],
            "parameter_types": parameter_receipt["parameter_types"],
            "model_received_parameter_values": False,
        }
        packet = self.modeling_packet(query=sanitized_request)
        if packet.get("status") != "ready":
            return {
                "status": "blocked",
                "reason": "Run standard or deep Discovery for this exact Splunk scope first.",
                "modeling_packet": packet,
            }
        schema = SplSearchPlan.model_json_schema()
        messages = [
            {
                "role": "system",
                "content": (
                    "You translate an analyst request into one to four typed, read-only Splunk "
                    "search plans. Return one JSON object with an intents array. Select index, "
                    "sourcetype, and field names exactly from the "
                    "supplied schema catalog. Never invent an identifier. Examples in the packet "
                    "are synthetic; never treat them as observed events. An empty sourcetypes list "
                    "means all discovered sourcetypes; never use '*'. Use filters only when the "
                    "request supplies the exact literal or typed parameter placeholder. Return "
                    "exactly one intent unless the analyst explicitly asks for separate searches. "
                    "For 'count by FIELD', use aggregate with a count metric and FIELD in group_by. "
                    "Do not emit SPL."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "analyst_request": sanitized_request[:12000],
                        "sample_sanitization": sanitization,
                        "spl_context": packet,
                    },
                    separators=(",", ":"),
                    default=str,
                ),
            },
        ]
        result = await provider.structured_chat(
            messages,
            schema,
            keep_alive="15m",
            max_output_tokens=1000,
        )
        try:
            plan = SplSearchPlan.model_validate(self._json_object(str(result.get("content") or "")))
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            return {
                "status": "blocked",
                "reason": f"The local model did not produce a valid typed SPL plan: {exc}",
                "model": result.get("model", ""),
                "modeling_packet": packet,
            }
        normalized_intents, normalizations = self._normalize_planned_intents(
            sanitized_request,
            plan.intents,
            packet,
        )
        bound_intents = [
            self._bind_intent_parameters(intent, parameters)
            for intent in normalized_intents
        ]
        compilations = [self.compile(intent) for intent in bound_intents]
        if normalizations:
            detail = " ".join(normalizations)[:1000]
            for compilation in compilations:
                compilation["checks"].insert(
                    1,
                    self._check("intent-normalization", "passed", detail),
                )
        ready = sum(item["status"] == "context-compiled" for item in compilations)
        status = (
            "context-compiled"
            if ready == len(compilations)
            else "partial"
            if ready
            else "blocked"
        )
        response = {
            "status": status,
            "compilations": compilations,
            "model": result.get("model", ""),
            "requested_model": result.get("requested_model", ""),
            "model_activation": result.get("activation", {}),
            "intents": [intent.model_dump(mode="json") for intent in bound_intents],
            "sample_sanitization": sanitization,
            "plan_normalizations": normalizations,
            "modeling_packet_fingerprint": self._fingerprint(packet),
        }
        if len(compilations) == 1:
            response = {**compilations[0], **response}
        return response

    @classmethod
    def sanitize_authoring_request(cls, message: str) -> tuple[str, dict[str, Any]]:
        """Replace pasted event-shaped samples while preserving the analyst's stated objective."""
        replacements = 0
        sample_fields: set[str] = set()

        def synthetic_block(match: re.Match[str]) -> str:
            nonlocal replacements
            language = (match.group("language") or "sample").strip().lower()
            body = match.group("body") or ""
            if language in {"spl", "splunk", "search"}:
                return match.group(0)
            fields = cls._sample_field_names(body)
            if not fields:
                return "[Pasted sample omitted from SPL authoring context]"
            replacements += 1
            sample_fields.update(fields)
            shape = {field: cls._synthetic_value(field) for field in fields[:40]}
            return (
                "```json\n"
                + json.dumps({"synthetic": True, "shape": shape}, sort_keys=True)
                + "\n```"
            )

        sanitized = re.sub(
            r"```(?P<language>[^\r\n`]*)\r?\n(?P<body>[\s\S]*?)```",
            synthetic_block,
            message,
        )

        def replace_inline_json(line: str) -> str:
            nonlocal replacements
            if '"synthetic": true' in line.lower() or '"synthetic":true' in line.lower():
                return line
            decoder = json.JSONDecoder()
            cursor = 0
            output: list[str] = []
            while cursor < len(line):
                start = line.find("{", cursor)
                if start < 0:
                    output.append(line[cursor:])
                    break
                output.append(line[cursor:start])
                try:
                    value, length = decoder.raw_decode(line[start:])
                except json.JSONDecodeError:
                    output.append("{")
                    cursor = start + 1
                    continue
                if not isinstance(value, dict):
                    output.append(line[start : start + length])
                    cursor = start + length
                    continue
                fields = cls._sample_field_names(json.dumps(value, default=str))
                replacements += 1
                sample_fields.update(fields)
                replacement = (
                    json.dumps(
                        {
                            "synthetic": True,
                            "shape": {
                                field: cls._synthetic_value(field) for field in fields[:40]
                            },
                        },
                        sort_keys=True,
                    )
                    if fields
                    else "[Inline JSON sample omitted from SPL authoring context]"
                )
                output.append(replacement)
                cursor = start + length
            return "".join(output)

        lines: list[str] = []
        pair_pattern = re.compile(
            r"(?P<field>[A-Za-z_][A-Za-z0-9_.:-]{0,159})="
            r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        )
        for line in sanitized.splitlines():
            marked_sample = re.match(
                r"(?i)^(?P<label>\s*(?:raw (?:event|data)|sample (?:event|data)|"
                r"event sample|example event)\s*:\s*)(?P<body>.*)$",
                line,
            )
            if marked_sample:
                fields = cls._sample_field_names(marked_sample.group("body"))
                replacements += 1
                sample_fields.update(fields)
                shape = {field: cls._synthetic_value(field) for field in fields[:40]}
                lines.append(
                    f'{marked_sample.group("label")}synthetic_shape='
                    f'{json.dumps(shape, sort_keys=True) if shape else "<OMITTED>"}'
                )
                continue
            line = replace_inline_json(line)
            pairs = list(pair_pattern.finditer(line))
            if len(pairs) < 2 or "synthetic\"" in line.lower():
                lines.append(line)
                continue
            replacements += 1
            sample_fields.update(match.group("field") for match in pairs)
            lines.append(
                pair_pattern.sub(
                    lambda match: (
                        f'{match.group("field")}="'
                        f'{cls._literal(cls._synthetic_value(match.group("field")))}"'
                    ),
                    line,
                )
            )
        return "\n".join(lines), {
            "policy": "event-shaped samples replaced with deterministic synthetic shapes",
            "sample_regions_replaced": replacements,
            "field_names_retained": sorted(sample_fields, key=str.lower)[:80],
            "sample_values_retained": False,
        }

    @classmethod
    def _parameterize_request(
        cls, value: str
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        """Keep interactive literals local while giving the planner stable typed placeholders."""
        parameters: dict[str, str] = {}
        parameter_types: dict[str, int] = {}

        patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
            ("URL", re.compile(r"(?i)\bhttps?://[^\s'\"<>]+")),
            (
                "EMAIL",
                re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
            ),
            ("HASH", re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])")),
            (
                "IPV4",
                re.compile(
                    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
                ),
            ),
        )
        sanitized = value
        for kind, pattern in patterns:
            def replace(match: re.Match[str], parameter_kind: str = kind) -> str:
                observed = match.group(0)
                if cls._is_synthetic_literal(observed):
                    return observed
                ordinal = parameter_types.get(parameter_kind, 0) + 1
                parameter_types[parameter_kind] = ordinal
                placeholder = f"<PARAM_{parameter_kind}_{ordinal}>"
                parameters[placeholder] = observed
                return placeholder

            sanitized = pattern.sub(replace, sanitized)
        return sanitized, parameters, {
            "parameters_replaced": len(parameters),
            "parameter_types": parameter_types,
            "parameter_values_retained_locally": bool(parameters),
        }

    @classmethod
    def _bind_intent_parameters(
        cls,
        intent: SplSearchIntent,
        parameters: dict[str, str],
    ) -> SplSearchIntent:
        filters: list[SplContextFilter] = []
        for item in intent.filters:
            value = item.value
            if isinstance(value, str):
                value = parameters.get(value, value)
            elif isinstance(value, list):
                value = [
                    parameters.get(entry, entry) if isinstance(entry, str) else entry
                    for entry in value
                ]
            filters.append(item.model_copy(update={"value": value}))
        return intent.model_copy(update={"filters": filters})

    @classmethod
    def _normalize_planned_intents(
        cls,
        request: str,
        intents: list[SplSearchIntent],
        packet: dict[str, Any],
    ) -> tuple[list[SplSearchIntent], list[str]]:
        """Apply request-grounded corrections before the compiler evaluates model intent."""
        normalized_request = request.lower()
        catalog = packet.get("catalog") or {}
        indexes = list(catalog.get("indexes") or [])
        field_names = [
            str(item.get("name") or "")
            for item in catalog.get("fields") or []
            if isinstance(item, dict)
        ]
        explicit_index = cls._mentioned_catalog_value(request, indexes)
        group_field = ""
        group_match = re.search(
            r"(?i)\bby\s+(?:the\s+)?([A-Za-z_][A-Za-z0-9_.:-]{0,159})\b",
            request,
        )
        if group_match:
            group_field = cls._canonical(group_match.group(1), field_names)
        wants_count = bool(re.search(r"(?i)\b(?:count|how many|number of)\b", request))
        relative_window = cls._relative_window(request)
        asks_for_multiple = bool(
            re.search(
                r"(?i)\b(?:two|three|four|multiple|separate|each)\b.{0,80}"
                r"\b(?:spl|search|searches|query|queries)\b|"
                r"\b(?:spl|search|searches|query|queries)\b.{0,80}"
                r"\b(?:two|three|four|multiple|separate|each)\b|"
                r"\b(?:sample|search|query)\b.{0,80}\band\s+(?:an?\s+)?"
                r"(?:aggregate|count|timechart|search|query)\b",
                request,
            )
        )
        notes: list[str] = []
        values: list[SplSearchIntent] = []
        for intent in intents:
            update: dict[str, Any] = {}
            if explicit_index and intent.index.lower() != explicit_index.lower():
                update["index"] = explicit_index
                notes.append("Applied the index named explicitly in the analyst request.")
            sourcetypes = [value for value in intent.sourcetypes if value != "*"]
            if sourcetypes != intent.sourcetypes:
                update["sourcetypes"] = sourcetypes
                notes.append("Replaced wildcard sourcetype with the compiler's all-sourcetypes form.")

            filters = [
                item
                for item in intent.filters
                if cls._filter_grounded_in_request(item, normalized_request)
            ]
            if filters != intent.filters:
                update["filters"] = filters
                notes.append("Removed model-proposed filter values not present in the request.")

            if wants_count and group_field:
                update.update(
                    {
                        "operation": "aggregate",
                        "metrics": [SplContextMetric(function="count", alias="event_count")],
                        "group_by": [group_field],
                        "output_fields": [],
                    }
                )
                if group_field.lower() == "sourcetype":
                    update["sourcetypes"] = []
                notes.append("Normalized 'count by field' to an aggregate count contract.")
            elif wants_count and intent.operation == "events":
                update.update({"operation": "count", "metrics": [], "group_by": []})
                notes.append("Normalized the stated count request to a count contract.")
            if relative_window and intent.earliest_time != relative_window:
                update["earliest_time"] = relative_window
                notes.append("Applied the relative time window stated in the analyst request.")
            if intent.purpose.strip().lower() in {"search", "query", "spl", "search splunk"}:
                update["purpose"] = request[:1000]
            values.append(intent.model_copy(update=update))

        deduplicated: list[SplSearchIntent] = []
        seen: set[str] = set()
        for intent in values:
            contract = intent.model_dump(mode="json", exclude={"purpose"})
            fingerprint = cls._fingerprint(contract)
            if fingerprint in seen:
                notes.append("Removed a duplicate typed intent proposed by the model.")
                continue
            seen.add(fingerprint)
            deduplicated.append(intent)
        if not asks_for_multiple and len(deduplicated) > 1:
            deduplicated = deduplicated[:1]
            notes.append("Kept one intent because the analyst did not request separate searches.")
        return deduplicated, list(dict.fromkeys(notes))

    @staticmethod
    def _filter_grounded_in_request(
        item: SplContextFilter,
        normalized_request: str,
    ) -> bool:
        if item.operator == "exists":
            return item.field.lower() in normalized_request
        values = item.value if isinstance(item.value, list) else [item.value]
        return bool(values) and all(
            str(value).lower() in normalized_request
            for value in values
            if value is not None
        )

    @staticmethod
    def _mentioned_catalog_value(request: str, catalog: list[str]) -> str:
        normalized = request.lower()
        return next(
            (
                value
                for value in sorted(catalog, key=len, reverse=True)
                if value and value.lower() in normalized
            ),
            "",
        )

    @staticmethod
    def _relative_window(request: str) -> str:
        match = re.search(
            r"(?i)\b(?:over|during|within|for)?\s*(?:the\s+)?(?:last|past)\s+"
            r"([1-9][0-9]{0,3})\s*(minute|hour|day|week)s?\b",
            request,
        )
        if not match:
            return ""
        unit = {"minute": "m", "hour": "h", "day": "d", "week": "w"}[match.group(2).lower()]
        return f"-{match.group(1)}{unit}"

    @classmethod
    def profile_result_shape(cls, value: Any) -> dict[str, Any]:
        rows = cls._rows(value)
        if not rows:
            return {
                "row_count": 0,
                "fields": [],
                "synthetic_rows": [],
                "raw_values_included": False,
            }
        field_types: dict[str, set[str]] = {}
        presence: dict[str, int] = {}
        for row in rows[:100]:
            if not isinstance(row, dict):
                continue
            for key, item in list(row.items())[:160]:
                name = str(key)[:160]
                field_types.setdefault(name, set()).add(cls._type_name(item))
                presence[name] = presence.get(name, 0) + 1
        fields = [
            {
                "name": name,
                "types": sorted(field_types[name]),
                "present_rows": presence[name],
                "classification": "raw-content-excluded" if name.lower() == "_raw" else "shape-only",
            }
            for name in sorted(field_types, key=str.lower)
        ]
        synthetic = {
            item["name"]: cls._synthetic_value(item["name"], item["types"][0])
            for item in fields[:40]
        }
        return {
            "row_count": len(rows),
            "fields": fields,
            "synthetic_rows": [{"synthetic": True, **synthetic}] if synthetic else [],
            "raw_values_included": False,
        }

    def _load_blueprint(self) -> tuple[dict[str, Any] | None, str]:
        path = self.latest_path()
        if not path.exists():
            return None, "No standard or deep discovery snapshot exists for this exact connection revision."
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"The exact-scope discovery snapshot could not be read: {exc}"
        if not isinstance(value, dict):
            return None, "The exact-scope discovery snapshot is not a JSON object."
        provenance = value.get("provenance") if isinstance(value.get("provenance"), dict) else {}
        observed = (
            str(provenance.get("connection_alias") or ""),
            str(provenance.get("connection_fingerprint") or ""),
            str(provenance.get("tenant_scope_id") or ""),
        )
        expected = (self.connection_alias, self.connection_fingerprint, self.tenant_scope_id)
        if observed != expected:
            return None, "The discovery snapshot identity does not match the active Splunk scope."
        return value, ""

    def _unavailable_snapshot(self, reason: str) -> dict[str, Any]:
        return {
            "status": "unavailable",
            "contract": self.CONTRACT,
            "data_exposure": self.DATA_EXPOSURE,
            "connection_alias": self.connection_alias,
            "connection_fingerprint": self.connection_fingerprint,
            "tenant_scope_id": self.tenant_scope_id,
            "context_revision": "",
            "reason": reason,
            "catalog": {
                "indexes": [],
                "sourcetypes": [],
                "fields": [],
                "data_models": [],
                "macros": [],
                "lookups": [],
            },
            "relationships": [],
            "synthetic_examples": [],
            "limitations": [reason],
        }

    @classmethod
    def _knowledge_graph(
        cls,
        knowledge: dict[str, Any],
        indexes: list[str],
        sourcetypes: list[str],
    ) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        relationships: dict[tuple[str, str, str], dict[str, str]] = {}
        field_sources: dict[str, set[str]] = {}
        index_lookup = {item.lower(): item for item in indexes}
        sourcetype_lookup = {item.lower(): item for item in sourcetypes}
        for kind in ("saved_searches", "alerts"):
            for item in cls._rows(knowledge.get(kind)):
                if not isinstance(item, dict):
                    continue
                name = cls._first(item, "name", "title", "value") or f"unnamed-{kind}"
                search = cls._first(item, "search", "query", "spl")
                if not search:
                    continue
                object_id = f"{kind}:{name}"
                query_indexes = [
                    index_lookup[value.lower()]
                    for value in cls._references(INDEX_REFERENCE, search)
                    if value.lower() in index_lookup
                ]
                query_sourcetypes = [
                    sourcetype_lookup[value.lower()]
                    for value in cls._references(SOURCETYPE_REFERENCE, search)
                    if value.lower() in sourcetype_lookup
                ]
                query_fields = cls._extract_fields(search)
                for index in query_indexes:
                    cls._edge(relationships, object_id, "searches-index", f"index:{index}", kind)
                for sourcetype in query_sourcetypes:
                    cls._edge(
                        relationships,
                        object_id,
                        "searches-sourcetype",
                        f"sourcetype:{sourcetype}",
                        kind,
                    )
                for index in query_indexes:
                    for sourcetype in query_sourcetypes:
                        cls._edge(
                            relationships,
                            f"index:{index}",
                            "observed-with-in-knowledge",
                            f"sourcetype:{sourcetype}",
                            kind,
                        )
                for field in query_fields:
                    field_sources.setdefault(field, set()).add(object_id)
                    cls._edge(
                        relationships,
                        object_id,
                        "references-field",
                        f"field:{field}",
                        kind,
                    )
        fields = [
            {
                "name": name,
                "evidence": "knowledge-object-reference",
                "referenced_by": sorted(sources, key=str.lower)[:20],
            }
            for name, sources in sorted(field_sources.items(), key=lambda item: item[0].lower())
        ]
        return list(relationships.values()), fields

    @classmethod
    def _synthetic_examples(
        cls,
        indexes: list[str],
        sourcetypes: list[str],
        relationships: list[dict[str, str]],
        fields: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        pairs: list[tuple[str, str]] = []
        for edge in relationships:
            if edge["predicate"] != "observed-with-in-knowledge":
                continue
            index = edge["source"].split(":", 1)[-1]
            sourcetype = edge["target"].split(":", 1)[-1]
            if (index, sourcetype) not in pairs:
                pairs.append((index, sourcetype))
        if not pairs and indexes and sourcetypes:
            pairs.append((indexes[0], sourcetypes[0]))
        field_names = [item["name"] for item in fields[:8]]
        examples: list[dict[str, Any]] = []
        for index, sourcetype in pairs[:8]:
            event = {
                "_time": "2026-01-15T12:34:56Z",
                "index": index,
                "sourcetype": sourcetype,
                "host": "workstation-023.example.invalid",
            }
            for field in field_names:
                if field not in event:
                    event[field] = cls._synthetic_value(field)
            examples.append(
                {
                    "synthetic": True,
                    "notice": "Generated shape example; no source event values were copied.",
                    "event": event,
                }
            )
        return examples

    @classmethod
    def _extract_fields(cls, search: str) -> set[str]:
        fields: set[str] = set()
        for match in FIELD_COMPARISON.finditer(search):
            cls._add_field(fields, match.group(1))
        for match in re.finditer(r"(?i)\b(?:by|table|fields)\s+([^|\r\n]+)", search):
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_.:-]*", match.group(1)):
                cls._add_field(fields, token)
        for match in re.finditer(
            r"(?i)\b(?:dc|values|sum|avg|min|max|earliest|latest)\s*\(\s*([A-Za-z_][A-Za-z0-9_.:-]*)",
            search,
        ):
            cls._add_field(fields, match.group(1))
        for match in re.finditer(r"(?i)\beval\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*=", search):
            cls._add_field(fields, match.group(1))
        return fields

    @staticmethod
    def _add_field(fields: set[str], value: str) -> None:
        normalized = value.strip()
        if (
            IDENTIFIER.fullmatch(normalized)
            and normalized.lower() not in RESERVED_WORDS
            and normalized.lower() not in {"earliest", "latest"}
        ):
            fields.add(normalized)

    @classmethod
    def _intent_fields(cls, intent: SplSearchIntent) -> set[str]:
        fields = {item.field for item in intent.filters}
        fields.update(intent.group_by)
        fields.update(intent.output_fields)
        if intent.sort:
            fields.add(intent.sort.field)
        for metric in intent.metrics:
            if metric.field:
                fields.add(metric.field)
        return {field for field in fields if field}

    @classmethod
    def _compile_spl(
        cls,
        intent: SplSearchIntent,
        index: str,
        sourcetypes: list[str],
        known_fields: dict[str, str],
    ) -> str:
        parts = [
            f'search index="{cls._literal(index)}"',
            f"earliest={intent.earliest_time}",
            f"latest={intent.latest_time}",
        ]
        if len(sourcetypes) == 1:
            parts.append(f'sourcetype="{cls._literal(sourcetypes[0])}"')
        elif sourcetypes:
            terms = " OR ".join(
                f'sourcetype="{cls._literal(value)}"' for value in sourcetypes
            )
            parts.append(f"({terms})")
        for item in intent.filters:
            field = known_fields[item.field.lower()]
            parts.append(cls._filter_term(field, item.operator, item.value))
        query = " ".join(parts)

        if intent.operation == "count":
            query += " | stats count AS event_count"
        elif intent.operation in {"aggregate", "timechart"}:
            metrics = intent.metrics or [SplContextMetric(function="count", alias="event_count")]
            metric_spl = " ".join(cls._metric(item, known_fields) for item in metrics)
            group_by = [known_fields[field.lower()] for field in intent.group_by]
            if intent.operation == "timechart":
                query += f" | timechart span={intent.span} {metric_spl}"
                if group_by:
                    query += " BY " + ", ".join(group_by)
            else:
                query += f" | stats {metric_spl}"
                if group_by:
                    query += " BY " + ", ".join(group_by)
        elif intent.output_fields:
            output = [known_fields[field.lower()] for field in intent.output_fields]
            query += " | fields " + ", ".join(output)

        if intent.sort:
            field = known_fields.get(intent.sort.field.lower(), intent.sort.field)
            direction = "+" if intent.sort.direction == "ascending" else "-"
            query += f" | sort {intent.limit} {direction} {field}"
        else:
            query += f" | head {intent.limit}"
        return query

    @classmethod
    def _filter_term(cls, field: str, operator: str, value: Any) -> str:
        if operator == "exists":
            return f"{field}=*"
        if operator == "contains":
            return f'{field}="*{cls._literal(value)}*"'
        if operator == "in":
            values = value if isinstance(value, list) else []
            return "(" + " OR ".join(
                f'{field}="{cls._literal(item)}"' for item in values
            ) + ")"
        return f'{field}{operator}"{cls._literal(value)}"'

    @classmethod
    def _metric(cls, metric: SplContextMetric, known_fields: dict[str, str]) -> str:
        function = metric.function
        if function == "count" and not metric.field:
            value = "count"
        else:
            if not metric.field:
                raise ValueError(f"Metric {function!r} requires a field")
            value = f"{function}({known_fields[metric.field.lower()]})"
        alias = metric.alias.strip()
        if alias:
            if not IDENTIFIER.fullmatch(alias):
                raise ValueError(f"Metric alias {alias!r} is not a safe SPL identifier")
            value += f" AS {alias}"
        return value

    def _compile_result(
        self,
        intent: SplSearchIntent,
        status: str,
        spl: str,
        snapshot: dict[str, Any],
        checks: list[dict[str, str]],
        errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any]:
        fingerprint = hashlib.sha256(spl.encode()).hexdigest() if spl else ""
        return {
            "status": status,
            "spl": spl,
            "purpose": intent.purpose,
            "expected_result": self._expected_result(intent),
            "result_contract": self._result_contract(intent),
            "earliest_time": intent.earliest_time,
            "latest_time": intent.latest_time,
            "row_limit": intent.limit,
            "query_fingerprint": fingerprint,
            "context_revision": snapshot.get("context_revision", ""),
            "source_run_id": snapshot.get("source_run_id", ""),
            "data_exposure": self.DATA_EXPOSURE,
            "checks": checks,
            "errors": errors,
            "warnings": warnings,
            "parser_validation": "not-run",
            "execution_validation": "not-run",
            "trusted_for_execution": False,
        }

    @staticmethod
    def _expected_result(intent: SplSearchIntent) -> str:
        if intent.operation == "count":
            return "One aggregate event_count field for the approved time window."
        if intent.operation == "timechart":
            return f"A bounded {intent.span} time series matching the requested metrics."
        if intent.operation == "aggregate":
            grouping = ", ".join(intent.group_by) or "the full selected dataset"
            return f"A bounded aggregate grouped by {grouping}."
        fields = ", ".join(intent.output_fields) or "the selected event fields"
        return f"Up to {intent.limit} events containing {fields}."

    @staticmethod
    def _result_contract(intent: SplSearchIntent) -> dict[str, Any]:
        expected_fields: list[str] = []
        if intent.operation == "count":
            expected_fields = ["event_count"]
        elif intent.operation in {"aggregate", "timechart"}:
            if intent.operation == "timechart":
                expected_fields.append("_time")
            expected_fields.extend(intent.group_by)
            for metric in intent.metrics or [SplContextMetric(function="count", alias="event_count")]:
                expected_fields.append(
                    metric.alias
                    or (metric.function if not metric.field else f"{metric.function}({metric.field})")
                )
        else:
            expected_fields = list(intent.output_fields)
        return {
            "contract": "signalroom.spl-result-shape.v1",
            "operation": intent.operation,
            "expected_fields": list(dict.fromkeys(expected_fields))[:80],
            "allow_zero_rows": True,
            "source": "typed-intent-context-compiler",
        }

    @staticmethod
    def _assessment(
        status: str,
        snapshot: dict[str, Any],
        checks: list[dict[str, str]],
        blockers: list[str],
        warnings: list[str],
    ) -> dict[str, Any]:
        return {
            "status": status,
            "context_revision": snapshot.get("context_revision", ""),
            "source_run_id": snapshot.get("source_run_id", ""),
            "data_exposure": SplContextEngine.DATA_EXPOSURE,
            "checks": checks,
            "blockers": blockers,
            "warnings": warnings,
            "trusted_for_execution": False,
        }

    @staticmethod
    def _check(name: str, status: str, detail: str) -> dict[str, str]:
        return {"name": name, "status": status, "detail": detail[:1000]}

    @staticmethod
    def _literal(value: Any) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _canonical(value: str, catalog: list[str]) -> str:
        lookup = {item.lower(): item for item in catalog}
        return lookup.get(value.strip().lower(), "")

    @staticmethod
    def _unknown(values: list[str], catalog: list[str]) -> list[str]:
        known = {item.lower() for item in catalog}
        return sorted({value for value in values if value.lower() not in known}, key=str.lower)

    @staticmethod
    def _references(pattern: re.Pattern[str], value: str) -> list[str]:
        found: list[str] = []
        for match in pattern.finditer(value):
            item = next((group for group in match.groups() if group is not None), "").strip()
            if item and item not in found:
                found.append(item)
        return found

    @staticmethod
    def _catalog_names(value: Any, keys: tuple[str, ...]) -> list[str]:
        names: set[str] = set()
        for item in SplContextEngine._rows(value):
            if isinstance(item, dict):
                name = SplContextEngine._first(item, *keys)
            else:
                name = str(item).strip()
            if name:
                names.add(name[:240])
        return sorted(names, key=str.lower)

    @staticmethod
    def _rows(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for key in ("results", "items", "data"):
                if isinstance(value.get(key), list):
                    return value[key]
        return []

    @staticmethod
    def _rank_context_items(
        query: str,
        items: list[dict[str, Any]],
        primary_key: str,
        limit: int,
        *,
        secondary_keys: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        if not query.strip():
            return items[:limit]
        normalized = query.lower()
        terms = {
            term
            for term in re.findall(r"[a-z0-9_.:-]{2,}", normalized)
            if term not in RESERVED_WORDS
        }

        def score(item: dict[str, Any]) -> tuple[int, str]:
            primary = str(item.get(primary_key) or "").lower()
            related = " ".join(
                str(item.get(key) or "").lower() for key in secondary_keys
            )
            references = " ".join(
                str(value).lower() for value in item.get("referenced_by", [])
            )
            text = f"{primary} {related} {references}"
            value = 100 if primary and primary in normalized else 0
            value += sum(12 for term in terms if term == primary)
            value += sum(5 for term in terms if term in text)
            if item.get("evidence") == "splunk-builtin":
                value += 2
            return -value, primary

        return sorted(items, key=score)[:limit]

    @staticmethod
    def _sample_field_names(value: str) -> list[str]:
        fields: set[str] = set()
        for match in re.finditer(
            r"(?m)(?:^|[{,\s])['\"]?([A-Za-z_][A-Za-z0-9_.:-]{0,159})['\"]?\s*[:=]",
            value,
        ):
            field = match.group(1)
            if IDENTIFIER.fullmatch(field) and field.lower() not in RESERVED_WORDS:
                fields.add(field)
        return sorted(fields, key=str.lower)

    @staticmethod
    def _is_synthetic_literal(value: str) -> bool:
        normalized = value.lower()
        if "example.invalid" in normalized or normalized.startswith("synthetic_"):
            return True
        return normalized.startswith(("192.0.2.", "198.51.100.", "203.0.113."))

    @staticmethod
    def _intent_placeholders(intent: SplSearchIntent) -> list[str]:
        found: set[str] = set()
        for item in intent.filters:
            values = item.value if isinstance(item.value, list) else [item.value]
            for value in values:
                if isinstance(value, str):
                    found.update(PLACEHOLDER.findall(value))
        return sorted(found)

    @staticmethod
    def _first(item: dict[str, Any], *keys: str) -> str:
        for key in keys:
            value = item.get(key)
            if value not in (None, ""):
                return str(value).strip()
        return ""

    @staticmethod
    def _edge(
        edges: dict[tuple[str, str, str], dict[str, str]],
        source: str,
        predicate: str,
        target: str,
        evidence: str,
    ) -> None:
        key = (source, predicate, target)
        edges.setdefault(
            key,
            {"source": source, "predicate": predicate, "target": target, "evidence": evidence},
        )

    @staticmethod
    def _type_name(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        return "string"

    @staticmethod
    def _synthetic_value(field: str, value_type: str = "string") -> Any:
        lower = field.lower()
        if lower == "_raw":
            return "synthetic_event=true value=<SYNTHETIC_VALUE>"
        if value_type == "boolean":
            return True
        if value_type in {"integer", "number"}:
            return 7
        if lower == "_time" or lower.endswith("_time") or "timestamp" in lower:
            return "2026-01-15T12:34:56Z"
        if "email" in lower:
            return "user014@example.invalid"
        if any(term in lower for term in ("src_ip", "dest_ip", "ip_address", "clientip")):
            return "198.51.100.27"
        if "ipv6" in lower:
            return "2001:db8::27"
        if "mac" in lower and "machine" not in lower:
            return "02:00:00:00:00:27"
        if any(term in lower for term in ("host", "computer", "device")):
            return "workstation-023.example.invalid"
        if any(term in lower for term in ("domain", "fqdn", "url")):
            return "service.example.invalid"
        if any(term in lower for term in ("user", "account", "principal")):
            return "user_014"
        if any(term in lower for term in ("hash", "sha256")):
            return hashlib.sha256(f"signalroom-synthetic:{field}".encode()).hexdigest()
        if "port" in lower:
            return 443
        if any(term in lower for term in ("count", "bytes", "size")):
            return 7
        if any(term in lower for term in ("process", "command")):
            return "example-process --synthetic"
        if any(term in lower for term in ("path", "file")):
            return "/opt/example/application.bin"
        if any(term in lower for term in ("action", "status", "result")):
            return "synthetic_action"
        return f"synthetic_{re.sub(r'[^a-z0-9]+', '_', lower).strip('_') or 'value'}_01"

    @staticmethod
    def _fingerprint(value: Any) -> str:
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()

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
        raise ValueError("The local model did not return one JSON search-intent object")
