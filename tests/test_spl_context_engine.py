import json

from splunk_security_agent.schemas import EvidenceRef
from splunk_security_agent.splunk import (
    SplContextEngine,
    SplContextFilter,
    SplContextMetric,
    SplSearchIntent,
)

RAW_CANARY = "actual-customer-user-do-not-copy"


def _engine(tmp_path):
    binding = {
        "alias": "lab-002",
        "fingerprint": "b" * 64,
        "tenant_scope_id": "tenant-lab-002",
    }
    engine = SplContextEngine(tmp_path, binding)
    blueprint = {
        "schema_version": "3.0",
        "run_id": "discovery-run-002",
        "generated_at": "2026-09-05T12:00:00Z",
        "overview": {"splunk_version": "10.4.0"},
        "provenance": {
            "connection_alias": binding["alias"],
            "connection_fingerprint": binding["fingerprint"],
            "tenant_scope_id": binding["tenant_scope_id"],
        },
        "inventory": {
            "indexes": [{"title": "security"}, {"title": "authentication"}],
            "sourcetypes": [
                {"sourcetype": "XmlWinEventLog:Security"},
                {"sourcetype": "linux_secure"},
            ],
            "knowledge_objects": {
                "saved_searches": [
                    {
                        "name": "Failed logons",
                        "search": (
                            'index=security sourcetype="XmlWinEventLog:Security" '
                            f'user="{RAW_CANARY}" action=failure '
                            "| stats count by host, user"
                        ),
                    }
                ],
                "alerts": [],
                "data_models": [{"name": "Authentication"}],
                "macros": [{"name": "security_index"}],
                "lookups": [{"name": "privileged_accounts.csv"}],
            },
        },
    }
    engine.latest_path().write_text(json.dumps(blueprint), encoding="utf-8")
    return engine


def test_snapshot_is_exact_scope_schema_and_synthetic_only(tmp_path):
    engine = _engine(tmp_path)

    snapshot = engine.snapshot()
    serialized = json.dumps(snapshot)

    assert snapshot["status"] == "ready"
    assert snapshot["data_exposure"] == "schema-and-synthetic-only"
    assert snapshot["source_run_id"] == "discovery-run-002"
    assert snapshot["catalog"]["indexes"] == ["authentication", "security"]
    assert {"action", "host", "user"}.issubset(
        {item["name"] for item in snapshot["catalog"]["fields"]}
    )
    assert RAW_CANARY not in serialized
    assert "stats count by host" not in serialized
    assert snapshot["synthetic_examples"]
    assert all(item["synthetic"] for item in snapshot["synthetic_examples"])
    assert "example.invalid" in serialized

    summary = engine.summary()
    assert "catalog" not in summary
    assert summary["catalog_counts"]["indexes"] == 2
    assert summary["catalog_counts"]["sourcetypes"] == 2
    assert summary["catalog_counts"]["fields"] == len(snapshot["catalog"]["fields"])


def test_result_profile_keeps_shape_and_replaces_every_value(tmp_path):
    engine = _engine(tmp_path)
    raw_result = {
        "results": [
            {
                "_raw": f"user={RAW_CANARY} src=10.23.45.67",
                "user": RAW_CANARY,
                "src_ip": "10.23.45.67",
                "bytes": 928374,
            }
        ]
    }

    profile = engine.profile_result_shape(raw_result)
    serialized = json.dumps(profile)

    assert profile["row_count"] == 1
    assert profile["raw_values_included"] is False
    assert {item["name"] for item in profile["fields"]} == {
        "_raw",
        "bytes",
        "src_ip",
        "user",
    }
    assert RAW_CANARY not in serialized
    assert "10.23.45.67" not in serialized
    assert "928374" not in serialized
    assert "198.51.100.27" in serialized


def test_compiler_emits_bounded_spl_only_from_context_known_identifiers(tmp_path):
    engine = _engine(tmp_path)
    intent = SplSearchIntent(
        purpose="Count failed authentications by host",
        index="security",
        sourcetypes=["XmlWinEventLog:Security"],
        filters=[SplContextFilter(field="action", value="failure")],
        operation="aggregate",
        metrics=[SplContextMetric(function="count", alias="event_count")],
        group_by=["host"],
        sort={"field": "host", "direction": "ascending"},
        earliest_time="-4h",
        limit=50,
    )

    result = engine.compile(intent)

    assert result["status"] == "context-compiled"
    assert result["trusted_for_execution"] is False
    assert result["data_exposure"] == "schema-and-synthetic-only"
    assert result["spl"] == (
        'search index="security" earliest=-4h latest=now '
        'sourcetype="XmlWinEventLog:Security" action="failure" '
        "| stats count AS event_count BY host | sort 50 + host"
    )
    checks = {item["name"]: item["status"] for item in result["checks"]}
    assert checks["deterministic-compiler"] == "passed"
    assert checks["splunk-parser"] == "pending"
    assert checks["bounded-execution"] == "pending"


def test_compiler_blocks_unknown_dataset_and_field(tmp_path):
    engine = _engine(tmp_path)

    unknown_index = engine.compile(
        SplSearchIntent(purpose="Search unknown data", index="invented_index")
    )
    unknown_field = engine.compile(
        SplSearchIntent(
            purpose="Search unknown field",
            index="security",
            filters=[SplContextFilter(field="invented_field", value="anything")],
        )
    )

    assert unknown_index["status"] == "blocked"
    assert unknown_index["spl"] == ""
    assert "not proven" in unknown_index["errors"][0]
    assert unknown_field["status"] == "blocked"
    assert unknown_field["spl"] == ""
    assert "invented_field" in unknown_field["errors"][0]

    unresolved_parameter = engine.compile(
        SplSearchIntent(
            purpose="Search an unbound indicator",
            index="security",
            filters=[SplContextFilter(field="user", value="<PARAM_EMAIL_1>")],
        )
    )
    assert unresolved_parameter["status"] == "blocked"
    assert unresolved_parameter["spl"] == ""
    assert "unresolved parameters" in unresolved_parameter["errors"][0]


def test_model_spl_assessment_never_promotes_to_execution_trust(tmp_path):
    engine = _engine(tmp_path)

    known = engine.assess_spl(
        'search index="security" sourcetype="XmlWinEventLog:Security" '
        "| stats count by host"
    )
    unknown = engine.assess_spl('search index="made_up" | stats count')

    assert known["status"] == "context-grounded"
    assert known["trusted_for_execution"] is False
    assert known["data_exposure"] == "schema-and-synthetic-only"
    assert unknown["status"] == "blocked"
    assert "Unproven indexes" in unknown["blockers"][0]


async def test_model_plans_typed_intent_without_receiving_raw_values(tmp_path):
    engine = _engine(tmp_path)

    class Provider:
        messages = []

        async def structured_chat(self, messages, schema, **kwargs):
            self.messages = messages
            assert schema["title"] == "SplSearchPlan"
            return {
                "model": "local-test-model",
                "content": json.dumps(
                    {"intents": [{
                            "purpose": "Count failed authentication events",
                            "index": "security",
                            "sourcetypes": ["XmlWinEventLog:Security"],
                            "filters": [
                                {"field": "action", "operator": "=", "value": "failure"}
                            ],
                            "operation": "count",
                            "earliest_time": "-24h",
                            "latest_time": "now",
                            "limit": 100,
                        }]}
                ),
            }

    provider = Provider()
    result = await engine.plan_and_compile(
        f"Count failed authentication events. Sample: user={RAW_CANARY} src_ip=10.23.45.67",
        provider,
    )
    sent = json.dumps(provider.messages)

    assert result["status"] == "context-compiled"
    assert result["model"] == "local-test-model"
    assert RAW_CANARY not in sent
    assert "10.23.45.67" not in sent
    assert "schema-and-synthetic-only" in sent
    assert result["sample_sanitization"]["sample_regions_replaced"] == 1
    assert result["sample_sanitization"]["sample_values_retained"] is False
    assert result["sample_sanitization"]["model_received_parameter_values"] is False


async def test_model_can_request_multiple_separately_compiled_searches(tmp_path):
    engine = _engine(tmp_path)

    class Provider:
        async def structured_chat(self, messages, schema, **kwargs):
            return {
                "model": "local-test-model",
                "content": json.dumps(
                    {
                        "intents": [
                            {
                                "purpose": "Inspect recent failures",
                                "index": "security",
                                "filters": [
                                    {"field": "action", "operator": "=", "value": "failure"}
                                ],
                                "operation": "events",
                                "output_fields": ["_time", "host", "user"],
                                "limit": 20,
                            },
                            {
                                "purpose": "Count failures by host",
                                "index": "security",
                                "filters": [
                                    {"field": "action", "operator": "=", "value": "failure"}
                                ],
                                "operation": "aggregate",
                                "metrics": [{"function": "count", "alias": "event_count"}],
                                "group_by": ["host"],
                                "limit": 50,
                            },
                        ]
                    }
                ),
            }

    result = await engine.plan_and_compile("Create an event sample and an aggregate", Provider())

    assert result["status"] == "context-compiled"
    assert len(result["compilations"]) == 2
    assert all(item["status"] == "context-compiled" for item in result["compilations"])
    assert result["compilations"][0]["spl"] != result["compilations"][1]["spl"]


def test_modeling_packet_excludes_evidence_excerpts_and_tool_values(tmp_path):
    engine = _engine(tmp_path)
    evidence = [
        EvidenceRef(
            id="evidence-canary:0",
            source="test",
            title="Sensitive sample",
            excerpt=RAW_CANARY,
        )
    ]

    packet = engine.modeling_packet(
        evidence,
        {"results": [{"_raw": RAW_CANARY, "src_ip": "10.23.45.67"}]},
    )
    serialized = json.dumps(packet)

    assert RAW_CANARY not in serialized
    assert "10.23.45.67" not in serialized
    assert packet["evidence_provenance"][0]["id"] == "evidence-canary:0"
    assert packet["result_shape"]["raw_values_included"] is False


def test_fenced_raw_sample_becomes_a_synthetic_shape():
    sanitized, receipt = SplContextEngine.sanitize_authoring_request(
        f'''Create SPL for this event shape:
```json
{{"user": "{RAW_CANARY}", "src_ip": "10.23.45.67", "action": "failure"}}
```'''
    )

    assert RAW_CANARY not in sanitized
    assert "10.23.45.67" not in sanitized
    assert '"synthetic": true' in sanitized
    assert "198.51.100.27" in sanitized
    assert receipt["sample_regions_replaced"] == 1
    assert receipt["field_names_retained"] == ["action", "src_ip", "user"]


def test_inline_and_marked_raw_samples_are_synthesized():
    sanitized, receipt = SplContextEngine.sanitize_authoring_request(
        'Create SPL for {"host":"prod-real-01","user":"chris"}.\n'
        "Raw event: 2026-09-05 login failure from a production workstation"
    )

    assert "prod-real-01" not in sanitized
    assert '"chris"' not in sanitized
    assert "production workstation" not in sanitized
    assert '"synthetic": true' in sanitized
    assert "Raw event: synthetic_shape=<OMITTED>" in sanitized
    assert receipt["sample_regions_replaced"] == 2
    assert receipt["sample_values_retained"] is False


def test_large_field_catalog_is_ranked_for_the_current_question():
    items = [
        {"name": f"field_{index:04d}", "evidence": "knowledge-object-reference"}
        for index in range(600)
    ]
    items.append(
        {
            "name": "process_command_line",
            "evidence": "knowledge-object-reference",
            "referenced_by": ["saved_searches:Suspicious PowerShell"],
        }
    )

    selected = SplContextEngine._rank_context_items(
        "Find suspicious PowerShell process command lines",
        items,
        "name",
        40,
    )

    assert selected[0]["name"] == "process_command_line"
    assert len(selected) == 40


def test_interactive_indicators_are_parameterized_then_bound_without_model_exposure(tmp_path):
    engine = _engine(tmp_path)
    parameterized, parameters, receipt = engine._parameterize_request(
        "Create SPL for source 10.23.45.67 and account analyst@example.org"
    )

    assert "10.23.45.67" not in parameterized
    assert "analyst@example.org" not in parameterized
    assert set(parameters.values()) == {"10.23.45.67", "analyst@example.org"}
    assert receipt["parameters_replaced"] == 2
    assert json.dumps(receipt).find("10.23.45.67") == -1

    intent = SplSearchIntent(
        purpose="Find the requested source",
        index="security",
        filters=[
            SplContextFilter(field="user", value="<PARAM_EMAIL_1>"),
        ],
    )
    bound = engine._bind_intent_parameters(intent, parameters)
    result = engine.compile(bound)

    assert bound.filters[0].value == "analyst@example.org"
    assert 'user="analyst@example.org"' in result["spl"]


def test_request_grounding_corrects_common_typed_planner_drift(tmp_path):
    engine = _engine(tmp_path)
    packet = engine.modeling_packet(
        query="Create SPL to count events by sourcetype in security over the last 4 hours"
    )
    proposed = [
        SplSearchIntent(
            purpose="search",
            index="authentication",
            sourcetypes=["*"],
            filters=[SplContextFilter(field="host", value="workstation-023.example.invalid")],
            operation="events",
            earliest_time="-24h",
        ),
        SplSearchIntent(
            purpose="search",
            index="security",
            filters=[],
            operation="events",
        ),
    ]

    normalized, notes = engine._normalize_planned_intents(
        "Create SPL to count events by sourcetype in security over the last 4 hours",
        proposed,
        packet,
    )

    assert len(normalized) == 1
    assert normalized[0].index == "security"
    assert normalized[0].sourcetypes == []
    assert normalized[0].filters == []
    assert normalized[0].operation == "aggregate"
    assert normalized[0].metrics[0].function == "count"
    assert normalized[0].group_by == ["sourcetype"]
    assert normalized[0].earliest_time == "-4h"
    assert any("duplicate" in note.lower() for note in notes)
