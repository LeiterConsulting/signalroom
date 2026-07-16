from splunk_security_agent.agents.security_agent import READ_ONLY_DENY, SecurityAgent
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import ArtifactCreate, ChatRequest, EvidenceRef
from splunk_security_agent.splunk import DemoSplunkClient


def test_write_capable_spl_is_detected():
    assert READ_ONLY_DENY.search("index=main | delete")
    assert READ_ONLY_DENY.search("index=main | outputlookup suspicious.csv")
    assert not READ_ONLY_DENY.search("index=main | stats count by host")


def test_spl_extraction_from_fence():
    assert (
        SecurityAgent._extract_spl("run this ```spl\nindex=security | stats count\n```")
        == "index=security | stats count"
    )


def test_entity_extraction_is_gated_by_security_intent():
    assert not SecurityAgent._should_extract_entities("What Splunk version is connected?", "general")
    assert SecurityAgent._should_extract_entities("Investigate CVE-2025-1234", "triage")
    assert SecurityAgent._should_extract_entities("Validate this detection", "detection")


def test_live_result_fields_become_deduplicated_investigation_pivots():
    pivots = SecurityAgent._deterministic_entity_pivots(
        {
            "results": [
                {
                    "host": "edge-sensor-01",
                    "src_ip": "10.4.7.9",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                    "vulnerability_id": "CVE-2026-12345",
                    "message": "CVE-2026-12345 was observed from 10.4.7.9",
                }
            ]
        }
    )

    values = {(item.entity_type, item.value.lower()) for item in pivots}
    assert ("host", "edge-sensor-01") in values
    assert ("ipv4", "10.4.7.9") in values
    assert ("mac", "aa:bb:cc:dd:ee:ff") in values
    assert ("cve", "cve-2026-12345") in values
    assert len([item for item in pivots if item.value.lower() == "cve-2026-12345"]) == 1
    assert all("bounded read-only Splunk tools" in item.prompt for item in pivots)


def test_model_entity_fragments_are_filtered_and_typed_pivots_win_duplicates():
    assert SecurityAgent._pivot("192", "indicator", 0.99, "local-transformers") is None
    assert SecurityAgent._pivot("unk", "indicator", 0.99, "local-transformers") is None
    assert (
        SecurityAgent._pivot(
            "esp32~1013~BAD42FBA", "indicator", 0.99, "local-transformers"
        )
        is None
    )
    domain = SecurityAgent._pivot(
        "sensor.example.org", "indicator", 0.99, "local-transformers"
    )
    assert domain is not None and domain.entity_type == "domain"
    deterministic = SecurityAgent._pivot("192.168.1.203", "ipv4", 1, "deterministic")
    modeled = SecurityAgent._pivot(
        "192.168.1.203", "indicator", 0.99, "local-transformers"
    )

    merged = SecurityAgent._merge_entity_pivots([modeled], [deterministic])

    assert len(merged) == 1
    assert merged[0].entity_type == "ipv4"
    assert merged[0].source == "deterministic"


def test_context_correlations_can_diversify_across_distinct_artifacts():
    matches = [
        EvidenceRef(id="artifact-a:0", source="local", title="A", excerpt="one", score=0.99),
        EvidenceRef(id="artifact-a:1", source="local", title="A", excerpt="two", score=0.98),
        EvidenceRef(id="artifact-b:0", source="local", title="B", excerpt="three", score=0.8),
    ]

    result = SecurityAgent._merge_evidence(
        [], matches, limit=4, max_per_artifact=1
    )

    assert [item.id for item in result] == ["artifact-a:0", "artifact-b:0"]


def test_latest_index_entry_compiles_to_bounded_read_only_spl():
    compiled = SecurityAgent._compile_live_query("What's the latest entry in the esp32 index")

    assert compiled == {
        "intent": "latest-events",
        "index": "esp32",
        "query": 'search index="esp32" | head 1',
        "earliest_time": "-30d",
        "row_limit": 1,
        "label": "Reading the latest esp32 event",
    }


def test_live_query_compiler_rejects_unbounded_or_unsafe_requests():
    assert SecurityAgent._compile_live_query("Tell me about the esp32 index") is None
    assert SecurityAgent._compile_live_query("latest entry in the esp32 | delete index") is None


async def test_latest_index_entry_executes_mcp_query_before_rag_reuse(tmp_path):
    class RecordingClient:
        def __init__(self):
            self.calls = []

        async def call(self, logical_name, arguments=None):
            self.calls.append((logical_name, arguments or {}))
            return {"results": [{"_time": "2026-07-16T12:00:00Z", "temperature": 4.2}]}

    evidence = [
        EvidenceRef(
            id="latest:0",
            title="Latest telemetry catalog",
            source="Splunk discovery knowledge",
            kind="discovery-knowledge",
            excerpt="The esp32 index exists.",
            score=0.8,
        )
    ]
    client = RecordingClient()
    agent = SecurityAgent(
        ConfigStore(tmp_path / "data"), EvidenceStore(tmp_path / "evidence.db"), client
    )

    result, trace, provenance = await agent._deterministic_tool(
        ChatRequest(message="What's the latest entry in the esp32 index"),
        "general",
        evidence,
    )

    assert result["results"][0]["temperature"] == 4.2
    assert trace[0] == "Called run_query from natural-language intent"
    assert provenance["compiled_from_natural_language"] is True
    assert client.calls == [
        (
            "run_query",
            {
                "query": 'search index="esp32" | head 1',
                "earliest_time": "-30d",
                "latest_time": "now",
                "row_limit": 1,
            },
        )
    ]


def test_latest_event_is_rendered_directly_with_useful_fields():
    answer = SecurityAgent._format_live_tool_answer(
        {
            "results": [
                {
                    "_time": "2026-07-16 12:48:13 EDT",
                    "host": "Freezer Temp Monitor",
                    "source": "http:esp32_temp",
                    "sourcetype": "esp32:temperature",
                    "temperature": "3.8",
                    "_raw": "temperature=3.8 unit=C",
                }
            ]
        },
        {
            "compiled_from_natural_language": True,
            "intent": "latest-events",
            "index": "esp32",
            "arguments": {
                "query": 'search index="esp32" | head 1',
                "earliest_time": "-30d",
            },
        },
    )

    assert "### Latest event in `esp32`" in answer
    assert "Freezer Temp Monitor" in answer
    assert "http:esp32_temp" in answer
    assert "temperature=3.8 unit=C" in answer
    assert "`temperature`: `3.8`" in answer
    assert "verify" not in answer.lower()


async def test_factual_live_read_bypasses_llm_synthesis(monkeypatch, tmp_path):
    class RecordingClient:
        async def call(self, logical_name, arguments=None):
            assert logical_name == "run_query"
            return {
                "results": [
                    {
                        "_time": "2026-07-16 12:48:13 EDT",
                        "host": "Freezer Temp Monitor",
                        "temperature": "3.8",
                    }
                ]
            }

    agent = SecurityAgent(
        ConfigStore(tmp_path / "data"), EvidenceStore(tmp_path / "evidence.db"), RecordingClient()
    )

    def fail_if_model_is_requested(_profile_id):
        raise AssertionError("A factual one-row MCP result must not invoke an LLM")

    monkeypatch.setattr(agent.router, "provider", fail_if_model_is_requested)
    response = await agent.chat(ChatRequest(message="What's the latest entry in the esp32 index"))

    assert response.model == "Splunk MCP"
    assert response.model_profile == ""
    assert response.route == "direct-tool-result"
    assert "Freezer Temp Monitor" in response.message
    assert response.trace[-1].label == "Rendered verified MCP result"
    assert response.ledger[-1].statement.startswith("Latest `esp32` event observed")


async def test_live_result_is_correlated_with_context_without_a_second_splunk_call(tmp_path):
    class RecordingClient:
        def __init__(self):
            self.calls = []

        async def call(self, logical_name, arguments=None):
            self.calls.append((logical_name, arguments or {}))
            return {
                "results": [
                    {
                        "_time": "2026-07-16 12:48:13 EDT",
                        "host": "edge-sensor-01",
                        "src_ip": "10.4.7.9",
                    }
                ]
            }

    evidence = EvidenceStore(tmp_path / "evidence.db")
    evidence.add(
        ArtifactCreate(
            title="Edge sensor response runbook",
            content="Investigate edge-sensor-01 and 10.4.7.9 using network telemetry.",
            kind="runbook",
            source="operator",
        )
    )
    client = RecordingClient()
    agent = SecurityAgent(ConfigStore(tmp_path / "data"), evidence, client)

    response = await agent.chat(
        ChatRequest(message="What's the latest entry in the esp32 index")
    )

    assert len(client.calls) == 1
    assert {item.value for item in response.enrichment.entities} >= {
        "edge-sensor-01",
        "10.4.7.9",
    }
    assert response.enrichment.context_matches[0].title == "Edge sensor response runbook"
    assert response.evidence[0].title == "Edge sensor response runbook"
    assert response.enrichment.runtime == "Deterministic local extraction"


async def test_discovery_mode_executes_bounded_read_only_plan(tmp_path):
    class RecordingClient(DemoSplunkClient):
        def __init__(self):
            self.calls = []

        async def call(self, logical_name, arguments=None):
            self.calls.append((logical_name, arguments or {}))
            return await super().call(logical_name, arguments)

    config = ConfigStore(tmp_path / "data")
    config.load().max_agent_steps = 4
    client = RecordingClient()
    agent = SecurityAgent(config, EvidenceStore(tmp_path / "evidence.db"), client)

    result, trace, provenance = await agent._deterministic_tool(
        ChatRequest(message="Assess coverage gaps", execute_searches=True), "discovery"
    )

    assert list(result) == ["index inventory", "sourcetypes", "hosts"]
    assert trace[0] == "Executed 3-step read-only plan"
    assert provenance["read_only"] is True
    assert [name for name, _arguments in client.calls] == [
        "get_indexes",
        "get_metadata",
        "get_metadata",
    ]


async def test_discovery_knowledge_prevents_redundant_splunk_call(tmp_path):
    class NeverCalled:
        async def call(self, logical_name, arguments=None):
            raise AssertionError(f"Unexpected Splunk call: {logical_name}")

    config = ConfigStore(tmp_path / "data")
    agent = SecurityAgent(config, EvidenceStore(tmp_path / "evidence.db"), NeverCalled())
    evidence = [
        EvidenceRef(
            id="latest:0",
            title="Latest detection catalog",
            source="Splunk discovery knowledge",
            kind="discovery-knowledge",
            excerpt="Detections: 20 enabled, 2 disabled",
            score=0.8,
        )
    ]

    result, trace, provenance = await agent._deterministic_tool(
        ChatRequest(message="What detection coverage do we have?"), "detection", evidence
    )

    assert result is None
    assert trace[0] == "Reused latest discovery knowledge"
    assert provenance["reused_context"] is True


def test_tool_results_are_distilled_before_model_context():
    result = SecurityAgent._distill_tool_result([{"value": index} for index in range(25)])

    assert result["result_count"] == 25
    assert len(result["sample"]) == 20
    assert result["truncated"] is True


def test_search_result_recommends_local_reasoning_and_local_securebert_install(tmp_path):
    config = ConfigStore(tmp_path / "data")
    agent = SecurityAgent(config, EvidenceStore(tmp_path / "evidence.db"), DemoSplunkClient())

    recommendations = agent._model_recommendations(
        "Find activity related to CVE-2026-1234",
        {"results": [{"description": "Malware exploited CVE-2026-1234", "host": "edge-01"}]},
        {"tool": "run_query", "read_only": True},
        "triage",
    )

    local = next(item for item in recommendations if item.profile_id == "foundation-sec")
    specialist = next(item for item in recommendations if item.profile_id == "securebert-ner")
    assert local.external is False
    assert local.availability == "ready"
    assert "facts, hypotheses, risk" in local.expected_result
    assert "CVE-2026-1234" in local.prompt
    assert specialist.external is False
    assert specialist.availability == "install-required"
    assert specialist.action_label == "Install locally"
    assert "Local-first execution is selected" in specialist.reason


def test_cloud_runtime_explains_disabled_hf_without_external_call(tmp_path):
    config = ConfigStore(tmp_path / "data")
    settings = config.load()
    settings.specialist_runtime = "cloud"
    config.save(settings)
    agent = SecurityAgent(config, EvidenceStore(tmp_path / "evidence.db"), DemoSplunkClient())

    recommendations = agent._model_recommendations(
        "Find activity related to CVE-2026-1234",
        {"results": [{"description": "Malware exploited CVE-2026-1234"}]},
        {"tool": "run_query", "read_only": True},
        "triage",
    )

    hosted = next(item for item in recommendations if item.profile_id == "securebert-ner")
    assert hosted.external is True
    assert hosted.availability == "disabled"
    assert hosted.action_label == "Review cloud policy"
    assert "kept this result local" in hosted.reason
    assert "no external call" in hosted.reason


def test_installed_local_specialist_is_ready_without_cloud_approval(tmp_path):
    config = ConfigStore(tmp_path / "data")
    model_path = config.local_model_path("securebert-ner")
    model_path.mkdir(parents=True)
    (model_path / "config.json").write_text("{}", encoding="utf-8")
    (model_path / "model.safetensors").write_bytes(b"synthetic")
    (model_path / ".signalroom-model.json").write_text("{}", encoding="utf-8")
    agent = SecurityAgent(config, EvidenceStore(tmp_path / "evidence.db"), DemoSplunkClient())

    recommendations = agent._model_recommendations(
        "Triage CVE-2026-1234",
        {"results": [{"description": "Malware exploited CVE-2026-1234"}]},
        {"tool": "run_query", "read_only": True},
        "triage",
    )

    specialist = next(item for item in recommendations if item.profile_id == "securebert-ner")
    assert specialist.external is False
    assert specialist.availability == "ready"
    assert specialist.action_label == "Use local specialist"
    assert "makes no cloud inference call" in specialist.reason


def test_broad_result_offers_one_call_securebert_retrieval_when_policy_asks(tmp_path):
    config = ConfigStore(tmp_path / "data")
    settings = config.load()
    settings.specialist_runtime = "cloud"
    settings.huggingface_policy = "ask"
    config.save(settings)
    config.update_secrets(huggingface_token="synthetic-test-token")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    evidence.add(
        ArtifactCreate(
            title="Endpoint triage runbook",
            content="Validate endpoint alerts using process and network telemetry.",
            kind="runbook",
        )
    )
    agent = SecurityAgent(config, evidence, DemoSplunkClient())

    recommendations = agent._model_recommendations(
        "Review this inventory",
        [{"host": f"endpoint-{index}", "count": index} for index in range(6)],
        {"tool": "run_query", "read_only": True},
        "discovery",
    )

    retrieval = next(item for item in recommendations if item.profile_id == "securebert-embed")
    assert retrieval.availability == "approval-required"
    assert retrieval.action_label == "Approve this HF specialist"
    assert retrieval.external is True
    assert "endpoint-5" in retrieval.prompt


def test_hf_recommendation_approval_is_scoped_to_the_named_specialist():
    ner_request = ChatRequest(
        message="Extract CVE-2026-1234",
        huggingface_approved=True,
        huggingface_specialist="ner",
    )

    assert SecurityAgent._huggingface_specialist_allowed(ner_request, "ner") is True
    assert SecurityAgent._huggingface_specialist_allowed(ner_request, "embedding") is False


def test_ledger_entries_explain_provenance_and_offer_follow_on_actions():
    evidence = EvidenceRef(
        id="artifact-123:0",
        source="operator runbook",
        title="PowerShell triage",
        excerpt="Validate encoded command-line execution.",
        score=0.88,
    )

    ledger = SecurityAgent._build_ledger(
        [evidence],
        {"results": [{"host": "synthetic-host"}]},
        {"tools": ["get_metadata"], "read_only": True},
    )

    assert "supporting context, not proof" in ledger[0].why
    assert {action.kind for action in ledger[0].actions} == {"prompt", "artifact"}
    assert ledger[0].actions[-1].target == "artifact-123"
    assert ledger[1].status == "observed"
    assert {action.mode for action in ledger[1].actions} >= {"hunt", "brief"}
