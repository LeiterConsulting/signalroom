import json

from splunk_security_agent.config import ConfigStore
from splunk_security_agent.discovery import DiscoveryPipeline
from splunk_security_agent.discovery.pipeline import (
    GeneralDiscoverySynthesis,
    SecurityDiscoveryAssessment,
)
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import ArtifactCreate
from splunk_security_agent.splunk import DemoSplunkClient


class RecordingDemoSplunkClient(DemoSplunkClient):
    def __init__(self):
        self.calls = []

    async def call(self, logical_name, arguments=None):
        self.calls.append((logical_name, arguments or {}))
        return await super().call(logical_name, arguments)


async def test_demo_discovery_emits_and_indexes_artifacts(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.db")
    pipeline = DiscoveryPipeline(DemoSplunkClient(), evidence, tmp_path / "artifacts")

    result = await pipeline.run("standard")

    assert result["overview"]["indexes"] == 5
    assert result["coverage"]["score"] > 0
    assert len(result["artifacts"]) == 2
    assert len(evidence.list()) == 4
    assert len(result["knowledge_artifacts"]) == 3
    assert result["security_posture"]["detections"]["total"] == 0
    assert {item.kind for item in evidence.list()} == {"discovery", "discovery-knowledge"}


async def test_standard_discovery_indexes_splunk_mltk_models_as_rag_context(tmp_path):
    class ModelInventory:
        async def scan(self):
            return {
                "available": True,
                "status": "complete",
                "checked_at": "2026-07-16T12:00:00+00:00",
                "summary": {
                    "observed": 1,
                    "new": 1,
                    "changed": 0,
                    "missing": 0,
                    "dependencies_not_observed": 1,
                },
                "freshness_contract": "Definition drift only; training freshness is not reported.",
                "models": [
                    {
                        "id": "model-1",
                        "name": "ollama_text_processing",
                        "type": "MLTKContainer",
                        "algorithm": "MLTKContainer",
                        "owner": "analyst",
                        "app": "mltk-container",
                        "status": "new",
                        "fingerprint": "abc123",
                        "dependency": {
                            "service": "ollama",
                            "model": "llama3.2:1b",
                            "observation": "not-observed",
                            "caveat": "Comparison covers only the configured endpoint.",
                        },
                    }
                ],
            }

    evidence = EvidenceStore(tmp_path / "evidence.db")
    pipeline = DiscoveryPipeline(
        DemoSplunkClient(),
        evidence,
        tmp_path / "artifacts",
        model_inventory=ModelInventory(),
    )

    result = await pipeline.run("standard")
    documents = [item for item in evidence.list() if item.kind == "discovery-knowledge"]

    assert result["security_posture"]["mltk_models"]["observed"] == 1
    assert len(result["knowledge_artifacts"]) == 4
    assert any(item.title == "Latest Splunk MLTK model catalog" for item in documents)
    assert any(item["domain"] == "ml-model-dependency" for item in result["findings"])


async def test_discovery_supplies_required_knowledge_object_types(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.db")
    client = RecordingDemoSplunkClient()
    pipeline = DiscoveryPipeline(client, evidence, tmp_path / "artifacts")

    result = await pipeline.run("deep")

    knowledge_calls = [
        arguments for name, arguments in client.calls if name == "get_knowledge_objects"
    ]
    assert [call["type"] for call in knowledge_calls] == [
        "saved_searches",
        "alerts",
        "data_models",
        "macros",
        "lookups",
    ]
    assert all(call["row_limit"] == 1000 for call in knowledge_calls)
    assert set(result["inventory"]["knowledge_objects"]) == {
        "saved_searches",
        "alerts",
        "data_models",
        "macros",
        "lookups",
    }


async def test_discovery_pages_bounded_knowledge_response_and_reports_progress(tmp_path):
    class PagedResponseClient(DemoSplunkClient):
        async def call(self, logical_name, arguments=None):
            if logical_name == "get_knowledge_objects":
                return [{"name": f"rule-{index}"} for index in range(250)]
            return await super().call(logical_name, arguments)

    events = []

    async def progress(event):
        events.append(event)

    pipeline = DiscoveryPipeline(
        PagedResponseClient(), EvidenceStore(tmp_path / "evidence.db"), tmp_path / "artifacts"
    )
    result = await pipeline.run("standard", progress=progress)

    saved_searches = result["collection_status"]["pagination"]["saved_searches"]
    assert saved_searches["returned"] == 250
    assert saved_searches["local_pages"] == 3
    assert saved_searches["server_cursor_supported"] is False
    assert any("page 3/3" in event["label"] for event in events)
    assert events[-1]["phase"] == "complete"
    assert events[-1]["progress"] == 100


def test_discovery_reads_values_from_mcp_results_envelope():
    assert DiscoveryPipeline._value({"results": [{"version": "9.4.0"}]}, "version") == "9.4.0"


async def test_discovery_compares_with_previous_snapshot(tmp_path):
    class ChangingClient(DemoSplunkClient):
        def __init__(self):
            self.extra = False

        async def call(self, logical_name, arguments=None):
            result = await super().call(logical_name, arguments)
            if logical_name == "get_indexes" and self.extra:
                return [*result, {"title": "new-security-index", "currentDBSizeMB": 1}]
            return result

    client = ChangingClient()
    pipeline = DiscoveryPipeline(
        client, EvidenceStore(tmp_path / "evidence.db"), tmp_path / "artifacts"
    )
    first = await pipeline.run("quick")
    client.extra = True
    second = await pipeline.run("quick")

    assert first["changes"]["baseline_available"] is False
    assert second["changes"]["baseline_available"] is True
    assert second["changes"]["inventory"]["indexes"]["added"] == ["new-security-index"]
    assert second["collection_status"]["complete"] is True


async def test_latest_discovery_summary_excludes_large_raw_catalogs(tmp_path):
    pipeline = DiscoveryPipeline(
        DemoSplunkClient(), EvidenceStore(tmp_path / "evidence.db"), tmp_path / "artifacts"
    )
    result = await pipeline.run("standard")

    latest = pipeline.latest_summary()

    assert latest is not None
    assert latest["run_id"] == result["run_id"]
    assert "inventory" not in latest
    assert "catalog" not in latest["security_posture"]["detections"]
    assert "catalog" not in latest["security_posture"]["data_models"]
    assert latest["findings"] == result["findings"]


async def test_quick_discovery_preserves_richer_rag_knowledge(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.db")
    pipeline = DiscoveryPipeline(DemoSplunkClient(), evidence, tmp_path / "artifacts")

    standard = await pipeline.run("standard")
    quick = await pipeline.run("quick")

    knowledge = [item for item in evidence.list() if item.kind == "discovery-knowledge"]
    assert len(standard["knowledge_artifacts"]) == 3
    assert quick["knowledge_artifacts"] == []
    assert len(knowledge) == 3


async def test_standard_discovery_runs_role_based_local_model_team(tmp_path):
    config = ConfigStore(tmp_path / "data")
    for profile_id in ("securebert-embed", "securebert-ner"):
        model_path = config.local_model_path(profile_id)
        model_path.mkdir(parents=True)
        (model_path / "config.json").write_text("{}", encoding="utf-8")
        (model_path / "model.safetensors").write_bytes(b"synthetic")
        (model_path / ".signalroom-model.json").write_text("{}", encoding="utf-8")

    evidence = EvidenceStore(tmp_path / "evidence.db")
    prior = evidence.add(
        ArtifactCreate(
            title="Prior endpoint discovery",
            content="CVE-2026-1234 endpoint coverage requires validation.",
            kind="discovery",
            source="prior run",
        )
    )
    evidence.save_embeddings("securebert-embed", [(f"{prior.id}:0", [1.0, 0.0])])
    structured_calls = []

    class EntityProvider:
        async def entities(self, text):
            return [
                {
                    "word": "CVE-2026-1234",
                    "entity_group": "vulnerability",
                    "score": 0.99,
                }
            ]

    class EmbeddingProvider:
        async def query_embedding(self, text):
            return [1.0, 0.0]

        async def document_embeddings(self, texts):
            return [[1.0, 0.0] for _text in texts]

    class StructuredProvider:
        def __init__(self, profile_id):
            self.profile_id = profile_id

        async def structured_chat(
            self, messages, schema, keep_alive="15m", max_output_tokens=None
        ):
            structured_calls.append((self.profile_id, keep_alive, schema, messages))
            if self.profile_id == "ollama-general":
                payload = {
                    "environment_summary": "A bounded local environment synthesis.",
                    "material_observations": ["Endpoint coverage needs validation."],
                    "coverage_interpretation": [],
                    "change_summary": [],
                    "questions_for_security_review": ["Which gap is material?"],
                    "caveats": [],
                }
            else:
                payload = {
                    "executive_summary": "Evidence-linked security assessment.",
                    "priorities": [
                        {
                            "title": "Validate endpoint telemetry",
                            "severity": "high",
                            "why": "A deterministic gap was reported.",
                            "owner": "SOC",
                            "next_step": "Run a bounded validation search.",
                            "evidence_refs": ["D1", "UNKNOWN-1"],
                        }
                    ],
                    "risk_hypotheses": [
                        {
                            "title": "Endpoint visibility may be incomplete",
                            "basis": "The deterministic finding reports a gap.",
                            "validation": "Validate endpoint sourcetypes over 24 hours.",
                            "confidence": "medium",
                            "evidence_refs": ["D1"],
                        }
                    ],
                    "detection_opportunities": [],
                    "caveats": [],
                }
            return {
                "content": json.dumps(payload),
                "model": self.profile_id,
                "activation": {},
                "raw": {"prompt_eval_count": 100, "eval_count": 30},
            }

    class FakeRouter:
        def provider(self, profile_id):
            if profile_id == "securebert-ner":
                return EntityProvider()
            if profile_id == "securebert-embed":
                return EmbeddingProvider()
            return StructuredProvider(profile_id)

    pipeline = DiscoveryPipeline(
        DemoSplunkClient(), evidence, tmp_path / "artifacts", config
    )
    pipeline.router = FakeRouter()

    result = await pipeline.run("standard")

    analysis = result["model_analysis"]
    assert analysis["status"] == "complete"
    assert analysis["models_used"] == 4
    assert [item[0] for item in structured_calls] == ["ollama-general", "foundation-sec"]
    assert structured_calls[0][1] == 0
    assert structured_calls[1][1] == "15m"
    generation_schema = json.dumps(structured_calls[0][2])
    assert '"$defs"' not in generation_schema
    assert '"$ref"' not in generation_schema
    assert '"maxLength"' not in generation_schema
    assert structured_calls[0][2]["additionalProperties"] is False
    assert analysis["specialist_enrichment"]["entities"][0]["value"] == "CVE-2026-1234"
    assert analysis["specialist_enrichment"]["context_matches"][0]["title"] == (
        "Prior endpoint discovery"
    )
    assert analysis["priorities"][0]["evidence_refs"] == ["D1"]
    assert analysis["reconciliation"]["invalid_reference_count"] == 1
    assert any(
        item.get("source") == "Foundation-Sec model-assisted"
        for item in result["investigation_tracks"]
    )
    assert analysis["network_inference"] is False

    await pipeline.run("standard")  # Baseline availability changes once and invalidates synthesis.
    unchanged = await pipeline.run("standard")
    unchanged_analysis = unchanged["model_analysis"]
    assert len(structured_calls) == 4
    assert unchanged_analysis["roles_reused"] == 4
    assert unchanged_analysis["roles_executed"] == 0
    assert all(
        item["reused"]
        for item in [
            *unchanged_analysis["passes"],
            *unchanged_analysis["specialist_enrichment"]["passes"],
        ]
    )


async def test_discovery_model_pass_repairs_invalid_local_output_once(tmp_path):
    config = ConfigStore(tmp_path / "data")
    responses = [
        {"environment_summary": ""},
        {
            "environment_summary": "The local repair pass restored the contract.",
            "material_observations": [],
            "coverage_interpretation": [],
            "change_summary": [],
            "questions_for_security_review": [],
            "caveats": [],
        },
    ]

    class RepairingProvider:
        async def structured_chat(
            self, messages, schema, keep_alive="15m", max_output_tokens=None
        ):
            return {
                "content": json.dumps(responses.pop(0)),
                "model": "llama3.1:8b",
                "activation": {},
                "raw": {"prompt_eval_count": 10, "eval_count": 5},
            }

    class RepairingRouter:
        def provider(self, profile_id):
            return RepairingProvider()

    pipeline = DiscoveryPipeline(
        DemoSplunkClient(),
        EvidenceStore(tmp_path / "evidence.db"),
        tmp_path / "artifacts",
        config,
    )
    pipeline.router = RepairingRouter()

    result = await pipeline._run_discovery_model_pass(
        role="environment-synthesis",
        profile_id="ollama-general",
        schema=GeneralDiscoverySynthesis,
        system_prompt="Return the discovery contract.",
        payload={"evidence_map": {"D1": "Endpoint coverage needs validation."}},
        progress=None,
        progress_value=78,
        keep_alive=0,
        max_output_tokens=700,
    )

    assert result["status"] == "complete"
    assert result["attempt_count"] == 2
    assert [attempt["status"] for attempt in result["attempts"]] == [
        "validation-error",
        "accepted",
    ]
    assert result["output"]["environment_summary"].startswith("The local repair")


def test_ollama_generation_schema_preserves_fields_named_like_schema_metadata():
    schema = DiscoveryPipeline._ollama_generation_schema(
        SecurityDiscoveryAssessment.model_json_schema()
    )

    priority = schema["properties"]["priorities"]["items"]
    hypothesis = schema["properties"]["risk_hypotheses"]["items"]
    opportunity = schema["properties"]["detection_opportunities"]["items"]
    assert "title" in priority["properties"]
    assert "title" in hypothesis["properties"]
    assert "title" in opportunity["properties"]
    assert "title" not in priority
