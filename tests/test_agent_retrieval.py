from splunk_security_agent.agents import SecurityAgent
from splunk_security_agent.config import ConfigStore
from splunk_security_agent.providers import ModelProviderError
from splunk_security_agent.rag import EvidenceStore
from splunk_security_agent.schemas import ArtifactCreate
from splunk_security_agent.splunk import DemoSplunkClient


class SimilarityOnlyProvider:
    async def embeddings(self, texts):
        raise ModelProviderError("Hosted model exposes sentence similarity")

    async def similarities(self, source, sentences):
        assert source == "encoded PowerShell"
        return [0.91 if "PowerShell" in sentence else 0.08 for sentence in sentences]


async def test_retrieval_falls_back_to_hosted_sentence_similarity(tmp_path):
    config = ConfigStore(tmp_path / "data")
    config.update_secrets(huggingface_token="synthetic-test-token")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    evidence.add(
        ArtifactCreate(
            title="Endpoint hunt",
            content="Detect encoded PowerShell using process telemetry.",
            kind="runbook",
        )
    )
    agent = SecurityAgent(config, evidence, DemoSplunkClient())
    agent.router.provider = lambda _profile_id: SimilarityOnlyProvider()

    settings = config.load()
    settings.specialist_runtime = "cloud"
    config.save(settings)

    results, mode = await agent._retrieve_evidence("encoded PowerShell", allow_specialist=True)

    assert results[0].title == "Endpoint hunt"
    assert results[0].score == 0.91
    assert mode == "Hybrid Hosted SecureBERT similarity + SQLite FTS5"


async def test_local_securebert_does_not_require_token_or_cloud_policy(tmp_path):
    config = ConfigStore(tmp_path / "data")
    evidence = EvidenceStore(tmp_path / "evidence.db")
    evidence.add(
        ArtifactCreate(
            title="Endpoint hunt",
            content="Detect encoded PowerShell using process telemetry.",
            kind="runbook",
        )
    )
    agent = SecurityAgent(config, evidence, DemoSplunkClient())
    agent.router.provider = lambda _profile_id: SimilarityOnlyProvider()

    results, mode = await agent._retrieve_evidence(
        "encoded PowerShell", allow_specialist=True
    )

    assert results[0].title == "Endpoint hunt"
    assert mode == "Hybrid Local SecureBERT similarity + SQLite FTS5"
    assert config.load().huggingface_policy == "disabled"
    assert config.secret("huggingface_token") == ""


def test_huggingface_policy_requires_explicit_query_approval(tmp_path):
    config = ConfigStore(tmp_path / "data")
    settings = config.load()
    settings.huggingface_policy = "ask"
    config.save(settings)
    agent = SecurityAgent(config, EvidenceStore(tmp_path / "evidence.db"), DemoSplunkClient())

    from splunk_security_agent.schemas import ChatRequest

    assert agent._huggingface_allowed(ChatRequest(message="hunt malware")) is False
    assert (
        agent._huggingface_allowed(
            ChatRequest(message="hunt malware", huggingface_approved=True)
        )
        is True
    )
