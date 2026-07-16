from splunk_security_agent.schemas import QueryIntelligenceRequest, ValidationTaskCreate
from splunk_security_agent.validation import QueryIntelligenceService, ValidationStore


def test_query_intelligence_explains_scope_cost_and_staged_contract(tmp_path):
    service = QueryIntelligenceService(ValidationStore(tmp_path / "validations.db"))

    result = service.analyze(
        QueryIntelligenceRequest(
            spl="search error | transaction user | stats count by host",
            earliest_time="-90d",
            row_limit=500,
        )
    )

    assert result["risk"] == "high"
    assert result["score"] >= 55
    assert any("index scope" in item["label"] for item in result["cost_drivers"])
    assert any("Transaction" in item["label"] for item in result["cost_drivers"])
    assert result["staged_contract"]["earliest_time"] == "-24h"
    assert result["staged_contract"]["row_limit"] == 100


def test_query_intelligence_blocks_prohibited_spl(tmp_path):
    service = QueryIntelligenceService(ValidationStore(tmp_path / "validations.db"))

    result = service.analyze(
        QueryIntelligenceRequest(spl="index=main | outputlookup overwrite.csv")
    )

    assert result["risk"] == "blocked"
    assert result["blocked_reason"]


def test_query_intelligence_finds_exact_preserved_result(tmp_path):
    store = ValidationStore(tmp_path / "validations.db")
    value = ValidationTaskCreate(
        title="Known result",
        rationale="Preserve an exact bounded result.",
        spl="index=identity action=failure | head 100",
        earliest_time="-24h",
        latest_time="now",
        row_limit=100,
    )
    task = store.create(value)
    store.approve(task.id)
    store.mark_running(task.id)
    store.complete(task.id, 2, [{"count": 2}], "artifact-1")

    result = QueryIntelligenceService(store).analyze(
        QueryIntelligenceRequest(
            spl=value.spl,
            earliest_time=value.earliest_time,
            latest_time=value.latest_time,
            row_limit=value.row_limit,
        )
    )

    assert result["reusable_result"]["id"] == task.id
    assert "Reuse" in result["execution_recommendation"]
