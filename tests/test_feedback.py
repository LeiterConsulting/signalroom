from splunk_security_agent.feedback import AnalystFeedbackStore
from splunk_security_agent.schemas import AnalystFeedbackCreate


def test_feedback_is_local_deduplicated_and_benchmarked_by_model_and_task(tmp_path):
    store = AnalystFeedbackStore(tmp_path / "feedback.db")
    useful = AnalystFeedbackCreate(
        target_type="chat",
        target_id="conversation-1:response-1",
        task_type="triage",
        rating="useful",
        model_profile="foundation-sec",
        model="foundation-sec:8b",
        route="security-agent",
    )

    first = store.record(useful)
    repeated = store.record(useful.model_copy(update={"note": "Strong evidence separation."}))
    store.record(
        AnalystFeedbackCreate(
            target_type="chat",
            target_id="conversation-2:response-1",
            task_type="triage",
            rating="missing-evidence",
            model_profile="foundation-sec",
            model="foundation-sec:8b",
            route="security-agent",
        )
    )
    benchmark = store.benchmarks()

    assert repeated["id"] == first["id"]
    assert benchmark["total"] == 2
    scorecard = benchmark["scorecards"][0]
    assert scorecard["model_profile"] == "foundation-sec"
    assert scorecard["task_type"] == "triage"
    assert scorecard["positive_rate"] == 0.5
    assert scorecard["confidence"] == "directional"
