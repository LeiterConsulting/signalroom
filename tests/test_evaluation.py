from splunk_security_agent.evaluation import evaluate


def test_synthetic_security_evaluation_suite_passes():
    result = evaluate()

    assert result["scenario_count"] == 8
    assert result["passed"] == result["scenario_count"]
    assert all(value == 1 for value in result["metrics"].values())
