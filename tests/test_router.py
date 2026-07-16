from splunk_security_agent.providers.router import ModelRouter


def test_investigation_modes_are_inferred_from_operator_intent():
    assert ModelRouter.classify_mode("Inventory indexes and sourcetypes") == "discovery"
    assert ModelRouter.classify_mode("Validate this detection rule") == "detection"
    assert ModelRouter.classify_mode("Build a threat hunt hypothesis") == "hunt"
    assert ModelRouter.classify_mode("Triage this incident") == "triage"
    assert ModelRouter.classify_mode("Explain this SPL search") == "spl"
    assert ModelRouter.classify_mode("Brief leadership on the findings") == "brief"


def test_operator_selected_mode_wins_over_inference():
    assert ModelRouter.classify_mode("Triage this incident", "brief") == "brief"
