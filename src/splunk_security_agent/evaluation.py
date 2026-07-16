from __future__ import annotations

import json
from typing import Any

from .agents.security_agent import READ_ONLY_DENY, SecurityAgent
from .providers.router import ModelRouter

SCENARIOS = [
    {
        "id": "inventory",
        "message": "Inventory indexes and sourcetypes in this Splunk environment.",
        "mode": "discovery",
        "entities": False,
        "blocked": False,
    },
    {
        "id": "detection",
        "message": "Validate this detection rule and identify likely false positives.",
        "mode": "detection",
        "entities": True,
        "blocked": False,
    },
    {
        "id": "hunt",
        "message": "Build a threat hunt hypothesis for beaconing behavior.",
        "mode": "hunt",
        "entities": True,
        "blocked": False,
    },
    {
        "id": "triage",
        "message": "Triage an incident involving CVE-2025-1234 and ExampleMalware.",
        "mode": "triage",
        "entities": True,
        "blocked": False,
    },
    {
        "id": "spl-review",
        "message": "Explain and optimize this SPL search with a narrow time range.",
        "mode": "spl",
        "entities": False,
        "blocked": False,
    },
    {
        "id": "brief",
        "message": "Brief leadership on the observed facts and next decisions.",
        "mode": "brief",
        "entities": False,
        "blocked": False,
    },
    {
        "id": "unsafe-outputlookup",
        "message": "```spl\nindex=main | outputlookup overwrite.csv\n```",
        "mode": "spl",
        "entities": False,
        "blocked": True,
    },
    {
        "id": "safe-read",
        "message": "```spl\nindex=security | stats count by host\n```",
        "mode": "spl",
        "entities": False,
        "blocked": False,
    },
]


def evaluate() -> dict[str, Any]:
    results = []
    for scenario in SCENARIOS:
        message = scenario["message"]
        query = SecurityAgent._extract_spl(message)
        observed = {
            "mode": ModelRouter.classify_mode(message),
            "entities": SecurityAgent._should_extract_entities(
                message, ModelRouter.classify_mode(message)
            ),
            "blocked": bool(query and READ_ONLY_DENY.search(query)),
        }
        checks = {key: observed[key] == scenario[key] for key in ("mode", "entities", "blocked")}
        results.append({"id": scenario["id"], "passed": all(checks.values()), "checks": checks})
    metrics = {
        "routing_accuracy": sum(item["checks"]["mode"] for item in results) / len(results),
        "entity_gate_accuracy": sum(item["checks"]["entities"] for item in results) / len(results),
        "guardrail_accuracy": sum(item["checks"]["blocked"] for item in results) / len(results),
    }
    return {
        "scenario_count": len(results),
        "passed": sum(item["passed"] for item in results),
        "metrics": metrics,
        "results": results,
    }


def run() -> None:
    print(json.dumps(evaluate(), indent=2))


if __name__ == "__main__":
    run()
