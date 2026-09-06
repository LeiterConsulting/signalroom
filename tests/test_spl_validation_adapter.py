import json

from splunk_security_agent.schemas import ValidationTaskCreate
from splunk_security_agent.splunk import SplValidationAdapter
from splunk_security_agent.validation import ValidationStore


def validation_task(tmp_path, **updates):
    value = {
        "title": "Count authentication events",
        "rationale": "Confirm the active telemetry shape.",
        "spl": 'search index="security" earliest=-24h latest=now | stats count as event_count',
        "earliest_time": "-24h",
        "latest_time": "now",
        "row_limit": 10,
        "result_contract": {
            "contract": "signalroom.spl-result-shape.v1",
            "operation": "count",
            "expected_fields": ["event_count"],
            "allow_zero_rows": True,
        },
        "connection_alias": "lab-002",
        "connection_fingerprint": "b" * 64,
        "tenant_scope_id": "tenant-lab-002",
    }
    value.update(updates)
    return ValidationStore(tmp_path / "validations.db").create(ValidationTaskCreate(**value))


class ValidationToolClient:
    def __init__(self, *, parser_valid=True):
        self.parser_valid = parser_valid
        self.calls = []

    async def list_tools(self):
        return [
            {
                "name": "splunk_validate_spl",
                "description": "Validate SPL without running it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "spl": {"type": "string"},
                        "earliest_time": {"type": "string"},
                        "latest_time": {"type": "string"},
                    },
                },
            },
            {
                "name": "saia_optimize_spl",
                "description": "Critique SPL with Splunk AI Assistant.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "instruction": {"type": "string"},
                    },
                },
            },
        ]

    async def call(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "splunk_validate_spl":
            return {"valid": self.parser_valid, "message": "Parser decision recorded."}
        if name == "saia_optimize_spl":
            return {
                "status": "success",
                "summary": "The SPL is bounded and uses an aggregate alias.",
                "results": [{"_raw": "must-never-enter-the-receipt"}],
                "unexpected_payload": [{"host": "another-secret-canary"}],
            }
        raise AssertionError(f"Unexpected tool call: {name}")


async def test_preflight_uses_parser_and_optional_saia_without_executing(tmp_path):
    task = validation_task(tmp_path)
    client = ValidationToolClient()

    receipt = await SplValidationAdapter().preflight(task, client, include_saia=True)

    assert receipt["status"] == "passed"
    assert receipt["parser"]["status"] == "passed"
    assert receipt["saia"]["status"] == "passed"
    assert [name for name, _ in client.calls] == [
        "splunk_validate_spl",
        "saia_optimize_spl",
    ]
    assert all(name != "splunk_run_query" for name, _ in client.calls)
    assert client.calls[0][1]["spl"] == task.spl
    assert client.calls[0][1]["earliest_time"] == "-24h"
    assert "event" not in client.calls[1][1]
    assert "must-never-enter-the-receipt" not in json.dumps(receipt)
    assert "another-secret-canary" not in json.dumps(receipt)
    assert receipt["trusted_for_execution"] is False


async def test_parser_rejection_blocks_preflight(tmp_path):
    task = validation_task(tmp_path)

    receipt = await SplValidationAdapter().preflight(
        task,
        ValidationToolClient(parser_valid=False),
    )

    assert receipt["status"] == "blocked"
    assert receipt["parser"]["status"] == "blocked"
    assert any(item["name"] == "splunk-parser" for item in receipt["checks"])


async def test_missing_parser_is_explicitly_advisory_only(tmp_path):
    class RunOnlyClient:
        async def list_tools(self):
            return [{"name": "splunk_run_query", "inputSchema": {}}]

        async def call(self, name, arguments):
            raise AssertionError("A preflight must not execute the search")

    receipt = await SplValidationAdapter().preflight(
        validation_task(tmp_path),
        RunOnlyClient(),
        include_saia=True,
    )

    assert receipt["status"] == "advisory-only"
    assert receipt["parser"]["status"] == "unavailable"
    assert receipt["saia"]["status"] == "unavailable"
    assert "does not advertise" in receipt["parser"]["summary"]


async def test_parser_without_explicit_decision_is_not_reported_as_passed(tmp_path):
    class AmbiguousParser(ValidationToolClient):
        async def call(self, name, arguments):
            self.calls.append((name, arguments))
            return {"message": "Parser request completed."}

    receipt = await SplValidationAdapter().preflight(
        validation_task(tmp_path),
        AmbiguousParser(),
    )

    assert receipt["status"] == "advisory-only"
    assert receipt["parser"]["status"] == "inconclusive"


def test_result_shape_receipt_contains_structure_but_no_raw_values(tmp_path):
    task = validation_task(tmp_path)

    matched = SplValidationAdapter.compare_result_shape(
        task,
        [{"event_count": 7, "_raw": "secret-canary"}],
    )

    assert matched["status"] == "matched"
    assert matched["observed_fields"] == ["_raw", "event_count"]
    assert matched["field_types"] == {"_raw": ["string"], "event_count": ["integer"]}
    assert matched["raw_values_included"] is False
    assert "secret-canary" not in json.dumps(matched)

    missing = SplValidationAdapter.compare_result_shape(task, [{"count": 7}])
    assert missing["status"] == "mismatch"
    assert missing["missing_fields"] == ["event_count"]

    empty = SplValidationAdapter.compare_result_shape(task, [])
    assert empty["status"] == "inconclusive-zero-rows"
