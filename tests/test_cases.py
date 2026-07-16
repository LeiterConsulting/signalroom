from __future__ import annotations

import json

from splunk_security_agent.cases import CaseStore
from splunk_security_agent.schemas import (
    CaseCreate,
    CaseItemCreate,
    CaseItemUpdate,
    CaseUpdate,
)


def test_case_lifecycle_persists_timeline_and_metadata(tmp_path):
    database = tmp_path / "cases.db"
    exports = tmp_path / "exports"
    store = CaseStore(database, exports)

    case = store.create(
        CaseCreate(
            title="Synthetic identity investigation",
            summary="Validate an unusual authentication pattern.",
            severity="high",
            owner="Night SOC",
            tags=["identity", "synthetic", "identity"],
        )
    )
    assert case.status == "open"
    assert case.tags == ["identity", "synthetic"]

    observation = store.add_item(
        case.id,
        CaseItemCreate(
            kind="observation",
            title="Authentication outlier observed",
            content="A synthetic read-only search returned an unusual count.",
            source="Splunk MCP",
            confidence="medium",
            status="needs-validation",
            occurred_at="2026-07-16T10:00:00+00:00",
            metadata={"search_id": "synthetic-1"},
        ),
    )
    note = store.add_item(
        case.id,
        CaseItemCreate(
            kind="note",
            title="Shift handoff note",
            content="Confirm the user's expected travel before escalation.",
            status="unverified",
        ),
    )
    assert observation is not None
    assert note is not None

    updated = store.update(
        case.id,
        CaseUpdate(status="investigating", owner="Day SOC", severity="critical"),
    )
    assert updated is not None
    assert updated.status == "investigating"
    assert updated.owner == "Day SOC"
    assert updated.severity == "critical"

    reopened = CaseStore(database, exports).get(case.id)
    assert reopened is not None
    assert reopened.item_count == 2
    assert [item.title for item in reopened.items] == [
        "Authentication outlier observed",
        "Shift handoff note",
    ]
    assert reopened.items[0].metadata == {"search_id": "synthetic-1"}


def test_case_item_deletion_and_handoff_exports(tmp_path):
    store = CaseStore(tmp_path / "cases.db", tmp_path / "exports")
    case = store.create(CaseCreate(title="Synthetic case", summary="Synthetic summary"))
    item = store.add_item(
        case.id,
        CaseItemCreate(
            kind="decision",
            title="Continue monitoring",
            content="No containment action is justified by current synthetic evidence.",
            status="complete",
        ),
    )
    assert item is not None

    paths = store.export(case.id, ["markdown", "json"])
    markdown = next(path for path in paths if path.suffix == ".md").read_text(encoding="utf-8")
    payload = json.loads(next(path for path in paths if path.suffix == ".json").read_text())
    assert "# Synthetic case" in markdown
    assert "## Investigation timeline" in markdown
    assert "Continue monitoring" in markdown
    assert "> No containment action is justified" in markdown
    assert payload["items"][0]["kind"] == "decision"

    assert store.delete_item(case.id, item.id) is True
    assert store.delete_item(case.id, item.id) is False
    reopened = store.get(case.id)
    assert reopened is not None
    assert reopened.item_count == 0


def test_case_and_timeline_items_can_be_updated_and_deleted(tmp_path):
    store = CaseStore(tmp_path / "cases.db", tmp_path / "exports")
    case = store.create(CaseCreate(title="Initial title"))
    item = store.add_item(
        case.id,
        CaseItemCreate(kind="note", title="Initial note", content="Needs revision"),
    )
    assert item is not None

    updated_case = store.update(case.id, CaseUpdate(title="Revised title"))
    updated_item = store.update_item(
        case.id,
        item.id,
        CaseItemUpdate(
            kind="decision",
            title="Validated decision",
            content="Continue monitoring.",
            status="complete",
        ),
    )

    assert updated_case is not None
    assert updated_case.title == "Revised title"
    assert updated_item is not None
    assert updated_item.kind == "decision"
    assert updated_item.status == "complete"
    assert store.delete(case.id) is True
    assert store.delete(case.id) is False
    assert store.get(case.id) is None
    assert store.update_item(case.id, item.id, CaseItemUpdate(title="Missing")) is None
