from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from ..rag import EvidenceStore
from .store import CaseStore


class CaseCockpitService:
    """Build a bounded, evidence-linked operating view for an investigation case."""

    def __init__(
        self,
        cases: CaseStore,
        validations: Any,
        evidence: EvidenceStore,
    ):
        self.cases = cases
        self.validations = validations
        self.evidence = evidence

    def build(self, case_id: str) -> dict[str, Any] | None:
        case = self.cases.get(case_id)
        if case is None:
            return None
        items = case.items
        validations = [task for task in self.validations.list(500) if task.case_id == case_id]
        referenced_validation_ids = {
            str(value)
            for item in items
            for value in self._metadata_values(item.metadata, "validation_task_ids")
        }
        validations.extend(
            task
            for task in self.validations.list(500)
            if task.id in referenced_validation_ids and task not in validations
        )

        by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in items:
            by_kind[item.kind].append(item.model_dump(mode="json"))
        open_items = [item for item in items if item.status not in {"observed", "complete"}]
        evidence_refs = sorted(
            {
                str(value)
                for item in items
                for key in ("artifact_id", "evidence_refs")
                for value in self._metadata_values(item.metadata, key)
                if value
            }
        )
        known_artifacts = {artifact.id for artifact in self.evidence.list(limit=1000)}
        available_refs = [ref for ref in evidence_refs if ref in known_artifacts]
        title_states: dict[str, set[str]] = defaultdict(set)
        title_examples: dict[str, str] = {}
        for item in items:
            key = re.sub(r"[^a-z0-9]+", " ", item.title.lower()).strip()
            if key:
                title_states[key].add(item.status)
                title_examples[key] = item.title
        tensions = [
            {
                "title": title_examples[key],
                "statuses": sorted(states),
                "detail": "This claim appears in both established and unresolved states.",
            }
            for key, states in title_states.items()
            if states.intersection({"observed", "complete"})
            and states.intersection({"unverified", "needs-validation"})
        ]
        validation_counts = Counter(task.status for task in validations)
        next_actions = self._next_actions(case, open_items, validations, tensions)
        packet = self._context_packet(case, open_items, validations, tensions)
        return {
            "case_id": case.id,
            "generated_from_updated_at": case.updated_at,
            "health": {
                "observations": len(by_kind["observation"]) + len(by_kind["evidence"]),
                "open_hypotheses": len(
                    [item for item in by_kind["hypothesis"] if item["status"] != "complete"]
                ),
                "unresolved_items": len(open_items),
                "decisions": len(by_kind["decision"]),
                "linked_validations": len(validations),
                "linked_artifacts": len(evidence_refs),
                "available_artifacts": len(available_refs),
                "tensions": len(tensions),
            },
            "buckets": dict(by_kind),
            "open_items": [item.model_dump(mode="json") for item in open_items],
            "validations": [task.model_dump(mode="json") for task in validations],
            "validation_counts": dict(validation_counts),
            "evidence_refs": evidence_refs,
            "available_evidence_refs": available_refs,
            "tensions": tensions,
            "next_actions": next_actions,
            "context_packet": packet,
        }

    @staticmethod
    def _metadata_values(metadata: dict[str, Any], key: str) -> list[Any]:
        value = metadata.get(key)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _next_actions(case: Any, open_items: list[Any], validations: list[Any], tensions: list[Any]):
        actions: list[dict[str, Any]] = []
        drafts = [task for task in validations if task.status in {"draft", "error"}]
        if drafts:
            task = drafts[0]
            actions.append(
                {
                    "kind": "review-validation",
                    "label": f"Review validation: {task.title}",
                    "reason": "A case-linked SPL draft is waiting for explicit analyst approval.",
                    "validation_task_id": task.id,
                }
            )
        if tensions:
            actions.append(
                {
                    "kind": "investigate",
                    "label": f"Resolve conflicting status: {tensions[0]['title']}",
                    "reason": tensions[0]["detail"],
                    "prompt": (
                        f"Resolve the evidence tension around '{tensions[0]['title']}'. Identify the "
                        "source of each claim and propose the smallest read-only validation."
                    ),
                }
            )
        if open_items:
            item = open_items[0]
            actions.append(
                {
                    "kind": "investigate",
                    "label": f"Advance: {item.title}",
                    "reason": f"This {item.kind} remains {item.status}.",
                    "case_item_id": item.id,
                    "prompt": (
                        f"Advance the unresolved case item '{item.title}'. Separate current evidence "
                        "from assumptions and recommend the minimum bounded next check."
                    ),
                }
            )
        if not case.summary.strip():
            actions.append(
                {
                    "kind": "investigate",
                    "label": "Draft an evidence-bounded executive summary",
                    "reason": "The case has no handoff summary.",
                    "prompt": "Draft a concise case summary using only observed or completed evidence.",
                }
            )
        if not actions:
            actions.append(
                {
                    "kind": "investigate",
                    "label": "Review closure readiness",
                    "reason": "No unresolved timeline items or validation drafts remain.",
                    "prompt": (
                        "Assess whether this case is ready to close. List residual risk, evidence gaps, "
                        "and any monitoring commitment."
                    ),
                }
            )
        return actions[:4]

    @staticmethod
    def _context_packet(case: Any, open_items: list[Any], validations: list[Any], tensions: list[Any]):
        lines = [
            f"Case {case.id}: {case.title}",
            f"Status: {case.status} · Severity: {case.severity} · Owner: {case.owner}",
            f"Summary: {case.summary or 'No executive summary recorded.'}",
            "",
            "Open case items:",
        ]
        lines.extend(
            f"- [{item.kind}/{item.status}/{item.confidence}] {item.title}: {item.content[:700]}"
            for item in open_items[:10]
        )
        if not open_items:
            lines.append("- None")
        lines.append("\nLinked validations:")
        lines.extend(
            f"- [{task.status}] {task.title} · {task.earliest_time} to {task.latest_time} · "
            f"fingerprint {task.query_fingerprint[:12]}"
            for task in validations[:8]
        )
        if not validations:
            lines.append("- None")
        if tensions:
            lines.append("\nEvidence tensions:")
            lines.extend(f"- {item['title']}: {', '.join(item['statuses'])}" for item in tensions[:5])
        lines.append(
            "\nUse this packet before requesting new SPL. Revalidate material claims in Splunk before action."
        )
        return "\n".join(lines)[:12000]
