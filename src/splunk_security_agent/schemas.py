from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

InvestigationMode = Literal[
    "auto", "general", "discovery", "detection", "hunt", "triage", "spl", "brief"
]


class SplunkConnection(BaseModel):
    name: str = "Primary Splunk"
    url: str = ""
    verify_ssl: bool = True
    ca_bundle: str | None = None


class ModelProfile(BaseModel):
    id: str
    label: str
    provider: Literal["ollama", "huggingface"]
    model: str
    task: Literal[
        "chat", "security_reasoning", "embedding", "ner", "reranking", "classification"
    ] = "chat"
    endpoint: str = ""
    enabled: bool = True
    description: str = ""
    provenance: str = ""
    context_window: int = 8192


class AppSettings(BaseModel):
    configured: bool = False
    splunk: SplunkConnection = Field(default_factory=SplunkConnection)
    models: list[ModelProfile] = Field(default_factory=list)
    default_chat_model: str = "ollama-general"
    security_reasoning_model: str = "foundation-sec"
    embedding_model: str = "securebert-embed"
    reranker_model: str = "securebert-rerank"
    ner_model: str = "securebert-ner"
    specialist_runtime: Literal["local", "cloud"] = "local"
    huggingface_policy: Literal["disabled", "ask", "allow"] = "disabled"
    allow_write_tools: bool = False
    max_agent_steps: int = 4
    demo_mode: bool = False


class SettingsUpdate(BaseModel):
    settings: AppSettings
    splunk_token: str | None = None
    huggingface_token: str | None = None


class ConnectionTestRequest(BaseModel):
    kind: Literal["splunk", "model"]
    profile_id: str | None = None
    splunk: SplunkConnection | None = None
    splunk_token: str | None = None
    demo_mode: bool | None = None


class ModelPullRequest(BaseModel):
    profile_id: str


class ModelActivateRequest(BaseModel):
    profile_id: str
    unload_other_signalroom_models: bool = True


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20000)
    conversation_id: str | None = None
    model_profile: str | None = None
    include_context: bool = True
    huggingface_approved: bool = False
    huggingface_specialist: Literal["embedding", "ner"] | None = None
    execute_searches: bool = True
    mode: InvestigationMode = "auto"


class EvidenceRef(BaseModel):
    id: str
    source: str
    title: str
    excerpt: str
    score: float = 0
    kind: str = "context"


class LedgerAction(BaseModel):
    id: str
    label: str
    kind: Literal["prompt", "artifact", "context-search", "discovery"] = "prompt"
    mode: InvestigationMode = "auto"
    prompt: str = ""
    target: str = ""


class EvidenceLedgerEntry(BaseModel):
    id: str
    classification: Literal["observation", "context", "hypothesis", "gap"]
    statement: str
    source: str
    confidence: Literal["high", "medium", "low"] = "medium"
    status: Literal["observed", "unverified", "needs-validation"] = "unverified"
    why: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    actions: list[LedgerAction] = Field(default_factory=list)


class AgentTrace(BaseModel):
    step: int
    kind: Literal["route", "tool", "model", "guardrail", "context"]
    label: str
    detail: str = ""
    status: Literal["pending", "running", "complete", "error"] = "complete"


class ModelRecommendation(BaseModel):
    id: str
    profile_id: str
    label: str
    model: str
    specialist: Literal["chat", "embedding", "ner"]
    purpose: str
    expected_result: str
    reason: str
    external: bool = False
    availability: Literal[
        "ready", "approval-required", "disabled", "unavailable", "install-required"
    ] = "ready"
    action_label: str
    prompt: str
    mode: InvestigationMode = "auto"


class EntityPivot(BaseModel):
    id: str
    value: str
    entity_type: str
    confidence: float = 1.0
    source: Literal["deterministic", "local-transformers", "hosted-transformers"] = (
        "deterministic"
    )
    prompt: str
    mode: InvestigationMode = "triage"


class ResultEnrichment(BaseModel):
    status: Literal["complete", "partial", "not-needed"] = "not-needed"
    runtime: str = "deterministic"
    summary: str = ""
    entities: list[EntityPivot] = Field(default_factory=list)
    context_matches: list[EvidenceRef] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ChatResponse(BaseModel):
    conversation_id: str
    message: str
    model: str
    route: str
    model_profile: str = ""
    requested_model: str = ""
    model_activation: dict[str, Any] = Field(default_factory=dict)
    mode: InvestigationMode = "auto"
    evidence: list[EvidenceRef] = Field(default_factory=list)
    ledger: list[EvidenceLedgerEntry] = Field(default_factory=list)
    trace: list[AgentTrace] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    suggested_actions: list[str] = Field(default_factory=list)
    model_recommendations: list[ModelRecommendation] = Field(default_factory=list)
    enrichment: ResultEnrichment = Field(default_factory=ResultEnrichment)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ArtifactCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    content: str = Field(min_length=1, max_length=2_000_000)
    kind: str = "reference"
    tags: list[str] = Field(default_factory=list)
    source: str = Field(default="operator", max_length=240)


class ArtifactUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    content: str | None = Field(default=None, min_length=1, max_length=2_000_000)
    kind: str | None = None
    tags: list[str] | None = None
    source: str | None = Field(default=None, max_length=240)


class ArtifactRecord(BaseModel):
    id: str
    title: str
    kind: str
    source: str
    tags: list[str]
    content: str
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DiscoveryRequest(BaseModel):
    depth: Literal["quick", "standard", "deep"] = "standard"


ValidationStatus = Literal["draft", "approved", "running", "complete", "error"]


class ValidationTaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    rationale: str = Field(min_length=1, max_length=4000)
    spl: str = Field(min_length=1, max_length=20000)
    earliest_time: str = Field(default="-24h", min_length=2, max_length=64)
    latest_time: str = Field(default="now", min_length=1, max_length=64)
    row_limit: int = Field(default=100, ge=1, le=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    source_run_id: str = Field(default="", max_length=120)
    source_finding_ref: str = Field(default="", max_length=40)
    case_id: str | None = Field(default=None, max_length=120)


class ValidationTaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    rationale: str | None = Field(default=None, min_length=1, max_length=4000)
    spl: str | None = Field(default=None, min_length=1, max_length=20000)
    earliest_time: str | None = Field(default=None, min_length=2, max_length=64)
    latest_time: str | None = Field(default=None, min_length=1, max_length=64)
    row_limit: int | None = Field(default=None, ge=1, le=500)
    evidence_refs: list[str] | None = Field(default=None, max_length=16)
    case_id: str | None = Field(default=None, max_length=120)


class ValidationTaskRecord(ValidationTaskCreate):
    id: str
    status: ValidationStatus
    query_fingerprint: str
    result_count: int = 0
    result_preview: list[Any] = Field(default_factory=list)
    artifact_id: str = ""
    error: str = ""
    approved_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    created_at: str
    updated_at: str


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


CaseStatus = Literal["open", "investigating", "contained", "monitoring", "closed"]
CaseSeverity = Literal["informational", "low", "medium", "high", "critical"]
CaseItemKind = Literal[
    "observation", "context", "hypothesis", "note", "action", "decision", "evidence"
]


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(default="", max_length=10000)
    severity: CaseSeverity = "medium"
    owner: str = Field(default="Unassigned", max_length=160)
    tags: list[str] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    summary: str | None = Field(default=None, max_length=10000)
    status: CaseStatus | None = None
    severity: CaseSeverity | None = None
    owner: str | None = Field(default=None, max_length=160)
    tags: list[str] | None = None


class CaseItemCreate(BaseModel):
    kind: CaseItemKind
    title: str = Field(min_length=1, max_length=240)
    content: str = Field(min_length=1, max_length=50000)
    source: str = Field(default="analyst", max_length=240)
    confidence: Literal["high", "medium", "low", "unknown"] = "unknown"
    status: Literal["observed", "unverified", "needs-validation", "complete"] = "unverified"
    occurred_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseItemUpdate(BaseModel):
    kind: CaseItemKind | None = None
    title: str | None = Field(default=None, min_length=1, max_length=240)
    content: str | None = Field(default=None, min_length=1, max_length=50000)
    source: str | None = Field(default=None, max_length=240)
    confidence: Literal["high", "medium", "low", "unknown"] | None = None
    status: Literal["observed", "unverified", "needs-validation", "complete"] | None = None
    occurred_at: str | None = None
    metadata: dict[str, Any] | None = None


class CaseItemRecord(CaseItemCreate):
    id: str
    case_id: str
    created_at: str


class CaseRecord(BaseModel):
    id: str
    title: str
    summary: str
    status: CaseStatus
    severity: CaseSeverity
    owner: str
    tags: list[str]
    created_at: str
    updated_at: str
    item_count: int = 0
    items: list[CaseItemRecord] = Field(default_factory=list)


class CaseExportRequest(BaseModel):
    formats: list[Literal["markdown", "json"]] = Field(default_factory=lambda: ["markdown", "json"])
