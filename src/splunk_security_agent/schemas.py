from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

InvestigationMode = Literal["auto", "general", "discovery", "detection", "hunt", "triage", "spl", "brief"]


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
    task: Literal["chat", "security_reasoning", "embedding", "ner", "reranking", "classification"] = "chat"
    endpoint: str = ""
    enabled: bool = True
    description: str = ""
    provenance: str = ""
    context_window: int = 8192
    max_output_tokens: int | None = Field(default=None, ge=64, le=8192)


class DetectionRepositorySettings(BaseModel):
    enabled: bool = False
    path: str = Field(default="", max_length=4000)
    base_ref: str = Field(default="main", min_length=1, max_length=240)
    branch_prefix: str = Field(default="signalroom/", min_length=1, max_length=120)
    remote_name: str = Field(default="origin", min_length=1, max_length=120)
    commit_author_name: str = Field(
        default="SignalRoom Detection Engineering",
        min_length=1,
        max_length=160,
    )
    commit_author_email: str = Field(
        default="signalroom@localhost",
        min_length=3,
        max_length=320,
    )
    allow_push: bool = False
    allow_draft_pull_request: bool = False


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
    detection_repository: DetectionRepositorySettings = Field(default_factory=DetectionRepositorySettings)


class SettingsUpdate(BaseModel):
    settings: AppSettings
    splunk_token: str | None = None
    huggingface_token: str | None = None


AccessRole = Literal["viewer", "analyst", "admin"]


class AuthLoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class AuthBootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=1024)


class AuthDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class AuthUserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    role: AccessRole = "analyst"
    password: str = Field(min_length=12, max_length=1024)
    connection_ids: list[str] = Field(default_factory=lambda: ["primary"], max_length=16)


class AuthUserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: AccessRole | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    active: bool | None = None
    connection_ids: list[str] | None = Field(default=None, max_length=16)


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


class ModelTrustPolicyUpdate(BaseModel):
    mode: Literal["audit", "enforce"] = "audit"
    allowed_publishers: list[str] = Field(
        default_factory=lambda: ["cisco-ai", "fdtn-ai", "ollama-library"],
        min_length=1,
        max_length=50,
    )


class ModelArtifactApproval(BaseModel):
    expected_fingerprint: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )


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
    availability: Literal["ready", "approval-required", "disabled", "unavailable", "install-required"] = (
        "ready"
    )
    action_label: str
    prompt: str
    mode: InvestigationMode = "auto"


class EntityPivot(BaseModel):
    id: str
    value: str
    entity_type: str
    confidence: float = 1.0
    source: Literal["deterministic", "local-transformers", "hosted-transformers"] = "deterministic"
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


FeedbackRating = Literal["useful", "incorrect", "missing-evidence", "false-positive", "corrected"]


class AnalystFeedbackCreate(BaseModel):
    target_type: Literal["chat", "discovery", "validation", "case"]
    target_id: str = Field(min_length=1, max_length=240)
    task_type: str = Field(default="general", max_length=80)
    rating: FeedbackRating
    model_profile: str = Field(default="", max_length=160)
    model: str = Field(default="", max_length=500)
    route: str = Field(default="", max_length=160)
    note: str = Field(default="", max_length=4000)
    correction: str = Field(default="", max_length=10000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GoldenBenchmarkRunCreate(BaseModel):
    profile_id: str = Field(min_length=1, max_length=160)
    suite_id: str = Field(default="builtin-core", min_length=1, max_length=160)


EvaluationToolName = Literal[
    "get_info",
    "get_indexes",
    "get_metadata",
    "get_knowledge_objects",
    "run_query",
]


class EvaluationScenario(BaseModel):
    id: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
    )
    title: str = Field(min_length=3, max_length=240)
    task_type: str = Field(min_length=1, max_length=80)
    mode: Literal["general", "discovery", "detection", "hunt", "triage", "spl", "brief"]
    message: str = Field(min_length=3, max_length=4000)
    fixture_title: str = Field(min_length=3, max_length=240)
    fixture_content: str = Field(min_length=3, max_length=20000)
    expected_tools: list[EvaluationToolName] = Field(default_factory=list, max_length=5)
    forbidden_tools: list[EvaluationToolName] = Field(default_factory=list, max_length=5)
    evidence_groups: list[list[str]] = Field(min_length=1, max_length=12)
    conclusion_groups: list[list[str]] = Field(min_length=1, max_length=12)
    forbidden_claims: list[str] = Field(default_factory=list, max_length=20)
    expected_blocked: bool = False


class EvaluationSuiteCreate(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=4000)
    scenarios: list[EvaluationScenario] = Field(default_factory=list, max_length=15)


class EvaluationSuiteUpdate(BaseModel):
    expected_draft_revision: int = Field(ge=1)
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=4000)
    scenarios: list[EvaluationScenario] = Field(default_factory=list, max_length=15)


class EvaluationSuitePublishRequest(BaseModel):
    expected_draft_revision: int = Field(ge=1)
    expected_fingerprint: str = Field(min_length=64, max_length=64)
    synthetic_data_confirmed: bool


class EvaluationSuiteArchiveRequest(BaseModel):
    archived: bool = True


ModelAssignmentTarget = Literal["default_chat_model", "security_reasoning_model"]


class ModelTournamentRunCreate(BaseModel):
    profile_ids: list[str] = Field(min_length=2, max_length=8)
    target: ModelAssignmentTarget = "security_reasoning_model"
    suite_id: str = Field(default="builtin-core", min_length=1, max_length=160)


class ModelTournamentReviewRequest(BaseModel):
    pair_id: str = Field(min_length=1, max_length=160)
    choice: Literal["a", "b", "tie"]


class ModelTournamentPromotionRequest(BaseModel):
    profile_id: str = Field(min_length=1, max_length=160)
    fingerprint: str = Field(min_length=64, max_length=64)


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


DiscoveryJobStatus = Literal[
    "queued",
    "running",
    "complete",
    "partial",
    "error",
    "cancelled",
    "budget-blocked",
    "connection-blocked",
]


class DiscoveryJobRecord(BaseModel):
    id: str
    depth: Literal["quick", "standard", "deep"]
    requested_by: str = "local-operator"
    status: DiscoveryJobStatus
    phase: str = "queued"
    progress: int = 0
    label: str = "Queued"
    detail: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    result_run_id: str = ""
    error: str = ""
    call_budget: int = 0
    calls_used: int = 0
    cancel_requested: bool = False
    recovery_count: int = 0
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    updated_at: str


AssuranceDepth = Literal["quick", "standard", "deep"]
AssuranceRunStatus = Literal[
    "queued",
    "running",
    "complete",
    "partial",
    "error",
    "cancelled",
    "budget-blocked",
    "connection-blocked",
]


class AssurancePolicyUpdate(BaseModel):
    enabled: bool = False
    interval_minutes: int = Field(default=360, ge=15, le=10080)
    discovery_depth: AssuranceDepth = "standard"
    max_splunk_calls_per_run: int = Field(default=12, ge=4, le=50)
    max_runs_per_day: int = Field(default=4, ge=1, le=48)
    notify_on_drift: bool = True
    notify_on_high_findings: bool = True


class WorkloadPolicyUpdate(BaseModel):
    mode: Literal["audit", "enforce"] = "audit"
    max_concurrent_calls: int = Field(default=6, ge=1, le=32)
    max_concurrent_queries: int = Field(default=2, ge=1, le=16)
    queue_timeout_seconds: int = Field(default=60, ge=5, le=600)
    max_query_risk_score: int = Field(default=70, ge=10, le=100)
    max_query_cost_units: int = Field(default=90, ge=10, le=100)
    daily_query_cost_units: int = Field(default=1000, ge=50, le=100000)


class AuditExportPolicyUpdate(BaseModel):
    enabled: bool = False
    index_name: str = Field(
        default="signalroom_audit",
        min_length=2,
        max_length=80,
        pattern=r"^[A-Za-z][A-Za-z0-9_-]+$",
    )
    sourcetype: str = Field(default="signalroom:audit", min_length=1, max_length=160)
    source: str = Field(default="signalroom:audit", min_length=1, max_length=240)
    host: str = Field(default="signalroom", min_length=1, max_length=240)
    verify_tls: bool = True
    ca_bundle: str | None = Field(default=None, max_length=1000)
    use_indexer_ack: bool = False
    batch_size: int = Field(default=25, ge=1, le=100)
    max_attempts: int = Field(default=5, ge=1, le=12)
    retry_backoff_seconds: int = Field(default=30, ge=10, le=3600)
    backfill_existing: bool = False
    hec_url: str | None = Field(default=None, max_length=4000)
    hec_token: str | None = Field(default=None, max_length=4000)
    clear_hec_url: bool = False
    clear_hec_token: bool = False


class AssuranceRunCreate(BaseModel):
    depth: AssuranceDepth | None = None


class AssuranceRunRecord(BaseModel):
    id: str
    trigger: Literal["manual", "scheduled", "recovered"]
    depth: AssuranceDepth
    status: AssuranceRunStatus
    phase: str = "queued"
    progress: int = 0
    label: str = "Queued"
    detail: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    call_budget: int = 0
    calls_used: int = 0
    cancel_requested: bool = False
    recovery_count: int = 0
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    updated_at: str


DeliverySignalKind = Literal["finding", "coverage", "inventory", "mltk", "collection"]
DeliverySeverity = Literal["low", "medium", "high", "critical"]
DeliveryDestinationKind = Literal["generic-webhook", "slack-incoming-webhook", "jira-cloud", "splunk-soar"]


class DeliveryPolicyUpdate(BaseModel):
    enabled: bool = False
    mode: Literal["manual", "automatic"] = "manual"
    destination_kind: DeliveryDestinationKind = "generic-webhook"
    minimum_severity: DeliverySeverity = "high"
    signal_kinds: list[DeliverySignalKind] = Field(
        default_factory=lambda: ["finding", "coverage", "inventory", "mltk", "collection"],
        min_length=1,
        max_length=5,
    )
    redaction_level: Literal["strict", "standard"] = "strict"
    destination_label: str = Field(default="Primary webhook", min_length=1, max_length=160)
    verify_tls: bool = True
    ca_bundle: str | None = Field(default=None, max_length=1000)
    max_attempts: int = Field(default=3, ge=1, le=8)
    retry_backoff_seconds: int = Field(default=60, ge=10, le=3600)
    webhook_url: str | None = Field(default=None, max_length=4000)
    authorization_header: str | None = Field(default=None, max_length=4000)
    clear_webhook_url: bool = False
    clear_authorization_header: bool = False
    jira_project_key: str = Field(default="", max_length=32)
    jira_issue_type: str = Field(default="Task", min_length=1, max_length=120)
    jira_summary_prefix: str = Field(default="[SignalRoom]", max_length=80)
    jira_labels: list[str] = Field(
        default_factory=lambda: ["signalroom", "security-assurance"],
        max_length=12,
    )
    jira_priority_map: dict[DeliverySeverity, str] = Field(
        default_factory=lambda: {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        },
        max_length=4,
    )
    jira_email: str | None = Field(default=None, max_length=320)
    jira_api_token: str | None = Field(default=None, max_length=4000)
    clear_jira_email: bool = False
    clear_jira_api_token: bool = False
    soar_label: str = Field(default="events", min_length=1, max_length=120)
    soar_container_type: Literal["default", "case"] = "default"
    soar_status: str = Field(default="new", min_length=1, max_length=120)
    soar_name_prefix: str = Field(default="[SignalRoom]", max_length=80)
    soar_sensitivity: Literal["red", "amber", "green", "white"] = "amber"
    soar_tags: list[str] = Field(
        default_factory=lambda: ["signalroom", "security-assurance"],
        max_length=12,
    )
    soar_severity_map: dict[DeliverySeverity, str] = Field(
        default_factory=lambda: {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
        },
        max_length=4,
    )
    soar_tenant_id: str = Field(default="", max_length=120)
    soar_auth_token: str | None = Field(default=None, max_length=4000)
    clear_soar_auth_token: bool = False


class DeliveryApproval(BaseModel):
    expected_payload_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


ValidationStatus = Literal["draft", "approved", "running", "complete", "error", "expired"]


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
    expires_at: str | None = None
    assurance_package_id: str = Field(default="", max_length=120)
    approval_scope: Literal["single-execution"] = "single-execution"


class ValidationTaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    rationale: str | None = Field(default=None, min_length=1, max_length=4000)
    spl: str | None = Field(default=None, min_length=1, max_length=20000)
    earliest_time: str | None = Field(default=None, min_length=2, max_length=64)
    latest_time: str | None = Field(default=None, min_length=1, max_length=64)
    row_limit: int | None = Field(default=None, ge=1, le=500)
    evidence_refs: list[str] | None = Field(default=None, max_length=16)
    case_id: str | None = Field(default=None, max_length=120)


class QueryIntelligenceRequest(BaseModel):
    spl: str = Field(min_length=1, max_length=20000)
    earliest_time: str = Field(default="-24h", min_length=2, max_length=64)
    latest_time: str = Field(default="now", min_length=1, max_length=64)
    row_limit: int = Field(default=100, ge=1, le=500)
    exclude_task_id: str = Field(default="", max_length=120)


DetectionSeverity = Literal["informational", "low", "medium", "high", "critical"]


class DetectionCreate(BaseModel):
    validation_task_id: str = Field(min_length=1, max_length=120)
    case_id: str | None = Field(default=None, max_length=120)
    title: str = Field(default="", max_length=240)
    description: str = Field(default="", max_length=10000)
    owner: str = Field(default="Unassigned", max_length=160)
    severity: DetectionSeverity = "medium"
    security_domain: str = Field(default="threat", max_length=120)
    cron_schedule: str = Field(default="*/5 * * * *", min_length=9, max_length=120)
    throttle_seconds: int = Field(default=3600, ge=0, le=86400)
    tags: list[str] = Field(default_factory=list, max_length=32)
    mitre_attack: list[str] = Field(default_factory=list, max_length=32)


class DetectionUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=10000)
    search: str | None = Field(default=None, min_length=1, max_length=20000)
    owner: str | None = Field(default=None, max_length=160)
    severity: DetectionSeverity | None = None
    security_domain: str | None = Field(default=None, max_length=120)
    cron_schedule: str | None = Field(default=None, min_length=9, max_length=120)
    earliest_time: str | None = Field(default=None, min_length=2, max_length=64)
    latest_time: str | None = Field(default=None, min_length=1, max_length=64)
    throttle_seconds: int | None = Field(default=None, ge=0, le=86400)
    tags: list[str] | None = Field(default=None, max_length=32)
    mitre_attack: list[str] | None = Field(default=None, max_length=32)
    expected_result: Literal["any", "zero", "nonzero"] | None = None
    required_fields: list[str] | None = Field(default=None, max_length=32)
    validation_row_limit: int | None = Field(default=None, ge=1, le=500)
    max_result_count: int | None = Field(default=None, ge=0, le=10_000_000)
    max_count_delta_percent: int | None = Field(default=None, ge=0, le=10_000)


class DetectionReviewRequest(BaseModel):
    decision: Literal["approve", "request-changes"]
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    reviewer: str = Field(default="Local reviewer", min_length=1, max_length=160)
    note: str = Field(default="", max_length=10000)


class DetectionExportRequest(BaseModel):
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionGitExportRequest(BaseModel):
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionRepositoryPreviewRequest(BaseModel):
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionRepositoryApprovalRequest(BaseModel):
    expected_preview_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionRepositoryRemoteRequest(BaseModel):
    expected_commit_sha: str = Field(min_length=40, max_length=64, pattern=r"^[0-9a-f]{40,64}$")


class DetectionRepositoryReviewRequest(BaseModel):
    expected_commit_sha: str = Field(min_length=40, max_length=64, pattern=r"^[0-9a-f]{40,64}$")


class DetectionRepositoryCaseRequest(BaseModel):
    expected_snapshot_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionDeploymentRefreshRequest(BaseModel):
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    target_app: str = Field(
        default="",
        max_length=160,
        pattern=r"^[A-Za-z0-9_.-]*$",
    )


class DetectionDeploymentCaseRequest(BaseModel):
    expected_snapshot_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionRuntimeDraftRequest(BaseModel):
    expected_snapshot_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    earliest_time: str = Field(default="", max_length=64)
    max_lag_seconds: int | None = Field(
        default=None,
        ge=60,
        le=30 * 24 * 60 * 60,
    )


class DetectionRuntimeAssessmentRequest(BaseModel):
    expected_runtime_check_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionRuntimeCaseRequest(BaseModel):
    expected_assessment_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionRepositoryTestRequest(BaseModel):
    settings: DetectionRepositorySettings


class DetectionGateRunRequest(BaseModel):
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class DetectionValidationDraftRequest(BaseModel):
    expected_content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


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
CaseItemKind = Literal["observation", "context", "hypothesis", "note", "action", "decision", "evidence"]


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
