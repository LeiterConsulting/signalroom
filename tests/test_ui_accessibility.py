import re
from pathlib import Path

STATIC_ROOT = Path(__file__).parents[1] / "src" / "splunk_security_agent" / "static"
INDEX_HTML = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
STYLES_CSS = (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")
APP_JS = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")


def test_switches_use_the_shared_accessible_control() -> None:
    switch_labels = len(re.findall(r'class="[^"]*\bswitch-line\b', INDEX_HTML))
    switch_controls = len(re.findall(r'class="switch-control"', INDEX_HTML))

    assert switch_labels > 0
    assert switch_controls == switch_labels
    assert ".switch-line input{display:none}" not in STYLES_CSS
    assert ".switch-line>.switch-control" in STYLES_CSS
    assert ".switch-line>input:focus-visible+.switch-control" in STYLES_CSS


def test_ui_uses_readable_system_type_scale() -> None:
    pixel_sizes = [
        int(value)
        for value in re.findall(r"(?:font-size:|font:[^;{}]*?)(\d+)px", STYLES_CSS)
    ]

    assert pixel_sizes
    assert min(pixel_sizes) >= 12


def test_mobile_navigation_keeps_accessible_names_and_discovery_contains_width() -> None:
    for label in (
        "Investigate",
        "Discovery",
        "Cases",
        "Detections",
        "Context",
        "Models",
        "Setup",
    ):
        assert f'aria-label="{label}"' in INDEX_HTML
    assert ".discovery-grid>*,.purpose-grid>*" in STYLES_CSS
    assert ".run-controls select,.run-controls .button" in STYLES_CSS
    assert "DM Mono" not in STYLES_CSS
    assert '"Segoe UI Variable Text"' in STYLES_CSS
    assert "--font-mono:" in STYLES_CSS


def test_discovery_presents_securebert_labels_as_validated_candidates() -> None:
    assert "Validated SecureBERT context" in APP_JS
    assert "Entity labels are candidates, not findings." in APP_JS
    assert "suppressed before synthesis and RAG" in APP_JS
    assert "<h4>SecureBERT enrichment</h4>" not in APP_JS


def test_delivery_exposes_adapter_semantics_before_approval() -> None:
    assert 'id="deliveryKind"' in INDEX_HTML
    assert 'value="slack-incoming-webhook"' in INDEX_HTML
    assert 'value="jira-cloud"' in INDEX_HTML
    assert 'value="splunk-soar"' in INDEX_HTML
    assert 'id="deliveryAdapterHelp"' in INDEX_HTML
    assert 'id="deliveryJiraFields"' in INDEX_HTML
    assert 'id="testDeliveryDestination"' in INDEX_HTML
    assert 'id="deliverySoarFields"' in INDEX_HTML
    assert 'id="testSoarDeliveryDestination"' in INDEX_HTML
    assert "reads container options and does not create a container" in INDEX_HTML
    assert "reads create metadata and does not create an issue" in INDEX_HTML
    assert 'id="deliveryWarnings"' in INDEX_HTML
    assert "Configure generic webhook policy" not in INDEX_HTML
    assert "Slack receives plain-text notification blocks only over verified TLS." in APP_JS
    assert "cannot update, transition, comment on, assign, attach to, or delete it" in APP_JS
    assert "explicitly disables automation, sends no artifacts" in APP_JS
    assert "Open correlated Splunk SOAR" in APP_JS
    assert "const usesDedicatedAuth = requiresPublicTls || isSoar" in APP_JS
    assert "$('#deliveryAuthorizationField').hidden = usesDedicatedAuth" in APP_JS
    assert "Open correlated Jira issue" in APP_JS
    assert "Refresh Jira status" in APP_JS
    assert "Explicit read only · minimal correlated issue fields" in APP_JS
    assert "Not found or not visible" in APP_JS
    assert "no issue mutation" in APP_JS
    assert "no SPL execution or validation approval" in APP_JS


def test_optional_rbac_is_visible_and_keyboard_operable() -> None:
    assert 'id="accessCard"' in INDEX_HTML
    assert 'id="loginModal"' in INDEX_HTML
    assert 'id="enterpriseLogin"' in INDEX_HTML
    assert 'id="oidcEnabled"' in INDEX_HTML
    assert 'id="oidcRequiredAmr"' in INDEX_HTML
    assert 'id="loginForm"' in INDEX_HTML
    assert 'id="accessControlSection"' in INDEX_HTML
    assert "Access control · optional" in INDEX_HTML
    assert "POC mode · RBAC off" in INDEX_HTML
    assert 'value="viewer"' in INDEX_HTML
    assert 'value="analyst"' in INDEX_HTML
    assert 'value="admin"' in INDEX_HTML
    assert 'id="newAuthConnections"' in INDEX_HTML
    assert 'id="managedSplunkForm"' in INDEX_HTML
    assert 'id="managedSplunkVerifyTls"' in INDEX_HTML
    assert "X-SignalRoom-CSRF" in APP_JS
    assert "await loadAuthStatus()" in APP_JS
    assert "if (state.auth.enabled && !state.auth.authenticated) return" in APP_JS
    assert ".access-user-controls" in STYLES_CSS


def test_model_artifact_trust_is_explicit_and_audit_first() -> None:
    assert 'id="modelTrustPanel"' in INDEX_HTML
    assert 'id="modelTrustPolicyForm"' in INDEX_HTML
    assert '<option value="audit">Audit only</option>' in INDEX_HTML
    assert "Approve exact artifact" in APP_JS
    assert "future digest or revision change" in APP_JS
    assert "publisher signature or a software-vulnerability verdict" in INDEX_HTML
    assert "[data-approve-model-artifact]" in APP_JS
    assert ".model-trust-card.approved" in STYLES_CSS


def test_splunk_workload_policy_is_explainable_and_audit_first() -> None:
    assert 'id="workloadPolicySection"' in INDEX_HTML
    assert '<option value="audit">Audit only' in INDEX_HTML
    assert '<option value="enforce">Enforce' in INDEX_HTML
    assert 'id="workloadConcurrentCalls"' in INDEX_HTML
    assert 'id="workloadConcurrentQueries"' in INDEX_HTML
    assert "not predicted scan bytes or Splunk scheduler cost" in INDEX_HTML
    assert "async function loadWorkload()" in APP_JS
    assert "query-workload" in APP_JS
    assert ".workload-mode-banner" in STYLES_CSS


def test_operator_evaluation_suites_expose_safe_versioned_authoring() -> None:
    assert 'id="evaluationSuiteGrid"' in INDEX_HTML
    assert 'id="evaluationSuiteModal"' in INDEX_HTML
    assert 'id="evaluationSyntheticConfirmed"' in INDEX_HTML
    assert 'id="goldenSuite"' in INDEX_HTML
    assert 'id="tournamentSuite"' in INDEX_HTML
    assert "The five built-in safety controls always run first" in INDEX_HTML
    assert "configured Splunk and hosted inference are never contacted" in INDEX_HTML
    assert "expected_draft_revision" in APP_JS
    assert "expected_fingerprint" in APP_JS
    assert ".evaluation-suite-card.builtin" in STYLES_CSS


def test_investigation_columns_scroll_independently() -> None:
    assert '<body class="chat-active">' in INDEX_HTML
    assert "document.body.classList.toggle('chat-active', name === 'chat')" in APP_JS
    assert "body.chat-active{overflow:hidden}" in STYLES_CSS
    assert (
        "body.chat-active .workspace{display:grid;grid-template-rows:auto minmax(0,1fr);"
        "height:100vh;height:100dvh;"
        "min-height:0;overflow:hidden}"
    ) in STYLES_CSS
    assert "body.chat-active #chatView{height:auto;min-height:0;overflow:hidden}" in STYLES_CSS
    assert "body.chat-active .conversation-panel{min-height:0;overflow:hidden}" in STYLES_CSS
    assert (
        "body.chat-active .messages{min-height:0;overflow-x:hidden;overflow-y:auto;"
        "overscroll-behavior:contain;scrollbar-gutter:stable}"
    ) in STYLES_CSS
    assert (
        "body.chat-active .evidence-panel{height:100%;min-height:0;overflow-x:hidden;"
        "overflow-y:auto;overscroll-behavior:contain;scrollbar-gutter:stable}"
    ) in STYLES_CSS
    assert ".rail{position:fixed;" in STYLES_CSS


def test_splunk_scope_selector_is_global_and_readable() -> None:
    assert 'id="scopeSelect"' in INDEX_HTML
    assert 'aria-label="Active Splunk instance and tenant scope"' in INDEX_HTML
    assert "function scopePayload()" in APP_JS
    assert "function scopedUrl(path, params = {})" in APP_JS
    assert ".scope-selector select{" in STYLES_CSS
    assert "@media(max-width:1100px){.chat-layout{grid-template-columns:1fr}" in STYLES_CSS


def test_durable_analytics_expose_explicit_splunk_targets_and_provenance() -> None:
    assert 'id="assuranceTarget"' in INDEX_HTML
    assert 'id="forecastTarget"' in APP_JS
    assert 'id="forecastScheduleTarget"' in APP_JS
    assert "Retained baselines are isolated by target and revision." in APP_JS
    assert "data-rebind-forecast-schedule" in APP_JS
    assert "expected_policy_updated_at" in APP_JS
    assert "connection_fingerprint" in APP_JS
    assert ".forecast-schedule-binding" in STYLES_CSS


def test_tenant_isolation_is_readiness_only_and_keyboard_accessible() -> None:
    assert 'id="tenantIsolationTarget"' in INDEX_HTML
    assert 'id="buildTenantIsolationPlan"' in INDEX_HTML
    assert "Planning reads schemas, counts, and filenames only" in INDEX_HTML
    assert "No unsafe isolation toggle" in INDEX_HTML
    assert "function renderTenantIsolationPlan(plan)" in APP_JS
    assert "async function buildTenantIsolationPlan()" in APP_JS
    assert "READINESS ONLY · NO DATA MOVED" in APP_JS
    assert "before final physical isolation" in APP_JS
    assert ".tenant-isolation-controls select:focus-visible" in STYLES_CSS
    assert ".tenant-isolation-controls button:focus-visible" in STYLES_CSS
    assert 'id="tenantDataPlaneSummary"' in INDEX_HTML
    assert "Stage and verify eight stores" in APP_JS
    assert "Activate verified route" in APP_JS
    assert "Rollback active generation" in APP_JS
    assert "physical cleanup is not final" in APP_JS
    assert "data-cutover-tenant" in APP_JS
    assert ".tenant-data-plane button:focus-visible" in STYLES_CSS


def test_discovery_comparison_is_explicit_source_preserving_and_accessible() -> None:
    assert 'id="estateComparisonForm"' in INDEX_HTML
    assert 'aria-label="Left Splunk comparison source"' in INDEX_HTML
    assert 'aria-label="Right Splunk comparison source"' in INDEX_HTML
    assert "runs zero new Splunk queries or model inference" in INDEX_HTML
    assert "no global conclusion" in INDEX_HTML
    assert "function renderEstateComparison(value)" in APP_JS
    assert "other estate's facts are intentionally not copied" in APP_JS
    assert "data-investigate-comparison" in APP_JS
    assert ".estate-comparison-controls select:focus-visible" in STYLES_CSS


def test_remote_audit_export_is_explicit_and_accessible() -> None:
    assert 'id="auditExportForm"' in INDEX_HTML
    assert 'id="auditExportEnabled"' in INDEX_HTML
    assert 'id="auditVerifyTls"' in INDEX_HTML
    assert 'id="auditUseAck"' in INDEX_HTML
    assert 'id="auditBackfill"' in INDEX_HTML
    assert 'id="runAuditExport"' in INDEX_HTML
    assert "never reuses the read-only MCP token" in INDEX_HTML
    assert "Default and internal Splunk indexes are rejected." in INDEX_HTML
    assert "Verified chain only" in INDEX_HTML
    assert "async function saveAuditExportPolicy" in APP_JS
    assert "async function runAuditExportNow" in APP_JS
    assert "renderAuditExport(value.audit_export || {})" in APP_JS
    assert ".audit-export-workspace" in STYLES_CSS
    assert 'id="auditOperationsForm"' in INDEX_HTML
    assert 'id="auditDeduplicationMode"' in INDEX_HTML
    assert 'id="previewAuditOperations"' in INDEX_HTML
    assert 'id="exportAuditOperations"' in INDEX_HTML
    assert "async function previewAuditOperations" in APP_JS
    assert "async function exportAuditOperations" in APP_JS
    assert "renderAuditOperations(value.audit_operations || {})" in APP_JS
    assert ".audit-operations-workspace" in STYLES_CSS
