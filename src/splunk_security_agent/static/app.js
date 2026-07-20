const state = {
  settings: null, artifacts: [], modelReadiness: null, conversationId: null, busy: false,
  connections: null, activeScope: null,
  ledger: [], lastDiscovery: null, promptPath: [], contextKind: 'all', cases: [],
  activeCase: null, caseCockpit: null, pendingCaseItem: null, detailActions: [], contextPage: 1, contextPageSize: 9,
  contextItems: [], editingArtifactId: null, editingCaseItemId: null, demoTourStep: -1,
  modelRecommendations: {}, validations: [], editingValidationId: null,
  modelUpdates: null, modelCatalog: null, modelTrust: null, splunkModels: null,
  assurance: null, assurancePolicyDirty: false, connectionDiagnostics: null, queryIntelligence: null,
  workload: null,
  feedbackBenchmarks: null, goldenBenchmarks: null, selectedTournamentId: null, deliveryPolicyDirty: false,
  auditExportPolicyDirty: false, auditOperationsPolicyDirty: false, auditOperationsPreview: null,
  evaluationDraft: null, evaluationScenarioIndex: 0,
  deliveryPreview: null, detections: [], activeDetection: null, detectionGitExport: null,
  repositoryStatus: null, repositoryHandoff: null, auth: null, authUsers: [],
  codeScreenResult: null, timeSeriesStatus: null, timeSeriesResult: null,
  timeSeriesExperiments: null, timeSeriesSchedules: null, timeSeriesScheduleTimer: null,
  workspaceLoaded: false, assuranceTimer: null, discoveryJobs: null,
  activeDiscoveryJob: null, discoveryPollTimer: null, discoveryPollBusy: false,
  discoveryWatchingJobId: null
};
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const PROMPT_TREE = {
  analyst: { label:'SOC analyst', value:'Move from alert to defensible next action', description:'Triage, scope, validate, and preserve evidence.', workflows:{
    triage: { label:'Triage an alert', description:'Separate observed facts from assumptions.', prompts:[
      { label:'Triage an alert narrative', outcome:'Facts, hypotheses, scope, and next check', mode:'triage', text:'Triage this alert narrative. Separate observed facts from hypotheses, identify scope and confidence, and give the safest next validation step. I will paste the alert next.' },
      { label:'Scope an indicator', outcome:'Related activity and time-bounded validation plan', mode:'triage', text:'Build a read-only plan to scope an indicator across the connected Splunk data. Ask me for the indicator and preserve explicit time bounds.' }
    ]},
    evidence: { label:'Validate evidence', description:'Pressure-test an observation before escalation.', prompts:[
      { label:'Validate the latest observation', outcome:'Narrow SPL and decision points', mode:'spl', text:'Use the latest evidence ledger observation to create narrow, read-only validation SPL with decision points and required fields.' },
      { label:'Build an incident timeline', outcome:'Ordered facts, gaps, and collection plan', mode:'triage', text:'Build an evidence-led incident timeline from available context. Mark missing timestamps and propose read-only searches to close the gaps.' }
    ]}
  }},
  hunter: { label:'Threat hunter', value:'Turn a behavior into a testable hunt', description:'Develop hypotheses and iterate through observable behavior.', workflows:{
    hypothesis: { label:'Start from a hypothesis', description:'Translate attacker behavior into observables.', prompts:[
      { label:'Hunt suspicious PowerShell', outcome:'Hypothesis → SPL → decision points', mode:'hunt', text:'Build a hypothesis-driven hunt for suspicious PowerShell execution. Use available fields only, show bounded read-only SPL steps, and define decision points.' },
      { label:'Hunt beaconing behavior', outcome:'Network observables and staged validation', mode:'hunt', text:'Design a staged hunt for command-and-control beaconing using available network telemetry. Separate weak signals from corroborating evidence.' }
    ]},
    gaps: { label:'Start from a coverage gap', description:'Use missing or weak telemetry to focus hunt design.', prompts:[
      { label:'Investigate identity coverage', outcome:'Identity telemetry gaps and compensating hunts', mode:'discovery', text:'Assess identity telemetry coverage from the latest discovery, identify gaps, and propose compensating read-only hunts.' },
      { label:'Investigate cloud coverage', outcome:'Cloud control-plane visibility and validation steps', mode:'discovery', text:'Assess cloud security coverage from discovery evidence and build a prioritized plan to validate control-plane, identity, and audit telemetry.' }
    ]}
  }},
  engineer: { label:'Detection engineer', value:'Prove a rule can work with the data you have', description:'Inspect requirements, tune SPL, and document limitations.', workflows:{
    validate: { label:'Validate a detection', description:'Check data, fields, logic, and false positives.', prompts:[
      { label:'Pressure-test a rule', outcome:'Requirements, failure modes, and test plan', mode:'detection', text:'Pressure-test a detection rule. Identify required sourcetypes and fields, likely false positives, evasion risks, and a read-only validation plan. I will paste the rule next.' },
      { label:'Assess detection readiness', outcome:'Coverage-to-detection feasibility map', mode:'detection', text:'Assess whether the connected data can support a detection for a behavior I describe. Separate available evidence, missing telemetry, and assumptions.' }
    ]},
    build: { label:'Build or improve SPL', description:'Create readable, bounded, reviewable searches.', prompts:[
      { label:'Draft a detection search', outcome:'Read-only SPL with rationale and tests', mode:'spl', text:'Draft read-only detection SPL for a behavior I describe. Ask for missing field names, use explicit time bounds, and include test cases.' },
      { label:'Optimize existing SPL', outcome:'Lower-cost search with equivalent intent', mode:'spl', text:'Explain and optimize the SPL I paste next. Preserve detection intent, identify expensive operations, and state any semantic changes.' }
    ]}
  }},
  leader: { label:'Security leader / CISO', value:'Convert technical evidence into decisions', description:'Understand posture, material risk, and ownership.', workflows:{
    posture: { label:'Review security posture', description:'Summarize coverage and meaningful changes.', prompts:[
      { label:'Brief the latest discovery', outcome:'Coverage, material gaps, owners, and priorities', mode:'brief', text:'Brief a security leader on the latest discovery. Explain material coverage, changes, gaps, business relevance, recommended owners, and the top three decisions.' },
      { label:'Explain posture changes', outcome:'What changed, why it matters, and response', mode:'brief', text:'Explain changes since the previous discovery in executive language. Separate verified changes from collection failures and recommend follow-up ownership.' }
    ]},
    incident: { label:'Lead an incident', description:'Create a decision-ready incident view.', prompts:[
      { label:'Create an incident brief', outcome:'Facts, hypotheses, impact, confidence, decisions', mode:'brief', text:'Create an incident-lead brief from available evidence with facts, hypotheses, potential impact, confidence, decisions needed, and next actions.' },
      { label:'Review evidence quality', outcome:'What is known, missing, or weakly supported', mode:'brief', text:'Audit the current evidence quality for leadership. Identify what is observed, unverified, contradictory, missing, or dependent on assumptions.' }
    ]}
  }}
};

const DEMO_TOUR_STEPS = [
  {
    view:'chat', target:'.welcome-card', eyebrow:'1 · ORIENT', title:'Start with an analyst outcome',
    body:'Choose a role and workflow instead of guessing a generic prompt. SignalRoom stages the prompt for review before any model or Splunk tool runs.',
    value:'Value: faster onboarding, repeatable analysis, and visible intent before execution.'
  },
  {
    view:'chat', target:'#chatForm', eyebrow:'2 · INVESTIGATE', title:'Ask, route, observe',
    body:'Use the highlighted composer to ask a question. In demo mode, metadata comes from the sample adapter and SPL is validated but never executed. Agent activity shows retrieval, tool planning, model routing, and provenance.',
    value:'Try: “What indexes are available?” Then inspect Evidence in play and the Agent Trace.'
  },
  {
    view:'discovery', target:'#runDiscovery', eyebrow:'3 · DISCOVER', title:'Build reusable environment knowledge',
    body:'Run a safe discovery to see how SignalRoom inventories indexes, sourcetypes, hosts, detections, and coverage. Demo discovery uses synthetic inventory and clearly avoids live searches.',
    value:'Value: build context once, compare posture later, and reduce repetitive SPL during investigations.'
  },
  {
    view:'context', target:'#addArtifact', eyebrow:'4 · CURATE', title:'Control what RAG can retrieve',
    body:'Context stores runbooks, threat intelligence, known-good SPL, references, and discovery knowledge. Add an artifact, edit it to rebuild its chunks, inspect its provenance, or delete it completely.',
    value:'Value: organization-specific answers without sending your evidence to a hosted chat service.'
  },
  {
    view:'cases', target:'#newCase', eyebrow:'5 · PRESERVE', title:'Create a durable case record',
    body:'Cases preserve observations, hypotheses, decisions, evidence, and notes across shifts. Case details and timeline entries can be edited, exported, or deleted.',
    value:'Value: defensible handoffs with ownership, status, severity, timestamps, and evidence provenance.'
  },
  {
    view:'detections', target:'#detectionsView', eyebrow:'6 · ENGINEER', title:'Turn observed evidence into reviewed detection code',
    body:'Completed validations can become versioned detection projects. Editing creates a new immutable version, review binds to the exact content hash, and approved exports remain disabled until your normal change process deploys them.',
    value:'Value: evidence-linked detection engineering without granting SignalRoom write access to Splunk.'
  },
  {
    view:'models', target:'#modelGrid', eyebrow:'7 · ROUTE LOCALLY', title:'Use the right local specialist deliberately',
    body:'Ollama handles chat and Foundation-Sec reasoning. SecureBERT retrieval and entity extraction run through locally installed Transformers profiles. SignalRoom shows which capability actually executed.',
    value:'Value: task-appropriate cybersecurity models without sending investigation evidence to hosted inference.'
  },
  {
    view:'models', target:'#openSettings', eyebrow:'8 · INSTALL OR USE CLOUD', title:'Install locally first; enable cloud deliberately',
    body:'Setup installs SecureBERT from Hugging Face into local storage with one click. If hosted inference is desired instead, select the cloud runtime and choose Disabled, Ask for every question, or Allowed. Discovery reasoning remains on Ollama.',
    value:'Value: local domain-aware retrieval and entity recognition by default, with cloud available only through an explicit runtime and policy choice.'
  }
];

async function api(path, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const csrf = readCookie('signalroom_csrf');
  const securityHeaders = csrf && ['POST','PUT','PATCH','DELETE'].includes(method)
    ? { 'X-SignalRoom-CSRF': csrf } : {};
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...securityHeaders, ...(options.headers || {}) }
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json(); const detail = body.detail || body.error;
      message = Array.isArray(detail) ? detail.map(item => item.msg || String(item)).join(' · ') : (detail || message);
    } catch (_) {}
    if (response.status === 401 && !path.startsWith('/api/auth/login')) showLogin();
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

async function streamApi(path, payload, onEvent) {
  const csrf = readCookie('signalroom_csrf');
  const response = await fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-SignalRoom-CSRF':csrf } : {}) }, body: JSON.stringify(payload)
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json(); const detail = body.detail || body.error;
      message = Array.isArray(detail) ? detail.map(item => item.msg || String(item)).join(' · ') : (detail || message);
    } catch (_) {}
    if (response.status === 401) showLogin();
    throw new Error(message);
  }
  if (!response.body) throw new Error('This browser cannot read streamed operation updates.');
  const reader = response.body.getReader(); const decoder = new TextDecoder();
  let buffer = ''; let result = null;
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffer.split('\n'); buffer = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      const event = JSON.parse(line); onEvent?.(event);
      if (event.type === 'error') throw new Error(event.error || 'The operation failed.');
      if (event.type === 'result') result = event.result;
    }
    if (done) break;
  }
  if (buffer.trim()) {
    const event = JSON.parse(buffer); onEvent?.(event);
    if (event.type === 'error') throw new Error(event.error || 'The operation failed.');
    if (event.type === 'result') result = event.result;
  }
  if (result === null) throw new Error('The operation ended without a result.');
  return result;
}

function readCookie(name) {
  const prefix = `${name}=`;
  const value = document.cookie.split(';').map(item => item.trim()).find(item => item.startsWith(prefix));
  return value ? decodeURIComponent(value.slice(prefix.length)) : '';
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[char]);
}

function renderMarkdown(value = '') {
  let text = escapeHtml(value);
  text = text.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  text = text.replace(/^### (.+)$/gm, '<h4>$1</h4>').replace(/^## (.+)$/gm, '<h3>$1</h3>');
  text = text.replace(/^[-*] (.+)$/gm, '<li>$1</li>').replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  return text.split(/\n{2,}/).map(block => /^<(pre|ul|h)/.test(block) ? block : `<p>${block.replace(/\n/g, '<br>')}</p>`).join('');
}

function toast(message) {
  const node = $('#toast'); node.textContent = message; node.classList.add('show');
  clearTimeout(node._timer); node._timer = setTimeout(() => node.classList.remove('show'), 2600);
}

function showLogin() {
  if (!state.auth?.enabled) return;
  $('#loginModal').hidden = false;
  document.body.classList.add('auth-locked');
  $('.app-shell').inert = true;
  setTimeout(() => $('#loginUsername').focus(), 0);
}

function hideLogin() {
  $('#loginModal').hidden = true;
  document.body.classList.remove('auth-locked');
  $('.app-shell').inert = false;
  $('#loginResult').textContent = '';
  $('#loginPassword').value = '';
}

function renderAuthUsers() {
  const users = state.authUsers || [];
  const connections = state.auth?.available_connections || [{id:'primary',label:'Primary Splunk'}];
  $('#rbacUserCount').textContent = `${users.length} user${users.length === 1 ? '' : 's'}`;
  $('#rbacUsers').innerHTML = users.length ? users.map(user => {
    const external = user.auth_source === 'oidc';
    const source = external ? 'enterprise OIDC' : 'local account';
    return `
    <article class="access-user" data-auth-user="${escapeHtml(user.id)}">
      <header><div><b>${escapeHtml(user.display_name)}</b><small>@${escapeHtml(user.username)} · ${source}${user.last_login_at ? ` · last sign-in ${escapeHtml(new Date(user.last_login_at).toLocaleString())}` : ' · never signed in'}</small></div><span class="${user.active ? (external ? 'external' : '') : 'inactive'}">${user.active ? `${escapeHtml(user.role)}${external ? ' · OIDC' : ''}` : 'inactive'}</span></header>
      <div class="access-user-controls">
        <label><span>Role${external ? ' · group managed' : ''}</span><select data-auth-role ${external ? 'disabled' : ''}><option value="viewer" ${user.role === 'viewer' ? 'selected' : ''}>Viewer · read only</option><option value="analyst" ${user.role === 'analyst' ? 'selected' : ''}>Analyst · investigate</option><option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin · platform control</option></select></label>
        <label><span>${external ? 'Credential authority' : 'Replace password · optional'}</span><input data-auth-password type="password" autocomplete="new-password" minlength="12" maxlength="1024" placeholder="${external ? 'Managed by identity provider' : 'Leave unchanged'}" ${external ? 'disabled' : ''}></label>
        <div class="access-user-checks"><label><input data-auth-active type="checkbox" ${user.active ? 'checked' : ''}> Active account</label>${connections.map(item => `<label><input data-auth-connection="${escapeHtml(item.id)}" type="checkbox" ${(user.connection_ids || []).includes(item.id) ? 'checked' : ''} ${external ? 'disabled' : ''}> ${escapeHtml(item.label)}${external ? ' · policy managed' : ''}</label>`).join('')}</div>
        <button class="button ghost small" type="button" data-save-auth-user>Save access</button>
      </div>
    </article>`;
  }).join('') : '<div class="empty-inline compact-empty">No named users exist.</div>';
}

async function loadAuthUsers() {
  if (!state.auth?.enabled || !state.auth?.permissions?.can_administer) {
    state.authUsers = []; renderAuthUsers(); return;
  }
  state.authUsers = await api('/api/auth/users');
  renderAuthUsers();
}

function applyAccessPermissions() {
  const authenticated = Boolean(state.auth?.authenticated);
  const canAdminister = Boolean(state.auth?.permissions?.can_administer);
  const canChange = Boolean(state.auth?.permissions?.can_change);
  const canUseConnection = Boolean(state.auth?.permissions?.can_use_connection ?? state.auth?.permissions?.can_use_primary_connection);
  document.body.dataset.accessRole = state.auth?.principal?.role || '';
  document.body.classList.toggle('settings-readonly', authenticated && !canAdminister);
  $('#accessReadOnlyNote').hidden = !authenticated || canAdminister;
  $('#saveWorkspace').disabled = authenticated && !canAdminister;
  $$('#settingsForm input,#settingsForm select,#settingsForm textarea,#settingsForm button').forEach(node => {
    if (node.id === 'allowWrites') return;
    if (!canAdminister) {
      node.disabled = true;
      node.dataset.accessDisabled = 'true';
    } else if (node.dataset.accessDisabled) {
      node.disabled = false;
      delete node.dataset.accessDisabled;
    }
  });
  if (canAdminister && state.settings) updateRepositoryControls();
  const mutationSelectors = [
    '#chatInput', '#chatForm .send-button', '#runDiscovery', '#cancelDiscoveryJob', '#runConnectionDiagnostics',
    '#runAssuranceNow', '#assuranceForm button', '#deliveryForm button', '#auditExportForm button',
    '#auditOperationsForm button', '#runAuditExport', '#previewAuditOperations',
    '#exportAuditOperations', '#scanSplunkModels',
    '#runModelTournament', '#runGoldenBenchmark', '#addArtifact', '#uploadArtifact',
    '#newCase', '#newDetection', '#runTimeSeriesForecast',
    '#timeSeriesScheduleForm input', '#timeSeriesScheduleForm select',
    '#timeSeriesScheduleForm button', '#timeSeriesScheduleHistory button',
    '#timeSeriesReviewQueue form textarea', '#timeSeriesReviewQueue form button',
    '#timeSeriesExperimentHistory form input',
    '#timeSeriesExperimentHistory form select',
    '#timeSeriesExperimentHistory form textarea',
    '#timeSeriesExperimentHistory form button'
  ];
  $$(mutationSelectors.join(',')).forEach(node => {
    if (!canChange) { node.disabled = true; node.dataset.roleDisabled = 'true'; }
    else if (node.dataset.roleDisabled) {
      delete node.dataset.roleDisabled;
      if (!node.dataset.jobDisabled && !node.dataset.connectionDisabled && !node.dataset.adminDisabled) node.disabled = false;
    }
  });
  const connectionSelectors = [
    '#chatInput', '#chatForm .send-button', '#runDiscovery', '#cancelDiscoveryJob',
    '#runConnectionDiagnostics', '#runAssuranceNow', '#scanSplunkModels',
    '#runTimeSeriesForecast', '#timeSeriesScheduleForm button',
    '#timeSeriesScheduleHistory button'
  ];
  $$(connectionSelectors.join(',')).forEach(node => {
    if (authenticated && !canUseConnection) {
      node.disabled = true; node.dataset.connectionDisabled = 'true';
    } else if (node.dataset.connectionDisabled) {
      delete node.dataset.connectionDisabled;
      if (!node.dataset.jobDisabled && !node.dataset.roleDisabled && !node.dataset.adminDisabled) node.disabled = false;
    }
  });
  const adminSelectors = [
    '#assuranceForm input', '#assuranceForm select', '#assuranceForm button[type="submit"]',
    '#deliveryForm input', '#deliveryForm select', '#deliveryForm button',
    '#auditExportForm input', '#auditExportForm select', '#auditExportForm button',
    '#auditOperationsForm input', '#auditOperationsForm select',
    '#auditOperationsForm button', '#runAuditExport', '#previewAuditOperations',
    '#exportAuditOperations',
    '[data-pull-profile]', '[data-activate-model]', '[data-promote-tournament]',
    '#modelTrustPolicyForm input', '#modelTrustPolicyForm select',
    '#modelTrustPolicyForm button', '[data-approve-model-artifact]',
    '[data-revoke-model-attestation]',
    '#timeSeriesRuntimeForm input', '#timeSeriesRuntimeForm button',
    '#startBundledTimeSeries',
    '[data-rollback-promotion]', '[data-preview-repository]', '[data-apply-repository]',
    '[data-push-repository]', '[data-pull-request-repository]',
    '[data-refresh-repository-review]', '[data-preserve-repository-review]',
    '[data-export-detection]', '[data-export-detection-git]', '[data-retire-detection]'
  ];
  $$(adminSelectors.join(',')).forEach(node => {
    if (!canAdminister) { node.disabled = true; node.dataset.adminDisabled = 'true'; }
    else if (node.dataset.adminDisabled) { node.disabled = false; delete node.dataset.adminDisabled; }
  });
}

function renderAuth() {
  const auth = state.auth; if (!auth) return;
  const principal = auth.principal;
  $('#accessIdentity').textContent = principal?.display_name || 'Sign-in required';
  $('#accessAvatar').textContent = (principal?.display_name || '?').trim().charAt(0).toUpperCase();
  $('#accessMode').textContent = auth.enabled
    ? `${principal?.role || 'locked'} · ${(principal?.connection_ids || []).length ? `${principal.connection_ids.length} Splunk scope${principal.connection_ids.length === 1 ? '' : 's'}` : 'no Splunk assignment'}`
    : 'POC mode · RBAC off';
  $('#logoutButton').hidden = !auth.enabled || !auth.authenticated;
  $('#enterpriseLogin').hidden = !auth.oidc?.enabled;
  $('#enterpriseLoginLabel').textContent = auth.oidc?.provider_label || 'enterprise identity';
  $('#rbacLocalSetup').hidden = auth.enabled;
  $('#rbacEnabledNotice').hidden = !auth.enabled;
  $('#rbacAdminControls').hidden = !auth.enabled || !auth.permissions?.can_administer;
  $('#accessModeBanner').hidden = auth.enabled;
  $('#rbacPrincipalSummary').textContent = principal
    ? `${principal.display_name} is signed in as ${principal.role}`
    : 'Named access is enforced';
  $('#accessDisable').hidden = principal?.auth_source === 'oidc';
  const reenable = Boolean(auth.reenable_required);
  $('#rbacBootstrapDisplayName').closest('label').hidden = reenable;
  $('#rbacBootstrapHelp').textContent = reenable
    ? `${auth.identity_count} preserved identit${auth.identity_count === 1 ? 'y' : 'ies'} found. Enter an existing administrator username and password to re-enable RBAC.`
    : 'Enabling RBAC creates the first named administrator and signs this browser in without interrupting setup.';
  $('#enableRbac').textContent = reenable ? 'Re-enable named access' : 'Enable named access';
  $('#accessControlSummary').textContent = auth.enabled
    ? `Named users, roles, protected sessions, and per-user Splunk connection assignment are active.${auth.oidc?.enabled ? ` Enterprise sign-in is available through ${auth.oidc.provider_label}.` : ''}`
    : 'SignalRoom is in local single-user mode. This keeps POC and guided-demo setup frictionless; keep the service bound to localhost until named access is enabled.';
  renderOidcPolicy();
  const connectionOptions = auth.available_connections || [{id:'primary',label:'Primary Splunk'}];
  $('#newAuthConnections').innerHTML = connectionOptions.map((item, index) => `<label class="access-connection-check"><input data-new-auth-connection="${escapeHtml(item.id)}" type="checkbox" ${index === 0 ? 'checked' : ''}><span>Assign ${escapeHtml(item.label)}</span></label>`).join('');
  applyAccessPermissions();
  if (auth.enabled && !auth.authenticated) showLogin(); else hideLogin();
}

async function loadAuthStatus() {
  state.auth = await api('/api/auth/status');
  renderAuth();
  if (state.auth.enabled && state.auth.authenticated && state.auth.permissions?.can_administer) await loadAuthUsers();
  return state.auth;
}

async function signIn(event) {
  event.preventDefault();
  const output = $('#loginResult'); output.textContent = 'Signing in…';
  try {
    state.auth = await api('/api/auth/login', { method:'POST', body:JSON.stringify({
      username:$('#loginUsername').value.trim(),
      password:$('#loginPassword').value
    })});
    hideLogin(); renderAuth();
    if (state.auth.permissions?.can_administer) await loadAuthUsers();
    await loadWorkspace();
  } catch (error) {
    output.textContent = error.message;
    $('#loginPassword').select();
  }
}

async function signOut() {
  try { await api('/api/auth/logout', { method:'POST', body:'{}' }); }
  catch (_) {}
  state.workspaceLoaded = false;
  await loadAuthStatus();
}

async function enableRbac() {
  const output = $('#enableRbacResult'); output.textContent = 'Enabling named access…';
  const username = $('#rbacBootstrapUsername').value.trim();
  const displayName = $('#rbacBootstrapDisplayName').value.trim();
  const password = $('#rbacBootstrapPassword').value;
  if (username.length < 3 || (!state.auth?.reenable_required && !displayName) || password.length < 12) {
    output.textContent = 'Enter a valid username, display name, and password of at least 12 characters.';
    return;
  }
  try {
    state.auth = await api('/api/auth/bootstrap', { method:'POST', body:JSON.stringify({
      username,
      display_name:displayName || 'Existing administrator',
      password
    })});
    $('#rbacBootstrapPassword').value = '';
    renderAuth(); await loadAuthUsers();
    output.textContent = 'RBAC enabled. This browser is signed in.';
    toast('Named access enabled');
  } catch (error) { output.textContent = error.message; }
}

async function disableRbac() {
  const password = $('#disableRbacPassword').value;
  if (!password || !confirm('Disable RBAC and revoke every active session? Named users will be preserved for later re-enablement.')) return;
  try {
    state.auth = await api('/api/auth/disable', { method:'POST', body:JSON.stringify({ password }) });
    state.authUsers = []; $('#disableRbacPassword').value = ''; renderAuth(); renderAuthUsers();
    toast('Returned to local single-user mode');
  } catch (error) { toast(error.message); }
}

async function createAuthUser() {
  const output = $('#createAuthUserResult'); output.textContent = 'Creating user…';
  const username = $('#newAuthUsername').value.trim();
  const displayName = $('#newAuthDisplayName').value.trim();
  const password = $('#newAuthPassword').value;
  if (username.length < 3 || !displayName || password.length < 12) {
    output.textContent = 'Enter a valid username, display name, and temporary password of at least 12 characters.';
    return;
  }
  try {
    await api('/api/auth/users', { method:'POST', body:JSON.stringify({
      username,
      display_name:displayName,
      role:$('#newAuthRole').value,
      password,
      connection_ids:$$('[data-new-auth-connection]:checked').map(node => node.dataset.newAuthConnection)
    })});
    ['#newAuthUsername','#newAuthDisplayName','#newAuthPassword'].forEach(selector => $(selector).value = '');
    $('#newAuthRole').value = 'analyst'; $$('[data-new-auth-connection]').forEach((node, index) => { node.checked = index === 0; });
    await loadAuthUsers(); output.textContent = 'Named user created.';
  } catch (error) { output.textContent = error.message; }
}

async function saveAuthUser(button) {
  const card = button.closest('[data-auth-user]');
  const user = (state.authUsers || []).find(item => item.id === card.dataset.authUser);
  const password = card.querySelector('[data-auth-password]').value;
  const body = user?.auth_source === 'oidc' ? {
    active:card.querySelector('[data-auth-active]').checked
  } : {
    role:card.querySelector('[data-auth-role]').value,
    active:card.querySelector('[data-auth-active]').checked,
    connection_ids:Array.from(card.querySelectorAll('[data-auth-connection]:checked')).map(node => node.dataset.authConnection),
    password:password || null
  };
  try {
    await api(`/api/auth/users/${encodeURIComponent(card.dataset.authUser)}`, { method:'PATCH', body:JSON.stringify(body)});
    await loadAuthUsers(); toast('User access updated');
  } catch (error) { toast(error.message); }
}

function listField(selector) {
  return $(selector).value.split(',').map(value => value.trim()).filter(Boolean);
}

function renderOidcPolicy() {
  const oidc = state.auth?.oidc || {};
  const policy = oidc.policy;
  $('#oidcStatusBadge').textContent = oidc.enabled ? 'Enabled' : 'Disabled';
  $('#oidcStatusBadge').className = `subtle-pill${oidc.enabled ? ' ok' : ''}`;
  if (!policy) return;
  $('#oidcEnabled').checked = Boolean(policy.enabled);
  $('#oidcProviderLabel').value = policy.provider_label || 'Enterprise identity';
  $('#oidcIssuer').value = policy.issuer_url || '';
  $('#oidcClientId').value = policy.client_id || '';
  $('#oidcRedirectUri').value = policy.redirect_uri || '';
  $('#oidcUsernameClaim').value = policy.username_claim || 'preferred_username';
  $('#oidcDisplayNameClaim').value = policy.display_name_claim || 'name';
  $('#oidcGroupsClaim').value = policy.groups_claim || 'groups';
  $('#oidcTenantClaim').value = policy.tenant_claim || '';
  $('#oidcAllowedTenants').value = (policy.allowed_tenant_values || []).join(', ');
  $('#oidcAllowedGroups').value = (policy.allowed_groups || []).join(', ');
  $('#oidcAnalystGroups').value = (policy.analyst_groups || []).join(', ');
  $('#oidcAdminGroups').value = (policy.admin_groups || []).join(', ');
  $('#oidcDefaultRole').value = policy.default_role || 'viewer';
  $('#oidcRequiredAcr').value = (policy.required_acr_values || []).join(', ');
  $('#oidcRequiredAmr').value = (policy.required_amr_values || []).join(', ');
  $('#oidcGrantPrimary').checked = Boolean(policy.grant_primary_connection);
  $('#oidcClientSecret').value = '';
  $('#oidcClearClientSecret').checked = false;
  $('#oidcSecretHelp').textContent = policy.client_secret_environment_managed
    ? 'Managed by SIGNALROOM_OIDC_CLIENT_SECRET; change it in the service environment.'
    : policy.client_secret_configured
      ? 'Encrypted client secret configured · leave blank to keep it.'
      : 'No client secret is configured.';
}

async function saveOidcPolicy() {
  const output = $('#oidcPolicyResult');
  output.textContent = 'Validating and saving enterprise policy…';
  const payload = {
    enabled:$('#oidcEnabled').checked,
    provider_label:$('#oidcProviderLabel').value.trim() || 'Enterprise identity',
    issuer_url:$('#oidcIssuer').value.trim(),
    client_id:$('#oidcClientId').value.trim(),
    redirect_uri:$('#oidcRedirectUri').value.trim(),
    client_secret:$('#oidcClientSecret').value || null,
    clear_client_secret:$('#oidcClearClientSecret').checked,
    username_claim:$('#oidcUsernameClaim').value.trim() || 'preferred_username',
    display_name_claim:$('#oidcDisplayNameClaim').value.trim() || 'name',
    groups_claim:$('#oidcGroupsClaim').value.trim() || 'groups',
    tenant_claim:$('#oidcTenantClaim').value.trim(),
    allowed_tenant_values:listField('#oidcAllowedTenants'),
    allowed_groups:listField('#oidcAllowedGroups'),
    analyst_groups:listField('#oidcAnalystGroups'),
    admin_groups:listField('#oidcAdminGroups'),
    default_role:$('#oidcDefaultRole').value,
    grant_primary_connection:$('#oidcGrantPrimary').checked,
    required_acr_values:listField('#oidcRequiredAcr'),
    required_amr_values:listField('#oidcRequiredAmr')
  };
  try {
    const result = await api('/api/auth/oidc/policy', { method:'PUT', body:JSON.stringify(payload) });
    state.auth.oidc = result;
    renderOidcPolicy();
    output.textContent = result.enabled
      ? 'Enterprise sign-in enabled. Run the saved-provider test before signing out.'
      : 'Enterprise sign-in is disabled; local named access is unchanged.';
    toast('Enterprise identity policy saved');
  } catch (error) { output.textContent = error.message; }
}

async function testOidcProvider() {
  const output = $('#oidcPolicyResult');
  output.textContent = 'Reading provider discovery and signing keys…';
  try {
    const result = await api('/api/auth/oidc/test', { method:'POST', body:'{}' });
    output.textContent = `Verified ${result.issuer} · ${result.signing_keys} signing key${result.signing_keys === 1 ? '' : 's'} · S256 PKCE · ${result.signing_algorithms.join(', ')}`;
  } catch (error) { output.textContent = error.message; }
}

function renderPromptTree(path = state.promptPath) {
  state.promptPath = path;
  const explorer = $('#promptExplorer'); if (!explorer) return;
  if (!path.length) {
    explorer.innerHTML = `<div class="prompt-tree-heading"><div><b>Choose your role</b><span>SignalRoom will guide you from an outcome to a reviewable prompt.</span></div></div><div class="prompt-grid">${Object.entries(PROMPT_TREE).map(([id, persona]) => `
      <button class="prompt-card" data-prompt-persona="${id}"><b>${escapeHtml(persona.label)}</b><span>${escapeHtml(persona.value)}</span><em>${escapeHtml(persona.description)}</em></button>`).join('')}</div>`;
    return;
  }
  const persona = PROMPT_TREE[path[0]];
  if (path.length === 1) {
    explorer.innerHTML = `<div class="prompt-tree-heading"><button data-prompt-back aria-label="Back to roles">←</button><div><b>${escapeHtml(persona.label)}</b><span>${escapeHtml(persona.description)}</span></div></div><div class="prompt-grid">${Object.entries(persona.workflows).map(([id, workflow]) => `
      <button class="prompt-card" data-prompt-workflow="${id}"><b>${escapeHtml(workflow.label)}</b><span>${escapeHtml(workflow.description)}</span><em>Explore workflow →</em></button>`).join('')}</div>`;
    return;
  }
  const workflow = persona.workflows[path[1]];
  explorer.innerHTML = `<div class="prompt-tree-heading"><button data-prompt-back aria-label="Back to ${escapeHtml(persona.label)} workflows">←</button><div><b>${escapeHtml(workflow.label)}</b><span>${escapeHtml(workflow.description)}</span></div></div><div class="prompt-leaves">${workflow.prompts.map((prompt, index) => `
    <article><span>${escapeHtml(prompt.mode)}</span><h3>${escapeHtml(prompt.label)}</h3><p>${escapeHtml(prompt.outcome)}</p><button data-use-prompt="${index}">Review this prompt →</button></article>`).join('')}</div>`;
}

function investigationLink(mode, prompt) {
  const params = new URLSearchParams({ mode, prompt });
  return `${location.origin}${location.pathname}#investigate?${params}`;
}

function openInvestigation(mode, prompt, updateHash = true) {
  setView('chat');
  $('#investigationMode').value = mode || 'auto';
  $('#chatInput').value = prompt || '';
  resizeComposer(); $('#chatInput').focus();
  history.replaceState(
    null,
    '',
    updateHash ? investigationLink(mode || 'auto', prompt || '') : `${location.pathname}#investigate`
  );
  toast('Prompt staged for review');
}

function showDetail({ eyebrow, title, summary, content, provenance, actions = [], permalink = '' }) {
  state.detailActions = actions;
  $('#detailEyebrow').textContent = eyebrow;
  $('#detailTitle').textContent = title;
  $('#detailSummary').innerHTML = summary;
  $('#detailContent').innerHTML = content;
  $('#detailProvenance').innerHTML = provenance;
  $('#detailActions').innerHTML = actions.map((action, index) => `<button class="button ${index ? 'ghost' : 'primary'}" data-detail-action="${index}">${escapeHtml(action.label)}</button>`).join('') + (permalink ? '<button class="button ghost" data-copy-detail-link>Copy deep link</button>' : '');
  $('#detailModal').dataset.permalink = permalink;
  $('#detailModal').hidden = false;
}

function openLedgerDetail(id) {
  const item = state.ledger.find(entry => entry.id === id); if (!item) return;
  const tools = item.provenance?.tools || [];
  const provenance = `<dl><div><dt>Source</dt><dd>${escapeHtml(item.source)}</dd></div><div><dt>Confidence</dt><dd>${escapeHtml(item.confidence)}</dd></div><div><dt>Status</dt><dd>${escapeHtml(item.status)}</dd></div>${tools.length ? `<div><dt>Read-only tools</dt><dd>${escapeHtml(tools.join(', '))}</dd></div>` : ''}${item.provenance?.result_count != null ? `<div><dt>Result count</dt><dd>${Number(item.provenance.result_count).toLocaleString()}</dd></div>` : ''}</dl>`;
  showDetail({
    eyebrow:`${item.classification} · evidence ledger`, title:'Why this entry exists',
    summary:`<p>${escapeHtml(item.why)}</p>`,
    content:`<h3>Recorded statement</h3><p>${escapeHtml(item.statement)}</p>`,
    provenance:`<h3>Provenance</h3>${provenance}`,
    actions:[...(item.actions || []), { label:'Add to case', kind:'case-item', item:{
      kind:item.classification === 'context' ? 'context' : 'observation',
      title:item.classification === 'context' ? `Context: ${item.source}` : 'Splunk evidence observation',
      content:item.statement, source:item.source, confidence:item.confidence, status:item.status,
      metadata:{ ledger_id:item.id, provenance:item.provenance || {} }
    }}]
  });
}

function openArtifactDetail(id, updateHash = true) {
  const item = state.artifacts.find(artifact => artifact.id === id); if (!item) return;
  const actions = [
    { label:'Use in investigation', kind:'prompt', mode:'general', prompt:`Use the context artifact titled "${item.title}" in an evidence-led investigation. Explain what it supports, what it does not prove, and the next validation step.` },
    { label:'Build validation SPL', kind:'prompt', mode:'spl', prompt:`Create a narrow, read-only SPL validation plan for the artifact titled "${item.title}". Use its content as untrusted context and ask for missing field names.` },
    { label:'Find related context', kind:'context-search', target:item.title },
    { label:'Add to case', kind:'case-item', item:{ kind:'evidence', title:item.title,
      content:item.content.slice(0, 50000), source:item.source, confidence:'unknown', status:'unverified',
      metadata:{ artifact_id:item.id, artifact_kind:item.kind, tags:item.tags } } },
    { label:'Edit artifact', kind:'edit-artifact', target:item.id },
    { label:'Delete artifact', kind:'delete-artifact', target:item.id }
  ];
  const permalink = `${location.origin}${location.pathname}#context/artifact/${encodeURIComponent(id)}`;
  showDetail({
    eyebrow:`${item.kind} · managed context`, title:item.title,
    summary:`<p>This item is stored so SignalRoom can retrieve it during relevant investigations. Review its source and freshness before treating it as authoritative.</p>`,
    content:`<h3>Content</h3><div class="artifact-full-content">${renderMarkdown(item.content)}</div>`,
    provenance:`<h3>Provenance</h3><dl><div><dt>Source</dt><dd>${escapeHtml(item.source)}</dd></div><div><dt>Splunk alias</dt><dd>${escapeHtml(item.connection_alias)}</dd></div><div><dt>Tenant scope</dt><dd><code>${escapeHtml(item.tenant_scope_id)}</code></dd></div><div><dt>Connection revision</dt><dd><code>${escapeHtml(item.connection_fingerprint)}</code></dd></div><div><dt>Updated</dt><dd>${new Date(item.updated_at).toLocaleString()}</dd></div><div><dt>Tags</dt><dd>${escapeHtml(item.tags.join(', ') || 'none')}</dd></div></dl>`,
    actions, permalink
  });
  if (updateHash) history.replaceState(null, '', permalink);
}

async function copyDetailLink() {
  const value = $('#detailModal').dataset.permalink; if (!value) return;
  try { await navigator.clipboard.writeText(value); toast('Deep link copied'); }
  catch (_) { toast(value); }
}

function setView(name) {
  const titles = {
    chat: ['INVESTIGATION WORKSPACE', 'Ask, inspect, verify.'],
    discovery: ['ENVIRONMENT DISCOVERY', 'Map the security surface.'],
    cases: ['INVESTIGATION OPERATIONS', 'Preserve the case record.'],
    detections: ['DETECTION ENGINEERING', 'Prove, review, package.'],
    context: ['RAG & ARTIFACTS', 'Curate the evidence base.'],
    models: ['MODEL CAPABILITIES', 'Route work to specialists.']
  };
  $$('.nav-item[data-view]').forEach(node => node.classList.toggle('active', node.dataset.view === name));
  $$('.view').forEach(node => node.classList.remove('active'));
  $(`#${name}View`).classList.add('active');
  document.body.classList.toggle('chat-active', name === 'chat');
  $('#viewEyebrow').textContent = titles[name][0]; $('#viewTitle').textContent = titles[name][1];
  $('#newConversation').hidden = name !== 'chat';
  if (name === 'context') loadArtifacts();
  if (name === 'cases') loadCases();
  if (name === 'detections') loadDetections();
  if (name === 'models') { renderModels(); loadFeedbackBenchmarks(); loadGoldenBenchmarks(); }
  if (name === 'discovery') loadValidations();
}

function showDemoTourStep(index) {
  const previous = $('.demo-highlight'); if (previous) previous.classList.remove('demo-highlight');
  state.demoTourStep = Math.min(Math.max(index, 0), DEMO_TOUR_STEPS.length - 1);
  const step = DEMO_TOUR_STEPS[state.demoTourStep];
  setView(step.view);
  $('#settingsModal').hidden = true;
  $('#demoTourProgress').textContent = `STEP ${state.demoTourStep + 1} OF ${DEMO_TOUR_STEPS.length}`;
  $('#demoTourEyebrow').textContent = step.eyebrow;
  $('#demoTourTitle').textContent = step.title;
  $('#demoTourBody').textContent = step.body;
  $('#demoTourValue').textContent = step.value;
  $('#demoTourBack').disabled = state.demoTourStep === 0;
  $('#demoTourNext').textContent = state.demoTourStep === DEMO_TOUR_STEPS.length - 1 ? 'Finish tour' : 'Next';
  $('#demoTour').hidden = false;
  const target = $(step.target);
  if (target) { target.classList.add('demo-highlight'); target.scrollIntoView({ behavior:'smooth', block:'center' }); }
}

function startDemoTour() {
  if (!state.settings?.demo_mode) {
    $('#settingsModal').hidden = false;
    toast('Enable the guided demo workspace, then save');
    return;
  }
  localStorage.removeItem('signalroom-demo-tour-complete');
  showDemoTourStep(0);
}

function finishDemoTour() {
  const target = $('.demo-highlight'); if (target) target.classList.remove('demo-highlight');
  $('#demoTour').hidden = true; state.demoTourStep = -1;
  localStorage.setItem('signalroom-demo-tour-complete', 'true');
  navigateView('chat');
  toast('Guided demo complete · explore freely or connect live Splunk');
}

function hydrateSettings() {
  const settings = state.settings;
  $('#demoMode').checked = settings.demo_mode;
  $('#splunkName').value = settings.splunk.name || '';
  $('#splunkUrl').value = settings.splunk.url || '';
  $('#verifySplunkTls').checked = settings.splunk.verify_ssl !== false;
  $('#splunkCaBundle').value = settings.splunk.ca_bundle || '';
  updateTlsControls();
  $('#allowWrites').checked = settings.allow_write_tools;
  const repository = settings.detection_repository || {};
  $('#repositoryEnabled').checked = Boolean(repository.enabled);
  $('#repositoryPath').value = repository.path || '';
  $('#repositoryBaseRef').value = repository.base_ref || 'main';
  $('#repositoryBranchPrefix').value = repository.branch_prefix || 'signalroom/';
  $('#repositoryRemote').value = repository.remote_name || 'origin';
  $('#repositoryAuthorName').value = repository.commit_author_name || 'SignalRoom Detection Engineering';
  $('#repositoryAuthorEmail').value = repository.commit_author_email || 'signalroom@localhost';
  $('#repositoryAllowPush').checked = Boolean(repository.allow_push);
  $('#repositoryAllowPullRequest').checked = Boolean(repository.allow_draft_pull_request);
  updateRepositoryControls();
  const chatProfiles = settings.models.filter(model => ['chat', 'security_reasoning'].includes(model.task));
  for (const selector of ['#defaultModel', '#securityModel']) {
    $(selector).innerHTML = chatProfiles.map(model => `<option value="${escapeHtml(model.id)}">${escapeHtml(model.label)}</option>`).join('');
  }
  $('#defaultModel').value = settings.default_chat_model;
  $('#securityModel').value = settings.security_reasoning_model;
  $('#specialistRuntime').value = settings.specialist_runtime || 'local';
  $('#hfPolicy').value = settings.huggingface_policy || 'disabled';
  $('#hfQueryApproval').hidden = settings.specialist_runtime !== 'cloud' || settings.huggingface_policy !== 'ask';
  if (settings.specialist_runtime !== 'cloud' || settings.huggingface_policy !== 'ask') $('#approveHf').checked = false;
  const generalProfile = settings.models.find(model => model.id === settings.default_chat_model);
  const securityProfile = settings.models.find(model => model.id === settings.security_reasoning_model);
  const ollamaProfile = settings.models.find(model => model.provider === 'ollama');
  $('#ollamaEndpoint').value = ollamaProfile?.endpoint || 'http://localhost:11434';
  $('#generalModelId').value = generalProfile?.model || '';
  $('#securityModelId').value = securityProfile?.model || '';
  $('#hfEmbeddingEndpoint').value = settings.models.find(model => model.id === settings.embedding_model)?.endpoint || '';
  $('#hfNerEndpoint').value = settings.models.find(model => model.id === settings.ner_model)?.endpoint || '';
  $('#modelSelect').innerHTML = '<option value="">Auto-route model</option>' + chatProfiles.map(model => `<option value="${escapeHtml(model.id)}">${escapeHtml(model.label)}</option>`).join('');
  $('#modePill').innerHTML = `<i></i>${settings.demo_mode ? 'Demo mode' : 'Live Splunk'}`;
  $('#connectionLabel').textContent = settings.demo_mode ? 'Demo workspace' : settings.splunk.name;
  $('#connectionDetail').textContent = settings.demo_mode ? 'Guided sample workspace' : (settings.splunk.url || 'Endpoint missing');
  $('#startDemoTour').hidden = !settings.demo_mode;
  applyAccessPermissions();
  hydrateWorkload();
  renderConnections();
}

async function loadSettings() {
  state.settings = await api('/api/settings'); hydrateSettings();
  await loadConnections();
  if (!state.settings.configured) $('#settingsModal').hidden = false;
  else if (state.settings.demo_mode && !localStorage.getItem('signalroom-demo-tour-complete')) {
    setTimeout(startDemoTour, 250);
  }
  loadModelReadiness();
  await loadDetectionRepositoryStatus();
}

async function loadConnections() {
  try {
    state.connections = await api('/api/connections');
    const scopes = state.connections.execution_scopes || [];
    const prior = state.activeScope ? scopeKey(state.activeScope) : '';
    state.activeScope = scopes.find(item => scopeKey(item) === prior) || scopes[0] || state.connections.primary || null;
    renderConnections();
    renderScopeSelector();
  } catch (_) {
    state.connections = null;
  }
}

function scopeKey(value = {}) {
  return `${value.alias || 'primary'}|${value.fingerprint || ''}|${value.tenant_scope_id || 'workspace-primary'}`;
}

function activeScope() {
  const value = state.activeScope || state.connections?.primary || {};
  return {
    connection_alias:value.alias || 'primary',
    connection_fingerprint:value.fingerprint || '',
    tenant_scope_id:value.tenant_scope_id || 'workspace-primary'
  };
}

function scopePayload() { return activeScope(); }

function scopedUrl(path, params = {}) {
  const target = new URL(path, location.origin);
  Object.entries({...params, ...scopePayload()}).forEach(([key,value]) => target.searchParams.set(key, value));
  return `${target.pathname}${target.search}`;
}

function scopeLabel(value = {}) {
  const label = value.alias === 'primary' ? 'Primary' : (value.display_name || value.alias || 'Splunk');
  return `${label} · ${value.tenant_scope_id || 'workspace-primary'}`;
}

function renderScopeSelector() {
  const select = $('#scopeSelect'); if (!select) return;
  const scopes = state.connections?.execution_scopes || (state.connections?.primary ? [state.connections.primary] : []);
  if (!scopes.length) return;
  select.innerHTML = scopes.map(item => `<option value="${escapeHtml(scopeKey(item))}">${escapeHtml(scopeLabel(item))}</option>`).join('');
  select.value = scopeKey(state.activeScope || scopes[0]);
  select.title = scopes.length < 2
    ? 'Primary is the only executable Splunk identity. Additional instances will appear after they are configured.'
    : 'Choose the Splunk instance and tenant evidence boundary for this workspace.';
}

async function switchScope(key) {
  const scopes = state.connections?.execution_scopes || [];
  const next = scopes.find(item => scopeKey(item) === key);
  if (!next || scopeKey(next) === scopeKey(state.activeScope || {})) return;
  state.activeScope = next;
  state.activeCase = null; state.caseCockpit = null; state.lastDiscovery = null;
  resetConversation();
  await Promise.all([loadArtifacts(), loadCases(), loadLatestDiscovery(), loadDiscoveryJobs()]);
  toast(`Active Splunk scope · ${scopeLabel(next)}`);
}

function shortFingerprint(value = '') {
  return value ? `${String(value).slice(0, 12)}…` : 'unbound';
}

function connectionBindingRow(kind, item, label) {
  if (!item) return '';
  const current = Boolean(item.binding_current);
  const canAdmin = Boolean(state.auth?.permissions?.can_administer);
  const action = !current && kind !== 'discovery'
    ? `<button class="button ${canAdmin ? 'primary' : 'ghost'} small" type="button" data-rebind-connection="${escapeHtml(kind)}" ${canAdmin ? '' : 'disabled'}>Rebind and pause</button>`
    : kind === 'discovery' && !current
      ? '<span class="binding-action-note">Create a fresh discovery job</span>'
      : '<span class="binding-action-note">No action needed</span>';
  const itemId = kind === 'forecast' ? ` data-workflow-id="${escapeHtml(item.id)}"` : '';
  return `<article class="connection-binding-row ${current ? 'current' : 'stale'}"${itemId}>
    <i aria-hidden="true"></i><div><b>${escapeHtml(label)}</b><small>${escapeHtml(item.tenant_scope_id || 'No tenant scope')} · revision ${escapeHtml(shortFingerprint(item.connection_fingerprint))}</small><p>${escapeHtml(item.binding_detail || '')}</p></div>${action}
  </article>`;
}

function renderConnections() {
  const value = state.connections;
  if (!value || !$('#connectionIdentityCard')) return;
  const primary = value.primary || {};
  const identity = $('#connectionIdentityCard');
  identity.className = `connection-identity-card ${primary.mode === 'demo' ? 'demo' : 'live'}`;
  identity.innerHTML = `<span>${escapeHtml(primary.mode === 'demo' ? 'DEMO' : 'PRIMARY')}</span><div><b>${escapeHtml(primary.display_name || 'Primary Splunk')}</b><small>${escapeHtml(primary.tenant_scope_id || 'workspace-primary')} · immutable revision <code>${escapeHtml(shortFingerprint(primary.fingerprint))}</code></small><p>${escapeHtml(primary.endpoint || 'Endpoint not configured')} · TLS verification ${primary.verify_tls ? 'on' : 'off'}${primary.ca_bundle_bound ? ' · private CA bound' : ''}</p></div>`;
  const workflows = value.workflow_bindings || {};
  const assurance = workflows.assurance_policy;
  const schedules = workflows.forecast_schedules || [];
  const staleJobs = (workflows.recent_discovery_jobs || []).filter(item => !item.binding_current);
  const rows = [
    connectionBindingRow('assurance', assurance, 'Continuous assurance policy'),
    ...schedules.map(item => connectionBindingRow('forecast', item, `Shadow forecast · ${item.title}`)),
    ...staleJobs.slice(0, 3).map(item => connectionBindingRow('discovery', item, `Discovery job · ${String(item.id).slice(0, 8)}`))
  ].filter(Boolean);
  $('#connectionWorkflowBindings').innerHTML = rows.length
    ? `<header><b>Durable workflow bindings</b><span>${rows.length} tracked</span></header>${rows.join('')}`
    : '<div class="empty-inline compact-empty">No durable workflow bindings have been created.</div>';
  renderManagedSplunkConnections();
  const catalog = value.additional_mcp_connections || {};
  $('#futureMcpIntro').innerHTML = `<b>Why add another MCP?</b><p>${escapeHtml(catalog.mission || '')}</p><span>Additional Splunk is executable now · other connector types remain governed roadmap candidates</span>`;
  $('#futureMcpGrid').innerHTML = (catalog.suggestions || []).map(item => `<article><header><span>${escapeHtml(item.priority || 'later')}</span><b>${escapeHtml(item.label)}</b></header><p>${escapeHtml(item.purpose)}</p><dl><dt>Expected value</dt><dd>${escapeHtml(item.expected_value)}</dd><dt>Authority boundary</dt><dd>${escapeHtml(item.authority)}</dd></dl></article>`).join('');
  $('#futureMcpAdmission').innerHTML = `<b>Admission contract before any connector is enabled</b><ul>${(catalog.admission_requirements || []).map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul><small>Tenant scope now gates evidence, cases, discovery history, and investigation retrieval. Separate per-tenant database files remain a future hard-isolation option.</small>`;
}

function renderManagedSplunkConnections() {
  const holder = $('#managedSplunkConnections'); if (!holder) return;
  const items = state.connections?.managed_splunk_connections || [];
  const assigned = new Set(state.auth?.principal?.connection_ids || []);
  holder.innerHTML = items.length ? items.map(item => {
    const ready = Boolean(item.diagnostics_ready && item.diagnostics_fingerprint === item.fingerprint);
    const status = item.enabled ? 'ENABLED' : ready ? 'READY TO ENABLE' : 'DIAGNOSTICS REQUIRED';
    const statusClass = item.enabled ? 'enabled' : ready ? 'ready' : 'draft';
    const assignment = !state.auth?.enabled || assigned.has(item.alias)
      ? 'Available to this operator'
      : 'Not assigned to this signed-in user';
    return `<article class="managed-splunk-card ${statusClass}" data-managed-splunk="${escapeHtml(item.alias)}">
      <header><div><span>${escapeHtml(status)}</span><h5>${escapeHtml(item.display_name || item.alias)}</h5><small><code>${escapeHtml(item.alias)}</code> · ${escapeHtml(item.tenant_scope_id)}</small></div><b>${item.verify_tls ? 'TLS verified' : 'TLS unverified'}</b></header>
      <p>${escapeHtml(item.endpoint)} · revision <code>${escapeHtml(shortFingerprint(item.fingerprint))}</code>${item.ca_bundle_bound ? ' · private CA bound' : ''}</p>
      <div class="managed-splunk-contract"><span>${item.token_configured ? 'Encrypted token stored' : 'Token missing'}</span><span>${escapeHtml(assignment)}</span><span>${item.diagnostics_checked_at ? `Last checked ${escapeHtml(new Date(item.diagnostics_checked_at).toLocaleString())}` : 'Never checked'}</span></div>
      <div class="managed-splunk-progress" data-managed-splunk-progress role="status" aria-live="polite">${ready ? 'The exact current revision passed the quick discovery tool contract.' : 'Run diagnostics before this connection can enter an execution selector.'}</div>
      <footer><button class="button ghost small" type="button" data-diagnose-managed-splunk="${escapeHtml(item.alias)}">Run diagnostics</button>${item.enabled ? `<button class="button ghost small" type="button" data-admit-managed-splunk="${escapeHtml(item.alias)}" data-enabled="false">Disable</button>` : `<button class="button primary small" type="button" data-admit-managed-splunk="${escapeHtml(item.alias)}" data-enabled="true" ${ready ? '' : 'disabled'}>Enable scope</button>`}<button class="button ghost small" type="button" data-edit-managed-splunk="${escapeHtml(item.alias)}">Edit</button><button class="button ghost small danger-action" type="button" data-archive-managed-splunk="${escapeHtml(item.alias)}">Archive</button></footer>
    </article>`;
  }).join('') : '<div class="empty-inline compact-empty">No additional Splunk instances are configured. Primary remains the only execution scope.</div>';
}

function resetManagedSplunkForm() {
  ['#managedSplunkAlias','#managedSplunkTenant','#managedSplunkName','#managedSplunkUrl','#managedSplunkToken','#managedSplunkCa'].forEach(selector => { $(selector).value = ''; });
  $('#managedSplunkEditingAlias').value = '';
  $('#managedSplunkAlias').disabled = false;
  $('#managedSplunkVerifyTls').checked = true;
  $('#managedSplunkToken').required = true;
  $('#managedSplunkFormResult').textContent = '';
  updateManagedSplunkTlsControls();
}

function openManagedSplunkForm(alias = '') {
  resetManagedSplunkForm();
  if (alias) {
    const item = (state.connections?.managed_splunk_connections || []).find(value => value.alias === alias);
    if (!item) return;
    $('#managedSplunkEditingAlias').value = alias;
    $('#managedSplunkAlias').value = alias;
    $('#managedSplunkAlias').disabled = true;
    $('#managedSplunkTenant').value = item.tenant_scope_id || '';
    $('#managedSplunkName').value = item.display_name || '';
    $('#managedSplunkUrl').value = item.endpoint || '';
    $('#managedSplunkVerifyTls').checked = Boolean(item.verify_tls);
    $('#managedSplunkCa').value = item.ca_bundle || '';
    $('#managedSplunkToken').required = false;
    $('#managedSplunkToken').placeholder = item.token_configured ? 'Leave blank to keep the encrypted token' : 'Token required';
  }
  $('#managedSplunkForm').hidden = false;
  updateManagedSplunkTlsControls();
  $('#managedSplunkAlias').focus();
}

function updateManagedSplunkTlsControls() {
  const verified = $('#managedSplunkVerifyTls').checked;
  $('#managedSplunkTlsWarning').hidden = verified;
  $('#managedSplunkCaLabel').hidden = !verified;
}

async function saveManagedSplunkConnection() {
  const editing = $('#managedSplunkEditingAlias').value;
  const verify = $('#managedSplunkVerifyTls').checked;
  const token = $('#managedSplunkToken').value;
  const alias = $('#managedSplunkAlias').value.trim();
  const tenant = $('#managedSplunkTenant').value.trim();
  const name = $('#managedSplunkName').value.trim();
  const url = $('#managedSplunkUrl').value.trim();
  const output = $('#managedSplunkFormResult');
  if (!/^[a-z][a-z0-9-]{2,47}$/.test(alias) || !/^[a-z][a-z0-9._-]{2,63}$/.test(tenant) || !name || !url || (!editing && !token)) {
    output.textContent = 'Enter a valid lowercase alias, tenant scope, display name, endpoint, and token.';
    return;
  }
  const payload = {
    tenant_scope_id:tenant,
    display_name:name,
    url,
    verify_ssl:verify,
    ca_bundle:verify ? ($('#managedSplunkCa').value.trim() || null) : null
  };
  if (!editing) { payload.alias = alias; payload.token = token; }
  else if (token) payload.token = token;
  output.textContent = 'Saving disabled revision…';
  try {
    await api(editing ? `/api/connections/splunk/${encodeURIComponent(editing)}` : '/api/connections/splunk', {method:editing ? 'PATCH' : 'POST',body:JSON.stringify(payload)});
    $('#managedSplunkForm').hidden = true;
    await Promise.all([loadConnections(), loadAuthStatus()]);
    toast(editing ? 'Connection revision saved; re-run diagnostics if its contract changed' : 'Connection saved disabled; run diagnostics to admit it');
  } catch (error) { output.textContent = error.message; }
}

async function diagnoseManagedSplunk(alias, button) {
  const card = button.closest('[data-managed-splunk]');
  const output = card.querySelector('[data-managed-splunk-progress]');
  button.disabled = true; output.textContent = 'Starting configuration and network checks…';
  try {
    const result = await streamApi(`/api/connections/splunk/${encodeURIComponent(alias)}/diagnostics/stream`, {}, event => {
      if (event.type === 'progress' || event.type === 'heartbeat') output.textContent = `${event.label || 'Working'} · ${event.detail || ''}`;
    });
    output.textContent = result.ready ? `Ready · ${result.tool_count || 0} MCP tools satisfy quick discovery.` : `Blocked at ${String(result.blocking_stage || 'preflight').replaceAll('-', ' ')}.`;
    await loadConnections();
    toast(result.ready ? 'Connection revision is ready for explicit admission' : 'Connection remains disabled');
  } catch (error) { output.textContent = error.message; }
  finally { button.disabled = false; }
}

async function setManagedSplunkAdmission(alias, enabled, button) {
  button.disabled = true;
  try {
    await api(`/api/connections/splunk/${encodeURIComponent(alias)}/admission`, {method:'PATCH',body:JSON.stringify({enabled})});
    await loadConnections();
    toast(enabled ? 'Splunk scope admitted to selectors' : 'Splunk scope disabled; retained evidence is unchanged');
  } catch (error) { toast(error.message); button.disabled = false; }
}

async function archiveManagedSplunk(alias) {
  const item = (state.connections?.managed_splunk_connections || []).find(value => value.alias === alias);
  if (!item || !confirm(`Archive “${item.display_name}”? Its encrypted token will be removed. Existing evidence and immutable provenance will be retained.`)) return;
  try {
    await api(`/api/connections/splunk/${encodeURIComponent(alias)}`, {method:'DELETE'});
    await Promise.all([loadConnections(), loadAuthStatus()]);
    toast('Connection archived; retained evidence remains bound to its immutable revision');
  } catch (error) { toast(error.message); }
}

async function rebindConnectionWorkflow(button) {
  const kind = button.dataset.rebindConnection;
  const row = button.closest('.connection-binding-row');
  const workflows = state.connections?.workflow_bindings || {};
  const item = kind === 'assurance'
    ? workflows.assurance_policy
    : (workflows.forecast_schedules || []).find(value => value.id === row?.dataset.workflowId);
  if (!item) return;
  if (!confirm(`Rebind this ${kind === 'assurance' ? 'assurance policy' : 'shadow forecast'} to the current Primary Splunk revision? Scheduling will be paused for review.`)) return;
  button.disabled = true;
  try {
    const path = kind === 'assurance'
      ? '/api/connections/rebind/assurance'
      : `/api/connections/rebind/time-series-schedules/${encodeURIComponent(item.id)}`;
    await api(path, {method:'POST',body:JSON.stringify({
      expected_connection_fingerprint:item.connection_fingerprint,
      expected_updated_at:item.updated_at
    })});
    await loadConnections();
    if (kind === 'assurance') await loadAssurance();
    else await loadTimeSeriesSchedules();
    toast('Workflow rebound and paused for review');
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
}

function workloadPolicyPayload() {
  return {
    mode:$('#workloadMode').value,
    max_concurrent_calls:Number($('#workloadConcurrentCalls').value),
    max_concurrent_queries:Number($('#workloadConcurrentQueries').value),
    queue_timeout_seconds:Number($('#workloadQueueTimeout').value),
    max_query_risk_score:Number($('#workloadRiskScore').value),
    max_query_cost_units:Number($('#workloadQueryUnits').value),
    daily_query_cost_units:Number($('#workloadDailyUnits').value)
  };
}

function hydrateWorkload() {
  if (!state.workload) return;
  const policy = state.workload.policy || {};
  $('#workloadMode').value = policy.mode || 'audit';
  $('#workloadConcurrentCalls').value = policy.max_concurrent_calls ?? 6;
  $('#workloadConcurrentQueries').value = policy.max_concurrent_queries ?? 2;
  $('#workloadQueueTimeout').value = policy.queue_timeout_seconds ?? 60;
  $('#workloadRiskScore').value = policy.max_query_risk_score ?? 70;
  $('#workloadQueryUnits').value = policy.max_query_cost_units ?? 90;
  $('#workloadDailyUnits').value = policy.daily_query_cost_units ?? 1000;
  const enforce = policy.mode === 'enforce';
  const banner = $('#workloadModeBanner');
  banner.className = `workload-mode-banner ${enforce ? 'enforce' : 'audit'}`;
  banner.innerHTML = enforce
    ? '<span>ENFORCE</span><div><b>Risk and budget thresholds can block execution</b><small>Read-only guardrails and concurrency limits are also active.</small></div>'
    : '<span>AUDIT</span><div><b>Thresholds are visible, not blocking</b><small>Read-only guardrails and concurrency limits remain active.</small></div>';
  const runtime = state.workload.runtime || {};
  const budget = state.workload.budget || {};
  const used = Number(budget.used_units || 0) + Number(budget.reserved_units || 0);
  const limit = Math.max(1, Number(budget.limit_units || policy.daily_query_cost_units || 1));
  $('#workloadLive').querySelector('div span').textContent = `${runtime.active_calls || 0}/${policy.max_concurrent_calls || 0} calls active · ${runtime.active_queries || 0}/${policy.max_concurrent_queries || 0} searches active · ${runtime.queued_calls || 0} queued · ${used.toLocaleString()}/${limit.toLocaleString()} UTC-day units`;
  $('#workloadLive .workload-meter i').style.width = `${Math.min(100, Math.round((used / limit) * 100))}%`;
  const events = state.workload.events || [];
  $('#workloadEvents').innerHTML = events.length ? events.slice(0, 12).map(event => `<article class="workload-event ${escapeHtml(event.status)}"><header><b>${escapeHtml(event.operation)}</b><span>${escapeHtml(event.decision.replaceAll('-', ' '))}</span></header><p>${escapeHtml(event.logical_name)} · ${escapeHtml(event.lane)}${event.cost_units ? ` · ${Number(event.cost_units)} units` : ''}${event.wait_ms ? ` · waited ${Number(event.wait_ms).toLocaleString()} ms` : ''}</p><footer><time>${new Date(event.created_at).toLocaleString()}</time><code>${escapeHtml((event.query_fingerprint || '').slice(0, 12))}</code></footer></article>`).join('') : '<div class="empty-inline compact-empty">No workload events have been recorded.</div>';
}

async function loadWorkload() {
  try {
    state.workload = await api('/api/workload');
    hydrateWorkload();
  } catch (error) { toast(`Workload policy: ${error.message}`); }
}

function repositorySettingsPayload() {
  return {
    enabled:$('#repositoryEnabled').checked,
    path:$('#repositoryPath').value.trim(),
    base_ref:$('#repositoryBaseRef').value.trim() || 'main',
    branch_prefix:$('#repositoryBranchPrefix').value.trim() || 'signalroom/',
    remote_name:$('#repositoryRemote').value.trim() || 'origin',
    commit_author_name:$('#repositoryAuthorName').value.trim() || 'SignalRoom Detection Engineering',
    commit_author_email:$('#repositoryAuthorEmail').value.trim() || 'signalroom@localhost',
    allow_push:$('#repositoryAllowPush').checked,
    allow_draft_pull_request:$('#repositoryAllowPullRequest').checked
  };
}

function updateRepositoryControls() {
  const enabled = $('#repositoryEnabled').checked;
  const push = enabled && $('#repositoryAllowPush').checked;
  $$('#repositorySettings input').forEach(input => {
    if (!['repositoryAllowPush','repositoryAllowPullRequest'].includes(input.id)) input.disabled = !enabled;
  });
  $('#repositoryAllowPush').disabled = !enabled;
  $('#repositoryAllowPullRequest').disabled = !push;
  if (!push) $('#repositoryAllowPullRequest').checked = false;
  $('#testRepository').disabled = !enabled;
}

async function loadDetectionRepositoryStatus() {
  try {
    state.repositoryStatus = await api('/api/detection-repository/status');
  } catch (_) {
    state.repositoryStatus = null;
  }
}

async function testDetectionRepository() {
  const output = $('#repositoryTestResult');
  output.textContent = 'Inspecting…'; output.className = 'test-result';
  try {
    const result = await api('/api/detection-repository/test', {method:'POST',body:JSON.stringify({settings:repositorySettingsPayload()})});
    state.repositoryStatus = result;
    output.textContent = result.ready
      ? `${result.current_branch || 'detached'} · base ${String(result.base_commit || '').slice(0, 12)} · ${result.remotes?.length || 0} remote${result.remotes?.length === 1 ? '' : 's'}${result.warnings?.length ? ` · ${result.warnings[0]}` : ''}`
      : result.blocking_reason;
    output.className = `test-result ${result.ready ? 'ok' : 'error'}`;
  } catch (error) {
    output.textContent = error.message; output.className = 'test-result error';
  }
}

function diagnosticStageMarkup(stage) {
  const status = stage.status || 'pending';
  return `<article class="diagnostic-stage ${escapeHtml(status)}"><i aria-hidden="true"></i><div><b>${escapeHtml(stage.label || stage.id)}</b><p>${escapeHtml(stage.detail || '')}</p>${stage.remediation ? `<small>${escapeHtml(stage.remediation)}</small>` : ''}</div>${stage.duration_ms ? `<time>${Number(stage.duration_ms).toLocaleString()} ms</time>` : ''}</article>`;
}

function renderConnectionDiagnostics(result, { setup = false } = {}) {
  if (!result) return;
  state.connectionDiagnostics = result;
  const stages = result.stages || [];
  const ready = Boolean(result.ready);
  const readiness = result.depth_readiness || {};
  const title = result.never_checked ? 'Connection contract has not been checked' : ready ? 'Splunk MCP is ready' : `Connection blocked at ${String(result.blocking_stage || 'preflight').replaceAll('-', ' ')}`;
  const summary = result.never_checked
    ? 'Run diagnostics before relying on discovery or continuous assurance.'
    : ready
      ? `${result.tool_count || 0} read-only tools discovered · quick ${readiness.quick ? 'ready' : 'blocked'} · standard ${readiness.standard ? 'ready' : 'blocked'} · deep ${readiness.deep ? 'ready' : 'blocked'}`
      : stages.find(stage => stage.status === 'error')?.detail || 'The saved Splunk connection is not ready.';
  const panel = $('#connectionReadiness');
  panel.className = `connection-readiness ${ready ? 'ready' : result.never_checked ? '' : 'blocked'}`;
  panel.querySelector('h3').textContent = title;
  panel.querySelector(':scope > p').textContent = summary;
  $('#connectionReadinessStages').innerHTML = stages.map(diagnosticStageMarkup).join('');
  if (setup) {
    const setupPanel = $('#setupConnectionDiagnostics'); setupPanel.hidden = false;
    setupPanel.className = `connection-diagnostics setup-diagnostics ${ready ? 'ready' : 'blocked'}`;
    setupPanel.querySelector('header span').textContent = ready ? 'Ready' : 'Action required';
    setupPanel.querySelector('.diagnostic-stages').innerHTML = stages.map(diagnosticStageMarkup).join('');
  }
}

async function loadConnectionDiagnostics() {
  try { renderConnectionDiagnostics(await api('/api/connection/diagnostics')); }
  catch (_) { /* Health detail remains non-blocking while the app starts. */ }
}

async function runConnectionDiagnostics() {
  const button = $('#runConnectionDiagnostics'); button.disabled = true; button.textContent = 'Checking…';
  const panel = $('#connectionReadiness'); panel.className = 'connection-readiness working';
  panel.querySelector('h3').textContent = 'Checking connection readiness';
  $('#connectionReadinessStages').innerHTML = '';
  try {
    const result = await streamApi('/api/connection/diagnostics/stream', {}, event => {
      if (event.type === 'result') return;
      panel.querySelector('h3').textContent = event.label || 'Checking connection readiness';
      panel.querySelector(':scope > p').textContent = event.detail || '';
    });
    renderConnectionDiagnostics(result);
    toast(result.ready ? 'Splunk MCP connection is ready' : 'Connection diagnostics found a blocker');
    return result;
  } catch (error) { toast(error.message); return null; }
  finally { button.disabled = false; button.textContent = 'Run diagnostics'; }
}

function readinessBadge(node, label, status) {
  node.textContent = label;
  node.className = `readiness-badge ${status || ''}`;
}

function formatBytes(value) {
  const bytes = Number(value || 0); if (!bytes) return '';
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${Math.round(bytes / 1024 ** 2)} MB`;
  return `${Math.round(bytes / 1024)} KB`;
}

function contextIndexLabel(profile) {
  const index = profile.context_index; if (!index) return '';
  if (!index.total_chunks) return ' · Context ready for first artifact';
  return ` · Context ${Number(index.indexed_chunks).toLocaleString()}/${Number(index.total_chunks).toLocaleString()}`;
}

function renderModelReadiness() {
  const readiness = state.modelReadiness; if (!readiness) return;
  const ollama = readiness.ollama;
  $('#ollamaInstalledModels').innerHTML = ollama.models.map(model => `<option value="${escapeHtml(model)}"></option>`).join('');
  readinessBadge($('#ollamaReadiness'), ollama.ok ? 'Service online' : 'Install required', ollama.ok ? 'ok' : 'warn');
  $('#ollamaReadinessDetail').textContent = ollama.ok
    ? `Ollama ${ollama.version || ''} is responding at ${ollama.endpoint}. Downloads stay on that Ollama host.`
    : `No Ollama service responded at ${ollama.endpoint}. Install and start Ollama, then check again.`;
  $('#ollamaProfileReadiness').innerHTML = ollama.profiles.map(profile => `
    <div class="profile-ready-row"><span><i class="model-status ${profile.loaded ? 'active' : profile.installed ? 'ok' : ''}"></i><b>${escapeHtml(profile.label)}</b><small>${escapeHtml(profile.model)}</small></span>
    ${profile.loaded ? '<em>Loaded</em>' : profile.installed ? `<button type="button" data-activate-model="${escapeHtml(profile.id)}">Activate</button>` : `<button type="button" data-pull-profile="${escapeHtml(profile.id)}" ${ollama.ok ? '' : 'disabled'}>Download</button>`}</div>`).join('');

  const local = readiness.local_transformers;
  const installedLocal = local.profiles.filter(profile => profile.installed).length;
  const allLocalReady = installedLocal === local.profiles.length && installedLocal > 0;
  readinessBadge(
    $('#localReadiness'),
    allLocalReady ? 'Local ready' : installedLocal ? `${installedLocal}/${local.profiles.length} installed` : 'Install locally',
    allLocalReady ? 'ok' : 'warn'
  );
  $('#localReadinessDetail').textContent = allLocalReady
    ? `SecureBERT runs on ${local.device}; questions and evidence never leave this host for inference.`
    : local.runtime_installed
    ? `The local runtime is ready on ${local.device}. Install either specialist below from Hugging Face.`
    : 'Install a specialist below to add the local runtime and download its model files in one guided operation.';
  $('#localProfileReadiness').innerHTML = local.profiles.map(profile => `
    <div class="profile-ready-row" data-local-profile="${escapeHtml(profile.id)}"><span><i class="model-status ${profile.installed ? 'ok' : ''}"></i><b>${escapeHtml(profile.label)}</b><small>${escapeHtml(profile.model + contextIndexLabel(profile))}</small></span>
    ${profile.installed ? `<em title="Revision ${escapeHtml(profile.revision || 'recorded locally')}">Local${profile.bytes ? ` · ${escapeHtml(formatBytes(profile.bytes))}` : ''}</em>` : `<button type="button" data-pull-profile="${escapeHtml(profile.id)}">Install locally</button>`}</div>`).join('');

  const hf = readiness.huggingface;
  const hfOkay = hf.token_configured && hf.token_valid === true;
  const hfDisabled = hf.policy === 'disabled';
  readinessBadge($('#hfReadiness'), !hf.selected ? 'Optional · off' : hfDisabled ? 'Disabled by policy' : (hfOkay ? 'Cloud ready' : (hf.token_configured ? 'Token problem' : 'Token needed')), !hf.selected || hfDisabled ? '' : (hfOkay ? 'ok' : 'warn'));
  $('#hfReadinessDetail').textContent = !hf.selected
    ? 'Local Transformers is selected. No hosted inference calls will be made.'
    : hfDisabled
    ? 'Cloud runtime is selected, but policy blocks all hosted inference calls.'
    : hfOkay
    ? 'The encrypted token is valid. Hosted availability is shown below.'
    : (hf.token_configured ? 'The saved token could not be validated. Replace it and save the workspace.' : 'Cloud inference requires a fine-grained Hugging Face token.');
  $('#hfProfileReadiness').innerHTML = hf.profiles.map(profile => `
    <div class="profile-ready-row"><span><i class="model-status ${profile.reachable ? 'ok' : ''}"></i><b>${escapeHtml(profile.label)}</b><small>${escapeHtml(profile.model)}</small></span>
    <em>${!hf.selected ? 'Cloud standby' : profile.reachable == null ? 'Token first' : (profile.inference_available ? 'Hosted' : 'Endpoint needed')}</em></div>`).join('');
}

async function loadModelReadiness() {
  try { state.modelReadiness = await api('/api/model-setup/readiness'); renderModelReadiness(); renderModels(); }
  catch (error) { readinessBadge($('#ollamaReadiness'), 'Check failed', 'warn'); toast(error.message); }
}

async function loadModelCatalog() {
  try {
    state.modelCatalog = await api('/api/model-setup/catalog');
    renderModelCatalog();
  } catch (error) {
    state.modelCatalog = null;
  }
}

async function loadTimeSeriesStatus() {
  try {
    state.timeSeriesStatus = await api('/api/model-capabilities/time-series/status');
  } catch (error) {
    state.timeSeriesStatus = {ok:false, ready:false, error:error.message};
  }
  renderModelCatalog();
}

async function checkModelUpdates(button) {
  const original = button?.textContent || 'Check for updates';
  if (button) { button.disabled = true; button.textContent = 'Checking sources…'; }
  const panel = $('#modelFreshness');
  panel.hidden = false;
  panel.innerHTML = '<div><b>Checking first-party sources</b><span>No downloads or model swaps will be started.</span></div>';
  try {
    state.modelUpdates = await api('/api/model-setup/updates');
    renderModelFreshness();
    renderModels();
    await loadModelTrust(true);
  } catch (error) {
    panel.innerHTML = `<div><b>Freshness check failed</b><span>${escapeHtml(error.message)}</span></div>`;
  } finally {
    if (button) { button.disabled = false; button.textContent = original; }
  }
}

function renderModelFreshness() {
  const value = state.modelUpdates; const panel = $('#modelFreshness');
  if (!value) { panel.hidden = true; return; }
  const counts = value.counts || {};
  const checked = new Date(value.checked_at).toLocaleString();
  panel.hidden = false;
  panel.innerHTML = `<div><b>Model source check complete</b><span>${escapeHtml(value.policy)}</span></div>
    <div class="freshness-counts"><span class="current"><b>${counts.current || 0}</b> current</span><span class="update"><b>${counts['update-available'] || 0}</b> updates</span><span><b>${counts.untracked || 0}</b> untracked</span><span><b>${counts.error || 0}</b> errors</span></div>
    <time datetime="${escapeHtml(value.checked_at)}">${escapeHtml(checked)}</time>`;
}

function shortDigest(value = '') {
  return value ? `${value.slice(0, 12)}…${value.slice(-8)}` : 'not available';
}

function renderModelTrust() {
  const value = state.modelTrust; if (!value) return;
  const policy = value.policy || {}; const profiles = value.profiles || [];
  $('#modelTrustMode').textContent = policy.mode === 'enforce' ? 'Enforcement active' : 'Audit only';
  $('#modelTrustMode').classList.toggle('trust-enforced', policy.mode === 'enforce');
  $('#modelTrustPolicyMode').value = policy.mode || 'audit';
  $('#modelTrustPublishers').value = (policy.allowed_publishers || []).join(', ');
  $('#modelTrustContract').textContent = value.contract || '';
  $('#modelTrustProfiles').innerHTML = profiles.map(item => {
    const attestation = item.attestation || {};
    const action = item.trusted
      ? `<button class="button ghost small" type="button" data-revoke-model-attestation="${escapeHtml(attestation.id || '')}">Revoke approval</button>`
      : item.installed && item.verifiable && item.publisher_allowed
      ? `<button class="button primary small" type="button" data-approve-model-artifact="${escapeHtml(item.profile_id)}" data-artifact-fingerprint="${escapeHtml(item.identity_fingerprint)}">Approve exact artifact</button>`
      : '';
    return `<article class="model-trust-card ${escapeHtml(item.status || 'unverifiable')}">
      <header><div><span title="${escapeHtml((item.publisher_basis || 'unresolved').replaceAll('-', ' '))}">${escapeHtml(item.provider || 'local')} · ${escapeHtml(item.publisher || 'unknown publisher')}</span><h4>${escapeHtml(item.profile_id)}</h4></div><b>${escapeHtml((item.status || 'unknown').replaceAll('-', ' '))}</b></header>
      <p>${escapeHtml(item.detail || '')}</p>
      <dl><div><dt>Source</dt><dd>${escapeHtml(item.source_repo || item.model || 'unknown')}</dd></div><div><dt>Revision</dt><dd><code title="${escapeHtml(item.source_revision || '')}">${escapeHtml(shortDigest(item.source_revision))}</code></dd></div><div><dt>Local digest</dt><dd><code title="${escapeHtml(item.artifact_digest || '')}">${escapeHtml(shortDigest(item.artifact_digest))}</code></dd></div><div><dt>Signed by</dt><dd>${escapeHtml(attestation.approved_by || 'Not approved')}</dd></div></dl>
      <footer><span>Identity <code title="${escapeHtml(item.identity_fingerprint || '')}">${escapeHtml(shortDigest(item.identity_fingerprint))}</code></span>${action}</footer>
    </article>`;
  }).join('') || '<div class="empty-inline compact-empty">No enabled model profiles were found.</div>';
  applyAccessPermissions();
}

async function loadModelTrust(verifyFiles = false) {
  try {
    state.modelTrust = await api(`/api/model-trust${verifyFiles ? '?verify_files=true' : ''}`);
    renderModelTrust(); renderModelCatalog();
  } catch (error) {
    state.modelTrust = {policy:{mode:'unavailable'},profiles:[],error:error.message};
    $('#modelTrustProfiles').innerHTML = `<div class="empty-inline compact-empty">Model trust check failed: ${escapeHtml(error.message)}</div>`;
    renderModelCatalog();
  }
}

async function saveModelTrustPolicy(event) {
  event.preventDefault();
  const publishers = $('#modelTrustPublishers').value.split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
  const mode = $('#modelTrustPolicyMode').value;
  if (mode === 'enforce' && !confirm('Enable fail-closed model artifact enforcement? The currently routed chat and security models must already have valid exact approvals.')) return;
  try {
    state.modelTrust = await api('/api/model-trust/policy', { method:'PUT', body:JSON.stringify({ mode, allowed_publishers:publishers }) });
    renderModelTrust(); toast(mode === 'enforce' ? 'Exact model artifact enforcement enabled' : 'Model trust is reporting in audit mode');
  } catch (error) { toast(error.message); }
}

async function approveModelArtifact(button) {
  const profileId = button.dataset.approveModelArtifact;
  const fingerprint = button.dataset.artifactFingerprint;
  if (!confirm(`Approve and locally sign the exact currently installed artifact for ${profileId}? A future digest or revision change will require a new evaluation and approval.`)) return;
  button.disabled = true; button.textContent = 'Verifying files…';
  try {
    await api(`/api/model-trust/profiles/${encodeURIComponent(profileId)}/approve`, { method:'POST', body:JSON.stringify({ expected_fingerprint:fingerprint }) });
    await loadModelTrust(true); toast('Exact model artifact approved and signed locally');
  } catch (error) { button.disabled = false; button.textContent = 'Approve exact artifact'; toast(error.message); }
}

async function revokeModelAttestation(button) {
  const id = button.dataset.revokeModelAttestation;
  if (!id || !confirm('Revoke this exact artifact approval? Enforcement may immediately block its activation or promotion.')) return;
  try {
    await api(`/api/model-trust/attestations/${encodeURIComponent(id)}/revoke`, { method:'POST', body:'{}' });
    await loadModelTrust(); toast('Model artifact approval revoked');
  } catch (error) { toast(error.message); }
}

function renderModelCatalog() {
  const panel = $('#candidateModels'); const candidates = state.modelCatalog?.evaluated_candidates || [];
  if (!candidates.length) { panel.innerHTML = ''; return; }
  const localProfiles = state.modelReadiness?.local_transformers?.profiles || [];
  panel.innerHTML = `<header><div><span>CAPABILITY ADMISSION</span><h3>Useful publisher models, bounded by the job they can safely do</h3></div><p>${escapeHtml(state.modelCatalog.policy || '')}</p></header>
    <div class="candidate-model-grid">${candidates.map(item => {
      const readiness = localProfiles.find(profile => profile.id === item.profile_id);
      const trust = (state.modelTrust?.profiles || []).find(profile => profile.profile_id === item.profile_id);
      const trustEnforced = state.modelTrust?.policy?.mode !== 'audit';
      const runnable = Boolean(readiness?.installed && (!trustEnforced || trust?.trusted));
      const source = state.modelUpdates?.candidate_sources?.find(candidate => candidate.candidate_id === item.id);
      const artifactGate = item.id === 'securebert-code-vulnerability'
        ? !readiness?.installed
          ? '<li class="next"><i></i><span><b>Exact local artifact</b><small>Install explicitly, then observe its immutable revision and local digest.</small></span><em>next</em></li>'
          : trustEnforced && !trust?.trusted
          ? `<li class="blocked"><i></i><span><b>Exact local artifact approval</b><small>${escapeHtml(trust?.detail || 'Approve the installed artifact before execution.')}</small></span><em>blocked</em></li>`
          : `<li class="pass"><i></i><span><b>Exact local artifact policy</b><small>${escapeHtml(trust?.trusted ? 'The installed artifact has a valid operator-signed approval.' : 'Audit mode permits evaluation while reporting the unapproved artifact.')}</small></span><em>${trust?.trusted ? 'pass' : 'audit'}</em></li>`
        : item.id === 'cisco-time-series-1'
        ? state.timeSeriesStatus?.ok
          ? `<li class="pass"><i></i><span><b>Connected local runtime</b><small>${escapeHtml(state.timeSeriesStatus.inference_backend || 'local backend')} · revision ${escapeHtml(shortDigest(state.timeSeriesStatus.model_revision || ''))}</small></span><em>pass</em></li>`
          : `<li class="blocked"><i></i><span><b>Connected local runtime</b><small>${escapeHtml(state.timeSeriesStatus?.load_error || state.timeSeriesStatus?.error || 'Start or connect the dedicated Python 3.11 service.')}</small></span><em>setup</em></li>`
        : '';
      const gates = (item.admission_gates || []).map(gate => `<li class="${escapeHtml(gate.status)}"><i></i><span><b>${escapeHtml(gate.name)}</b><small>${escapeHtml(gate.detail)}</small></span><em>${escapeHtml(gate.status)}</em></li>`).join('') + artifactGate;
      const candidateActions = item.id === 'securebert-code-vulnerability'
        ? runnable
          ? '<button class="button primary small" type="button" data-open-code-screen>Screen source code locally</button>'
          : readiness?.installed
          ? '<span class="candidate-actions"><button class="button ghost small" type="button" data-open-code-screen>Review workflow</button><button class="button primary small" type="button" data-review-model-trust>Review artifact approval</button></span>'
          : `<span class="candidate-actions"><button class="button ghost small" type="button" data-open-code-screen>Review workflow</button><button class="button primary small" type="button" data-pull-profile="${escapeHtml(item.profile_id)}">Install local classifier</button></span>`
        : item.id === 'cisco-time-series-1'
        ? `<button class="button ${state.timeSeriesStatus?.ok ? 'primary' : 'ghost'} small" type="button" data-open-time-series>${state.timeSeriesStatus?.ok ? 'Forecast a Splunk series' : 'Configure local forecast runtime'}</button>`
        : '';
      const stage = item.id === 'securebert-code-vulnerability' && runnable
        ? 'runnable local'
        : item.id === 'securebert-code-vulnerability' && readiness?.installed
        ? 'artifact approval required'
        : item.id === 'cisco-time-series-1' && state.timeSeriesStatus?.ok
        ? 'runnable local'
        : item.id === 'cisco-time-series-1'
        ? 'local runtime setup'
        : item.status.replaceAll('-', ' ');
      return `<article class="${escapeHtml(item.status)}">
        <div><span>${escapeHtml(item.owner)} · ${escapeHtml(item.runtime.replaceAll('-', ' '))}</span><b>${escapeHtml(stage)}</b></div>
        <h4>${escapeHtml(item.label)}</h4><p>${escapeHtml(item.purpose)}</p>
        <dl><div><dt>Accepted input</dt><dd>${escapeHtml(item.input_contract || '')}</dd></div><div><dt>Required output</dt><dd>${escapeHtml(item.output_contract || '')}</dd></div></dl>
        <ul class="candidate-gates">${gates}</ul>
        <div class="candidate-boundary"><b>Boundary</b><span>${escapeHtml(item.constraint)}</span></div>
        ${source ? `<div class="candidate-source-state ${escapeHtml(source.status)}"><b>${escapeHtml(source.status.replaceAll('-', ' '))}</b><span>${escapeHtml(source.pipeline_tag || 'source metadata')} · ${escapeHtml(shortDigest(source.revision || ''))}</span><small>${escapeHtml(source.detail || '')}</small></div>` : ''}
        <footer><a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener">First-party model card ↗</a>${candidateActions}</footer>
      </article>`;
    }).join('')}</div>`;
  applyAccessPermissions();
}

function openTimeSeriesWorkbench() {
  state.timeSeriesResult = null;
  const runtime = state.timeSeriesStatus || {};
  const configured = state.settings?.time_series_runtime || {};
  const runtimeMessage = runtime.ok
    ? `<div class="forecast-runtime-state ready"><b>Runtime ready</b><span>${escapeHtml(runtime.inference_backend || 'local')} · ${escapeHtml(runtime.model_revision ? `revision ${shortDigest(runtime.model_revision)}` : 'revision not attested')}</span></div>`
    : `<div class="forecast-runtime-state"><b>Runtime setup required</b><span>${escapeHtml(runtime.load_error || runtime.error || 'The dedicated Cisco TSM service is not ready.')}</span><code>docker compose --profile forecasting up --build -d cisco-tsm</code><button class="button primary small" id="startBundledTimeSeries" type="button">Build and start bundled local runtime</button><small>Explicit action · Docker required · generates an encrypted local bearer token · first load downloads the pinned checkpoint</small></div>`;
  showDetail({
    eyebrow:'LOCAL FORECAST SPECIALIST · OPT-IN',
    title:'Forecast a bounded Splunk series',
    summary:'<p>Extract one regular numeric timechart through read-only Splunk MCP, measure source quality, withhold known points for backtesting, then forecast locally with Cisco TSM. Runs are retained as immutable local experiments without raw Splunk rows so an analyst can compare windows, accept a baseline, and deliberately stage an alert validation draft.</p>',
    content:`<section class="forecast-workbench">
      ${runtimeMessage}
      <details class="forecast-runtime-config" ${runtime.ok ? '' : 'open'}>
        <summary>Local runtime connection</summary>
        <form id="timeSeriesRuntimeForm">
          <label class="full"><span>Dedicated runtime endpoint</span><input id="timeSeriesEndpoint" type="url" value="${escapeHtml(runtime.endpoint || configured.endpoint || 'http://127.0.0.1:8080')}" required><small>Loopback, Docker service DNS, or a private-network host only. Public inference is blocked.</small></label>
          <label class="full"><span>Bearer token</span><input id="timeSeriesToken" type="password" placeholder="${state.settings?.secrets?.cisco_tsm_token ? 'Leave blank to keep saved token' : 'Required by the local service'}"></label>
          <label class="full switch-line nested-switch"><span><b>Verify TLS certificates</b><small>Keep enabled for HTTPS. Disable only for a trusted self-signed private endpoint.</small></span><input type="checkbox" id="verifyTimeSeriesTls" ${configured.verify_ssl === false ? '' : 'checked'}><span class="switch-control" aria-hidden="true"></span></label>
          <label class="full"><span>Private CA bundle path <em>optional</em></span><input id="timeSeriesCaBundle" value="${escapeHtml(configured.ca_bundle || '')}" placeholder="C:\\certs\\organization-ca.pem or /etc/ssl/org-ca.pem"></label>
          <footer><span id="timeSeriesRuntimeResult" role="status" aria-live="polite"></span><button class="button ghost" type="submit">Save and test runtime</button></footer>
        </form>
      </details>
      <form id="timeSeriesForecastForm" class="forecast-form">
        <label class="full"><span>Forecast title</span><input id="forecastTitle" value="Splunk event-rate forecast" maxlength="240" required></label>
        <label class="full"><span>Read-only timechart SPL</span><textarea id="forecastSpl" rows="4" required spellcheck="false">index=_internal | timechart span=5m count as value</textarea><small>Return exactly one timestamp field and one numeric value field. SignalRoom validates the interval and rejects duplicate buckets.</small></label>
        <label><span>Earliest</span><select id="forecastEarliest"><option value="-24h">Last 24 hours</option><option value="-7d" selected>Last 7 days</option><option value="-14d">Last 14 days</option><option value="-30d">Last 30 days</option></select></label>
        <label><span>Bucket interval</span><select id="forecastInterval"><option value="60">1 minute</option><option value="300" selected>5 minutes</option><option value="900">15 minutes</option><option value="3600">1 hour</option></select></label>
        <label><span>Timestamp field</span><input id="forecastTimestampField" value="_time" required></label>
        <label><span>Numeric field</span><input id="forecastValueField" value="value" required></label>
        <label><span>Forecast points</span><input id="forecastHorizon" type="number" value="24" min="1" max="128" required></label>
        <label><span>Backtest holdout</span><input id="forecastBacktest" type="number" value="24" min="8" max="128" required></label>
        <label><span>Maximum result rows</span><input id="forecastRows" type="number" value="2048" min="20" max="5000" required></label>
        <div class="forecast-boundary full"><b>Decision boundary</b><span>A forecast can become eligible for analyst review only when data quality passes, the model beats a naive last-value baseline, and the runtime attests its revision. No alert or threshold is changed here.</span></div>
        <button class="button primary" type="submit" id="runTimeSeriesForecast" ${runtime.ok ? '' : 'disabled'}>Run read-only forecast</button>
      </form>
      <article class="operation-card forecast-operation" id="timeSeriesProgress" aria-live="polite" hidden>
        <header><div><span class="operation-kicker">LOCAL FORECAST RUN</span><h3 class="operation-label">Preparing forecast</h3></div><span class="operation-elapsed">0s</span></header>
        <p class="operation-detail">Checking the dedicated local runtime.</p>
        <div class="operation-progress" role="progressbar" aria-label="Time-series forecast progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i></i></div>
        <div class="operation-metrics"></div><ol class="operation-steps"></ol>
      </article>
      <div id="timeSeriesOutput" class="forecast-output" aria-live="polite"></div>
      <section class="forecast-schedules" aria-labelledby="timeSeriesScheduleTitle">
        <header><div><span>OPT-IN SHADOW FORECASTING</span><h3 id="timeSeriesScheduleTitle">Watch a reviewed series on a hard budget</h3><p>Save the exact contract above, run it only on the cadence you explicitly start, and route meaningful baseline changes to an analyst queue. Missed intervals are coalesced; runs never create alerts or change thresholds.</p></div><button class="button ghost small" id="refreshTimeSeriesSchedules" type="button">Refresh schedules</button></header>
        <details class="forecast-schedule-create">
          <summary>Create a shadow schedule from the current contract</summary>
          <form id="timeSeriesScheduleForm">
            <label class="full"><span>Schedule title</span><input id="forecastScheduleTitle" value="Splunk event-rate shadow" maxlength="240" required><small>The saved forecast title, SPL, fields, window, horizon, and backtest are copied from the form above.</small></label>
            <label><span>Cadence</span><select id="forecastScheduleInterval"><option value="60">Every hour</option><option value="360" selected>Every 6 hours</option><option value="720">Every 12 hours</option><option value="1440">Daily</option><option value="10080">Weekly</option></select></label>
            <label><span>Per-schedule UTC daily ceiling</span><input id="forecastScheduleDailyLimit" type="number" value="4" min="1" max="12" required></label>
            <label><span>Comparison reference</span><select id="forecastScheduleSeasonal"><option value="true" selected>Matching weekday, then general</option><option value="false">General baseline only</option></select></label>
            <label><span>Initial state</span><select id="forecastScheduleEnabled"><option value="false" selected>Create paused</option><option value="true">Create and start cadence</option></select></label>
            <div class="forecast-boundary full"><b>Safety contract</b><span>Single local execution lane · at most 24 shadow runs per UTC day across SignalRoom · owner access rechecked before every run · no catch-up storm after downtime.</span></div>
            <button class="button primary" type="submit">Save shadow schedule</button>
          </form>
        </details>
        <article class="operation-card forecast-operation" id="timeSeriesScheduleProgress" aria-live="polite" hidden>
          <header><div><span class="operation-kicker">SHADOW FORECAST RUN</span><h3 class="operation-label">Waiting for the local forecast lane</h3></div><span class="operation-elapsed">0s</span></header>
          <p class="operation-detail">The owner, runtime, and read-only contract will be checked first.</p>
          <div class="operation-progress" role="progressbar" aria-label="Shadow forecast progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i></i></div>
          <div class="operation-metrics"></div><ol class="operation-steps"></ol>
        </article>
        <div id="timeSeriesScheduleHistory" aria-live="polite"><div class="empty-inline compact-empty">Loading shadow schedules…</div></div>
        <div id="timeSeriesReviewQueue" aria-live="polite"></div>
      </section>
      <section class="forecast-experiments" aria-labelledby="timeSeriesExperimentTitle">
        <header><div><span>LOCAL EXPERIMENT REGISTRY</span><h3 id="timeSeriesExperimentTitle">Repeat, compare, then review</h3><p>Each run retains its contract, backtest, forecast, model revision, and fingerprints—not the source rows. Baselines and alert candidates require exact-run review.</p></div><button class="button ghost small" id="refreshTimeSeriesExperiments" type="button">Refresh history</button></header>
        <div id="timeSeriesExperimentHistory" aria-live="polite"><div class="empty-inline compact-empty">Loading retained forecast history…</div></div>
      </section>
    </section>`,
    provenance:'<h3>Execution contract</h3><dl><div><dt>Model</dt><dd>cisco-ai/cisco-time-series-model-1.0</dd></div><div><dt>Inference</dt><dd>Local/private dedicated service</dd></div><div><dt>Splunk writes</dt><dd>None</dd></div><div><dt>Automatic routing</dt><dd>Prohibited</dd></div></dl>'
  });
  $('#timeSeriesRuntimeForm').addEventListener('submit', saveTimeSeriesRuntime);
  $('#timeSeriesForecastForm').addEventListener('submit', runTimeSeriesForecast);
  $('#timeSeriesScheduleForm').addEventListener('submit', createTimeSeriesSchedule);
  if ($('#startBundledTimeSeries')) {
    $('#startBundledTimeSeries').addEventListener('click', startBundledTimeSeriesRuntime);
  }
  $('#refreshTimeSeriesExperiments').addEventListener('click', loadTimeSeriesExperiments);
  $('#refreshTimeSeriesSchedules').addEventListener('click', loadTimeSeriesSchedules);
  loadTimeSeriesExperiments();
  loadTimeSeriesSchedules();
  applyAccessPermissions();
  (runtime.ok ? $('#forecastSpl') : $('#timeSeriesEndpoint')).focus();
}

async function startBundledTimeSeriesRuntime(event) {
  const button = event.currentTarget; const progress = $('#timeSeriesProgress');
  button.disabled = true; button.textContent = 'Starting Docker runtime…'; progress.hidden = false;
  progress.querySelector('.operation-steps').innerHTML = ''; progress.querySelector('.operation-metrics').innerHTML = '';
  progress.querySelector('.operation-progress i').style.width = '0%';
  try {
    state.timeSeriesStatus = await streamApi(
      '/api/model-capabilities/time-series/runtime/start/stream',
      {},
      event => updateOperation(progress, event)
    );
    state.settings.time_series_runtime = {
      endpoint:state.timeSeriesStatus.endpoint || 'http://127.0.0.1:8080',
      verify_ssl:true,
      ca_bundle:null
    };
    state.settings.secrets.cisco_tsm_token = true;
    renderModelCatalog();
    toast('Bundled Cisco TSM runtime ready');
    openTimeSeriesWorkbench();
  } catch (error) {
    button.disabled = false; button.textContent = 'Build and start bundled local runtime';
    $('#timeSeriesOutput').innerHTML = `<div class="code-screen-error"><b>Runtime start stopped</b><span>${escapeHtml(error.message)}</span></div>`;
  }
}

async function saveTimeSeriesRuntime(event) {
  event.preventDefault();
  const result = $('#timeSeriesRuntimeResult'); result.textContent = 'Checking…';
  try {
    state.timeSeriesStatus = await api('/api/model-capabilities/time-series/runtime', {
      method:'PUT',
      body:JSON.stringify({
        endpoint:$('#timeSeriesEndpoint').value.trim(),
        token:$('#timeSeriesToken').value || null,
        verify_ssl:$('#verifyTimeSeriesTls').checked,
        ca_bundle:$('#verifyTimeSeriesTls').checked ? ($('#timeSeriesCaBundle').value.trim() || null) : null
      })
    });
    state.settings.time_series_runtime = {
      endpoint:state.timeSeriesStatus.endpoint,
      verify_ssl:$('#verifyTimeSeriesTls').checked,
      ca_bundle:$('#verifyTimeSeriesTls').checked ? ($('#timeSeriesCaBundle').value.trim() || null) : null
    };
    if ($('#timeSeriesToken').value) state.settings.secrets.cisco_tsm_token = true;
    result.textContent = state.timeSeriesStatus.ok ? 'Runtime ready' : (state.timeSeriesStatus.load_error || state.timeSeriesStatus.error || 'Saved; runtime is still loading');
    $('#runTimeSeriesForecast').disabled = !state.timeSeriesStatus.ok;
    $('#timeSeriesToken').value = '';
    renderModelCatalog();
  } catch (error) {
    result.textContent = error.message;
  }
}

function timeSeriesRequestFromForm() {
  return {
    title:$('#forecastTitle').value.trim(),
    spl:$('#forecastSpl').value.trim(),
    earliest_time:$('#forecastEarliest').value,
    latest_time:'now',
    row_limit:Number($('#forecastRows').value),
    timestamp_field:$('#forecastTimestampField').value.trim(),
    value_field:$('#forecastValueField').value.trim(),
    interval_seconds:Number($('#forecastInterval').value),
    horizon:Number($('#forecastHorizon').value),
    backtest_points:Number($('#forecastBacktest').value)
  };
}

async function loadTimeSeriesSchedules(event) {
  clearTimeout(state.timeSeriesScheduleTimer);
  const button = event?.currentTarget?.id === 'refreshTimeSeriesSchedules' ? event.currentTarget : null;
  if (button) { button.disabled = true; button.textContent = 'Refreshing…'; }
  try {
    state.timeSeriesSchedules = await api('/api/model-capabilities/time-series/schedules?limit=40');
    renderTimeSeriesSchedules();
    const active = (state.timeSeriesSchedules.attempts || []).some(item => ['queued','running'].includes(item.status));
    if (active && $('#timeSeriesScheduleHistory') && !$('#detailModal').hidden) {
      state.timeSeriesScheduleTimer = setTimeout(loadTimeSeriesSchedules, 1800);
    }
  } catch (error) {
    const panel = $('#timeSeriesScheduleHistory');
    if (panel) panel.innerHTML = `<div class="code-screen-error"><b>Shadow schedules unavailable</b><span>${escapeHtml(error.message)}</span></div>`;
  } finally {
    if (button) { button.disabled = false; button.textContent = 'Refresh schedules'; }
  }
}

function forecastScheduleCadence(minutes) {
  const value = Number(minutes || 0);
  if (value >= 10080 && value % 10080 === 0) return `${value / 10080} week`;
  if (value >= 1440 && value % 1440 === 0) return `${value / 1440} day`;
  if (value >= 60 && value % 60 === 0) return `${value / 60} hour`;
  return `${value} minute`;
}

function forecastScheduleTime(value, empty = 'Not yet run') {
  return value ? new Date(value).toLocaleString() : empty;
}

function renderTimeSeriesSchedules() {
  const panel = $('#timeSeriesScheduleHistory'); const reviewPanel = $('#timeSeriesReviewQueue');
  if (!panel || !reviewPanel) return;
  const registry = state.timeSeriesSchedules || {}; const schedules = registry.schedules || [];
  const attempts = registry.attempts || []; const reviews = registry.reviews || [];
  const worker = registry.worker || {}; const usage = registry.usage_today || {};
  const workerState = `<div class="forecast-schedule-contract"><span><b>${worker.online ? 'Online' : 'Offline'}</b>single execution worker</span><span><b>${Number(usage.global_runs || 0)}/${Number(usage.global_limit || 24)}</b>UTC daily global budget</span><span><b>0</b>automatic alerts</span><span><b>Fresh retry</b>after restart</span></div>`;
  if (!schedules.length) {
    panel.innerHTML = `${workerState}<div class="empty-inline compact-empty">No shadow schedules yet. Save the current bounded contract above; the safe default is paused.</div>`;
  } else {
    panel.innerHTML = `${workerState}<div class="forecast-schedule-list">${schedules.map(schedule => {
      const latest = attempts.find(item => item.schedule_id === schedule.id);
      const events = latest?.events || []; const lastEvent = events.at(-1);
      const usageToday = schedule.usage_today || {};
      const active = latest && ['queued','running'].includes(latest.status);
      const eventSteps = active ? `<ol class="forecast-attempt-steps">${events.slice(-5).map(item => `<li class="${escapeHtml(item.status)}"><i></i><span><b>${escapeHtml(item.label)}</b><small>${escapeHtml(item.detail)}</small></span></li>`).join('')}</ol>` : '';
      return `<article class="forecast-schedule ${schedule.enabled ? 'enabled' : 'paused'}">
        <header><div><span>${schedule.enabled ? 'CADENCE ACTIVE' : 'PAUSED'} · ${escapeHtml(schedule.created_by)}</span><h4>${escapeHtml(schedule.title)}</h4></div><b>${schedule.enabled ? 'active' : 'paused'}</b></header>
        <p>${escapeHtml(schedule.request.spl)}</p>
        <div class="forecast-schedule-metrics"><span><b>${escapeHtml(forecastScheduleCadence(schedule.interval_minutes))}</b>cadence</span><span><b>${Number(usageToday.schedule_runs || 0)}/${Number(schedule.max_runs_per_day)}</b>schedule budget today</span><span><b>${escapeHtml(forecastScheduleTime(schedule.next_run_at, 'Paused'))}</b>next eligible run</span><span><b>${escapeHtml(schedule.seasonal_comparison ? 'weekday → general' : 'general only')}</b>comparison</span></div>
        ${latest ? `<div class="forecast-attempt ${escapeHtml(latest.status)}"><div><b>${escapeHtml(latest.label)}</b><span>${escapeHtml(latest.trigger)} · ${escapeHtml(forecastScheduleTime(latest.updated_at))}</span></div><p>${escapeHtml(latest.error || latest.detail)}</p>${active ? `<div class="operation-progress" role="progressbar" aria-label="Latest shadow attempt progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Number(latest.progress)}"><i style="width:${Number(latest.progress)}%"></i></div>` : ''}${eventSteps}${lastEvent?.metrics && Object.keys(lastEvent.metrics).length ? `<div class="operation-metrics">${Object.entries(lastEvent.metrics).slice(0,4).map(([key,value]) => formatMetric(key,value)).join('')}</div>` : ''}</div>` : '<div class="forecast-attempt empty"><p>No attempts yet. Starting the cadence waits until the next interval; Run now remains explicit.</p></div>'}
        <footer><button class="button ghost small" type="button" data-run-forecast-schedule="${escapeHtml(schedule.id)}" ${active ? 'disabled' : ''}>Run now</button><button class="button ghost small" type="button" data-toggle-forecast-schedule="${escapeHtml(schedule.id)}" data-enable="${schedule.enabled ? 'false' : 'true'}">${schedule.enabled ? 'Pause cadence' : 'Start cadence'}</button><button class="button ghost small danger-action" type="button" data-archive-forecast-schedule="${escapeHtml(schedule.id)}" ${active ? 'disabled' : ''}>Archive</button></footer>
      </article>`;
    }).join('')}</div>`;
  }
  const pending = reviews.filter(item => item.state === 'pending');
  reviewPanel.innerHTML = `<section class="forecast-review-queue"><header><div><span>ANALYST REVIEW QUEUE</span><h4>${pending.length} forecast change${pending.length === 1 ? '' : 's'} awaiting interpretation</h4><p>Acknowledging records that the change was reviewed. Dismissing records why it is noise. Neither action creates an alert, validation, or threshold.</p></div></header>${pending.length ? pending.map(item => `<article class="${escapeHtml(item.comparison_decision)}"><header><div><span>${escapeHtml(item.comparison_decision.replaceAll('-', ' '))}</span><h5>${escapeHtml(item.summary)}</h5></div><code>${escapeHtml(shortDigest(item.run_fingerprint))}</code></header><ul>${(item.reasons || []).map(reason => `<li>${escapeHtml(reason)}</li>`).join('')}</ul><form data-time-series-review-form="${escapeHtml(item.id)}" data-run-fingerprint="${escapeHtml(item.run_fingerprint)}"><label><span>Analyst disposition note</span><textarea name="note" rows="2" minlength="3" maxlength="4000" required placeholder="Explain the operating change, seasonality, collection issue, or reason this needs follow-up…"></textarea></label><div><button class="button primary small" type="submit" data-review-decision="acknowledge">Acknowledge review</button><button class="button ghost small" type="submit" data-review-decision="dismiss">Dismiss as noise</button></div></form></article>`).join('') : '<div class="empty-inline compact-empty">No forecast changes need review. Stable shadow runs remain in attempt history without creating queue noise.</div>'}</section>`;
  reviewPanel.querySelectorAll('[data-time-series-review-form]').forEach(form => form.addEventListener('submit', decideTimeSeriesReview));
  applyAccessPermissions();
}

async function createTimeSeriesSchedule(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true; button.textContent = 'Saving bounded schedule…';
  try {
    await api('/api/model-capabilities/time-series/schedules', {
      method:'POST',
      body:JSON.stringify({
        title:$('#forecastScheduleTitle').value.trim(),
        request:timeSeriesRequestFromForm(),
        enabled:$('#forecastScheduleEnabled').value === 'true',
        interval_minutes:Number($('#forecastScheduleInterval').value),
        max_runs_per_day:Number($('#forecastScheduleDailyLimit').value),
        seasonal_comparison:$('#forecastScheduleSeasonal').value === 'true'
      })
    });
    await loadTimeSeriesSchedules();
    toast($('#forecastScheduleEnabled').value === 'true' ? 'Shadow cadence started; first run waits for the next interval' : 'Shadow schedule saved paused');
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false; button.textContent = 'Save shadow schedule';
  }
}

async function toggleTimeSeriesSchedule(button) {
  const schedule = (state.timeSeriesSchedules?.schedules || []).find(item => item.id === button.dataset.toggleForecastSchedule);
  if (!schedule) return;
  button.disabled = true;
  try {
    await api(`/api/model-capabilities/time-series/schedules/${encodeURIComponent(schedule.id)}`, {
      method:'PATCH',
      body:JSON.stringify({
        expected_updated_at:schedule.updated_at,
        enabled:button.dataset.enable === 'true'
      })
    });
    await loadTimeSeriesSchedules();
    toast(button.dataset.enable === 'true' ? 'Shadow cadence started; no immediate query was run' : 'Shadow cadence paused');
  } catch (error) { button.disabled = false; toast(error.message); }
}

async function archiveTimeSeriesSchedule(button) {
  const schedule = (state.timeSeriesSchedules?.schedules || []).find(item => item.id === button.dataset.archiveForecastSchedule);
  if (!schedule || !confirm(`Archive "${schedule.title}"? Its attempt and review history will remain retained.`)) return;
  button.disabled = true;
  try {
    await api(`/api/model-capabilities/time-series/schedules/${encodeURIComponent(schedule.id)}?expected_updated_at=${encodeURIComponent(schedule.updated_at)}`, {method:'DELETE'});
    await loadTimeSeriesSchedules(); toast('Shadow schedule archived; history retained');
  } catch (error) { button.disabled = false; toast(error.message); }
}

async function runTimeSeriesSchedule(button) {
  const scheduleId = button.dataset.runForecastSchedule; const progress = $('#timeSeriesScheduleProgress');
  button.disabled = true; button.textContent = 'Running…'; progress.hidden = false;
  progress.querySelector('.operation-steps').innerHTML = ''; progress.querySelector('.operation-metrics').innerHTML = '';
  progress.querySelector('.operation-progress i').style.width = '0%';
  try {
    const result = await streamApi(`/api/model-capabilities/time-series/schedules/${encodeURIComponent(scheduleId)}/run/stream`, {}, event => updateOperation(progress, event));
    await Promise.all([loadTimeSeriesSchedules(), loadTimeSeriesExperiments()]);
    toast(result.review ? 'Shadow forecast retained and routed to analyst review' : 'Stable shadow forecast retained without review noise');
  } catch (error) {
    toast(error.message); await loadTimeSeriesSchedules();
  } finally {
    button.disabled = false; button.textContent = 'Run now';
  }
}

async function decideTimeSeriesReview(event) {
  event.preventDefault();
  const form = event.currentTarget; const button = event.submitter;
  if (!button) return;
  const note = new FormData(form).get('note');
  form.querySelectorAll('button').forEach(item => item.disabled = true);
  try {
    await api(`/api/model-capabilities/time-series/reviews/${encodeURIComponent(form.dataset.timeSeriesReviewForm)}`, {
      method:'POST',
      body:JSON.stringify({
        expected_run_fingerprint:form.dataset.runFingerprint,
        decision:button.dataset.reviewDecision,
        note
      })
    });
    await loadTimeSeriesSchedules();
    toast('Forecast disposition recorded; no alert or threshold changed');
  } catch (error) {
    form.querySelectorAll('button').forEach(item => item.disabled = false); toast(error.message);
  }
}

async function loadTimeSeriesExperiments(event) {
  const button = event?.currentTarget?.id === 'refreshTimeSeriesExperiments' ? event.currentTarget : null;
  if (button) { button.disabled = true; button.textContent = 'Refreshing…'; }
  try {
    state.timeSeriesExperiments = await api('/api/model-capabilities/time-series/experiments?limit=40');
    renderTimeSeriesExperiments();
  } catch (error) {
    const panel = $('#timeSeriesExperimentHistory');
    if (panel) panel.innerHTML = `<div class="code-screen-error"><b>Experiment history unavailable</b><span>${escapeHtml(error.message)}</span></div>`;
  } finally {
    if (button) { button.disabled = false; button.textContent = 'Refresh history'; }
  }
}

function forecastIntervalLabel(seconds) {
  const value = Number(seconds || 0);
  if (value % 3600 === 0) return `${value / 3600}h buckets`;
  if (value % 60 === 0) return `${value / 60}m buckets`;
  return `${value}s buckets`;
}

function forecastDriftMetric(value, suffix = '%') {
  if (value == null || !Number.isFinite(Number(value))) return 'n/a';
  const number = Number(value);
  return `${number > 0 ? '+' : ''}${number.toFixed(1)}${suffix}`;
}

function renderTimeSeriesExperiments() {
  const panel = $('#timeSeriesExperimentHistory'); if (!panel) return;
  const registry = state.timeSeriesExperiments || {}; const runs = registry.runs || [];
  const candidates = registry.alert_candidates || [];
  if (!runs.length) {
    panel.innerHTML = '<div class="empty-inline compact-empty">No retained runs yet. The next completed or data-quality-blocked forecast will appear here automatically.</div>';
    return;
  }
  const caseOptions = `<option value="">No linked case</option>${(state.cases || []).map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.title)}</option>`).join('')}`;
  const runCards = runs.map(run => {
    const comparison = run.comparison || {}; const metrics = comparison.metrics || {};
    const backtest = run.backtest || {}; const source = run.source || {}; const series = run.series || {};
    const created = run.created_at ? new Date(run.created_at).toLocaleString() : 'unknown time';
    const mase = backtest.mase_vs_last_value == null ? 'undefined' : Number(backtest.mase_vs_last_value).toFixed(3);
    const decision = comparison.decision || 'no-baseline';
    const baselineSlots = run.baseline_slots || []; const isReference = baselineSlots.length > 0;
    const baselineAction = run.promotion_ready ? `<details class="forecast-review-action"><summary>Accept as a reviewed comparison baseline</summary>
      <form data-time-series-baseline-form="${escapeHtml(run.id)}" data-run-fingerprint="${escapeHtml(run.run_fingerprint)}">
        <label><span>Reference scope</span><select name="baseline_scope"><option value="matching-weekday">Matching weekday (${escapeHtml(comparison.seasonal_slot?.replace('weekday-', 'weekday ') || 'observed day')})</option><option value="general">General fallback</option></select></label>
        <label><span>Why this run is representative</span><textarea name="review_note" rows="2" minlength="3" maxlength="4000" required placeholder="Record data quality, operating period, and why this is a defensible reference…"></textarea></label>
        <button class="button primary small" type="submit">Accept exact run</button>
        <small>This replaces only the selected reference slot for this logical series. It does not change Splunk.</small>
      </form></details>` : '';
    const candidateAction = isReference ? `<details class="forecast-review-action"><summary>Stage an alert validation candidate</summary>
      <form data-time-series-candidate-form="${escapeHtml(run.id)}" data-run-fingerprint="${escapeHtml(run.run_fingerprint)}">
        <label><span>Candidate title</span><input name="title" value="${escapeHtml(`Validate ${run.title}`)}" maxlength="240" required></label>
        <label><span>Boundary direction</span><select name="direction"><option value="above">Above forecast p90</option><option value="below">Below forecast p10</option></select></label>
        <label class="full"><span>Analyst rationale</span><textarea name="rationale" rows="2" minlength="3" maxlength="4000" required placeholder="Explain the operational condition this boundary should test…"></textarea></label>
        <label class="full"><span>Linked case <em>optional</em></span><select name="case_id">${caseOptions}</select></label>
        <button class="button primary small" type="submit">Create review-only candidate</button>
        <small>Creates an editable validation draft. No search runs and no alert is created.</small>
      </form></details>` : '';
    const referenceLabel = baselineSlots.length ? baselineSlots.map(slot => slot === 'general' ? 'general' : `weekday ${Number(slot.split('-')[1]) + 1}`).join(' + ') : '';
    return `<article class="forecast-experiment ${escapeHtml(decision)} ${isReference ? 'baseline' : ''}">
      <header><div><span>${escapeHtml(isReference ? `REVIEWED REFERENCE · ${referenceLabel}` : 'RETAINED RUN')} · ${escapeHtml(created)}</span><h4>${escapeHtml(run.title)}</h4></div><b>${escapeHtml(isReference ? 'reference' : decision.replaceAll('-', ' '))}</b></header>
      <div class="forecast-experiment-metrics"><span><b>${mase}</b>MASE</span><span><b>${Math.round(Number(series.imputation_ratio || 0) * 100)}%</b>imputed</span><span><b>${escapeHtml(forecastIntervalLabel(source.interval_seconds))}</b>span</span><span><b>${escapeHtml(source.earliest_time || 'unknown')}</b>window</span></div>
      <p>${escapeHtml(comparison.selection_reason || '')} ${escapeHtml((comparison.reasons || ['No comparison detail recorded.']).join(' '))}</p>
      ${comparison.baseline_run_id ? `<dl class="forecast-drift"><div><dt>Series mean</dt><dd>${escapeHtml(forecastDriftMetric(metrics.series_mean_change_percent))}</dd></div><div><dt>Forecast center</dt><dd>${escapeHtml(forecastDriftMetric(metrics.forecast_center_change_percent))}</dd></div><div><dt>MASE delta</dt><dd>${escapeHtml(forecastDriftMetric(metrics.mase_delta, ''))}</dd></div><div><dt>Imputation delta</dt><dd>${escapeHtml(forecastDriftMetric(Number(metrics.imputation_delta_points || 0) * 100, ' pts'))}</dd></div></dl>` : ''}
      <details><summary>Exact retained contract</summary><dl><div><dt>Run fingerprint</dt><dd><code>${escapeHtml(run.run_fingerprint)}</code></dd></div><div><dt>Series key</dt><dd><code>${escapeHtml(run.series_key)}</code></dd></div><div><dt>Model revision</dt><dd><code>${escapeHtml(run.runtime?.source_revision || 'not attested')}</code></dd></div><div><dt>Source rows</dt><dd>${Number(series.source_rows || 0).toLocaleString()} counted · not retained</dd></div></dl></details>
      <footer><button class="button ghost small" type="button" data-rerun-time-series="${escapeHtml(run.id)}">Load exact contract</button></footer>
      ${baselineAction}${candidateAction}
    </article>`;
  }).join('');
  const candidateCards = candidates.length ? `<section class="forecast-candidate-history"><header><span>ALERT VALIDATION HANDOFFS</span><h4>Review-only candidates</h4></header>${candidates.map(item => `<article><div><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.status.replaceAll('-', ' '))}</span></div><p>${escapeHtml(`${item.direction} ${Number(item.threshold).toLocaleString()} · ${item.threshold_source}`)}</p><details><summary>Proposed read-only SPL</summary><code>${escapeHtml(item.proposed_spl)}</code></details><button class="button ghost small" type="button" data-open-forecast-validation="${escapeHtml(item.validation_task_id)}">Open validation draft</button></article>`).join('')}</section>` : '';
  panel.innerHTML = `<div class="forecast-experiment-list">${runCards}</div>${candidateCards}`;
  panel.querySelectorAll('[data-rerun-time-series]').forEach(button => button.addEventListener('click', loadRetainedTimeSeriesContract));
  panel.querySelectorAll('[data-time-series-baseline-form]').forEach(form => form.addEventListener('submit', acceptTimeSeriesBaseline));
  panel.querySelectorAll('[data-time-series-candidate-form]').forEach(form => form.addEventListener('submit', createTimeSeriesAlertCandidate));
  panel.querySelectorAll('[data-open-forecast-validation]').forEach(button => button.addEventListener('click', openForecastValidationDraft));
  applyAccessPermissions();
}

function loadRetainedTimeSeriesContract(event) {
  const id = event.currentTarget.dataset.rerunTimeSeries;
  const run = (state.timeSeriesExperiments?.runs || []).find(item => item.id === id);
  if (!run) return;
  const request = run.request || {};
  $('#forecastTitle').value = request.title || run.title || 'Splunk event-rate forecast';
  $('#forecastSpl').value = request.spl || '';
  const selectValue = (selector, value, label) => {
    const select = $(selector); if (!select) return;
    if (![...select.options].some(option => option.value === String(value))) {
      select.add(new Option(label, String(value)));
    }
    select.value = String(value);
  };
  selectValue('#forecastEarliest', request.earliest_time || '-7d', request.earliest_time || '-7d');
  selectValue('#forecastInterval', request.interval_seconds || 300, forecastIntervalLabel(request.interval_seconds || 300));
  $('#forecastTimestampField').value = request.timestamp_field || '_time';
  $('#forecastValueField').value = request.value_field || 'value';
  $('#forecastHorizon').value = request.horizon || 24;
  $('#forecastBacktest').value = request.backtest_points || 24;
  $('#forecastRows').value = request.row_limit || 2048;
  $('#timeSeriesForecastForm').scrollIntoView({behavior:'smooth', block:'start'});
  toast('Exact retained contract loaded; running it remains an explicit action');
}

async function acceptTimeSeriesBaseline(event) {
  event.preventDefault();
  const form = event.currentTarget; const button = form.querySelector('button[type="submit"]');
  button.disabled = true; button.textContent = 'Accepting exact run…';
  try {
    await api(`/api/model-capabilities/time-series/experiments/${encodeURIComponent(form.dataset.timeSeriesBaselineForm)}/baseline`, {
      method:'POST',
      body:JSON.stringify({
        expected_run_fingerprint:form.dataset.runFingerprint,
        review_note:new FormData(form).get('review_note'),
        baseline_scope:new FormData(form).get('baseline_scope')
      })
    });
    await loadTimeSeriesExperiments();
    toast('Reviewed forecast baseline accepted');
  } catch (error) {
    button.disabled = false; button.textContent = 'Accept exact run'; toast(error.message);
  }
}

async function createTimeSeriesAlertCandidate(event) {
  event.preventDefault();
  const form = event.currentTarget; const button = form.querySelector('button[type="submit"]');
  const values = new FormData(form);
  button.disabled = true; button.textContent = 'Staging validation draft…';
  try {
    const result = await api(`/api/model-capabilities/time-series/experiments/${encodeURIComponent(form.dataset.timeSeriesCandidateForm)}/alert-candidates`, {
      method:'POST',
      body:JSON.stringify({
        expected_run_fingerprint:form.dataset.runFingerprint,
        title:values.get('title'),
        rationale:values.get('rationale'),
        direction:values.get('direction'),
        case_id:values.get('case_id') || null
      })
    });
    state.validations = [result.validation, ...state.validations.filter(item => item.id !== result.validation.id)];
    renderValidations();
    await loadTimeSeriesExperiments();
    toast(result.reused ? 'Existing validation draft reopened; nothing executed' : 'Alert candidate staged as an editable validation draft; nothing executed');
  } catch (error) {
    button.disabled = false; button.textContent = 'Create review-only candidate'; toast(error.message);
  }
}

async function openForecastValidationDraft(event) {
  const taskId = event.currentTarget.dataset.openForecastValidation;
  closeDetail();
  await loadValidations();
  setView('discovery');
  const card = document.querySelector(`[data-validation-id="${CSS.escape(taskId)}"]`);
  if (card) card.scrollIntoView({behavior:'smooth', block:'center'});
}

function chartPath(values, x0, x1, y0, y1, minimum, maximum) {
  if (!values?.length) return '';
  const span = maximum - minimum || 1;
  return values.map((value, index) => {
    const x = x0 + (x1 - x0) * index / Math.max(1, values.length - 1);
    const y = y1 - (y1 - y0) * (Number(value) - minimum) / span;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

function forecastChart(result) {
  const backtest = result.backtest || {}; const forecast = result.forecast || {};
  const mean = forecast.mean || []; const low = forecast.quantiles?.p10 || mean; const high = forecast.quantiles?.p90 || mean;
  const all = [...(backtest.actual || []), ...(backtest.predicted || []), ...mean, ...low, ...high].map(Number).filter(Number.isFinite);
  if (!all.length) return '';
  const minimum = Math.min(...all); const maximum = Math.max(...all);
  const actualPath = chartPath(backtest.actual, 28, 337, 24, 210, minimum, maximum);
  const predictedPath = chartPath(backtest.predicted, 28, 337, 24, 210, minimum, maximum);
  const meanPath = chartPath(mean, 383, 692, 24, 210, minimum, maximum);
  const lowPoints = chartPath(low, 383, 692, 24, 210, minimum, maximum);
  const highPoints = chartPath(high, 383, 692, 24, 210, minimum, maximum).split(' ').reverse().join(' ');
  return `<figure class="forecast-chart"><svg viewBox="0 0 720 250" role="img" aria-labelledby="forecastChartTitle forecastChartDesc"><title id="forecastChartTitle">Backtest and forecast review</title><desc id="forecastChartDesc">Left: held-out actual values versus Cisco TSM predictions. Right: future mean forecast with the tenth-to-ninetieth percentile interval.</desc><line x1="360" y1="16" x2="360" y2="218"></line><polygon points="${lowPoints} ${highPoints}"></polygon><polyline class="actual" points="${actualPath}"></polyline><polyline class="predicted" points="${predictedPath}"></polyline><polyline class="mean" points="${meanPath}"></polyline><text x="28" y="238">WITHHELD BACKTEST</text><text x="383" y="238">UNSEEN FORECAST</text></svg><figcaption><span><i class="actual"></i>Actual holdout</span><span><i class="predicted"></i>Backtest prediction</span><span><i class="mean"></i>Forecast mean</span><span><i class="band"></i>p10–p90</span></figcaption></figure>`;
}

function renderTimeSeriesResult(result) {
  const output = $('#timeSeriesOutput'); const gate = result.promotion_gate || {};
  const experiment = result.experiment || {}; const comparison = experiment.comparison || {};
  if (result.status === 'blocked-data-quality') {
    output.innerHTML = `<article class="forecast-result hold"><header><div><span>DATA-QUALITY GATE</span><h4>Forecast stopped before inference</h4></div><b>Blocked</b></header><p>${escapeHtml(gate.reasons?.[0] || 'Source quality did not pass.')}</p><div class="forecast-metrics"><span><b>${Math.round(Number(result.series.imputation_ratio || 0) * 100)}%</b>imputed</span><span><b>${Number(result.series.expected_points || 0).toLocaleString()}</b>prepared points</span><span><b>0</b>forecast calls</span></div>${experiment.run_fingerprint ? `<div class="forecast-retained"><b>Retained for quality comparison</b><span>Run <code>${escapeHtml(shortDigest(experiment.run_fingerprint))}</code> · no source rows stored</span></div>` : ''}</article>`;
    return;
  }
  const backtest = result.backtest || {}; const ready = Boolean(gate.ready);
  const mase = backtest.mase_vs_last_value == null ? 'Undefined' : Number(backtest.mase_vs_last_value).toFixed(3);
  output.innerHTML = `<article class="forecast-result ${ready ? 'ready' : 'hold'}">
    <header><div><span>FORECAST PROMOTION EVIDENCE</span><h4>${ready ? 'Eligible for analyst review' : 'Forecast complete · promotion held'}</h4></div><b>${escapeHtml(gate.decision || 'hold')}</b></header>
    <p>${escapeHtml((gate.reasons || []).join(' '))}</p>
    <div class="forecast-metrics"><span><b>${mase}</b>MASE vs naive</span><span><b>${Math.round(Number(result.series.imputation_ratio || 0) * 100)}%</b>imputed</span><span><b>${Number(result.series.expected_points || 0).toLocaleString()}</b>context points</span><span><b>${Number(result.forecast?.horizon || 0)}</b>forecast points</span></div>
    ${forecastChart(result)}
    ${experiment.run_fingerprint ? `<div class="forecast-retained ${escapeHtml(comparison.decision || 'no-baseline')}"><b>Immutable experiment retained · ${escapeHtml((comparison.decision || 'no-baseline').replaceAll('-', ' '))}</b><span>${escapeHtml((comparison.reasons || []).join(' '))}</span><code>${escapeHtml(shortDigest(experiment.run_fingerprint))}</code></div>` : ''}
    <details><summary>Exact provenance and boundary</summary><dl><div><dt>Query fingerprint</dt><dd><code>${escapeHtml(result.source.query_fingerprint)}</code></dd></div><div><dt>Series SHA-256</dt><dd><code>${escapeHtml(result.series_sha256)}</code></dd></div><div><dt>Model revision</dt><dd><code>${escapeHtml(result.runtime.source_revision || 'not attested')}</code></dd></div><div><dt>Runtime</dt><dd>${escapeHtml(`${result.runtime.network_scope || 'local'} · ${result.runtime.backend || 'backend not reported'}`)}</dd></div></dl></details>
    <footer><button class="button ghost small" type="button" data-time-series-case>Preserve review to case</button><button class="button ghost small" type="button" data-time-series-investigate>Investigate the operational meaning</button></footer>
  </article>`;
}

async function runTimeSeriesForecast(event) {
  event.preventDefault();
  const button = $('#runTimeSeriesForecast'); const progress = $('#timeSeriesProgress');
  button.disabled = true; button.textContent = 'Forecasting locally…'; progress.hidden = false;
  progress.querySelector('.operation-steps').innerHTML = ''; progress.querySelector('.operation-metrics').innerHTML = '';
  progress.querySelector('.operation-progress i').style.width = '0%';
  $('#timeSeriesOutput').innerHTML = '';
  try {
    state.timeSeriesResult = await streamApi(
      '/api/model-capabilities/time-series/forecast/stream',
      timeSeriesRequestFromForm(),
      event => updateOperation(progress, event)
    );
    renderTimeSeriesResult(state.timeSeriesResult);
    await loadTimeSeriesExperiments();
  } catch (error) {
    state.timeSeriesResult = null;
    $('#timeSeriesOutput').innerHTML = `<div class="code-screen-error"><b>Forecast stopped</b><span>${escapeHtml(error.message)}</span></div>`;
  } finally {
    button.disabled = !state.timeSeriesStatus?.ok; button.textContent = 'Run read-only forecast';
  }
}

function openCodeScreening() {
  state.codeScreenResult = null;
  const readiness = (state.modelReadiness?.local_transformers?.profiles || []).find(profile => profile.id === 'securebert-code-vulnerability');
  const trust = (state.modelTrust?.profiles || []).find(profile => profile.profile_id === 'securebert-code-vulnerability');
  const trustEnforced = state.modelTrust?.policy?.mode !== 'audit';
  const runnable = Boolean(readiness?.installed && (!trustEnforced || trust?.trusted));
  const runAction = runnable
    ? '<button class="button primary" type="submit" id="runCodeScreen">Run local screen</button>'
    : readiness?.installed
    ? `<div class="code-screen-install"><span>${escapeHtml(trust?.detail || 'Exact artifact approval is required before this classifier can execute.')}</span><button class="button primary" type="button" data-review-model-trust>Review artifact approval</button></div>`
    : '<div class="code-screen-install"><span>The workflow is bounded, but the classifier is not installed on this host.</span><button class="button primary" type="button" data-pull-profile="securebert-code-vulnerability">Install local classifier</button></div>';
  showDetail({
    eyebrow:'LOCAL SPECIALIST · OPT-IN',
    title:'Screen a source-code snippet',
    summary:'<p>Paste source code deliberately. SignalRoom rejects SPL, event text, and prose; runs the classifier locally; hashes but does not persist the source; and returns an assistive review signal—not a vulnerability finding.</p>',
    content:`<form id="codeScreenForm" class="code-screen-form">
      <label><span>Language</span><select id="codeScreenLanguage"><option value="python">Python</option><option value="c">C</option><option value="cpp">C++</option></select></label>
      <label class="full"><span>Source code</span><textarea id="codeScreenInput" rows="9" minlength="20" maxlength="50000" required spellcheck="false" placeholder="Paste one bounded function or class for assistive screening…"></textarea><small>Only the first 1,024 model tokens are evaluated. The interface reports truncation explicitly.</small></label>
      <div class="code-screen-boundary"><b>Never automatic</b><span>This model is not used by Discovery, RAG, SPL analysis, or event triage. Corroborate any signal with static analysis and expert review.</span></div>
      ${runAction}
    </form><div id="codeScreenOutput" class="code-screen-output" aria-live="polite"></div>`,
    provenance:'<h3>Execution contract</h3><dl><div><dt>Runtime</dt><dd>Local Transformers</dd></div><div><dt>Network inference</dt><dd>Disabled for this workflow</dd></div><div><dt>Source persistence</dt><dd>None</dd></div><div><dt>Model</dt><dd>cisco-ai/SecureBERT2.0-code-vuln-detection</dd></div></dl>'
  });
  $('#codeScreenForm').addEventListener('submit', runCodeScreening);
  (runnable ? $('#codeScreenInput') : $('#codeScreenLanguage')).focus();
}

async function runCodeScreening(event) {
  event.preventDefault();
  const button = $('#runCodeScreen'); const output = $('#codeScreenOutput');
  button.disabled = true; button.textContent = 'Running locally…';
  output.innerHTML = '<div class="code-screen-working"><b>Loading the local classifier</b><span>No source code is being sent to Splunk or Hugging Face.</span></div>';
  try {
    const result = await api('/api/model-capabilities/code-vulnerability/screen', {
      method:'POST',
      body:JSON.stringify({code:$('#codeScreenInput').value, language:$('#codeScreenLanguage').value})
    });
    state.codeScreenResult = result;
    const prediction = result.prediction || {}; const contract = result.contract || {};
    const positive = prediction.signal === 'potential-vulnerability-review';
    const confidence = Math.round(Number(prediction.confidence || 0) * 100);
    output.innerHTML = `<article class="code-screen-result ${positive ? 'review' : 'clear'}">
      <header><div><span>ASSISTIVE MODEL SIGNAL</span><h4>${positive ? 'Prioritize for vulnerability review' : 'No positive model signal'}</h4></div><b>${confidence}% confidence</b></header>
      <p>${escapeHtml(contract.meaning || '')}</p>
      <div><span><b>${Number(result.evaluated_tokens || 0).toLocaleString()}</b> evaluated tokens</span><span><b>${result.truncated ? 'Yes' : 'No'}</b> input truncated</span><span><b>0</b> network inference calls</span><span><b>0</b> source copies retained</span></div>
      <code title="SHA-256 of supplied source">${escapeHtml(result.input_sha256)}</code>
      <details><summary>Required limitations</summary><ul>${(contract.limitations || []).map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></details>
      <footer><button class="button ghost small" type="button" data-code-screen-case>Preserve signal to a case</button></footer>
    </article>`;
  } catch (error) {
    state.codeScreenResult = null;
    output.innerHTML = `<div class="code-screen-error"><b>Screening stopped</b><span>${escapeHtml(error.message)}</span></div>`;
  } finally {
    button.disabled = false; button.textContent = 'Run local screen';
  }
}

function splunkDependencyLabel(dependency = {}) {
  if (!dependency.service) return 'No external dependency declared';
  const target = `${dependency.service}${dependency.model ? ` · ${dependency.model}` : ''}`;
  const observations = {
    observed:'Observed on SignalRoom Ollama',
    'not-observed':'Not observed · verify endpoint',
    unknown:'Could not compare',
    'not-declared':'Backing model not declared',
    'not-applicable':'Dependency recorded'
  };
  return `${target} · ${observations[dependency.observation] || dependency.observation || 'not compared'}`;
}

function renderSplunkModels() {
  const value = state.splunkModels; const summaryNode = $('#splunkModelSummary'); const grid = $('#splunkModelGrid');
  if (!summaryNode || !grid) return;
  if (!value?.available) {
    summaryNode.innerHTML = `<div class="splunk-model-empty"><b>${escapeHtml(value?.status === 'unavailable' ? 'MLTK scan unavailable' : 'No MLTK inventory baseline yet')}</b><span>${escapeHtml(value?.detail || 'Run a read-only scan to inventory Splunk-native models.')}</span>${value?.error ? `<small>${escapeHtml(value.error)}</small>` : ''}</div>`;
    grid.innerHTML = '';
    return;
  }
  const summary = value.summary || {}; const checked = value.checked_at ? new Date(value.checked_at).toLocaleString() : 'unknown';
  summaryNode.innerHTML = `<div class="splunk-model-counts">
    <span><b>${Number(summary.observed || 0).toLocaleString()}</b> observed</span><span class="new"><b>${summary.new || 0}</b> new</span><span class="changed"><b>${summary.changed || 0}</b> changed</span><span><b>${summary.missing || 0}</b> missing</span><span class="dependency"><b>${summary.dependencies_not_observed || 0}</b> dependencies to verify</span>
    </div><p>${escapeHtml(value.freshness_contract || '')}</p><time datetime="${escapeHtml(value.checked_at || '')}">Checked ${escapeHtml(checked)} · read-only · 0 writes</time>`;
  grid.innerHTML = (value.models || []).map(item => {
    const dependency = item.dependency || {}; const status = item.status || 'unknown';
    return `<article class="splunk-model-card ${escapeHtml(status)}">
      <header><span>${escapeHtml(item.type || 'MLTK model')}</span><b class="splunk-model-status ${escapeHtml(status)}">${escapeHtml(status)}</b></header>
      <h4>${escapeHtml(item.name || 'Unnamed model')}</h4>
      <dl><div><dt>Algorithm</dt><dd>${escapeHtml(item.algorithm || 'Not reported')}</dd></div><div><dt>App / owner</dt><dd>${escapeHtml(`${item.app || 'unknown'} / ${item.owner || 'unknown'}`)}</dd></div><div><dt>Sharing</dt><dd>${escapeHtml(item.sharing || 'Not reported')}</dd></div></dl>
      <div class="splunk-model-dependency ${escapeHtml(dependency.observation || '')}"><span>DECLARED BACKING SERVICE</span><b>${escapeHtml(splunkDependencyLabel(dependency))}</b>${dependency.caveat ? `<small>${escapeHtml(dependency.caveat)}</small>` : ''}</div>
      <footer><span>Fingerprint</span><code>${escapeHtml((item.fingerprint || '').slice(0, 12))}</code></footer>
    </article>`;
  }).join('') || '<div class="empty-inline compact-empty">Splunk MLTK returned no model definitions.</div>';
}

async function loadSplunkModels() {
  try { state.splunkModels = await api('/api/splunk-models/latest'); renderSplunkModels(); }
  catch (error) { state.splunkModels = { available:false, status:'unavailable', detail:error.message }; renderSplunkModels(); }
}

async function scanSplunkModels() {
  const button = $('#scanSplunkModels'); const panel = $('#splunkModelProgress');
  button.disabled = true; button.textContent = 'Scanning…'; panel.hidden = false;
  panel.querySelector('.operation-label').textContent = 'Preparing MLTK scan'; panel.querySelector('.operation-detail').textContent = 'Waiting for the configured Splunk MCP connection.';
  panel.querySelector('.operation-elapsed').textContent = '0s'; panel.querySelector('.operation-progress i').style.width = '0%'; panel.querySelector('.operation-progress').setAttribute('aria-valuenow', '0');
  panel.querySelector('.operation-metrics').innerHTML = ''; panel.querySelector('.operation-steps').innerHTML = '';
  try {
    state.splunkModels = await streamApi('/api/splunk-models/scan/stream', {}, event => updateOperation(panel, event));
    renderSplunkModels(); toast(state.splunkModels.available ? 'Splunk MLTK inventory updated' : (state.splunkModels.detail || 'MLTK inventory unavailable'));
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.textContent = 'Scan MLTK models'; }
}

async function pullModel(profileId, button) {
  button.disabled = true; button.textContent = 'Starting…';
  try {
    let job = await api('/api/model-setup/pull', { method:'POST', body:JSON.stringify({ profile_id:profileId }) });
    while (['queued', 'pulling'].includes(job.status)) {
      button.textContent = job.context_chunks
        ? `Indexing ${job.indexed_chunks || 0}/${job.context_chunks}`
        : job.progress ? `${job.progress}%` : 'Downloading…';
      button.title = job.detail || '';
      await new Promise(resolve => setTimeout(resolve, 1000));
      job = await api(`/api/model-setup/pull/${job.id}`);
    }
    if (job.status !== 'complete') throw new Error(job.detail || 'Model download failed');
    toast(job.kind === 'local-transformers' ? 'Local specialist installed · approve its exact artifact after evaluation' : 'Model is ready in Ollama · approve its exact artifact after evaluation'); await Promise.all([loadModelReadiness(), loadModelTrust(true)]); renderModels();
  } catch (error) { button.disabled = false; button.textContent = 'Retry'; toast(error.message); }
}

async function activateModel(profileId, button) {
  const original = button.textContent; button.disabled = true; button.textContent = 'Activating…';
  try {
    const result = await api('/api/model-setup/activate', { method:'POST', body:JSON.stringify({ profile_id:profileId, unload_other_signalroom_models:true }) });
    toast(`Active model · ${result.executed_model}`); await Promise.all([loadModelReadiness(), loadModelTrust()]); renderModels();
  } catch (error) { button.disabled = false; button.textContent = original; toast(error.message); }
}

async function loadArtifacts() {
  state.artifacts = await api(scopedUrl('/api/artifacts'));
  $('#artifactCount').textContent = state.artifacts.length;
  state.contextPage = 1;
  renderArtifacts(filterArtifacts(state.artifacts));
}

function filterArtifacts(items) {
  if (state.contextKind === 'discovery') return items.filter(item => item.kind.startsWith('discovery'));
  return state.contextKind === 'all' ? items : items.filter(item => item.kind === state.contextKind);
}

function renderArtifacts(items) {
  state.contextItems = items;
  $('#contextResultCount').textContent = `${items.length} artifact${items.length === 1 ? '' : 's'}`;
  const pageCount = Math.max(1, Math.ceil(items.length / state.contextPageSize));
  state.contextPage = Math.min(Math.max(1, state.contextPage), pageCount);
  const start = (state.contextPage - 1) * state.contextPageSize;
  const pageItems = items.slice(start, start + state.contextPageSize);
  $('#contextPagination').hidden = items.length <= state.contextPageSize;
  $('#contextPageStatus').textContent = `Page ${state.contextPage} of ${pageCount} · ${start + 1}–${Math.min(start + state.contextPageSize, items.length)} of ${items.length}`;
  $('#contextPrevious').disabled = state.contextPage <= 1;
  $('#contextNext').disabled = state.contextPage >= pageCount;
  $('#artifactGrid').innerHTML = pageItems.length ? pageItems.map(item => `
    <article class="artifact-card">
      <header><span class="kind">${escapeHtml(item.kind)}</span><span class="artifact-admin-actions"><button data-edit-artifact="${item.id}">Edit</button><button class="delete-artifact" data-delete="${item.id}">Delete</button></span></header>
      <h3><button class="artifact-title" data-open-artifact="${item.id}">${escapeHtml(item.title)}</button></h3><p>${escapeHtml(item.content.slice(0, 190))}</p>
      <div class="tags">${item.tags.slice(0,5).map(tag => `<span>${escapeHtml(tag)}</span>`).join('')}</div>
      <div class="scope-provenance"><span>${escapeHtml(item.connection_alias)}</span><code>${escapeHtml(item.tenant_scope_id)}</code><code>${escapeHtml(shortFingerprint(item.connection_fingerprint))}</code></div>
      <footer><span>${escapeHtml(item.source)}</span><span>${new Date(item.updated_at).toLocaleDateString()}</span></footer>
      <div class="card-actions"><button data-open-artifact="${item.id}">Inspect</button><button data-artifact-investigate="${item.id}">Investigate</button><button data-artifact-case="${item.id}">Add to case</button></div>
    </article>`).join('') : '<div class="empty-inline">No artifacts match this search.</div>';
}

function openArtifactEditor(item = null) {
  state.editingArtifactId = item?.id || null;
  $('#artifactForm').reset();
  $('#artifactTitle').textContent = item ? 'Edit evidence artifact' : 'New evidence artifact';
  $('#artifactModalEyebrow').textContent = item ? 'UPDATE MANAGED CONTEXT' : 'ADD TO CONTEXT';
  $('#artifactSubmit').textContent = item ? 'Save changes' : 'Index artifact';
  $('#newArtifactTitle').value = item?.title || '';
  $('#newArtifactKind').value = item?.kind || 'runbook';
  $('#newArtifactTags').value = item?.tags?.join(', ') || '';
  $('#newArtifactContent').value = item?.content || '';
  $('#artifactModal').hidden = false;
}

async function removeArtifact(id) {
  const item = state.artifacts.find(artifact => artifact.id === id);
  if (!item || !confirm(`Delete “${item.title}” from local context and RAG? This cannot be undone.`)) return;
  await api(scopedUrl(`/api/artifacts/${encodeURIComponent(id)}`), { method:'DELETE' });
  if (!$('#detailModal').hidden) closeDetail();
  await loadArtifacts(); toast('Artifact deleted');
}

async function loadCases() {
  state.cases = await api(scopedUrl('/api/cases'));
  $('#caseCount').textContent = state.cases.length;
  $('#caseListCount').textContent = `${state.cases.length} total`;
  renderCaseList();
  if (state.activeCase && state.cases.some(item => item.id === state.activeCase.id)) {
    await openCase(state.activeCase.id, false);
  }
}

function renderCaseList() {
  $('#caseList').innerHTML = state.cases.length ? state.cases.map(item => `
    <button class="case-list-item ${state.activeCase?.id === item.id ? 'active' : ''}" data-open-case="${escapeHtml(item.id)}">
      <span><b>${escapeHtml(item.title)}</b><em class="case-severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</em></span>
      <small>${escapeHtml(item.owner)} · ${escapeHtml(item.status)} · ${escapeHtml(item.tenant_scope_id)}</small>
      <footer><span>${item.item_count} timeline item${item.item_count === 1 ? '' : 's'}</span><time>${new Date(item.updated_at).toLocaleDateString()}</time></footer>
    </button>`).join('') : '<div class="case-list-empty"><b>No cases yet</b><p>Create a case, then preserve evidence from Investigate, Discovery, or Context.</p></div>';
}

async function openCase(id, updateHash = true) {
  [state.activeCase, state.caseCockpit] = await Promise.all([
    api(scopedUrl(`/api/cases/${encodeURIComponent(id)}`)),
    api(scopedUrl(`/api/cases/${encodeURIComponent(id)}/cockpit`))
  ]);
  renderCaseList(); renderCaseDetail();
  if (updateHash) history.replaceState(null, '', `${location.pathname}#cases/${encodeURIComponent(id)}`);
}

function caseOption(value, current, label = value) {
  return `<option value="${escapeHtml(value)}" ${value === current ? 'selected' : ''}>${escapeHtml(label)}</option>`;
}

function caseCockpitMarkup() {
  const cockpit = state.caseCockpit; if (!cockpit) return '';
  const health = cockpit.health || {};
  const actions = cockpit.next_actions || [];
  const validationSummary = Object.entries(cockpit.validation_counts || {}).map(([status,count]) => `${count} ${status}`).join(' · ') || 'No linked validation work';
  return `<section class="case-cockpit" aria-labelledby="caseCockpitTitle">
    <header><div><p class="eyebrow">INVESTIGATION COCKPIT</p><h3 id="caseCockpitTitle">Evidence state and next best action</h3></div><button class="button primary small" data-case-investigate="review">Resume in Investigate</button></header>
    <div class="case-health-grid">
      <article><b>${health.observations || 0}</b><span>observations</span></article><article><b>${health.open_hypotheses || 0}</b><span>open hypotheses</span></article><article><b>${health.unresolved_items || 0}</b><span>unresolved</span></article><article><b>${health.linked_validations || 0}</b><span>validations</span></article><article class="${health.tensions ? 'warn' : ''}"><b>${health.tensions || 0}</b><span>evidence tensions</span></article>
    </div>
    <div class="case-cockpit-body"><section><span>NEXT BEST ACTIONS</span><div class="case-next-actions">${actions.map((action,index) => `<button data-case-next-action="${index}"><b>${escapeHtml(action.label)}</b><small>${escapeHtml(action.reason)}</small></button>`).join('')}</div></section><aside><span>CONTEXT HEALTH</span><p>${health.available_artifacts || 0}/${health.linked_artifacts || 0} linked artifacts available locally</p><p>${escapeHtml(validationSummary)}</p><p>${health.decisions || 0} recorded decision${health.decisions === 1 ? '' : 's'}</p></aside></div>
  </section>`;
}

function renderCaseDetail() {
  const item = state.activeCase;
  if (!item) return;
  const timeline = item.items.length ? item.items.map(entry => {
    const repositoryEvidence = entry.metadata?.detection_repository_handoff_id;
    const deploymentEvidence = entry.metadata?.detection_deployment_snapshot_id;
    const detectionLink = entry.metadata?.detection_id && (repositoryEvidence || deploymentEvidence)
      ? `<button class="timeline-deep-link" data-open-repository-detection="${escapeHtml(entry.metadata.detection_id)}">${deploymentEvidence ? 'Open deployment verification' : 'Open detection handoff'}</button>`
      : '';
    return `
    <article class="timeline-item">
      <div class="timeline-marker ${escapeHtml(entry.kind)}"></div>
      <div class="timeline-card">
        <header><div><span>${escapeHtml(entry.kind)} · ${escapeHtml(entry.status)}</span><h4>${escapeHtml(entry.title)}</h4></div><span class="timeline-admin-actions"><button data-edit-case-item="${escapeHtml(entry.id)}">Edit</button><button data-delete-case-item="${escapeHtml(entry.id)}" aria-label="Remove ${escapeHtml(entry.title)}">Remove</button></span></header>
        <p>${escapeHtml(entry.content)}</p>
        <footer><span>${escapeHtml(entry.source)} · ${escapeHtml(entry.confidence)} confidence</span>${detectionLink}<time>${new Date(entry.occurred_at || entry.created_at).toLocaleString()}</time></footer>
      </div>
    </article>`;
  }).join('') : '<div class="case-timeline-empty"><b>The timeline is ready.</b><p>Add an analyst note, or preserve evidence directly from Investigate, Discovery, or Context.</p></div>';
  $('#caseDetail').innerHTML = `
    <div class="case-detail-header">
      <div><p class="eyebrow">CASE ${escapeHtml(item.id.slice(0, 8).toUpperCase())}</p><h2>${escapeHtml(item.title)}</h2><p>Created ${new Date(item.created_at).toLocaleString()} · Updated ${new Date(item.updated_at).toLocaleString()}</p><div class="scope-provenance"><span>${escapeHtml(item.connection_alias)}</span><code>${escapeHtml(item.tenant_scope_id)}</code><code>${escapeHtml(shortFingerprint(item.connection_fingerprint))}</code></div></div>
      <div class="button-row"><button class="button danger" data-delete-case>Delete case</button><button class="button ghost" data-export-case>Export handoff</button><button class="button primary" data-add-case-item>Add timeline item</button></div>
    </div>
    <div class="case-lifecycle" aria-label="Case lifecycle">
      <label class="case-title-field"><span>Case title</span><input id="caseTitleInput" value="${escapeHtml(item.title)}" maxlength="240" required></label>
      <label><span>Owner</span><input id="caseOwner" value="${escapeHtml(item.owner)}" maxlength="160"></label>
      <label><span>Status</span><select id="caseStatus">${caseOption('open',item.status,'Open')}${caseOption('investigating',item.status,'Investigating')}${caseOption('contained',item.status,'Contained')}${caseOption('monitoring',item.status,'Monitoring')}${caseOption('closed',item.status,'Closed')}</select></label>
      <label><span>Severity</span><select id="caseSeverity">${caseOption('informational',item.severity,'Informational')}${caseOption('low',item.severity,'Low')}${caseOption('medium',item.severity,'Medium')}${caseOption('high',item.severity,'High')}${caseOption('critical',item.severity,'Critical')}</select></label>
      <label class="case-summary-field"><span>Executive summary</span><textarea id="caseSummary" rows="3" maxlength="10000">${escapeHtml(item.summary)}</textarea></label>
      <label class="case-tags-field"><span>Tags</span><input id="caseTags" value="${escapeHtml(item.tags.join(', '))}"></label>
      <button class="button ghost" data-save-case>Save case details</button>
    </div>
    ${caseCockpitMarkup()}
    <div class="case-exports" id="caseExports" hidden></div>
    <div class="case-timeline-heading"><div><p class="eyebrow">CHRONOLOGICAL RECORD</p><h3>Evidence and decision timeline</h3></div><span>${item.items.length} item${item.items.length === 1 ? '' : 's'}</span></div>
    <div class="case-timeline">${timeline}</div>`;
}

function openCaseItemModal(item = null) {
  state.editingCaseItemId = item?.id || null;
  state.pendingCaseItem = item;
  $('#caseItemForm').reset();
  $('#caseItemTitle').textContent = item ? 'Edit timeline item' : 'Add timeline item';
  $('#caseItemSubmit').textContent = item ? 'Save timeline item' : 'Add to timeline';
  $('#caseItemKind').value = item?.kind || 'note';
  $('#caseItemStatus').value = item?.status || 'unverified';
  $('#caseItemName').value = item?.title || '';
  $('#caseItemContent').value = item?.content || '';
  $('#caseItemSource').value = item?.source || 'analyst';
  $('#caseItemConfidence').value = item?.confidence || 'unknown';
  $('#caseItemOccurred').value = item?.occurred_at ? new Date(item.occurred_at).toISOString().slice(0,16) : '';
  $('#caseItemModal').hidden = false;
}

async function openCasePicker(item) {
  state.pendingCaseItem = item;
  await loadCases();
  $('#casePickerSummary').textContent = `Preserve “${item.title}” in a durable case timeline.`;
  $('#casePickerList').innerHTML = state.cases.length ? state.cases.map(entry => `
    <button data-pick-case="${escapeHtml(entry.id)}"><span><b>${escapeHtml(entry.title)}</b><small>${escapeHtml(entry.owner)} · ${escapeHtml(entry.status)}</small></span><em>Add →</em></button>`).join('') : '<div class="case-list-empty"><b>No saved cases</b><p>Create one to preserve this item.</p></div>';
  $('#casePickerModal').hidden = false;
}

async function addItemToCase(caseId, item) {
  await api(scopedUrl(`/api/cases/${encodeURIComponent(caseId)}/items`), { method:'POST', body:JSON.stringify(item) });
  state.pendingCaseItem = null;
  await loadCases(); await openCase(caseId, false);
  toast('Added to the case timeline');
}

async function exportActiveCase() {
  if (!state.activeCase) return;
  const result = await api(scopedUrl(`/api/cases/${encodeURIComponent(state.activeCase.id)}/export`), { method:'POST', body:JSON.stringify({ formats:['markdown','json'] }) });
  const holder = $('#caseExports'); holder.hidden = false;
  holder.innerHTML = `<b>Handoff package ready</b><span>Files contain the case metadata and chronological timeline.</span>${result.files.map(file => `<a class="button ghost" href="${escapeHtml(file.url)}" download>${escapeHtml(file.format === 'md' ? 'Markdown brief' : 'JSON record')}</a>`).join('')}`;
  toast('Handoff package created');
}

function renderModels() {
  if (!state.settings) return;
  const ollamaProfiles = state.modelReadiness?.ollama?.profiles || [];
  const localProfiles = state.modelReadiness?.local_transformers?.profiles || [];
  $('#modelGrid').innerHTML = state.settings.models.map(model => {
    const readiness = (model.provider === 'ollama' ? ollamaProfiles : localProfiles).find(item => item.id === model.id);
    const isLocalSpecialist = model.provider === 'huggingface' && state.settings.specialist_runtime === 'local';
    const providerLabel = model.provider === 'ollama' ? 'ollama' : isLocalSpecialist ? 'local transformers' : 'hugging face cloud';
    const capabilityLabel = ['embedding','ner','reranking','classification'].includes(model.task) ? 'Test capability' : 'Test generation';
    const update = state.modelUpdates?.profiles?.find(item => item.profile_id === model.id);
    const updateLabels = { current:'CURRENT', 'update-available':'UPDATE AVAILABLE', 'not-installed':'NOT INSTALLED', untracked:'PROVENANCE UNTRACKED', 'check-unavailable':'MANUAL REFRESH', error:'CHECK ERROR' };
    return `
    <article class="model-card">
      <header><span class="provider">${escapeHtml(providerLabel)} · ${escapeHtml(model.task.replace('_',' '))}</span><i class="model-status ${readiness?.loaded ? 'active' : readiness?.installed ? 'ok' : ''}" id="status-${escapeHtml(model.id)}"></i></header>
      <h3>${escapeHtml(model.label)}</h3><div class="model-id">${escapeHtml(model.model)}</div>
      <p>${escapeHtml(model.description)}</p><div class="tags"><span>${escapeHtml(model.provenance || 'Operator supplied')}</span><span>${Number(model.context_window).toLocaleString()} ctx</span>${readiness?.loaded ? '<span class="active-model-tag">LOADED IN OLLAMA</span>' : ''}${isLocalSpecialist && readiness?.installed ? '<span class="active-model-tag">LOCAL · NO CLOUD INFERENCE</span>' : ''}</div>
      ${update ? `<div class="model-update ${escapeHtml(update.status)}"><b>${escapeHtml(updateLabels[update.status] || update.status)}</b><span>${escapeHtml(update.detail || '')}</span>${update.last_modified ? `<time>Source updated ${escapeHtml(new Date(update.last_modified).toLocaleDateString())}</time>` : ''}</div>` : ''}
      <footer><span>${model.enabled ? 'ENABLED' : 'DISABLED'}</span><div class="model-actions">${model.provider === 'ollama' && readiness?.installed && !readiness?.loaded ? `<button data-activate-model="${escapeHtml(model.id)}">Activate</button>` : ''}${model.provider === 'ollama' && !readiness?.installed ? `<button data-pull-profile="${escapeHtml(model.id)}">Download</button>` : ''}${isLocalSpecialist && !readiness?.installed ? `<button data-pull-profile="${escapeHtml(model.id)}">Install locally</button>` : ''}${update && ['update-available','untracked','check-unavailable'].includes(update.status) && readiness?.installed ? `<button data-pull-profile="${escapeHtml(model.id)}">Refresh explicitly</button>` : ''}<button data-test-model="${escapeHtml(model.id)}">${capabilityLabel}</button></div></footer>
    </article>`;
  }).join('');
  renderModelCatalog();
}

function evaluationSuites() {
  return state.goldenBenchmarks?.evaluation_suites?.suites || [];
}

function runnableEvaluationSuites() {
  return evaluationSuites().filter(item => item.id === 'builtin-core' || (item.status === 'active' && item.current_version > 0));
}

function evaluationSuiteOptions(selected = 'builtin-core') {
  return runnableEvaluationSuites().map(item => `<option value="${escapeHtml(item.id)}" ${item.id === selected ? 'selected' : ''}>${escapeHtml(item.name)} · ${item.scenario_count} scenarios</option>`).join('');
}

function evaluationSuiteName(suiteId) {
  return evaluationSuites().find(item => item.id === suiteId)?.name || suiteId || 'Core gate';
}

function renderEvaluationSuites() {
  const authority = state.goldenBenchmarks?.evaluation_suites;
  if (!authority) return;
  $('#evaluationSuiteGrid').innerHTML = (authority.suites || []).map(item => {
    const builtIn = item.id === 'builtin-core';
    const customCount = item.draft_dirty ? item.draft_custom_scenario_count : item.custom_scenario_count;
    const totalCount = item.draft_dirty ? item.draft_scenario_count : item.scenario_count;
    const version = builtIn ? `CORE · ${item.scenario_count} controls` : item.current_version ? `v${item.current_version} · ${customCount} custom in draft` : 'DRAFT · unpublished';
    const status = builtIn ? 'always required' : item.status === 'archived' ? 'archived' : item.draft_dirty ? 'draft changes' : 'published';
    return `<article class="evaluation-suite-card ${builtIn ? 'builtin' : ''} ${escapeHtml(item.status)}">
      <header><div><span>${escapeHtml(version)}</span><h4>${escapeHtml(item.name)}</h4></div><b>${escapeHtml(status)}</b></header>
      <p>${escapeHtml(item.description || (builtIn ? 'SignalRoom evidence, safety, tool, and conclusion contracts.' : 'No purpose has been documented yet.'))}</p>
      <div><span><b>${totalCount}</b> ${item.draft_dirty ? 'draft' : 'total'} scenarios</span><span><b>${customCount}</b> organization controls</span><span><b>${item.versions?.length || (builtIn ? 1 : 0)}</b> retained versions</span></div>
      <footer><code>${escapeHtml(item.suite_version || item.draft_fingerprint || '')}</code>${builtIn ? '<span class="baseline-badge">Immutable</span>' : `<button class="button ghost small" data-edit-evaluation-suite="${escapeHtml(item.id)}">Open suite</button>`}</footer>
    </article>`;
  }).join('');
}

function newEvaluationScenario(index) {
  return {
    id:`organization-control-${index + 1}`, title:'', task_type:'triage', mode:'triage',
    message:'', fixture_title:'Synthetic organization evidence', fixture_content:'',
    expected_tools:[], forbidden_tools:['run_query'], evidence_groups:[['']],
    conclusion_groups:[['']], forbidden_claims:[], expected_blocked:false
  };
}

function matchGroupsFromText(value) {
  return value.split('\n').map(line => line.split('|').map(term => term.trim()).filter(Boolean)).filter(group => group.length);
}

function matchGroupsToText(groups) {
  return (groups || []).map(group => group.join(' | ')).join('\n');
}

function syncEvaluationScenario() {
  const suite = state.evaluationDraft;
  const scenario = suite?.draft_scenarios?.[state.evaluationScenarioIndex];
  if (!scenario || !$('#evaluationScenarioId')) return;
  scenario.id = $('#evaluationScenarioId').value.trim();
  scenario.title = $('#evaluationScenarioTitle').value.trim();
  scenario.task_type = $('#evaluationScenarioTask').value.trim();
  scenario.mode = $('#evaluationScenarioMode').value;
  scenario.message = $('#evaluationScenarioMessage').value.trim();
  scenario.fixture_title = $('#evaluationFixtureTitle').value.trim();
  scenario.fixture_content = $('#evaluationFixtureContent').value.trim();
  scenario.expected_tools = $$('#evaluationExpectedTools input:checked').map(node => node.value);
  scenario.forbidden_tools = $$('#evaluationForbiddenTools input:checked').map(node => node.value);
  scenario.evidence_groups = matchGroupsFromText($('#evaluationEvidenceGroups').value);
  scenario.conclusion_groups = matchGroupsFromText($('#evaluationConclusionGroups').value);
  scenario.forbidden_claims = $('#evaluationForbiddenClaims').value.split('\n').map(value => value.trim()).filter(Boolean);
  scenario.expected_blocked = $('#evaluationExpectedBlocked').checked;
}

function renderEvaluationScenarioEditor() {
  const suite = state.evaluationDraft;
  const scenarios = suite?.draft_scenarios || [];
  $('#evaluationScenarioList').innerHTML = scenarios.length ? scenarios.map((scenario,index) => `<button type="button" class="${index === state.evaluationScenarioIndex ? 'active' : ''}" data-evaluation-scenario="${index}"><span>${escapeHtml(scenario.task_type || 'general')}</span><b>${escapeHtml(scenario.title || scenario.id || `Scenario ${index + 1}`)}</b><small>${escapeHtml(scenario.id || 'ID required')}</small></button>`).join('') : '<div class="empty-inline compact-empty">Add an organization scenario to make this draft publishable.</div>';
  const scenario = scenarios[state.evaluationScenarioIndex];
  if (!scenario) {
    $('#evaluationScenarioEditor').innerHTML = '<div class="empty-inline compact-empty">A scenario defines the synthetic evidence, expected behavior, and prohibited behavior that matter to your team.</div>';
    return;
  }
  const tools = ['get_info','get_indexes','get_metadata','get_knowledge_objects','run_query'];
  const toolChecks = (id, selected) => `<fieldset id="${id}" class="evaluation-tool-checks"><legend>${id === 'evaluationExpectedTools' ? 'Expected tools · exact set' : 'Forbidden tools · critical if called'}</legend>${tools.map(tool => `<label><input type="checkbox" value="${tool}" ${(selected || []).includes(tool) ? 'checked' : ''}><span>${escapeHtml(tool)}</span></label>`).join('')}</fieldset>`;
  $('#evaluationScenarioEditor').innerHTML = `
    <header><div><span>SCENARIO ${state.evaluationScenarioIndex + 1} OF ${scenarios.length}</span><h3>Evidence and behavior contract</h3></div><button class="button danger small" type="button" id="removeEvaluationScenario">Remove scenario</button></header>
    <div class="form-grid">
      <label><span>Stable scenario ID</span><input id="evaluationScenarioId" required minlength="3" maxlength="80" pattern="[a-z0-9][a-z0-9-]*[a-z0-9]" value="${escapeHtml(scenario.id || '')}"></label>
      <label><span>Analyst task type</span><input id="evaluationScenarioTask" required maxlength="80" value="${escapeHtml(scenario.task_type || '')}"></label>
      <label class="full"><span>Outcome title</span><input id="evaluationScenarioTitle" required minlength="3" maxlength="240" value="${escapeHtml(scenario.title || '')}"></label>
      <label><span>Agent mode</span><select id="evaluationScenarioMode">${['general','discovery','detection','hunt','triage','spl','brief'].map(mode => `<option value="${mode}" ${scenario.mode === mode ? 'selected' : ''}>${mode}</option>`).join('')}</select></label>
      <label class="evaluation-blocked"><input id="evaluationExpectedBlocked" type="checkbox" ${scenario.expected_blocked ? 'checked' : ''}><span>Agent must block this request</span></label>
      <label class="full"><span>User request under test</span><textarea id="evaluationScenarioMessage" rows="3" required minlength="3" maxlength="4000">${escapeHtml(scenario.message || '')}</textarea></label>
      <label class="full"><span>Synthetic evidence title</span><input id="evaluationFixtureTitle" required minlength="3" maxlength="240" value="${escapeHtml(scenario.fixture_title || '')}"></label>
      <label class="full"><span>Synthetic evidence fixture</span><textarea id="evaluationFixtureContent" rows="6" required minlength="3" maxlength="20000">${escapeHtml(scenario.fixture_content || '')}</textarea><small class="field-help">This is indexed only in the temporary benchmark evidence store.</small></label>
      ${toolChecks('evaluationExpectedTools', scenario.expected_tools)}
      ${toolChecks('evaluationForbiddenTools', scenario.forbidden_tools)}
      <label class="full"><span>Required evidence groups</span><textarea id="evaluationEvidenceGroups" rows="4" required>${escapeHtml(matchGroupsToText(scenario.evidence_groups))}</textarea><small class="field-help">One required group per line; separate acceptable alternatives with <code>|</code>.</small></label>
      <label class="full"><span>Required conclusion groups</span><textarea id="evaluationConclusionGroups" rows="4" required>${escapeHtml(matchGroupsToText(scenario.conclusion_groups))}</textarea><small class="field-help">Every line must match at least one term in the agent response.</small></label>
      <label class="full"><span>Prohibited exact claims</span><textarea id="evaluationForbiddenClaims" rows="3">${escapeHtml((scenario.forbidden_claims || []).join('\n'))}</textarea><small class="field-help">One case-insensitive phrase per line; a match is a critical failure.</small></label>
    </div>`;
}

function renderEvaluationSuiteModal() {
  const suite = state.evaluationDraft; if (!suite) return;
  $('#evaluationSuiteModalTitle').textContent = suite.name || 'Edit organization suite';
  $('#evaluationSuiteName').value = suite.name || '';
  $('#evaluationSuiteDescription').value = suite.description || '';
  $('#evaluationSuiteRevision').value = String(suite.draft_revision || 1);
  $('#evaluationSuiteFingerprint').textContent = suite.draft_fingerprint || '';
  $('#evaluationSyntheticConfirmed').checked = false;
  $('#deleteEvaluationSuite').hidden = suite.current_version > 0;
  $('#archiveEvaluationSuite').hidden = suite.current_version === 0;
  $('#archiveEvaluationSuite').textContent = suite.status === 'archived' ? 'Restore suite' : 'Archive suite';
  $('#saveEvaluationSuite').disabled = suite.status === 'archived';
  $('#publishEvaluationSuite').disabled = suite.status === 'archived' || !suite.draft_dirty;
  renderEvaluationScenarioEditor();
}

async function openEvaluationSuite(suiteId) {
  try {
    state.evaluationDraft = await api(`/api/benchmarks/suites/${encodeURIComponent(suiteId)}`);
    state.evaluationScenarioIndex = 0;
    renderEvaluationSuiteModal();
    $('#evaluationSuiteModal').hidden = false;
  } catch (error) { toast(error.message); }
}

async function createEvaluationSuite() {
  try {
    const created = await api('/api/benchmarks/suites', {method:'POST',body:JSON.stringify({name:'Untitled evaluation suite',description:'',scenarios:[]})});
    await loadGoldenBenchmarks();
    await openEvaluationSuite(created.id);
  } catch (error) { toast(error.message); }
}

async function saveEvaluationSuiteDraft(showToast = true) {
  const suite = state.evaluationDraft; if (!suite) return null;
  syncEvaluationScenario();
  const payload = {
    expected_draft_revision:suite.draft_revision,
    name:$('#evaluationSuiteName').value.trim(),
    description:$('#evaluationSuiteDescription').value.trim(),
    scenarios:suite.draft_scenarios || []
  };
  const saved = await api(`/api/benchmarks/suites/${encodeURIComponent(suite.id)}`, {method:'PATCH',body:JSON.stringify(payload)});
  state.evaluationDraft = saved;
  renderEvaluationSuiteModal();
  await loadGoldenBenchmarks();
  if (showToast) toast('Evaluation draft saved locally');
  return saved;
}

async function publishEvaluationSuite() {
  const form = $('#evaluationSuiteForm');
  if (!form.reportValidity()) return;
  if (!$('#evaluationSyntheticConfirmed').checked) { toast('Confirm the synthetic fixture attestation before publication'); return; }
  try {
    const saved = await saveEvaluationSuiteDraft(false);
    if (!saved?.draft_scenarios?.length) { toast('Add at least one organization scenario before publication'); return; }
    const approved = confirm(`Publish immutable evaluation suite v${saved.current_version + 1}?\n\nExact draft fingerprint:\n${saved.draft_fingerprint}\n\nThe five built-in controls will remain required and ${saved.draft_scenarios.length} organization scenario(s) will be added.`);
    if (!approved) return;
    const published = await api(`/api/benchmarks/suites/${encodeURIComponent(saved.id)}/publish`, {method:'POST',body:JSON.stringify({expected_draft_revision:saved.draft_revision,expected_fingerprint:saved.draft_fingerprint,synthetic_data_confirmed:true})});
    state.evaluationDraft = published;
    renderEvaluationSuiteModal();
    await loadGoldenBenchmarks();
    toast(`Evaluation suite v${published.current_version} published`);
  } catch (error) { toast(error.message); }
}

async function archiveEvaluationSuite() {
  const suite = state.evaluationDraft; if (!suite) return;
  const archived = suite.status !== 'archived';
  if (archived && !confirm('Archive this suite? Published history and benchmark results will remain available, but new runs will be disabled.')) return;
  try {
    state.evaluationDraft = await api(`/api/benchmarks/suites/${encodeURIComponent(suite.id)}/archive`, {method:'POST',body:JSON.stringify({archived})});
    renderEvaluationSuiteModal(); await loadGoldenBenchmarks();
    toast(archived ? 'Evaluation suite archived; history retained' : 'Evaluation suite restored');
  } catch (error) { toast(error.message); }
}

async function deleteEvaluationSuite() {
  const suite = state.evaluationDraft; if (!suite) return;
  if (!confirm('Delete this unpublished evaluation draft? This cannot be undone.')) return;
  try {
    await api(`/api/benchmarks/suites/${encodeURIComponent(suite.id)}`, {method:'DELETE'});
    state.evaluationDraft = null; $('#evaluationSuiteModal').hidden = true;
    await loadGoldenBenchmarks(); toast('Unpublished evaluation draft deleted');
  } catch (error) { toast(error.message); }
}

function benchmarkTime(value) {
  return value ? new Date(value).toLocaleString() : 'not completed';
}

function tournamentTargetLabel(target) {
  return target === 'default_chat_model' ? 'General investigation route' : 'Security reasoning route';
}

function renderTournamentRun(tournament, overview) {
  if (!tournament) return '<div class="empty-inline compact-empty">Choose at least two local profiles to create a reviewable comparison.</div>';
  const recommendation = tournament.recommendation || {};
  const activePromotion = (overview.active_promotions || []).find(item => item.tournament_id === tournament.id);
  const completedReviews = (tournament.review_pairs || []).filter(item => item.choice).length;
  const ranking = (tournament.ranking || []).map(item => `
    <article class="tournament-rank ${item.eligible ? 'eligible' : 'hold'} ${recommendation.profile_id === item.profile_id ? 'recommended' : ''}">
      <header><span>#${item.rank} · ${item.eligible ? 'GATE PASSED' : 'HOLD'}</span><b>${Number(item.final_score || 0).toFixed(1)}</b></header>
      <h4>${escapeHtml(item.label)}</h4><code>${escapeHtml(item.model)}</code>
      <div><span><b>${Math.round(Number(item.score || 0))}</b>quality</span><span><b>${Math.round(Number(item.latency_score || 0))}</b>latency index</span><span><b>${item.blind_review_score == null ? '—' : Math.round(Number(item.blind_review_score))}</b>blind review</span><span><b>${Math.round(Number(item.pass_rate || 0) * 100)}%</b>pass rate</span></div>
      ${(item.task_wins || []).length ? `<p class="tournament-task-wins">Task leader · ${(item.task_wins || []).map(value => escapeHtml(value)).join(' · ')}</p>` : ''}
      ${(item.gate_blockers || []).length ? `<details><summary>${item.gate_blockers.length} promotion blocker${item.gate_blockers.length === 1 ? '' : 's'}</summary><ul>${item.gate_blockers.map(value => `<li>${escapeHtml(value)}</li>`).join('')}</ul></details>` : ''}
    </article>`).join('');
  const reviewPairs = (tournament.review_pairs || []).map(pair => {
    const choiceLabel = pair.choice === 'a' ? 'Candidate A preferred' : pair.choice === 'b' ? 'Candidate B preferred' : pair.choice === 'tie' ? 'Equivalent / tie' : 'Review required';
    const aIdentity = pair.identity_revealed ? ` · ${escapeHtml(pair.a_profile_id)}` : '';
    const bIdentity = pair.identity_revealed ? ` · ${escapeHtml(pair.b_profile_id)}` : '';
    const reviewActions = activePromotion ? '<span class="baseline-badge">Review locked by promotion</span>' : `<button class="button ghost small" data-tournament-review="${escapeHtml(tournament.id)}" data-pair-id="${escapeHtml(pair.id)}" data-choice="a">Prefer A</button><button class="button ghost small" data-tournament-review="${escapeHtml(tournament.id)}" data-pair-id="${escapeHtml(pair.id)}" data-choice="tie">Equivalent</button><button class="button ghost small" data-tournament-review="${escapeHtml(tournament.id)}" data-pair-id="${escapeHtml(pair.id)}" data-choice="b">Prefer B</button>`;
    return `<article class="blind-comparison ${pair.choice ? 'reviewed' : ''}">
      <header><div><span>${escapeHtml(pair.task_type)} · BLIND RESPONSE REVIEW</span><h5>${escapeHtml(pair.title)}</h5></div><b>${escapeHtml(choiceLabel)}</b></header>
      <div class="blind-responses"><section><span>Candidate A${aIdentity}</span><p>${escapeHtml(pair.a_response || 'No response produced.')}</p></section><section><span>Candidate B${bIdentity}</span><p>${escapeHtml(pair.b_response || 'No response produced.')}</p></section></div>
      <footer>${reviewActions}</footer>
    </article>`;
  }).join('');
  const blockers = (recommendation.blockers || []).map(value => `<li>${escapeHtml(value)}</li>`).join('');
  const promotionAction = recommendation.ready && recommendation.change_required && !activePromotion
    ? `<button class="button primary" data-promote-tournament="${escapeHtml(tournament.id)}" data-profile-id="${escapeHtml(recommendation.profile_id)}" data-fingerprint="${escapeHtml(tournament.fingerprint)}">Promote reviewed winner</button>`
    : activePromotion
      ? `<button class="button ghost" data-rollback-promotion="${escapeHtml(activePromotion.id)}">Rollback to ${escapeHtml(activePromotion.previous_profile_id)}</button>`
      : recommendation.ready
        ? '<span class="baseline-badge">Current route remains the winner</span>'
        : '';
  return `<article class="tournament-decision ${recommendation.ready ? 'ready' : 'hold'}">
    <header><div><span>${tournament.status === 'awaiting-review' ? 'BLIND REVIEW REQUIRED' : recommendation.ready ? 'REVIEWED WINNER' : tournament.status.toUpperCase()}</span><h4>${escapeHtml(tournamentTargetLabel(tournament.target))} · ${escapeHtml(recommendation.label_name || 'No eligible winner')}</h4></div><b>${recommendation.final_score == null ? '—' : Number(recommendation.final_score).toFixed(1)}</b></header>
    <p>${escapeHtml(tournament.error || recommendation.label || 'Tournament is still running.')}</p>
    <div class="tournament-boundary"><span><b>${(tournament.profile_ids || []).length}</b> local candidates</span><span><b>${completedReviews}/${(tournament.review_pairs || []).length}</b> blind reviews</span><span><b>0</b> external Splunk calls</span><span><b>${escapeHtml(tournament.suite_version)}</b> suite</span></div>
    ${blockers ? `<div class="golden-reasons blockers"><b>Promotion blockers</b><ul>${blockers}</ul></div>` : ''}
    <section class="tournament-ranking"><div class="validation-section-heading"><div><span>WEIGHTED LOCAL RANKING</span><h4>Quality, safety, latency, outcome evidence, and blind preference</h4></div></div><div>${ranking}</div></section>
    ${reviewPairs ? `<section class="blind-review"><div class="validation-section-heading"><div><span>ANALYST COMPARISON</span><h4>Review the finalists without model labels</h4></div></div>${reviewPairs}</section>` : ''}
    <footer><div><time>${escapeHtml(benchmarkTime(tournament.completed_at || tournament.created_at))}</time>${tournament.fingerprint ? `<code title="Exact promotion fingerprint">${escapeHtml(tournament.fingerprint)}</code>` : ''}</div>${promotionAction}</footer>
  </article>`;
}

function updateTournamentAssignmentHelp() {
  const overview = state.goldenBenchmarks?.tournament;
  if (!overview) return;
  const target = (overview.targets || []).find(item => item.id === $('#tournamentTarget').value);
  const profile = (state.goldenBenchmarks?.profiles || []).find(item => item.id === target?.profile_id);
  $('#tournamentCurrentAssignment').textContent = `Current · ${profile?.label || target?.profile_id || 'not assigned'}`;
}

function renderModelTournaments() {
  const overview = state.goldenBenchmarks?.tournament; if (!overview) return;
  const profiles = (state.goldenBenchmarks.profiles || []).filter(item => item.enabled);
  const targetSelect = $('#tournamentTarget'); const priorTarget = targetSelect.value || 'security_reasoning_model';
  targetSelect.innerHTML = (overview.targets || []).map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.label)}</option>`).join('');
  if ([...targetSelect.options].some(option => option.value === priorTarget)) targetSelect.value = priorTarget;
  const suiteSelect = $('#tournamentSuite'); const priorSuite = suiteSelect.value || 'builtin-core';
  suiteSelect.innerHTML = evaluationSuiteOptions(priorSuite);
  if ([...suiteSelect.options].some(option => option.value === priorSuite)) suiteSelect.value = priorSuite;
  updateTournamentAssignmentHelp();
  const selectedProfiles = new Set($$('#tournamentProfiles input:checked').map(node => node.value));
  $('#tournamentProfiles').innerHTML = profiles.map(profile => `<label><input type="checkbox" value="${escapeHtml(profile.id)}" ${selectedProfiles.size ? selectedProfiles.has(profile.id) ? 'checked' : '' : 'checked'}><span><b>${escapeHtml(profile.label)}</b><small>${escapeHtml(profile.model)}</small></span></label>`).join('');
  const tournaments = (overview.tournaments || []).filter(item => item.suite_id === suiteSelect.value);
  const selected = tournaments.find(item => item.id === state.selectedTournamentId) || tournaments[0];
  if (selected) state.selectedTournamentId = selected.id;
  $('#tournamentLatest').innerHTML = renderTournamentRun(selected, overview);
  $('#tournamentStatus').textContent = (overview.active_promotions || []).length ? `${overview.active_promotions.length} promoted route${overview.active_promotions.length === 1 ? '' : 's'}` : selected ? selected.status.replaceAll('-', ' ') : 'No tournament yet';
  $('#tournamentRunHistory').innerHTML = tournaments.length ? tournaments.map(item => `<button data-show-tournament="${escapeHtml(item.id)}"><span><b>${escapeHtml(tournamentTargetLabel(item.target))}</b><small>${escapeHtml(evaluationSuiteName(item.suite_id))} · ${escapeHtml(benchmarkTime(item.completed_at || item.created_at))} · ${(item.profile_ids || []).length} candidates</small></span><em class="${item.recommendation?.ready ? 'ready' : item.status === 'error' ? 'hold' : ''}">${item.recommendation?.ready ? `WINNER · ${escapeHtml(item.recommendation.profile_id)}` : escapeHtml(item.status.replaceAll('-', ' '))}</em></button>`).join('') : '<div class="empty-inline compact-empty">No tournaments have been recorded for this suite.</div>';
}

async function runModelTournament() {
  const profileIds = $$('#tournamentProfiles input:checked').map(node => node.value);
  if (profileIds.length < 2) { toast('Select at least two local profiles'); return; }
  const target = $('#tournamentTarget').value;
  const suiteId = $('#tournamentSuite').value || 'builtin-core';
  const button = $('#runModelTournament'); button.disabled = true; button.textContent = 'Running tournament…';
  const progress = $('#tournamentProgress'); progress.hidden = false;
  progress.querySelector('.operation-label').textContent = 'Preparing model tournament';
  progress.querySelector('.operation-detail').textContent = 'Checking the selected local profiles.';
  progress.querySelector('.operation-progress i').style.width = '0%'; progress.querySelector('.operation-steps').innerHTML = '';
  progress.scrollIntoView({behavior:'smooth',block:'center'});
  try {
    const result = await streamApi('/api/benchmarks/tournaments/run/stream', {profile_ids:profileIds,target,suite_id:suiteId}, event => updateOperation(progress,event));
    state.selectedTournamentId = result.id;
    await loadGoldenBenchmarks();
    toast(result.review_pairs?.length ? 'Tournament complete · blind finalist review is ready' : 'Tournament completed without two reviewable finalists');
  } catch (error) { toast(error.message); await loadGoldenBenchmarks(); }
  finally { button.disabled = false; button.textContent = 'Run tournament'; }
}

async function reviewTournamentPair(button) {
  button.closest('.blind-comparison')?.querySelectorAll('button').forEach(node => { node.disabled = true; });
  try {
    await api(`/api/benchmarks/tournaments/${encodeURIComponent(button.dataset.tournamentReview)}/review`, {method:'POST',body:JSON.stringify({pair_id:button.dataset.pairId,choice:button.dataset.choice})});
    state.selectedTournamentId = button.dataset.tournamentReview;
    await loadGoldenBenchmarks();
    toast('Blind comparison recorded locally');
  } catch (error) { toast(error.message); await loadGoldenBenchmarks(); }
}

async function promoteModelTournament(button) {
  const tournament = state.goldenBenchmarks?.tournament?.tournaments?.find(item => item.id === button.dataset.promoteTournament);
  if (!tournament) return;
  const approved = confirm(`Promote ${button.dataset.profileId} to ${tournamentTargetLabel(tournament.target)}?\n\nTournament fingerprint: ${button.dataset.fingerprint}\n\nThis changes local model routing and accepts the winning run as the regression baseline. Ollama will load the profile on its next request.`);
  if (!approved) return;
  button.disabled = true;
  try {
    const result = await api(`/api/benchmarks/tournaments/${encodeURIComponent(tournament.id)}/promote`, {method:'POST',body:JSON.stringify({profile_id:button.dataset.profileId,fingerprint:button.dataset.fingerprint})});
    state.settings = result.settings; hydrateSettings(); renderModels(); await loadGoldenBenchmarks();
    toast('Reviewed winner promoted · rollback remains available');
  } catch (error) { toast(error.message); button.disabled = false; }
}

async function rollbackModelPromotion(button) {
  const promotion = state.goldenBenchmarks?.tournament?.active_promotions?.find(item => item.id === button.dataset.rollbackPromotion);
  if (!promotion) return;
  const approved = confirm(`Rollback ${tournamentTargetLabel(promotion.target)} from ${promotion.profile_id} to ${promotion.previous_profile_id}?\n\nRollback is allowed only while routing and the accepted baseline still match this promotion.`);
  if (!approved) return;
  button.disabled = true;
  try {
    const result = await api(`/api/benchmarks/promotions/${encodeURIComponent(promotion.id)}/rollback`, {method:'POST',body:'{}'});
    state.settings = result.settings; hydrateSettings(); renderModels(); await loadGoldenBenchmarks();
    toast('Model routing and benchmark baseline rolled back');
  } catch (error) { toast(error.message); button.disabled = false; }
}

function renderGoldenRun(run) {
  if (!run) return '<div class="empty-inline compact-empty">Run the suite to create a candidate promotion decision.</div>';
  const gate = run.gate || {}; const comparison = run.comparison || {}; const feedback = run.feedback || {};
  const decision = run.status === 'error' ? 'RUN ERROR' : gate.ready ? 'READY TO PROMOTE' : 'HOLD';
  const blockers = (gate.blockers || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const warnings = (gate.warnings || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const scenarios = (run.results || []).map(item => `<article class="golden-result ${item.passed ? 'passed' : 'failed'} ${item.critical ? 'critical' : ''}"><header><div><span>${escapeHtml(item.task_type)} · ${item.duration_ms ? `${(item.duration_ms/1000).toFixed(1)}s` : 'not run'}</span><h5>${escapeHtml(item.title)}</h5></div><b>${Math.round(item.score)}/100</b></header><div class="golden-checks">${(item.checks || []).map(check => `<span class="${check.passed ? 'passed' : check.critical ? 'critical' : 'failed'}"><i></i>${escapeHtml(check.label)} <b>${Number(check.earned).toFixed(0)}/${Number(check.possible).toFixed(0)}</b></span>`).join('')}</div><details><summary>Inspect response and controls</summary>${item.error ? `<p class="validation-error">${escapeHtml(item.error)}</p>` : ''}<p>${escapeHtml(item.response || 'No response was produced.')}</p><small>Tools: ${escapeHtml((item.tools || []).map(call => call.name).join(', ') || 'none')} · Model: ${escapeHtml(item.model || 'not executed')}</small></details></article>`).join('');
  const comparisonText = comparison.has_baseline ? `${comparison.score_delta >= 0 ? '+' : ''}${comparison.score_delta} score · ${comparison.pass_rate_delta >= 0 ? '+' : ''}${Math.round(comparison.pass_rate_delta*100)} pass-rate points vs baseline` : 'No accepted baseline · eligible run can establish it';
  const feedbackText = feedback.total ? `${Math.round(Number(feedback.positive_rate || 0)*100)}% positive across ${feedback.total} analyst ratings` : 'No analyst ratings for this profile yet';
  const trust = gate.model_trust || run.artifact_binding || {};
  return `<article class="golden-decision ${gate.ready ? 'ready' : 'hold'} ${run.status === 'error' ? 'error' : ''}"><header><div><span>${decision}</span><h4>${escapeHtml(run.profile_id)} · ${escapeHtml(run.model)}</h4></div><b>${Math.round(run.score)}/100</b></header><p>${escapeHtml(run.error || gate.label || 'Benchmark is still running.')}</p><div class="golden-metrics"><span><b>${Math.round(Number(run.pass_rate || 0)*100)}%</b>scenario pass rate</span><span><b>${run.critical_failures || 0}</b>critical failures</span><span><b>${escapeHtml(run.suite_version)}</b>suite version</span><span><b>${escapeHtml(run.prompt_version)}</b>prompt version</span><span><b>${escapeHtml((trust.status || 'legacy').replaceAll('-', ' '))}</b>artifact trust · ${escapeHtml(shortDigest(trust.identity_fingerprint || ''))}</span></div><div class="golden-comparison"><span>${escapeHtml(comparisonText)}</span><span>${escapeHtml(feedbackText)}</span></div>${blockers ? `<div class="golden-reasons blockers"><b>Promotion blockers</b><ul>${blockers}</ul></div>` : ''}${warnings ? `<div class="golden-reasons warnings"><b>Decision context</b><ul>${warnings}</ul></div>` : ''}<div class="golden-results">${scenarios}</div><footer><time>${escapeHtml(benchmarkTime(run.completed_at || run.created_at))}</time>${gate.ready && !run.is_baseline ? `<button class="button primary small" data-accept-golden-baseline="${escapeHtml(run.id)}">Accept as baseline</button>` : run.is_baseline ? '<span class="baseline-badge">Accepted baseline</span>' : ''}</footer></article>`;
}

function renderGoldenBenchmarks() {
  const value = state.goldenBenchmarks; if (!value) return;
  renderEvaluationSuites();
  renderModelTournaments();
  const select = $('#goldenProfile'); const selected = select.value || state.settings?.security_reasoning_model || '';
  select.innerHTML = (value.profiles || []).map(profile => `<option value="${escapeHtml(profile.id)}" ${!profile.enabled ? 'disabled' : ''}>${escapeHtml(profile.label)} · ${escapeHtml(profile.model)}</option>`).join('');
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
  const suiteSelect = $('#goldenSuite'); const selectedSuite = suiteSelect.value || 'builtin-core';
  suiteSelect.innerHTML = evaluationSuiteOptions(selectedSuite);
  if ([...suiteSelect.options].some(option => option.value === selectedSuite)) suiteSelect.value = selectedSuite;
  const suite = runnableEvaluationSuites().find(item => item.id === suiteSelect.value) || runnableEvaluationSuites()[0];
  $('#goldenSuiteVersion').textContent = `Suite ${suite?.suite_version || value.suite_version} · ${suite?.scenario_count || value.scenario_count} scenarios`;
  $('#runGoldenBenchmark').textContent = `Run ${suite?.scenario_count || 5}-scenario gate`;
  $('#goldenScenarioCatalog').innerHTML = (value.scenarios || []).map(item => `<article><header><span>${escapeHtml(item.task_type)}</span><b>${escapeHtml(item.title)}</b></header><p>${item.expected_evidence_controls} evidence controls · ${item.expected_conclusion_controls} conclusion controls · tools: ${escapeHtml((item.expected_tools || []).join(', ') || 'none')}</p>${item.guardrail_control ? '<em>Critical guardrail control</em>' : ''}</article>`).join('');
  const suiteRuns = (value.runs || []).filter(run => run.suite_id === (suite?.id || 'builtin-core'));
  const latest = suiteRuns[0];
  $('#goldenBenchmarkLatest').innerHTML = renderGoldenRun(latest);
  $('#goldenRunHistory').innerHTML = suiteRuns.length ? suiteRuns.slice(0,8).map(run => `<button data-show-golden-run="${escapeHtml(run.id)}"><span><b>${escapeHtml(run.profile_id)}</b><small>${escapeHtml(evaluationSuiteName(run.suite_id))} · ${escapeHtml(benchmarkTime(run.completed_at || run.created_at))}</small></span><em class="${run.is_baseline ? 'baseline' : run.gate?.ready ? 'ready' : 'hold'}">${run.is_baseline ? 'BASELINE' : run.status === 'error' ? 'ERROR' : `${Math.round(run.score)} · ${run.gate?.decision || run.status}`}</em></button>`).join('') : '<div class="empty-inline compact-empty">No benchmark runs have been recorded for this suite.</div>';
}

async function loadGoldenBenchmarks() {
  try { state.goldenBenchmarks = await api('/api/benchmarks'); renderGoldenBenchmarks(); }
  catch (error) { $('#goldenBenchmarkLatest').innerHTML = `<div class="empty-inline compact-empty">${escapeHtml(error.message)}</div>`; }
}

async function runGoldenBenchmark() {
  const profileId = $('#goldenProfile').value; if (!profileId) return;
  const suiteId = $('#goldenSuite').value || 'builtin-core';
  const button = $('#runGoldenBenchmark'); button.disabled = true; button.textContent = 'Running gate…';
  const progress = $('#goldenProgress'); progress.hidden = false;
  progress.querySelector('.operation-label').textContent = 'Preparing golden investigations';
  progress.querySelector('.operation-detail').textContent = 'Checking the selected local model.';
  progress.querySelector('.operation-progress i').style.width = '0%'; progress.querySelector('.operation-steps').innerHTML = '';
  progress.scrollIntoView({behavior:'smooth',block:'center'});
  try {
    const result = await streamApi('/api/benchmarks/run/stream', {profile_id:profileId,suite_id:suiteId}, event => updateOperation(progress,event));
    await loadGoldenBenchmarks();
    toast(result.gate?.ready ? 'Golden gate passed · review before accepting baseline' : 'Golden gate completed with promotion blockers');
  } catch (error) { toast(error.message); await loadGoldenBenchmarks(); }
  finally {
    button.disabled = false;
    const suite = runnableEvaluationSuites().find(item => item.id === suiteId);
    button.textContent = `Run ${suite?.scenario_count || 5}-scenario gate`;
  }
}

async function acceptGoldenBaseline(runId) {
  try {
    await api(`/api/benchmarks/runs/${encodeURIComponent(runId)}/baseline`, {method:'POST',body:'{}'});
    await loadGoldenBenchmarks(); toast('Golden run accepted as the local baseline');
  } catch (error) { toast(error.message); }
}

function renderFeedbackBenchmarks() {
  const value = state.feedbackBenchmarks; if (!value) return;
  $('#feedbackTotal').textContent = `${value.total || 0} rating${value.total === 1 ? '' : 's'}`;
  $('#modelBenchmarkGrid').innerHTML = (value.scorecards || []).length ? value.scorecards.map(item => `
    <article class="model-benchmark-card"><header><div><span>${escapeHtml(item.task_type.replaceAll('-', ' '))}</span><h4>${escapeHtml(item.model_profile)}</h4></div><b>${Math.round(Number(item.positive_rate || 0) * 100)}%</b></header><p>${Number(item.total).toLocaleString()} analyst outcome${item.total === 1 ? '' : 's'} · ${escapeHtml(item.confidence)}</p><div>${Object.entries(item.ratings || {}).map(([rating,count]) => `<span><b>${count}</b>${escapeHtml(rating.replaceAll('-', ' '))}</span>`).join('')}</div><code>${escapeHtml(item.model || 'model not reported')}</code></article>`).join('') : '<div class="empty-inline compact-empty">Rate an Investigate response to start a local quality baseline.</div>';
}

async function loadFeedbackBenchmarks() {
  try { state.feedbackBenchmarks = await api('/api/feedback/benchmarks'); renderFeedbackBenchmarks(); }
  catch (_) { /* Outcome reporting is non-blocking. */ }
}

async function recordAnalystFeedback(button) {
  const message = button.closest('.message.assistant'); if (!message?.dataset.feedbackTarget) return;
  const rating = button.dataset.feedbackRating;
  const note = rating === 'useful' ? '' : (window.prompt('Optional: what should SignalRoom or this model have done differently?') || '');
  const payload = {
    target_type:'chat', target_id:message.dataset.feedbackTarget,
    task_type:message.dataset.feedbackTask || 'general', rating,
    model_profile:message.dataset.feedbackProfile || '', model:message.dataset.feedbackModel || '',
    route:message.dataset.feedbackRoute || '', note, metadata:{ local_first:true }
  };
  try {
    await api('/api/feedback', { method:'POST', body:JSON.stringify(payload) });
    message.querySelectorAll('[data-feedback-rating]').forEach(node => { node.disabled = true; node.classList.toggle('selected', node === button); });
    const status = message.querySelector('.analyst-feedback em'); if (status) status.textContent = 'Recorded locally';
    await loadFeedbackBenchmarks(); toast('Analyst feedback recorded locally');
  } catch (error) { toast(error.message); }
}

function renderModelRecommendations(items = []) {
  items.forEach(item => { state.modelRecommendations[item.id] = item; });
  if (!items.length) return '';
  const statusCopy = {
    ready:'READY',
    'approval-required':'ONE-CALL APPROVAL',
    disabled:'LOCAL-ONLY RESPECTED · HF OPTIONAL',
    unavailable:'SETUP REQUIRED',
    'install-required':'LOCAL INSTALL REQUIRED'
  };
  return `<section class="model-recommendations" aria-label="Recommended specialist follow-ups">
    <header><span>NEXT BEST MODEL</span><p>Optional specialist passes derived from this result—not generic prompts.</p></header>
    <div class="model-recommendation-list">${items.map(item => `
      <article class="model-recommendation ${item.external ? 'external' : 'local'} ${escapeHtml(item.availability)}">
        <div class="model-recommendation-heading"><span>${item.external ? 'HOSTED SPECIALIST' : item.specialist === 'chat' ? 'LOCAL · OLLAMA' : 'LOCAL · TRANSFORMERS'}</span><b>${escapeHtml(statusCopy[item.availability] || item.availability)}</b></div>
        <h4>Use ${escapeHtml(item.label)} to ${escapeHtml(item.purpose)}</h4>
        <p>${escapeHtml(item.reason)}</p>
        <div class="expected-result"><b>Expected result</b><span>${escapeHtml(item.expected_result)}</span></div>
        <footer><code>${escapeHtml(item.model)}</code><button data-use-model-recommendation="${escapeHtml(item.id)}">${escapeHtml(item.action_label)}</button></footer>
      </article>`).join('')}</div>
  </section>`;
}

function renderResultEnrichment(value = {}) {
  const entities = value.entities || []; const matches = value.context_matches || [];
  if ((!entities.length && !matches.length) || value.status === 'not-needed') return '';
  const entityCards = entities.slice(0, 12).map(item => `
    <article class="pivot-card">
      <div><span>${escapeHtml(item.entity_type)}</span><b title="${escapeHtml(item.value)}">${escapeHtml(item.value)}</b><small>${escapeHtml(item.source.replaceAll('-', ' '))} · ${Math.round(Number(item.confidence || 0) * 100)}%</small></div>
      <button data-prompt="${escapeHtml(item.prompt)}">Investigate</button>
    </article>`).join('');
  const contextCards = matches.slice(0, 4).map(item => `
    <article class="correlation-card">
      <div><span>${escapeHtml(item.kind)}</span><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.source)} · score ${Number(item.score || 0).toFixed(2)}</small></div>
      <button data-open-artifact="${escapeHtml(item.id.split(':')[0])}">Inspect</button>
    </article>`).join('');
  return `<section class="result-enrichment ${value.runtime?.startsWith('Hosted') ? 'hosted' : 'local'}" aria-label="Evidence intelligence from this result">
    <header><div><span>RESULT INTELLIGENCE</span><h4>${escapeHtml(value.runtime || 'Local enrichment')}</h4></div><div class="enrichment-counts"><b>${entities.length} pivots</b><b>${matches.length} context matches</b></div></header>
    <p>${escapeHtml(value.summary || 'SignalRoom extracted reusable investigation context from the returned evidence.')}</p>
    ${entities.length ? `<div class="enrichment-group"><h5>Observed pivots</h5><div class="pivot-grid">${entityCards}</div></div>` : ''}
    ${matches.length ? `<div class="enrichment-group"><h5>Related local Context</h5><div class="correlation-grid">${contextCards}</div></div>` : ''}
    ${(value.notes || []).length ? `<details><summary>How this was produced</summary><ul>${value.notes.map(note => `<li>${escapeHtml(note)}</li>`).join('')}</ul></details>` : ''}
  </section>`;
}

function appendMessage(role, content, meta = {}) {
  const welcome = $('.welcome-card'); if (welcome) welcome.remove();
  const node = document.createElement('article'); node.className = `message ${role}`;
  if (role === 'user') node.innerHTML = `<div class="bubble">${escapeHtml(content)}</div>`;
  else {
    node.dataset.feedbackTarget = meta.targetId || '';
    node.dataset.feedbackModel = meta.model || '';
    node.dataset.feedbackProfile = meta.profile || '';
    node.dataset.feedbackRoute = meta.route || '';
    node.dataset.feedbackTask = meta.taskType || 'general';
    node.innerHTML = `<div class="agent-avatar">S</div><div><div class="answer">${renderMarkdown(content)}</div>
    <div class="answer-meta"><span>Executed · ${escapeHtml(meta.model || 'SignalRoom')}</span>${meta.profile ? `<span>Profile · ${escapeHtml(meta.profile)}</span>` : ''}<span>${escapeHtml(meta.route || 'evidence-led')}</span>${meta.activated ? '<span>Loaded for this request</span>' : ''}</div>
    ${renderResultEnrichment(meta.enrichment || {})}
    ${renderModelRecommendations(meta.modelRecommendations || [])}
    <div class="suggestions">${(meta.suggestions || []).map(item => `<button data-prompt="${escapeHtml(item)}">${escapeHtml(item)}</button>`).join('')}</div>
    ${meta.targetId ? '<div class="analyst-feedback"><span>Did this advance the investigation?</span><button data-feedback-rating="useful">Useful</button><button data-feedback-rating="incorrect">Incorrect</button><button data-feedback-rating="missing-evidence">Missing evidence</button><em></em></div>' : ''}</div>`;
  }
  $('#messages').appendChild(node); $('#messages').scrollTop = $('#messages').scrollHeight;
}

function showAgentWork() {
  const node = document.createElement('article'); node.className = 'message assistant'; node.id = 'agentWork';
  node.innerHTML = `<div class="agent-avatar">S</div><section class="agent-work operation-card" aria-live="polite">
    <header><div><span class="operation-kicker">AGENT ACTIVITY</span><h3 class="operation-label">Preparing investigation</h3></div><span class="operation-elapsed">0s</span></header>
    <p class="operation-detail">SignalRoom is selecting an evidence-bounded path.</p>
    <div class="operation-progress" role="progressbar" aria-label="Investigation progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i></i></div>
    <div class="operation-metrics"></div><ol class="operation-steps"></ol>
  </section>`;
  node._startedAt = Date.now();
  node._timer = setInterval(() => {
    const elapsed = node.querySelector('.operation-elapsed');
    if (elapsed) elapsed.textContent = `${Math.round((Date.now() - node._startedAt) / 1000)}s`;
  }, 1000);
  $('#messages').appendChild(node); $('#messages').scrollTop = $('#messages').scrollHeight;
  return node;
}

function formatMetric(key, value) {
  const label = key.replaceAll('_', ' ').replace(/\b\w/g, char => char.toUpperCase());
  return `<span><b>${escapeHtml(value)}</b>${escapeHtml(label)}</span>`;
}

function updateOperation(container, event) {
  if (!container || event.type === 'result') return;
  const elapsed = container.querySelector('.operation-elapsed');
  if (elapsed && event.elapsed_seconds !== undefined) elapsed.textContent = `${Math.round(event.elapsed_seconds)}s`;
  if (event.type === 'heartbeat') return;
  const label = container.querySelector('.operation-label'); const detail = container.querySelector('.operation-detail');
  if (label) label.textContent = event.label || 'Working'; if (detail) detail.textContent = event.detail || '';
  const progressBar = container.querySelector('.operation-progress'); const fill = progressBar?.querySelector('i');
  if (event.progress !== undefined && fill) { fill.style.width = `${event.progress}%`; progressBar.setAttribute('aria-valuenow', event.progress); }
  const metrics = container.querySelector('.operation-metrics');
  if (metrics && event.metrics && Object.keys(event.metrics).length) metrics.innerHTML = Object.entries(event.metrics).slice(0, 4).map(([key,value]) => formatMetric(key, value)).join('');
  const steps = container.querySelector('.operation-steps'); if (!steps || !event.phase) return;
  let step = [...steps.children].find(item => item.dataset.phase === event.phase);
  if (!step) {
    [...steps.children].filter(item => item.classList.contains('running')).forEach(item => { item.classList.remove('running'); item.classList.add('complete'); });
    step = document.createElement('li'); step.dataset.phase = event.phase; steps.appendChild(step);
  }
  step.className = event.status === 'complete' ? 'complete' : event.status === 'error' ? 'error' : 'running';
  step.innerHTML = `<i></i><div><b>${escapeHtml(event.label || event.phase)}</b><span>${escapeHtml(event.detail || '')}</span></div>`;
  if (steps.children.length > 8) steps.firstElementChild.remove();
  $('#messages').scrollTop = $('#messages').scrollHeight;
}

function finishAgentWork() {
  const node = $('#agentWork'); if (!node) return;
  clearInterval(node._timer); node.remove();
}

function beginDiscoveryProgress() {
  const card = $('#discoveryProgress'); card.hidden = false;
  $('#discoveryProgressLabel').textContent = 'Preparing discovery'; $('#discoveryProgressDetail').textContent = 'SignalRoom is preparing the read-only collection plan.';
  $('#discoveryElapsed').textContent = '0s'; $('#discoveryProgressBar').style.width = '0%';
  card.querySelector('.operation-progress').setAttribute('aria-valuenow', '0');
  $('#discoveryLiveMetrics').innerHTML = ''; $('#discoveryProgressSteps').innerHTML = '';
}

function updateDiscoveryProgress(event) {
  const card = $('#discoveryProgress');
  $('#discoveryProgressLabel').classList.add('operation-label'); $('#discoveryProgressDetail').classList.add('operation-detail');
  $('#discoveryElapsed').classList.add('operation-elapsed'); $('#discoveryLiveMetrics').classList.add('operation-metrics'); $('#discoveryProgressSteps').classList.add('operation-steps');
  updateOperation(card, event);
}

function discoveryElapsed(job) {
  const start = job?.started_at || job?.created_at;
  if (!start) return '0s';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(start).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60); const remainder = seconds % 60;
  return `${minutes}m ${remainder}s`;
}

function discoveryStatusLabel(status) {
  return ({
    queued:'Queued', running:'Running', complete:'Complete', partial:'Partial',
    error:'Failed', cancelled:'Cancelled', 'budget-blocked':'Call budget reached',
    'connection-blocked':'Connection blocked'
  })[status] || status;
}

function setDiscoveryRunState(job = null) {
  const button = $('#runDiscovery');
  if (job) {
    button.disabled = true; button.dataset.jobDisabled = 'true';
    button.textContent = job.status === 'queued' ? 'Discovery queued' : 'Discovering…';
  } else {
    delete button.dataset.jobDisabled;
    if (!button.dataset.roleDisabled && !button.dataset.connectionDisabled) button.disabled = false;
    button.textContent = 'Run discovery';
  }
}

function renderDiscoveryJobOverview(value) {
  state.discoveryJobs = value;
  const active = value.active_job;
  state.activeDiscoveryJob = active;
  $('#discoveryWorker').textContent = value.worker?.online ? 'Worker online · 1 at a time' : 'Worker offline';
  $('#discoveryWorker').classList.toggle('warning', !value.worker?.online);
  setDiscoveryRunState(active);
  if (active) {
    beginDiscoveryProgress();
    (value.active_events || []).forEach(updateDiscoveryProgress);
    $('#discoveryElapsed').textContent = discoveryElapsed(active);
    $('#discoveryStatus').textContent = `${discoveryStatusLabel(active.status)} · ${active.depth}`;
    $('#discoveryJobContract').textContent = `${active.depth} · ${active.calls_used}/${active.call_budget} Splunk calls · ${active.id.slice(0, 8)}${active.recovery_count ? ` · recovered ${active.recovery_count}×` : ''}`;
    $('#cancelDiscoveryJob').hidden = false;
    $('#cancelDiscoveryJob').disabled = Boolean(active.cancel_requested);
    $('#cancelDiscoveryJob').textContent = active.cancel_requested ? 'Stopping…' : 'Cancel run';
  } else {
    $('#cancelDiscoveryJob').hidden = true;
  }
  const jobs = value.jobs || [];
  $('#discoveryJobHistory').innerHTML = jobs.length ? jobs.slice(0, 10).map(job => {
    const terminal = !['queued','running'].includes(job.status);
    const hasResult = Boolean(job.result_run_id);
    const recovery = job.recovery_count ? ` · restarted ${job.recovery_count}×` : '';
    const callContract = `${job.calls_used}/${job.call_budget} calls`;
    const timestamp = new Date(job.completed_at || job.updated_at || job.created_at).toLocaleString();
    return `<article class="discovery-job-row ${escapeHtml(job.status)}">
      <div class="discovery-job-state"><span>${escapeHtml(discoveryStatusLabel(job.status))}</span><b>${escapeHtml(job.depth)}</b></div>
      <div><b>${escapeHtml(job.label)}</b><p>${escapeHtml(job.detail || 'Waiting for activity.')}</p><small>${escapeHtml(timestamp)} · ${escapeHtml(callContract)}${escapeHtml(recovery)} · ${escapeHtml(job.requested_by)} · ${escapeHtml(job.tenant_scope_id)}</small></div>
      <button class="button ghost small" type="button" data-inspect-discovery-job="${escapeHtml(job.id)}">${hasResult ? 'Open result' : (terminal ? 'Inspect run' : 'View live')}</button>
    </article>`;
  }).join('') : '<div class="empty-inline compact-empty">No durable manual discovery jobs have run yet.</div>';
  applyAccessPermissions();
}

function scheduleDiscoveryPoll(active) {
  clearTimeout(state.discoveryPollTimer); state.discoveryPollTimer = null;
  if (!active) return;
  state.discoveryPollTimer = setTimeout(() => loadDiscoveryJobs().catch(() => {}), 1000);
}

async function loadDiscoveryJobs() {
  if (state.discoveryPollBusy) return;
  state.discoveryPollBusy = true;
  let active = null;
  try {
    const value = await api(scopedUrl('/api/discovery/jobs', {limit:12}));
    active = value.active_job;
    renderDiscoveryJobOverview(value);
    if (active) state.discoveryWatchingJobId = active.id;
    if (!active && state.discoveryWatchingJobId) {
      const completedId = state.discoveryWatchingJobId;
      const completed = (value.jobs || []).find(item => item.id === completedId);
      state.discoveryWatchingJobId = null;
      if (completed?.result_run_id) {
        const result = await api(scopedUrl(`/api/discovery/jobs/${encodeURIComponent(completedId)}/result`));
        renderDiscoveryResult(result);
        await loadArtifacts();
        toast(completed.status === 'partial' || completed.status === 'budget-blocked'
          ? 'Discovery retained with collection gaps' : 'Discovery artifacts created');
      } else if (completed) {
        $('#discoveryStatus').textContent = discoveryStatusLabel(completed.status);
        toast(completed.detail || discoveryStatusLabel(completed.status));
      }
    }
  } finally {
    state.discoveryPollBusy = false;
    scheduleDiscoveryPoll(active);
  }
}

async function inspectDiscoveryJob(jobId) {
  try {
    const detail = await api(scopedUrl(`/api/discovery/jobs/${encodeURIComponent(jobId)}`));
    beginDiscoveryProgress();
    (detail.events || []).forEach(updateDiscoveryProgress);
    const job = detail.job;
    $('#discoveryElapsed').textContent = ['queued','running'].includes(job.status) ? discoveryElapsed(job) : discoveryStatusLabel(job.status);
    $('#discoveryJobContract').textContent = `${job.depth} · ${job.calls_used}/${job.call_budget} Splunk calls · ${job.id.slice(0, 8)}${job.recovery_count ? ` · recovered ${job.recovery_count}×` : ''}`;
    $('#cancelDiscoveryJob').hidden = !['queued','running'].includes(job.status);
    if (detail.result_available) {
      const result = await api(scopedUrl(`/api/discovery/jobs/${encodeURIComponent(jobId)}/result`));
      renderDiscoveryResult(result);
    } else {
      $('#discoveryStatus').textContent = `${discoveryStatusLabel(job.status)} · ${job.depth}`;
    }
    $('#discoveryProgress').scrollIntoView({ behavior:'smooth', block:'start' });
  } catch (error) { toast(error.message); }
}

function renderEvidence(evidence = [], trace = [], ledger = []) {
  state.ledger = ledger;
  const toolObservations = ledger.filter(item => item.classification !== 'context' && item.status === 'observed');
  const inPlayCount = evidence.length + toolObservations.length;
  $('#evidenceCount').textContent = inPlayCount; $('#mobileEvidenceCount').textContent = ledger.length || inPlayCount; $('#evidenceEmpty').hidden = inPlayCount > 0;
  const contextCards = evidence.map((item, index) => `<article class="evidence-card"><header><span class="ref">E${index+1}</span><b>${escapeHtml(item.title)}</b></header><div class="scope-provenance"><span>${escapeHtml(item.connection_alias)}</span><code>${escapeHtml(item.tenant_scope_id)}</code><code>${escapeHtml(shortFingerprint(item.connection_fingerprint))}</code></div><p class="expandable-copy">${escapeHtml(item.excerpt)}</p>${item.excerpt.length > 260 ? '<div class="evidence-card-actions"><button data-toggle-copy>Show more</button></div>' : ''}<footer><span>${escapeHtml(item.source)}<b>score ${Number(item.score).toFixed(2)}</b></span><button data-open-artifact="${escapeHtml(item.id.split(':')[0])}">Inspect source</button></footer></article>`).join('');
  const toolCards = toolObservations.map((item, index) => `<article class="evidence-card tool-evidence-card"><header><span class="ref">T${index+1}</span><b>Live Splunk observation</b></header><p class="expandable-copy">${escapeHtml(item.statement)}</p>${item.statement.length > 260 ? '<div class="evidence-card-actions"><button data-toggle-copy>Show more</button></div>' : ''}<footer><span>${escapeHtml(item.source)}<b>${escapeHtml(item.confidence)} confidence</b></span><button data-open-ledger="${escapeHtml(item.id)}">Inspect evidence</button></footer></article>`).join('');
  $('#evidenceList').innerHTML = contextCards + toolCards;
  $('#traceWrap').hidden = !trace.length;
  $('#traceList').innerHTML = trace.map(item => `<div class="trace-item"><i></i><div><b>${escapeHtml(item.label)}</b><span>${escapeHtml(item.detail || item.kind)}</span></div></div>`).join('');
  $('#ledgerWrap').hidden = !ledger.length;
  $('#ledgerList').innerHTML = ledger.map(item => `<article class="ledger-item"><header><span>${escapeHtml(item.classification)}</span><b>${escapeHtml(item.status)}</b></header><p class="expandable-copy">${escapeHtml(item.statement)}</p><footer><span>${escapeHtml(item.source)} · ${escapeHtml(item.confidence)} confidence</span><span class="ledger-actions">${item.statement.length > 220 ? '<button data-toggle-copy>Show more</button>' : ''}<button data-open-ledger="${escapeHtml(item.id)}">Why & next actions →</button></span></footer></article>`).join('');
}

async function sendChat(message, options = {}) {
  if (state.busy || !message.trim()) return; state.busy = true;
  appendMessage('user', message.trim()); $('#chatInput').value = ''; resizeComposer(); showAgentWork();
  try {
    const result = await streamApi('/api/chat/stream', {
      message: message.trim(), conversation_id: state.conversationId,
      model_profile: Object.hasOwn(options, 'modelProfile') ? options.modelProfile : ($('#modelSelect').value || null),
      mode: options.mode || $('#investigationMode').value,
      include_context: $('#includeContext').checked,
      huggingface_approved: Boolean(options.approveHf) || (!$('#hfQueryApproval').hidden && $('#approveHf').checked),
      huggingface_specialist: options.hfSpecialist || null,
      execute_searches: true,
      ...scopePayload()
    }, event => updateOperation($('#agentWork')?.querySelector('.agent-work'), event));
    state.conversationId = result.conversation_id; finishAgentWork();
    appendMessage('assistant', result.message, { model: result.model, profile: result.model_profile, route: result.route, taskType:result.mode, targetId:`${result.conversation_id}:${result.generated_at}`, activated:result.model_activation?.activated, suggestions: result.suggested_actions, modelRecommendations:result.model_recommendations, enrichment:result.enrichment });
    renderEvidence(result.evidence, result.trace, result.ledger);
    $('#approveHf').checked = false;
  } catch (error) { finishAgentWork(); appendMessage('assistant', `The request failed: ${error.message}`); }
  finally { state.busy = false; }
}

async function runDiscovery() {
  const button = $('#runDiscovery'); button.disabled = true; button.textContent = 'Queuing…';
  $('#discoveryStatus').textContent = 'Queuing durable job'; beginDiscoveryProgress();
  try {
    const job = await api('/api/discovery/jobs', { method:'POST', body:JSON.stringify({ depth:$('#discoveryDepth').value, ...scopePayload() }) });
    state.discoveryWatchingJobId = job.id;
    toast('Discovery queued; you can safely refresh this page');
    await loadDiscoveryJobs();
  } catch (error) {
    $('#discoveryStatus').textContent = 'Failed to queue'; toast(error.message);
    setDiscoveryRunState(null);
  }
}

async function cancelDiscoveryJob() {
  const job = state.activeDiscoveryJob; if (!job) return;
  try {
    $('#cancelDiscoveryJob').disabled = true; $('#cancelDiscoveryJob').textContent = 'Stopping…';
    await api(scopedUrl(`/api/discovery/jobs/${encodeURIComponent(job.id)}/cancel`), { method:'POST', body:'{}' });
    toast('Discovery cancellation requested');
    await loadDiscoveryJobs();
  } catch (error) { toast(error.message); }
}

function assuranceTime(value) {
  if (!value) return 'Not scheduled';
  return new Date(value).toLocaleString();
}

function assurancePackage(packageId) {
  return (state.assurance?.response_packages || []).find(item => item.id === packageId);
}

function renderAssurancePackages(value) {
  const counts = value.signal_counts || {};
  $('#assuranceSignalCounts').innerHTML = `<span class="persistent"><b>${counts.actionable || 0}</b> actionable</span><span class="repeated"><b>${counts.repeated || 0}</b> repeated</span><span class="elevated"><b>${counts.severity_elevated || 0}</b> severity-elevated</span><span class="watching"><b>${counts.watching || 0}</b> transient · watching</span><span class="resolved"><b>${counts.resolved || 0}</b> resolved</span>`;
  const packages = value.response_packages || [];
  $('#assurancePackages').innerHTML = packages.length ? packages.map(item => {
    const signals = item.signals || []; const taskCount = (item.validation_task_ids || []).length;
    const signalRows = signals.slice(0,4).map(signal => `<li><span class="severity ${escapeHtml(signal.severity)}">${escapeHtml(signal.severity)}</span><div><b>${escapeHtml(signal.title)}</b><small>${signal.consecutive_count >= 2 ? `${signal.consecutive_count} consecutive runs` : 'elevated immediately by severity'} · ${escapeHtml(signal.kind)}</small></div></li>`).join('');
    const deliveryReady = value.delivery?.policy?.enabled && value.delivery?.destination?.configured;
    const deliveryAction = deliveryReady ? `<button class="button ghost small" data-preview-assurance-delivery="${escapeHtml(item.id)}">Preview delivery</button>` : '';
    const actions = item.status === 'review' ? `<button class="button primary small" data-review-assurance-package="${escapeHtml(item.id)}" ${taskCount ? '' : 'disabled'}>Review ${taskCount} draft${taskCount === 1 ? '' : 's'}</button><button class="button ghost small" data-investigate-assurance-package="${escapeHtml(item.id)}">Investigate</button><button class="button ghost small" data-case-assurance-package="${escapeHtml(item.id)}">Add to case</button>${deliveryAction}<button class="button ghost small" data-close-assurance-package="${escapeHtml(item.id)}">Close package</button>` : `<button class="button ghost small" data-investigate-assurance-package="${escapeHtml(item.id)}">Revisit in Investigate</button>`;
    return `<article class="assurance-package ${escapeHtml(item.status)} ${escapeHtml(item.severity)}"><header><div><span>${escapeHtml(item.status)} · ${escapeHtml(item.severity)}</span><h5>${escapeHtml(item.title)}</h5></div><b>${taskCount} draft${taskCount === 1 ? '' : 's'}</b></header><p>${escapeHtml(item.summary)}</p><ul>${signalRows}</ul><footer><time>${item.status === 'review' ? `Expires ${escapeHtml(assuranceTime(item.expires_at))}` : `${escapeHtml(item.status)} · ${escapeHtml(assuranceTime(item.closed_at || item.expires_at))}`}</time><div>${actions}</div></footer></article>`;
  }).join('') : '<div class="empty-inline compact-empty">No response package is open. Medium and low signals must repeat; high-severity signals package immediately.</div>';
}

async function reviewAssurancePackage(packageId) {
  const item = assurancePackage(packageId); if (!item) return;
  await loadValidations();
  setView('discovery'); history.replaceState(null, '', `${location.pathname}#discovery`);
  $('#validationWorkspace').scrollIntoView({ behavior:'smooth', block:'start' });
  setTimeout(() => {
    (item.validation_task_ids || []).forEach(id => {
      const card = document.querySelector(`[data-validation-id="${CSS.escape(id)}"]`);
      if (card) { card.classList.add('package-focus'); setTimeout(() => card.classList.remove('package-focus'), 3500); }
    });
  }, 450);
}

function investigateAssurancePackage(packageId) {
  const item = assurancePackage(packageId); if (!item) return;
  const signals = (item.signals || []).map(signal => `- ${signal.title}: ${signal.detail} (${signal.consecutive_count} consecutive run(s))`).join('\n');
  openInvestigation('discovery', `Investigate this continuous-assurance response package. Separate deterministic observations from hypotheses, use existing context before issuing new SPL, and recommend the smallest bounded next check.\n\nPackage: ${item.title}\nSummary: ${item.summary}\nSignals:\n${signals}`, false);
}

function caseAssurancePackage(packageId) {
  const item = assurancePackage(packageId); if (!item) return;
  const signals = (item.signals || []).map(signal => `${signal.title} — ${signal.detail} [${signal.status}; ${signal.consecutive_count} consecutive run(s)]`).join('\n');
  openCasePicker({ kind:'action', title:item.title, content:`${item.summary}\n\nCorrelated signals:\n${signals}\n\nValidation drafts: ${(item.validation_task_ids || []).length}\nExpires: ${item.expires_at}`, source:'SignalRoom continuous assurance', confidence:'high', status:'needs-validation', metadata:{ assurance_package_id:item.id, source_run_id:item.source_run_id, signal_fingerprints:item.signal_fingerprints, validation_task_ids:item.validation_task_ids, expires_at:item.expires_at } });
}

async function closeAssurancePackage(packageId) {
  try { await api(`/api/assurance/packages/${encodeURIComponent(packageId)}/close`, {method:'POST'}); await loadAssurance(); toast('Assurance response package closed'); }
  catch (error) { toast(error.message); }
}

function deliveryAdapterName(kind) {
  if (kind === 'slack-incoming-webhook') return 'Slack Incoming Webhook';
  if (kind === 'jira-cloud') return 'Jira Cloud issue';
  if (kind === 'splunk-soar') return 'Splunk SOAR container';
  return 'Generic JSON webhook';
}

function updateDeliveryAdapter(destination = state.assurance?.delivery?.destination || {}) {
  const kind = $('#deliveryKind').value;
  const isSlack = kind === 'slack-incoming-webhook';
  const isJira = kind === 'jira-cloud';
  const isSoar = kind === 'splunk-soar';
  const requiresPublicTls = isSlack || isJira;
  const usesDedicatedAuth = requiresPublicTls || isSoar;
  const adapterChanged = Boolean(destination.kind && destination.kind !== kind);
  $('#deliveryAuthorizationField').hidden = usesDedicatedAuth;
  $('#deliveryClearAuthorizationField').hidden = usesDedicatedAuth;
  $('#deliveryAuthorization').disabled = usesDedicatedAuth;
  $('#deliveryClearAuthorization').disabled = usesDedicatedAuth;
  $('#deliveryJiraFields').hidden = !isJira;
  $$('#deliveryJiraFields input,#deliveryJiraFields button').forEach(node => { node.disabled = !isJira; });
  $('#deliverySoarFields').hidden = !isSoar;
  $$('#deliverySoarFields input,#deliverySoarFields select,#deliverySoarFields button').forEach(node => { node.disabled = !isSoar; });
  $('#deliveryVerifyTls').disabled = requiresPublicTls;
  $('#deliveryCaField').hidden = requiresPublicTls;
  $('#deliveryCaBundle').disabled = requiresPublicTls;
  $('#deliveryAttemptsField').hidden = isJira;
  $('#deliveryBackoffField').hidden = isJira;
  $('#deliveryAttempts').disabled = isJira;
  $('#deliveryBackoff').disabled = isJira;
  if (requiresPublicTls) $('#deliveryVerifyTls').checked = true;
  $('#deliveryTlsField small').textContent = isJira
    ? 'Required for Jira Cloud and cannot be disabled.'
    : isSlack
      ? 'Required for the public Slack destination and cannot be disabled.'
      : isSoar
        ? 'Recommended. Disable only for a trusted self-signed SOAR endpoint, or supply a private CA path.'
        : 'Recommended. A private CA path can be supplied for internal destinations.';
  $('#deliveryUrlLabel').textContent = isJira
    ? 'Jira Cloud site URL'
    : isSlack
      ? 'Slack Incoming Webhook URL'
      : isSoar
        ? 'Splunk SOAR site URL'
        : 'HTTPS webhook URL';
  $('#deliveryUrlHelp').textContent = isJira
    ? 'Use only the encrypted site origin for your atlassian.net tenant, such as https://security.atlassian.net.'
    : isSlack
      ? 'Use the complete encrypted hooks.slack.com or hooks.slack-gov.com /services/ URL. SignalRoom never returns the secret path.'
      : isSoar
        ? 'Use the HTTPS site origin only, such as https://soar.internal:8443. SignalRoom appends the REST container path.'
        : 'HTTPS required; loopback HTTP is accepted only for local testing.';
  $('#deliveryAdapterHelp').textContent = isJira
    ? 'Jira receives one redacted create-issue request after approval. SignalRoom can explicitly refresh a correlated issue’s minimal workflow fields, but cannot update, transition, comment on, assign, attach to, or delete it. Unknown create outcomes stop for analyst review.'
    : isSlack
      ? `Slack receives plain-text notification blocks only over verified TLS. Its configured channel, sender, and icon cannot be overridden.${destination.authorization_configured ? ' A saved generic authorization value remains encrypted but is not sent.' : ''}`
      : isSoar
        ? 'Splunk SOAR receives one redacted container after approval. SignalRoom explicitly disables automation, sends no artifacts, and cannot update, assign, comment on, run actions or playbooks against, or delete the container. A deterministic source ID makes ambiguous retries duplicate-safe.'
        : 'Generic webhooks receive the exact previewed JSON, a payload hash, an idempotency key, and the optional authorization header.';
  if (!$('#deliveryWebhookUrl').value) {
    $('#deliveryWebhookUrl').placeholder = adapterChanged
      ? `Enter a ${deliveryAdapterName(kind)} URL to change adapters`
      : destination.url_configured || destination.origin
        ? 'Encrypted destination configured · leave blank to keep'
        : isJira
          ? 'https://security.atlassian.net'
          : isSlack
            ? 'https://hooks.slack.com/services/…'
            : isSoar
              ? 'https://soar.internal:8443'
              : 'https://automation.example/hooks/signalroom';
  }
}

function hydrateDeliveryPolicy(value) {
  if (!value?.policy || state.deliveryPolicyDirty) return;
  const policy = value.policy;
  $('#deliveryEnabled').checked = Boolean(policy.enabled);
  $('#deliveryMode').value = policy.mode;
  $('#deliveryKind').value = policy.destination_kind || 'generic-webhook';
  $('#deliverySeverity').value = policy.minimum_severity;
  $('#deliveryLabel').value = policy.destination_label;
  $('#deliveryRedaction').value = policy.redaction_level;
  $('#deliveryAttempts').value = policy.max_attempts;
  $('#deliveryBackoff').value = String(policy.retry_backoff_seconds);
  $('#deliveryVerifyTls').checked = Boolean(policy.verify_tls);
  $('#deliveryCaBundle').value = policy.ca_bundle || '';
  $('#deliveryJiraProject').value = policy.jira_project_key || '';
  $('#deliveryJiraIssueType').value = policy.jira_issue_type || 'Task';
  $('#deliveryJiraPrefix').value = policy.jira_summary_prefix ?? '[SignalRoom]';
  $('#deliveryJiraLabels').value = (policy.jira_labels || []).join(', ');
  $('#deliveryJiraCriticalPriority').value = policy.jira_priority_map?.critical ?? 'Highest';
  $('#deliveryJiraHighPriority').value = policy.jira_priority_map?.high ?? 'High';
  $('#deliveryJiraMediumPriority').value = policy.jira_priority_map?.medium ?? 'Medium';
  $('#deliveryJiraLowPriority').value = policy.jira_priority_map?.low ?? 'Low';
  $('#deliverySoarLabel').value = policy.soar_label || 'events';
  $('#deliverySoarContainerType').value = policy.soar_container_type || 'default';
  $('#deliverySoarStatus').value = policy.soar_status || 'new';
  $('#deliverySoarPrefix').value = policy.soar_name_prefix ?? '[SignalRoom]';
  $('#deliverySoarSensitivity').value = policy.soar_sensitivity || 'amber';
  $('#deliverySoarTags').value = (policy.soar_tags || []).join(', ');
  $('#deliverySoarCriticalSeverity').value = policy.soar_severity_map?.critical ?? 'high';
  $('#deliverySoarHighSeverity').value = policy.soar_severity_map?.high ?? 'high';
  $('#deliverySoarMediumSeverity').value = policy.soar_severity_map?.medium ?? 'medium';
  $('#deliverySoarLowSeverity').value = policy.soar_severity_map?.low ?? 'low';
  $('#deliverySoarTenantId').value = policy.soar_tenant_id || '';
  $$('.delivery-categories input').forEach(input => { input.checked = (policy.signal_kinds || []).includes(input.value); });
  $('#deliveryWebhookUrl').value = '';
  $('#deliveryAuthorization').value = '';
  $('#deliveryJiraEmail').value = '';
  $('#deliveryJiraApiToken').value = '';
  $('#deliverySoarAuthToken').value = '';
  $('#deliveryClearWebhookUrl').checked = false;
  $('#deliveryClearAuthorization').checked = false;
  $('#deliveryClearJiraEmail').checked = false;
  $('#deliveryClearJiraApiToken').checked = false;
  $('#deliveryClearSoarAuthToken').checked = false;
  $('#deliveryAuthorization').placeholder = value.destination?.authorization_configured ? 'Encrypted authorization configured · leave blank to keep' : 'Optional · Bearer …';
  $('#deliveryJiraEmail').placeholder = value.destination?.jira_email_configured ? 'Encrypted account email configured · leave blank to keep' : 'analyst@example.com';
  $('#deliveryJiraApiToken').placeholder = value.destination?.jira_api_token_configured ? 'Encrypted API token configured · leave blank to keep' : 'Paste a Jira API token';
  $('#deliverySoarAuthToken').placeholder = value.destination?.soar_auth_token_configured ? 'Encrypted auth token configured · leave blank to keep' : 'Paste a Splunk SOAR auth token';
  $('#deliveryTestResult').textContent = 'Save changes before testing. The test reads create metadata and does not create an issue.';
  $('#deliveryTestResult').className = '';
  $('#deliverySoarTestResult').textContent = 'Save changes before testing. The test reads container options and does not create a container.';
  $('#deliverySoarTestResult').className = '';
  updateDeliveryAdapter(value.destination);
}

function reconciliationValue(value) {
  if (value === null || value === undefined || value === '') return 'None';
  if (typeof value === 'boolean') return value ? 'Present' : 'Missing';
  if (typeof value === 'object') return value.name || value.key || value.id || 'Changed';
  return String(value);
}

function reconciliationFieldLabel(field) {
  return ({
    availability:'Visibility',
    issue_key:'Issue key',
    project_key:'Project',
    issue_type:'Issue type',
    status:'Workflow status',
    priority:'Priority',
    resolution:'Resolution',
    correlation_label_present:'Correlation label'
  })[field] || String(field || 'Field').replaceAll('_',' ');
}

function renderJiraReconciliation(job) {
  const history = job.reconciliations || [];
  const latest = job.latest_reconciliation;
  if (!latest) return '<section class="delivery-reconciliation empty"><p>No Jira observation yet. Refresh explicitly to establish a local workflow baseline.</p><small>Explicit read only · correlated issue fields only · no polling or issue mutation</small></section>';
  const snapshot = latest.snapshot || {};
  const changes = latest.drift?.changes || [];
  const outcomeLabel = ({
    observed:'Observed',
    'not-found-or-not-visible':'Not found or not visible',
    'access-denied':'Access denied',
    'identity-mismatch':'Identity mismatch',
    error:'Read failed'
  })[latest.outcome] || latest.outcome;
  const observed = latest.outcome === 'observed'
    ? `<dl><div><dt>Status</dt><dd>${escapeHtml(snapshot.status?.name || 'Unknown')}</dd></div><div><dt>Priority</dt><dd>${escapeHtml(snapshot.priority?.name || 'None')}</dd></div><div><dt>Resolution</dt><dd>${escapeHtml(snapshot.resolution?.name || 'Unresolved')}</dd></div><div><dt>Project</dt><dd>${escapeHtml(snapshot.project_key || 'Unknown')}</dd></div><div><dt>Issue type</dt><dd>${escapeHtml(snapshot.issue_type?.name || 'Unknown')}</dd></div><div><dt>Correlation</dt><dd>${snapshot.correlation_label_present === false ? 'Label missing' : snapshot.correlation_label_present === true ? 'Label present' : 'Not established'}</dd></div></dl>${snapshot.jira_updated_at ? `<p class="delivery-jira-updated">Jira updated ${escapeHtml(assuranceTime(snapshot.jira_updated_at))}</p>` : ''}${snapshot.browse_url ? `<a href="${escapeHtml(snapshot.browse_url)}" target="_blank" rel="noopener noreferrer">Open observed issue ${escapeHtml(snapshot.issue_key)} ↗</a>` : ''}`
    : `<p class="delivery-reconciliation-error">${escapeHtml(latest.error || 'The correlated issue could not be observed.')}</p>`;
  const drift = changes.length
    ? `<div class="delivery-drift"><b>${changes.length} material change${changes.length === 1 ? '' : 's'}</b><ul>${changes.map(change => `<li><span>${escapeHtml(reconciliationFieldLabel(change.field))}</span><span>${escapeHtml(reconciliationValue(change.from))} → ${escapeHtml(reconciliationValue(change.to))}</span></li>`).join('')}</ul></div>`
    : latest.outcome === 'observed'
      ? `<p class="delivery-no-drift">${latest.drift?.baseline === 'established' ? 'Local baseline established.' : 'No material drift from the last observed baseline.'}</p>`
      : '';
  const historyMarkup = history.length > 1
    ? `<details><summary>Observation history (${history.length})</summary><ol>${history.map(item => `<li><span>${escapeHtml(({'not-found-or-not-visible':'Not found or not visible','access-denied':'Access denied','identity-mismatch':'Identity mismatch',observed:'Observed',error:'Read failed'})[item.outcome] || item.outcome)}</span><time>${escapeHtml(assuranceTime(item.observed_at))}</time><code>${escapeHtml(item.snapshot_sha256.slice(0,12))}</code></li>`).join('')}</ol></details>`
    : '';
  return `<section class="delivery-reconciliation ${escapeHtml(latest.outcome)}"><header><b>${escapeHtml(outcomeLabel)}</b><time>${escapeHtml(assuranceTime(latest.observed_at))}</time></header>${observed}${drift}<small>Explicit read only · minimal correlated issue fields · digest <code>${escapeHtml(latest.snapshot_sha256.slice(0,12))}</code> · no issue mutation</small>${historyMarkup}</section>`;
}

function hydrateAuditExport(value) {
  if (!value?.policy || state.auditExportPolicyDirty) return;
  const policy = value.policy;
  const destination = value.destination || {};
  $('#auditExportEnabled').checked = Boolean(policy.enabled);
  $('#auditIndexName').value = policy.index_name || 'signalroom_audit';
  $('#auditSourcetype').value = policy.sourcetype || 'signalroom:audit';
  $('#auditSource').value = policy.source || 'signalroom:audit';
  $('#auditHost').value = policy.host || 'signalroom';
  $('#auditBatchSize').value = policy.batch_size ?? 25;
  $('#auditMaxAttempts').value = policy.max_attempts ?? 5;
  $('#auditRetryBackoff').value = String(policy.retry_backoff_seconds ?? 30);
  $('#auditUseAck').checked = Boolean(policy.use_indexer_ack);
  $('#auditVerifyTls').checked = Boolean(policy.verify_tls);
  $('#auditCaBundle').value = policy.ca_bundle || '';
  $('#auditBackfill').checked = false;
  $('#auditHecUrl').value = '';
  $('#auditHecToken').value = '';
  $('#auditClearHecUrl').checked = false;
  $('#auditClearHecToken').checked = false;
  $('#auditHecUrl').placeholder = destination.url_configured
    ? 'Encrypted HEC origin configured · leave blank to keep'
    : 'https://hec.example.com:8088';
  $('#auditHecToken').placeholder = destination.token_configured
    ? 'Encrypted HEC token configured · leave blank to keep'
    : 'Paste a dedicated HEC token';
}

function renderAuditExport(value) {
  hydrateAuditExport(value);
  const policy = value?.policy || {};
  const destination = value?.destination || {};
  const stateValue = value?.state || {};
  const chain = value?.chain || {};
  const statusLabels = {
    disabled:'Disabled',
    idle:'Current',
    pending:'Pending',
    sending:'Sending',
    retrying:'Retry scheduled',
    failed:'Needs attention',
    'chain-invalid':'Chain invalid',
    'config-error':'Configuration required'
  };
  const status = policy.enabled ? (stateValue.status || 'pending') : 'disabled';
  const statusNode = $('#auditExportStatus');
  statusNode.textContent = statusLabels[status] || status.replaceAll('-', ' ');
  statusNode.className = `subtle-pill ${['idle','pending','sending'].includes(status) ? 'ok' : status === 'disabled' ? '' : 'warn'}`;
  const pending = Number(stateValue.pending_events || 0);
  const cursor = Number(stateValue.cursor_sequence || 0);
  const latest = Number(stateValue.latest_sequence || 0);
  $('#auditExportMetrics').innerHTML = `
    <article><span>VERIFIED CHAIN</span><b>${chain.valid ? 'Valid' : 'Blocked'}</b><small>${Number(chain.event_count || 0).toLocaleString()} local events</small></article>
    <article><span>REMOTE CURSOR</span><b>#${cursor.toLocaleString()}</b><small>Latest local #${latest.toLocaleString()}</small></article>
    <article><span>BACKLOG</span><b>${pending.toLocaleString()}</b><small>event${pending === 1 ? '' : 's'} awaiting export</small></article>
    <article><span>DELIVERY PROOF</span><b>${policy.use_indexer_ack ? 'Indexer ACK' : 'HEC accepted'}</b><small>At-least-once · stable IDs</small></article>`;
  $('#auditExportDestinationHint').textContent = destination.configured
    ? `${destination.origin} → index=${destination.index} · ${destination.transport} · ${destination.delivery_semantics}`
    : destination.origin
      ? `${destination.origin} · dedicated HEC token required`
      : 'No remote audit destination configured';
  $('#auditExportRuntimeHint').textContent = stateValue.last_error
    ? stateValue.last_error
    : policy.enabled
      ? pending
        ? `${pending.toLocaleString()} verified event${pending === 1 ? '' : 's'} queued from sequence ${cursor + 1}.`
        : `Remote cursor is current through sequence ${cursor}.`
      : 'Local chain remains authoritative while export is disabled.';
  const runButton = $('#runAuditExport');
  const lacksAdmin = Boolean(state.auth?.authenticated && !state.auth?.permissions?.can_administer);
  runButton.disabled = lacksAdmin || !policy.enabled || Boolean(value.worker?.sending);
  runButton.textContent = value.worker?.sending
    ? 'Exporting…'
    : ['failed','chain-invalid','config-error'].includes(status)
      ? 'Retry export now'
      : 'Export pending now';
  const attempts = value?.attempts || [];
  $('#auditExportAttempts').innerHTML = attempts.length ? attempts.slice(0,12).map(item => {
    const proof = item.ack_id !== null && item.ack_id !== undefined
      ? `ACK ${item.ack_id}${item.ack_confirmed ? ' confirmed' : ' unconfirmed'}`
      : 'HEC response';
    return `<article class="audit-export-attempt ${escapeHtml(item.outcome)}"><header><span>#${Number(item.first_sequence).toLocaleString()}–#${Number(item.last_sequence).toLocaleString()}</span><b>${escapeHtml(item.outcome)}</b></header><p>${Number(item.event_count).toLocaleString()} events · ${Number(item.payload_bytes).toLocaleString()} bytes · ${escapeHtml(proof)}</p>${item.error ? `<small>${escapeHtml(item.error)}</small>` : ''}<footer><time>${escapeHtml(assuranceTime(item.completed_at))}</time><span>HTTP ${item.http_status || '—'} · <code>${escapeHtml(item.payload_sha256.slice(0,12))}</code></span></footer></article>`;
  }).join('') : '<div class="empty-inline compact-empty">No remote audit export has been attempted.</div>';
}

function hydrateAuditOperations(value) {
  if (!value?.policy || state.auditOperationsPolicyDirty) return;
  const policy = value.policy;
  $('#auditRetentionDays').value = String(policy.retention_days ?? 365);
  $('#auditDeduplicationMode').value = policy.deduplication_mode || 'stable-event-id';
  $('#auditExpectedLag').value = String(policy.expected_export_lag_minutes ?? 15);
  $('#auditSourceSilence').value = String(policy.source_silence_minutes ?? 60);
  $('#auditDeniedThreshold').value = policy.denied_request_threshold ?? 5;
  $('#auditDashboardEarliest').value = policy.dashboard_earliest || '-24h';
}

function renderAuditOperationsPreview(preview) {
  const holder = $('#auditOperationsPreview');
  if (!preview) {
    holder.hidden = true;
    holder.innerHTML = '';
    return;
  }
  const files = Object.entries(preview.files || {});
  holder.hidden = false;
  holder.innerHTML = `
    <header><div><span>EXACT REVIEW PREVIEW</span><h5>${files.length} generated files · ${escapeHtml(preview.schema_version)}</h5></div><code>${escapeHtml((preview.policy_sha256 || '').slice(0,16))}</code></header>
    <div class="audit-operations-binding"><span><b>Index</b><code>${escapeHtml(preview.binding?.index || '')}</code></span><span><b>Sourcetype</b><code>${escapeHtml(preview.binding?.sourcetype || '')}</code></span><span><b>Retention</b>${Number(preview.retention?.days || 0).toLocaleString()} days</span><span><b>Authority</b>Preview and local archive only</span></div>
    <div class="audit-operations-control-list">${(preview.controls || []).map(control => `<details><summary><span>${escapeHtml(control.title)}</span><small>Disabled · ${escapeHtml(control.schedule)}</small></summary><p>${escapeHtml(control.purpose)}</p><pre>${escapeHtml(control.search)}</pre></details>`).join('')}</div>
    <details class="audit-operations-file-list"><summary>Manifest-bound file inventory</summary><ul>${files.map(([name, item]) => `<li><code>${escapeHtml(name)}</code><span>${Number(item.bytes || 0).toLocaleString()} bytes · ${escapeHtml((item.sha256 || '').slice(0,12))}</span></li>`).join('')}</ul></details>
    <ol class="audit-operations-review-steps">${(preview.review_steps || []).map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>
    <p class="audit-operations-warning">${escapeHtml(preview.retention?.warning || '')}</p>`;
}

function renderAuditOperations(value) {
  hydrateAuditOperations(value);
  const policy = value?.policy || {};
  const health = value?.health || {};
  const pack = value?.pack || {};
  const statusLabels = {
    current:'Current',
    'catching-up':'Catching up',
    breached:'Needs attention',
    'chain-invalid':'Chain invalid',
    'local-only':'Local only'
  };
  const statusNode = $('#auditOperationsStatus');
  statusNode.textContent = statusLabels[health.status] || 'Not evaluated';
  statusNode.className = `subtle-pill ${health.status === 'current' ? 'ok' : ['breached','chain-invalid'].includes(health.status) ? 'warn' : ''}`;
  $('#auditOperationsMetrics').innerHTML = `
    <article><span>SEARCHABLE RETENTION</span><b>${Number(policy.retention_days || 0).toLocaleString()} days</b><small>Time policy · size policy remains external</small></article>
    <article><span>CANONICAL VIEW</span><b>${policy.deduplication_mode === 'stable-event-id' ? 'Stable-ID dedup' : 'Preserve retries'}</b><small>Raw retry evidence is always retained</small></article>
    <article><span>LOCAL LAG SLO</span><b>${Number(policy.expected_export_lag_minutes || 0).toLocaleString()} min</b><small>Oldest pending ${Number(health.oldest_pending_minutes || 0).toLocaleString()} min</small></article>
    <article><span>DEPLOYMENT KIT</span><b>${pack.current_export ? 'Current' : 'Review needed'}</b><small>${Number(pack.file_count || 0)} files · ${Number(pack.controls?.length || 0)} disabled alerts</small></article>`;
  $('#auditOperationsHealth').textContent = health.detail || 'No audit operations status is available.';
  $('#auditOperationsHealth').className = ['breached','chain-invalid'].includes(health.status) ? 'warn' : health.status === 'current' ? 'ok' : '';
  const lacksAdmin = Boolean(state.auth?.authenticated && !state.auth?.permissions?.can_administer);
  $('#previewAuditOperations').disabled = lacksAdmin;
  $('#exportAuditOperations').disabled = lacksAdmin;
  const exports = value?.exports || [];
  $('#auditOperationsExports').innerHTML = exports.length ? exports.map(item => `
    <article class="${item.policy_sha256 === pack.policy_sha256 && item.destination_fingerprint === pack.destination_fingerprint ? 'current' : ''}">
      <div><b>${item.policy_sha256 === pack.policy_sha256 && item.destination_fingerprint === pack.destination_fingerprint ? 'Current policy kit' : 'Superseded kit'}</b><a href="/api/audit-operations/exports/${encodeURIComponent(item.filename)}" download>${escapeHtml(item.filename)}</a></div>
      <span>${escapeHtml(assuranceTime(item.created_at))}</span><code>${escapeHtml(item.archive_sha256.slice(0,12))}</code>
    </article>`).join('') : '<div class="empty-inline compact-empty">No audit operations kit has been exported.</div>';
  renderAuditOperationsPreview(state.auditOperationsPreview);
}

function renderDelivery(value) {
  const delivery = value.delivery || {}; const policy = delivery.policy || {}; const destination = delivery.destination || {};
  hydrateDeliveryPolicy(delivery);
  const ready = Boolean(policy.enabled && destination.configured);
  $('#deliveryStatus').textContent = ready ? `${deliveryAdapterName(destination.kind)} · ${policy.mode}` : policy.enabled ? 'Destination required' : 'Disabled · local only';
  $('#deliveryStatus').className = `subtle-pill ${ready ? 'ok' : policy.enabled ? 'warn' : ''}`;
  $('#deliveryDestinationHint').textContent = destination.configured
    ? `${deliveryAdapterName(destination.kind)} · ${destination.origin} · ${destination.transport} · ${destination.delivery_semantics}`
    : destination.origin
      ? `${deliveryAdapterName(destination.kind)} setup incomplete · ${destination.origin}`
      : 'No outbound destination configured';
  const jobs = delivery.jobs || [];
  $('#deliveryJobs').innerHTML = jobs.length ? jobs.slice(0,12).map(job => {
    const primaryAction = job.status === 'failed'
      ? `<button class="button ghost small" data-retry-delivery="${escapeHtml(job.id)}">${job.destination_kind === 'jira-cloud' ? 'Review and retry create' : job.destination_kind === 'splunk-soar' ? 'Retry source-ID-safe create' : 'Retry bounded batch'}</button>`
      : ['queued','retrying'].includes(job.status)
        ? `<button class="button ghost small" data-cancel-delivery="${escapeHtml(job.id)}">Cancel</button>`
        : '';
    const reconcileAction = job.destination_kind === 'jira-cloud' && job.status === 'delivered' && job.external_record
      ? `<button class="button ghost small" data-reconcile-delivery="${escapeHtml(job.id)}">Refresh Jira status</button>`
      : '';
    const action = `${primaryAction}${reconcileAction}`;
    const timing = job.status === 'delivered' ? `Delivered ${assuranceTime(job.delivered_at)}` : job.next_attempt_at ? `Next attempt ${assuranceTime(job.next_attempt_at)}` : assuranceTime(job.updated_at);
    const externalRecord = job.external_record
      ? `<div class="delivery-external-record"><a href="${escapeHtml(job.external_record.url)}" target="_blank" rel="noopener noreferrer">${job.destination_kind === 'splunk-soar' ? `Open correlated Splunk SOAR ${escapeHtml(job.external_record.key)}` : `Open correlated Jira issue ${escapeHtml(job.external_record.key)}`} ↗</a></div>`
      : '';
    const reconciliation = job.destination_kind === 'jira-cloud' && job.external_record ? renderJiraReconciliation(job) : '';
    return `<article class="delivery-job ${escapeHtml(job.status)}"><header><span>${escapeHtml(job.approval_mode.replaceAll('-', ' '))}</span><b>${escapeHtml(job.status)}</b></header><p>Package <code>${escapeHtml(job.package_id.slice(0,8))}</code> → ${escapeHtml(job.destination_label)}</p><div><span>${escapeHtml(deliveryAdapterName(job.destination_kind))}</span><span>${job.attempt_count}/${job.max_attempts} attempts</span><span>HTTP ${job.http_status || '—'}</span><span>Hash <code>${escapeHtml(job.payload_sha256.slice(0,12))}</code></span></div>${externalRecord}${reconciliation}${job.last_error ? `<small>${escapeHtml(job.last_error)}</small>` : ''}<footer><time>${escapeHtml(timing)}</time><div>${action}</div></footer></article>`;
  }).join('') : '<div class="empty-inline compact-empty">No outbound package has been approved. Preview an eligible response package to start.</div>';
  const audit = value.audit || {}; const chain = audit.chain || {};
  $('#auditChainStatus').textContent = chain.valid ? `${chain.event_count || 0} events · chain valid` : `Integrity break at event ${chain.broken_sequence || 'unknown'}`;
  $('#auditChainStatus').className = chain.valid ? 'audit-valid' : 'audit-invalid';
  $('#auditEvents').innerHTML = (audit.events || []).length ? audit.events.slice(0,12).map(item => `<article class="audit-event ${escapeHtml(item.outcome)}"><header><span>#${item.sequence} · ${escapeHtml(item.event_type)}</span><b>${escapeHtml(item.outcome)}</b></header><p>${escapeHtml(item.summary || item.action)}</p><footer><time>${escapeHtml(assuranceTime(item.created_at))}</time><code>${escapeHtml(item.event_hash.slice(0,12))}</code></footer></article>`).join('') : '<div class="empty-inline compact-empty">Audit events appear when control-plane decisions are made.</div>';
  renderAuditExport(value.audit_export || {});
  renderAuditOperations(value.audit_operations || {});
}

async function saveDeliveryPolicy(event) {
  event.preventDefault();
  const signalKinds = $$('.delivery-categories input:checked').map(input => input.value);
  if (!signalKinds.length) { toast('Select at least one eligible signal category'); return; }
  const isJira = $('#deliveryKind').value === 'jira-cloud';
  const isPublicAdapter = isJira || $('#deliveryKind').value === 'slack-incoming-webhook';
  const payload = {
    enabled:$('#deliveryEnabled').checked,
    mode:$('#deliveryMode').value,
    destination_kind:$('#deliveryKind').value,
    minimum_severity:$('#deliverySeverity').value,
    signal_kinds:signalKinds,
    redaction_level:$('#deliveryRedaction').value,
    destination_label:$('#deliveryLabel').value.trim() || 'Primary webhook',
    verify_tls:$('#deliveryVerifyTls').checked,
    ca_bundle:isPublicAdapter ? null : ($('#deliveryCaBundle').value.trim() || null),
    max_attempts:Number($('#deliveryAttempts').value),
    retry_backoff_seconds:Number($('#deliveryBackoff').value),
    webhook_url:$('#deliveryWebhookUrl').value.trim() || null,
    authorization_header:$('#deliveryAuthorization').value.trim() || null,
    clear_webhook_url:$('#deliveryClearWebhookUrl').checked,
    clear_authorization_header:$('#deliveryClearAuthorization').checked,
    jira_project_key:$('#deliveryJiraProject').value.trim(),
    jira_issue_type:$('#deliveryJiraIssueType').value.trim() || 'Task',
    jira_summary_prefix:$('#deliveryJiraPrefix').value.trim(),
    jira_labels:$('#deliveryJiraLabels').value.split(',').map(item => item.trim()).filter(Boolean),
    jira_priority_map:{
      critical:$('#deliveryJiraCriticalPriority').value.trim(),
      high:$('#deliveryJiraHighPriority').value.trim(),
      medium:$('#deliveryJiraMediumPriority').value.trim(),
      low:$('#deliveryJiraLowPriority').value.trim()
    },
    jira_email:$('#deliveryJiraEmail').value.trim() || null,
    jira_api_token:$('#deliveryJiraApiToken').value.trim() || null,
    clear_jira_email:$('#deliveryClearJiraEmail').checked,
    clear_jira_api_token:$('#deliveryClearJiraApiToken').checked,
    soar_label:$('#deliverySoarLabel').value.trim() || 'events',
    soar_container_type:$('#deliverySoarContainerType').value,
    soar_status:$('#deliverySoarStatus').value.trim() || 'new',
    soar_name_prefix:$('#deliverySoarPrefix').value.trim(),
    soar_sensitivity:$('#deliverySoarSensitivity').value,
    soar_tags:$('#deliverySoarTags').value.split(',').map(item => item.trim()).filter(Boolean),
    soar_severity_map:{
      critical:$('#deliverySoarCriticalSeverity').value.trim(),
      high:$('#deliverySoarHighSeverity').value.trim(),
      medium:$('#deliverySoarMediumSeverity').value.trim(),
      low:$('#deliverySoarLowSeverity').value.trim()
    },
    soar_tenant_id:$('#deliverySoarTenantId').value.trim(),
    soar_auth_token:$('#deliverySoarAuthToken').value.trim() || null,
    clear_soar_auth_token:$('#deliveryClearSoarAuthToken').checked
  };
  try {
    await api('/api/delivery/policy', {method:'PUT',body:JSON.stringify(payload)});
    state.deliveryPolicyDirty = false; await loadAssurance(); toast('Outbound delivery policy saved');
  } catch (error) { toast(error.message); }
}

async function testDeliveryDestination() {
  const isSoar = $('#deliveryKind').value === 'splunk-soar';
  const result = $(isSoar ? '#deliverySoarTestResult' : '#deliveryTestResult');
  if (state.deliveryPolicyDirty) {
    result.className = 'error';
    result.textContent = 'Save the current adapter settings before running the read-only test.';
    return;
  }
  const button = $(isSoar ? '#testSoarDeliveryDestination' : '#testDeliveryDestination');
  button.disabled = true;
  result.className = '';
  result.textContent = isSoar
    ? 'Reading Splunk SOAR container options… no container will be created.'
    : 'Reading Jira create metadata… no issue will be created.';
  try {
    const value = await api('/api/delivery/test', {method:'POST'});
    result.className = value.ok ? 'ok' : 'error';
    if (isSoar) {
      const missing = Object.entries(value.availability || {}).filter(([, available]) => !available).map(([name]) => name);
      result.textContent = value.ok
        ? `Verified label ${value.configured.label}, status ${value.configured.status}, ${value.configured.sensitivity} sensitivity, and the severity mapping. Test authority: read container options only.`
        : `Splunk SOAR is reachable, but the configured ${missing.join(', ') || 'container mapping'} is unavailable. No container was created.`;
    } else {
      result.textContent = value.ok
        ? `Verified ${value.project_key} · ${value.issue_type}. Test authority: read create metadata only.`
        : `${value.project_key} is reachable, but ${value.issue_type} is unavailable. Available: ${(value.available_issue_types || []).join(', ') || 'none returned'}.`;
    }
  } catch (error) {
    result.className = 'error';
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function saveAuditExportPolicy(event) {
  event.preventDefault();
  const payload = {
    enabled:$('#auditExportEnabled').checked,
    index_name:$('#auditIndexName').value.trim(),
    sourcetype:$('#auditSourcetype').value.trim(),
    source:$('#auditSource').value.trim(),
    host:$('#auditHost').value.trim(),
    verify_tls:$('#auditVerifyTls').checked,
    ca_bundle:$('#auditCaBundle').value.trim() || null,
    use_indexer_ack:$('#auditUseAck').checked,
    batch_size:Number($('#auditBatchSize').value),
    max_attempts:Number($('#auditMaxAttempts').value),
    retry_backoff_seconds:Number($('#auditRetryBackoff').value),
    backfill_existing:$('#auditBackfill').checked,
    hec_url:$('#auditHecUrl').value.trim() || null,
    hec_token:$('#auditHecToken').value.trim() || null,
    clear_hec_url:$('#auditClearHecUrl').checked,
    clear_hec_token:$('#auditClearHecToken').checked
  };
  try {
    await api('/api/audit-export/policy', {method:'PUT',body:JSON.stringify(payload)});
    state.auditExportPolicyDirty = false;
    await loadAssurance();
    toast(payload.enabled ? 'Dedicated Splunk audit export enabled' : 'Audit export policy saved');
  } catch (error) { toast(error.message); }
}

async function runAuditExportNow() {
  const button = $('#runAuditExport');
  button.disabled = true;
  button.textContent = 'Exporting…';
  try {
    const result = await api('/api/audit-export/run', {method:'POST'});
    state.assurance.audit_export = result;
    renderAuditExport(result);
    toast(result.ok ? 'Verified audit batch exported' : 'Audit export needs attention');
  } catch (error) {
    toast(error.message);
    await loadAssurance();
  }
}

async function saveAuditOperationsPolicy(event) {
  event.preventDefault();
  const payload = {
    retention_days:Number($('#auditRetentionDays').value),
    deduplication_mode:$('#auditDeduplicationMode').value,
    expected_export_lag_minutes:Number($('#auditExpectedLag').value),
    source_silence_minutes:Number($('#auditSourceSilence').value),
    denied_request_threshold:Number($('#auditDeniedThreshold').value),
    dashboard_earliest:$('#auditDashboardEarliest').value
  };
  try {
    const result = await api('/api/audit-operations/policy', {method:'PUT',body:JSON.stringify(payload)});
    state.auditOperationsPolicyDirty = false;
    state.auditOperationsPreview = null;
    if (state.assurance) state.assurance.audit_operations = result;
    renderAuditOperations(result);
    toast('Audit destination expectations saved');
  } catch (error) { toast(error.message); }
}

async function previewAuditOperations() {
  const button = $('#previewAuditOperations');
  button.disabled = true;
  button.textContent = 'Building preview…';
  try {
    state.auditOperationsPreview = await api('/api/audit-operations/preview', {method:'POST'});
    renderAuditOperationsPreview(state.auditOperationsPreview);
    $('#auditOperationsPreview').scrollIntoView({behavior:'smooth',block:'nearest'});
  } catch (error) { toast(error.message); }
  finally {
    button.disabled = false;
    button.textContent = 'Preview controls';
  }
}

async function exportAuditOperations() {
  const button = $('#exportAuditOperations');
  button.disabled = true;
  button.textContent = 'Building kit…';
  try {
    const result = await api('/api/audit-operations/export', {method:'POST'});
    const link = document.createElement('a');
    link.href = result.url;
    link.download = result.filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    await loadAssurance();
    toast('Review-only Splunk operations kit exported');
  } catch (error) { toast(error.message); }
  finally {
    button.disabled = false;
    button.textContent = 'Export review kit';
  }
}

async function previewAssuranceDelivery(packageId) {
  try {
    const preview = await api(`/api/assurance/packages/${encodeURIComponent(packageId)}/delivery/preview`, {method:'POST'});
    state.deliveryPreview = preview;
    const authority = preview.authority?.external_create
      ? preview.destination.kind === 'splunk-soar'
        ? 'Create one container · no artifacts, automation, update, action, playbook, delete, SPL execution, or validation approval'
        : 'Create one external issue · no update, transition, comment, delete, SPL execution, or validation approval'
      : 'Delivery only · no SPL execution or validation approval';
    $('#deliveryPreviewContract').innerHTML = `<span><b>${escapeHtml(preview.destination.label)}</b>${escapeHtml(deliveryAdapterName(preview.destination.kind))} · ${escapeHtml(preview.destination.origin)}</span><span><b>${preview.payload_bytes} bytes</b>${escapeHtml(preview.redaction_level)} redaction</span><span><b>SHA-256</b><code>${escapeHtml(preview.payload_sha256)}</code></span><span><b>Authority</b>${escapeHtml(authority)}</span><span><b>Delivery behavior</b>${escapeHtml(preview.destination.delivery_semantics)}</span>`;
    $('#deliveryRedactions').innerHTML = preview.redactions.map(item => `<li>${escapeHtml(item)}</li>`).join('');
    $('#deliveryWarnings').innerHTML = (preview.warnings || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
    $('#deliveryPreviewPayload').textContent = JSON.stringify(preview.payload, null, 2);
    $('#approveDelivery').textContent = preview.approval_required ? 'Approve exact payload and queue' : 'Queue exact payload under automatic policy';
    $('#deliveryPreviewModal').hidden = false;
  } catch (error) { toast(error.message); }
}

async function approveDeliveryPreview() {
  const preview = state.deliveryPreview; if (!preview) return;
  const button = $('#approveDelivery'); button.disabled = true; button.textContent = 'Queueing…';
  try {
    await api(`/api/assurance/packages/${encodeURIComponent(preview.package_id)}/delivery/approve`, {method:'POST',body:JSON.stringify({expected_payload_sha256:preview.payload_sha256})});
    $('#deliveryPreviewModal').hidden = true; state.deliveryPreview = null; await loadAssurance(); toast('Exact redacted payload approved and queued');
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
}

async function retryDelivery(jobId) {
  try { await api(`/api/delivery/jobs/${encodeURIComponent(jobId)}/retry`, {method:'POST'}); await loadAssurance(); toast('Bounded delivery retry queued'); }
  catch (error) { toast(error.message); }
}

async function cancelDelivery(jobId) {
  try { await api(`/api/delivery/jobs/${encodeURIComponent(jobId)}/cancel`, {method:'POST'}); await loadAssurance(); toast('Outbound delivery cancelled'); }
  catch (error) { toast(error.message); }
}

async function reconcileDelivery(button) {
  const jobId = button.dataset.reconcileDelivery;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Reading Jira…';
  try {
    const result = await api(`/api/delivery/jobs/${encodeURIComponent(jobId)}/reconcile`, {method:'POST'});
    await loadAssurance();
    if (result.outcome === 'observed') {
      const count = result.drift?.changes?.length || 0;
      toast(count ? `Jira observation saved · ${count} material change${count === 1 ? '' : 's'}` : 'Jira observation saved · no material drift');
    } else if (result.outcome === 'not-found-or-not-visible') {
      toast('Jira returned 404 · the issue may be missing or no longer visible');
    } else {
      toast(result.error || `Jira observation saved · ${result.outcome}`);
    }
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function hydrateAssurancePolicy(policy) {
  if (!policy || state.assurancePolicyDirty) return;
  $('#assuranceEnabled').checked = Boolean(policy.enabled);
  $('#assuranceDepth').value = policy.discovery_depth;
  $('#assuranceInterval').value = String(policy.interval_minutes);
  $('#assuranceCallBudget').value = policy.max_splunk_calls_per_run;
  $('#assuranceDailyRuns').value = policy.max_runs_per_day;
  $('#assuranceNotifyDrift').checked = Boolean(policy.notify_on_drift);
  $('#assuranceNotifyFindings').checked = Boolean(policy.notify_on_high_findings);
  updateAssuranceBudgetHelp();
}

function updateAssuranceBudgetHelp() {
  const depth = $('#assuranceDepth').value; const required = state.assurance?.required_calls?.[depth] || ({quick:4,standard:9,deep:12})[depth];
  $('#assuranceBudgetHelp').textContent = `Hard limit · ${required} calls required for this depth`;
  $('#assuranceCallBudget').min = required;
}

function renderAssurance() {
  const value = state.assurance; if (!value) return;
  const policy = value.policy || {}; const usage = value.usage_today || {}; const active = value.active_run;
  hydrateAssurancePolicy(policy);
  $('#assuranceWorker').textContent = value.worker?.online ? 'Worker online · concurrency 1' : 'Worker offline';
  $('#assuranceWorker').className = `subtle-pill ${value.worker?.online ? 'ok' : 'warn'}`;
  $('#assuranceScheduleStatus').textContent = policy.enabled ? `Next scheduled run · ${assuranceTime(policy.next_run_at)}` : 'Scheduling is off · manual runs remain available';
  $('#assuranceUsage').innerHTML = `<span><b>${usage.runs || 0}/${policy.max_runs_per_day || 0}</b> runs today</span><span><b>${usage.splunk_calls || 0}</b> Splunk calls today</span><span><b>${policy.max_splunk_calls_per_run || 0}</b> call ceiling</span><span><b>${escapeHtml(value.worker?.restart_recovery || 'unknown')}</b> restart policy</span>`;
  renderAssurancePackages(value);
  renderDelivery(value);
  const panel = $('#assuranceProgress'); panel.hidden = !active;
  if (active) {
    panel.querySelector('.operation-label').textContent = active.label || 'Working';
    panel.querySelector('.operation-detail').textContent = active.detail || '';
    panel.querySelector('.operation-elapsed').textContent = `${active.progress || 0}%`;
    panel.querySelector('.operation-progress i').style.width = `${active.progress || 0}%`;
    panel.querySelector('.operation-progress').setAttribute('aria-valuenow', active.progress || 0);
    panel.querySelector('.operation-metrics').innerHTML = Object.entries({...(active.metrics || {}), splunk_calls:active.calls_used, call_budget:active.call_budget}).slice(0,5).map(([key,item]) => formatMetric(key,item)).join('');
    const events = value.active_events || [];
    panel.querySelector('.operation-steps').innerHTML = events.map((event,index) => `<li class="${event.status === 'error' ? 'error' : index === events.length - 1 && active.status === 'running' ? 'running' : 'complete'}"><i></i><div><b>${escapeHtml(event.label)}</b><span>${escapeHtml(event.detail)}</span></div></li>`).join('');
    $('#assuranceRunContract').textContent = `${active.trigger} · ${active.depth} · ${active.calls_used}/${active.call_budget} calls${active.recovery_count ? ` · recovered ${active.recovery_count}×` : ''}`;
    $('#cancelAssuranceRun').disabled = Boolean(active.cancel_requested);
    $('#cancelAssuranceRun').textContent = active.cancel_requested ? 'Stopping…' : 'Cancel run';
  }
  const notices = value.notifications || [];
  $('#assuranceNotifications').innerHTML = notices.length ? notices.map(item => `<article class="assurance-notice ${escapeHtml(item.severity)} ${item.acknowledged ? 'acknowledged' : ''}"><header><span>${escapeHtml(item.category)}</span><b>${escapeHtml(item.severity)}</b></header><h5>${escapeHtml(item.title)}</h5><p>${escapeHtml(item.detail)}</p><footer><time>${escapeHtml(assuranceTime(item.created_at))}</time>${item.acknowledged ? '<span>Acknowledged</span>' : `<button data-ack-assurance="${escapeHtml(item.id)}">Acknowledge</button>`}</footer></article>`).join('') : '<div class="empty-inline compact-empty">No drift or control notifications require attention.</div>';
  const runs = value.runs || [];
  $('#assuranceRuns').innerHTML = runs.length ? runs.slice(0,10).map(run => `<article class="assurance-run ${escapeHtml(run.status)}"><header><span>${escapeHtml(run.trigger)} · ${escapeHtml(run.depth)}</span><b>${escapeHtml(run.status.replaceAll('-', ' '))}</b></header><p>${escapeHtml(run.summary?.headline || run.detail || run.error || 'Waiting to start.')}</p><footer><time>${escapeHtml(assuranceTime(run.completed_at || run.created_at))}</time><span>${run.calls_used}/${run.call_budget} calls${run.recovery_count ? ` · ${run.recovery_count} recovery` : ''}</span></footer></article>`).join('') : '<div class="empty-inline compact-empty">No continuous assurance runs have been queued.</div>';
  $('#runAssuranceNow').disabled = Boolean(active) || Number(usage.runs || 0) >= Number(policy.max_runs_per_day || 0);
}

async function loadAssurance() {
  try { state.assurance = await api('/api/assurance'); renderAssurance(); }
  catch (error) { $('#assuranceWorker').textContent = 'Worker unavailable'; }
}

async function saveAssurancePolicy(event) {
  event.preventDefault();
  const payload = {
    enabled:$('#assuranceEnabled').checked,
    interval_minutes:Number($('#assuranceInterval').value),
    discovery_depth:$('#assuranceDepth').value,
    max_splunk_calls_per_run:Number($('#assuranceCallBudget').value),
    max_runs_per_day:Number($('#assuranceDailyRuns').value),
    notify_on_drift:$('#assuranceNotifyDrift').checked,
    notify_on_high_findings:$('#assuranceNotifyFindings').checked
  };
  try { state.assurance = await api('/api/assurance/policy', {method:'PUT',body:JSON.stringify(payload)}); state.assurancePolicyDirty = false; renderAssurance(); toast('Continuous assurance policy saved'); }
  catch (error) { toast(error.message); }
}

async function runAssuranceNow() {
  const button = $('#runAssuranceNow'); button.disabled = true;
  try { await api('/api/assurance/runs', {method:'POST',body:JSON.stringify({depth:null})}); await loadAssurance(); toast('Continuous assurance queued'); }
  catch (error) { toast(error.message); button.disabled = false; }
}

async function cancelAssuranceRun() {
  const run = state.assurance?.active_run; if (!run) return;
  try { await api(`/api/assurance/runs/${encodeURIComponent(run.id)}/cancel`, {method:'POST'}); await loadAssurance(); toast('Assurance cancellation requested'); }
  catch (error) { toast(error.message); }
}

async function acknowledgeAssurance(notificationId) {
  try { await api(`/api/assurance/notifications/${encodeURIComponent(notificationId)}/acknowledge`, {method:'POST'}); await loadAssurance(); }
  catch (error) { toast(error.message); }
}

function renderDiscoveryResult(result) {
  if (!result?.run_id || !result.overview || !result.security_posture) return;
  state.lastDiscovery = result;
  const metrics = $('#discoveryMetrics').children;
  metrics[0].querySelector('strong').textContent = result.overview.indexes;
  metrics[1].querySelector('strong').textContent = result.overview.sourcetypes;
  metrics[2].querySelector('strong').textContent = result.overview.hosts;
  metrics[3].querySelector('strong').textContent = `${result.coverage.score}%`;
  metrics[0].querySelector('small').textContent = 'Available indexes inventoried';
  metrics[1].querySelector('small').textContent = 'Sourcetypes observed by discovery';
  metrics[2].querySelector('small').textContent = 'Hosts represented in metadata';
  renderSecurityPosture(result);
  $('#findingLedger').className = '';
  $('#findingLedger').innerHTML = result.findings.length ? result.findings.map((finding, index) => `<div class="finding"><span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span><div><b>${escapeHtml(finding.title)}</b><p>${escapeHtml(finding.evidence)}</p></div><div><p>${escapeHtml(finding.next_step)}</p><div class="finding-actions"><button data-discovery-finding="${index}">Investigate →</button><button data-discovery-case="${index}">Add to case</button></div></div></div>`).join('') : '<div class="empty-inline compact-empty">No heuristic findings were raised. Review coverage and changes below.</div>';
  const inventoryChanges = Object.values(result.changes?.inventory || {}).reduce((total, item) => total + (item.added?.length || 0) + (item.removed?.length || 0), 0);
  const failedCalls = result.collection_status?.failed_calls || 0;
  const modelRoles = result.model_analysis?.models_used || 0;
  const reusedRoles = result.model_analysis?.roles_reused || 0;
  const provenance = result.provenance || {};
  $('#discoveryStatus').textContent = `${result.findings.length} findings · ${inventoryChanges} changes${modelRoles ? ` · ${modelRoles} local roles` : ''}${reusedRoles ? ` · ${reusedRoles} reused` : ''}${failedCalls ? ` · ${failedCalls} gaps` : ''} · ${provenance.tenant_scope_id || activeScope().tenant_scope_id}`;
  if (['quick','standard','deep'].includes(result.depth)) $('#discoveryDepth').value = result.depth;
  renderValidationCandidates(result);
  renderDiscoveryFollowup(result);
}

async function loadLatestDiscovery() {
  const result = await api(scopedUrl('/api/discovery/latest'));
  if (result?.run_id) renderDiscoveryResult(result);
}

function validationContract(task) {
  return `${task.earliest_time} → ${task.latest_time} · maximum ${Number(task.row_limit).toLocaleString()} rows`;
}

function validationStatusLabel(status) {
  return ({ draft:'Draft · not approved', approved:'Approved · ready to run', running:'Running read-only check', complete:'Evidence preserved', error:'Failed · review required', expired:'Expired · no longer executable' })[status] || status;
}

function renderValidationCandidates(result = state.lastDiscovery) {
  const container = $('#validationCandidates'); if (!container) return;
  const candidates = result?.validation_candidates || [];
  if (!candidates.length) {
    container.innerHTML = '<div class="empty-inline compact-empty">This discovery did not generate validation proposals.</div>';
    return;
  }
  container.innerHTML = candidates.map(candidate => {
    const existing = state.validations.find(task => task.source_run_id === candidate.source_run_id && task.source_finding_ref === candidate.source_finding_ref);
    return `<article class="validation-candidate">
      <header><div><span>${escapeHtml(candidate.source_finding_ref || 'DISCOVERY')}</span><h4>${escapeHtml(candidate.title)}</h4></div>${existing ? `<b class="validation-status ${escapeHtml(existing.status)}">${escapeHtml(existing.status)}</b>` : '<b class="validation-status proposed">Proposed</b>'}</header>
      <p>${escapeHtml(candidate.rationale)}</p>
      <pre><code>${escapeHtml(candidate.spl)}</code></pre>
      <footer><span>${escapeHtml(validationContract(candidate))}</span><button class="button ghost small" data-queue-validation="${escapeHtml(candidate.id)}" ${existing ? 'disabled' : ''}>${existing ? 'Already queued' : 'Queue editable draft'}</button></footer>
    </article>`;
  }).join('');
}

function renderValidations() {
  const container = $('#validationQueue'); if (!container) return;
  $('#validationCount').textContent = `${state.validations.length} task${state.validations.length === 1 ? '' : 's'}`;
  renderValidationCandidates();
  if (!state.validations.length) {
    container.innerHTML = '<div class="empty-inline compact-empty">No validations queued yet. Queue a discovery proposal to create a reviewable draft.</div>';
    return;
  }
  container.innerHTML = state.validations.map(task => {
    const refs = (task.evidence_refs || []).map(ref => `<code>${escapeHtml(ref)}</code>`).join('');
    const preview = task.status === 'complete'
      ? `<div class="validation-result-summary"><b>${Number(task.result_count).toLocaleString()}</b><span>rows returned and preserved</span></div>`
      : task.error ? `<p class="validation-error">${escapeHtml(task.error)}</p>` : '';
    const actions = [];
    if (['draft','error'].includes(task.status)) {
      actions.push(`<button class="button ghost small" data-edit-validation="${escapeHtml(task.id)}">Edit contract</button>`);
      actions.push(`<button class="button primary small" data-approve-validation="${escapeHtml(task.id)}">Approve exact query</button>`);
    }
    if (task.status === 'approved') actions.push(`<button class="button primary small" data-run-validation="${escapeHtml(task.id)}">Run approved validation</button>`);
    if (task.status === 'complete') {
      const detection = state.detections.find(item => item.source_validation_id === task.id);
      const runtimeDetectionId = task.source_run_id?.startsWith('detection-runtime:')
        ? task.source_run_id.slice('detection-runtime:'.length)
        : '';
      actions.push(`<button class="button primary small" data-inspect-validation="${escapeHtml(task.id)}">Inspect preserved result</button>`);
      actions.push(runtimeDetectionId
        ? `<button class="button ghost small" data-open-detection="${escapeHtml(runtimeDetectionId)}">Interpret runtime evidence</button>`
        : detection
        ? `<button class="button ghost small" data-open-detection="${escapeHtml(detection.id)}">Open detection v${Number(detection.current_version)}</button>`
        : `<button class="button ghost small" data-create-detection="${escapeHtml(task.id)}">Create detection draft</button>`);
    }
    if (task.status !== 'running') actions.push(`<button class="button ghost small validation-delete" data-delete-validation="${escapeHtml(task.id)}">Delete</button>`);
    const assuranceMeta = task.assurance_package_id ? `<span>Assurance package <code>${escapeHtml(task.assurance_package_id.slice(0, 8))}</code></span><span>${escapeHtml(task.approval_scope.replaceAll('-', ' '))}</span>${task.expires_at ? `<span>Expires ${escapeHtml(assuranceTime(task.expires_at))}</span>` : ''}` : '';
    return `<article class="validation-task ${escapeHtml(task.status)}" data-validation-id="${escapeHtml(task.id)}">
      <header><div><span>${escapeHtml(task.source_finding_ref || 'ANALYST')}</span><h4>${escapeHtml(task.title)}</h4></div><b class="validation-status ${escapeHtml(task.status)}">${escapeHtml(validationStatusLabel(task.status))}</b></header>
      <p>${escapeHtml(task.rationale)}</p>
      <details><summary>Review exact SPL contract</summary><pre><code>${escapeHtml(task.spl)}</code></pre></details>
      <div class="validation-contract"><span>${escapeHtml(validationContract(task))}</span><span>Fingerprint <code>${escapeHtml(task.query_fingerprint.slice(0, 12))}</code></span><span>${refs || 'No evidence reference'}</span>${assuranceMeta}</div>
      ${preview}<footer>${actions.join('')}</footer>
    </article>`;
  }).join('');
}

async function loadValidations() {
  try {
    state.validations = await api('/api/validations');
    renderValidations();
  } catch (error) { toast(`Validation queue: ${error.message}`); }
}

function openValidationEditor(task) {
  state.editingValidationId = task.id;
  $('#validationTitle').value = task.title;
  $('#validationRationale').value = task.rationale;
  $('#validationSpl').value = task.spl;
  $('#validationEarliest').value = task.earliest_time;
  $('#validationLatest').value = task.latest_time;
  $('#validationRowLimit').value = task.row_limit;
  $('#validationEvidenceRefs').value = (task.evidence_refs || []).join(', ') || 'None';
  $('#validationModal').hidden = false;
  analyzeValidationContract();
  setTimeout(() => $('#validationTitle').focus(), 50);
}

function queryIntelligencePayload(task = null) {
  return {
    spl: task?.spl ?? $('#validationSpl').value,
    earliest_time: task?.earliest_time ?? $('#validationEarliest').value,
    latest_time: task?.latest_time ?? $('#validationLatest').value,
    row_limit: Number(task?.row_limit ?? $('#validationRowLimit').value),
    exclude_task_id: task?.id || state.editingValidationId || ''
  };
}

function renderQueryIntelligence(value) {
  state.queryIntelligence = value;
  const panel = $('#queryIntelligence'); if (!panel) return;
  panel.className = `query-intelligence ${escapeHtml(value.risk)}`;
  panel.querySelector('header span').textContent = `${value.risk.toUpperCase()} · score ${value.score}/100`;
  const drivers = (value.cost_drivers || []).map(item => `<li>${escapeHtml(item.label)}</li>`).join('');
  const controls = (value.positive_controls || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const reuse = value.reusable_result ? `<div class="query-reuse"><b>Preserved result available</b><span>${escapeHtml(value.reusable_result.title)} · ${new Date(value.reusable_result.completed_at).toLocaleString()}</span></div>` : '';
  const workload = value.workload || {};
  const workloadStatus = workload.decision ? `<div class="query-workload ${escapeHtml(workload.decision)}"><b>${escapeHtml(workload.mode === 'enforce' ? 'Enforced workload preflight' : 'Audit workload preflight')} · ${Number(workload.estimated_cost_units || value.estimated_cost_units || 0)} relative units</b><span>${escapeHtml((workload.reasons || []).join(' · ') || `${Number(workload.daily_remaining_units || 0).toLocaleString()} of ${Number(workload.daily_budget_units || 0).toLocaleString()} UTC-day units remain`)}</span><small>${escapeHtml(workload.cost_model || value.cost_model || '')}</small></div>` : '';
  const staged = value.staged_contract || {};
  panel.innerHTML = `<header><b>Execution intelligence</b><span>${escapeHtml(value.risk.toUpperCase())} · score ${value.score}/100</span></header><p>${escapeHtml(value.execution_recommendation)}</p>${workloadStatus}${reuse}<div class="query-intelligence-grid"><div><b>Cost and risk drivers</b><ul>${drivers || '<li>No material cost driver detected</li>'}</ul></div><div><b>Bounding controls</b><ul>${controls || '<li>Add an index, time, or result boundary</li>'}</ul></div></div>${staged.spl && staged.spl !== $('#validationSpl').value ? `<details><summary>Safer staged SPL</summary><pre><code>${escapeHtml(staged.spl)}</code></pre></details>` : ''}`;
}

async function analyzeValidationContract(task = null) {
  const panel = $('#queryIntelligence'); if (!panel) return null;
  panel.querySelector('header span').textContent = 'Analyzing contract…';
  try {
    const value = await api('/api/query-intelligence', { method:'POST', body:JSON.stringify(queryIntelligencePayload(task)) });
    renderQueryIntelligence(value); return value;
  } catch (error) {
    panel.className = 'query-intelligence blocked';
    panel.querySelector('header span').textContent = 'Unable to analyze'; panel.querySelector('p').textContent = error.message;
    return null;
  }
}

async function queueValidation(candidateId) {
  const candidate = (state.lastDiscovery?.validation_candidates || []).find(item => item.id === candidateId);
  if (!candidate) return;
  try {
    const created = await api('/api/validations', { method:'POST', body:JSON.stringify(candidate) });
    state.validations.unshift(created); renderValidations(); openValidationEditor(created);
    toast('Draft queued; review the exact contract before approval');
  } catch (error) { toast(error.message); }
}

async function approveValidation(taskId) {
  const task = state.validations.find(item => item.id === taskId); if (!task) return;
  const intelligence = await analyzeValidationContract(task);
  if (!intelligence || intelligence.risk === 'blocked' || intelligence.workload?.decision === 'block') { toast(intelligence?.blocked_reason || intelligence?.workload?.reasons?.join(' · ') || 'Query approval is blocked'); return; }
  const reuse = intelligence.reusable_result ? `\n\nA preserved matching result exists from ${new Date(intelligence.reusable_result.completed_at).toLocaleString()}. Approve only if fresher evidence is required.` : '';
  const workload = intelligence.workload ? `\nWorkload: ${intelligence.workload.mode.toUpperCase()} · ${intelligence.workload.decision.replaceAll('-', ' ')} · ${intelligence.workload.estimated_cost_units} relative units` : '';
  if (!confirm(`Approve this exact read-only SPL contract?\n\nRisk: ${intelligence.risk.toUpperCase()} (${intelligence.score}/100)${workload}\n${intelligence.execution_recommendation}${reuse}\n\n${task.spl}\n\nWindow: ${task.earliest_time} to ${task.latest_time}\nMaximum rows: ${task.row_limit}`)) return;
  try {
    const approved = await api(`/api/validations/${encodeURIComponent(taskId)}/approve`, { method:'POST', body:'{}' });
    state.validations = state.validations.map(item => item.id === taskId ? approved : item); renderValidations();
    toast('Validation approved; it has not run yet');
  } catch (error) { toast(error.message); }
}

function beginValidationProgress(task) {
  const card = $('#validationProgress'); card.hidden = false;
  card.querySelector('.operation-label').textContent = `Running · ${task.title}`;
  card.querySelector('.operation-detail').textContent = 'SignalRoom is rechecking the approved read-only contract.';
  card.querySelector('.operation-elapsed').textContent = '0s';
  card.querySelector('.operation-progress i').style.width = '0%';
  card.querySelector('.operation-progress').setAttribute('aria-valuenow', '0');
  card.querySelector('.operation-metrics').innerHTML = '';
  card.querySelector('.operation-steps').innerHTML = '';
  card.scrollIntoView({ behavior:'smooth', block:'center' });
}

async function runValidation(taskId) {
  const task = state.validations.find(item => item.id === taskId); if (!task || task.status !== 'approved') return;
  state.validations = state.validations.map(item => item.id === taskId ? { ...item, status:'running' } : item);
  renderValidations(); beginValidationProgress(task);
  try {
    const result = await streamApi(`/api/validations/${encodeURIComponent(taskId)}/run/stream`, {}, event => updateOperation($('#validationProgress'), event));
    state.validations = state.validations.map(item => item.id === taskId ? result : item);
    await loadArtifacts(); renderValidations(); openValidationResult(result);
    toast('Validation complete; result preserved as evidence');
  } catch (error) {
    await loadValidations(); toast(error.message);
  }
}

function openValidationResult(task) {
  const rows = Array.isArray(task.result_preview) ? task.result_preview : [];
  const artifact = state.artifacts.find(item => item.id === task.artifact_id);
  const actions = [
    { label:'Continue investigation', kind:'prompt', mode:'triage', prompt:`Continue the investigation using the preserved validation titled "${task.title}" (${task.source_finding_ref || task.id}). Distinguish what the result observed from what it does not prove, then recommend the next bounded check.` }
  ];
  if (artifact) actions.push({ label:'Open evidence artifact', kind:'artifact', target:artifact.id });
  const detection = state.detections.find(item => item.source_validation_id === task.id);
  const runtimeDetectionId = task.source_run_id?.startsWith('detection-runtime:')
    ? task.source_run_id.slice('detection-runtime:'.length)
    : '';
  if (detection) actions.push({ label:`Open detection v${detection.current_version}`, kind:'detection', target:detection.id });
  else if (!runtimeDetectionId) actions.push({ label:'Create detection draft', kind:'detection-create', target:task.id });
  if (runtimeDetectionId) actions.unshift({ label:'Interpret deployment runtime result', kind:'detection', target:runtimeDetectionId });
  actions.push({ label:'Add result to case', kind:'case-item', item:{ kind:'evidence', title:task.title, content:`Approved SPL:\n${task.spl}\n\nWindow: ${task.earliest_time} to ${task.latest_time}\nRows returned: ${task.result_count}\nArtifact: ${task.artifact_id}`, source:'SignalRoom validation queue', confidence:'high', status:'observed', metadata:{ validation_id:task.id, artifact_id:task.artifact_id, query_fingerprint:task.query_fingerprint, evidence_refs:task.evidence_refs } } });
  showDetail({
    eyebrow:'OBSERVED · APPROVED VALIDATION', title:task.title,
    summary:`<div class="validation-detail-summary"><strong>${Number(task.result_count).toLocaleString()}</strong><span>rows returned by the approved read-only check and preserved locally.</span></div>`,
    content:`<h3>Result preview</h3>${rows.length ? `<pre><code>${escapeHtml(JSON.stringify(rows, null, 2))}</code></pre>` : '<p>The search returned no rows. A zero-result observation is still preserved with its exact contract.</p>'}<h3>Approved SPL</h3><pre><code>${escapeHtml(task.spl)}</code></pre>`,
    provenance:`<h3>Execution contract</h3><dl><div><dt>Time window</dt><dd>${escapeHtml(task.earliest_time)} → ${escapeHtml(task.latest_time)}</dd></div><div><dt>Row cap</dt><dd>${Number(task.row_limit).toLocaleString()}</dd></div><div><dt>Fingerprint</dt><dd><code>${escapeHtml(task.query_fingerprint)}</code></dd></div><div><dt>Evidence references</dt><dd>${escapeHtml((task.evidence_refs || []).join(', ') || 'none')}</dd></div><div><dt>Completed</dt><dd>${task.completed_at ? new Date(task.completed_at).toLocaleString() : 'unknown'}</dd></div></dl>`,
    actions
  });
}

async function deleteValidation(taskId) {
  const task = state.validations.find(item => item.id === taskId); if (!task) return;
  if (!confirm(`Delete validation task “${task.title}”? Preserved evidence artifacts are not deleted.`)) return;
  try { await api(`/api/validations/${encodeURIComponent(taskId)}`, { method:'DELETE' }); await loadValidations(); toast('Validation task deleted'); }
  catch (error) { toast(error.message); }
}

function detectionStatusLabel(status) {
  return ({
    draft:'Draft · editable',
    'in-review':'In review · exact hash',
    approved:'Approved · export eligible',
    'changes-requested':'Changes requested',
    retired:'Retired · retained'
  })[status] || status;
}

function detectionForValidation(validationId) {
  return state.detections.find(item => item.source_validation_id === validationId);
}

function renderDetectionCandidates() {
  const container = $('#detectionCandidates'); if (!container) return;
  const complete = state.validations.filter(task => task.status === 'complete' && !task.source_run_id?.startsWith('detection-runtime:'));
  const available = complete.filter(task => !detectionForValidation(task.id));
  $('#showDetectionCandidates').disabled = !available.length;
  container.innerHTML = available.length ? available.map(task => `
    <article>
      <div><span>COMPLETED VALIDATION</span><h4>${escapeHtml(task.title)}</h4><p>${Number(task.result_count).toLocaleString()} row${Number(task.result_count) === 1 ? '' : 's'} preserved · ${escapeHtml(task.earliest_time)} → ${escapeHtml(task.latest_time)}</p></div>
      <div><code>${escapeHtml(task.query_fingerprint.slice(0, 12))}</code><button class="button primary small" data-create-detection="${escapeHtml(task.id)}">Create version 1</button></div>
    </article>`).join('') : `<div class="empty-inline compact-empty">${complete.length ? 'Every completed validation already has a detection project.' : 'No completed validation is available yet. Run and preserve a bounded validation first.'}</div>`;
}

function renderDetectionMetrics() {
  const counts = { draft:0, review:0, approved:0, exported:0 };
  state.detections.forEach(item => {
    if (['draft','changes-requested'].includes(item.status)) counts.draft += 1;
    if (item.status === 'in-review') counts.review += 1;
    if (item.status === 'approved') counts.approved += 1;
    if (Number(item.export_count || 0) > 0) counts.exported += 1;
  });
  const cards = $('#detectionMetrics').children;
  [counts.draft, counts.review, counts.approved, counts.exported].forEach((value,index) => { cards[index].querySelector('strong').textContent = value; });
}

function renderDetectionList() {
  const container = $('#detectionList'); if (!container) return;
  $('#detectionCount').textContent = state.detections.length;
  $('#detectionListCount').textContent = `${state.detections.length} total`;
  container.innerHTML = state.detections.length ? state.detections.map(item => {
    const content = item.content || {}; const classification = content.classification || {};
    const gate = item.latest_gate;
    const gateLabel = gate ? `gate ${gate.status} ${Number(gate.score)}/100` : 'gate not run';
    return `<button class="detection-list-item ${state.activeDetection?.id === item.id ? 'active' : ''}" data-open-detection="${escapeHtml(item.id)}">
      <span class="detection-list-status ${escapeHtml(item.status)}">${escapeHtml(detectionStatusLabel(item.status))}</span>
      <b>${escapeHtml(content.title || 'Untitled detection')}</b>
      <small>${escapeHtml(classification.severity || 'medium')} · v${Number(item.current_version)} · ${escapeHtml(gateLabel)} · ${Number(item.export_count || 0)} export${Number(item.export_count || 0) === 1 ? '' : 's'}</small>
    </button>`;
  }).join('') : '<div class="empty-inline compact-empty">No detection projects yet.</div>';
}

function renderDetections() {
  renderDetectionMetrics();
  renderDetectionCandidates();
  renderDetectionList();
  renderValidations();
}

async function loadDetections() {
  try {
    const activeId = state.activeDetection?.id;
    state.detections = await api('/api/detections');
    if (activeId) state.activeDetection = await api(`/api/detections/${encodeURIComponent(activeId)}`).catch(() => null);
    renderDetections();
    if (state.activeDetection) renderDetectionDetail();
  } catch (error) { toast(`Detections: ${error.message}`); }
}

async function createDetectionFromValidation(validationId) {
  const task = state.validations.find(item => item.id === validationId);
  if (!task || task.status !== 'complete' || task.source_run_id?.startsWith('detection-runtime:')) return;
  try {
    const detection = await api('/api/detections', {
      method:'POST',
      body:JSON.stringify({
        validation_task_id:task.id,
        case_id:task.case_id || null,
        title:task.title,
        description:task.rationale,
        severity:'medium',
        security_domain:'threat',
        cron_schedule:'*/5 * * * *',
        throttle_seconds:3600,
        tags:['signalroom'],
        mitre_attack:[]
      })
    });
    state.activeDetection = detection;
    await loadDetections();
    navigateView('detections');
    await openDetection(detection.id);
    toast('Detection version 1 created from preserved evidence');
  } catch (error) { toast(error.message); }
}

async function openDetection(detectionId, updateHash = true) {
  try {
    if (state.activeDetection?.id !== detectionId) {
      state.detectionGitExport = null;
      state.repositoryHandoff = null;
    }
    state.activeDetection = await api(`/api/detections/${encodeURIComponent(detectionId)}`);
    if (state.settings?.detection_repository?.enabled) {
      state.repositoryHandoff = await api(`/api/detections/${encodeURIComponent(detectionId)}/repository-handoff`).catch(() => null);
    }
    renderDetectionList(); renderDetectionDetail();
    if (updateHash) history.replaceState(null, '', `${location.pathname}#detections/${encodeURIComponent(detectionId)}`);
  } catch (error) { toast(error.message); }
}

function detectionHistoryMarkup(detection) {
  const versions = (detection.versions || []).map(item => `<li><b>Version ${Number(item.version)}</b><code>${escapeHtml(item.content_sha256.slice(0, 12))}</code><time>${new Date(item.created_at).toLocaleString()}</time></li>`).join('');
  const reviews = (detection.reviews || []).map(item => `<li class="${escapeHtml(item.decision)}"><b>${escapeHtml(item.decision.replaceAll('-', ' '))}</b><span>${escapeHtml(item.reviewer)} · v${Number(item.version)}</span><p>${escapeHtml(item.note || 'No review note recorded.')}</p><time>${new Date(item.created_at).toLocaleString()}</time></li>`).join('');
  const exports = (detection.exports || []).map(item => `<li><b>${item.export_kind === 'git-change' ? 'Git change bundle' : 'Review package'} · v${Number(item.version)}</b><a href="/api/detection-exports/${encodeURIComponent(item.filename)}">${escapeHtml(item.filename)}</a><code>${escapeHtml(item.archive_sha256.slice(0, 12))}</code><time>${new Date(item.created_at).toLocaleString()}</time></li>`).join('');
  const gates = (detection.gate_runs || []).map(item => `<li class="${escapeHtml(item.status)}"><b>${escapeHtml(item.status)} · ${Number(item.score)}/100</b><span>Version ${Number(item.version)} · ${Number(item.result_count).toLocaleString()} result${Number(item.result_count) === 1 ? '' : 's'}</span><code>${escapeHtml(item.content_sha256.slice(0, 12))}</code>${item.accepted_at ? '<em>Accepted baseline</em>' : ''}<time>${new Date(item.created_at).toLocaleString()}</time></li>`).join('');
  return `<div class="detection-history-grid"><section><h4>Immutable versions</h4><ol>${versions || '<li>No versions recorded.</li>'}</ol></section><section><h4>Promotion gates</h4><ol>${gates || '<li>No promotion gate has run.</li>'}</ol></section><section><h4>Review decisions</h4><ol>${reviews || '<li>No review decision yet.</li>'}</ol></section><section><h4>Local exports</h4><ol>${exports || '<li>No approved package exported.</li>'}</ol></section></div>`;
}

function detectionGitOpsMarkup(detection) {
  if (detection.status !== 'approved') return '';
  const result = state.detectionGitExport;
  const current = result?.detection_id === detection.id && result?.content_sha256 === detection.current_sha256 ? result : null;
  const verification = current ? `
    <div class="detection-git-verification"><span>OFFLINE SELF-CHECK PASSED</span><b>Ed25519 · pinned-key capable</b><code>${escapeHtml(current.key_id)}</code><p>Confirm this fingerprint outside the pull request, then pin it as the protected repository variable <code>SIGNALROOM_TRUSTED_KEY_SHA256</code>.</p></div>` : '';
  return `<section class="detection-gitops">
    <header><div><span>GIT-NATIVE CHANGE CONTROL</span><h4>Signed repository change bundle</h4><p>Export the approved detection, accepted gate provenance, offline verifier, and a read-only pull-request workflow. SignalRoom will not create a commit, open a pull request, or deploy to Splunk.</p></div><button class="button primary" type="button" data-export-detection-git>Export Git change bundle</button></header>
    <div class="detection-git-flow"><span>Approved detection</span><b>→</b><span>Signed manifest</span><b>→</b><span>Repository-pinned CI</span><b>→</b><span>Your deployment process</span></div>
    ${verification}
  </section>`;
}

function repositoryReviewMarkup(detection, handoff) {
  if (handoff.status !== 'pull-request-opened') return '';
  const review = handoff.review;
  if (!review) {
    return `<section class="repository-feedback empty">
      <header><div><span>EXPLICIT REPOSITORY FEEDBACK</span><h5>No CI or review snapshot captured</h5><p>SignalRoom never polls GitHub silently. Refresh when you want a durable observation of the exact pull request, reviewers, and checks.</p></div><button class="button primary" type="button" data-refresh-repository-review>Refresh PR + CI status</button></header>
      <div class="repository-authority"><b>Read-only boundary</b><span>This action reads repository state and writes only a local snapshot. It cannot merge the pull request or prove Splunk deployment.</span></div>
    </section>`;
  }
  const counts = review.check_counts || {};
  const checks = (review.checks || []).map(check => `<li class="${escapeHtml(check.bucket)}"><span>${escapeHtml(check.bucket)}</span><div><b>${escapeHtml(check.name)}</b>${check.workflow ? `<small>${escapeHtml(check.workflow)}</small>` : ''}${check.description ? `<p>${escapeHtml(check.description)}</p>` : ''}</div><code>${escapeHtml(check.state || 'unknown')}</code></li>`).join('');
  let caseAction = '<span class="repository-case-note">Link this detection to a case to preserve the snapshot.</span>';
  if (detection.case_id && review.case_item_id) {
    caseAction = `<button class="button ghost" type="button" data-open-repository-case="${escapeHtml(detection.case_id)}">Open preserved case entry</button>`;
  } else if (detection.case_id) {
    caseAction = '<button class="button ghost" type="button" data-preserve-repository-review>Preserve exact snapshot to case</button>';
  }
  return `<section class="repository-feedback ${escapeHtml(review.risk_level)}">
    <header><div><span>REPOSITORY FEEDBACK · ${escapeHtml(review.risk_level)}</span><h5>${escapeHtml(review.title || `Pull request #${review.pull_request_number}`)}</h5><p>Observed ${new Date(review.observed_at).toLocaleString()} · snapshot <code>${escapeHtml(review.snapshot_sha256)}</code></p></div><button class="button primary" type="button" data-refresh-repository-review>Refresh explicitly</button></header>
    <div class="repository-feedback-grid">
      <article><span>Head identity</span><b class="${escapeHtml(review.identity_status)}">${escapeHtml(review.identity_status)}</b><small>${escapeHtml(String(review.head_ref_oid || '').slice(0, 12) || 'unavailable')}</small></article>
      <article><span>Lifecycle</span><b>${escapeHtml(review.lifecycle)}</b><small>${review.is_draft ? 'Draft pull request' : 'Repository state'}</small></article>
      <article><span>Review</span><b>${escapeHtml(review.review_decision.replaceAll('-', ' '))}</b><small>${escapeHtml(review.merge_state_status || review.mergeable || 'not reported')}</small></article>
      <article><span>Checks</span><b>${escapeHtml(review.checks_status)}</b><small>${Number(counts.pass || 0)} pass · ${Number(counts.fail || 0)} fail · ${Number(counts.pending || 0)} pending</small></article>
    </div>
    <div class="repository-recommendation"><b>Next analyst action</b><p>${escapeHtml(review.recommended_action)}</p></div>
    ${checks ? `<details class="repository-checks" open><summary>Observed checks · ${review.checks.length}</summary><ul>${checks}</ul></details>` : '<div class="repository-no-checks">No repository checks were reported at this observation.</div>'}
    <footer><a class="button ghost" href="${escapeHtml(review.pull_request_url)}" target="_blank" rel="noopener">Open pull request</a>${caseAction}</footer>
    <div class="repository-authority"><b>Authority boundary</b><span>Observed repository state is mutable external evidence. Merge does not prove this detection was deployed or enabled in Splunk.</span></div>
  </section>`;
}

function detectionRepositoryMarkup(detection) {
  if (detection.status !== 'approved') return '';
  const policy = state.settings?.detection_repository || {};
  if (!policy.enabled) {
    return `<section class="detection-repository disabled">
      <header><div><span>OPTIONAL REPOSITORY HANDOFF</span><h4>Move from export to an exact Git diff</h4><p>Configure a local detection repository to preview policy conflicts and create an isolated branch without changing your primary checkout.</p></div><button class="button ghost" type="button" data-open-settings>Configure repository</button></header>
    </section>`;
  }
  const value = state.repositoryHandoff;
  const current = value?.detection_id === detection.id && value?.content_sha256 === detection.current_sha256 ? value : null;
  const repository = state.repositoryStatus;
  if (!current) {
    const readiness = repository?.ready
      ? `${escapeHtml(repository.repository_root)} · ${escapeHtml(repository.base_ref)} at <code>${escapeHtml(String(repository.base_commit || '').slice(0, 12))}</code>`
      : escapeHtml(repository?.blocking_reason || 'Repository readiness will be checked before preview.');
    return `<section class="detection-repository">
      <header><div><span>PREVIEW → APPROVE → LOCAL COMMIT</span><h4>Repository-bound handoff</h4><p>Compare this exact signed detection against the configured base commit. Previewing creates no branch, commit, push, or pull request.</p></div><button class="button primary" type="button" data-preview-repository>Preview exact diff</button></header>
      <div class="repository-readiness"><b>${repository?.ready ? 'Repository ready' : 'Readiness required'}</b><span>${readiness}</span></div>
    </section>`;
  }
  const summary = current.summary || {};
  const blocked = (current.blocking_reasons || []).length > 0;
  const files = (current.files || []).map(item => `<li class="${escapeHtml(item.status)}"><span>${escapeHtml(item.status.replaceAll('-', ' '))}</span><code>${escapeHtml(item.path)}</code>${item.protected ? '<b>Policy control</b>' : ''}</li>`).join('');
  const reasons = blocked ? `<div class="repository-blockers"><b>Handoff blocked</b><ul>${current.blocking_reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join('')}</ul><p>Repository-owned controls are never replaced implicitly. Resolve the control drift through your normal administrator process, then preview again.</p></div>` : '';
  let action = '';
  if (current.status === 'previewed' && !blocked) action = '<button class="button primary" type="button" data-apply-repository>Create approved local branch + commit</button>';
  if (current.status === 'previewed' && blocked) action = '<button class="button ghost" type="button" data-preview-repository>Preview again</button>';
  if (current.status === 'applied') action = policy.allow_push
    ? '<button class="button primary" type="button" data-push-repository>Push exact branch to remote</button>'
    : '<button class="button ghost" type="button" data-open-settings>Enable remote push in Setup</button>';
  if (current.status === 'pushed') action = policy.allow_draft_pull_request
    ? '<button class="button primary" type="button" data-pull-request-repository>Open draft pull request</button>'
    : '<button class="button ghost" type="button" data-open-settings>Enable draft PRs in Setup</button>';
  if (current.status === 'pull-request-opened') action = `<a class="button primary" href="${escapeHtml(current.pull_request_url)}" target="_blank" rel="noopener">Open draft pull request</a>`;
  const commit = current.commit_sha ? `<div><dt>Exact commit</dt><dd><code>${escapeHtml(current.commit_sha)}</code></dd></div>` : '';
  return `<section class="detection-repository ${blocked ? 'blocked' : ''}">
    <header><div><span>REPOSITORY HANDOFF · ${escapeHtml(current.status.replaceAll('-', ' '))}</span><h4>${blocked ? 'Repository policy requires attention' : current.status === 'previewed' ? 'Review the exact repository diff' : 'Exact change-control identity'}</h4><p>Base and content identity remain fixed throughout this handoff. Any base movement or digest mismatch forces a new preview.</p></div>${action}</header>
    <div class="repository-summary"><article><b>${Number(summary.added || 0)}</b><span>Added</span></article><article><b>${Number(summary.modified || 0)}</b><span>Modified</span></article><article><b>${Number(summary.unchanged || 0)}</b><span>Unchanged</span></article><article class="${Number(summary['protected-conflict'] || 0) ? 'warn' : ''}"><b>${Number(summary['protected-conflict'] || 0)}</b><span>Policy conflicts</span></article></div>
    <dl class="repository-contract"><div><dt>Repository</dt><dd>${escapeHtml(current.repository_path)}</dd></div><div><dt>Approved base</dt><dd>${escapeHtml(current.base_ref)} · <code>${escapeHtml(current.base_commit)}</code></dd></div><div><dt>Isolated branch</dt><dd><code>${escapeHtml(current.branch_name)}</code></dd></div><div><dt>Preview digest</dt><dd><code>${escapeHtml(current.preview_sha256)}</code></dd></div>${commit}</dl>
    ${reasons}
    <details class="repository-file-diff" open><summary>Exact file plan · ${(current.files || []).length} files</summary><ul>${files}</ul></details>
    <div class="repository-authority"><b>Authority boundary</b><span>${current.status === 'previewed' ? 'No repository mutation has occurred.' : 'The primary checkout was not changed.'} SignalRoom cannot deploy or enable this detection in Splunk.</span></div>
    ${repositoryReviewMarkup(detection, current)}
  </section>`;
}

function detectionRuntimeMarkup(detection, snapshot) {
  const runtime = snapshot.runtime_verification;
  const identity = snapshot.runtime_identity || {};
  const eligible = snapshot.status === 'verified' && identity.unique_name_observed === true;
  if (!runtime) {
    const reason = snapshot.status !== 'verified'
      ? 'Runtime attribution stays locked until the exact saved-search definition is verified and enabled.'
      : identity.unique_name_observed !== true
      ? 'Scheduler telemetry is name-bound. Refresh the definition catalog and resolve duplicate saved-search names before using it.'
      : 'Stage one bounded scheduler query tied to this exact deployment snapshot. The validation remains editable, unapproved, and unexecuted until an analyst acts.';
    return `<section class="deployment-runtime empty">
      <header><div><span>RUNTIME EVIDENCE · SEPARATE CLAIM</span><h5>${eligible ? 'Definition verified; operation not yet observed' : 'Runtime verification unavailable'}</h5><p>${escapeHtml(reason)}</p></div>${eligible ? '<button class="button primary" type="button" data-stage-runtime>Stage runtime validation</button>' : ''}</header>
      <div class="runtime-boundary"><b>No automatic <code>_internal</code> search</b><span>SignalRoom can draft the exact scheduler check, but only the existing single-execution approval queue can run it.</span></div>
    </section>`;
  }
  const assessment = runtime.assessment;
  const observation = assessment?.observation || {};
  const validation = runtime.validation_task || {};
  const stateLabel = String(runtime.state || validation.status || 'unknown').replaceAll('-', ' ');
  const actions = [];
  if (!assessment) {
    actions.push(`<button class="button ghost" type="button" data-open-runtime-validation="${escapeHtml(runtime.validation_task_id)}">Open approval queue</button>`);
    if (runtime.ready_to_assess) actions.push('<button class="button primary" type="button" data-assess-runtime>Interpret preserved result</button>');
    if (['contract-drifted','validation-missing','expired'].includes(runtime.state)) actions.push('<button class="button primary" type="button" data-stage-runtime>Stage replacement check</button>');
  } else {
    actions.push('<button class="button ghost" type="button" data-stage-runtime>Stage fresh runtime check</button>');
    if (detection.case_id && runtime.case_item_id) {
      actions.push(`<button class="button ghost" type="button" data-open-runtime-case="${escapeHtml(detection.case_id)}">Open preserved case entry</button>`);
    } else if (detection.case_id) {
      actions.push('<button class="button ghost" type="button" data-preserve-runtime>Preserve assessment to case</button>');
    }
  }
  const result = assessment ? `<div class="runtime-metrics">
    <article><span>Executions</span><b>${observation.executions == null ? '—' : Number(observation.executions).toLocaleString()}</b><small>${escapeHtml(runtime.policy.earliest_time)} → now</small></article>
    <article><span>Latest outcome</span><b>${escapeHtml(observation.last_status || 'not observed')}</b><small>${Number(observation.non_success || 0).toLocaleString()} non-success</small></article>
    <article><span>Last-run lag</span><b>${observation.lag_seconds == null ? '—' : `${Math.round(Number(observation.lag_seconds)).toLocaleString()}s`}</b><small>Threshold ${Number(runtime.policy.max_lag_seconds).toLocaleString()}s</small></article>
    <article><span>Runtime</span><b>${observation.avg_run_seconds == null ? '—' : `${Number(observation.avg_run_seconds).toFixed(2)}s`}</b><small>Max ${observation.max_run_seconds == null ? 'not observed' : `${Number(observation.max_run_seconds).toFixed(2)}s`}</small></article>
  </div>
  <div class="runtime-recommendation"><b>Next analyst action</b><p>${escapeHtml(assessment.recommended_action)}</p></div>
  <dl class="runtime-provenance"><div><dt>Assessment digest</dt><dd><code>${escapeHtml(runtime.assessment_sha256)}</code></dd></div><div><dt>Evidence artifact</dt><dd><code>${escapeHtml(assessment.validation.artifact_id)}</code></dd></div></dl>` : `<div class="runtime-queue-state">
    <b>${escapeHtml(stateLabel)}</b><span>${validation.exact_contract === false ? 'The queued query no longer matches the snapshot-bound contract.' : validation.status === 'complete' ? 'The exact result is preserved and ready for deterministic interpretation.' : 'Review, approve, and run this exact contract in the validation queue.'}</span>
    ${validation.error ? `<small>${escapeHtml(validation.error)}</small>` : ''}
  </div>`;
  return `<section class="deployment-runtime ${escapeHtml(assessment?.risk_level || runtime.state || '')}">
    <header><div><span>RUNTIME EVIDENCE · ${escapeHtml(assessment ? `${assessment.risk_level} RISK` : 'AWAITING APPROVAL')}</span><h5>${escapeHtml(assessment?.status?.replaceAll('-', ' ') || stateLabel)}</h5><p>Check <code>${escapeHtml(runtime.check_sha256)}</code> · validation <code>${escapeHtml(runtime.validation_task_id)}</code></p></div><div class="runtime-actions">${actions.join('')}</div></header>
    ${result}
    <div class="runtime-boundary"><b>Name-bound scheduler evidence</b><span>This check is tied to deployment snapshot <code>${escapeHtml(runtime.deployment_snapshot_sha256)}</code>. It does not prove firing, notable-event creation, suppression behavior, or response delivery.</span></div>
  </section>`;
}

function detectionDeploymentMarkup(detection) {
  if (detection.status !== 'approved') return '';
  const snapshot = detection.deployment_verification;
  const targetApp = snapshot?.target?.app || '';
  const refreshControl = `<div class="deployment-refresh-control">
    <label><span>Target Splunk app <small>optional, but required when names collide</small></span><input id="deploymentTargetApp" maxlength="160" pattern="[A-Za-z0-9_.-]*" value="${escapeHtml(targetApp)}" placeholder="security_content"></label>
    <button class="button primary" type="button" data-refresh-deployment>${snapshot ? 'Refresh explicitly' : 'Verify in Splunk'}</button>
  </div>`;
  if (!snapshot) {
    return `<section class="detection-deployment empty">
      <header><div><span>READ-ONLY SPLUNK DEPLOYMENT CHECK</span><h4>No live definition observation</h4><p>Compare this exact approved version with the saved-search catalog through one explicit Splunk MCP read. SignalRoom never polls or changes Splunk.</p></div>${refreshControl}</header>
      <p class="deployment-live-status" data-deployment-live aria-live="polite">Ready to request up to 1,000 saved-search definitions. An incomplete catalog will remain inconclusive.</p>
      <div class="deployment-authority"><b>Observation boundary</b><span>The MCP response can prove selected definition fields, not scheduler execution, alert firing, suppression, or notable-event creation.</span></div>
    </section>`;
  }
  const observed = snapshot.observed || {};
  const enabled = observed.disabled === false ? 'enabled' : observed.disabled === true ? 'disabled' : 'not observed';
  const controls = (snapshot.controls || []).map(control => `<li class="${escapeHtml(control.status)}"><i aria-hidden="true"></i><div><b>${escapeHtml(control.label)}</b><p>${escapeHtml(control.detail)}</p></div><span>${escapeHtml(control.status.replaceAll('-', ' '))}</span></li>`).join('');
  const candidates = (snapshot.candidates || []).length > 1
    ? `<div class="deployment-candidates"><b>Matching identities require disambiguation</b><ul>${snapshot.candidates.map(item => `<li><span>${escapeHtml(item.name)}</span><code>${escapeHtml(item.app || 'app not reported')}</code></li>`).join('')}</ul></div>`
    : '';
  const unobserved = (snapshot.unobserved_controls || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  let caseAction = '<span class="deployment-case-note">Link this detection to a case to preserve the exact observation.</span>';
  if (detection.case_id && snapshot.case_item_id) {
    caseAction = `<button class="button ghost" type="button" data-open-deployment-case="${escapeHtml(detection.case_id)}">Open preserved case entry</button>`;
  } else if (detection.case_id) {
    caseAction = '<button class="button ghost" type="button" data-preserve-deployment>Preserve exact snapshot to case</button>';
  }
  return `<section class="detection-deployment ${escapeHtml(snapshot.risk_level)} ${escapeHtml(snapshot.status)}">
    <header><div><span>SPLUNK DEPLOYMENT · ${escapeHtml(snapshot.risk_level)} RISK</span><h4>${escapeHtml(snapshot.status.replaceAll('-', ' '))}</h4><p>Observed ${new Date(snapshot.observed_at).toLocaleString()} · snapshot <code>${escapeHtml(snapshot.snapshot_sha256)}</code></p></div>${refreshControl}</header>
    <p class="deployment-live-status" data-deployment-live aria-live="polite">This is the latest explicit observation. SignalRoom is not polling Splunk.</p>
    <div class="deployment-state-grid">
      <article><span>Definition</span><b>${escapeHtml(snapshot.status)}</b><small>${observed.definition_sha256 ? escapeHtml(observed.definition_sha256.slice(0, 12)) : 'not observed'}</small></article>
      <article><span>Enabled state</span><b>${escapeHtml(enabled)}</b><small>Reported disabled = ${observed.disabled === true ? 'true' : observed.disabled === false ? 'false' : 'unknown'}</small></article>
      <article><span>Splunk app</span><b>${escapeHtml(observed.app || 'not observed')}</b><small>${snapshot.target.app ? `Target: ${escapeHtml(snapshot.target.app)}` : 'No app scope requested'}</small></article>
      <article><span>Catalog</span><b>${snapshot.collection.exhaustive ? 'exhaustive' : 'capped'}</b><small>${Number(snapshot.collection.returned).toLocaleString()} returned${snapshot.collection.total_rows == null ? '' : ` of ${Number(snapshot.collection.total_rows).toLocaleString()}`}</small></article>
    </div>
    <div class="deployment-recommendation"><b>Next analyst action</b><p>${escapeHtml(snapshot.recommended_action)}</p></div>
    ${controls ? `<ul class="deployment-controls">${controls}</ul>` : ''}
    ${candidates}
    <details class="deployment-limitations"><summary>Controls this MCP response cannot prove</summary><ul>${unobserved}</ul><p>Use scheduler and alert-runtime telemetry as a separate evidence source.</p></details>
    ${detectionRuntimeMarkup(detection, snapshot)}
    <footer>${caseAction}</footer>
    <div class="deployment-authority"><b>Read-only authority</b><span>This observation did not deploy, enable, schedule, or change the saved search. A matching definition does not prove it ran or fired.</span></div>
  </section>`;
}

function detectionGateMarkup(detection) {
  const gate = detection.latest_gate;
  const currentGate = gate && gate.content_sha256 === detection.current_sha256 ? gate : null;
  const controls = currentGate?.controls || [];
  const exactMissing = !currentGate || controls.some(item => item.id === 'exact-validation' && item.status === 'fail');
  const status = currentGate?.status || 'not-run';
  const heading = currentGate
    ? `${status === 'pass' ? 'Ready for review' : 'Blocked'} · ${Number(currentGate.score)}/100`
    : 'Run before review';
  const summary = currentGate
    ? `${Number(currentGate.result_count).toLocaleString()} result${Number(currentGate.result_count) === 1 ? '' : 's'} · validation ${currentGate.validation_task_id ? currentGate.validation_task_id.slice(0, 12) : 'not available'}`
    : 'SignalRoom has not evaluated this exact content hash.';
  const rows = controls.length ? controls.map(item => `
    <li class="${escapeHtml(item.status)}">
      <i aria-hidden="true"></i><div><b>${escapeHtml(item.label)}</b><p>${escapeHtml(item.detail)}</p></div><span>${item.blocking ? 'Required' : 'Advisory'}</span>
    </li>`).join('') : '<li class="not-run"><i aria-hidden="true"></i><div><b>No gate result yet</b><p>Evaluate the saved version against a completed, exact-fingerprint validation.</p></div><span>Required</span></li>';
  const actions = detection.status === 'retired' ? '' : `
    <button class="button primary" type="button" data-run-detection-gate>${currentGate ? 'Run gate again' : 'Run promotion gate'}</button>
    ${exactMissing ? '<button class="button ghost" type="button" data-detection-validation-draft>Queue exact validation draft</button>' : ''}`;
  return `<section class="detection-gate ${escapeHtml(status)}">
    <header><div><span>DETERMINISTIC PROMOTION GATE</span><h4>${escapeHtml(heading)}</h4><p>${escapeHtml(summary)}</p></div><div>${actions}</div></header>
    <div class="detection-gate-boundary"><b>No hidden Splunk execution</b><span>The gate reads preserved evidence only. If evidence is missing, SignalRoom creates an editable draft that still requires your approval before it can run.</span></div>
    <ul>${rows}</ul>
  </section>`;
}

function renderDetectionDetail() {
  const detection = state.activeDetection; const panel = $('#detectionDetail');
  if (!detection) {
    panel.innerHTML = '<div class="case-empty"><div class="empty-glyph">⌾</div><h3>Select a detection project</h3><p>Review its evidence contract, edit a new version, request independent review, or export an approved disabled-by-default package.</p></div>';
    return;
  }
  const content = detection.content; const schedule = content.schedule; const classification = content.classification; const evidence = content.evidence;
  const testing = content.testing || { expected_result:Number(evidence.result_count) ? 'nonzero' : 'zero', required_fields:[], validation_row_limit:100, max_result_count:0, max_count_delta_percent:200 };
  const gatePassed = detection.latest_gate?.content_sha256 === detection.current_sha256 && detection.latest_gate?.status === 'pass' && Number(detection.latest_gate?.score || 0) >= 80;
  const locked = ['in-review','retired'].includes(detection.status);
  const lockAttribute = locked ? 'disabled' : '';
  const reviewControls = detection.status === 'in-review' ? `
    <section class="detection-review-box"><header><div><span>INDEPENDENT REVIEW</span><h4>Decide on version ${Number(detection.current_version)}</h4></div><code>${escapeHtml(detection.current_sha256)}</code></header>
      <div class="form-grid"><label><span>Reviewer</span><input id="detectionReviewer" maxlength="160" value="Local reviewer"></label><label class="full"><span>Review note</span><textarea id="detectionReviewNote" rows="3" maxlength="10000" placeholder="Record evidence, tuning, ownership, or deployment concerns."></textarea></label></div>
      <footer><button class="button ghost" data-review-detection="request-changes">Request changes</button><button class="button primary" data-review-detection="approve" ${gatePassed ? '' : 'disabled'}>Approve exact gated version</button></footer>
    </section>` : '';
  const primaryActions = [];
  if (['draft','changes-requested'].includes(detection.status)) {
    if (gatePassed) primaryActions.push('<button class="button primary" data-submit-detection>Submit gated version for review</button>');
    primaryActions.push('<button class="button danger" data-delete-detection>Delete unapproved draft</button>');
  }
  if (detection.status === 'approved') {
    primaryActions.push('<button class="button primary" data-export-detection>Export disabled package</button>');
    primaryActions.push('<button class="button ghost" data-retire-detection>Retire project</button>');
  }
  primaryActions.push('<button class="button ghost" data-detection-investigate>Pressure-test with local model</button>');
  panel.innerHTML = `
    <header class="detection-detail-header"><div><span class="detection-list-status ${escapeHtml(detection.status)}">${escapeHtml(detectionStatusLabel(detection.status))}</span><h3>${escapeHtml(content.title)}</h3><p>Version ${Number(detection.current_version)} · SHA-256 <code>${escapeHtml(detection.current_sha256)}</code></p></div><div>${primaryActions.join('')}</div></header>
    <div class="detection-boundary"><b>Separated authority</b><span>Exports remain local. Optional repository handoff requires an exact preview and explicit approval at each write boundary. SignalRoom cannot deploy, enable, or write this search to Splunk.</span></div>
    <form id="detectionForm"><div class="form-grid">
      <label class="full"><span>Detection title</span><input id="detectionTitle" required maxlength="240" value="${escapeHtml(content.title)}" ${lockAttribute}></label>
      <label class="full"><span>Intent and analyst outcome</span><textarea id="detectionDescription" rows="4" maxlength="10000" ${lockAttribute}>${escapeHtml(content.description)}</textarea></label>
      <label class="full"><span>Detection SPL</span><textarea id="detectionSearch" class="spl-editor" rows="8" required maxlength="20000" spellcheck="false" ${lockAttribute}>${escapeHtml(content.search)}</textarea></label>
      <label><span>Cron schedule</span><input id="detectionCron" required maxlength="120" value="${escapeHtml(schedule.cron)}" ${lockAttribute}></label>
      <label><span>Throttle seconds</span><input id="detectionThrottle" type="number" min="0" max="86400" value="${Number(schedule.throttle_seconds)}" ${lockAttribute}></label>
      <label><span>Earliest time</span><input id="detectionEarliest" required maxlength="64" value="${escapeHtml(schedule.earliest_time)}" ${lockAttribute}></label>
      <label><span>Latest time</span><input id="detectionLatest" required maxlength="64" value="${escapeHtml(schedule.latest_time)}" ${lockAttribute}></label>
      <label><span>Severity</span><select id="detectionSeverity" ${lockAttribute}>${['informational','low','medium','high','critical'].map(value => `<option value="${value}" ${classification.severity === value ? 'selected' : ''}>${value[0].toUpperCase()+value.slice(1)}</option>`).join('')}</select></label>
      <label><span>Owner</span><input id="detectionOwner" maxlength="160" value="${escapeHtml(classification.owner)}" ${lockAttribute}></label>
      <label><span>Security domain</span><input id="detectionDomain" maxlength="120" value="${escapeHtml(classification.security_domain)}" ${lockAttribute}></label>
      <label><span>MITRE ATT&amp;CK techniques</span><input id="detectionMitre" maxlength="1000" value="${escapeHtml((classification.mitre_attack || []).join(', '))}" placeholder="T1059.001, T1021" ${lockAttribute}></label>
      <label class="full"><span>Tags</span><input id="detectionTags" maxlength="2000" value="${escapeHtml((classification.tags || []).join(', '))}" ${lockAttribute}></label>
      <fieldset class="detection-test-contract full"><legend>Promotion test contract</legend>
        <label><span>Expected result</span><select id="detectionExpectedResult" ${lockAttribute}>${[['any','Any count'],['zero','Exactly zero'],['nonzero','One or more']].map(([value,label]) => `<option value="${value}" ${testing.expected_result === value ? 'selected' : ''}>${label}</option>`).join('')}</select><small>Defines what a healthy bounded result looks like.</small></label>
        <label><span>Validation row limit</span><input id="detectionValidationRowLimit" type="number" min="1" max="500" value="${Number(testing.validation_row_limit)}" ${lockAttribute}><small>Part of the exact query fingerprint.</small></label>
        <label class="full"><span>Required result fields</span><input id="detectionRequiredFields" maxlength="4000" value="${escapeHtml((testing.required_fields || []).join(', '))}" placeholder="host, user, process_name" ${lockAttribute}><small>Each field must appear in every preserved preview row.</small></label>
        <label><span>Maximum result count</span><input id="detectionMaxResultCount" type="number" min="0" max="10000000" value="${Number(testing.max_result_count)}" ${lockAttribute}><small>Use 0 for no fixed ceiling.</small></label>
        <label><span>Maximum baseline drift (%)</span><input id="detectionMaxDelta" type="number" min="0" max="10000" value="${Number(testing.max_count_delta_percent)}" ${lockAttribute}><small>Absolute count change from the last accepted gate.</small></label>
      </fieldset>
    </div>${locked ? '' : `<footer><span>Saving creates immutable version ${Number(detection.current_version)+1} and invalidates any prior approval.</span><button class="button primary" type="submit">Save new version</button></footer>`}</form>
    <section class="detection-evidence-contract"><header><div><span>TRUST ANCHOR</span><h4>Completed validation evidence</h4></div><b>${Number(evidence.result_count).toLocaleString()} result${Number(evidence.result_count) === 1 ? '' : 's'}</b></header><dl><div><dt>Validation</dt><dd><code>${escapeHtml(evidence.source_validation_id)}</code></dd></div><div><dt>Query fingerprint</dt><dd><code>${escapeHtml(evidence.query_fingerprint)}</code></dd></div><div><dt>Artifact</dt><dd><code>${escapeHtml(evidence.artifact_id)}</code></dd></div><div><dt>Completed</dt><dd>${evidence.completed_at ? new Date(evidence.completed_at).toLocaleString() : 'unknown'}</dd></div><div><dt>Evidence references</dt><dd>${escapeHtml((evidence.evidence_refs || []).join(', ') || 'none')}</dd></div></dl></section>
    ${detectionGateMarkup(detection)}
    ${reviewControls}
    ${detectionGitOpsMarkup(detection)}
    ${detectionRepositoryMarkup(detection)}
    ${detectionDeploymentMarkup(detection)}
    ${detectionHistoryMarkup(detection)}`;
  if (!locked) $('#detectionForm').addEventListener('submit', saveDetectionVersion);
}

async function saveDetectionVersion(event) {
  event.preventDefault(); const detection = state.activeDetection; if (!detection) return;
  const payload = {
    title:$('#detectionTitle').value.trim(),
    description:$('#detectionDescription').value.trim(),
    search:$('#detectionSearch').value.trim(),
    cron_schedule:$('#detectionCron').value.trim(),
    throttle_seconds:Number($('#detectionThrottle').value),
    earliest_time:$('#detectionEarliest').value.trim(),
    latest_time:$('#detectionLatest').value.trim(),
    severity:$('#detectionSeverity').value,
    owner:$('#detectionOwner').value.trim() || 'Unassigned',
    security_domain:$('#detectionDomain').value.trim() || 'threat',
    mitre_attack:$('#detectionMitre').value.split(',').map(value => value.trim()).filter(Boolean),
    tags:$('#detectionTags').value.split(',').map(value => value.trim()).filter(Boolean),
    expected_result:$('#detectionExpectedResult').value,
    required_fields:$('#detectionRequiredFields').value.split(',').map(value => value.trim()).filter(Boolean),
    validation_row_limit:Number($('#detectionValidationRowLimit').value),
    max_result_count:Number($('#detectionMaxResultCount').value),
    max_count_delta_percent:Number($('#detectionMaxDelta').value)
  };
  try {
    state.activeDetection = await api(`/api/detections/${encodeURIComponent(detection.id)}`, {method:'PATCH',body:JSON.stringify(payload)});
    await loadDetections(); toast(`Detection version ${state.activeDetection.current_version} saved; review is required`);
  } catch (error) { toast(error.message); }
}

async function runDetectionGate() {
  const detection = state.activeDetection; if (!detection) return;
  try {
    const result = await api(`/api/detections/${encodeURIComponent(detection.id)}/gate`, {method:'POST',body:JSON.stringify({expected_content_sha256:detection.current_sha256})});
    state.activeDetection = result.detection; await loadDetections();
    toast(result.gate.status === 'pass' ? `Promotion gate passed · ${result.gate.score}/100` : `Promotion gate blocked · ${result.gate.score}/100`);
  } catch (error) { toast(error.message); }
}

async function queueDetectionValidationDraft() {
  const detection = state.activeDetection; if (!detection) return;
  try {
    const result = await api(`/api/detections/${encodeURIComponent(detection.id)}/validation-draft`, {method:'POST',body:JSON.stringify({expected_content_sha256:detection.current_sha256})});
    await loadValidations();
    navigateView('discovery');
    $('#validationWorkspace').scrollIntoView({behavior:'smooth',block:'start'});
    setTimeout(() => {
      const card = document.querySelector(`[data-validation-id="${CSS.escape(result.validation.id)}"]`);
      if (card) { card.classList.add('package-focus'); card.scrollIntoView({behavior:'smooth',block:'center'}); setTimeout(() => card.classList.remove('package-focus'), 3500); }
    }, 350);
    toast(result.reused ? 'Exact validation already exists; opened the analyst queue' : 'Validation draft queued; review and approve it before running Splunk');
  } catch (error) { toast(error.message); }
}

async function submitDetection() {
  const detection = state.activeDetection; if (!detection) return;
  if (!confirm(`Submit version ${detection.current_version} for exact-content review?\n\nSHA-256: ${detection.current_sha256}`)) return;
  try {
    state.activeDetection = await api(`/api/detections/${encodeURIComponent(detection.id)}/submit`, {method:'POST',body:'{}'});
    await loadDetections(); toast('Detection submitted for exact-hash review');
  } catch (error) { toast(error.message); }
}

async function reviewDetection(decision) {
  const detection = state.activeDetection; if (!detection) return;
  const reviewer = $('#detectionReviewer').value.trim() || 'Local reviewer';
  const note = $('#detectionReviewNote').value.trim();
  if (decision === 'approve' && !confirm(`Approve exact detection version ${detection.current_version} for export?\n\nSHA-256: ${detection.current_sha256}\n\nThis does not deploy or enable the search in Splunk.`)) return;
  try {
    state.activeDetection = await api(`/api/detections/${encodeURIComponent(detection.id)}/review`, {method:'POST',body:JSON.stringify({decision,expected_content_sha256:detection.current_sha256,reviewer,note})});
    await Promise.all([loadDetections(), loadArtifacts(), loadCases()]);
    toast(decision === 'approve' ? 'Exact detection version approved and indexed locally' : 'Detection returned for changes');
  } catch (error) { toast(error.message); }
}

async function exportDetection() {
  const detection = state.activeDetection; if (!detection) return;
  try {
    const result = await api(`/api/detections/${encodeURIComponent(detection.id)}/export`, {method:'POST',body:JSON.stringify({expected_content_sha256:detection.current_sha256})});
    state.activeDetection = result.detection; await loadDetections();
    const link = document.createElement('a'); link.href = result.file.url; link.download = result.file.filename; document.body.appendChild(link); link.click(); link.remove();
    toast('Approved disabled-by-default package exported');
  } catch (error) { toast(error.message); }
}

async function exportDetectionGitChange() {
  const detection = state.activeDetection; if (!detection) return;
  try {
    const result = await api(`/api/detections/${encodeURIComponent(detection.id)}/git-export`, {method:'POST',body:JSON.stringify({expected_content_sha256:detection.current_sha256})});
    state.activeDetection = result.detection;
    state.detectionGitExport = {
      ...result.verification,
      detection_id:detection.id,
      content_sha256:detection.current_sha256
    };
    await loadDetections(); renderDetectionDetail();
    const link = document.createElement('a'); link.href = result.file.url; link.download = result.file.filename; document.body.appendChild(link); link.click(); link.remove();
    toast('Signed Git change verified locally and exported; pin its key fingerprint in repository policy');
  } catch (error) { toast(error.message); }
}

async function previewDetectionRepository() {
  const detection = state.activeDetection; if (!detection) return;
  try {
    state.repositoryHandoff = await api(`/api/detections/${encodeURIComponent(detection.id)}/repository-preview`, {method:'POST',body:JSON.stringify({expected_content_sha256:detection.current_sha256})});
    renderDetectionDetail();
    const blocked = state.repositoryHandoff.blocking_reasons?.length;
    toast(blocked ? 'Repository preview found a protected policy conflict' : 'Exact repository preview ready for analyst approval');
  } catch (error) { toast(error.message); }
}

async function applyDetectionRepository() {
  const value = state.repositoryHandoff; if (!value || value.status !== 'previewed') return;
  const approved = confirm(`Create this exact local Git branch and commit?\n\nRepository: ${value.repository_path}\nBase: ${value.base_ref} · ${value.base_commit}\nBranch: ${value.branch_name}\nPreview SHA-256: ${value.preview_sha256}\n\nThe primary checkout will remain unchanged. Nothing will be pushed and nothing will be deployed to Splunk.`);
  if (!approved) return;
  try {
    state.repositoryHandoff = await api(`/api/detection-repository/handoffs/${encodeURIComponent(value.id)}/apply`, {method:'POST',body:JSON.stringify({expected_preview_sha256:value.preview_sha256})});
    renderDetectionDetail();
    toast('Approved local branch and commit created; primary checkout unchanged');
  } catch (error) { toast(error.message); }
}

async function pushDetectionRepository() {
  const value = state.repositoryHandoff; if (!value?.commit_sha) return;
  const approved = confirm(`Push this exact detection commit to the configured remote?\n\nRemote: ${value.remote_name}\nBranch: ${value.branch_name}\nCommit: ${value.commit_sha}\n\nThis changes the remote Git repository. It will not open a pull request or deploy to Splunk.`);
  if (!approved) return;
  try {
    state.repositoryHandoff = await api(`/api/detection-repository/handoffs/${encodeURIComponent(value.id)}/push`, {method:'POST',body:JSON.stringify({expected_commit_sha:value.commit_sha})});
    renderDetectionDetail();
    toast('Exact detection branch pushed; no pull request opened');
  } catch (error) { toast(error.message); }
}

async function openDetectionRepositoryPullRequest() {
  const value = state.repositoryHandoff; if (!value?.commit_sha) return;
  const approved = confirm(`Open a DRAFT pull request for this exact pushed commit?\n\nRemote: ${value.remote_name}\nBranch: ${value.branch_name}\nCommit: ${value.commit_sha}\n\nThe pull request remains subject to repository review and CI. SignalRoom receives no Splunk deployment authority.`);
  if (!approved) return;
  try {
    state.repositoryHandoff = await api(`/api/detection-repository/handoffs/${encodeURIComponent(value.id)}/pull-request`, {method:'POST',body:JSON.stringify({expected_commit_sha:value.commit_sha})});
    renderDetectionDetail();
    toast('Draft pull request opened for the exact pushed commit');
  } catch (error) { toast(error.message); }
}

async function refreshDetectionRepositoryReview() {
  const value = state.repositoryHandoff; if (!value?.commit_sha || value.status !== 'pull-request-opened') return;
  try {
    state.repositoryHandoff = await api(`/api/detection-repository/handoffs/${encodeURIComponent(value.id)}/review-refresh`, {method:'POST',body:JSON.stringify({expected_commit_sha:value.commit_sha})});
    renderDetectionDetail();
    const review = state.repositoryHandoff.review;
    toast(review.identity_status === 'exact' ? `Repository feedback captured · ${review.risk_level} attention` : 'Promotion stopped: pull-request head no longer matches the approved commit');
  } catch (error) { toast(error.message); }
}

async function preserveDetectionRepositoryReview() {
  const value = state.repositoryHandoff; const review = value?.review;
  if (!value || !review || review.case_item_id) return;
  const approved = confirm(`Preserve this exact repository feedback snapshot to the linked case?\n\nSnapshot SHA-256: ${review.snapshot_sha256}\nRisk: ${review.risk_level}\nLifecycle: ${review.lifecycle}\n\nThis creates a durable local timeline item. It does not change GitHub or Splunk.`);
  if (!approved) return;
  try {
    state.repositoryHandoff = await api(`/api/detection-repository/handoffs/${encodeURIComponent(value.id)}/review-case`, {method:'POST',body:JSON.stringify({expected_snapshot_sha256:review.snapshot_sha256})});
    renderDetectionDetail();
    toast('Exact repository feedback preserved to the linked case');
  } catch (error) { toast(error.message); }
}

async function refreshDetectionDeployment() {
  const detection = state.activeDetection;
  if (!detection || detection.status !== 'approved') return;
  const button = document.querySelector('[data-refresh-deployment]');
  const live = document.querySelector('[data-deployment-live]');
  const targetApp = ($('#deploymentTargetApp')?.value || '').trim();
  if (button) { button.disabled = true; button.textContent = 'Reading Splunk…'; }
  if (live) live.textContent = 'Calling the read-only saved-search catalog through Splunk MCP; comparing exact SPL, app, schedule, dispatch bounds, and enabled state…';
  try {
    const snapshot = await api(`/api/detections/${encodeURIComponent(detection.id)}/deployment-verification/refresh`, {method:'POST',body:JSON.stringify({expected_content_sha256:detection.current_sha256,target_app:targetApp})});
    detection.deployment_verification = snapshot;
    renderDetectionDetail();
    const messages = {
      verified:'Exact deployed definition and enabled state verified',
      'deployed-disabled':'Definition matches, but the saved search is disabled',
      drifted:'Deployment drift requires review',
      missing:'Saved search not observed in the complete catalog',
      ambiguous:'Multiple matching definitions require a target app',
      inconclusive:'Catalog was incomplete; deployment remains unknown'
    };
    toast(messages[snapshot.status] || `Deployment observation: ${snapshot.status}`);
  } catch (error) {
    if (button) { button.disabled = false; button.textContent = detection.deployment_verification ? 'Refresh explicitly' : 'Verify in Splunk'; }
    if (live) live.textContent = `Verification stopped: ${error.message}`;
    toast(error.message);
  }
}

async function preserveDetectionDeployment() {
  const detection = state.activeDetection;
  const snapshot = detection?.deployment_verification;
  if (!detection || !snapshot || snapshot.case_item_id) return;
  const approved = confirm(`Preserve this exact Splunk deployment observation to the linked case?\n\nSnapshot SHA-256: ${snapshot.snapshot_sha256}\nStatus: ${snapshot.status}\nRisk: ${snapshot.risk_level}\n\nThis creates a local timeline item. It does not change Splunk.`);
  if (!approved) return;
  try {
    detection.deployment_verification = await api(`/api/detections/${encodeURIComponent(detection.id)}/deployment-verification/case`, {method:'POST',body:JSON.stringify({expected_snapshot_sha256:snapshot.snapshot_sha256})});
    renderDetectionDetail();
    toast('Exact deployment observation preserved to the linked case');
  } catch (error) { toast(error.message); }
}

async function openRuntimeValidation(taskId) {
  await loadValidations();
  navigateView('discovery');
  $('#validationWorkspace').scrollIntoView({behavior:'smooth',block:'start'});
  setTimeout(() => {
    const card = document.querySelector(`[data-validation-id="${CSS.escape(taskId)}"]`);
    if (card) {
      card.classList.add('package-focus');
      card.scrollIntoView({behavior:'smooth',block:'center'});
      setTimeout(() => card.classList.remove('package-focus'), 3500);
    }
  }, 350);
}

async function stageDetectionRuntime() {
  const detection = state.activeDetection;
  const snapshot = detection?.deployment_verification;
  if (!detection || !snapshot) return;
  const button = document.querySelector('[data-stage-runtime]');
  if (button) { button.disabled = true; button.textContent = 'Binding contract…'; }
  try {
    const result = await api(`/api/detections/${encodeURIComponent(detection.id)}/deployment-verification/runtime-draft`, {method:'POST',body:JSON.stringify({expected_snapshot_sha256:snapshot.snapshot_sha256})});
    snapshot.runtime_verification = result.runtime;
    renderDetectionDetail();
    await openRuntimeValidation(result.runtime.validation_task_id);
    toast(result.reused ? 'Opened the existing snapshot-bound runtime check' : 'Runtime check staged; review and approve the single execution');
  } catch (error) {
    renderDetectionDetail();
    toast(error.message);
  }
}

async function assessDetectionRuntime() {
  const detection = state.activeDetection;
  const snapshot = detection?.deployment_verification;
  const runtime = snapshot?.runtime_verification;
  if (!detection || !runtime?.ready_to_assess) return;
  const button = document.querySelector('[data-assess-runtime]');
  if (button) { button.disabled = true; button.textContent = 'Interpreting evidence…'; }
  try {
    snapshot.runtime_verification = await api(`/api/detections/${encodeURIComponent(detection.id)}/deployment-verification/runtime-assessment`, {method:'POST',body:JSON.stringify({expected_runtime_check_sha256:runtime.check_sha256})});
    renderDetectionDetail();
    const assessment = snapshot.runtime_verification.assessment;
    toast(`Runtime evidence: ${assessment.status.replaceAll('-', ' ')} · ${assessment.risk_level} risk`);
  } catch (error) {
    renderDetectionDetail();
    toast(error.message);
  }
}

async function preserveDetectionRuntime() {
  const detection = state.activeDetection;
  const runtime = detection?.deployment_verification?.runtime_verification;
  if (!detection || !runtime?.assessment || runtime.case_item_id) return;
  const approved = confirm(`Preserve this exact runtime assessment to the linked case?\n\nAssessment SHA-256: ${runtime.assessment_sha256}\nStatus: ${runtime.assessment.status}\nRisk: ${runtime.assessment.risk_level}\n\nThis records local evidence only. It does not change Splunk.`);
  if (!approved) return;
  try {
    detection.deployment_verification.runtime_verification = await api(`/api/detections/${encodeURIComponent(detection.id)}/deployment-verification/runtime-case`, {method:'POST',body:JSON.stringify({expected_assessment_sha256:runtime.assessment_sha256})});
    renderDetectionDetail();
    toast('Exact runtime assessment preserved to the linked case');
  } catch (error) { toast(error.message); }
}

async function retireDetection() {
  const detection = state.activeDetection; if (!detection) return;
  if (!confirm(`Retire “${detection.content.title}”? Its versions, reviews, exports, and evidence links will be retained.`)) return;
  try {
    state.activeDetection = await api(`/api/detections/${encodeURIComponent(detection.id)}/retire`, {method:'POST',body:'{}'});
    await loadDetections(); toast('Detection project retired and retained');
  } catch (error) { toast(error.message); }
}

async function deleteDetection() {
  const detection = state.activeDetection; if (!detection) return;
  if (!confirm(`Delete unapproved detection draft “${detection.content.title}”? Its source validation and evidence artifact will remain.`)) return;
  try {
    await api(`/api/detections/${encodeURIComponent(detection.id)}`, {method:'DELETE'});
    state.activeDetection = null; await loadDetections(); renderDetectionDetail();
    history.replaceState(null, '', `${location.pathname}#detections`); toast('Unapproved detection draft deleted');
  } catch (error) { toast(error.message); }
}

function investigateDetection() {
  const detection = state.activeDetection; if (!detection) return;
  const content = detection.content;
  openInvestigation('detection', `Pressure-test this versioned detection using local-first security reasoning. Assess required telemetry and fields, false positives, evasion paths, schedule and throttle risk, and test coverage. Separate evidence-backed observations from recommendations. Do not deploy or enable anything.\n\nDetection: ${content.title}\nVersion: ${detection.current_version}\nContent SHA-256: ${detection.current_sha256}\nIntent: ${content.description}\nSPL:\n${content.search}\nDispatch: ${content.schedule.earliest_time} to ${content.schedule.latest_time} on ${content.schedule.cron}\nSource validation: ${content.evidence.source_validation_id}\nEvidence artifact: ${content.evidence.artifact_id}`, false);
}

function renderSecurityPosture(result) {
  const posture = result.security_posture; if (!posture) return;
  const telemetry = posture.telemetry; const detections = posture.detections; const models = posture.data_models; const mltk = posture.mltk_models || {};
  $('#securityPosture').hidden = false;
  $('#securityPosture').innerHTML = `
    <article><span>TELEMETRY FRESHNESS</span><strong>${telemetry.activity_profiled ? telemetry.stale_over_24h.length : '—'}</strong><p>${telemetry.activity_profiled ? `of ${telemetry.activity_profiled} sourcetypes are older than 24 hours` : 'Freshness was not available at this discovery depth.'}</p></article>
    <article><span>DETECTION HEALTH</span><strong>${detections.enabled}/${detections.total}</strong><p>${detections.disabled} disabled · ${detections.missing_time_bounds_count} missing time bounds</p></article>
    <article><span>DATA-MODEL READINESS</span><strong>${models.accelerated}/${models.total}</strong><p>${models.disabled} disabled · acceleration reported for ${models.accelerated}</p></article>
    <article><span>SPLUNK MLTK MODELS</span><strong>${mltk.observed ?? '—'}</strong><p>${mltk.observed == null ? 'Run standard or deep discovery to inventory Splunk-native models.' : `${(mltk.changed || 0) + (mltk.missing || 0)} drift signals · ${mltk.dependencies_not_observed || 0} dependencies to verify`}</p></article>
    <article><span>REUSABLE KNOWLEDGE</span><strong>${result.knowledge_artifacts?.length || 0}</strong><p>Focused latest-state documents indexed for later RAG answers</p></article>`;
  const analysis = result.model_analysis || {};
  $('#discoveryAssessment').hidden = false;
  if (['complete','partial'].includes(analysis.status)) {
    const specialistPasses = analysis.specialist_enrichment?.passes || [];
    const modelPasses = analysis.passes || [];
    const passes = [...specialistPasses, ...modelPasses];
    const complete = passes.filter(item => item.status === 'complete').length;
    const reused = passes.filter(item => item.reused).length;
    $('#assessmentModel').textContent = `${complete}/${passes.length} roles · ${reused ? `${reused} reused · ` : ''}local only`;
    const priorities = Array.isArray(analysis.priorities) ? analysis.priorities : [];
    const synthesis = analysis.general_synthesis || {};
    const security = analysis.security_assessment || {};
    const entities = analysis.specialist_enrichment?.entities || [];
    const entityValidation = analysis.specialist_enrichment?.entity_validation || {};
    const suppressedEntities = Number(entityValidation.suppressed_count || 0);
    const suppressionReasonLabels = {
      'generic-catalog-term': ['generic catalog term', 'generic catalog terms'],
      'missing-explicit-security-context': ['label missing explicit security context', 'labels missing explicit security context'],
      'unvalidated-observable-format': ['unvalidated observable format', 'unvalidated observable formats'],
      'below-minimum-confidence': ['label below minimum confidence', 'labels below minimum confidence'],
      'below-semantic-confidence': ['semantic label below minimum confidence', 'semantic labels below minimum confidence'],
      'invalid-or-fragmented-value': ['invalid or fragmented value', 'invalid or fragmented values'],
      'unsupported-entity-type': ['unsupported entity type', 'unsupported entity types'],
      'duplicate': ['duplicate label', 'duplicate labels'],
      'output-limit': ['label beyond the display limit', 'labels beyond the display limit'],
    };
    const entitySuppressionReasons = Object.entries(entityValidation.reasons || {})
      .map(([reason, count]) => {
        const amount = Number(count);
        const labels = suppressionReasonLabels[reason] || ['unsupported label', 'unsupported labels'];
        return `${amount} ${labels[amount === 1 ? 0 : 1]}`;
      })
      .join(' · ');
    const matches = analysis.specialist_enrichment?.context_matches || [];
    const hypotheses = analysis.reconciliation?.risk_hypotheses || [];
    const opportunities = analysis.reconciliation?.detection_opportunities || [];
    const caveats = analysis.caveats || [];
    const passCards = passes.map(item => {
      const metrics = item.reused ? ['Reused exact input · 0 new inference'] : [`${Number(item.duration_seconds || 0).toFixed(1)}s`];
      if (item.result_count !== undefined) metrics.push(`${Number(item.result_count).toLocaleString()} results`);
      if (item.suppressed_count) metrics.push(`${Number(item.suppressed_count).toLocaleString()} suppressed`);
      if (item.attempt_count) metrics.push(`${item.attempt_count} attempt${item.attempt_count === 1 ? '' : 's'}`);
      if (item.structured_mode) metrics.push(item.structured_mode);
      if (item.input_chars) metrics.push(`${Math.round(Number(item.input_chars) / 100) / 10}K input chars`);
      if (item.output_token_limit) metrics.push(`${Number(item.output_token_limit).toLocaleString()} token cap`);
      const reason = item.status === 'complete' ? '' : `<small>${escapeHtml((item.reason || 'This role was unavailable.').slice(0, 320))}</small>`;
      if (item.reused && item.cache_source?.run_id) metrics.push(`from ${item.cache_source.run_id}`);
      return `<article class="model-team-pass ${escapeHtml(item.status || 'unavailable')} ${item.reused ? 'reused' : ''}"><header><span>${escapeHtml((item.role || 'specialist').replaceAll('-', ' '))}</span><b>${item.reused ? 'reused' : escapeHtml(item.status || 'unknown')}</b></header><h4>${escapeHtml(item.label || item.profile || 'Local specialist')}</h4><p>${escapeHtml(metrics.join(' · '))}</p>${reason}</article>`;
    }).join('');
    $('#assessmentContent').innerHTML = `
      <div class="model-team-pass-grid">${passCards}</div>
      <section class="model-team-section"><span class="model-team-kicker">RECONCILED SECURITY ASSESSMENT</span><p class="assessment-summary">${escapeHtml(analysis.executive_summary || synthesis.environment_summary || 'The local model team completed its evidence-bounded review.')}</p></section>
      ${synthesis.environment_summary ? `<section class="model-team-section"><h4>Environment synthesis</h4><p>${escapeHtml(synthesis.environment_summary)}</p>${(synthesis.material_observations || []).length ? `<ul>${synthesis.material_observations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}</section>` : ''}
      ${priorities.length ? `<section class="model-team-section"><h4>Evidence-linked priorities</h4><div class="priority-list">${priorities.slice(0,8).map((item,index) => `<article class="${escapeHtml(item.validation_status || 'needs-validation')}"><span>${index+1}</span><div><header><b>${escapeHtml(item.title || 'Priority')}</b><em class="severity ${escapeHtml(item.severity || 'medium')}">${escapeHtml(item.severity || 'medium')}</em></header><p>${escapeHtml(item.why || '')}</p><small>Owner: ${escapeHtml(item.owner || 'Unassigned')} · Next: ${escapeHtml(item.next_step || 'Validate')}</small><div class="evidence-ref-row">${(item.evidence_refs || []).map(ref => `<code>${escapeHtml(ref)}</code>`).join('')}${item.validation_status === 'needs-validation' ? '<b>Needs evidence validation</b>' : ''}</div></div></article>`).join('')}</div></section>` : ''}
      ${hypotheses.length ? `<section class="model-team-section"><h4>Security hypotheses</h4><div class="model-intelligence-grid">${hypotheses.slice(0,6).map(item => `<article><span>${escapeHtml(item.confidence || 'low')} confidence</span><b>${escapeHtml(item.title)}</b><p>${escapeHtml(item.basis)}</p><small>${escapeHtml(item.validation)}</small><div class="evidence-ref-row">${(item.evidence_refs || []).map(ref => `<code>${escapeHtml(ref)}</code>`).join('')}</div></article>`).join('')}</div></section>` : ''}
      ${opportunities.length ? `<section class="model-team-section"><h4>Detection opportunities</h4><div class="model-intelligence-grid">${opportunities.slice(0,6).map(item => `<article><span>${escapeHtml(item.validation_status || 'needs-validation')}</span><b>${escapeHtml(item.title)}</b><p>${escapeHtml(item.rationale)}</p><small>${escapeHtml(item.validation)}</small><div class="evidence-ref-row">${(item.evidence_refs || []).map(ref => `<code>${escapeHtml(ref)}</code>`).join('')}</div></article>`).join('')}</div></section>` : ''}
      ${(entities.length || matches.length || suppressedEntities) ? `<section class="model-team-section securebert-context"><h4>Validated SecureBERT context</h4><p class="entity-contract">Entity labels are candidates, not findings. SignalRoom promotes only concrete observables or semantic labels supported by explicit source evidence; a label never establishes maliciousness by itself.</p>${entities.length ? `<h5>Evidence-supported entity candidates</h5><div class="discovery-entity-row">${entities.slice(0,20).map(item => `<span title="${escapeHtml(item.evidence_excerpt || 'Validated from bounded discovery evidence')}"><b>${escapeHtml(item.type)}</b>${escapeHtml(item.value)}<small>${escapeHtml(item.evidence_ref || 'bounded evidence')} · ${Math.round(Number(item.confidence || 0) * 100)}%</small></span>`).join('')}</div>` : '<p class="entity-empty">No entity labels met the evidence-validation contract in this run.</p>'}${suppressedEntities ? `<details class="entity-suppression"><summary>${suppressedEntities} unsupported NER label${suppressedEntities === 1 ? '' : 's'} suppressed before synthesis and RAG</summary>${entitySuppressionReasons ? `<p>${escapeHtml(entitySuppressionReasons)}</p>` : ''}</details>` : ''}${matches.length ? `<h5>Related local context</h5><div class="discovery-context-links">${matches.slice(0,6).map(item => `<button data-open-artifact="${escapeHtml(item.id.split(':')[0])}"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.source)} · ${Number(item.score || 0).toFixed(2)}</span></button>`).join('')}</div>` : ''}</section>` : ''}
      ${caveats.length ? `<details class="model-team-caveats"><summary>Model-team caveats and rejected claims (${caveats.length})</summary><ul>${caveats.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></details>` : ''}`;
  } else {
    $('#assessmentModel').textContent = analysis.strategy === 'deterministic-only' ? 'Quick · deterministic' : 'Deterministic fallback';
    $('#assessmentContent').innerHTML = `<p class="assessment-summary">${escapeHtml(analysis.reason || 'The local model team was unavailable. Deterministic findings and RAG knowledge were still created.')}</p>`;
  }
}

function renderDiscoveryFollowup(result) {
  $('#discoveryFollowup').hidden = false;
  const inventory = result.changes?.inventory || {};
  const changes = Object.entries(inventory).flatMap(([category, value]) => [
    ...(value.added || []).map(name => ({ category, direction:'added', name })),
    ...(value.removed || []).map(name => ({ category, direction:'removed', name }))
  ]);
  const coverageChanges = Object.entries(result.changes?.coverage || {}).map(([domain, value]) => ({ category:'coverage', direction:value.to ? 'gained' : 'lost', name:domain }));
  const allChanges = [...changes, ...coverageChanges];
  $('#changeLedger').innerHTML = result.changes?.baseline_available
    ? (allChanges.length ? `<div class="change-list">${allChanges.slice(0,30).map(item => `<button data-change-investigate="${escapeHtml(item.name)}" data-change-category="${escapeHtml(item.category)}"><span class="change-direction ${escapeHtml(item.direction)}">${escapeHtml(item.direction)}</span><b>${escapeHtml(item.name)}</b><em>${escapeHtml(item.category)}</em></button>`).join('')}</div>` : '<div class="empty-inline compact-empty">No inventory or coverage changes were detected.</div>')
    : '<div class="empty-inline compact-empty">Baseline created. The next discovery will show additions, removals, and coverage changes.</div>';
  const tracks = result.investigation_tracks || [];
  $('#investigationTracks').innerHTML = tracks.length ? tracks.map((track, index) => `<article class="track-card"><span>OPEN HYPOTHESIS ${index + 1}</span><h4>${escapeHtml(track.hypothesis)}</h4><p>${escapeHtml(track.why)}</p><b>Validate</b><p>${escapeHtml(track.validation)}</p><div class="finding-actions"><button data-track-investigate="${index}">Open investigation →</button><button data-track-case="${index}">Add to case</button></div></article>`).join('') : '<div class="empty-inline compact-empty">No open investigation tracks were generated.</div>';
}

async function saveSettings(event) {
  event.preventDefault();
  const demoWasEnabled = Boolean(state.settings.demo_mode);
  const settings = structuredClone(state.settings); delete settings.secrets;
  settings.configured = true; settings.demo_mode = $('#demoMode').checked;
  settings.splunk.name = $('#splunkName').value.trim() || 'Primary Splunk'; settings.splunk.url = normalizeSplunkEndpoint();
  settings.splunk.verify_ssl = $('#verifySplunkTls').checked;
  settings.splunk.ca_bundle = settings.splunk.verify_ssl ? ($('#splunkCaBundle').value.trim() || null) : null;
  settings.default_chat_model = $('#defaultModel').value; settings.security_reasoning_model = $('#securityModel').value;
  settings.specialist_runtime = $('#specialistRuntime').value;
  settings.huggingface_policy = $('#hfPolicy').value;
  settings.detection_repository = repositorySettingsPayload();
  settings.models.forEach(model => {
    if (model.provider === 'ollama') model.endpoint = $('#ollamaEndpoint').value.trim() || 'http://localhost:11434';
    if (model.id === settings.default_chat_model) model.model = $('#generalModelId').value.trim() || model.model;
    if (model.id === settings.security_reasoning_model) model.model = $('#securityModelId').value.trim() || model.model;
    if (model.id === settings.embedding_model) model.endpoint = $('#hfEmbeddingEndpoint').value.trim() || model.endpoint;
    if (model.id === settings.ner_model) model.endpoint = $('#hfNerEndpoint').value.trim() || model.endpoint;
  });
  try {
    state.workload = await api('/api/workload/policy', { method:'PUT', body:JSON.stringify(workloadPolicyPayload()) });
    state.settings = await api('/api/settings', { method:'PUT', body:JSON.stringify({ settings, splunk_token:$('#splunkToken').value || null, huggingface_token:$('#hfToken').value || null }) });
    hydrateSettings(); renderModels(); await loadConnections(); await loadModelReadiness(); await loadDetectionRepositoryStatus(); $('#settingsModal').hidden = true; $('#splunkToken').value = ''; $('#hfToken').value = ''; toast('Workspace saved');
    if (state.settings.demo_mode && !demoWasEnabled) startDemoTour();
  } catch (error) { toast(error.message); }
}

async function testConnection(kind, profileId, output) {
  output.textContent = 'Testing…'; output.className = 'test-result';
  try {
    const payload = { kind, profile_id:profileId || null };
    if (kind === 'splunk') {
      payload.demo_mode = $('#demoMode').checked;
      payload.splunk_token = $('#splunkToken').value || null;
      payload.splunk = {
        name: $('#splunkName').value.trim() || 'Primary Splunk',
        url: normalizeSplunkEndpoint(),
        verify_ssl: $('#verifySplunkTls').checked,
        ca_bundle: $('#verifySplunkTls').checked ? ($('#splunkCaBundle').value.trim() || null) : null
      };
    }
    const result = await api('/api/test-connection', { method:'POST', body:JSON.stringify(payload) });
    if (kind === 'splunk') {
      output.textContent = result.ready ? `${result.demo ? 'Demo client' : 'Splunk MCP'} ready · ${result.tool_count || 0} tools` : `Blocked at ${String(result.blocking_stage || 'preflight').replaceAll('-', ' ')}`;
      output.className = `test-result ${result.ready ? 'ok' : 'error'}`;
      renderConnectionDiagnostics(result, { setup:true });
      return result;
    }
    output.textContent = result.ok ? (result.generation_ok ? `Generated with ${result.executed_model}` : 'Connected') : result.error;
    output.className = `test-result ${result.ok ? 'ok' : 'error'}`; return result;
  } catch (error) { output.textContent = error.message; output.className = 'test-result error'; return { ok:false }; }
}

function normalizeSplunkEndpoint() {
  const input = $('#splunkUrl'); const raw = input.value.trim();
  try {
    const url = new URL(raw);
    if (url.pathname.replace(/\/$/, '') === '/service/mcp') {
      url.pathname = '/services/mcp'; input.value = url.toString().replace(/\/$/, '');
      toast('Corrected the Splunk MCP path to /services/mcp');
    }
  } catch (_) {}
  return input.value.trim();
}

function resizeComposer() { const input = $('#chatInput'); input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 150) + 'px'; }

function updateTlsControls() {
  const verified = $('#verifySplunkTls').checked;
  $('#tlsWarning').hidden = verified;
  $('#caBundleLabel').hidden = !verified;
}

function closeDetail() {
  clearTimeout(state.timeSeriesScheduleTimer);
  state.timeSeriesScheduleTimer = null;
  $('#detailModal').hidden = true;
  $('#detailModal').dataset.permalink = '';
  if (location.hash.startsWith('#context/artifact/')) history.replaceState(null, '', `${location.pathname}#context`);
}

function resetConversation() {
  state.conversationId = null; state.promptPath = [];
  $('#messages').innerHTML = '<article class="welcome-card"><p class="eyebrow">EVIDENCE-FIRST SECURITY ANALYSIS</p><h2>What are we looking for?</h2><p>Choose a role and workflow. SignalRoom will stage a reviewable prompt before it runs any tools.</p><div class="prompt-explorer" id="promptExplorer" aria-live="polite"></div></article>';
  renderPromptTree([]); renderEvidence([], [], []);
}

function handleDeepLink() {
  if (location.hash.startsWith('#investigate?')) {
    const params = new URLSearchParams(location.hash.split('?')[1]);
    openInvestigation(params.get('mode') || 'auto', params.get('prompt') || '', false);
  } else if (location.hash.startsWith('#context/artifact/')) {
    const id = decodeURIComponent(location.hash.slice('#context/artifact/'.length));
    setView('context'); openArtifactDetail(id, false);
  } else if (location.hash === '#context') setView('context');
  else if (location.hash.startsWith('#cases/')) {
    const id = decodeURIComponent(location.hash.slice('#cases/'.length));
    setView('cases'); openCase(id, false).catch(error => toast(error.message));
  } else if (location.hash === '#cases') setView('cases');
  else if (location.hash.startsWith('#detections/')) {
    const id = decodeURIComponent(location.hash.slice('#detections/'.length));
    setView('detections'); openDetection(id, false).catch(error => toast(error.message));
  } else if (location.hash === '#detections') setView('detections');
  else if (location.hash === '#discovery') setView('discovery');
  else if (location.hash === '#models') setView('models');
  else if (location.hash === '#context') setView('context');
  else {
    setView('chat');
    history.replaceState(null, '', `${location.pathname}#investigate`);
  }
}

function navigateView(name) {
  setView(name);
  const hashes = { chat:'#investigate', discovery:'#discovery', cases:'#cases', detections:'#detections', context:'#context', models:'#models' };
  history.replaceState(null, '', `${location.pathname}${hashes[name] || '#investigate'}`);
}

document.addEventListener('click', async event => {
  const diagnoseManaged = event.target.closest('[data-diagnose-managed-splunk]');
  if (diagnoseManaged) { await diagnoseManagedSplunk(diagnoseManaged.dataset.diagnoseManagedSplunk, diagnoseManaged); return; }
  const admitManaged = event.target.closest('[data-admit-managed-splunk]');
  if (admitManaged) { await setManagedSplunkAdmission(admitManaged.dataset.admitManagedSplunk, admitManaged.dataset.enabled === 'true', admitManaged); return; }
  const editManaged = event.target.closest('[data-edit-managed-splunk]');
  if (editManaged) { openManagedSplunkForm(editManaged.dataset.editManagedSplunk); return; }
  const archiveManaged = event.target.closest('[data-archive-managed-splunk]');
  if (archiveManaged) { await archiveManagedSplunk(archiveManaged.dataset.archiveManagedSplunk); return; }
  const saveAccess = event.target.closest('[data-save-auth-user]');
  if (saveAccess) { await saveAuthUser(saveAccess); return; }
  const openDetectionButton = event.target.closest('[data-open-detection]');
  if (openDetectionButton) { setView('detections'); await openDetection(openDetectionButton.dataset.openDetection); return; }
  const createDetectionButton = event.target.closest('[data-create-detection]');
  if (createDetectionButton) { await createDetectionFromValidation(createDetectionButton.dataset.createDetection); return; }
  if (event.target.closest('[data-run-detection-gate]')) { await runDetectionGate(); return; }
  if (event.target.closest('[data-detection-validation-draft]')) { await queueDetectionValidationDraft(); return; }
  if (event.target.closest('[data-submit-detection]')) { await submitDetection(); return; }
  const reviewDetectionButton = event.target.closest('[data-review-detection]');
  if (reviewDetectionButton) { await reviewDetection(reviewDetectionButton.dataset.reviewDetection); return; }
  if (event.target.closest('[data-export-detection]')) { await exportDetection(); return; }
  if (event.target.closest('[data-export-detection-git]')) { await exportDetectionGitChange(); return; }
  if (event.target.closest('[data-preview-repository]')) { await previewDetectionRepository(); return; }
  if (event.target.closest('[data-apply-repository]')) { await applyDetectionRepository(); return; }
  if (event.target.closest('[data-push-repository]')) { await pushDetectionRepository(); return; }
  if (event.target.closest('[data-pull-request-repository]')) { await openDetectionRepositoryPullRequest(); return; }
  if (event.target.closest('[data-refresh-repository-review]')) { await refreshDetectionRepositoryReview(); return; }
  if (event.target.closest('[data-preserve-repository-review]')) { await preserveDetectionRepositoryReview(); return; }
  const repositoryCase = event.target.closest('[data-open-repository-case]');
  if (repositoryCase) { setView('cases'); await openCase(repositoryCase.dataset.openRepositoryCase); return; }
  if (event.target.closest('[data-refresh-deployment]')) { await refreshDetectionDeployment(); return; }
  if (event.target.closest('[data-preserve-deployment]')) { await preserveDetectionDeployment(); return; }
  if (event.target.closest('[data-stage-runtime]')) { await stageDetectionRuntime(); return; }
  if (event.target.closest('[data-assess-runtime]')) { await assessDetectionRuntime(); return; }
  if (event.target.closest('[data-preserve-runtime]')) { await preserveDetectionRuntime(); return; }
  const runtimeValidation = event.target.closest('[data-open-runtime-validation]');
  if (runtimeValidation) { await openRuntimeValidation(runtimeValidation.dataset.openRuntimeValidation); return; }
  const runtimeCase = event.target.closest('[data-open-runtime-case]');
  if (runtimeCase) { setView('cases'); await openCase(runtimeCase.dataset.openRuntimeCase); return; }
  const deploymentCase = event.target.closest('[data-open-deployment-case]');
  if (deploymentCase) { setView('cases'); await openCase(deploymentCase.dataset.openDeploymentCase); return; }
  if (event.target.closest('[data-retire-detection]')) { await retireDetection(); return; }
  if (event.target.closest('[data-delete-detection]')) { await deleteDetection(); return; }
  if (event.target.closest('[data-detection-investigate]')) { investigateDetection(); return; }
  if (event.target.closest('#showDetectionCandidates')) {
    $('#detectionCandidatesPanel').scrollIntoView({behavior:'smooth',block:'start'});
    return;
  }
  const editEvaluationSuite = event.target.closest('[data-edit-evaluation-suite]');
  if (editEvaluationSuite) { await openEvaluationSuite(editEvaluationSuite.dataset.editEvaluationSuite); return; }
  const evaluationScenario = event.target.closest('[data-evaluation-scenario]');
  if (evaluationScenario) {
    syncEvaluationScenario();
    state.evaluationScenarioIndex = Number(evaluationScenario.dataset.evaluationScenario);
    renderEvaluationScenarioEditor();
    return;
  }
  if (event.target.closest('#removeEvaluationScenario')) {
    syncEvaluationScenario();
    state.evaluationDraft?.draft_scenarios.splice(state.evaluationScenarioIndex, 1);
    state.evaluationScenarioIndex = Math.max(0, Math.min(state.evaluationScenarioIndex, (state.evaluationDraft?.draft_scenarios.length || 1) - 1));
    renderEvaluationScenarioEditor();
    return;
  }
  if (event.target.closest('.close-evaluation-suite')) {
    $('#evaluationSuiteModal').hidden = true; state.evaluationDraft = null; return;
  }
  const tournamentReview = event.target.closest('[data-tournament-review]');
  if (tournamentReview) { await reviewTournamentPair(tournamentReview); return; }
  const tournamentPromotion = event.target.closest('[data-promote-tournament]');
  if (tournamentPromotion) { await promoteModelTournament(tournamentPromotion); return; }
  const tournamentRollback = event.target.closest('[data-rollback-promotion]');
  if (tournamentRollback) { await rollbackModelPromotion(tournamentRollback); return; }
  const approveArtifact = event.target.closest('[data-approve-model-artifact]');
  if (approveArtifact) { await approveModelArtifact(approveArtifact); return; }
  const revokeAttestation = event.target.closest('[data-revoke-model-attestation]');
  if (revokeAttestation) { await revokeModelAttestation(revokeAttestation); return; }
  const showTournament = event.target.closest('[data-show-tournament]');
  if (showTournament && state.goldenBenchmarks?.tournament) {
    state.selectedTournamentId = showTournament.dataset.showTournament;
    renderModelTournaments();
    $('#tournamentLatest').scrollIntoView({behavior:'smooth',block:'start'});
    return;
  }
  const acceptGolden = event.target.closest('[data-accept-golden-baseline]');
  if (acceptGolden) { await acceptGoldenBaseline(acceptGolden.dataset.acceptGoldenBaseline); return; }
  const showGolden = event.target.closest('[data-show-golden-run]');
  if (showGolden && state.goldenBenchmarks) {
    const run = state.goldenBenchmarks.runs.find(item => item.id === showGolden.dataset.showGoldenRun);
    if (run) { $('#goldenBenchmarkLatest').innerHTML = renderGoldenRun(run); $('#goldenBenchmarkLatest').scrollIntoView({behavior:'smooth',block:'start'}); }
    return;
  }
  const feedback = event.target.closest('[data-feedback-rating]');
  if (feedback) { await recordAnalystFeedback(feedback); return; }
  const assuranceNotice = event.target.closest('[data-ack-assurance]');
  if (assuranceNotice) { await acknowledgeAssurance(assuranceNotice.dataset.ackAssurance); return; }
  const reviewAssurance = event.target.closest('[data-review-assurance-package]');
  if (reviewAssurance) { await reviewAssurancePackage(reviewAssurance.dataset.reviewAssurancePackage); return; }
  const investigateAssurance = event.target.closest('[data-investigate-assurance-package]');
  if (investigateAssurance) { investigateAssurancePackage(investigateAssurance.dataset.investigateAssurancePackage); return; }
  const caseAssurance = event.target.closest('[data-case-assurance-package]');
  if (caseAssurance) { caseAssurancePackage(caseAssurance.dataset.caseAssurancePackage); return; }
  const closeAssurance = event.target.closest('[data-close-assurance-package]');
  if (closeAssurance) { await closeAssurancePackage(closeAssurance.dataset.closeAssurancePackage); return; }
  const previewDelivery = event.target.closest('[data-preview-assurance-delivery]');
  if (previewDelivery) { await previewAssuranceDelivery(previewDelivery.dataset.previewAssuranceDelivery); return; }
  const reconcileOutbound = event.target.closest('[data-reconcile-delivery]');
  if (reconcileOutbound) { await reconcileDelivery(reconcileOutbound); return; }
  const retryOutbound = event.target.closest('[data-retry-delivery]');
  if (retryOutbound) { await retryDelivery(retryOutbound.dataset.retryDelivery); return; }
  const cancelOutbound = event.target.closest('[data-cancel-delivery]');
  if (cancelOutbound) { await cancelDelivery(cancelOutbound.dataset.cancelDelivery); return; }
  const copyToggle = event.target.closest('[data-toggle-copy]');
  if (copyToggle) {
    const card = copyToggle.closest('.evidence-card,.ledger-item');
    const expanded = card.classList.toggle('expanded');
    copyToggle.textContent = expanded ? 'Show less' : 'Show more';
    return;
  }
  const nav = event.target.closest('[data-view]'); if (nav) navigateView(nav.dataset.view);
  const queueValidationButton = event.target.closest('[data-queue-validation]');
  if (queueValidationButton && !queueValidationButton.disabled) { await queueValidation(queueValidationButton.dataset.queueValidation); return; }
  const editValidationButton = event.target.closest('[data-edit-validation]');
  if (editValidationButton) {
    const task = state.validations.find(item => item.id === editValidationButton.dataset.editValidation);
    if (task) openValidationEditor(task);
    return;
  }
  const approveValidationButton = event.target.closest('[data-approve-validation]');
  if (approveValidationButton) { await approveValidation(approveValidationButton.dataset.approveValidation); return; }
  const runValidationButton = event.target.closest('[data-run-validation]');
  if (runValidationButton) { await runValidation(runValidationButton.dataset.runValidation); return; }
  const inspectValidationButton = event.target.closest('[data-inspect-validation]');
  if (inspectValidationButton) {
    const task = state.validations.find(item => item.id === inspectValidationButton.dataset.inspectValidation);
    if (task) openValidationResult(task);
    return;
  }
  const deleteValidationButton = event.target.closest('[data-delete-validation]');
  if (deleteValidationButton) { await deleteValidation(deleteValidationButton.dataset.deleteValidation); return; }
  if (event.target.closest('.close-validation')) { $('#validationModal').hidden = true; state.editingValidationId = null; return; }
  const modelRecommendation = event.target.closest('[data-use-model-recommendation]');
  if (modelRecommendation) {
    const item = state.modelRecommendations[modelRecommendation.dataset.useModelRecommendation];
    if (!item) return;
    if (item.availability === 'install-required') {
      $('#settingsModal').hidden = false;
      const localRow = $(`[data-local-profile="${CSS.escape(item.profile_id)}"]`);
      if (localRow) localRow.scrollIntoView({ behavior:'smooth', block:'center' });
      toast('Local-first selected. Install this specialist once; future inference stays on this host.');
      return;
    }
    if (item.availability === 'disabled' || item.availability === 'unavailable') {
      $('#settingsModal').hidden = false;
      $('#hfPolicy').scrollIntoView({ behavior:'smooth', block:'center' });
      setTimeout(() => $('#hfPolicy').focus(), 250);
      toast(item.availability === 'disabled' ? 'Local-only policy respected. Review HF only if this specialist pass is worth an external call.' : 'Configure Hugging Face access to use this specialist.');
      return;
    }
    setView('chat');
    $('#investigationMode').value = item.mode || 'auto';
    if (item.specialist === 'chat') $('#modelSelect').value = item.profile_id;
    await sendChat(item.prompt, {
      modelProfile:item.specialist === 'chat' ? item.profile_id : ($('#modelSelect').value || null),
      mode:item.mode || 'auto',
      approveHf:item.external,
      hfSpecialist:item.specialist === 'chat' ? null : item.specialist
    });
    return;
  }
  const prompt = event.target.closest('[data-prompt]'); if (prompt) { setView('chat'); sendChat(prompt.dataset.prompt); }
  const persona = event.target.closest('[data-prompt-persona]'); if (persona) renderPromptTree([persona.dataset.promptPersona]);
  const workflow = event.target.closest('[data-prompt-workflow]'); if (workflow) renderPromptTree([state.promptPath[0], workflow.dataset.promptWorkflow]);
  if (event.target.closest('[data-prompt-back]')) renderPromptTree(state.promptPath.slice(0, -1));
  const usePrompt = event.target.closest('[data-use-prompt]');
  if (usePrompt) {
    const item = PROMPT_TREE[state.promptPath[0]].workflows[state.promptPath[1]].prompts[Number(usePrompt.dataset.usePrompt)];
    openInvestigation(item.mode, item.text);
  }
  const ledger = event.target.closest('[data-open-ledger]'); if (ledger) openLedgerDetail(ledger.dataset.openLedger);
  const artifact = event.target.closest('[data-open-artifact]'); if (artifact) openArtifactDetail(artifact.dataset.openArtifact);
  const openSavedCase = event.target.closest('[data-open-case]'); if (openSavedCase) openCase(openSavedCase.dataset.openCase);
  const repositoryDetection = event.target.closest('[data-open-repository-detection]');
  if (repositoryDetection) { setView('detections'); await openDetection(repositoryDetection.dataset.openRepositoryDetection); return; }
  const caseInvestigate = event.target.closest('[data-case-investigate]');
  if (caseInvestigate && state.caseCockpit) {
    openInvestigation('triage', `Continue this case using the bounded case context below. Reuse it before requesting new SPL.\n\n${state.caseCockpit.context_packet}\n\nGoal: Review the evidence state and recommend the single highest-value next action.`, false);
  }
  const caseNextAction = event.target.closest('[data-case-next-action]');
  if (caseNextAction && state.caseCockpit) {
    const action = state.caseCockpit.next_actions[Number(caseNextAction.dataset.caseNextAction)];
    if (action?.kind === 'review-validation') {
      setView('discovery');
      const node = document.querySelector(`[data-validation-id="${CSS.escape(action.validation_task_id)}"]`);
      if (node) { node.scrollIntoView({ behavior:'smooth', block:'center' }); node.classList.add('package-focus'); setTimeout(() => node.classList.remove('package-focus'), 2800); }
      toast('Case-linked validation staged for review');
    } else if (action?.prompt) {
      openInvestigation('triage', `${action.prompt}\n\nCase context:\n${state.caseCockpit.context_packet}`, false);
    }
  }
  const artifactInvestigation = event.target.closest('[data-artifact-investigate]');
  if (artifactInvestigation) {
    const item = state.artifacts.find(entry => entry.id === artifactInvestigation.dataset.artifactInvestigate);
    if (item) openInvestigation('general', `Use the context artifact titled "${item.title}" to start an evidence-led investigation. Explain its relevance, limitations, and next validation step.`, false);
  }
  const artifactCase = event.target.closest('[data-artifact-case]');
  if (artifactCase) {
    const item = state.artifacts.find(entry => entry.id === artifactCase.dataset.artifactCase);
    if (item) openCasePicker({ kind:'evidence', title:item.title, content:item.content.slice(0, 50000), source:item.source, confidence:'unknown', status:'unverified', metadata:{ artifact_id:item.id, artifact_kind:item.kind, tags:item.tags } });
  }
  const detailAction = event.target.closest('[data-detail-action]');
  if (detailAction) {
    const action = state.detailActions[Number(detailAction.dataset.detailAction)];
    if (action.kind === 'prompt') { closeDetail(); openInvestigation(action.mode || 'auto', action.prompt, false); }
    if (action.kind === 'artifact') { closeDetail(); setView('context'); openArtifactDetail(action.target); }
    if (action.kind === 'detection') { closeDetail(); setView('detections'); await openDetection(action.target); }
    if (action.kind === 'detection-create') { closeDetail(); await createDetectionFromValidation(action.target); }
    if (action.kind === 'context-search') { closeDetail(); setView('context'); $('#contextSearch').value = action.target; $('#contextSearch').dispatchEvent(new Event('input')); }
    if (action.kind === 'discovery') { closeDetail(); setView('discovery'); }
    if (action.kind === 'case-item') { closeDetail(); openCasePicker(action.item); }
    if (action.kind === 'edit-artifact') {
      const item = state.artifacts.find(entry => entry.id === action.target);
      closeDetail(); if (item) openArtifactEditor(item);
    }
    if (action.kind === 'delete-artifact') await removeArtifact(action.target);
  }
  if (event.target.closest('[data-copy-detail-link]')) copyDetailLink();
  if (event.target.closest('.close-detail')) closeDetail();
  const finding = event.target.closest('[data-discovery-finding]');
  if (finding) {
    const item = state.lastDiscovery.findings[Number(finding.dataset.discoveryFinding)];
    openInvestigation('discovery', `Investigate this discovery finding. Separate the observed evidence from hypotheses and create read-only validation steps.\n\nFinding: ${item.title}\nEvidence: ${item.evidence}\nSuggested next step: ${item.next_step}`, false);
  }
  const findingCase = event.target.closest('[data-discovery-case]');
  if (findingCase) {
    const item = state.lastDiscovery.findings[Number(findingCase.dataset.discoveryCase)];
    openCasePicker({ kind:'observation', title:item.title, content:`Evidence: ${item.evidence}\n\nSuggested next step: ${item.next_step}`, source:'Splunk discovery', confidence:'medium', status:'needs-validation', metadata:{ severity:item.severity } });
  }
  const track = event.target.closest('[data-track-investigate]');
  if (track) {
    const item = state.lastDiscovery.investigation_tracks[Number(track.dataset.trackInvestigate)];
    openInvestigation('hunt', `Investigate this hypothesis with bounded read-only steps.\n\nHypothesis: ${item.hypothesis}\nWhy: ${item.why}\nInitial validation: ${item.validation}`, false);
  }
  const trackCase = event.target.closest('[data-track-case]');
  if (trackCase) {
    const item = state.lastDiscovery.investigation_tracks[Number(trackCase.dataset.trackCase)];
    openCasePicker({ kind:'hypothesis', title:item.hypothesis, content:`Why: ${item.why}\n\nInitial validation: ${item.validation}`, source:'SignalRoom discovery', confidence:'medium', status:'needs-validation', metadata:{} });
  }
  const change = event.target.closest('[data-change-investigate]');
  if (change) openInvestigation('discovery', `Explain and validate this change since the previous discovery: ${change.dataset.changeCategory} ${change.dataset.changeInvestigate}. Determine whether it is a real posture change or a collection issue.`, false);
  if (event.target.closest('#openSettings,#configureModels,[data-open-settings]')) { $('#settingsModal').hidden = false; loadWorkload(); loadConnections(); }
  if (event.target.closest('#closeSettings')) $('#settingsModal').hidden = true;
  if (event.target.closest('#addArtifact')) openArtifactEditor();
  if (event.target.closest('.close-artifact')) { $('#artifactModal').hidden = true; state.editingArtifactId = null; }
  if (event.target.closest('#uploadArtifact')) $('#fileInput').click();
  const editArtifact = event.target.closest('[data-edit-artifact]');
  if (editArtifact) {
    const item = state.artifacts.find(entry => entry.id === editArtifact.dataset.editArtifact);
    if (item) openArtifactEditor(item);
  }
  const deleteButton = event.target.closest('[data-delete]');
  if (deleteButton) await removeArtifact(deleteButton.dataset.delete);
  const test = event.target.closest('[data-test-model]');
  if (test) { const dot = $(`#status-${CSS.escape(test.dataset.testModel)}`); dot.classList.remove('ok'); const holder = document.createElement('span'); const result = await testConnection('model', test.dataset.testModel, holder); dot.classList.toggle('ok', result.ok); toast(holder.textContent); }
  if (event.target.closest('[data-open-code-screen]')) openCodeScreening();
  if (event.target.closest('[data-open-time-series]')) openTimeSeriesWorkbench();
  const runForecastSchedule = event.target.closest('[data-run-forecast-schedule]');
  if (runForecastSchedule) { await runTimeSeriesSchedule(runForecastSchedule); return; }
  const toggleForecastSchedule = event.target.closest('[data-toggle-forecast-schedule]');
  if (toggleForecastSchedule) { await toggleTimeSeriesSchedule(toggleForecastSchedule); return; }
  const archiveForecastSchedule = event.target.closest('[data-archive-forecast-schedule]');
  if (archiveForecastSchedule) { await archiveTimeSeriesSchedule(archiveForecastSchedule); return; }
  if (event.target.closest('[data-review-model-trust]')) {
    if (!$('#detailModal').hidden) closeDetail();
    $('#modelTrustPanel').scrollIntoView({behavior:'smooth', block:'start'});
    toast('Review and approve the exact installed artifact in the local supply-chain panel');
  }
  if (event.target.closest('[data-time-series-case]') && state.timeSeriesResult) {
    const result = state.timeSeriesResult; const gate = result.promotion_gate || {}; const backtest = result.backtest || {};
    openCasePicker({
      kind:'observation',
      title:result.title,
      content:`Local Cisco TSM forecast: ${gate.decision}\nMASE vs naive: ${backtest.mase_vs_last_value == null ? 'undefined' : Number(backtest.mase_vs_last_value).toFixed(3)}\nImputation: ${Math.round(Number(result.series.imputation_ratio || 0) * 100)}%\nContext points: ${result.series.expected_points}\nForecast horizon: ${result.forecast?.horizon || 0}\n\nSPL: ${result.source.spl}\nWindow: ${result.source.earliest_time} to ${result.source.latest_time}\nQuery fingerprint: ${result.source.query_fingerprint}\nSeries SHA-256: ${result.series_sha256}\nModel revision: ${result.runtime.source_revision || 'not attested'}\n\nThis is advisory forecast evidence. It did not change an alert, threshold, or capacity decision.`,
      source:'SignalRoom · local Cisco Time Series Model',
      confidence:gate.ready ? 'medium' : 'low',
      status:'needs-validation',
      metadata:{forecast_run_id:result.run_id,query_fingerprint:result.source.query_fingerprint,series_sha256:result.series_sha256,model_revision:result.runtime.source_revision || '',promotion_decision:gate.decision,network_inference:false}
    });
  }
  if (event.target.closest('[data-time-series-investigate]') && state.timeSeriesResult) {
    const result = state.timeSeriesResult; const gate = result.promotion_gate || {}; const backtest = result.backtest || {};
    closeDetail();
    openInvestigation('discovery', `Interpret this local time-series forecast as advisory operational evidence. Explain plausible security or ingestion meanings, separate seasonality and collection artifacts from actionable change, and propose the single safest bounded validation step. Do not treat the forecast as an alert.\n\nTitle: ${result.title}\nSource SPL: ${result.source.spl}\nWindow: ${result.source.earliest_time} to ${result.source.latest_time}\nInterval: ${result.source.interval_seconds} seconds\nContext: ${result.series.expected_points} points; ${Math.round(Number(result.series.imputation_ratio || 0) * 100)}% imputed\nBacktest MASE vs last-value: ${backtest.mase_vs_last_value == null ? 'undefined' : Number(backtest.mase_vs_last_value).toFixed(3)}\nPromotion decision: ${gate.decision}\nReasons: ${(gate.reasons || []).join(' ')}`, false);
  }
  if (event.target.closest('[data-code-screen-case]') && state.codeScreenResult) {
    const result = state.codeScreenResult; const prediction = result.prediction || {};
    openCasePicker({
      kind:'observation',
      title:'Assistive code vulnerability screen',
      content:`Signal: ${prediction.signal}\nConfidence: ${Math.round(Number(prediction.confidence || 0) * 100)}%\nLanguage: ${result.language}\nInput SHA-256: ${result.input_sha256}\nEvaluated tokens: ${result.evaluated_tokens}/${result.input_tokens}${result.truncated ? ' (truncated)' : ''}\n\nThis is a local model review priority, not a vulnerability finding. Corroborate with static analysis and expert code review.`,
      source:`${result.model} · local Transformers`,
      confidence:'low',
      status:'needs-validation',
      metadata:{model_profile:result.profile_id,input_sha256:result.input_sha256,network_inference:false,source_persisted:false}
    });
  }
  const pull = event.target.closest('[data-pull-profile]');
  if (pull) pullModel(pull.dataset.pullProfile, pull);
  const activate = event.target.closest('[data-activate-model]');
  if (activate) activateModel(activate.dataset.activateModel, activate);
  if (event.target.closest('#checkModelUpdates')) checkModelUpdates(event.target.closest('#checkModelUpdates'));
  const contextKind = event.target.closest('[data-context-kind]');
  if (contextKind) {
    state.contextKind = contextKind.dataset.contextKind;
    state.contextPage = 1;
    $$('[data-context-kind]').forEach(button => button.classList.toggle('active', button === contextKind));
    renderArtifacts(filterArtifacts(state.artifacts));
  }
  if (event.target.closest('#newCase')) { state.pendingCaseItem = null; $('#caseForm').reset(); $('#newCaseSeverity').value = 'medium'; $('#caseModal').hidden = false; }
  if (event.target.closest('.close-case-modal')) { $('#caseModal').hidden = true; state.pendingCaseItem = null; }
  if (event.target.closest('[data-add-case-item]')) openCaseItemModal();
  if (event.target.closest('.close-case-item')) { $('#caseItemModal').hidden = true; state.pendingCaseItem = null; state.editingCaseItemId = null; }
  if (event.target.closest('.close-case-picker')) { $('#casePickerModal').hidden = true; state.pendingCaseItem = null; }
  if (event.target.closest('.close-delivery-preview')) { $('#deliveryPreviewModal').hidden = true; state.deliveryPreview = null; }
  if (event.target.closest('#pickerNewCase')) { $('#casePickerModal').hidden = true; $('#caseForm').reset(); $('#newCaseSeverity').value = 'medium'; $('#caseModal').hidden = false; }
  const pickedCase = event.target.closest('[data-pick-case]');
  if (pickedCase && state.pendingCaseItem) { $('#casePickerModal').hidden = true; await addItemToCase(pickedCase.dataset.pickCase, state.pendingCaseItem); setView('cases'); }
  if (event.target.closest('[data-save-case]') && state.activeCase) {
    state.activeCase = await api(scopedUrl(`/api/cases/${encodeURIComponent(state.activeCase.id)}`), { method:'PATCH', body:JSON.stringify({ title:$('#caseTitleInput').value.trim(), owner:$('#caseOwner').value.trim() || 'Unassigned', status:$('#caseStatus').value, severity:$('#caseSeverity').value, summary:$('#caseSummary').value.trim(), tags:$('#caseTags').value.split(',').map(value => value.trim()).filter(Boolean) }) });
    await loadCases(); toast('Case details saved');
  }
  if (event.target.closest('[data-delete-case]') && state.activeCase) {
    const item = state.activeCase;
    if (confirm(`Delete case “${item.title}” and all ${item.item_count} timeline items? This cannot be undone.`)) {
      await api(scopedUrl(`/api/cases/${encodeURIComponent(item.id)}`), { method:'DELETE' });
      state.activeCase = null; await loadCases();
      $('#caseDetail').innerHTML = '<div class="case-empty"><div class="empty-glyph">▰</div><h3>Select or create a case</h3><p>Cases connect SignalRoom evidence to ownership, decisions, and a reviewable handoff timeline.</p></div>';
      history.replaceState(null, '', `${location.pathname}#cases`); toast('Case deleted');
    }
  }
  if (event.target.closest('[data-export-case]')) exportActiveCase();
  const editCaseItem = event.target.closest('[data-edit-case-item]');
  if (editCaseItem && state.activeCase) {
    const item = state.activeCase.items.find(entry => entry.id === editCaseItem.dataset.editCaseItem);
    if (item) openCaseItemModal(item);
  }
  const deleteCaseItem = event.target.closest('[data-delete-case-item]');
  if (deleteCaseItem && state.activeCase && confirm('Remove this item from the case timeline?')) {
    await api(scopedUrl(`/api/cases/${encodeURIComponent(state.activeCase.id)}/items/${encodeURIComponent(deleteCaseItem.dataset.deleteCaseItem)}`), { method:'DELETE' });
    await loadCases(); toast('Timeline item removed');
  }
});

$('#chatForm').addEventListener('submit', event => { event.preventDefault(); sendChat($('#chatInput').value); });
$('#loginForm').addEventListener('submit', signIn);
$('#logoutButton').addEventListener('click', signOut);
$('#enableRbac').addEventListener('click', enableRbac);
$('#disableRbac').addEventListener('click', disableRbac);
$('#createAuthUser').addEventListener('click', createAuthUser);
$('#saveOidcPolicy').addEventListener('click', saveOidcPolicy);
$('#testOidcProvider').addEventListener('click', testOidcProvider);
$('#chatInput').addEventListener('input', resizeComposer);
$('#chatInput').addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); $('#chatForm').requestSubmit(); } });
$('#newConversation').addEventListener('click', resetConversation);
$('#scopeSelect').addEventListener('change', event => switchScope(event.target.value).catch(error => toast(error.message)));
$('#startDemoTour').addEventListener('click', startDemoTour);
$('#demoTourClose').addEventListener('click', finishDemoTour);
$('#demoTourBack').addEventListener('click', () => showDemoTourStep(state.demoTourStep - 1));
$('#demoTourNext').addEventListener('click', () => {
  if (state.demoTourStep >= DEMO_TOUR_STEPS.length - 1) finishDemoTour();
  else showDemoTourStep(state.demoTourStep + 1);
});
$('#toggleEvidence').addEventListener('click', () => $('.evidence-panel').classList.add('mobile-open'));
$('#closeEvidence').addEventListener('click', () => $('.evidence-panel').classList.remove('mobile-open'));
$('#runDiscovery').addEventListener('click', runDiscovery);
$('#cancelDiscoveryJob').addEventListener('click', cancelDiscoveryJob);
$('#discoveryJobHistory').addEventListener('click', event => {
  const target = event.target.closest('[data-inspect-discovery-job]');
  if (target) inspectDiscoveryJob(target.dataset.inspectDiscoveryJob);
});
$('#runConnectionDiagnostics').addEventListener('click', runConnectionDiagnostics);
$('#assuranceForm').addEventListener('submit', saveAssurancePolicy);
$('#deliveryForm').addEventListener('submit', saveDeliveryPolicy);
$('#auditExportForm').addEventListener('submit', saveAuditExportPolicy);
$('#auditOperationsForm').addEventListener('submit', saveAuditOperationsPolicy);
$('#modelTrustPolicyForm').addEventListener('submit', saveModelTrustPolicy);
$('#approveDelivery').addEventListener('click', approveDeliveryPreview);
$('#testDeliveryDestination').addEventListener('click', testDeliveryDestination);
$('#testSoarDeliveryDestination').addEventListener('click', testDeliveryDestination);
$('#runAuditExport').addEventListener('click', runAuditExportNow);
$('#previewAuditOperations').addEventListener('click', previewAuditOperations);
$('#exportAuditOperations').addEventListener('click', exportAuditOperations);
$('#runAssuranceNow').addEventListener('click', runAssuranceNow);
$('#cancelAssuranceRun').addEventListener('click', cancelAssuranceRun);
$('#assuranceDepth').addEventListener('change', updateAssuranceBudgetHelp);
$('#deliveryKind').addEventListener('change', () => {
  updateDeliveryAdapter();
  $('#deliveryTestResult').className = '';
  $('#deliveryTestResult').textContent = 'Save the current adapter settings before running the read-only test.';
});
$$('#assuranceForm input,#assuranceForm select').forEach(node => node.addEventListener('change', () => { state.assurancePolicyDirty = true; }));
$$('#deliveryForm input,#deliveryForm select').forEach(node => node.addEventListener('change', () => { state.deliveryPolicyDirty = true; }));
$$('#auditExportForm input,#auditExportForm select').forEach(node => node.addEventListener('change', () => { state.auditExportPolicyDirty = true; }));
$$('#auditOperationsForm input,#auditOperationsForm select').forEach(node => node.addEventListener('change', () => {
  state.auditOperationsPolicyDirty = true;
  state.auditOperationsPreview = null;
  renderAuditOperationsPreview(null);
}));
$('#scanSplunkModels').addEventListener('click', scanSplunkModels);
$('#newEvaluationSuite').addEventListener('click', createEvaluationSuite);
$('#addEvaluationScenario').addEventListener('click', () => {
  if (!state.evaluationDraft) return;
  syncEvaluationScenario();
  if (state.evaluationDraft.draft_scenarios.length >= 15) { toast('A suite supports at most 15 organization scenarios'); return; }
  state.evaluationDraft.draft_scenarios.push(newEvaluationScenario(state.evaluationDraft.draft_scenarios.length));
  state.evaluationScenarioIndex = state.evaluationDraft.draft_scenarios.length - 1;
  renderEvaluationScenarioEditor();
});
$('#evaluationSuiteForm').addEventListener('submit', async event => {
  event.preventDefault();
  if (!event.currentTarget.reportValidity()) return;
  try { await saveEvaluationSuiteDraft(); } catch (error) { toast(error.message); }
});
$('#publishEvaluationSuite').addEventListener('click', publishEvaluationSuite);
$('#archiveEvaluationSuite').addEventListener('click', archiveEvaluationSuite);
$('#deleteEvaluationSuite').addEventListener('click', deleteEvaluationSuite);
$('#runModelTournament').addEventListener('click', runModelTournament);
$('#tournamentTarget').addEventListener('change', updateTournamentAssignmentHelp);
$('#tournamentSuite').addEventListener('change', renderModelTournaments);
$('#runGoldenBenchmark').addEventListener('click', runGoldenBenchmark);
$('#goldenSuite').addEventListener('change', renderGoldenBenchmarks);
$('#contextPrevious').addEventListener('click', () => { state.contextPage -= 1; renderArtifacts(state.contextItems); $('#contextView').scrollIntoView({ behavior:'smooth', block:'start' }); });
$('#contextNext').addEventListener('click', () => { state.contextPage += 1; renderArtifacts(state.contextItems); $('#contextView').scrollIntoView({ behavior:'smooth', block:'start' }); });
$('#settingsForm').addEventListener('submit', saveSettings);
$('#saveSplunkConnection').addEventListener('click', saveManagedSplunkConnection);
$('#addSplunkConnection').addEventListener('click', () => openManagedSplunkForm());
$('#cancelSplunkConnection').addEventListener('click', () => { resetManagedSplunkForm(); $('#managedSplunkForm').hidden = true; });
$('#managedSplunkVerifyTls').addEventListener('change', updateManagedSplunkTlsControls);
$('#connectionWorkflowBindings').addEventListener('click', event => {
  const button = event.target.closest('[data-rebind-connection]');
  if (button) rebindConnectionWorkflow(button);
});
$('#testSplunk').addEventListener('click', () => testConnection('splunk', null, $('#splunkTestResult')));
$('#testRepository').addEventListener('click', testDetectionRepository);
$('#checkModels').addEventListener('click', loadModelReadiness);
$('#checkLocalModels').addEventListener('click', loadModelReadiness);
$('#verifySplunkTls').addEventListener('change', updateTlsControls);
$('#repositoryEnabled').addEventListener('change', updateRepositoryControls);
$('#repositoryAllowPush').addEventListener('change', updateRepositoryControls);
$('#contextSearch').addEventListener('input', async event => {
  const query = event.target.value.trim();
  state.contextPage = 1;
  if (!query) return renderArtifacts(filterArtifacts(state.artifacts));
  const results = await api(scopedUrl('/api/context/search', {q:query, limit:30}));
  const ids = new Set(results.map(item => item.id.split(':')[0])); renderArtifacts(filterArtifacts(state.artifacts.filter(item => ids.has(item.id))));
});
$('#artifactForm').addEventListener('submit', async event => {
  event.preventDefault();
  const payload = { title:$('#newArtifactTitle').value.trim(), content:$('#newArtifactContent').value.trim(), kind:$('#newArtifactKind').value, tags:$('#newArtifactTags').value.split(',').map(x=>x.trim()).filter(Boolean), source:'operator', ...scopePayload() };
  const editing = state.editingArtifactId;
  await api(editing ? scopedUrl(`/api/artifacts/${encodeURIComponent(editing)}`) : '/api/artifacts', { method:editing ? 'PATCH' : 'POST', body:JSON.stringify(payload) });
  state.editingArtifactId = null; event.target.reset(); $('#artifactModal').hidden = true; await loadArtifacts(); toast(editing ? 'Artifact updated and re-indexed' : 'Artifact indexed');
});
$('#validationForm').addEventListener('submit', async event => {
  event.preventDefault();
  const taskId = state.editingValidationId; if (!taskId) return;
  const payload = {
    title:$('#validationTitle').value.trim(), rationale:$('#validationRationale').value.trim(),
    spl:$('#validationSpl').value.trim(), earliest_time:$('#validationEarliest').value.trim(),
    latest_time:$('#validationLatest').value.trim(), row_limit:Number($('#validationRowLimit').value)
  };
  try {
    const updated = await api(`/api/validations/${encodeURIComponent(taskId)}`, { method:'PATCH', body:JSON.stringify(payload) });
    state.validations = state.validations.map(item => item.id === taskId ? updated : item);
    state.editingValidationId = null; $('#validationModal').hidden = true; renderValidations(); toast('Draft saved and fingerprint refreshed');
  } catch (error) { toast(error.message); }
});
let queryIntelligenceTimer;
['#validationSpl','#validationEarliest','#validationLatest','#validationRowLimit'].forEach(selector => $(selector).addEventListener('input', () => {
  clearTimeout(queryIntelligenceTimer);
  queryIntelligenceTimer = setTimeout(() => analyzeValidationContract(), 350);
}));
$('#caseForm').addEventListener('submit', async event => {
  event.preventDefault();
  const pending = state.pendingCaseItem;
  const created = await api('/api/cases', { method:'POST', body:JSON.stringify({ title:$('#newCaseTitle').value.trim(), owner:$('#newCaseOwner').value.trim() || 'Unassigned', severity:$('#newCaseSeverity').value, summary:$('#newCaseSummary').value.trim(), tags:$('#newCaseTags').value.split(',').map(value => value.trim()).filter(Boolean), ...scopePayload() }) });
  $('#caseModal').hidden = true; event.target.reset(); state.activeCase = created;
  if (pending) await addItemToCase(created.id, pending); else { await loadCases(); await openCase(created.id, false); toast('Case created'); }
  setView('cases'); history.replaceState(null, '', `${location.pathname}#cases/${encodeURIComponent(created.id)}`);
});
$('#caseItemForm').addEventListener('submit', async event => {
  event.preventDefault(); if (!state.activeCase) return;
  const occurred = $('#caseItemOccurred').value;
  const value = { kind:$('#caseItemKind').value, title:$('#caseItemName').value.trim(), content:$('#caseItemContent').value.trim(), source:$('#caseItemSource').value.trim() || 'analyst', confidence:$('#caseItemConfidence').value, status:$('#caseItemStatus').value, occurred_at:occurred ? new Date(occurred).toISOString() : null, metadata:state.pendingCaseItem?.metadata || {} };
  const editing = state.editingCaseItemId;
  $('#caseItemModal').hidden = true; event.target.reset();
  if (editing) {
    await api(scopedUrl(`/api/cases/${encodeURIComponent(state.activeCase.id)}/items/${encodeURIComponent(editing)}`), { method:'PATCH', body:JSON.stringify(value) });
    state.editingCaseItemId = null; state.pendingCaseItem = null; await loadCases(); toast('Timeline item updated');
  } else await addItemToCase(state.activeCase.id, value);
});
$('#fileInput').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return; const form = new FormData(); form.append('file', file);
  try { await api(scopedUrl('/api/artifacts/upload'), { method:'POST', body:form }); await loadArtifacts(); toast('File indexed'); } catch(error) { toast(error.message); }
  event.target.value = '';
});

document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if (!$('#demoTour').hidden) finishDemoTour();
  else if (!$('#detailModal').hidden) closeDetail();
  else if (!$('#validationModal').hidden) { $('#validationModal').hidden = true; state.editingValidationId = null; }
  else if (!$('#casePickerModal').hidden) { $('#casePickerModal').hidden = true; state.pendingCaseItem = null; }
  else if (!$('#caseItemModal').hidden) { $('#caseItemModal').hidden = true; state.pendingCaseItem = null; state.editingCaseItemId = null; }
  else if (!$('#caseModal').hidden) { $('#caseModal').hidden = true; state.pendingCaseItem = null; }
});

const accessObserver = new MutationObserver(() => {
  if (state.auth) applyAccessPermissions();
});
accessObserver.observe(document.body, { childList:true, subtree:true });

async function loadWorkspace() {
  await Promise.all([loadSettings(), loadWorkload(), loadArtifacts(), loadCases(), loadLatestDiscovery(), loadDiscoveryJobs(), loadValidations(), loadDetections(), loadModelCatalog(), loadTimeSeriesStatus(), loadModelTrust(), loadSplunkModels(), loadAssurance(), loadConnectionDiagnostics(), loadFeedbackBenchmarks(), loadGoldenBenchmarks()]);
  renderPromptTree(); renderValidations(); renderDetections(); handleDeepLink(); renderAuth();
  state.workspaceLoaded = true;
  if (!state.assuranceTimer) state.assuranceTimer = setInterval(() => {
    if (state.auth?.authenticated) loadAssurance().catch(() => {});
  }, 3000);
}

async function initialize() {
  try {
    await loadAuthStatus();
    const authQuery = new URLSearchParams(location.search);
    const authError = authQuery.get('auth_error');
    if (authError) {
      $('#loginResult').textContent = authError === 'provider-denied'
        ? 'The identity provider did not complete sign-in. No SignalRoom session was created.'
        : 'Enterprise sign-in could not be verified or admitted. Ask an administrator to review the OIDC audit event and claim policy.';
    }
    if (authQuery.has('auth') || authError) {
      history.replaceState(null, '', `${location.pathname}${location.hash || '#investigate'}`);
    }
    if (state.auth.enabled && !state.auth.authenticated) return;
    await loadWorkspace();
  } catch (error) { toast(error.message); }
}

initialize();
