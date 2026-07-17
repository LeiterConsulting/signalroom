const state = {
  settings: null, artifacts: [], modelReadiness: null, conversationId: null, busy: false,
  ledger: [], lastDiscovery: null, promptPath: [], contextKind: 'all', cases: [],
  activeCase: null, caseCockpit: null, pendingCaseItem: null, detailActions: [], contextPage: 1, contextPageSize: 9,
  contextItems: [], editingArtifactId: null, editingCaseItemId: null, demoTourStep: -1,
  modelRecommendations: {}, validations: [], editingValidationId: null,
  modelUpdates: null, modelCatalog: null, splunkModels: null,
  assurance: null, assurancePolicyDirty: false, connectionDiagnostics: null, queryIntelligence: null,
  feedbackBenchmarks: null, goldenBenchmarks: null, deliveryPolicyDirty: false,
  deliveryPreview: null, detections: [], activeDetection: null, detectionGitExport: null
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
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(options.headers || {}) }
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { const body = await response.json(); message = body.detail || body.error || message; } catch (_) {}
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

async function streamApi(path, payload, onEvent) {
  const response = await fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { const body = await response.json(); message = body.detail || body.error || message; } catch (_) {}
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
    provenance:`<h3>Provenance</h3><dl><div><dt>Source</dt><dd>${escapeHtml(item.source)}</dd></div><div><dt>Updated</dt><dd>${new Date(item.updated_at).toLocaleString()}</dd></div><div><dt>Tags</dt><dd>${escapeHtml(item.tags.join(', ') || 'none')}</dd></div></dl>`,
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
}

async function loadSettings() {
  state.settings = await api('/api/settings'); hydrateSettings();
  if (!state.settings.configured) $('#settingsModal').hidden = false;
  else if (state.settings.demo_mode && !localStorage.getItem('signalroom-demo-tour-complete')) {
    setTimeout(startDemoTour, 250);
  }
  loadModelReadiness();
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

function renderModelCatalog() {
  const panel = $('#candidateModels'); const candidates = state.modelCatalog?.evaluated_candidates || [];
  if (!candidates.length) { panel.innerHTML = ''; return; }
  panel.innerHTML = `<header><div><span>EVALUATED NEXT</span><h3>Useful models with honest integration boundaries</h3></div><p>${escapeHtml(state.modelCatalog.policy || '')}</p></header>
    <div class="candidate-model-grid">${candidates.map(item => `<article>
      <div><span>${escapeHtml(item.owner)} · ${escapeHtml(item.runtime.replaceAll('-', ' '))}</span><b>${escapeHtml(item.status.replaceAll('-', ' '))}</b></div>
      <h4>${escapeHtml(item.label)}</h4><p>${escapeHtml(item.purpose)}</p><small>${escapeHtml(item.constraint)}</small>
      <a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener">Review first-party source ↗</a>
    </article>`).join('')}</div>`;
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
    toast(job.kind === 'local-transformers' ? 'Local specialist installed · cloud inference is not required' : 'Model is ready in Ollama'); await loadModelReadiness(); renderModels();
  } catch (error) { button.disabled = false; button.textContent = 'Retry'; toast(error.message); }
}

async function activateModel(profileId, button) {
  const original = button.textContent; button.disabled = true; button.textContent = 'Activating…';
  try {
    const result = await api('/api/model-setup/activate', { method:'POST', body:JSON.stringify({ profile_id:profileId, unload_other_signalroom_models:true }) });
    toast(`Active model · ${result.executed_model}`); await loadModelReadiness(); renderModels();
  } catch (error) { button.disabled = false; button.textContent = original; toast(error.message); }
}

async function loadArtifacts() {
  state.artifacts = await api('/api/artifacts');
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
  await api(`/api/artifacts/${encodeURIComponent(id)}`, { method:'DELETE' });
  if (!$('#detailModal').hidden) closeDetail();
  await loadArtifacts(); toast('Artifact deleted');
}

async function loadCases() {
  state.cases = await api('/api/cases');
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
      <small>${escapeHtml(item.owner)} · ${escapeHtml(item.status)}</small>
      <footer><span>${item.item_count} timeline item${item.item_count === 1 ? '' : 's'}</span><time>${new Date(item.updated_at).toLocaleDateString()}</time></footer>
    </button>`).join('') : '<div class="case-list-empty"><b>No cases yet</b><p>Create a case, then preserve evidence from Investigate, Discovery, or Context.</p></div>';
}

async function openCase(id, updateHash = true) {
  [state.activeCase, state.caseCockpit] = await Promise.all([
    api(`/api/cases/${encodeURIComponent(id)}`),
    api(`/api/cases/${encodeURIComponent(id)}/cockpit`)
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
  const timeline = item.items.length ? item.items.map(entry => `
    <article class="timeline-item">
      <div class="timeline-marker ${escapeHtml(entry.kind)}"></div>
      <div class="timeline-card">
        <header><div><span>${escapeHtml(entry.kind)} · ${escapeHtml(entry.status)}</span><h4>${escapeHtml(entry.title)}</h4></div><span class="timeline-admin-actions"><button data-edit-case-item="${escapeHtml(entry.id)}">Edit</button><button data-delete-case-item="${escapeHtml(entry.id)}" aria-label="Remove ${escapeHtml(entry.title)}">Remove</button></span></header>
        <p>${escapeHtml(entry.content)}</p>
        <footer><span>${escapeHtml(entry.source)} · ${escapeHtml(entry.confidence)} confidence</span><time>${new Date(entry.occurred_at || entry.created_at).toLocaleString()}</time></footer>
      </div>
    </article>`).join('') : '<div class="case-timeline-empty"><b>The timeline is ready.</b><p>Add an analyst note, or preserve evidence directly from Investigate, Discovery, or Context.</p></div>';
  $('#caseDetail').innerHTML = `
    <div class="case-detail-header">
      <div><p class="eyebrow">CASE ${escapeHtml(item.id.slice(0, 8).toUpperCase())}</p><h2>${escapeHtml(item.title)}</h2><p>Created ${new Date(item.created_at).toLocaleString()} · Updated ${new Date(item.updated_at).toLocaleString()}</p></div>
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
  await api(`/api/cases/${encodeURIComponent(caseId)}/items`, { method:'POST', body:JSON.stringify(item) });
  state.pendingCaseItem = null;
  await loadCases(); await openCase(caseId, false);
  toast('Added to the case timeline');
}

async function exportActiveCase() {
  if (!state.activeCase) return;
  const result = await api(`/api/cases/${encodeURIComponent(state.activeCase.id)}/export`, { method:'POST', body:JSON.stringify({ formats:['markdown','json'] }) });
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

function benchmarkTime(value) {
  return value ? new Date(value).toLocaleString() : 'not completed';
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
  return `<article class="golden-decision ${gate.ready ? 'ready' : 'hold'} ${run.status === 'error' ? 'error' : ''}"><header><div><span>${decision}</span><h4>${escapeHtml(run.profile_id)} · ${escapeHtml(run.model)}</h4></div><b>${Math.round(run.score)}/100</b></header><p>${escapeHtml(run.error || gate.label || 'Benchmark is still running.')}</p><div class="golden-metrics"><span><b>${Math.round(Number(run.pass_rate || 0)*100)}%</b>scenario pass rate</span><span><b>${run.critical_failures || 0}</b>critical failures</span><span><b>${escapeHtml(run.suite_version)}</b>suite version</span><span><b>${escapeHtml(run.prompt_version)}</b>prompt version</span></div><div class="golden-comparison"><span>${escapeHtml(comparisonText)}</span><span>${escapeHtml(feedbackText)}</span></div>${blockers ? `<div class="golden-reasons blockers"><b>Promotion blockers</b><ul>${blockers}</ul></div>` : ''}${warnings ? `<div class="golden-reasons warnings"><b>Decision context</b><ul>${warnings}</ul></div>` : ''}<div class="golden-results">${scenarios}</div><footer><time>${escapeHtml(benchmarkTime(run.completed_at || run.created_at))}</time>${gate.ready && !run.is_baseline ? `<button class="button primary small" data-accept-golden-baseline="${escapeHtml(run.id)}">Accept as baseline</button>` : run.is_baseline ? '<span class="baseline-badge">Accepted baseline</span>' : ''}</footer></article>`;
}

function renderGoldenBenchmarks() {
  const value = state.goldenBenchmarks; if (!value) return;
  $('#goldenSuiteVersion').textContent = `Suite ${value.suite_version} · ${value.scenario_count} scenarios`;
  const select = $('#goldenProfile'); const selected = select.value || state.settings?.security_reasoning_model || '';
  select.innerHTML = (value.profiles || []).map(profile => `<option value="${escapeHtml(profile.id)}" ${!profile.enabled ? 'disabled' : ''}>${escapeHtml(profile.label)} · ${escapeHtml(profile.model)}</option>`).join('');
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
  $('#goldenScenarioCatalog').innerHTML = (value.scenarios || []).map(item => `<article><header><span>${escapeHtml(item.task_type)}</span><b>${escapeHtml(item.title)}</b></header><p>${item.expected_evidence_controls} evidence controls · ${item.expected_conclusion_controls} conclusion controls · tools: ${escapeHtml((item.expected_tools || []).join(', ') || 'none')}</p>${item.guardrail_control ? '<em>Critical guardrail control</em>' : ''}</article>`).join('');
  const latest = (value.runs || [])[0];
  $('#goldenBenchmarkLatest').innerHTML = renderGoldenRun(latest);
  $('#goldenRunHistory').innerHTML = (value.runs || []).length ? value.runs.slice(0,8).map(run => `<button data-show-golden-run="${escapeHtml(run.id)}"><span><b>${escapeHtml(run.profile_id)}</b><small>${escapeHtml(benchmarkTime(run.completed_at || run.created_at))}</small></span><em class="${run.is_baseline ? 'baseline' : run.gate?.ready ? 'ready' : 'hold'}">${run.is_baseline ? 'BASELINE' : run.status === 'error' ? 'ERROR' : `${Math.round(run.score)} · ${run.gate?.decision || run.status}`}</em></button>`).join('') : '<div class="empty-inline compact-empty">No golden benchmark runs have been recorded.</div>';
}

async function loadGoldenBenchmarks() {
  try { state.goldenBenchmarks = await api('/api/benchmarks'); renderGoldenBenchmarks(); }
  catch (error) { $('#goldenBenchmarkLatest').innerHTML = `<div class="empty-inline compact-empty">${escapeHtml(error.message)}</div>`; }
}

async function runGoldenBenchmark() {
  const profileId = $('#goldenProfile').value; if (!profileId) return;
  const button = $('#runGoldenBenchmark'); button.disabled = true; button.textContent = 'Running gate…';
  const progress = $('#goldenProgress'); progress.hidden = false;
  progress.querySelector('.operation-label').textContent = 'Preparing golden investigations';
  progress.querySelector('.operation-detail').textContent = 'Checking the selected local model.';
  progress.querySelector('.operation-progress i').style.width = '0%'; progress.querySelector('.operation-steps').innerHTML = '';
  progress.scrollIntoView({behavior:'smooth',block:'center'});
  try {
    const result = await streamApi('/api/benchmarks/run/stream', {profile_id:profileId}, event => updateOperation(progress,event));
    await loadGoldenBenchmarks();
    toast(result.gate?.ready ? 'Golden gate passed · review before accepting baseline' : 'Golden gate completed with promotion blockers');
  } catch (error) { toast(error.message); await loadGoldenBenchmarks(); }
  finally { button.disabled = false; button.textContent = 'Run five-scenario gate'; }
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

function renderEvidence(evidence = [], trace = [], ledger = []) {
  state.ledger = ledger;
  const toolObservations = ledger.filter(item => item.classification !== 'context' && item.status === 'observed');
  const inPlayCount = evidence.length + toolObservations.length;
  $('#evidenceCount').textContent = inPlayCount; $('#mobileEvidenceCount').textContent = ledger.length || inPlayCount; $('#evidenceEmpty').hidden = inPlayCount > 0;
  const contextCards = evidence.map((item, index) => `<article class="evidence-card"><header><span class="ref">E${index+1}</span><b>${escapeHtml(item.title)}</b></header><p class="expandable-copy">${escapeHtml(item.excerpt)}</p>${item.excerpt.length > 260 ? '<div class="evidence-card-actions"><button data-toggle-copy>Show more</button></div>' : ''}<footer><span>${escapeHtml(item.source)}<b>score ${Number(item.score).toFixed(2)}</b></span><button data-open-artifact="${escapeHtml(item.id.split(':')[0])}">Inspect source</button></footer></article>`).join('');
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
      execute_searches: true
    }, event => updateOperation($('#agentWork')?.querySelector('.agent-work'), event));
    state.conversationId = result.conversation_id; finishAgentWork();
    appendMessage('assistant', result.message, { model: result.model, profile: result.model_profile, route: result.route, taskType:result.mode, targetId:`${result.conversation_id}:${result.generated_at}`, activated:result.model_activation?.activated, suggestions: result.suggested_actions, modelRecommendations:result.model_recommendations, enrichment:result.enrichment });
    renderEvidence(result.evidence, result.trace, result.ledger);
    $('#approveHf').checked = false;
  } catch (error) { finishAgentWork(); appendMessage('assistant', `The request failed: ${error.message}`); }
  finally { state.busy = false; }
}

async function runDiscovery() {
  const button = $('#runDiscovery'); button.disabled = true; button.textContent = 'Discovering…';
  $('#discoveryStatus').textContent = 'Running'; beginDiscoveryProgress();
  try {
    const result = await streamApi('/api/discovery/stream', { depth:$('#discoveryDepth').value }, updateDiscoveryProgress);
    renderDiscoveryResult(result); toast('Discovery artifacts created'); await loadArtifacts();
  } catch (error) { $('#discoveryStatus').textContent = 'Failed'; toast(error.message); }
  finally { button.disabled = false; button.textContent = 'Run discovery'; }
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

function hydrateDeliveryPolicy(value) {
  if (!value?.policy || state.deliveryPolicyDirty) return;
  const policy = value.policy;
  $('#deliveryEnabled').checked = Boolean(policy.enabled);
  $('#deliveryMode').value = policy.mode;
  $('#deliverySeverity').value = policy.minimum_severity;
  $('#deliveryLabel').value = policy.destination_label;
  $('#deliveryRedaction').value = policy.redaction_level;
  $('#deliveryAttempts').value = policy.max_attempts;
  $('#deliveryBackoff').value = String(policy.retry_backoff_seconds);
  $('#deliveryVerifyTls').checked = Boolean(policy.verify_tls);
  $('#deliveryCaBundle').value = policy.ca_bundle || '';
  $$('.delivery-categories input').forEach(input => { input.checked = (policy.signal_kinds || []).includes(input.value); });
  $('#deliveryWebhookUrl').value = '';
  $('#deliveryAuthorization').value = '';
  $('#deliveryClearWebhookUrl').checked = false;
  $('#deliveryClearAuthorization').checked = false;
  $('#deliveryWebhookUrl').placeholder = value.destination?.configured ? 'Encrypted destination configured · leave blank to keep' : 'https://automation.example/hooks/signalroom';
  $('#deliveryAuthorization').placeholder = value.destination?.authorization_configured ? 'Encrypted authorization configured · leave blank to keep' : 'Optional · Bearer …';
}

function renderDelivery(value) {
  const delivery = value.delivery || {}; const policy = delivery.policy || {}; const destination = delivery.destination || {};
  hydrateDeliveryPolicy(delivery);
  const ready = Boolean(policy.enabled && destination.configured);
  $('#deliveryStatus').textContent = ready ? `${policy.mode} · ${destination.origin}` : policy.enabled ? 'Destination required' : 'Disabled · local only';
  $('#deliveryStatus').className = `subtle-pill ${ready ? 'ok' : policy.enabled ? 'warn' : ''}`;
  $('#deliveryDestinationHint').textContent = destination.configured
    ? `${destination.origin} · ${destination.transport} · ${destination.authorization_configured ? 'authorization configured' : 'no authorization header'}`
    : 'No outbound destination configured';
  const jobs = delivery.jobs || [];
  $('#deliveryJobs').innerHTML = jobs.length ? jobs.slice(0,12).map(job => {
    const action = job.status === 'failed'
      ? `<button class="button ghost small" data-retry-delivery="${escapeHtml(job.id)}">Retry bounded batch</button>`
      : ['queued','retrying'].includes(job.status)
        ? `<button class="button ghost small" data-cancel-delivery="${escapeHtml(job.id)}">Cancel</button>`
        : '';
    const timing = job.status === 'delivered' ? `Delivered ${assuranceTime(job.delivered_at)}` : job.next_attempt_at ? `Next attempt ${assuranceTime(job.next_attempt_at)}` : assuranceTime(job.updated_at);
    return `<article class="delivery-job ${escapeHtml(job.status)}"><header><span>${escapeHtml(job.approval_mode.replaceAll('-', ' '))}</span><b>${escapeHtml(job.status)}</b></header><p>Package <code>${escapeHtml(job.package_id.slice(0,8))}</code> → ${escapeHtml(job.destination_label)}</p><div><span>${job.attempt_count}/${job.max_attempts} attempts</span><span>HTTP ${job.http_status || '—'}</span><span>Hash <code>${escapeHtml(job.payload_sha256.slice(0,12))}</code></span></div>${job.last_error ? `<small>${escapeHtml(job.last_error)}</small>` : ''}<footer><time>${escapeHtml(timing)}</time>${action}</footer></article>`;
  }).join('') : '<div class="empty-inline compact-empty">No outbound package has been approved. Preview an eligible response package to start.</div>';
  const audit = value.audit || {}; const chain = audit.chain || {};
  $('#auditChainStatus').textContent = chain.valid ? `${chain.event_count || 0} events · chain valid` : `Integrity break at event ${chain.broken_sequence || 'unknown'}`;
  $('#auditChainStatus').className = chain.valid ? 'audit-valid' : 'audit-invalid';
  $('#auditEvents').innerHTML = (audit.events || []).length ? audit.events.slice(0,12).map(item => `<article class="audit-event ${escapeHtml(item.outcome)}"><header><span>#${item.sequence} · ${escapeHtml(item.event_type)}</span><b>${escapeHtml(item.outcome)}</b></header><p>${escapeHtml(item.summary || item.action)}</p><footer><time>${escapeHtml(assuranceTime(item.created_at))}</time><code>${escapeHtml(item.event_hash.slice(0,12))}</code></footer></article>`).join('') : '<div class="empty-inline compact-empty">Audit events appear when control-plane decisions are made.</div>';
}

async function saveDeliveryPolicy(event) {
  event.preventDefault();
  const signalKinds = $$('.delivery-categories input:checked').map(input => input.value);
  if (!signalKinds.length) { toast('Select at least one eligible signal category'); return; }
  const payload = {
    enabled:$('#deliveryEnabled').checked,
    mode:$('#deliveryMode').value,
    minimum_severity:$('#deliverySeverity').value,
    signal_kinds:signalKinds,
    redaction_level:$('#deliveryRedaction').value,
    destination_label:$('#deliveryLabel').value.trim() || 'Primary webhook',
    verify_tls:$('#deliveryVerifyTls').checked,
    ca_bundle:$('#deliveryCaBundle').value.trim() || null,
    max_attempts:Number($('#deliveryAttempts').value),
    retry_backoff_seconds:Number($('#deliveryBackoff').value),
    webhook_url:$('#deliveryWebhookUrl').value.trim() || null,
    authorization_header:$('#deliveryAuthorization').value.trim() || null,
    clear_webhook_url:$('#deliveryClearWebhookUrl').checked,
    clear_authorization_header:$('#deliveryClearAuthorization').checked
  };
  try {
    await api('/api/delivery/policy', {method:'PUT',body:JSON.stringify(payload)});
    state.deliveryPolicyDirty = false; await loadAssurance(); toast('Outbound delivery policy saved');
  } catch (error) { toast(error.message); }
}

async function previewAssuranceDelivery(packageId) {
  try {
    const preview = await api(`/api/assurance/packages/${encodeURIComponent(packageId)}/delivery/preview`, {method:'POST'});
    state.deliveryPreview = preview;
    $('#deliveryPreviewContract').innerHTML = `<span><b>${escapeHtml(preview.destination.label)}</b>${escapeHtml(preview.destination.origin)}</span><span><b>${preview.payload_bytes} bytes</b>${escapeHtml(preview.redaction_level)} redaction</span><span><b>SHA-256</b><code>${escapeHtml(preview.payload_sha256)}</code></span><span><b>Authority</b>Delivery only · no SPL execution</span>`;
    $('#deliveryRedactions').innerHTML = preview.redactions.map(item => `<li>${escapeHtml(item)}</li>`).join('');
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
  $('#discoveryStatus').textContent = `${result.findings.length} findings · ${inventoryChanges} changes${modelRoles ? ` · ${modelRoles} local roles` : ''}${reusedRoles ? ` · ${reusedRoles} reused` : ''}${failedCalls ? ` · ${failedCalls} gaps` : ''}`;
  if (['quick','standard','deep'].includes(result.depth)) $('#discoveryDepth').value = result.depth;
  renderValidationCandidates(result);
  renderDiscoveryFollowup(result);
}

async function loadLatestDiscovery() {
  const result = await api('/api/discovery/latest');
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
      actions.push(`<button class="button primary small" data-inspect-validation="${escapeHtml(task.id)}">Inspect preserved result</button>`);
      actions.push(detection
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
  const staged = value.staged_contract || {};
  panel.innerHTML = `<header><b>Execution intelligence</b><span>${escapeHtml(value.risk.toUpperCase())} · score ${value.score}/100</span></header><p>${escapeHtml(value.execution_recommendation)}</p>${reuse}<div class="query-intelligence-grid"><div><b>Cost and risk drivers</b><ul>${drivers || '<li>No material cost driver detected</li>'}</ul></div><div><b>Bounding controls</b><ul>${controls || '<li>Add an index, time, or result boundary</li>'}</ul></div></div>${staged.spl && staged.spl !== $('#validationSpl').value ? `<details><summary>Safer staged SPL</summary><pre><code>${escapeHtml(staged.spl)}</code></pre></details>` : ''}`;
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
  if (!intelligence || intelligence.risk === 'blocked') { toast(intelligence?.blocked_reason || 'Query approval is blocked'); return; }
  const reuse = intelligence.reusable_result ? `\n\nA preserved matching result exists from ${new Date(intelligence.reusable_result.completed_at).toLocaleString()}. Approve only if fresher evidence is required.` : '';
  if (!confirm(`Approve this exact read-only SPL contract?\n\nRisk: ${intelligence.risk.toUpperCase()} (${intelligence.score}/100)\n${intelligence.execution_recommendation}${reuse}\n\n${task.spl}\n\nWindow: ${task.earliest_time} to ${task.latest_time}\nMaximum rows: ${task.row_limit}`)) return;
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
  actions.push(detection
    ? { label:`Open detection v${detection.current_version}`, kind:'detection', target:detection.id }
    : { label:'Create detection draft', kind:'detection-create', target:task.id });
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
  const complete = state.validations.filter(task => task.status === 'complete');
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
  if (!task || task.status !== 'complete') return;
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
    if (state.activeDetection?.id !== detectionId) state.detectionGitExport = null;
    state.activeDetection = await api(`/api/detections/${encodeURIComponent(detectionId)}`);
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
    <div class="detection-boundary"><b>Export authority only</b><span>SignalRoom can create a review package. It cannot deploy, enable, or write this search to Splunk.</span></div>
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
    const matches = analysis.specialist_enrichment?.context_matches || [];
    const hypotheses = analysis.reconciliation?.risk_hypotheses || [];
    const opportunities = analysis.reconciliation?.detection_opportunities || [];
    const caveats = analysis.caveats || [];
    const passCards = passes.map(item => {
      const metrics = item.reused ? ['Reused exact input · 0 new inference'] : [`${Number(item.duration_seconds || 0).toFixed(1)}s`];
      if (item.result_count !== undefined) metrics.push(`${Number(item.result_count).toLocaleString()} results`);
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
      ${(entities.length || matches.length) ? `<section class="model-team-section"><h4>SecureBERT enrichment</h4>${entities.length ? `<div class="discovery-entity-row">${entities.slice(0,20).map(item => `<span><b>${escapeHtml(item.type)}</b>${escapeHtml(item.value)}</span>`).join('')}</div>` : ''}${matches.length ? `<div class="discovery-context-links">${matches.slice(0,6).map(item => `<button data-open-artifact="${escapeHtml(item.id.split(':')[0])}"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.source)} · ${Number(item.score || 0).toFixed(2)}</span></button>`).join('')}</div>` : ''}</section>` : ''}
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
  settings.models.forEach(model => {
    if (model.provider === 'ollama') model.endpoint = $('#ollamaEndpoint').value.trim() || 'http://localhost:11434';
    if (model.id === settings.default_chat_model) model.model = $('#generalModelId').value.trim() || model.model;
    if (model.id === settings.security_reasoning_model) model.model = $('#securityModelId').value.trim() || model.model;
    if (model.id === settings.embedding_model) model.endpoint = $('#hfEmbeddingEndpoint').value.trim() || model.endpoint;
    if (model.id === settings.ner_model) model.endpoint = $('#hfNerEndpoint').value.trim() || model.endpoint;
  });
  try {
    state.settings = await api('/api/settings', { method:'PUT', body:JSON.stringify({ settings, splunk_token:$('#splunkToken').value || null, huggingface_token:$('#hfToken').value || null }) });
    hydrateSettings(); renderModels(); await loadModelReadiness(); $('#settingsModal').hidden = true; $('#splunkToken').value = ''; $('#hfToken').value = ''; toast('Workspace saved');
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
  if (event.target.closest('[data-retire-detection]')) { await retireDetection(); return; }
  if (event.target.closest('[data-delete-detection]')) { await deleteDetection(); return; }
  if (event.target.closest('[data-detection-investigate]')) { investigateDetection(); return; }
  if (event.target.closest('#showDetectionCandidates')) {
    $('#detectionCandidatesPanel').scrollIntoView({behavior:'smooth',block:'start'});
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
  if (event.target.closest('#openSettings,#configureModels')) $('#settingsModal').hidden = false;
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
    state.activeCase = await api(`/api/cases/${encodeURIComponent(state.activeCase.id)}`, { method:'PATCH', body:JSON.stringify({ title:$('#caseTitleInput').value.trim(), owner:$('#caseOwner').value.trim() || 'Unassigned', status:$('#caseStatus').value, severity:$('#caseSeverity').value, summary:$('#caseSummary').value.trim(), tags:$('#caseTags').value.split(',').map(value => value.trim()).filter(Boolean) }) });
    await loadCases(); toast('Case details saved');
  }
  if (event.target.closest('[data-delete-case]') && state.activeCase) {
    const item = state.activeCase;
    if (confirm(`Delete case “${item.title}” and all ${item.item_count} timeline items? This cannot be undone.`)) {
      await api(`/api/cases/${encodeURIComponent(item.id)}`, { method:'DELETE' });
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
    await api(`/api/cases/${encodeURIComponent(state.activeCase.id)}/items/${encodeURIComponent(deleteCaseItem.dataset.deleteCaseItem)}`, { method:'DELETE' });
    await loadCases(); toast('Timeline item removed');
  }
});

$('#chatForm').addEventListener('submit', event => { event.preventDefault(); sendChat($('#chatInput').value); });
$('#chatInput').addEventListener('input', resizeComposer);
$('#chatInput').addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); $('#chatForm').requestSubmit(); } });
$('#newConversation').addEventListener('click', resetConversation);
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
$('#runConnectionDiagnostics').addEventListener('click', runConnectionDiagnostics);
$('#assuranceForm').addEventListener('submit', saveAssurancePolicy);
$('#deliveryForm').addEventListener('submit', saveDeliveryPolicy);
$('#approveDelivery').addEventListener('click', approveDeliveryPreview);
$('#runAssuranceNow').addEventListener('click', runAssuranceNow);
$('#cancelAssuranceRun').addEventListener('click', cancelAssuranceRun);
$('#assuranceDepth').addEventListener('change', updateAssuranceBudgetHelp);
$$('#assuranceForm input,#assuranceForm select').forEach(node => node.addEventListener('change', () => { state.assurancePolicyDirty = true; }));
$$('#deliveryForm input,#deliveryForm select').forEach(node => node.addEventListener('change', () => { state.deliveryPolicyDirty = true; }));
$('#scanSplunkModels').addEventListener('click', scanSplunkModels);
$('#runGoldenBenchmark').addEventListener('click', runGoldenBenchmark);
$('#contextPrevious').addEventListener('click', () => { state.contextPage -= 1; renderArtifacts(state.contextItems); $('#contextView').scrollIntoView({ behavior:'smooth', block:'start' }); });
$('#contextNext').addEventListener('click', () => { state.contextPage += 1; renderArtifacts(state.contextItems); $('#contextView').scrollIntoView({ behavior:'smooth', block:'start' }); });
$('#settingsForm').addEventListener('submit', saveSettings);
$('#testSplunk').addEventListener('click', () => testConnection('splunk', null, $('#splunkTestResult')));
$('#checkModels').addEventListener('click', loadModelReadiness);
$('#checkLocalModels').addEventListener('click', loadModelReadiness);
$('#verifySplunkTls').addEventListener('change', updateTlsControls);
$('#contextSearch').addEventListener('input', async event => {
  const query = event.target.value.trim();
  state.contextPage = 1;
  if (!query) return renderArtifacts(filterArtifacts(state.artifacts));
  const results = await api(`/api/context/search?q=${encodeURIComponent(query)}&limit=30`);
  const ids = new Set(results.map(item => item.id.split(':')[0])); renderArtifacts(filterArtifacts(state.artifacts.filter(item => ids.has(item.id))));
});
$('#artifactForm').addEventListener('submit', async event => {
  event.preventDefault();
  const payload = { title:$('#newArtifactTitle').value.trim(), content:$('#newArtifactContent').value.trim(), kind:$('#newArtifactKind').value, tags:$('#newArtifactTags').value.split(',').map(x=>x.trim()).filter(Boolean), source:'operator' };
  const editing = state.editingArtifactId;
  await api(editing ? `/api/artifacts/${encodeURIComponent(editing)}` : '/api/artifacts', { method:editing ? 'PATCH' : 'POST', body:JSON.stringify(payload) });
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
  const created = await api('/api/cases', { method:'POST', body:JSON.stringify({ title:$('#newCaseTitle').value.trim(), owner:$('#newCaseOwner').value.trim() || 'Unassigned', severity:$('#newCaseSeverity').value, summary:$('#newCaseSummary').value.trim(), tags:$('#newCaseTags').value.split(',').map(value => value.trim()).filter(Boolean) }) });
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
    await api(`/api/cases/${encodeURIComponent(state.activeCase.id)}/items/${encodeURIComponent(editing)}`, { method:'PATCH', body:JSON.stringify(value) });
    state.editingCaseItemId = null; state.pendingCaseItem = null; await loadCases(); toast('Timeline item updated');
  } else await addItemToCase(state.activeCase.id, value);
});
$('#fileInput').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return; const form = new FormData(); form.append('file', file);
  try { await api('/api/artifacts/upload', { method:'POST', body:form }); await loadArtifacts(); toast('File indexed'); } catch(error) { toast(error.message); }
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

Promise.all([loadSettings(), loadArtifacts(), loadCases(), loadLatestDiscovery(), loadValidations(), loadDetections(), loadModelCatalog(), loadSplunkModels(), loadAssurance(), loadConnectionDiagnostics(), loadFeedbackBenchmarks(), loadGoldenBenchmarks()]).then(() => { renderPromptTree(); renderValidations(); renderDetections(); handleDeepLink(); setInterval(loadAssurance, 3000); }).catch(error => toast(error.message));
