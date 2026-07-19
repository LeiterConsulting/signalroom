# SignalRoom — Splunk Security Agent

SignalRoom is a local-first analyst workspace and MCP server for evidence-led Splunk security work. It combines read-only Splunk discovery, a chat agent, model routing, contextual artifacts, and a managed RAG library without requiring a cloud LLM.

This is a focused reimplementation inspired by [LeiterConsulting/splunk-discovery-tool](https://github.com/LeiterConsulting/splunk-discovery-tool), not a fork. It preserves the useful product patterns—durable discovery artifacts, a managed SPL/context library, MCP tool aliasing, encrypted credentials, and deterministic chat routes—while separating them into smaller modules and adding task-specific Ollama/Hugging Face model routing.

## What works now

- A polished local web workspace with setup, investigation chat, discovery, durable cases, context, and model views
- Splunk MCP tool discovery and alias resolution for common server naming differences
- Layered Splunk MCP diagnostics across configuration, DNS, TCP, TLS identity, authentication, and depth-specific tool contracts
- Parallel read-only quick, standard, and deep discovery with change detection, JSON blueprints, and briefs
- First-class security discovery across telemetry freshness, detection health, data-model readiness, and reusable RAG knowledge
- Durable manual discovery jobs with live retained progress, hard call ceilings, cancellation, restart recovery, and per-run results
- Delta-aware model-team reuse with exact input fingerprints and visible cache provenance
- Read-only Splunk MLTK model inventory with definition drift and endpoint-scoped dependency checks
- Opt-in continuous assurance with durable schedules, cross-run signal correlation, response packages, and hard Splunk-call budgets
- A restart-safe validation queue with bounded SPL preview, explicit analyst approval, expiring assurance drafts, live progress, and preserved results
- An evidence-first agent with bounded multi-tool plans, investigation modes, and a structured ledger
- Durable local investigation cases with an evidence-health cockpit, next-best actions, case-scoped context packets, chronological timelines, and handoff exports
- Deterministic SPL cost and reuse intelligence before approval, including safer staged contracts and exact-result reuse
- Audit-first Splunk workload protection with relative query-cost units, shared per-instance concurrency lanes, queue visibility, daily budgets, and enforce-mode gates
- Local analyst feedback and model/task outcome scorecards with no telemetry export
- Versioned local golden investigations with isolated evidence, instrumented tool selection, durable baselines, and explicit promotion gates
- Audit-first model publisher allowlists and local Ed25519 approvals bound to exact model revisions and content digests
- Opt-in generic JSON and Slack Incoming Webhook adapters with exact redaction previews, hash-bound approval, guarded routing, and a tamper-evident local audit chain
- Opt-in export of the verified audit chain to a dedicated Splunk HEC index with a durable cursor, bounded retries, and optional indexer acknowledgement
- Evidence-bound detection-as-code projects with immutable versions, exact-hash review, case linkage, and disabled-by-default Splunk packages
- Ollama chat and tool-capable model support
- Hugging Face chat, embedding, and token-classification adapters
- Capability profiles for Foundation-Sec and SecureBERT 2.0
- Hybrid SQLite FTS5, SecureBERT bi-encoder retrieval, and optional cross-encoder reranking with stable artifact/chunk references
- Conditional specialist inference, short-lived inventory caches, and warm Ollama model retention
- Encrypted Splunk and Hugging Face tokens at rest
- A safe demo workspace that runs without Splunk, Ollama, or Hugging Face
- An outward MCP Streamable HTTP-compatible JSON-RPC endpoint at `POST /mcp`

## Quick start

Python 3.11 or later is the only prerequisite. The universal installer creates an isolated environment, installs dependencies, starts SignalRoom in the background, checks its health, and prints the workspace URL.

### Windows

```powershell
.\install.ps1
```

### Linux and macOS

```bash
chmod +x install.sh
./install.sh
```

Open the URL printed by the installer—normally [http://localhost:8003](http://localhost:8003). Demo mode is opt-in during Setup; a new installation does not silently substitute synthetic data for a live connection.

Lifecycle commands intentionally mirror the Splunk Discovery Tool:

| Action | Windows | Linux/macOS |
|---|---|---|
| Start/install | `.\install.ps1 -Start` | `./install.sh --start` |
| Status | `.\install.ps1 -Status` | `./install.sh --status` |
| Restart | `.\install.ps1 -Restart` | `./install.sh --restart` |
| Stop | `.\install.ps1 -Stop` | `./install.sh --stop` |
| Uninstall environment | `.\install.ps1 -Uninstall` | `./install.sh --uninstall` |
| Public PyPI only | `.\install.ps1 -PublicOnly` | `./install.sh --public_only` |
| Check model readiness | `.\install.ps1 -SetupModels` | `./install.sh --setup-models` |
| Install Ollama and pull models | `.\install.ps1 -InstallOllama -PullModels` | `./install.sh --install-ollama --pull-models` |

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for port fallback, logs, unattended installs, data preservation, and Docker.

## Optional named access

A new install starts in **local single-user mode**. No login is required, the local operator has administrator
authority, and demo/POC setup remains as simple as opening the installer URL. This mode is intended for one trusted
operator on a loopback-bound service.

When the workspace is ready to be shared, open **Setup → Access control · optional** and create the first named
administrator. SignalRoom immediately establishes that administrator's session and begins enforcing:

- **Viewer:** read-only access to workspace evidence and state
- **Analyst:** investigation, curation, validation, cases, and other non-policy workflows
- **Admin:** workspace policy, model installation/routing, repository authority, and user administration
- **Connection assignment:** a separate per-user grant for actions that call the Primary Splunk MCP connection

Local passwords are scrypt-hashed; opaque sessions are time-limited, stored only as SHA-256 digests, use an
HttpOnly same-site cookie, and require a separate same-site CSRF token for changes. Repeated failed logins are
throttled. Disabling RBAC requires the current administrator password, revokes every session, and preserves users
so named access can be re-enabled later.

Local mode is not an authentication boundary: keep SignalRoom bound to localhost until RBAC is enabled. SignalRoom
does not terminate TLS; use a controlled HTTPS reverse proxy and a deployment-specific threat model before network
exposure.

After named access is active, an administrator can opt in to one enterprise OpenID Connect issuer. SignalRoom uses
the authorization-code flow with S256 PKCE, one-time state and nonce values, exact issuer/audience/callback checks,
provider signing keys, and asymmetric ID-token algorithms only. Admission can require an exact tenant and group.
Provider groups map to viewer, analyst, or admin, while Primary Splunk assignment remains a separate policy.
Configured `amr` and/or `acr` values must prove that the identity provider applied the required MFA assurance.

OIDC identities bind only to `(issuer, sub)` and are never linked by matching email or username. Policy changes
revoke all external sessions. At least one active local administrator is retained as a break-glass identity. If
that local password is lost, an authorized host administrator can replace it without opening a web recovery route:

```powershell
signalroom-access reset-password --username security-admin --confirm-local-host-access
```

The recovery command prompts twice, accepts local accounts only, revokes that user's sessions, and appends an audit
event. OIDC tenant claims are an identity-admission boundary, not multi-tenant data isolation.

## Connect Splunk

Open **Setup** and configure:

1. A Splunk MCP HTTP endpoint
2. A bearer token with the narrowest useful read-only permissions
3. The **Verify TLS certificates** toggle; keep it enabled and provide a private CA bundle where possible, or disable it explicitly for a trusted self-signed development endpoint
4. Disable demo mode and test the connection

The diagnostic action evaluates configuration, DNS, TCP reachability, TLS identity, MCP initialization,
authentication, and the read-only tool contract required by each discovery depth. Results are secret-free and
stored locally so the Discovery page can show the current blocking stage and last known successful check.
Continuous assurance runs this same preflight and records `connection-blocked` with zero Splunk tool calls when
the selected discovery depth is not ready.

The client discovers available tools and resolves common aliases such as `splunk_run_query` / `run_splunk_query`, `splunk_get_indexes` / `get_indexes`, and related SAIA SPL helpers.

Environment variables override encrypted stored secrets:

```text
SPLUNK_MCP_TOKEN=...
HF_TOKEN=...
SIGNALROOM_AUDIT_HEC_URL=https://hec.example.com:8088
SIGNALROOM_AUDIT_HEC_TOKEN=...
```

## Connect a detection repository

Repository handoff is optional and disabled by default. In **Setup → Detection repository handoff**, choose an
absolute local Git repository root, base branch or ref, branch prefix, remote name, and commit identity. Use the
read-only inspection action before saving. Remote push and draft-pull-request permissions are independent,
off-by-default controls; enabling them never makes an export, preview, or local commit perform those later
actions automatically.

SignalRoom compares each signed bundle with the exact base commit and displays every added, modified, unchanged,
or protected-conflict file. Approval binds that file plan, bundle SHA-256, signing key, repository, base commit,
and generated branch name into a 30-minute preview digest. Apply uses a temporary no-checkout Git worktree and
isolated index, constructs the exact tree with Git plumbing, verifies its paths and bytes, atomically creates one
local branch, and removes the worktree. Repository hooks, content filters, filesystem monitors, and the Git
`ext` protocol cannot participate in that commit path. The user's primary checkout is never switched or
modified. If the base moves, the bundle changes, a symbolic-link boundary is present, or a repository-owned
policy control differs, the handoff fails closed.

An allowed remote push and GitHub draft pull request each require another explicit confirmation. The latter uses
the locally installed and authenticated GitHub CLI. None of these repository actions writes to Splunk, enables a
saved search, or grants SignalRoom deployment authority.

After a draft pull request exists, **Refresh PR + CI status** performs one explicit read-only GitHub observation;
SignalRoom never polls in the background. The durable snapshot binds the observed PR head to the approved commit,
normalizes review and check state, and recommends the next analyst action. A changed head is a critical stop even
when CI is green. An analyst can preserve that exact snapshot by SHA-256 to a linked case timeline and deep-link
back to the detection. Merge state remains repository evidence—not proof that a saved search was deployed or
enabled in Splunk.

## Model setup

The default registry describes six local-first profiles. The installer downloads only the selected
general and security-reasoning defaults; the additional profiles remain explicit installs:

| Profile | Default | Purpose |
|---|---|---|
| General agent | `llama3.1:8b` through Ollama | Fast orchestration and ordinary chat |
| Security reasoning | `fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF` through Ollama | Triage, hypotheses, ATT&CK reasoning, risk discussion |
| Security instruct | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` through Ollama | Optional instruction-focused security summaries and extraction |
| Cyber retrieval | `cisco-ai/SecureBERT2.0-biencoder` through local Transformers by default | Security-domain semantic retrieval |
| Evidence reranking | `cisco-ai/SecureBERT2.0-cross_encoder` through local Transformers by default | Second-stage ranking of retrieved security evidence |
| Entity extraction | `cisco-ai/SecureBERT2.0-NER` through local Transformers by default | Cybersecurity entity extraction |

Model identifiers are configuration, not hard-coded trust decisions. Review each model card and license, pin an approved revision, and use your organization’s model intake process before production deployment. The app works with lexical FTS retrieval when the optional embedding model is unavailable.

The easiest path is **Setup → Model services**. SignalRoom detects Ollama and the local Transformers runtime, shows every profile as ready or missing, and downloads only after an explicit click. Installing a SecureBERT profile adds the local runtime when necessary, resolves an immutable publisher revision, downloads safetensor assets into `data/models`, and records a local manifest. Opening Setup never starts a model download.

The **Models → Check for updates** action is also read-only. Local Transformers snapshots are compared
to their recorded immutable Hub revision. Hugging Face-backed Ollama models become trackable after an
explicit SignalRoom pull binds the resulting local digest to the Hub revision. Older/pre-existing Ollama
installs are reported as untracked until explicitly refreshed; generic Ollama registry models are labeled
manual refresh because Ollama does not expose a non-mutating remote freshness API. The check never pulls,
updates, loads, unloads, or swaps a model.

The **Models → Local model supply chain** panel observes the exact installed artifact separately from
source freshness. SignalRoom defaults to non-blocking **audit** mode with `cisco-ai`, `fdtn-ai`, and
`ollama-library` on the publisher allowlist. An administrator can verify the current files and explicitly
approve that identity; SignalRoom signs a canonical attestation with a host-local Ed25519 key. Enabling
**enforce** mode requires valid approvals for both currently routed chat profiles and then fails closed for
activation, accepted golden baselines, tournament promotion, and rollback. A digest or immutable revision
change is reported as drift and requires a fresh evaluation and approval. This signature proves local
operator approval—not publisher authorship, license acceptance, or vulnerability-free software. For a
plain Ollama library name, `ollama-library` is the configured namespace assertion; the approved local
content digest remains the identity boundary.

The **Models → Scan MLTK models** action inventories models stored inside the connected Splunk instance
using `| listmodels | head 500`. It records new, changed, unchanged, and previously observed-but-missing
definitions and identifies declared Ollama dependencies. A backing model that is not observed is labeled
for endpoint validation because the MLTK connection may intentionally use a different Ollama service.
This scan performs no Splunk writes and does not claim to measure model accuracy or training-data freshness.

### Golden investigation promotion gate

**Models → Promotion gate for models and prompts** runs five versioned synthetic investigations through the
real agent and selected Ollama profile. The runner creates a temporary evidence library, disables hosted
specialists, and replaces the Splunk connection with an instrumented demo client. The configured Splunk URL and
token are never passed to the harness, and the interface reports a hard contract of zero external Splunk calls.
A benchmark-only 640-token response ceiling keeps candidate timing comparable without limiting normal
investigations.

Each scenario scores routing, exact tool choice, expected evidence retrieval, required answer concepts, and
safety discipline separately. Unexpected live-query behavior, a missed modifying-SPL block, prohibited certainty,
or failure to execute the candidate model is a critical failure regardless of the aggregate score. Promotion
requires an overall score of 80, an 80% scenario pass rate, no scenario below 70, no critical failures, and no
material regression from the accepted baseline. Once a profile has at least five analyst ratings, a positive
outcome rate below 60% also blocks promotion; smaller samples remain visible but directional.

Runs, prompt and suite versions, per-control scores, synthetic responses, baseline comparisons, and the
observed artifact fingerprint are stored in `data/benchmarks.db`. Passing a gate does not automatically
change any configured model or prompt. **Accept as baseline** is a separate analyst action and rechecks the
installed artifact against that evaluation. In enforcement mode, the exact artifact must also have a valid
operator-signed approval.

### Local model tournament and controlled promotion

**Models → Local model tournament** compares two or more enabled Ollama chat profiles without contacting the
configured Splunk instance or Hugging Face. Every candidate runs the same versioned five-scenario suite. SignalRoom
ranks completed runs using deterministic quality and safety results, relative local latency, and established
analyst outcome evidence; directional feedback remains visible but does not influence the score. Task leaders are
reported separately for triage, detection engineering, hunting, SPL review, and leadership briefing.

The two highest-ranked complete candidates then enter five blind response comparisons. Candidate identities remain
hidden until every comparison is recorded. Blind preference can adjust the finalist ranking by at most five points,
so human review informs the decision without overriding a critical safety failure or a blocked promotion gate.
Incomplete review produces no promotion fingerprint.

After review, SignalRoom hashes the exact suite and prompt versions, candidate run IDs, model revisions and local
artifact fingerprints, scores,
blind pair mappings and choices, route target, prior assignment, and winner. **Promote reviewed winner** succeeds
only when that 64-character fingerprint still matches, the winner still has a passing gate, the model revision and
route assignment are unchanged, and the tournament has not already been promoted. Promotion changes only the chosen
local routing assignment and accepts the winning run as the regression baseline; Ollama loads the profile on its
next request. The previous route and baseline are retained for a guarded one-click rollback. A later manual route
or baseline change disables automatic rollback rather than overwriting that newer operator decision.

Tournament and promotion history is stored in `data/model_tournaments.db`. Every blind review, promotion, and
rollback is also written to the local tamper-evident audit chain.

For scripted setup, install SignalRoom and then explicitly install Ollama and download the configured profiles:

```powershell
.\install.ps1 -InstallOllama -PullModels
```

```bash
./install.sh --install-ollama --pull-models
```

The macOS flag opens Ollama's signed app download because its supported installation is interactive; rerun with `--pull-models` after starting the app. Model downloads can consume several gigabytes, so neither installer downloads them unless requested.

The equivalent manual commands are:

```powershell
ollama pull llama3.1:8b
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M
# Optional instruction-focused profile:
ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M
```

Public SecureBERT snapshots can normally be installed locally without a token. A Hugging Face token is optional for downloads and encrypted locally when provided. Cloud inference is a separate, explicit runtime choice; it requires a fine-grained token that can **Make calls to Inference Providers**. A model being present on the Hub does not guarantee serverless inference, so the readiness panel distinguishes Hub access from hosted availability.

You can also use the model helper directly after installation:

```powershell
.\.venv\Scripts\signalroom-models.exe status
.\.venv\Scripts\signalroom-models.exe pull foundation-sec
```

## MCP client configuration

Point an MCP client at:

```text
http://localhost:8003/mcp
```

Exposed tools:

- `security_chat`
- `discover_splunk`
- `search_context`
- `list_artifacts`
- `save_context`

## Investigation modes

The chat composer can auto-detect or explicitly select environment discovery, detection validation,
threat hunting, incident triage, SPL review, incident briefing, or general analysis. Each mode changes
the model instructions and read-only tool plan. Independent retrieval, entity extraction, and Splunk
work run concurrently; irrelevant specialist calls are skipped. Tool results are compacted before model
inference and retained as observations in the evidence ledger.

Discovery stores a `security_blueprint_latest.json` baseline and reports indexes, sourcetypes, hosts,
sources, and coverage domains that changed since the previous run. Individual MCP failures are surfaced
in `collection_status` instead of being silently treated as empty inventory.

Example handshake:

```powershell
$body = @{ jsonrpc = "2.0"; id = 1; method = "tools/list"; params = @{} } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8003/mcp -ContentType application/json -Body $body
```

## Repository map

```text
src/splunk_security_agent/
  agents/          evidence-first chat orchestration and SPL guardrails
  assurance/       durable scheduling, drift correlation, budgets, recovery, and response packages
  audit/           append-only, hash-chained local control-plane events
  benchmarks/      isolated golden investigations, scoring, history, and promotion gates
  discovery/       inventory, coverage analysis, and artifact packaging
  delivery/        redacted webhook policy, approval state, attempts, and retries
  detections/      evidence-bound versions, exact-hash review, and safe local exports
  cases/           durable case records, evidence cockpit, timelines, and handoff exports
  model_trust/     publisher policy, artifact identity, signed approvals, and enforcement
  providers/       Ollama, local Transformers, Hugging Face cloud, and capability routing
  rag/             SQLite evidence and chunk retrieval
  splunk/          tolerant MCP client, layered connection diagnostics, and safe demo client
  validation/      bounded execution queue plus deterministic query cost/reuse intelligence
  workload/        shared Splunk admission control, relative cost policy, and safe local history
  feedback.py      local analyst outcomes and model/task scorecards
  static/          dependency-free operator SPA
  app.py           FastAPI routes and service wiring
  mcp_server.py    outward MCP tools
data/              runtime config, encrypted secrets, database, and artifacts
docs/              architecture, security, and upstream adoption notes
tests/             unit and contract tests
```

## Validate

```powershell
python -m ruff check src tests
python -m pytest -q
python -m splunk_security_agent.evaluation
```

The synthetic evaluation reports routing, entity-gating, and read-only guardrail accuracy without
requiring a live Splunk instance or model inference.

## Immediate value by role

SignalRoom opens with a role → workflow → prompt tree instead of a flat list of generic examples:

| Role | Immediate workflow value |
|---|---|
| SOC analyst | Triage alerts, scope indicators, validate observations, and build timelines |
| Threat hunter | Turn behavior or coverage gaps into testable, bounded hunt hypotheses |
| Detection engineer | Pressure-test rule requirements, false positives, SPL, and data readiness |
| Security leader / CISO | Convert discovery and incident evidence into material risks, owners, and decisions |

Prompts are staged in the composer for operator review rather than executed immediately. Safe static prompt
templates can be shared as deep links. Environment-derived prompts remain out of URLs so Splunk details are
not copied into browser history.

### Evidence ledger

Ledger entries explain why they exist, whether they are an observation or supporting context, confidence,
validation status, and provenance. Opening an entry provides workflow-specific actions such as explaining
relevance, generating validation SPL, starting a hunt, opening the source artifact, or preserving the item
in a durable case timeline.

### Cases and query intelligence

Opening a case builds an investigation cockpit from its timeline, linked artifacts, and case-bound validation
tasks. It separates observations, open hypotheses, unresolved items, decisions, and evidence tensions; then
offers a prioritized next action. **Resume in Investigate** stages a bounded case context packet so the agent can
reuse known facts before requesting another Splunk search.

Before a validation SPL contract is approved, SignalRoom explains deterministic execution risk. It flags missing
index scope, wide or unknown time ranges, high row limits, expensive commands, and prohibited operations; it also
shows positive bounding controls. An exact fingerprint match to a completed validation is surfaced as reusable
evidence, and wider contracts receive a narrower staged SPL suggestion. This is guidance rather than a Splunk
cardinality estimate—the actual query still requires explicit, single-use approval.

Each model-backed Investigate response can be rated **Useful**, **Incorrect**, or **Missing evidence**. Ratings
and optional notes stay in `data/feedback.db`. The Models page aggregates outcomes by local profile and task;
samples under ten ratings are explicitly labeled directional rather than presented as an accuracy claim.

### Detection engineering

The **Detections** workspace promotes a completed validation—not a hypothesis or an unexecuted SPL draft—into
a versioned detection project. The source validation fingerprint, preserved artifact, result count, completion
time, and evidence references remain attached as the trust anchor. Editing creates an immutable new version and
clears prior approval.

Before review, a deterministic promotion gate binds the exact content SHA-256 to a completed validation with the
same SPL, time window, and row limit. It enforces the expected zero/nonzero outcome, required result fields,
optional result-count ceiling, preserved evidence availability, and result-count drift from the last accepted
baseline. Missing evidence never triggers Splunk automatically: SignalRoom creates an editable validation draft
that still requires the analyst's normal approve-and-run flow.

Submitting a passing version for review freezes its current SHA-256. An approval or changes-requested decision
must name that exact hash, and approval atomically accepts the passing gate as the next regression baseline.
Approved versions are indexed into local Context and, when linked to a case, recorded as a case decision. Export
produces a ZIP with `detection.yml`, a disabled `savedsearches.conf` stanza, a review README, and a file-hash
manifest containing the accepted gate provenance. The package contains no raw Splunk rows, sets `disabled = 1`
and `enableSched = 0`, and grants SignalRoom no authority to deploy or enable the search in Splunk.

An approved, gated version can also export a **Git change bundle**. SignalRoom signs its canonical manifest with
a persistent local Ed25519 key and includes a standalone offline verifier, a read-only GitHub pull-request
workflow, repository policy, and change-request checklist. The workflow fails closed until an administrator pins
the out-of-band verified key fingerprint as the protected repository variable
`SIGNALROOM_TRUSTED_KEY_SHA256`. SignalRoom does not initialize a repository, create a commit, push a branch, or
open a pull request as part of export.

When optional repository handoff is configured, the same signed artifact can proceed through a separate
**preview → approve → local commit → optional push → optional draft PR** workflow. Each transition is exact-hash
bound and independently authorized; the export button itself remains a local packaging operation.

After deployment through the organization’s normal process, **Verify in Splunk** performs one explicit read-only
saved-search catalog request. SignalRoom compares the approved name, normalized SPL, target app when supplied,
cron, dispatch bounds, and disabled state. The immutable result distinguishes verified, deployed-but-disabled,
drifted, missing, ambiguous, and inconclusive outcomes. Absence is only called missing when Splunk reports an
exhaustive catalog; capped responses remain unknown. The MCP contract does not expose scheduler execution, alert
actions, suppression, firing, or notable-event behavior, so those controls remain visibly unobserved. An exact
snapshot can be preserved to a linked case without granting deployment or enablement authority.

Verify an extracted change or the ZIP directly:

```bash
signalroom-verify-detection ./repository \
  --trusted-key-sha256 "$SIGNALROOM_TRUSTED_KEY_SHA256"
signalroom-verify-detection signalroom_git_change_abcd1234_v2.zip \
  --trusted-key-sha256 "$SIGNALROOM_TRUSTED_KEY_SHA256"
```

The verifier checks the pinned signing identity, Ed25519 signature, exact file inventory, every signed file hash,
the recomputed canonical approved-content hash and accepted gate binding, gate score, raw-result boundary, and
disabled/unscheduled Splunk stanza.

### Discovery

Discovery is a read-only security-intelligence workflow rather than a count-only inventory. Quick establishes
an inventory baseline. Standard adds one bounded telemetry-freshness profile, saved-search and alert analysis,
detection scope and scheduling checks, deterministic findings, and a four-role local model team. Deep additionally
assesses data models, acceleration, macros, and lookups. Findings, posture changes, and hypotheses can each start
an investigation or enter a case.

Standard and deep discovery run in this order:

1. Deterministic Splunk analysis creates stable evidence references and ranks detections that warrant review.
2. SecureBERT NER and semantic correlation run locally and in parallel over the bounded evidence packet.
3. The general Ollama profile compresses inventory, coverage, change, and collection-state evidence.
4. Foundation-Sec performs the security assessment using a smaller, non-duplicative packet.
5. A deterministic reconciler rejects unknown evidence references, labels unsupported conclusions as needing
   validation, and promotes only evidence-linked hypotheses into investigation tracks.

Operator-initiated discovery now runs through a durable local worker. `data/discovery_jobs.db` retains the
requesting identity, queue and progress events, depth-specific hard Splunk-call ceiling, cancellation state,
restart count, terminal summary, and compact renderable result for each run. Refreshing or closing the browser
does not interrupt the job. A process restart re-queues an interrupted run as a fresh read-only collection;
explicit cancellation is terminal. The Discovery page can reopen retained results and replay each run's activity.
Full timestamped blueprints and briefs remain in the artifact directory, while the job database deliberately
stores the smaller projection that excludes raw inventory catalogs.

### Continuous assurance

The Discovery page can opt in to a local recurring schedule. The policy selects quick, standard, or deep
discovery, an interval, a hard per-run Splunk MCP call ceiling, a maximum number of runs per UTC day, and
notification categories. Scheduling is disabled by default. Manual and scheduled assurance runs share the daily
assurance budget. Assurance, durable manual discovery, compatibility discovery endpoints, and MLTK inventory
share one per-instance read-only execution lane.

Run state and progress events are stored in `data/assurance.db`. A restart re-queues an interrupted read-only
run as a fresh collection; an operator cancellation persists across restart. Completed runs classify inventory,
coverage, MLTK, high-severity finding, collection-failure, dependency, and budget events into acknowledgeable
local notices. Deterministic signals are correlated across runs as transient, repeated, severity-elevated, or
resolved. Repeated medium/low signals and first-seen high/critical signals create deduplicated response packages.
Each package can pivot into Investigate, a case, or the validation queue. Continuous assurance never approves or
executes proposed validation SPL automatically.

Outbound response-package delivery is independently disabled by default. Operators can select a generic JSON
webhook (with loopback HTTP permitted only for local testing), a Slack Incoming Webhook, a Jira Cloud
create-issue adapter, or a Splunk SOAR create-container adapter. Strict redaction sends opaque package metadata and aggregate signal counts while withholding
source-derived package and signal text. Standard redaction may additionally include bounded package text, signal
titles, and subjects. Neither level includes raw events, SPL, validation identifiers, signal fingerprints, discovery
run identifiers, Splunk credentials, or endpoint configuration. Manual mode binds approval to the exact payload
SHA-256 and destination identity. Automatic mode must be separately enabled and applies severity/category policy
before creating a locally deduplicated delivery job.

The Slack adapter accepts only complete `hooks.slack.com` or `hooks.slack-gov.com` URLs, requires verified TLS, emits
only `plain_text` Block Kit objects, and never sends the generic authorization header. Slack controls the destination
channel, sender name, and icon. Incoming Webhooks do not expose a delete operation or document a destination
idempotency key, so an ambiguous retry can duplicate a notification. These limits are shown in the exact-payload
approval modal. See Slack's
[Incoming Webhooks documentation](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).

The Jira adapter accepts only an HTTPS `*.atlassian.net` site origin and uses a dedicated encrypted account email
and API token. Operators map project key, issue type, labels, summary prefix, and severity-to-priority names. Its
read-only test inspects create metadata without creating an issue. An approved delivery may create one issue and
records the returned ID, key, trusted browse URL, a correlation label, and an issue property. It has no authority
to update, transition, comment on, assign, attach to, or delete issues. Because Jira's create endpoint does not
provide a destination idempotency contract, a failed or interrupted create stops automatic retry; the analyst must
inspect the correlation label before explicitly retrying. See Atlassian's
[create-issue API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post)
and [API-token authentication guidance](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/).

For a successfully correlated issue, an analyst can explicitly refresh a minimal read-only observation by immutable
numeric Jira issue ID. SignalRoom requests only project, issue type, workflow status, priority, resolution, Jira's
updated timestamp, and labels needed to verify its correlation marker. It does not request descriptions, comments,
attachments, people, or other issue content. Each result is preserved as a digest-bound local snapshot and compared
with the previous successful observation for identity, workflow, triage, resolution, and correlation-label drift.
A Jira 404 is reported as **not found or not visible** because Jira may use that response when the credentials lack
permission to browse the issue; SignalRoom does not claim the issue was deleted. Reconciliation is never polled and
does not add issue update authority. See Atlassian's
[get-issue API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-get).

The Splunk SOAR adapter accepts an HTTPS SOAR origin, including an internal host and port, and uses a dedicated
encrypted `ph-auth-token`. Operators map container label, type, initial status, sensitivity, tags, tenant ID, name
prefix, and severity names. Its optional read-only test calls container options and never creates a container. An
approved delivery posts exactly one container with `run_automation` set to `false` and no artifacts. SignalRoom has
no route to update, assign, comment on, run an action or playbook against, or delete the container. Every payload
uses a deterministic `source_data_identifier`; SOAR's documented duplicate response returns the existing container
ID, making bounded retry and restart recovery safe after an ambiguous response. TLS verification defaults on and
can use a private CA bundle or be explicitly disabled for a trusted self-signed internal endpoint. See Splunk's
[container endpoint reference](https://help.splunk.com/en/splunk-soar/soar-on-premises/rest-api-reference/8.4.0/container-endpoints/rest-containers)
and [REST authentication guidance](https://help.splunk.com/en/splunk-soar/soar-cloud/rest-api-reference/using-the-splunk-soar-rest-api/using-the-rest-api-reference-for-splunk-soar-cloud).

Attempt state, generic/Slack/SOAR exponential backoff, explicit retries, Jira/SOAR external-record correlation, and restart
recovery are durable. Changing the adapter, URL, authorization identity, adapter mapping or credentials, TLS policy,
or private CA cancels stale queued work and requires a fresh preview. Disabling delivery also cancels queued work;
saved destination and authorization secrets can be explicitly removed.

Ollama model switching is serialized to avoid local accelerator contention. Generative passes use deterministic,
token-bounded structured output, strict local validation, and one visible repair/fallback attempt when necessary.
The Discovery page shows the executed model, role, duration, input size, token ceiling, and validation mode. A
compact latest-run endpoint restores the saved result after reload without returning the raw multi-megabyte catalog.
Each deterministic discovery section and model role also receives a stable input fingerprint. When the relevant
evidence, context revision, model profile, and output contract are unchanged, SignalRoom reuses the prior successful
role result and labels it as `reused` with its source run and zero new inference. Changed inputs invalidate only the
dependent roles.

Standard and deep runs maintain focused `discovery-knowledge` artifacts: the latest telemetry catalog,
detection/data-model catalog, security-posture assessment, and—when available—the Splunk MLTK model catalog. Older latest-state documents are replaced so RAG
does not mix obsolete posture with current posture. Chat retrieves these locally before planning Splunk tools;
inventory and posture questions reuse the discovery record unless the operator explicitly asks for live events,
a refresh, or SPL execution. The agent trace states when a Splunk call was avoided.

### Local specialists and cloud policy

Ollama remains the chat and reasoning path. `specialist_runtime` defaults to `local`, which routes installed
SecureBERT retrieval and entity extraction through Transformers on the SignalRoom host. Hugging Face is contacted
only when the operator deliberately installs a model; subsequent inference is local and does not require a token or
cloud approval.

Selecting the `cloud` specialist runtime enables the separate `huggingface_policy`: `disabled` (the default), `ask`,
or `allow`. Disabled makes no hosted inference or readiness network calls. Ask exposes a per-question approval
control scoped to the named specialist. Allow enables the configured hosted specialists automatically. Discovery
reasoning itself always stays on Ollama regardless of this setting.

### Validation queue

Discovery findings now include deterministic validation proposals tied to stable evidence references. Queueing a
proposal creates an editable draft only. The analyst can inspect the full SPL, relative time window, row cap, and query
fingerprint before granting approval; approval and execution are deliberately separate actions. SignalRoom rechecks the
shared read-only guardrail at draft, approval, and execution boundaries, allows at most a 30-day window and 500 rows,
streams execution and preservation progress, and stores a bounded result preview as a local `validation` artifact.
Approved work survives restarts, while an interrupted running task returns to the approved state for an intentional retry.
Assurance-generated drafts carry a seven-day expiry, a package reference, and a single-execution approval scope.
Expiry invalidates an unexecuted draft or approval without modifying completed evidence. A recurring package reuses
an existing live fingerprint instead of creating duplicate validation work.

Approved detections add a snapshot-bound runtime path after explicit Splunk definition verification. SignalRoom
stages—but does not approve or run—a one-row scheduler-health validation for the uniquely observed saved-search
name. Once the normal queue preserves that exact result, the detection workspace interprets executions, latest
outcome, non-success count, last-run lag, and runtime duration against a cron-derived threshold. The durable
assessment links the deployment digest, query fingerprint, validation artifact, and optional case entry while
remaining explicit that scheduler activity is not alert-firing or response-delivery proof.

### Named authorization and local audit

Major local control-plane decisions and every outbound delivery action are written to `data/audit.db` as an
append-only SHA-256 hash chain. Audit metadata applies key-based secret redaction and the Discovery interface reports
chain integrity. When RBAC is active, request-scoped audit records carry the named username. This is a
tamper-evident local record, not an external immutable audit sink.

The Discovery page can promote that record into a separate, opt-in Splunk HEC delivery authority. SignalRoom
requires a dedicated non-default index and encrypted HEC origin/token, verifies the entire local chain before each
batch, and advances a durable cursor only after HEC accepts the batch. Optional indexer acknowledgement waits for
Splunk to confirm indexing before advancing. The HEC token is never reused for MCP, search, or administration;
use a token restricted to the configured audit index. Existing events are not exported unless the administrator
explicitly selects backfill while enabling or changing the destination.

Export is at-least-once. Every remote event therefore includes the stable local event ID, sequence,
`previous_hash`, and `event_hash` for destination-side correlation or deduplication. A restart retries an
uncommitted cursor; a broken local chain blocks export. See Splunk's
[JSON HEC event format](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.2/get-data-with-http-event-collector/format-events-for-http-event-collector)
and [indexer acknowledgement](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.1/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment)
documentation.

Splunk SOAR now has a duplicate-safe, create-container-only adapter with exact-payload approval, automation disabled,
no artifacts, durable correlation, self-signed/private-CA transport support, and a read-only container-options test.
Correlated Jira issues retain explicit read-only reconciliation and immutable local drift history. Optional local
RBAC gives those actions named role and connection boundaries. Durable manual discovery preserves progress,
cancellation, restart recovery, and retained results. Model evaluation and promotion now carry exact revision and
digest bindings through operator-signed local attestations. A shared Splunk admission controller now protects
Investigate, Discovery, Validation, Assurance, and MLTK traffic with live queue state, relative cost preflight,
per-instance concurrency, and audit-first risk and UTC-day budget policy. Operator-authored evaluation suites now
extend the durable golden and tournament authorities. Verified audit events can now be exported to a dedicated
Splunk index under an explicit HEC delivery policy. Optional single-issuer OIDC now adds PKCE, provider MFA
evidence, exact tenant/group admission, immutable-subject binding, and host-only local-account recovery. The next
production increment is deployment-specific audit retention, dashboards, alerts, destination-side deduplication,
and deeper tenant/data-boundary design.

### Operator-authored evaluation suites

Models now exposes a local evaluation authority for security-team standards that the generic golden gate cannot
know. An administrator can author up to 15 organization scenarios with a synthetic evidence fixture, an analyst
request, an exact expected tool set, forbidden tools, required evidence and conclusion groups, prohibited claims,
and an expected blocked/not-blocked result. The five built-in controls are always prepended, so a custom suite adds
rigor but cannot redefine or remove SignalRoom safety controls.

Suite drafts use optimistic revision checks and an exact SHA-256 fingerprint. Publication requires an explicit
synthetic-data attestation and creates an immutable retained version; later edits create a new draft and version.
Published suites can be archived without deleting their benchmark, review, or promotion history. Only unpublished
drafts can be deleted.

A published suite can drive either a single-profile golden run or a multi-profile tournament. Runs and accepted
baselines are suite-scoped, and tournaments bind the suite ID and composite version into their blind review and
promotion fingerprint. Promotion fails closed if the published suite, prompt, route assignment, or evaluated model
artifact changed. Rollback restores the baseline for that exact suite.

All organization fixtures execute in the same temporary evidence database and instrumented demo-tool boundary as
the core gate. Configured Splunk, Hugging Face hosted inference, production evidence, and persistent RAG context are
not contacted. This is a deterministic local regression authority, not a live Splunk integration test.

### Splunk workload protection

Settings exposes a separate, durable workload policy. `audit` is the default: read-only guardrails and configured
concurrency limits are active, while risk, per-query cost, and UTC-day budget crossings are reported without
blocking. Promoting the policy to `enforce` makes those threshold crossings fail closed before the Splunk MCP call.
Policy changes require administrator authority when RBAC is enabled.

Every normal Splunk MCP call uses one per-instance controller, so parallel chat tool plans cannot bypass Discovery,
Validation, Assurance, or MLTK capacity. Streamed operations show local queue position and admission state.
Validation preflight shows the estimated units, threshold decision, remaining daily budget, and safer staged
contract before approval. History retains operation, tool, lane, query fingerprint, decision, wait, duration, and
relative units; raw SPL is never written to the workload database.

Relative units are a deterministic comparison derived from SPL shape, explicit index and time scope, result cap,
and known expensive commands. They are not predicted scan bytes, search runtime, or an authoritative Splunk
scheduler estimate. Splunk roles, workload pools, quotas, and search limits remain the resource boundary.

### Context

Context is the managed evidence available to retrieval. Artifacts can be filtered, searched, inspected in
full, deep-linked by opaque ID, reused in an investigation, or converted into a validation plan. Runbooks and
threat intelligence remain unverified context until current Splunk evidence supports them.

### Investigation cases

Cases turn transient investigation activity into a durable local record. Each case has an owner, severity,
status (`open`, `investigating`, `contained`, `monitoring`, or `closed`), executive summary, and tags. Analysts
can add notes, observations, hypotheses, actions, decisions, context, and evidence to a chronological timeline.
Evidence-led actions on the ledger, Discovery findings and hypotheses, and Context artifacts can all add an
attributed item directly to an existing case or create a new one. Case links use opaque IDs and survive reloads.

The **Export handoff** action creates both a readable Markdown brief and a structured JSON record under the
local data directory. These packages preserve ownership, case state, source, confidence, validation status,
timestamps, and the complete timeline for shift handoff or downstream review. They do not send notifications,
open tickets, or change Splunk; external workflow automation remains an explicit deployment integration.

## Production boundary

This release is an operator-grade prototype with optional local RBAC, not a complete multi-tenant security product.
Before external exposure, enable RBAC and add HTTPS, trusted proxy configuration, centralized identity and recovery,
configure the dedicated audit export with destination-side retention and alerting, add broader rate limiting, and
complete a deployment-specific threat model.
Keep local single-user mode bound to localhost.

## License and attribution

SignalRoom is MIT-licensed. Upstream inspiration and model provenance are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/UPSTREAM_ADOPTION.md](docs/UPSTREAM_ADOPTION.md).
