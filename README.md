# SignalRoom — Splunk Security Agent

SignalRoom is a local-first analyst workspace and MCP server for evidence-led Splunk security work. It combines read-only Splunk discovery, a chat agent, model routing, contextual artifacts, and a managed RAG library without requiring a cloud LLM.

This is a focused reimplementation inspired by [LeiterConsulting/splunk-discovery-tool](https://github.com/LeiterConsulting/splunk-discovery-tool), not a fork. It preserves the useful product patterns—durable discovery artifacts, a managed SPL/context library, MCP tool aliasing, encrypted credentials, and deterministic chat routes—while separating them into smaller modules and adding task-specific Ollama/Hugging Face model routing.

## What works now

- A polished local web workspace with setup, investigation chat, discovery, durable cases, context, and model views
- Splunk MCP tool discovery and alias resolution for common server naming differences
- Parallel read-only quick, standard, and deep discovery with change detection, JSON blueprints, and briefs
- First-class security discovery across telemetry freshness, detection health, data-model readiness, and reusable RAG knowledge
- Delta-aware model-team reuse with exact input fingerprints and visible cache provenance
- Read-only Splunk MLTK model inventory with definition drift and endpoint-scoped dependency checks
- Opt-in continuous assurance with durable schedules, restart recovery, cancellation, drift notices, and hard Splunk-call budgets
- A restart-safe validation queue with bounded SPL preview, explicit analyst approval, live progress, and preserved results
- An evidence-first agent with bounded multi-tool plans, investigation modes, and a structured ledger
- Durable local investigation cases with ownership, lifecycle, severity, chronological timelines, and handoff exports
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

## Connect Splunk

Open **Setup** and configure:

1. A Splunk MCP HTTP endpoint
2. A bearer token with the narrowest useful read-only permissions
3. The **Verify TLS certificates** toggle; keep it enabled and provide a private CA bundle where possible, or disable it explicitly for a trusted self-signed development endpoint
4. Disable demo mode and test the connection

The client discovers available tools and resolves common aliases such as `splunk_run_query` / `run_splunk_query`, `splunk_get_indexes` / `get_indexes`, and related SAIA SPL helpers.

Environment variables override encrypted stored secrets:

```text
SPLUNK_MCP_TOKEN=...
HF_TOKEN=...
```

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

The **Models → Scan MLTK models** action inventories models stored inside the connected Splunk instance
using `| listmodels | head 500`. It records new, changed, unchanged, and previously observed-but-missing
definitions and identifies declared Ollama dependencies. A backing model that is not observed is labeled
for endpoint validation because the MLTK connection may intentionally use a different Ollama service.
This scan performs no Splunk writes and does not claim to measure model accuracy or training-data freshness.

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
  assurance/       durable scheduling, budgets, recovery, and drift notices
  discovery/       inventory, coverage analysis, and artifact packaging
  cases/           durable local case records, timelines, and handoff exports
  providers/       Ollama, local Transformers, Hugging Face cloud, and capability routing
  rag/             SQLite evidence and chunk retrieval
  splunk/          tolerant MCP client and safe demo client
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

### Continuous assurance

The Discovery page can opt in to a local recurring schedule. The policy selects quick, standard, or deep
discovery, an interval, a hard per-run Splunk MCP call ceiling, a maximum number of runs per UTC day, and
notification categories. Scheduling is disabled by default. Manual and scheduled runs share the daily budget
and one per-instance execution lane with interactive Discovery and MLTK inventory.

Run state and progress events are stored in `data/assurance.db`. A restart re-queues an interrupted read-only
run as a fresh collection; an operator cancellation persists across restart. Completed runs classify inventory,
coverage, MLTK, high-severity finding, collection-failure, dependency, and budget events into acknowledgeable
local notices. Continuous assurance never approves or executes proposed validation SPL automatically.

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

### Recommended next discovery increment

Turn assurance drift into reviewable response packages: correlate repeated changes across runs, rank persistent versus
transient gaps, and create deduplicated validation drafts with explicit expiry and approval scopes. Outbound notification
delivery should remain separately opt-in and redact environment details by default.

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

This release is an operator-grade prototype, not a finished multi-user security product. Before external exposure, add authentication and authorization, per-user Splunk connection assignment, audit logging, rate limiting, background job execution, retention controls, and a deployment-specific threat model. Keep it bound to localhost until those controls exist.

## License and attribution

SignalRoom is MIT-licensed. Upstream inspiration and model provenance are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/UPSTREAM_ADOPTION.md](docs/UPSTREAM_ADOPTION.md).
