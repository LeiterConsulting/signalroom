# Architecture

SignalRoom uses a deliberately narrow pipeline:

```text
Browser or MCP client
        │
        ▼
FastAPI application ───── outward MCP tools
        │
        ├── SecurityAgent ── mode + capability router ── Ollama / local Transformers / HF cloud
        │        │
        │        ├── hybrid evidence retrieval + evidence ledger
        │        └── bounded read-only Splunk tool plans
        │
        └── DiscoveryPipeline ── Splunk MCP ── deterministic evidence map + fingerprints
                   │                         ├── SecureBERT NER + correlation (parallel)
                   │                         ├── general Ollama synthesis
                   │                         ├── Foundation-Sec assessment
                   │                         └── deterministic reconciliation
                   ├── JSON + Markdown artifacts ── indexed back into evidence store
                   └── ValidationService ── draft → approve → bounded SPL → preserved evidence
```

## Design decisions

### Models are capabilities

Profiles declare a model source, identifier, task, endpoint, provenance label, and context limit. The router chooses a security reasoning profile only for security-domain work. Embedding and NER models are separate capabilities rather than pretend chat models. Hugging Face is the source for SecureBERT snapshots; `specialist_runtime` determines whether those capabilities execute locally through Transformers or through optional hosted inference.

### Deterministic routes precede agentic behavior

High-confidence asks use deterministic read-only MCP plans capped by `max_agent_steps`. Discovery,
metadata, and knowledge-object intents may collect several independent results concurrently. Explicit
SPL is checked against modifying and high-risk commands before execution. Model synthesis happens only
after results are captured, distilled, and added to the evidence ledger.

### Evidence is a first-class object

Artifacts are stored once, chunked deterministically, indexed with SQLite FTS5, and returned with stable
`artifact-id:chunk-number` references. FTS candidates are reranked through local SecureBERT embeddings by
default, or its hosted sentence-similarity interface when cloud is explicitly selected. Retrieved content is explicitly delimited as untrusted data, while
tool observations carry read-only provenance, result counts, confidence, and validation status.

### Discovery produces reusable artifacts

Every run creates a machine-readable security blueprint and an operator brief. Independent inventory
calls run concurrently. A latest baseline records additions, removals, coverage changes, and partial
collection failures. Standard and deep runs add two parallel local SecureBERT specialist passes, a
general Ollama environment synthesis, a Foundation-Sec assessment, and deterministic evidence-reference
reconciliation. The brief is indexed back into RAG for subsequent conversations, while a compact latest-run
projection restores the Discovery UI without loading the raw inventory catalogs.

Ollama receives a flattened generation schema limited to grammar-safe structural keywords. SignalRoom then
enforces the complete Pydantic contract locally, including length and collection limits. Generation is seeded,
temperature-zero, and token-bounded; one repair or JSON-mode fallback is allowed and surfaced in the activity UI.
Hosted inference is not part of discovery.

### Discovery validation is an explicit state machine

Semantic discovery sections, non-discovery context, model profiles, and output contracts are fingerprinted separately.
A successful model role is reused only when its complete dependency fingerprint matches. This avoids new local inference
without concealing the decision: the UI shows the source run and zero-inference reuse state.

Validation proposals enter a SQLite-backed state machine as `draft`. Only draft and failed tasks can be edited; editing
resets prior approval and results. An analyst separately transitions an exact fingerprinted contract to `approved`, and
only an approved task can transition atomically to `running`. SPL safety, a relative window of at most 30 days, and a row
cap of 500 are enforced at creation, edit, approval, and execution. Successful results become evidence artifacts; an
interrupted run returns to `approved` after restart, preserving intent without silently rerunning Splunk.

## Next discovery increment

Add continuous assurance orchestration around this state machine: scheduled restart-safe discovery, cancellation,
per-instance concurrency and search-cost budgets, evidence freshness policies, and drift notifications. Changed inputs
should create reviewable validation drafts; recurring execution must use a separate scoped approval policy.

### MCP exists on both sides

SignalRoom is an MCP client of a Splunk MCP server and an MCP server to agent hosts. That lets another agent call the controlled, domain-specific workflows without receiving raw Splunk credentials.

## Next production increments

1. Authenticated multi-user sessions with RBAC and connection assignment
2. Durable background discovery jobs with cancellation and restart recovery
3. Model revision allowlists, artifact signatures, and evaluation gates
4. Search cost estimation, per-instance concurrency limits, and Splunk workload controls
5. Durable evaluation history with analyst usefulness ratings and regression gates
6. Detection-as-code export and review workflow
7. Audit events sent to a dedicated Splunk index
