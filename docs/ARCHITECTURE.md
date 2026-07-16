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
                   ├── read-only MLTK inventory + definition drift
                   │                         ├── SecureBERT NER + correlation (parallel)
                   │                         ├── general Ollama synthesis
                   │                         ├── Foundation-Sec assessment
                   │                         └── deterministic reconciliation
                   ├── JSON + Markdown artifacts ── indexed back into evidence store
                   └── ValidationService ── draft → approve → bounded SPL → preserved evidence

AssuranceService ── SQLite policy + runs + events + notices
        ├── one restart-safe background worker
        ├── shared per-instance discovery/MLTK execution lane
        └── hard MCP call ceiling + UTC daily run budget
```

## Design decisions

### Models are capabilities

Profiles declare a model source, identifier, task, endpoint, provenance label, and context limit. The router chooses a security reasoning profile only for security-domain work. Embedding, reranking, and NER models are separate capabilities rather than pretend chat models. Broad FTS5 + bi-encoder candidates can be rescored by the optional local SecureBERT cross-encoder before evidence reaches chat or discovery synthesis. Hugging Face is the source for SecureBERT snapshots; `specialist_runtime` determines whether those capabilities execute locally through Transformers or through optional hosted inference.

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

Standard and deep discovery also run Splunk's read-only `listmodels` search. `SplunkModelInventoryService`
normalizes MLTK definitions, fingerprints their owner/app/type/options contract, and compares each scan with the
previous local snapshot. Declared Ollama dependencies are compared only with SignalRoom's configured Ollama
endpoint and carry that scope as an explicit caveat. The resulting catalog becomes local RAG context; it never
loads, updates, deletes, or retrains a Splunk model.

Ollama receives a flattened generation schema limited to grammar-safe structural keywords. SignalRoom then
enforces the complete Pydantic contract locally, including length and collection limits. Generation is seeded,
temperature-zero, and token-bounded; one repair or JSON-mode fallback is allowed and surfaced in the activity UI.
Hosted inference is not part of discovery.

### Continuous assurance is durable but deliberately bounded

`AssuranceStore` persists the singleton schedule policy, run state, progress events, and acknowledgeable notices.
`AssuranceService` owns one local worker. Scheduled work, manual discovery, and MLTK scans share an async execution
lock; no second scheduled run is queued while one is active. A `BudgetedSplunkClient` counts before delegation and
refuses calls beyond the configured ceiling, including calls launched concurrently. On shutdown, active work is
re-queued for a fresh read-only collection; an explicit cancellation is terminal and persists across restart.

The scheduler creates local notifications from deterministic result fields. It does not let an LLM send messages,
approve SPL, or mutate Splunk. A run that observes drift can inform an analyst, but recurring validation remains a
separate approval boundary.

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

Correlate recurring drift across multiple assurance runs and generate deduplicated, expiring validation drafts.
Keep outbound notification channels and any recurring validation authority separately configured and auditable.

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
