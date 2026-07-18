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
        ├── hard MCP call ceiling + UTC daily run budget
        └── AssuranceResponseService
                ├── transient / repeated / severity-elevated / resolved correlation
                ├── deduplicated seven-day response packages
                └── ValidationService drafts (never approval or execution)
```

## Design decisions

### Models are capabilities

Profiles declare a model source, identifier, task, endpoint, provenance label, and context limit. The router chooses a security reasoning profile only for security-domain work. Embedding, reranking, and NER models are separate capabilities rather than pretend chat models. Broad FTS5 + bi-encoder candidates can be rescored by the optional local SecureBERT cross-encoder before evidence reaches chat or discovery synthesis. Hugging Face is the source for SecureBERT snapshots; `specialist_runtime` determines whether those capabilities execute locally through Transformers or through optional hosted inference.

`ModelTournamentService` treats routing changes as a separate authority. It orchestrates multiple immutable golden
runs, applies deterministic quality, latency, and established-feedback scoring, and constructs blind comparisons
for the two highest-ranked complete profiles. A promotion fingerprint covers the suite, prompts, candidate model
revisions and run IDs, blind-review mapping and decisions, prior route assignment, and reviewed winner. Promotion
atomically changes the configured route and accepted regression baseline only after an exact fingerprint match.
Rollback fails closed if either value has changed since promotion.

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

The scheduler creates local notifications from deterministic result fields. `AssuranceResponseService` fingerprints
findings, inventory changes, coverage changes, MLTK drift, and named collection failures. Medium and low signals stay
transient until two consecutive observations; high and critical signals are actionable immediately. An authoritative
collection resolves an absent signal only for the signal classes covered by that discovery depth. Partial collection
never converts absence into resolution.

Actionable signals not already represented by an open package create one local response package with a seven-day
expiry. Evidence-linked discovery proposals become validation drafts; live query fingerprints are reused instead of
duplicated. The scheduler does not let an LLM send messages, approve SPL, or mutate Splunk. Investigate and case pivots
remain analyst actions, and validation approval remains a separate per-contract boundary.

### Discovery validation is an explicit state machine

Semantic discovery sections, non-discovery context, model profiles, and output contracts are fingerprinted separately.
A successful model role is reused only when its complete dependency fingerprint matches. This avoids new local inference
without concealing the decision: the UI shows the source run and zero-inference reuse state.

Validation proposals enter a SQLite-backed state machine as `draft`. Only draft and failed tasks can be edited; editing
resets prior approval and results. An analyst separately transitions an exact fingerprinted contract to `approved`, and
only an approved task can transition atomically to `running`. SPL safety, a relative window of at most 30 days, and a row
cap of 500 are enforced at creation, edit, approval, and execution. Successful results become evidence artifacts; an
interrupted run returns to `approved` after restart, preserving intent without silently rerunning Splunk. Assurance
drafts add a package ID, single-execution scope, and expiry; an expired unexecuted task cannot be approved or run.

### Detection-as-code starts from observed evidence

`DetectionService` accepts only a completed validation whose preserved artifact is still available. The initial
project captures the exact validated SPL, time contract, query fingerprint, result count, and stable evidence
references. Every edit appends an immutable version and clears any prior approval. Review decisions are accepted
only while the project is in review and only when the submitted SHA-256 matches the current canonical content.

The promotion gate is deterministic and reads only durable local state. It requires an exact completed validation
fingerprint, available artifact, expected outcome, required fields, configured count limits, and acceptable drift
from the last accepted gate. It never executes Splunk. When exact evidence is absent, the service can create or
reuse a bounded validation draft, but approval and execution remain separate analyst actions. Submission requires
a passing gate, and final approval accepts that exact gate in the same database transaction as the hash-bound
review decision.

Approval indexes a bounded detection document into local RAG and can add a decision to a linked case. Export is a
local packaging operation, not a Splunk mutation: the generated saved-search stanza is disabled, the manifest
states that no deployment authority is present, records accepted gate provenance, and excludes raw validation
rows. Previously approved projects cannot be deleted; they can be retired while retaining their versions, gate
runs, reviews, and export history.

`DetectionSigningKey` lazily creates a persistent local Ed25519 key only when the first Git change is exported.
The signed repository manifest binds the approved content hash, accepted promotion gate, authority boundary, and
all detection file hashes. Canonical `detection.json` lets the verifier independently recompute that approved
hash, while `detection.yml` remains the human-facing artifact. The generated standalone verifier performs no
network calls and supports an externally pinned public-key fingerprint; the generated CI workflow requires that
protected repository variable rather than trusting a fingerprint modified inside the same pull request. Git and
Splunk mutations remain outside this service boundary.

`DetectionRepositoryService` is a separate, opt-in authority boundary. It compares a temporary signed archive
with a resolved immutable base commit and persists a 30-minute preview contract containing the repository path,
base and content identities, generated branch, signing key, archive hash, and per-file plan. Protected policy
controls and symbolic-link boundaries fail closed. Applying the exact digest creates a temporary Git worktree,
verifies the signed archive again, and uses a no-checkout isolated index plus `hash-object`, `update-index`,
`write-tree`, and `commit-tree` to construct and validate the exact commit before atomically creating the branch.
Git hooks, content filters, filesystem monitors, and the `ext` protocol do not participate. The worktree is then
removed while preserving the new local branch. The configured primary checkout is neither switched nor modified.

Remote push and GitHub draft-PR creation are later state transitions with separate disabled-by-default settings
and exact commit binding. Push verifies the remote ref after transfer. Draft PR creation requires that pushed
identity, an authenticated local GitHub CLI, and an additional explicit action. Repository handoff never changes
the generated disabled saved-search policy and does not cross the Splunk write boundary.

Repository feedback is a later, read-only state transition and is never polled implicitly. An explicit refresh
uses the local GitHub CLI to capture PR identity, exact head OID, lifecycle, review decision, mergeability, and
normalized check results. `DetectionRepositoryStore` keeps each observation as an immutable SHA-256 snapshot.
Head or branch drift from the approved handoff becomes a critical stop condition. A separately requested case
action binds one exact snapshot digest into the linked case timeline; the timeline item deep-links to the
detection and states that repository merge is not deployment proof.

`DetectionDeploymentService` closes the definition-observation loop without acquiring Splunk write authority.
For one exact approved content hash, an explicit action requests the bounded `saved_searches` catalog through
Splunk MCP and compares only returned fields: name, optional target app, normalized SPL, cron, dispatch bounds,
and disabled state. `DetectionDeploymentStore` retains each result as an immutable SHA-256 snapshot. Duplicate
identities fail closed, SPL drift is critical, and absence is classified as missing only when `total_rows` and
`truncated` establish an exhaustive response. Scheduler execution, actions, suppression, and firing remain
unobserved. Preserving a digest-bound result to a linked case is a separate local action.

Runtime verification is a second, deliberately separate evidence chain. Only a verified, enabled definition with
a uniquely observed saved-search name can stage a scheduler-health query. The draft binds the approved detection
hash, immutable deployment snapshot digest, exact SPL fingerprint, cron-derived observation window and lag
threshold, and single-execution approval scope. SignalRoom does not approve or execute the query. After the normal
validation queue preserves a result, deterministic interpretation rejects edited contracts and evidence that
predates the definition snapshot, then classifies execution as healthy, degraded, failing, stale, no-executions,
or inconclusive. The immutable assessment retains its validation artifact and digest; preserving it to a case is
another explicit local action. Scheduler attribution is name-only and never becomes proof of alert firing,
notable-event creation, suppression behavior, or response delivery.

## Outbound delivery is a separate authority

`AssuranceDeliveryService` owns a separately opt-in adapter policy and restart-safe delivery worker. The durable
adapter identity selects a generic JSON webhook, Slack Incoming Webhook, or Jira Cloud issue creation. A deterministic
redactor creates the exact adapter-native payload preview; manual approval binds its SHA-256 to the destination
fingerprint. Automatic policy is a separate operator choice and still applies severity and signal-kind routing. Any
adapter, transport, Jira credential, or Jira field-mapping identity change cancels stale queued work and requires a
new preview.

Generic requests carry an idempotency key and may use an encrypted authorization value. Slack requests use verified
TLS, an allowlisted Incoming Webhook URL shape, and `plain_text` Block Kit objects; generic authorization and
idempotency headers are not sent to Slack. Both adapters refuse redirects and use bounded exponential retries, but
Slack delivery is explicitly at-least-once because Incoming Webhooks do not document a destination idempotency key
and an ambiguous retry can duplicate a post. Every adapter contract grants no Splunk execution or validation
approval authority.

Jira is restricted to a tenant `atlassian.net` origin over verified TLS. SignalRoom can read create metadata and
post one exact create-issue request; it has no update, transition, comment, assignment, attachment, or delete path.
The payload uses Atlassian Document Format, operator-controlled mappings, and a deterministic correlation label and
issue property. A successful response is accepted only with HTTP 201 and a trustworthy numeric ID and issue key;
the durable job then exposes a trusted browse URL constructed from the configured tenant. Ambiguous transport
outcomes and interrupted creates without a persisted key fail closed for analyst inspection instead of automatic
retry. A create whose key was persisted before interruption can be completed locally without another external call.

An analyst can explicitly reconcile a delivered Jira job through the immutable numeric issue ID. The adapter uses
one verified-TLS GET for a fixed minimal field allowlist: project, issue type, status, priority, resolution, updated
timestamp, and labels. Descriptions, comments, attachments, people, and arbitrary fields are not requested or
retained. `delivery_reconciliations` stores each bounded snapshot, its SHA-256, the read outcome, and deterministic
drift from the preceding successful observation. Issue-key/project movement, workflow, priority, resolution, and
correlation-label changes remain visible without modifying the original create correlation. HTTP 404 is persisted
as `not-found-or-not-visible`, not as deletion, because Jira visibility permissions can produce the same response.
Reads are explicit rather than scheduled, require the unchanged destination fingerprint, and add no external
mutation authority.

`AuditStore` records delivery and major control-plane decisions in an append-only local SHA-256 hash chain. Secrets
are redacted before persistence. The UI verifies the chain, but the local database is not a substitute for a remote
immutable audit sink on a fully compromised host.

### MCP exists on both sides

SignalRoom is an MCP client of a Splunk MCP server and an MCP server to agent hosts. That lets another agent call the controlled, domain-specific workflows without receiving raw Splunk credentials.

## Next production increments

1. Authenticated multi-user sessions with RBAC and connection assignment
2. Durable background discovery jobs with cancellation and restart recovery
3. Model revision allowlists and signed model artifacts around the implemented evaluation gates
4. Search cost estimation, per-instance concurrency limits, and Splunk workload controls
5. Broader operator-authored evaluation suites beyond the durable golden, tournament, and feedback history
6. Audit events sent to a dedicated Splunk index
7. Splunk SOAR create-only adapter with an explicit authority and field-mapping contract
