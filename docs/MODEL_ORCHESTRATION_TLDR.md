# How SignalRoom model orchestration works — TL;DR

SignalRoom uses a deterministic orchestration layer around several narrowly scoped models. The generative LLM does not directly control Splunk and never receives MCP credentials. Application code decides what context to retrieve, which tools may run, and which model receives the final synthesis task.

The UI calls the retained RAG/artifact surface **Knowledge**. This is a presentation label; internal APIs and
architecture may still use `context` for retrieval inputs and context-window state.

```text
Browser prompt
   ↓ NDJSON request and progress stream
Scope and immutable connection gate
   ↓
Intent classifier → model-profile router
   ├─ SPL creation → exact-scope schema graph → local typed intent
   │                                      → deterministic SPL compiler
   ↓
Exact-revision local RAG retrieval
   ├─ SQLite FTS5
   ├─ embedding model
   └─ cross-encoder reranker
   ↓
NER specialist ║ deterministic Splunk tool planner
               ║
               └─ workload and safety gate → Splunk MCP
   ↓
Result enrichment and local Knowledge correlation
   ↓
Exact formatter OR generative model
   ↓
Answer + evidence + ledger + trace + SPL candidates + recommended actions
```

## Request and trust boundary

The browser sends `/api/chat/stream` a structured request containing the prompt, conversation ID, investigation mode, optional model override, search and context permissions, hosted-specialist approval state, and the selected Splunk alias, connection fingerprint, and tenant scope.

Before orchestration starts, SignalRoom verifies that the alias, immutable fingerprint, and tenant still identify the current authorized Splunk connection. A stale or replaced target fails before any model or MCP call. The browser receives NDJSON progress events and five-second heartbeats; this is orchestration progress streaming rather than token streaming.

## Intent and model routing

`ModelRouter` classifies the prompt into general, discovery, detection, hunt, triage, SPL, or executive-brief mode. This is currently a fast deterministic classifier, not another LLM call.

Security modes route to the configured security-reasoning profile, while ordinary questions route to the general profile. An operator can explicitly select a profile. Each profile declares a provider, model identifier, endpoint, task, context window, and output limit.

The provider boundary supports:

- Ollama for generative chat and security reasoning.
- Local Transformers for embedding, NER, reranking, and classification.
- Hugging Face hosted inference when the corresponding policy and request approval permit a specialist pass.

The normal operating posture is local-first: Ollama generates responses and downloaded Transformers models perform specialist work.

## Retrieve before querying Splunk

Unless the prompt requires current event data, SignalRoom searches evidence belonging to the selected tenant,
connection alias, and immutable connection revision before considering another SPL query:

1. SQLite FTS5 retrieves lexical candidates.
2. The configured embedding model adds semantic candidates when available.
3. The configured cross-encoder optionally reranks the merged set.
4. SignalRoom supplies the six strongest chunks to the investigation.

Embeddings are retained for reuse, and identical retrievals are cached briefly. If a specialist is unavailable, retrieval degrades to FTS5 instead of failing the request. This lets discovery knowledge and RAG eliminate repeat Splunk searches.

## SPL creation takes a separate trusted path

When the analyst asks SignalRoom to create SPL, the normal free-form synthesis path does not author the query.
The SPL Context Engine loads the latest discovery blueprint for the exact active connection revision and builds a
question-ranked schema packet containing catalog names, knowledge-object relationships, and result field/type
shapes. Event rows are omitted from that planning packet. It also excludes saved-search bodies, evidence excerpts,
`_raw`, and actual tool-result values. Pasted JSON and multi-field key/value samples are deterministically converted
to clearly labeled synthetic shapes before the model call.

The local model returns one to four typed search intents under a strict JSON schema. Application code then
resolves every index, sourcetype, and field against the full exact-scope catalog and compiles only an allowlisted
set of event, count, aggregate, and timechart forms with an explicit relative window and row cap. Unknown schema
blocks the affected draft. The model never supplies the trusted SPL string.

Each compiled candidate includes a trust receipt: compiler origin, context revision, discovery run, authoring
data-exposure contract, completed checks, a typed expected-result shape, and the still-pending Splunk validation
stages. This makes **context compiled** a review claim—not an execution claim. In the validation queue, SignalRoom
discovers parser and optional SAIA tools on the exact MCP target. Parser validation must return an explicit positive
decision to pass; unavailable or ambiguous capability is labeled as requiring runtime proof. SAIA is critique-only
and receives SPL plus bounds, never event rows. The approved bounded run then produces a value-free field/type
receipt showing whether the observed result shape matched the compiled intent.

## Specialist work and MCP planning

After retrieval, SignalRoom runs security-entity extraction and deterministic tool planning concurrently. Entity extraction combines typed field and indicator patterns with the configured NER specialist.

The tool planner is deliberately not an open-ended ReAct loop. The LLM does not invent arbitrary MCP calls. Application code recognizes bounded intents such as:

- Latest, recent, or counted events in a named index.
- Explicit read-only SPL.
- Index, sourcetype, host, and source inventory.
- Saved searches, alerts, and deployment information.
- Small read-only discovery plans.

Plans have a configured step ceiling, capped at six calls, and independent metadata calls may execute concurrently.

## Governed Splunk MCP execution

Every Splunk operation passes through the shared per-instance workload controller. It applies or records:

- Read-only SPL restrictions.
- Query risk and relative-cost estimates.
- Per-query and UTC-day budgets.
- MCP-call and query concurrency.
- Queue state and timeouts.
- Immutable instance identity.
- A query fingerprint without retaining raw SPL in workload history.

The MCP client then performs the JSON-RPC initialization handshake, reads the server tool catalog, resolves SignalRoom's logical tool name against compatible Splunk tool aliases, calls `tools/call`, and normalizes JSON or event-stream content. Tokens, TLS settings, and MCP sessions stay behind this boundary and are never placed in the model prompt.

## Result enrichment

Splunk results are bounded before model use: SignalRoom limits nesting depth, field count, row samples, and string length. It then extracts deterministic pivots such as hosts, users, IPs, hashes, domains, CVEs, processes, indexes, and sourcetypes.

The NER specialist can add candidate pivots, and those pivots are correlated against local Knowledge without another SPL query. Specialist failures soft-fail to deterministic extraction and lexical retrieval.

## Exact rendering or generative synthesis

Narrow factual requests such as “What is the latest event in this index?” are formatted directly from the MCP result. SignalRoom skips LLM synthesis for these responses so exact timestamps and fields are not reinterpreted.

For analytical requests, SignalRoom builds a bounded prompt from:

- A security-analyst system policy.
- Instructions for the selected investigation mode.
- Recent conversation turns.
- Retrieved evidence labeled `[E1]`, `[E2]`, and so on.
- A bounded `[TOOL_RESULT]` when a tool ran.
- Extracted entities.

Evidence and tool output are explicitly marked as untrusted data rather than instructions. The model is directed to separate observations from hypotheses, cite supplied evidence, and state what remains unproven.

The prompt also receives an authoritative scope capsule naming the selected alias, tenant, and immutable
connection revision. If no discovery knowledge for that exact scope was retrieved, the model is told not to imply
that an index, sourcetype, field, or knowledge object exists. This keeps SPL proposals tied to the active Splunk
instance rather than to stale context from a prior connection revision.

For Ollama, SignalRoom checks the resident models, unloads other managed peers when necessary, activates the requested model with a keep-alive, calls `/api/chat`, and verifies that Ollama reports the model that was requested. If inference fails or returns an empty response, SignalRoom produces a deterministic evidence-first fallback.

## Structured output

The final response is a structured envelope, not just generated text. It includes:

- The answer and executed/requested model identities.
- Route, investigation mode, and model activation details.
- Evidence references and connection provenance.
- Evidence-ledger entries with validation status and follow-on actions.
- Tool, model, context, and guardrail trace entries.
- Entity pivots, suggested actions, and relevant specialist recommendations.
- Every distinct SPL-shaped code block as a scope-bound candidate with purpose, expected result, evidence references, default bounds, and initial safety state.
- The immutable Splunk alias, fingerprint, and tenant scope.

The browser presents one **Try this SPL in Splunk** action or, for multiple candidates, a comparison chooser.
Each reviewable block is checked through query intelligence before it can become a validation draft. Model output
never bypasses the existing draft, explicit approval, workload admission, and MCP execution state machine.

Conversation memory is currently process-local and keyed by tenant, connection fingerprint, and conversation ID. Evidence, discovery, cases, validations, and other operational records use separate durable stores.

## Honest V1 characterization

SignalRoom V1 is a bounded, code-directed security workflow with specialist ML stages and one generative synthesis model. It is not a free-roaming multi-agent system.

That design provides predictable tool use, local-first inference, and explicit provenance. Current limitations include a defined tool-intent grammar, one generative synthesis model per normal response, non-streaming model generation, and non-durable chat memory.

For the deeper service and data-boundary description, see [ARCHITECTURE.md](ARCHITECTURE.md).
