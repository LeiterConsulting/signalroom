# Security posture

The local prototype defaults to localhost, opt-in demo mode, local specialist execution, and read-only tools.

## Implemented controls

- Splunk and Hugging Face tokens are held in a Fernet-encrypted file.
- Secret values are never included in the settings response.
- Environment variables may supply secrets without persistence.
- Named access is optional. Local single-user mode preserves the zero-login POC path; enabling RBAC creates or authenticates a first admin and immediately protects API and MCP routes with named sessions.
- RBAC separates viewer, analyst, and admin roles from per-user Primary Splunk connection assignment. Administrative platform policy and identity operations require the admin role.
- Passwords use salted scrypt hashes. Opaque session and CSRF values are stored only as SHA-256 digests; browser sessions use strict same-site cookies, an HttpOnly session cookie, and a separate header-bound CSRF cookie.
- Failed login attempts are throttled per normalized username and source. Role, connection, active-state, and password changes revoke affected sessions; disabling RBAC revokes all sessions and requires the current admin password.
- Request-scoped audit events inherit the authenticated username. Authentication enablement, disablement, login, logout, user changes, and authorization denials are explicitly audited.
- Known modifying/high-risk SPL commands are blocked in the chat execution path.
- Every normal SignalRoom Splunk MCP caller shares one per-instance admission controller. MCP-call and query concurrency limits always apply; risk, per-query relative-cost, and UTC-day budget thresholds default to non-blocking audit mode and become fail-closed only after explicit admin promotion to enforce mode.
- Workload decisions retain operation metadata and a query fingerprint, never raw SPL. SignalRoom cost units are deterministic comparisons rather than claims about scan bytes, execution time, or Splunk scheduler cost.
- Uploaded context is restricted to text-like extensions and 2 MB.
- Retrieved context is framed as untrusted evidence, not instructions.
- External fonts and script CDNs are not used.
- Demo mode allows validation without live infrastructure.
- SecureBERT downloads are explicit, use safetensor snapshots, resolve an immutable publisher revision, and record a local installation manifest.
- Model freshness checks are read-only. They compare recorded immutable revisions and local Ollama digests without pulling, loading, unloading, or swapping models; unprovable provenance is labeled untracked.
- Model artifact trust defaults to non-blocking audit mode. Exact publisher, immutable revision, runtime, and local content digest identities can receive an explicit operator approval signed with a persistent local Ed25519 key. Enforced mode requires trusted active routes and fails closed for activation, accepted benchmark baselines, tournament promotion, and rollback; artifact drift requires re-evaluation and re-approval.
- Splunk MLTK scans use only `listmodels`, retain local definition fingerprints, and perform zero model writes. Dependency comparisons are explicitly scoped to SignalRoom's configured Ollama endpoint.
- Continuous assurance is opt-in, single-concurrency, and protected by hard per-run MCP call and UTC daily run ceilings. It stores local notifications but never sends them externally or auto-approves validation SPL.
- Interrupted assurance runs restart as fresh read-only collections; explicit cancellation is persisted and prevents recovery from silently resuming work.
- Operator discovery uses a durable single-worker queue with depth-specific hard Splunk-call ceilings. Connection readiness is checked before discovery calls, progress and compact results remain local, and explicit cancellation is terminal.
- Interrupted manual discovery is re-queued as a fresh read-only collection. The requesting username, restart count, call count, and terminal outcome are retained in local job and audit state.
- Assurance packages remain local unless the separate outbound policy is enabled. Generated validation work is deduplicated, expires after seven days, and remains scoped to one explicitly approved execution.
- Outbound response delivery is separately opt-in, requires HTTPS except for generic loopback testing, verifies TLS by default, does not follow redirects, and binds manual approval to the exact adapter-native payload bytes and destination identity. Generic webhooks receive an idempotency key; Slack and Jira do not; Splunk SOAR receives a deterministic source data identifier. Disabling delivery or changing adapter/transport identity cancels pending jobs.
- Strict delivery redaction exposes opaque package metadata and aggregate signal counts while withholding source-derived package and signal text. Standard redaction adds bounded package text, titles, and subjects but never raw results, SPL, validation identifiers, signal fingerprints, discovery run identifiers, credentials, or endpoint configuration.
- Slack Incoming Webhook destinations are restricted to the official commercial or GovSlack webhook hosts and `/services/` URL shape, require verified TLS, receive only `plain_text` blocks, and never receive the generic authorization header.
- Jira Cloud destinations are restricted to an HTTPS `*.atlassian.net` site origin, require verified TLS, and use dedicated encrypted account-email/API-token credentials. The adapter can read create metadata and create one issue only; there is no update, transition, comment, assignment, attachment, or delete route. Successful issue IDs and keys are durably correlated. Unknown and interrupted create outcomes stop for analyst review rather than automatic retry.
- Jira reconciliation is an explicit, verified-TLS GET by immutable correlated issue ID. It requests only project, issue type, status, priority, resolution, updated timestamp, and labels; it stores digest-bound local snapshots and deterministic drift without gaining update authority. The destination fingerprint must remain unchanged. A 404 is retained as `not-found-or-not-visible`, never asserted to prove deletion.
- Splunk SOAR destinations accept only an HTTPS site origin and use a dedicated encrypted `ph-auth-token`. TLS verification defaults on; an operator may select a private CA or explicitly disable verification for a trusted self-signed internal endpoint. The only mutation route creates one container with automation disabled and no artifacts. The adapter cannot update, assign, comment on, run actions or playbooks against, or delete a container. A deterministic `source_data_identifier` permits bounded duplicate recovery, and only a trustworthy numeric created or existing container ID is correlated.
- Major local control-plane decisions and every delivery attempt are stored in an append-only SHA-256 hash-chained audit database with secret-key redaction.
- Detection-as-code projects require completed preserved validation evidence. A deterministic exact-fingerprint promotion gate enforces outcome, field, count, and accepted-baseline drift contracts before hash-bound review; it never runs Splunk or approves a validation draft. Edits create immutable versions, approved projects are retained, and exports contain no raw result rows.
- Git change bundles use a persistent local Ed25519 key, signed canonical manifests, complete detection-file hashing, and an offline verifier. Organizational trust requires pinning the key fingerprint outside the pull request; the generated CI workflow fails when that protected variable is absent and has read-only repository permissions.
- Detection repository handoff is separately opt-in and preview-bound. It resolves an immutable base commit, classifies every file, rejects policy-control replacement and symbolic-link boundaries, expires previews after 30 minutes, and applies through a temporary no-checkout worktree and isolated Git index. The exact commit is constructed with plumbing commands; repository hooks, content filters, filesystem monitors, and the Git `ext` protocol are disabled. The primary checkout is not switched or modified.
- Remote push and GitHub draft-pull-request creation are independent disabled-by-default controls and explicit user actions. Push verifies the exact remote ref; PR creation requires the exact pushed commit and a locally authenticated GitHub CLI.
- GitHub review feedback is refreshed only by explicit user action and stored as an immutable local snapshot. SignalRoom validates the configured repository, PR URL, number, branch, and head commit; a changed head fails the promotion interpretation even when checks pass. Case preservation requires the exact snapshot digest and does not mutate GitHub.
- Splunk deployment verification is an explicit, bounded `get_knowledge_objects` read and never polls. It binds the observation to the exact approved detection hash, fails closed on duplicate app/name identity, treats SPL drift as critical, and distinguishes exhaustive absence from a truncated unknown. Returned fields cannot prove scheduler execution, alert actions, suppression, firing, or notable-event creation. Case preservation requires the exact local snapshot digest.
- Detection runtime verification is staged only after an exact enabled definition and unique saved-search name are observed. It creates an unapproved, bounded `_internal` scheduler draft in the existing single-execution queue; SignalRoom never runs it implicitly. Interpretation requires the unchanged fingerprint, a preserved artifact completed after the deployment snapshot, and an exact runtime-check digest. Scheduler evidence remains name-bound and cannot prove firing or delivery.
- Generated Splunk saved-search stanzas are disabled and unscheduled. SignalRoom never deploys or enables the exported detection and does not acquire Splunk write authority through this workflow.
- Partial discovery cannot resolve an existing correlated signal; absence is treated as unknown until an authoritative collection covers that signal class.
- Hugging Face cloud inference has a separate disabled/ask/allow policy and is never implied by local model installation.

## Known limitations

- The local Fernet key is adjacent to encrypted secrets. This protects against accidental disclosure, not a fully compromised host. Use an OS keychain or secret manager in production.
- Local single-user mode intentionally performs no authentication and grants local-admin authority to every caller. Do not bind that mode externally.
- Local RBAC is not tenant isolation, OIDC/SSO, MFA, account self-service, or a recovery system. Protect `data/auth.db`, retain at least one active admin, and use a controlled HTTPS reverse proxy and external identity boundary for production exposure.
- The app does not terminate HTTPS itself. Session cookies receive the `Secure` attribute only when the request scheme is HTTPS; configure and validate trusted proxy behavior in the deployment environment.
- SPL command blocking is a guardrail, not a parser or authorization boundary. Enforce read-only roles in Splunk.
- SignalRoom workload estimation is static and cannot know real index volume, bucket locality, acceleration state, concurrent non-SignalRoom searches, or Splunk scheduler decisions. Keep authoritative quotas and workload pools in Splunk.
- Model output can contain incorrect or unsafe recommendations. Human verification remains required.
- Model approval is a local operator attestation, not a publisher signature, license review, malware scan, training-data assessment, or vulnerability verdict. Protect and independently inventory `data/model_trust_signing.key`; changing or losing it invalidates the local approval authority.
- The audit chain is local and tamper-evident, not remotely immutable. A fully compromised host can modify the database and application together; production should export verified events to a dedicated audit system.
- The local detection signing key is only as trustworthy as the SignalRoom host and data directory. Back it up securely, restrict filesystem access, and verify its public-key fingerprint through an independent channel before pinning it in repository policy.
- Enabling repository handoff grants SignalRoom narrow write authority over a configured local Git repository. Repository filesystem permissions, Git credentials, remote branch protections, CODEOWNERS, required CI, and reviewer policy remain external enforcement boundaries.
- Slack Incoming Webhooks have at-least-once delivery semantics: Slack does not document a destination idempotency key, so an ambiguous response followed by retry can create a duplicate, and a posted webhook message cannot be deleted through the webhook.
- Jira Cloud issue creation has no destination idempotency contract exposed by this integration. An analyst-requested retry after an unknown outcome can create a duplicate despite the embedded correlation label. Reconciliation is explicit rather than continuously polled, and Jira permissions can make a present issue indistinguishable from a missing issue through a 404 response.
- SignalRoom does not yet provide Teams or email adapters, or destination-native update/delete workflows.
- Enabling outbound delivery creates an explicit data-egress path. Operators must review destination ownership and redaction policy before enabling automatic mode.
- Restart recovery is fresh execution, not exactly-once MCP execution. Calls completed before an interruption may be issued again after restart; Splunk service-role quotas and workload controls remain the authoritative resource boundary.
- Cancellation stops scheduling further Splunk calls and cancels the async discovery plan. A local model pass already executing in a native worker thread may finish computation before its result is discarded.

## Recommended Splunk role

Create a dedicated service identity with only the indexes and REST/MCP tools required for analysis. Do not grant `admin`, `edit_search_server`, `delete_by_keyword`, or unrestricted write capabilities. Apply search quotas and workload management where available.
