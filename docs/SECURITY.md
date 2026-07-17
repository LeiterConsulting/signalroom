# Security posture

The local prototype defaults to localhost, opt-in demo mode, local specialist execution, and read-only tools.

## Implemented controls

- Splunk and Hugging Face tokens are held in a Fernet-encrypted file.
- Secret values are never included in the settings response.
- Environment variables may supply secrets without persistence.
- Known modifying/high-risk SPL commands are blocked in the chat execution path.
- Uploaded context is restricted to text-like extensions and 2 MB.
- Retrieved context is framed as untrusted evidence, not instructions.
- External fonts and script CDNs are not used.
- Demo mode allows validation without live infrastructure.
- SecureBERT downloads are explicit, use safetensor snapshots, resolve an immutable publisher revision, and record a local installation manifest.
- Model freshness checks are read-only. They compare recorded immutable revisions and local Ollama digests without pulling, loading, unloading, or swapping models; unprovable provenance is labeled untracked.
- Splunk MLTK scans use only `listmodels`, retain local definition fingerprints, and perform zero model writes. Dependency comparisons are explicitly scoped to SignalRoom's configured Ollama endpoint.
- Continuous assurance is opt-in, single-concurrency, and protected by hard per-run MCP call and UTC daily run ceilings. It stores local notifications but never sends them externally or auto-approves validation SPL.
- Interrupted assurance runs restart as fresh read-only collections; explicit cancellation is persisted and prevents recovery from silently resuming work.
- Assurance packages remain local unless the separate outbound policy is enabled. Generated validation work is deduplicated, expires after seven days, and remains scoped to one explicitly approved execution.
- Outbound response delivery is separately opt-in, requires HTTPS except for loopback testing, verifies TLS by default, does not follow redirects, binds manual approval to the exact redacted payload bytes and destination identity, and sends an idempotency key. Disabling delivery cancels pending jobs.
- Strict delivery redaction exposes package metadata and aggregate signal counts. Standard redaction adds bounded titles and subjects but never raw results, SPL, validation identifiers, signal fingerprints, discovery run identifiers, credentials, or endpoint configuration.
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
- There is no authentication or tenant isolation. Do not bind externally.
- SPL command blocking is a guardrail, not a parser or authorization boundary. Enforce read-only roles in Splunk.
- Model output can contain incorrect or unsafe recommendations. Human verification remains required.
- Hugging Face model loading remains a supply-chain decision. Production deployments should add publisher/revision allowlists and artifact signatures around the recorded immutable revision.
- The audit chain is local and tamper-evident, not remotely immutable. A fully compromised host can modify the database and application together; production should export verified events to a dedicated audit system.
- The local detection signing key is only as trustworthy as the SignalRoom host and data directory. Back it up securely, restrict filesystem access, and verify its public-key fingerprint through an independent channel before pinning it in repository policy.
- Enabling repository handoff grants SignalRoom narrow write authority over a configured local Git repository. Repository filesystem permissions, Git credentials, remote branch protections, CODEOWNERS, required CI, and reviewer policy remain external enforcement boundaries.
- The generic webhook adapter intentionally does not provide destination-specific Slack, Teams, email, ticketing, or SOAR formatting yet.
- Enabling outbound delivery creates an explicit data-egress path. Operators must review destination ownership and redaction policy before enabling automatic mode.

## Recommended Splunk role

Create a dedicated service identity with only the indexes and REST/MCP tools required for analysis. Do not grant `admin`, `edit_search_server`, `delete_by_keyword`, or unrestricted write capabilities. Apply search quotas and workload management where available.
