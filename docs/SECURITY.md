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
- The generic webhook adapter intentionally does not provide destination-specific Slack, Teams, email, ticketing, or SOAR formatting yet.
- Enabling outbound delivery creates an explicit data-egress path. Operators must review destination ownership and redaction policy before enabling automatic mode.

## Recommended Splunk role

Create a dedicated service identity with only the indexes and REST/MCP tools required for analysis. Do not grant `admin`, `edit_search_server`, `delete_by_keyword`, or unrestricted write capabilities. Apply search quotas and workload management where available.
