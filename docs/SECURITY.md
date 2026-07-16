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
- Hugging Face cloud inference has a separate disabled/ask/allow policy and is never implied by local model installation.

## Known limitations

- The local Fernet key is adjacent to encrypted secrets. This protects against accidental disclosure, not a fully compromised host. Use an OS keychain or secret manager in production.
- There is no authentication or tenant isolation. Do not bind externally.
- SPL command blocking is a guardrail, not a parser or authorization boundary. Enforce read-only roles in Splunk.
- Model output can contain incorrect or unsafe recommendations. Human verification remains required.
- Hugging Face model loading remains a supply-chain decision. Production deployments should add publisher/revision allowlists and artifact signatures around the recorded immutable revision.
- The application does not yet emit a durable audit trail.

## Recommended Splunk role

Create a dedicated service identity with only the indexes and REST/MCP tools required for analysis. Do not grant `admin`, `edit_search_server`, `delete_by_keyword`, or unrestricted write capabilities. Apply search quotas and workload management where available.
