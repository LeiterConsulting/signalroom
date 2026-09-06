# SignalRoom documentation

Choose the document that matches the decision you are making. The web interface uses guided view by default;
these documents preserve the full operational and technical detail needed to deploy, govern, and extend it.

## Use the product

- [User guide](USER_GUIDE.md): navigation, guided/full modes, role-oriented starting points, and terminology.
- [Model orchestration TL;DR](MODEL_ORCHESTRATION_TLDR.md): shareable prompt-to-evidence-to-model flow.
- [Model installation diagnostics](MODEL_DIAGNOSTICS.md): collect a safe model/runtime support log.

## Deploy and operate

- [Deployment and lifecycle](DEPLOYMENT.md): installation, service lifecycle, model bootstrap, access, and TLS.
- [Installation and upgrade compatibility](UPGRADES.md): preflight, retained data, cutover, and rollback boundaries.
- [Operational acceptance](OPERATIONAL_ACCEPTANCE.md): connection, recovery, tenancy, worker, and access drills.
- [Release-candidate acceptance](RELEASE_CANDIDATE.md): automated and named-review promotion gates.
- [Security posture](SECURITY.md): implemented controls and production boundaries.

## Understand and extend

- [Architecture](ARCHITECTURE.md): services, durable stores, trust boundaries, and design decisions.
- [Connection identities and additional MCPs](CONNECTIONS.md): immutable Splunk revisions, tenant scopes, and future connectors.
- [Cisco and Splunk model catalog](MODEL_CATALOG.md): reviewed revisions, admitted capabilities, and exclusions.
- [Upstream adoption map](UPSTREAM_ADOPTION.md): what SignalRoom reused conceptually from the Splunk Discovery Tool.

License and external model/project attribution are recorded in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Interface terminology

The navigation label **Knowledge** replaces the earlier **Context** label for the managed RAG/artifact library.
Internal APIs and technical text may still use `context` for a model context window, retrieved context, or legacy
schema name. **Settings** replaces the earlier **Setup** navigation label. Command names such as
`-SetupModels` and `--setup-models` remain unchanged for compatibility.
