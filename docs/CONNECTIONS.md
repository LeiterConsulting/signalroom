# Connection identities, tenant scopes, and future MCPs

SignalRoom treats a connection as a security boundary, not only an endpoint URL.

## Primary Splunk today

The current release executes against one mutable alias, `primary`. That alias points to an immutable
connection identity inside `data/connection_registry.db`. The identity fingerprint covers:

- the normalized Splunk MCP endpoint;
- live or isolated-demo mode;
- TLS verification policy;
- the configured private-CA trust material; and
- the tenant scope.

The bearer token is deliberately excluded. Rotating a credential for the same endpoint and trust
contract does not move durable work to another evidence boundary, and SignalRoom never stores a token
or token digest in the registry.

The default tenant scope is `workspace-primary`. In this release it is durable execution and evidence
metadata. It is the foundation for instance-aware authorization and retrieval; it is not a claim of
separate tenant databases or complete multi-tenant isolation.

## Durable workflow behavior

Discovery jobs, continuous-assurance runs, the assurance policy, shadow-forecast schedules, and their
queued attempts copy the exact connection fingerprint and tenant scope at creation.

If an administrator changes the endpoint, TLS trust, mode, or scope:

1. `primary` advances to a new immutable revision.
2. Previously bound work remains attached to its original revision.
3. A worker compares the saved binding before creating a client or issuing a Splunk MCP call.
4. A mismatch stops the workflow with zero calls against the replacement instance.

Assurance policy and shadow schedules can be explicitly rebound by an administrator. The request must
match both the prior fingerprint and the record's `updated_at` value, and rebinding pauses scheduling
for review. A queued discovery job is never rebound; cancel or recreate it so its intent and provenance
remain clear.

Records created before this feature have no recoverable historical identity. SignalRoom performs one
documented migration that binds only blank legacy records to the current Primary revision. It does not
automatically rebind them again.

## Multiple Splunk instances

The registry separates immutable identities from mutable aliases so a future release can add aliases
such as `production-us`, `production-eu`, or `security-lab` without changing the durable workflow
contract. Before execution can span instances, SignalRoom still needs:

- per-alias credential storage and health checks;
- per-user and OIDC-group connection assignments;
- tenant-scoped evidence retrieval and case rules;
- an explicit instance selector in every tool-planning and scheduling surface;
- cross-instance comparison rules that preserve source attribution; and
- migration and backup controls for tenant-isolated data.

Until those controls ship, the additional-connection catalog in Settings is an architecture preview,
not an executable connector manager.

## Why additional MCP connections belong in SignalRoom

SignalRoom's mission is evidence-first security analysis around Splunk. Another MCP connection should
be admitted only when it adds corroborating context or a governed handoff:

| Connection | Security purpose | Initial authority |
| --- | --- | --- |
| Additional Splunk MCP | Separate estates and instance-aware comparison | Read-only metadata and search |
| Asset inventory / CMDB | Ownership, criticality, and business purpose | Read-only lookup |
| Identity / directory | Account, device, group, privilege, and lifecycle context | Read-only lookup |
| Threat intelligence | Sourced, time-bounded indicator context | Read-only enrichment |
| Cloud control plane | Cloud identity, asset, audit, and posture corroboration | Read-only inventory |
| Case management / SOAR | Reviewed evidence handoff | Draft/preview; explicit writes |
| Detection repository | Versioned rules, tests, and runbooks | Read-only; existing Git controls for proposals |

Reputation never proves compromise, an unfamiliar asset is not malware, and contextual data does not
silently become an instruction. Each future connector must declare a stable identity, tenant scope,
least-privilege authority, data-handling boundary, health/version contract, evidence attribution, and
separate approval for external writes.
