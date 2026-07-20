# Connection identities, tenant scopes, and additional MCPs

SignalRoom treats a connection as a security boundary, not only an endpoint URL.

## Primary and additional Splunk connections

Every installation retains the backward-compatible mutable alias `primary`. That alias points to an immutable
connection identity inside `data/connection_registry.db`. The identity fingerprint covers:

- the normalized Splunk MCP endpoint;
- live or isolated-demo mode;
- TLS verification policy;
- the configured private-CA trust material; and
- the tenant scope.

The bearer token is deliberately excluded. Rotating a credential for the same endpoint and trust
contract does not move durable work to another evidence boundary, and SignalRoom never stores a token
or token digest in the registry.

The default tenant scope is `workspace-primary`. It is now an enforced query boundary for managed
artifacts, lexical and semantic RAG retrieval, embedding queues and status, investigation memory,
discovery history/latest state, cases, case cockpit evidence resolution, and SignalRoom's own MCP
tools. Every result retains the alias, immutable connection fingerprint, and tenant scope that
produced it. This is shared-database row filtering, not a claim of separate tenant databases or
complete multi-tenant isolation.

Administrators can add live Splunk aliases such as `production-us`, `production-eu`, or `security-lab`
in Settings. Each alias has its own encrypted MCP token, tenant scope, endpoint/TLS identity, diagnostic
state, and enable/disable lifecycle. A new or changed revision is disabled. It enters the application
header selector only after diagnostics prove that the exact current revision satisfies the quick
discovery tool contract and an administrator explicitly enables it. Token rotation also revokes
admission even though the token is deliberately excluded from the identity fingerprint.

The selected alias is used to construct a separate MCP client, workload-controller identity, model
inventory, discovery pipeline, and investigation agent. Context and case retrieval remain tenant and
revision scoped. Archiving removes the encrypted token and selector entry but preserves existing
evidence, cases, jobs, and immutable provenance.

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

## Multiple Splunk instance lifecycle

The registry separates immutable identities from mutable aliases. The current lifecycle is:

1. Create a stable lowercase alias and tenant scope.
2. Save its endpoint, TLS policy, optional private CA path, and encrypted MCP token.
3. Run streamed configuration, DNS, TCP, TLS, MCP-authentication, and tool-contract diagnostics.
4. Explicitly enable the exact successful revision.
5. Assign the alias to named local users when optional RBAC is active.
6. Select the admitted scope in the header before investigating, discovering, or curating Context and Cases.
7. Disable or archive the alias without deleting retained evidence.

Local POC mode can use every admitted alias. With RBAC enabled, the selector is filtered to the exact
aliases assigned to the signed-in user, and every scoped API request rechecks that assignment. Roles
and connection grants remain separate controls.

Continuous assurance, scheduled shadow forecasting, detection deployment verification, and other
platform-wide durable automation remain Primary-bound in this increment. Manual discovery jobs can
bind and execute against an admitted secondary alias. The next scheduling increment must make the
target alias an explicit policy field rather than inferring it from a browser selector.

Cross-instance comparison, OIDC group-to-alias mapping beyond the current Primary grant, backup and
migration tooling for connection credentials, and optional per-tenant data-plane isolation remain
future work. Comparisons must preserve source attribution instead of merging results into an
unqualified global answer.

## Why additional MCP connections belong in SignalRoom

SignalRoom's mission is evidence-first security analysis around Splunk. Another MCP connection should
be admitted only when it adds corroborating context or a governed handoff:

| Connection | Security purpose | Initial authority |
| --- | --- | --- |
| Additional Splunk MCP | Separate estates and instance-aware investigation | Read-only metadata and search; available now |
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
