# Operational acceptance

SignalRoom's operational acceptance board is an evidence view, not an automatic production exercise. It makes the
current state legible, preserves deliberate operator authority, and distinguishes **Passed**, **Attention**,
**Not yet drilled**, and **Blocked**.

## Safe operator sequence

1. Open Setup → **Recovery** and refresh local evidence. This reads only SignalRoom state and makes no Splunk call.
2. Run live diagnostics on Primary and every additional Splunk instance. Each click binds the result to the exact
   current endpoint/TLS/tenant fingerprint and exercises configuration, DNS, TCP, TLS, MCP authentication, and tool
   compatibility. Correct the named failing stage before rerunning it.
3. Review attention states. Disabled execution admission, diagnostics older than seven days, and TLS certificate
   verification disabled are visible acceptance risks, not silent success. A trusted self-signed lab can remain an
   accepted attention item; production should bind a trusted certificate or private CA.
4. Run the local recovery rehearsal. SignalRoom snapshots its fixed control-plane allowlist, uses an ephemeral
   password to encrypt and decrypt it, validates every digest and database/security contract, and discards both the
   package and password. It never creates an export, inspection stage, pending restore, or external call.
5. Review tenant routing, access, and workers. Every configured instance must own a unique tenant scope; every
   isolated route must point to a configured scope; durable bindings must match the current revision; all five
   workers must be online. RBAC requires an active local break-glass admin. Local single-user mode is blocked when
   the recorded runtime host is non-loopback.
6. Capture the assessment. The retained receipt contains the five statuses, immutable connection fingerprints,
   application version, operator, timestamp, and canonical state digest. It contains no endpoint tokens, SPL,
   evidence, cases, model prompts, or raw diagnostic payloads.

Any connection revision, route, access, worker, or rehearsal change produces a different state digest. A prior
receipt remains history and is never presented as the current state.

## Decision matrix

| Contract | Passed | Attention | Not yet drilled | Blocked |
|---|---|---|---|---|
| Recovery | Current release round trip within 90 days | Rehearsal older than 90 days | No current-release rehearsal | Round trip cannot complete |
| Splunk instance | Current diagnostics ready, enabled, recent, verified TLS | Disabled scope, stale diagnostics, or unverified TLS | No diagnostic for current revision | Missing token or failed stage |
| Tenant routing | Unique scope ownership and known routes | Copy/apply currently active | Not applicable | Duplicate scope or orphan route |
| Authorization | Named access plus local break-glass admin | Local-only mode on loopback | Not applicable | Exposed local-admin mode or no local admin under RBAC |
| Durable work | Workers online and bindings current | Not applicable | Not applicable | Offline worker or stale binding |

## Deployment-owned restore drill

The local rehearsal proves package construction and validation; it deliberately does not prove host replacement,
off-host custody, or recovery objectives. Before production promotion, perform this separate controlled exercise:

1. create and download a password-encrypted operator package;
2. move it to the approved off-host backup system and hold the password through a separate approved channel;
3. provision an isolated SignalRoom host with no production traffic and the matching release line;
4. inspect the copied package, stage it with the exact package-ID confirmation, and restart;
5. verify settings, connection identities, access policy, and model-trust authority without issuing production SPL;
6. verify that investigation data, queues, schedules, audit history, model weights, environment secrets, and private
   CA contents were not imported;
7. record recovery time, recovery point, operator identities, package digest, and any external prerequisites in the
   organization's system of record; then destroy the isolated exercise environment under its approved procedure.

SignalRoom does not automate that host-level exercise because doing so would silently create restore authority and
could contact real infrastructure. The deployment owner controls the sandbox, backup system, custody, and evidence.
