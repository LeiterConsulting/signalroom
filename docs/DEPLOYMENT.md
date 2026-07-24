# Deployment and lifecycle

SignalRoom uses the same low-friction lifecycle as the upstream Splunk Discovery Tool: clone or unpack the repository, run one installer, and manage the local service with the same script.

## Prerequisite

- Python 3.11 or newer
- PowerShell 7+ on Windows
- Bash on Linux, macOS, WSL, or Git Bash

Node.js, npm, Docker, Ollama, and Hugging Face are not required to explore demo mode.

## Read-only install and upgrade preflight

Before changing an existing environment, both lifecycle managers run the same compatibility engine. Run it
independently at any time:

```powershell
.\install.ps1 -Preflight
```

```bash
./install.sh --preflight
```

The preflight validates the admitted release path, schema-2 source/installation manifest, Python runtime, writable
capacity, settings and vault pairing, every retained SQLite store, pending restore state, tenant migrations,
restartable work, optional model preservation, runtime binding, and process/container contracts. It is read only.
An automatic installer preflight writes a content-addressed receipt before stopping an owned process. See
[UPGRADES.md](UPGRADES.md) for the complete compatibility and rollback matrix.

## Optional model bootstrap

Setup contains independent readiness panels for three execution paths:

- **Ollama:** detects the configured service, lists installed profiles, and starts an explicit background download with progress. The default security profile pulls the official Foundation-Sec Q4_K_M GGUF directly from Hugging Face through Ollama.
- **Local Transformers (recommended):** installs the runtime and SecureBERT snapshots only after an explicit click. The completed snapshot is pinned to the resolved publisher revision and stored under `data/models`; inference then stays on the SignalRoom host.
- **Hugging Face cloud (optional):** validates the encrypted token only when cloud is selected and policy permits it, then distinguishes Hub access from hosted inference availability.

For a terminal-driven deployment:

```powershell
.\install.ps1 -SetupModels
.\install.ps1 -InstallOllama -PullModels
```

```bash
./install.sh --setup-models
./install.sh --install-ollama --pull-models
```

External installation and model downloads are always opt-in. Local SecureBERT installation is initiated from Setup so the operator sees the exact profile, purpose, and progress. On macOS, `--install-ollama` opens the signed app download; finish the app installation and rerun with `--pull-models`.

For a non-mutating model-preparation audit on Linux or macOS, run:

```bash
./install.sh --diagnose_all
```

The collector runs from the system Python so it remains usable when `.venv`, pip, PyTorch, or Transformers is incomplete. It writes `signalroom-diagnose-all.log` in the installation root and returns a non-zero status when it observes a blocker. It never reads the credential vault or dumps environment variables. See [Model installation diagnostics](MODEL_DIAGNOSTICS.md).

After installing and evaluating models, use **Models → Local model supply chain** to approve each exact
artifact. The default audit mode is appropriate while proving the deployment. Before selecting enforcement,
approve the currently configured general and security-reasoning routes; SignalRoom will reject the transition
otherwise. Back up `data/model_trust_signing.key`, `data/model_trust.db`, and `data/model_attestations/`
together. Treat the signing-key fingerprint as deployment inventory and restrict filesystem access to the
SignalRoom service identity.

## Optional access promotion

The installer deliberately does not require an administrator account. SignalRoom starts in local single-user mode
so one trusted operator can evaluate demo mode, connect Splunk, and validate models with no login ceremony.

Before allowing another person or host to reach the service:

1. Open **Setup → Access control · optional**.
2. Create the first named administrator with a password of at least 12 characters.
3. Add viewer, analyst, or admin identities and independently assign Primary or any admitted additional Splunk aliases.
4. Put SignalRoom behind a controlled HTTPS reverse proxy and verify the browser observes HTTPS.

Enabling RBAC signs the first administrator into the current browser, so setup is not interrupted. Disabling it
requires that administrator's password, revokes all sessions, and returns to local mode without deleting identities.
Re-enabling requires an existing administrator credential. Identity state is stored in `data/auth.db` and is
preserved by normal uninstall; `-PurgeData` / `--purge-data` removes it with the rest of the data directory.

Local mode gives every caller administrator authority. It must remain loopback-bound. SignalRoom does not terminate
TLS; keep named access behind a controlled HTTPS reverse proxy.

### Optional enterprise OIDC

After local RBAC is active, a SignalRoom administrator can configure one provider under **Setup → Access control →
Enterprise identity**:

1. Register the exact callback URI shown in Setup: `/api/auth/oidc/callback` on the externally visible HTTPS origin.
2. Provide the provider's exact issuer URL, client ID, and confidential-client secret.
3. Configure the provider claim names and, where applicable, exact allowed tenant values and admitted groups.
4. Map analyst and administrator groups independently from connection authority.
5. Under **Group-to-Splunk access**, map exact provider group values to each configured alias. Prefer these scoped
   mappings over the broad Primary fallback.
6. Keep at least one required `amr` method (normally `mfa`) or configure accepted provider-specific `acr` values.
7. Save the policy, review the last-claims effective-access preview, and run **Test saved provider** before signing
   out. Every enterprise identity must sign in again after a policy change.

The test reads discovery metadata and signing keys; it does not authenticate a user. The browser flow uses
authorization code plus S256 PKCE and validates issuer, audience, nonce, expiry, signature, tenant, groups, and MFA
evidence before issuing a local SignalRoom session. Identity linkage uses only `(issuer, sub)`. Alias mappings are
exact and filtered against SignalRoom's current connection catalog during every sign-in; archived aliases grant no
new session authority.

The client secret is encrypted in the local vault. An environment-managed deployment can instead set:

```text
SIGNALROOM_OIDC_CLIENT_SECRET=…
```

SignalRoom always retains an active local break-glass administrator. If its password is unavailable, stop or
otherwise control access to the service, open a terminal as the SignalRoom host identity, and run:

```powershell
signalroom-access reset-password --username security-admin --confirm-local-host-access
```

Use `--data-dir` when `SIGNALROOM_DATA_DIR` is not available in the recovery shell. The command changes only an
active local identity, revokes its sessions, and records `auth.local.password.recovered`. It cannot change an OIDC
identity. Direct data-directory access is the recovery authority, so restrict that directory accordingly.

OIDC tenant/group admission and alias authorization do not themselves partition artifacts or processes. SignalRoom
can route eight tenant-owned workflow databases and two manifested file roots into a digest-verified tenant
generation, then build a verified return path before explicitly finalizing shared duplicates. Deploy separate
instances where complete process, credential, control-plane, or audit-authority isolation is required.

## Splunk TLS certificates

Setup exposes a **Verify TLS certificates** toggle for the Splunk MCP connection. Verification is enabled by default and should remain enabled for production connections.

Changing the endpoint, demo/live mode, TLS verification, or private-CA trust advances the immutable
Primary connection revision. Existing continuous-assurance and shadow-forecast schedules will require
an administrator to rebind them in Settings and will be paused during that rebind. Recreate queued
discovery work. This prevents a durable workflow approved for one Splunk instance from silently
running against another.

For an internal certificate authority, keep verification enabled and provide the CA bundle path in Setup. For a trusted development endpoint using a self-signed certificate, verification can be disabled explicitly. Disabling verification preserves transport encryption but does not validate the server certificate or identity.

## Outbound response webhook

Outbound assurance delivery is configured independently on the Discovery page and is disabled by default. HTTPS is
required except for generic loopback development endpoints. Certificate verification defaults on; generic internal
destinations can use a private CA bundle or an explicit verification override. Splunk SOAR also supports those
internal-certificate controls; Slack and Jira always require verified TLS. The destination URL, optional generic
Authorization header, dedicated Jira account email/API token, and dedicated SOAR auth token are
encrypted in the same local vault used for other secrets and are never returned by the API. Saved values can be
explicitly removed in the interface. Environment-managed values must instead be removed from the process environment
followed by a SignalRoom restart.

Jira reconciliation uses the same dedicated credentials and requires permission to browse each correlated issue.
Refreshes are analyst-initiated and read only. Jira can return 404 both when an issue is unavailable and when the
credentials cannot see it, so SignalRoom reports that result as **not found or not visible**.

Splunk SOAR delivery requires permission to create a container with the configured label and tenant. SignalRoom
creates no artifacts and explicitly disables container automation. The optional setup test requires permission to
view container options; it performs only `GET /rest/container_options` and does not create a container. Operators
who do not want to grant that read permission can skip the test without expanding the create-only application path.

Environment-managed deployments can supply these values without saving them through the interface:

```text
SIGNALROOM_WEBHOOK_URL=https://automation.example/hooks/signalroom
SIGNALROOM_WEBHOOK_AUTHORIZATION=Bearer …
SIGNALROOM_JIRA_EMAIL=analyst@example.com
SIGNALROOM_JIRA_API_TOKEN=…
SIGNALROOM_SOAR_AUTH_TOKEN=…
```

## Dedicated Splunk audit index

Remote audit export is configured under **Discovery → Remote audit authority** and is disabled by default. Create a
dedicated Splunk index such as `signalroom_audit` and a separate HEC token restricted to that index. Do not reuse the
read-only MCP token. SignalRoom rejects default and internal index names and includes the configured index in every
HEC event envelope.

Enter the HEC origin only, such as `https://hec.example.com:8088`; SignalRoom appends
`/services/collector/event`. TLS verification defaults on and can use a private CA bundle. The explicit
verification override is intended only for a trusted self-signed internal endpoint. Redirects are not followed.

By default, enabling begins with the next audit event. Select **Backfill the existing verified chain** only when the
destination should receive retained history. **Require Splunk indexer acknowledgement** provides stronger delivery
evidence but requires `useACK=true` on the dedicated HEC token. SignalRoom stores one persistent request channel,
polls the matching acknowledgement endpoint, and does not advance its cursor until confirmation.

Environment-managed deployments can keep both HEC values outside the local encrypted vault:

```text
SIGNALROOM_AUDIT_HEC_URL=https://hec.example.com:8088
SIGNALROOM_AUDIT_HEC_TOKEN=…
```

Grant the token event-ingest access only to the dedicated index.

### Audit operations deployment kit

**Discovery → Remote audit authority → Destination operations** generates a review-only ZIP bound to the current
index, sourcetype, source, and host. Configure the retention expectation, stable-ID canonical-view policy, local
export-lag expectation, destination-silence threshold, denied-request threshold, and dashboard time range. Use
**Preview controls** to inspect the four exact searches and schedules before export.

The archive deliberately separates topology roles:

- `search-head/signalroom_audit_operations` contains the dashboard, macros, metadata, and scheduled-alert
  definitions. Every definition has `disabled = 1`; no alert action is configured.
- `indexer/signalroom_audit_retention` contains only the dedicated-index `frozenTimePeriodInSecs` stanza. Deploy it
  to the indexer tier or indexer-cluster manager path appropriate to the environment. Splunk Cloud customers should
  use their supported app-review and retention-administration process.

Review role access, search cost, scheduler placement, storage sizing, cold-to-frozen archival, and each alert action
before enabling a schedule. `frozenTimePeriodInSecs` controls the age at which buckets freeze, but a size limit can
roll data earlier; without an archive configuration, frozen data is deleted. The generated source-silence alert
assumes regular SignalRoom activity and should remain disabled for a quiet POC unless that expectation is valid.
Splunk documents the relevant settings in
[indexes.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/indexes.conf),
[savedsearches.conf](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.2/configuration-file-reference/10.2.2-configuration-file-reference/savedsearches.conf),
and the
[Simple XML reference](https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/9.0/simple-xml-reference/simple-xml-reference).

The ZIP manifest hashes every generated file and binds the pack to the destination and operations-policy
fingerprints. SignalRoom records exports in its local hash chain, but does not call Splunk, install either app,
enable a search, or configure an alert action.

After an administrator deploys the reviewed components, select the exact admitted Splunk target and choose
**Reconcile deployed pack**. SignalRoom verifies the local archive before making any remote call, requires the HEC
and MCP endpoint hostnames to match, and reads exact index information plus bounded app, saved-search, macro, and
view catalogs. It executes no SPL and stores only matched normalized configuration. A result can be:

- **Verified**: all required fields exposed by MCP match the exported contract.
- **Drift detected**: a value explicitly differs, or an expected object is absent from an exhaustive response.
- **Inconclusive**: a catalog is truncated, an identity is ambiguous, or a required field is unavailable.
- **Blocked**: destination identity or all required MCP reads failed closed.

The MCP contract does not prove full app.conf, navigation, metadata ACL, or cluster-wide bundle replication. Those
limits remain visible in every retained reconciliation rather than being inferred from app presence.

## Windows

```powershell
.\install.ps1
```

The installer will:

1. Validate PowerShell and Python versions.
2. Create `.venv` beside the installer.
3. Validate pip and install SignalRoom in editable mode, rebuilding an interrupted environment if needed.
4. Retry against public PyPI if a configured private package index is unavailable.
5. Create schema-2 `.install_manifest.json` with dependency and exact-source fingerprints.
6. Start the app in a hidden background process.
7. Wait for `/api/health` and print the actual workspace URL.

Useful commands:

```powershell
.\install.ps1 -Status
.\install.ps1 -Preflight
.\install.ps1 -Restart
.\install.ps1 -Stop
.\install.ps1 -Start -OpenBrowser
.\install.ps1 -Start -Port 8100
.\install.ps1 -PublicOnly
.\install.ps1 -SetupModels
.\install.ps1 -InstallOllama -PullModels
```

Positional verbs also work: `.\install.ps1 status`.

## Linux and macOS

```bash
chmod +x install.sh
./install.sh
```

Useful commands:

```bash
./install.sh --status
./install.sh --preflight
./install.sh --diagnose_all
./install.sh --restart
./install.sh --stop
./install.sh --start --open-browser
./install.sh --start --port 8100
./install.sh --public_only
./install.sh --setup-models
./install.sh --install-ollama --pull-models
```

Positional verbs also work: `./install.sh status`.

## Runtime files

All lifecycle files stay inside the repository:

| Path | Purpose |
|---|---|
| `.venv/` | Isolated Python environment |
| `.install_manifest.json` | Installed version, dependency hash, exact-source digest, and lifecycle ownership |
| `data/upgrade/preflight_receipts/` | Content-addressed automatic install/upgrade preflight history |
| `data/upgrade/latest_preflight.json` | Most recent automatic preflight result |
| `.signalroom.pid` | Managed process identifier |
| `.signalroom.runtime.json` | Actual host, port, URL, and start time |
| `signalroom.log` | Standard output |
| `signalroom.err.log` | Server and startup errors |
| `signalroom-diagnose-all.log` | Redacted, non-mutating installation and model-preparation diagnostic report |
| `data/` | Configuration, encrypted secrets, evidence database, and artifacts |
| `data/discovery_jobs.db` | Durable manual discovery queue, progress, cancellation, recovery, and compact results |
| `data/estate_reviews.db` | Content-free immutable multi-estate review references, alignment decisions, and lifecycle state |
| `data/model_trust.db` | Model publisher policy and exact artifact approval history |
| `data/time_series_experiments.db` | Immutable forecast runs, accepted baselines, drift comparisons, and review-only alert candidates |
| `data/time_series_schedules.db` | Shadow schedules, hard-budget attempt history, progress events, restart recovery, and analyst dispositions |
| `data/model_trust_signing.key` | Local Ed25519 private key for operator artifact attestations |
| `data/model_attestations/` | Portable canonical approval payloads, signatures, and public key |
| `data/recovery/exports/` | Administrator-created password-encrypted control-plane packages |
| `data/recovery/inspections/` | Short-lived encrypted uploads and non-secret inspection metadata |
| `data/recovery/pending/` | Validated restart stage and mutation-freeze marker |
| `data/recovery/rollbacks/` | Automatic password-encrypted pre-restore checkpoints |
| `data/recovery/receipts/` | Non-secret applied-restore receipts |
| `data/recovery/rehearsals/` | Payload-free local cryptographic round-trip receipts; no package or password |
| `data/operational_acceptance/receipts/` | State-bound operational assessments without evidence, SPL, prompts, or credentials |

The lifecycle manager validates that a PID belongs to SignalRoom before stopping it. A stale PID will never be used to terminate an unrelated process.

Stopping or restarting SignalRoom does not discard a queued manual discovery. An active job is re-queued and
starts a fresh read-only collection when the worker returns; it does not resume in the middle of an MCP plan.
An operator cancellation remains terminal. Normal uninstall preserves this state with the rest of `data/`;
purging data removes the job history and retained results.

## Encrypted control-plane recovery

Use Setup → **Encrypted control-plane recovery** while signed in as an administrator. Create a unique 16-character
or longer package password, download the resulting `.signalroom-recovery` file, move it to an approved backup
store, and delete the extra local export. Store the password through a separate approved channel.

An inspection is always read only and expires after 30 minutes. A compatible package may then be staged with its
exact package-ID confirmation. Staging creates `data/recovery/rollbacks/pre-restore-<id>.signalroom-recovery` using
the same password and freezes configuration mutations. Download that checkpoint before restart when operational
policy requires an off-host recovery copy.

Apply or cancel with the normal lifecycle manager:

```powershell
.\install.ps1 -Restart
```

```bash
./install.sh --restart
```

At the next start, restore runs before application stores open. Staged component digests and contracts are checked
again; auth sessions and OIDC transactions are cleared. An invalid stage stops startup rather than partially
opening a foreign control plane. If web startup is unavailable, use the host-only tool:

```powershell
signalroom-recovery --data-dir .\data status
signalroom-recovery --data-dir .\data inspect <package>
signalroom-recovery --data-dir .\data restore <package> --host-authorized
signalroom-recovery --data-dir .\data cancel --host-authorized
```

Use `python -m splunk_security_agent.recovery.cli` if the installed console-script entry point has not yet been
refreshed. The tool prompts for the password and exact confirmation; it never accepts a password on the command
line. Do not run host restore concurrently with filesystem backup tools or another SignalRoom process.

The package restores settings, the local credential vault/key, Splunk connection registry, optional RBAC/OIDC
state, and paired model-trust state. It does not restore investigation data, queues, schedules, audit history,
models, generated artifacts, environment variables, external service state, or private CA files. A restored CA
path must exist and be independently trusted on the destination host.

Use Setup → **Recovery and multi-instance acceptance** before promotion and after a connection, tenant route,
access-policy, runtime-bind, or worker lifecycle change. Refresh is local-only. Splunk diagnostics and the encrypted
recovery rehearsal are separate explicit actions. The assessment deliberately blocks local single-user mode when
the recorded runtime host is `0.0.0.0` or `::`; enable RBAC or return the process to loopback. Follow
[Operational acceptance](OPERATIONAL_ACCEPTANCE.md) for the complete sequence.

## Port fallback

Port `8003` is preferred. If it is already occupied, SignalRoom scans the next 20 ports and records the selected URL in `.signalroom.runtime.json`. `start` and `status` print that actual URL.

Use a different preferred port with `-Port 8100` or `--port 8100`.

## Package-index fallback

The installer first honors normal pip configuration. If that fails, it retries against `https://pypi.org/simple` with a fresh cache policy. To skip a configured private index immediately:

```powershell
.\install.ps1 -PublicOnly
```

```bash
./install.sh --public_only
```

## Uninstall and data retention

Normal uninstall removes the virtual environment, lifecycle state, and logs while preserving `data/`:

```powershell
.\install.ps1 -Uninstall
```

```bash
./install.sh --uninstall
```

To also remove configuration, encrypted credentials, the evidence database, uploads, and generated artifacts:

```powershell
.\install.ps1 -Uninstall -PurgeData
```

```bash
./install.sh --uninstall --purge-data
```

Add `-ForceYes` or `--force-yes` for an unattended uninstall.

## Docker Compose

```bash
docker compose up --build -d
```

The published port is bound to localhost by default and `./data` is mounted for persistence. Set
`SIGNALROOM_BIND_ADDRESS=0.0.0.0` only for an explicitly governed LAN deployment. The image build excludes the
host data directory and lifecycle secrets; retained state enters only through the runtime volume. Compose also
provides a health check and graceful-stop window. When Ollama runs on the host, configure its endpoint as
`http://host.docker.internal:11434` in Setup.

The Cisco Time Series Model runtime is optional and remains stopped unless its profile is selected. The easiest
process-install path is **Models → Cisco Time Series Model → Build and start bundled local runtime**. SignalRoom
generates and encrypts the bearer token, builds the isolated Python 3.11 service, streams checkpoint loading, and
waits for readiness.

For a container-first deployment, provide a strong shared token to both services and start the forecasting
profile explicitly:

```bash
export SIGNALROOM_CISCO_TSM_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(36))')"
docker compose --profile forecasting up --build -d
```

The sidecar is published only on loopback, uses a persistent `cisco_tsm_cache` volume, installs
`cisco-tsm==1.0.2` under Python 3.11, and defaults to the pinned
`038831104abace772bd50bffe76da0c77c364c51` checkpoint revision. Override
`CISCO_TSM_MODEL_REVISION` only through a deliberate model intake and regression review. `auto` selects CUDA when
available; set `CISCO_TSM_TORCH_BACKEND=cpu` or `gpu` to require a specific backend. The in-app process launcher
selects the first available port from 8080–8099 and saves the exact endpoint. Container operators can set
`SIGNALROOM_CISCO_TSM_PORT`; service-to-service traffic still uses port 8080 inside the Compose network.
The container runs as a non-root user with a read-only root filesystem, no Linux capabilities, and
`no-new-privileges`; only its checkpoint cache and temporary filesystem are writable. Inference remains local,
but the first model load contacts Hugging Face to download the approved checkpoint.

Forecast history, baseline review notes, and alert-candidate handoffs are local control-plane state in
`data/time_series_experiments.db`; include it in normal data-directory backups. It contains exact forecast SPL,
aggregate time-series statistics, backtest/forecast arrays, model revisions, and fingerprints, but not the raw
Splunk result rows. Treat it as security-sensitive investigation metadata. A restore does not start the Cisco
sidecar or execute any retained validation draft.

Shadow cadence, attempts, progress, and review dispositions are stored separately in
`data/time_series_schedules.db` and require the same backup protection. Restoring an enabled schedule makes it
eligible for its next recorded interval after SignalRoom starts; an interrupted running attempt is retried as a
fresh read-only forecast. Missed intervals are not replayed. Schedules remain bounded to one concurrent run, a
per-schedule UTC daily ceiling, and a 24-run global UTC daily ceiling.

## Manual development setup

The installer is recommended for operators. Developers can still use:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
splunk-security-agent
```
