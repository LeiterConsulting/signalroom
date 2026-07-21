# Installation and upgrade compatibility

SignalRoom treats an install or upgrade as a retained-data operation, not merely a package installation. The
preflight is read only: it opens SQLite stores in read-only mode, parses lifecycle metadata, inspects filesystem
capacity and recovery state, and evaluates the checked-in process/container contracts. It does not contact Splunk,
download a model, stop a process, install a dependency, or mutate retained data.

Run it directly or through the lifecycle manager:

```powershell
.\install.ps1 -Preflight
signalroom-upgrade-check --json
```

```bash
./install.sh --preflight
signalroom-upgrade-check --json
```

The normal installer runs the same preflight automatically whenever the exact source fingerprint differs from the
installed manifest. A successful automatic preflight is retained under `data/upgrade/preflight_receipts/`. Only
after it passes does the lifecycle manager stop a process that it can prove belongs to this SignalRoom workspace.

## Admitted matrix

| Starting state | Decision | Installer behavior |
|---|---|---|
| No lifecycle manifest | Ready · clean install | Creates `.venv`, manifest schema 2, and missing stores |
| Exact version and source digest | Ready · current | Does not reinstall or restart an already running process |
| Same version, changed source digest | Ready · controlled refresh | Preflights, stops the owned process, refreshes dependencies, and restarts |
| Forward patch in the same major/minor line | Ready · patch upgrade | Uses the controlled refresh path and preserves `data/` |
| Different major/minor line | Blocked | Requires a separately documented data migrator |
| Downgrade | Blocked | Requires an isolated rollback using matching source and recovery evidence |
| Invalid lifecycle manifest | Blocked | Retained data is not deleted; repair lifecycle ownership first |
| Corrupt settings, vault pairing, or SQLite store | Blocked | Names the exact failing retained component |
| Pending encrypted restore | Blocked | Apply or cancel with the current release before changing source |
| Active tenant copy/apply | Blocked | Complete or roll back the transition first |
| Verified, unfinished tenant transition | Ready with attention | Preserves exact transition digests across restart |
| Queued durable work | Ready with attention | Uses each workflow's documented restart/requeue contract |
| Optional local models present or absent | Ready | Preserves `data/models`; starts no download |

Warnings do not claim production safety. For example, a `0.0.0.0` runtime remains upgrade-compatible while the
preflight explicitly calls out the need for RBAC, HTTPS termination, and firewall policy before shared use.

## Lifecycle manifest schema 2

`.install_manifest.json` now binds:

- the SignalRoom version and dependency-file hash;
- a deterministic digest of `src/`, both lifecycle managers, and container deployment files;
- the owning installation root, data directory, operating system, Python environment, and preferred port;
- the `same-major-minor` in-place compatibility policy and mandatory-preflight contract.

A legacy manifest is not trusted as exact-source evidence. Its first run takes the controlled-refresh path and
replaces it with schema 2 after installation succeeds.

## Rollback boundary

SignalRoom does not pretend that an editable source checkout is an automatic application rollback. Before an
upgrade, create a password-encrypted control-plane recovery package and move it to approved off-host storage. If
your recovery objective includes evidence, cases, discovery history, queues, audit history, models, or generated
artifacts, protect the complete `data/` directory with a filesystem or volume snapshot as well; the encrypted
control-plane package intentionally excludes those payloads.

A rollback uses the source or container image that matches the intended version, a clean/rebuilt environment, and
only recovery material compatible with that release line. Never point an older runtime at a data directory that a
newer, unadmitted migrator has changed.

## Containers and network binding

The Docker build excludes the complete host `data/` directory, lifecycle files, logs, tests, and local environment.
Runtime data enters only through `./data:/app/data`. Compose has a health check, graceful-stop window, stable image
label, and configurable host binding:

```bash
# Loopback default
docker compose up --build -d

# Explicit LAN binding; govern access before use
SIGNALROOM_BIND_ADDRESS=0.0.0.0 docker compose up --build -d
```

For process installs, use `-BindAddress 0.0.0.0` on Windows or `--host 0.0.0.0` on Linux/macOS. Loopback remains
the default in every deployment path.
