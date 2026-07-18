# Deployment and lifecycle

SignalRoom uses the same low-friction lifecycle as the upstream Splunk Discovery Tool: clone or unpack the repository, run one installer, and manage the local service with the same script.

## Prerequisite

- Python 3.11 or newer
- PowerShell 7+ on Windows
- Bash on Linux, macOS, WSL, or Git Bash

Node.js, npm, Docker, Ollama, and Hugging Face are not required to explore demo mode.

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

## Splunk TLS certificates

Setup exposes a **Verify TLS certificates** toggle for the Splunk MCP connection. Verification is enabled by default and should remain enabled for production connections.

For an internal certificate authority, keep verification enabled and provide the CA bundle path in Setup. For a trusted development endpoint using a self-signed certificate, verification can be disabled explicitly. Disabling verification preserves transport encryption but does not validate the server certificate or identity.

## Outbound response webhook

Outbound assurance delivery is configured independently on the Discovery page and is disabled by default. HTTPS is
required except for generic loopback development endpoints. Certificate verification defaults on; generic internal
destinations can use a private CA bundle or an explicit verification override. Slack and Jira always require verified
TLS. The destination URL, optional generic Authorization header, and dedicated Jira account email/API token are
encrypted in the same local vault used for other secrets and are never returned by the API. Saved values can be
explicitly removed in the interface. Environment-managed values must instead be removed from the process environment
followed by a SignalRoom restart.

Jira reconciliation uses the same dedicated credentials and requires permission to browse each correlated issue.
Refreshes are analyst-initiated and read only. Jira can return 404 both when an issue is unavailable and when the
credentials cannot see it, so SignalRoom reports that result as **not found or not visible**.

Environment-managed deployments can supply these values without saving them through the interface:

```text
SIGNALROOM_WEBHOOK_URL=https://automation.example/hooks/signalroom
SIGNALROOM_WEBHOOK_AUTHORIZATION=Bearer …
SIGNALROOM_JIRA_EMAIL=analyst@example.com
SIGNALROOM_JIRA_API_TOKEN=…
```

## Windows

```powershell
.\install.ps1
```

The installer will:

1. Validate PowerShell and Python versions.
2. Create `.venv` beside the installer.
3. Validate pip and install SignalRoom in editable mode, rebuilding an interrupted environment if needed.
4. Retry against public PyPI if a configured private package index is unavailable.
5. Create `.install_manifest.json` with a dependency-file fingerprint.
6. Start the app in a hidden background process.
7. Wait for `/api/health` and print the actual workspace URL.

Useful commands:

```powershell
.\install.ps1 -Status
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
| `.install_manifest.json` | Installed version and `pyproject.toml` fingerprint |
| `.signalroom.pid` | Managed process identifier |
| `.signalroom.runtime.json` | Actual host, port, URL, and start time |
| `signalroom.log` | Standard output |
| `signalroom.err.log` | Server and startup errors |
| `data/` | Configuration, encrypted secrets, evidence database, and artifacts |

The lifecycle manager validates that a PID belongs to SignalRoom before stopping it. A stale PID will never be used to terminate an unrelated process.

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

The published port is bound to localhost and `./data` is mounted for persistence. When Ollama runs on the host, configure its endpoint as `http://host.docker.internal:11434` in Setup.

## Manual development setup

The installer is recommended for operators. Developers can still use:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
splunk-security-agent
```
