# Model installation diagnostics

`./install.sh --diagnose_all` is a read-only support workflow for Linux and macOS model setup. It is designed to produce one useful log even when the SignalRoom virtual environment, local Transformers runtime, Ollama service, or web application is not working.

```bash
cd /path/to/signalroom
./install.sh --diagnose_all
```

The report is overwritten on each run at:

```text
signalroom-diagnose-all.log
```

Run it after reproducing a model setup problem and attach that file to the issue or development conversation. Collect it before restarting SignalRoom when the existing service-log tail is relevant, because the normal lifecycle manager starts each process with fresh `signalroom.log` and `signalroom.err.log` files.

## What it checks

The collector records explicit `PASS`, `WARN`, `FAIL`, and `INFO` observations for:

- Operating system, physical machine architecture, Python architecture, OpenSSL, Apple Silicon capability from
  `sysctl`, and mixed Rosetta/native execution on macOS.
- Source-tree completeness, installation-manifest readability, write access, and free model-storage capacity.
- `.venv` Python and pip availability plus `pip check`.
- Importability and versions of `huggingface_hub`, `sentence_transformers`, `torch`, and `transformers`.
- PyTorch CUDA and Apple Metal Performance Shaders build/availability state.
- A no-install, no-cache pip dry run that verifies compatible binary wheels exist for the configured local-runtime requirements.
- Local model manifests, configuration, safetensors weights, revisions, and model-storage permissions.
- Public Hugging Face DNS, TLS/API reachability, pinned revision metadata, pipeline tags, gating state, and observable safetensors files.
- Ollama CLI discovery and version output.
- `/Applications/Ollama.app` or `~/Applications/Ollama.app` and a running Ollama process on macOS.
- Every configured Ollama endpoint through `/api/version`, `/api/tags`, and `/api/ps`.
- Configured Ollama profile names against the endpoint's installed model catalog.
- The running SignalRoom health and model-readiness APIs when they can be accessed without a named browser session.
- Redacted tails from `signalroom.err.log` and `signalroom.log`.

The pip compatibility step uses `--dry-run`, `--no-deps`, `--only-binary=:all:`, and `--no-cache-dir`. It resolves the four direct runtime requirements without installing packages, building source distributions, or retaining a package cache. This is intended to expose unsupported Python/macOS architecture combinations and package-index failures without repeating the installation.

On an Apple Silicon Mac, a report that says `Apple Silicon is using Intel Python under Rosetta` is actionable
even when `uname -m` reports `x86_64`: translated processes can mask the physical hardware architecture.
Rerun the normal installer and approve its native-Python repair, or use
`./install.sh --install-native-python` for an explicitly approved scripted repair.

## What it does not do

The workflow does not:

- Install or upgrade SignalRoom, pip packages, Ollama, or model files.
- Start, stop, or restart SignalRoom or Ollama.
- Pull an Ollama model or download a Hugging Face snapshot.
- Change settings, model trust, routing, or runtime policy.
- Read `data/secrets.enc`, `.vault.key`, environment variables, or bearer tokens.
- Send a saved Hugging Face token. Public model metadata is tested without authentication.

Common authorization, token, password, API-key, and URL-user-info forms are redacted before text reaches disk. Existing application logs are untrusted input and receive the same redaction pass; review any diagnostic attachment according to the deployment's normal data-handling policy.

## Result semantics

- `PASS` means the tested capability completed successfully.
- `WARN` means an optional component is missing, a check was unavailable, or operator attention is useful.
- `FAIL` means a required installation or configured model path cannot currently operate.
- `INFO` records context or a deliberately skipped check.

The command exits with status `1` when one or more `FAIL` records exist and `0` otherwise. The log is still complete when the command returns `1`.

The final section reports one of:

- `READY`
- `READY WITH ATTENTION`
- `BLOCKED`

## Direct collector invocation

The shell lifecycle command intentionally uses the system Python rather than `.venv`. For testing without network access:

```bash
python3 src/splunk_security_agent/diagnose_all.py \
  --root . \
  --log signalroom-diagnose-all.log \
  --offline
```

`--offline` skips SignalRoom HTTP, Ollama HTTP, PyPI, DNS, and Hugging Face probes. It is primarily useful for local validation; a model-installation support report should normally use `./install.sh --diagnose_all`.
