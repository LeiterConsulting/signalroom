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

In the web workspace, begin with **Settings → Models** for readiness and installation. Use **Models → Show all
tools** for artifact trust, evaluation, promotion, MLTK inventory, and publisher review. The guided/full choice
does not change what this diagnostic collects.

## Guided installation troubleshooting

Before using the two-runtime drill below, each missing non-Ollama model in **Settings → Models** exposes its own
adaptive action. Loading the page performs a bounded, credential-free preflight of architecture, runtime, free
storage, partial model state, and public publisher metadata. It does not install anything. SignalRoom stores only
safe attempt metadata in `data/model_install_attempts.json`; package output, tokens, and model content are not
retained there.

The first action is selected from that preflight. If it fails, the button is relabeled **Retry** and the model row
plus browser notification explain what failed and how the next attempt differs. The recovery ladder can isolate
runtime resolution to public PyPI, disable Hugging Face Xet in favor of verified native-system HTTPS, and finally
remove only the selected model's incomplete directory before a clean immutable snapshot download. Each retry is
explicit. TLS and hostname verification remain enabled throughout.

**Settings → Models → Guided installation troubleshooting** is the mutating companion to the read-only
collector. An administrator selects one Ollama profile and one local Transformers specialist, confirms the
potentially multi-gigabyte operation, and SignalRoom then:

1. records the host OS, Python, architecture, and Apple Silicon translation state;
2. verifies or explicitly installs the selected Ollama model;
3. verifies or explicitly installs the local specialist runtime and safetensor snapshot;
4. runs a synthetic, value-free capability check through each local runtime; and
5. returns the exact failing stage, redacted installer tail, corrective actions, and shipped/configured
   alternatives without changing active model routing, artifact-trust policy, or cloud policy.

The drill checks both paths even when the first fails. Its **Copy safe troubleshooting report** action excludes
credentials, model output, and investigation data.

Admitted public SecureBERT repositories use `https://huggingface.co` with `token=False` on the first attempt, even
when a saved token or alternate Hub endpoint exists. The result explicitly identifies this as the credential-free
public source already used. If the normal package request fails within 45 seconds in a way consistent with a narrow
development index or mirror, the drill makes one bounded public-only retry:

- pip uses `--isolated --index-url https://pypi.org/simple --no-cache-dir --no-input`.

The receipt identifies the source, states that no credential was sent, and records success or failure. TLS
verification is never disabled. Certificate failures, storage failures, and filesystem-permission failures do
not trigger an automatic repeated request to the same source. The per-model **Retry** action may explicitly
select a materially different verified transfer method after one of those failures. The same guarded package
retry and public-first model policy are used by an explicit one-profile local specialist installation;
opening Settings and running readiness never install packages or retrieve model weights. `--diagnose_all` may use the same source decision for a
second `--dry-run`: it strips all `PIP_*` settings, ignores pip configuration, sends no credentials, and resolves
against public PyPI without installing or caching anything.

SignalRoom gives public package and Hugging Face clients an explicit native operating-system TLS context. On
macOS, downloads therefore use the same Keychain-managed trust decisions as the host instead of being limited to
a Python-specific CA bundle. This is scoped rather than process-wide: it cannot override a Splunk MCP
connection's verify-TLS or private-CA policy. The result card and copied report identify `native-system` or
`python-default`; neither mode disables certificate or hostname verification. If native trust is active and the
request still fails, the issuer (often an organization TLS-inspection root) is not trusted or the served chain is
incomplete. Repair that trust in Keychain Access, restart SignalRoom, and retry. Where policy distributes a PEM
bundle instead, set `SSL_CERT_FILE` to the approved complete bundle before starting SignalRoom.

## What it checks

The collector records explicit `PASS`, `WARN`, `FAIL`, and `INFO` observations for:

- Operating system, physical machine architecture, Python architecture, OpenSSL, native/system HTTPS trust,
  CA-path presence, Apple Silicon capability from `sysctl`, and mixed Rosetta/native execution on macOS.
- Source-tree completeness, installation-manifest readability, write access, and free model-storage capacity.
- `.venv` Python and pip availability plus `pip check`.
- Importability and versions of `huggingface_hub`, `sentence_transformers`, `torch`, and `transformers`.
- PyTorch CUDA and Apple Metal Performance Shaders build/availability state.
- A no-install, no-cache pip dry run that verifies compatible binary wheels exist for the configured local-runtime
  requirements. A fast restricted-index failure triggers one isolated, credential-free public-PyPI dry run; a
  successful fallback records the configured index as a warning rather than falsely blocking the host.
- Local model manifests, configuration, safetensors weights, revisions, and model-storage permissions.
- Public Hugging Face DNS, TLS/API reachability, pinned revision metadata, pipeline tags, gating state, and observable
  safetensors files. A one-byte range probe follows each weight URL to verify the separate redirected artifact
  delivery/CDN trust path without retaining model content or URL query signatures.
- Ollama CLI discovery and version output.
- `/Applications/Ollama.app` or `~/Applications/Ollama.app` and a running Ollama process on macOS.
- Every configured Ollama endpoint through `/api/version`, `/api/tags`, and `/api/ps`.
- Configured Ollama profile names against the endpoint's installed model catalog.
- The running SignalRoom health and model-readiness APIs when they can be accessed without a named browser session.
- Redacted tails from `signalroom.err.log` and `signalroom.log`.

The pip compatibility step uses `--dry-run`, `--no-deps`, `--only-binary=:all:`, and `--no-cache-dir`. It resolves
the four direct runtime requirements without installing packages, building source distributions, or retaining a
package cache. If the configured source quickly reports an unavailable distribution, authorization, or connectivity
signature, the fallback adds `--isolated --index-url https://pypi.org/simple --no-input`, removes inherited
`PIP_*` values, and sets `PIP_CONFIG_FILE` to the platform null device. This distinguishes a narrow mirror from
an unsupported host without exposing credentials or mutating the environment.

On an Apple Silicon Mac, a report that says `Apple Silicon is using Intel Python under Rosetta` is actionable
even when `uname -m` reports `x86_64`: translated processes can mask the physical hardware architecture.
Rerun the normal installer and approve its native-Python repair, or use
`./install.sh --install-native-python` for an explicitly approved scripted repair.

## What it does not do

The workflow does not:

- Install or upgrade SignalRoom, pip packages, Ollama, or model files.
- Start, stop, or restart SignalRoom or Ollama.
- Pull an Ollama model or download/retain a Hugging Face snapshot. It reads at most one byte from each
  public weight-delivery path solely to exercise redirects and TLS trust.
- Change settings, model trust, routing, or runtime policy.
- Read `data/secrets.enc`, `.vault.key`, environment variables, or bearer tokens.
- Send a saved Hugging Face token. Public model metadata is tested without authentication.

These statements describe `./install.sh --diagnose_all`, not the separately confirmed guided installation
troubleshooting action above.

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

The shell lifecycle command uses the SignalRoom virtual-environment Python when available so the diagnostic
exercises the same native trust integration as the running application; before installation it falls back to the
selected system Python. For testing without network access:

```bash
python3 src/splunk_security_agent/diagnose_all.py \
  --root . \
  --log signalroom-diagnose-all.log \
  --offline
```

`--offline` skips SignalRoom HTTP, Ollama HTTP, PyPI, DNS, and Hugging Face probes. It is primarily useful for local validation; a model-installation support report should normally use `./install.sh --diagnose_all`.
