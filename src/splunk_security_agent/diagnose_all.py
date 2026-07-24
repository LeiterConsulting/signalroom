from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import sysconfig
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

RUNTIME_REQUIREMENTS = (
    "huggingface-hub>=0.27,<2",
    "sentence-transformers>=3.4,<6",
    "torch>=2.5",
    "transformers>=4.48,<6",
)
DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434"
MAX_HTTP_BYTES = 2 * 1024 * 1024
MAX_COMMAND_CHARACTERS = 24_000

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|access[_-]?token|api[_-]?key|password|secret|token)"
    r"(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIALS = re.compile(r"(https?://)([^/@\s:]+):([^/@\s]+)@")


def redact(value: Any) -> str:
    """Remove common credential forms before diagnostic text reaches disk."""
    text = str(value)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        text,
    )
    return _URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)


def safe_url(value: str) -> str:
    """Return an endpoint identity without user info, query, or fragment."""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return redact(value)
    if parsed.scheme not in {"http", "https"} or not hostname:
        return redact(value)
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), "", ""))


def ollama_base(value: str) -> str:
    endpoint = (value or DEFAULT_OLLAMA_ENDPOINT).rstrip("/")
    for suffix in ("/api/chat", "/api/tags", "/v1"):
        if endpoint.endswith(suffix):
            endpoint = endpoint[: -len(suffix)]
    return endpoint


def model_matches(requested: str, actual: str) -> bool:
    left = requested.lower()
    right = actual.lower()
    return left == right or (":" not in left and right == f"{left}:latest")


def bounded_output(value: str, limit: int = MAX_COMMAND_CHARACTERS) -> str:
    text = redact(value).strip()
    if len(text) <= limit:
        return text
    head = text[:4000]
    tail = text[-(limit - 4100) :]
    return f"{head}\n... [diagnostic output truncated] ...\n{tail}"


class DiagnosticLog:
    def __init__(self, path: Path):
        self.path = path
        self.counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
        self._stream: Any = None

    def __enter__(self) -> DiagnosticLog:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("w", encoding="utf-8", buffering=1)
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        if self._stream:
            self._stream.close()

    def heading(self, title: str) -> None:
        self._write("")
        self._write(f"## {title}")

    def record(self, level: str, label: str, detail: Any = "") -> None:
        normalized = level if level in self.counts else "INFO"
        self.counts[normalized] += 1
        self._write(f"[{normalized}] {redact(label)}")
        clean_detail = bounded_output(str(detail))
        if clean_detail:
            for line in clean_detail.splitlines():
                self._write(f"  {line}")

    def raw(self, value: str) -> None:
        for line in redact(value).splitlines():
            self._write(line)

    def _write(self, value: str) -> None:
        assert self._stream is not None
        self._stream.write(value + "\n")


class DiagnoseAll:
    def __init__(self, root: Path, log_path: Path, *, network: bool = True):
        self.root = root.resolve()
        self.log_path = log_path.resolve()
        self.network = network
        self.config = self._load_json(self.root / "data" / "config.json")
        self.runtime = self._load_json(self.root / ".signalroom.runtime.json")
        self.models = [
            item for item in self.config.get("models", []) if isinstance(item, dict)
        ]
        self.venv_python = (
            self.root / ".venv" / "Scripts" / "python.exe"
            if os.name == "nt"
            else self.root / ".venv" / "bin" / "python"
        )

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def run(self) -> int:
        with DiagnosticLog(self.log_path) as log:
            log.raw("SignalRoom --diagnose_all")
            log.raw(f"Generated: {datetime.now(UTC).isoformat()}")
            log.raw(f"Installation root: {self.root}")
            log.raw(
                "Privacy: environment variables, credential vaults, tokens, passwords, and "
                "configuration payloads are not collected. Common secret forms are redacted."
            )
            log.raw(
                "Mutation contract: this command does not install packages, download models, "
                "start services, or change SignalRoom configuration."
            )
            self._host(log)
            self._installation(log)
            self._python_environment(log)
            self._signalroom_runtime(log)
            self._ollama(log)
            self._transformers(log)
            self._existing_logs(log)
            log.heading("Summary")
            counts = " · ".join(
                f"{name.lower()}={value}" for name, value in log.counts.items()
            )
            log.raw(counts)
            if log.counts["FAIL"]:
                log.raw(
                    "Decision: BLOCKED. Attach this log to the SignalRoom issue or development "
                    "conversation."
                )
            elif log.counts["WARN"]:
                log.raw(
                    "Decision: READY WITH ATTENTION. Review warnings before installing or using "
                    "local models."
                )
            else:
                log.raw("Decision: READY. No installation or model-preparation blockers observed.")
            failures = log.counts["FAIL"]
            warnings = log.counts["WARN"]
        print(f"SignalRoom diagnostics written to: {self.log_path}")
        print(f"Result: {failures} failure(s), {warnings} warning(s)")
        return 1 if failures else 0

    def _host(self, log: DiagnosticLog) -> None:
        log.heading("Host and architecture")
        log.record(
            "PASS",
            "Operating system identified",
            json.dumps(
                {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "platform": platform.platform(),
                },
                sort_keys=True,
            ),
        )
        log.record(
            "PASS",
            "Diagnostic Python is supported",
            json.dumps(
                {
                    "executable": sys.executable,
                    "version": platform.python_version(),
                    "implementation": platform.python_implementation(),
                    "machine": platform.machine(),
                    "sysconfig_platform": sysconfig.get_platform(),
                    "openssl": ssl.OPENSSL_VERSION,
                },
                sort_keys=True,
            ),
        )
        if platform.system() == "Darwin":
            uname_machine = self._command_text(["uname", "-m"], timeout=5).strip()
            if uname_machine and uname_machine != platform.machine():
                log.record(
                    "WARN",
                    "macOS process architecture differs from the kernel architecture",
                    f"process={platform.machine()} · kernel={uname_machine}. "
                    "Rosetta or mixed-architecture Python can prevent compatible wheels from loading.",
                )
            else:
                log.record(
                    "PASS",
                    "macOS architecture is internally consistent",
                    f"architecture={uname_machine or platform.machine()}",
                )

    def _installation(self, log: DiagnosticLog) -> None:
        log.heading("Installation and filesystem")
        required = ("install.sh", "pyproject.toml", "src/splunk_security_agent")
        missing = [item for item in required if not (self.root / item).exists()]
        if missing:
            log.record("FAIL", "SignalRoom source tree is incomplete", ", ".join(missing))
        else:
            log.record("PASS", "SignalRoom source tree is present")

        try:
            usage = shutil.disk_usage(self.root)
            free_gib = usage.free / (1024**3)
            level = "PASS" if free_gib >= 10 else "WARN"
            log.record(
                level,
                "Model-storage capacity",
                f"free={free_gib:.1f} GiB · total={usage.total / (1024**3):.1f} GiB. "
                "At least 10 GiB free is recommended before model downloads.",
            )
        except OSError as exc:
            log.record("WARN", "Disk capacity could not be measured", exc)

        try:
            probe = self.root / ".signalroom-diagnose-write-probe"
            probe.write_text("write-probe", encoding="utf-8")
            probe.unlink()
            log.record("PASS", "Installation root is writable")
        except OSError as exc:
            log.record("FAIL", "Installation root is not writable", exc)

        manifest = self._load_json(self.root / ".install_manifest.json")
        if manifest:
            log.record(
                "PASS",
                "Installation manifest is readable",
                json.dumps(
                    {
                        "schema": manifest.get("manifest_schema"),
                        "version": manifest.get("version"),
                        "os": manifest.get("os"),
                        "python": (manifest.get("python") or {}).get("version"),
                        "pip": (manifest.get("pip") or {}).get("version"),
                    },
                    sort_keys=True,
                ),
            )
        else:
            log.record(
                "WARN",
                "Installation manifest is absent or unreadable",
                "Run ./install.sh before expecting the application or model environment to be ready.",
            )

    def _python_environment(self, log: DiagnosticLog) -> None:
        log.heading("SignalRoom virtual environment")
        if not self.venv_python.is_file():
            log.record(
                "FAIL",
                "SignalRoom virtual environment Python is missing",
                self.venv_python,
            )
            return
        self._run_command(
            log,
            "Virtual environment Python",
            [str(self.venv_python), "--version"],
            timeout=10,
        )
        self._run_command(
            log,
            "pip availability",
            [str(self.venv_python), "-m", "pip", "--version"],
            timeout=20,
        )
        self._run_command(
            log,
            "Installed package dependency consistency",
            [str(self.venv_python), "-m", "pip", "check"],
            timeout=90,
        )
        import_probe = """
import importlib, importlib.util, json, platform, sys, sysconfig
names = ("huggingface_hub", "sentence_transformers", "torch", "transformers")
result = {
    "python": sys.version.split()[0],
    "executable": sys.executable,
    "machine": platform.machine(),
    "sysconfig_platform": sysconfig.get_platform(),
    "modules": {},
}
for name in names:
    item = {"present": importlib.util.find_spec(name) is not None}
    if item["present"]:
        try:
            module = importlib.import_module(name)
            item["version"] = str(getattr(module, "__version__", "unknown"))
            item["import_ok"] = True
        except Exception as exc:
            item.update(import_ok=False, error=f"{type(exc).__name__}: {exc}")
    result["modules"][name] = item
try:
    import torch
    result["torch"] = {
        "mps_built": bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_built()),
        "mps_available": bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_available()),
        "cuda_available": bool(torch.cuda.is_available()),
    }
except Exception as exc:
    result["torch"] = {"error": f"{type(exc).__name__}: {exc}"}
print(json.dumps(result, sort_keys=True))
""".strip()
        completed = self._run_command(
            log,
            "Transformers runtime import probe",
            [str(self.venv_python), "-c", import_probe],
            timeout=120,
            failure_level="WARN",
        )
        if completed and completed.returncode == 0:
            try:
                probe = json.loads(completed.stdout)
                missing = [
                    name
                    for name, item in probe.get("modules", {}).items()
                    if not item.get("present") or not item.get("import_ok")
                ]
                if missing:
                    log.record(
                        "WARN",
                        "Local Transformers runtime is incomplete",
                        "Missing or unloadable: " + ", ".join(missing),
                    )
                else:
                    log.record("PASS", "All local Transformers modules import successfully")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                log.record("WARN", "Transformers import probe returned invalid JSON", exc)

        package_probe = (
            "import json; "
            "from splunk_security_agent.model_setup import LOCAL_RUNTIME_PACKAGES; "
            "print(json.dumps({'requirements': list(LOCAL_RUNTIME_PACKAGES)}))"
        )
        self._run_command(
            log,
            "Installed SignalRoom model-setup module",
            [str(self.venv_python), "-c", package_probe],
            timeout=60,
        )

    def _signalroom_runtime(self, log: DiagnosticLog) -> None:
        log.heading("Running SignalRoom service")
        if not self.runtime:
            log.record(
                "WARN",
                "Runtime identity file is absent",
                "The service may be stopped. Model diagnostics will continue directly.",
            )
            return
        runtime_summary = {
            "pid": self.runtime.get("pid"),
            "host": self.runtime.get("host"),
            "port": self.runtime.get("port"),
            "url": safe_url(str(self.runtime.get("url") or "")),
            "started_at": self.runtime.get("started_at"),
        }
        log.record("PASS", "Runtime identity file is readable", json.dumps(runtime_summary))
        if not self.network:
            log.record("INFO", "Runtime HTTP checks skipped by --offline")
            return
        base = str(self.runtime.get("url") or "").rstrip("/")
        if not base:
            log.record("WARN", "Runtime URL is missing")
            return
        try:
            health = self._http_json(f"{base}/api/health")
            log.record(
                "PASS",
                "SignalRoom health endpoint responded",
                json.dumps(
                    {
                        "ok": health.get("ok"),
                        "version": health.get("version"),
                        "configured": health.get("configured"),
                        "access_mode": health.get("access_mode"),
                        "discovery_worker": health.get("discovery_worker"),
                        "assurance_worker": health.get("assurance_worker"),
                    },
                    sort_keys=True,
                ),
            )
        except Exception as exc:
            log.record("WARN", "SignalRoom health endpoint did not respond", exc)
        try:
            readiness = self._http_json(f"{base}/api/model-setup/readiness")
            log.record(
                "PASS",
                "SignalRoom model-readiness endpoint responded",
                json.dumps(self._readiness_summary(readiness), sort_keys=True),
            )
        except HTTPError as exc:
            detail = (
                "Named access may require a browser session; direct model probes continue."
                if exc.code in {401, 403}
                else str(exc)
            )
            log.record("WARN", "Model-readiness API was unavailable", detail)
        except Exception as exc:
            log.record("WARN", "Model-readiness API was unavailable", exc)

    @staticmethod
    def _readiness_summary(value: dict[str, Any]) -> dict[str, Any]:
        ollama = value.get("ollama") or {}
        local = value.get("local_transformers") or {}
        huggingface = value.get("huggingface") or {}
        return {
            "host_os": value.get("host_os"),
            "ready": value.get("ready"),
            "ollama": {
                "ok": ollama.get("ok"),
                "endpoint": safe_url(str(ollama.get("endpoint") or "")),
                "version": ollama.get("version"),
                "models": ollama.get("models") or [],
                "loaded_models": ollama.get("loaded_models") or [],
                "error": ollama.get("error"),
            },
            "local_transformers": {
                "runtime_installed": local.get("runtime_installed"),
                "device": local.get("device"),
                "profiles": [
                    {
                        "id": item.get("id"),
                        "model": item.get("model"),
                        "task": item.get("task"),
                        "installed": item.get("installed"),
                        "revision": item.get("revision"),
                    }
                    for item in local.get("profiles") or []
                    if isinstance(item, dict)
                ],
            },
            "huggingface": {
                "selected": huggingface.get("selected"),
                "policy": huggingface.get("policy"),
                "token_configured": huggingface.get("token_configured"),
                "token_valid": huggingface.get("token_valid"),
            },
        }

    def _ollama(self, log: DiagnosticLog) -> None:
        log.heading("Ollama installation and service")
        cli = shutil.which("ollama")
        if cli:
            log.record("PASS", "Ollama CLI is on PATH", cli)
            self._run_command(log, "Ollama CLI version", [cli, "--version"], timeout=20)
        else:
            log.record(
                "WARN",
                "Ollama CLI is not on PATH",
                "The macOS app can still serve HTTP, but shell-based setup and model pulls will "
                "not work until its CLI is linked or placed on PATH.",
            )

        if platform.system() == "Darwin":
            app_locations = [
                Path("/Applications/Ollama.app"),
                Path.home() / "Applications" / "Ollama.app",
            ]
            installed_apps = [str(path) for path in app_locations if path.exists()]
            if installed_apps:
                log.record(
                    "PASS",
                    "Ollama macOS application is installed",
                    ", ".join(installed_apps),
                )
            else:
                log.record(
                    "FAIL",
                    "Ollama macOS application was not found",
                    "Expected /Applications/Ollama.app or ~/Applications/Ollama.app.",
                )
            pgrep = shutil.which("pgrep")
            if pgrep:
                self._run_command(
                    log,
                    "Ollama macOS process observation",
                    [pgrep, "-fl", "Ollama"],
                    timeout=10,
                    failure_level="WARN",
                )

        profiles_by_endpoint: dict[str, list[dict[str, Any]]] = {}
        for profile in self.models:
            if profile.get("provider") != "ollama":
                continue
            endpoint = ollama_base(str(profile.get("endpoint") or DEFAULT_OLLAMA_ENDPOINT))
            profiles_by_endpoint.setdefault(endpoint, []).append(profile)
        if not profiles_by_endpoint:
            profiles_by_endpoint[DEFAULT_OLLAMA_ENDPOINT] = []
            log.record(
                "WARN",
                "No Ollama profiles were found in data/config.json",
                f"Probing the default endpoint {DEFAULT_OLLAMA_ENDPOINT}.",
            )
        if not self.network:
            log.record(
                "INFO",
                "Ollama HTTP checks skipped by --offline",
                ", ".join(safe_url(endpoint) for endpoint in profiles_by_endpoint),
            )
            return

        for endpoint, profiles in profiles_by_endpoint.items():
            observed = safe_url(endpoint)
            try:
                version = self._http_json(f"{endpoint}/api/version")
                log.record(
                    "PASS",
                    f"Ollama service responded at {observed}",
                    f"version={version.get('version') or 'unknown'}",
                )
            except Exception as exc:
                log.record(
                    "FAIL",
                    f"Ollama service did not respond at {observed}",
                    f"{type(exc).__name__}: {exc}. Install and launch Ollama, then verify the "
                    "profile endpoint.",
                )
                continue
            try:
                tags = self._http_json(f"{endpoint}/api/tags")
                installed = [
                    str(item.get("name") or "")
                    for item in tags.get("models") or []
                    if isinstance(item, dict)
                ]
                log.record(
                    "PASS",
                    f"Ollama model catalog responded at {observed}",
                    json.dumps({"installed_models": installed}, sort_keys=True),
                )
                for profile in profiles:
                    requested = str(profile.get("model") or "")
                    if not requested:
                        continue
                    level = (
                        "PASS"
                        if any(model_matches(requested, actual) for actual in installed)
                        else "WARN"
                    )
                    detail = (
                        "Installed"
                        if level == "PASS"
                        else "Configured but not downloaded; use the explicit model pull workflow."
                    )
                    log.record(
                        level,
                        f"Ollama profile {profile.get('id') or requested}",
                        f"model={requested} · {detail}",
                    )
            except Exception as exc:
                log.record("FAIL", f"Ollama model catalog failed at {observed}", exc)
            try:
                running = self._http_json(f"{endpoint}/api/ps")
                loaded = [
                    str(item.get("name") or "")
                    for item in running.get("models") or []
                    if isinstance(item, dict)
                ]
                log.record(
                    "PASS",
                    f"Ollama resident-model endpoint responded at {observed}",
                    json.dumps({"loaded_models": loaded}, sort_keys=True),
                )
            except Exception as exc:
                log.record("WARN", f"Ollama resident-model check failed at {observed}", exc)

    def _transformers(self, log: DiagnosticLog) -> None:
        log.heading("Local Transformers and Hugging Face preparation")
        model_root = self.root / "data" / "models"
        if model_root.exists():
            writable = os.access(model_root, os.W_OK)
        else:
            writable = os.access(model_root.parent, os.W_OK)
        log.record(
            "PASS" if writable else "FAIL",
            "Local model storage is writable" if writable else "Local model storage is not writable",
            model_root,
        )

        local_profiles = [
            profile
            for profile in self.models
            if profile.get("provider") == "huggingface"
            and profile.get("task") in {"embedding", "ner", "reranking", "classification"}
            and profile.get("enabled", True)
        ]
        if not local_profiles:
            log.record("WARN", "No enabled local-specialist profiles are configured")
        for profile in local_profiles:
            profile_id = str(profile.get("id") or "")
            path = model_root / profile_id
            manifest = self._load_json(path / ".signalroom-model.json")
            config_present = (path / "config.json").is_file()
            weights = list(path.glob("*.safetensors")) if path.exists() else []
            installed = bool(manifest and config_present and weights)
            log.record(
                "PASS" if installed else "WARN",
                f"Local specialist artifact {profile_id or profile.get('model')}",
                json.dumps(
                    {
                        "model": profile.get("model"),
                        "task": profile.get("task"),
                        "installed": installed,
                        "config_present": config_present,
                        "safetensors_files": len(weights),
                        "revision": manifest.get("revision"),
                    },
                    sort_keys=True,
                ),
            )

        if not self.venv_python.is_file():
            log.record(
                "FAIL",
                "Transformers wheel compatibility cannot be checked without .venv",
            )
        elif not self.network:
            log.record("INFO", "PyPI wheel compatibility check skipped by --offline")
        else:
            self._run_command(
                log,
                "PyPI binary-wheel resolution for the local runtime",
                [
                    str(self.venv_python),
                    "-m",
                    "pip",
                    "install",
                    "--dry-run",
                    "--ignore-installed",
                    "--no-deps",
                    "--only-binary=:all:",
                    "--disable-pip-version-check",
                    "--no-cache-dir",
                    "--retries",
                    "1",
                    "--timeout",
                    "20",
                    *RUNTIME_REQUIREMENTS,
                ],
                timeout=240,
            )

        if not self.network:
            log.record("INFO", "Hugging Face metadata checks skipped by --offline")
            return
        try:
            addresses = socket.getaddrinfo("huggingface.co", 443, type=socket.SOCK_STREAM)
            log.record(
                "PASS",
                "Hugging Face DNS resolution",
                f"resolved_addresses={len(addresses)}",
            )
        except OSError as exc:
            log.record("FAIL", "Hugging Face DNS resolution failed", exc)
            return
        for profile in local_profiles:
            model = str(profile.get("model") or "")
            if not model:
                continue
            url = f"https://huggingface.co/api/models/{quote(model, safe='/')}"
            try:
                metadata = self._http_json(url)
                siblings = [
                    item
                    for item in metadata.get("siblings") or []
                    if isinstance(item, dict)
                ]
                weights = [
                    item.get("rfilename")
                    for item in siblings
                    if str(item.get("rfilename") or "").endswith(".safetensors")
                ]
                log.record(
                    "PASS",
                    f"Hugging Face model metadata {model}",
                    json.dumps(
                        {
                            "id": metadata.get("id") or model,
                            "sha": metadata.get("sha"),
                            "pipeline_tag": metadata.get("pipeline_tag"),
                            "private": metadata.get("private"),
                            "gated": metadata.get("gated"),
                            "files": len(siblings),
                            "safetensors_files": weights,
                        },
                        sort_keys=True,
                    ),
                )
                if not weights:
                    log.record(
                        "FAIL",
                        f"Hugging Face model has no observable safetensors weights: {model}",
                        "The current local installer ignores legacy .bin weights.",
                    )
            except HTTPError as exc:
                level = "WARN" if exc.code in {401, 403} else "FAIL"
                log.record(
                    level,
                    f"Hugging Face metadata request failed for {model}",
                    f"HTTP {exc.code}. Private or gated models may require the encrypted workspace "
                    "token; this diagnostic never reads or transmits it.",
                )
            except Exception as exc:
                log.record("FAIL", f"Hugging Face metadata request failed for {model}", exc)

    def _existing_logs(self, log: DiagnosticLog) -> None:
        log.heading("Existing SignalRoom log tails")
        for path in (self.root / "signalroom.err.log", self.root / "signalroom.log"):
            if not path.exists():
                log.record("INFO", f"{path.name} is not present")
                continue
            try:
                stat = path.stat()
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                tail = "\n".join(lines[-200:])
                log.record(
                    "INFO",
                    f"{path.name} · last {min(200, len(lines))} line(s)",
                    f"bytes={stat.st_size}\n{tail}",
                )
            except OSError as exc:
                log.record("WARN", f"{path.name} could not be read", exc)

    def _run_command(
        self,
        log: DiagnosticLog,
        label: str,
        arguments: list[str],
        *,
        timeout: int,
        failure_level: str = "FAIL",
    ) -> subprocess.CompletedProcess[str] | None:
        try:
            completed = subprocess.run(
                arguments,
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.record(failure_level, label, f"{type(exc).__name__}: {exc}")
            return None
        output = "\n".join(
            item for item in (completed.stdout.strip(), completed.stderr.strip()) if item
        )
        if completed.returncode == 0:
            log.record("PASS", label, output or "Command completed successfully.")
        else:
            log.record(
                failure_level,
                label,
                f"exit_code={completed.returncode}\n{output or 'No command output.'}",
            )
        return completed

    def _command_text(self, arguments: list[str], *, timeout: int) -> str:
        try:
            completed = subprocess.run(
                arguments,
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            return completed.stdout if completed.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""

    @staticmethod
    def _http_json(url: str, timeout: int = 12) -> dict[str, Any]:
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "SignalRoom-Diagnose-All/1",
            },
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                content = response.read(MAX_HTTP_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError):
            raise
        if len(content) > MAX_HTTP_BYTES:
            raise ValueError("Response exceeded the 2 MiB diagnostic safety limit")
        value = json.loads(content.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object")
        return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run non-mutating SignalRoom installation, Ollama, Transformers, and model-source "
            "diagnostics."
        )
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--log", type=Path)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip HTTP, DNS, Hugging Face, PyPI, and Ollama service probes.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    log_path = (
        args.log.resolve()
        if args.log
        else root / "signalroom-diagnose-all.log"
    )
    return DiagnoseAll(root, log_path, network=not args.offline).run()


if __name__ == "__main__":
    raise SystemExit(main())
