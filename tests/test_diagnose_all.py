import json
import os
import subprocess
from pathlib import Path

import splunk_security_agent.diagnose_all as diagnose_module
from splunk_security_agent.diagnose_all import (
    RUNTIME_REQUIREMENTS,
    DiagnoseAll,
    DiagnosticLog,
    model_matches,
    redact,
    safe_url,
)
from splunk_security_agent.model_setup import LOCAL_RUNTIME_PACKAGES

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_diagnostic_requirements_match_runtime_installer() -> None:
    assert RUNTIME_REQUIREMENTS == LOCAL_RUNTIME_PACKAGES


def test_diagnostic_redacts_credentials_and_url_userinfo() -> None:
    value = (
        "Authorization: Bearer abc.def.ghi token=token-value password: password-value "
        "https://user:pass@example.test/path"
    )
    cleaned = redact(value)

    assert "abc.def.ghi" not in cleaned
    assert "token-value" not in cleaned
    assert "password-value" not in cleaned
    assert "user:pass" not in cleaned
    assert cleaned.count("[REDACTED]") >= 4


def test_safe_url_removes_credentials_query_and_fragment() -> None:
    assert (
        safe_url("https://operator:secret@example.test:8443/api?token=secret#fragment")
        == "https://example.test:8443/api"
    )
    assert "[REDACTED]" in safe_url("https://example.test:invalid/path?token=secret")


def test_model_matching_accepts_ollama_latest_alias_only() -> None:
    assert model_matches("llama3.1", "llama3.1:latest")
    assert model_matches("llama3.1:8b", "llama3.1:8b")
    assert not model_matches("llama3.1:8b", "llama3.1:latest")


def test_offline_diagnostic_writes_secret_free_failure_log(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    (tmp_path / "src" / "splunk_security_agent").mkdir(parents=True)
    data = tmp_path / "data"
    data.mkdir()
    (data / "config.json").write_text(
        json.dumps(
            {
                "huggingface_token": "must-never-appear",
                "models": [
                    {
                        "id": "securebert-test",
                        "provider": "huggingface",
                        "model": "publisher/model",
                        "task": "embedding",
                        "enabled": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    log_path = tmp_path / "diagnose.log"

    result = DiagnoseAll(tmp_path, log_path, network=False).run()
    output = log_path.read_text(encoding="utf-8")

    assert result == 1
    assert "[FAIL] SignalRoom virtual environment Python is missing" in output
    assert "must-never-appear" not in output
    assert "Hugging Face metadata checks skipped by --offline" in output
    assert "Outbound HTTPS certificate trust" in output
    assert '"certificate_verification": true' in output
    assert "Decision: BLOCKED" in output


def test_installer_exposes_diagnose_all_command_and_log() -> None:
    shell = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")

    assert "--diagnose_all" in shell
    assert "--diagnose-all" in shell
    assert "signalroom-diagnose-all.log" in shell
    assert "src/splunk_security_agent/diagnose_all.py" in shell
    assert "run_public_pip" in shell
    assert "PIP_CONFIG_FILE=/dev/null" in shell
    assert "-m pip --isolated" in shell


def test_installer_offers_native_python_repair_for_apple_silicon() -> None:
    shell = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")

    assert "hw.optional.arm64" in shell
    assert "--install-native-python" in shell
    assert "--allow-rosetta-python" in shell
    assert "Type \"yes\" to continue" in shell
    assert "/usr/bin/arch -arm64 /bin/bash" in shell
    assert "/opt/homebrew/bin/brew install python@3.13" in shell
    assert "different CPU architecture; rebuilding it" in shell
    assert 'INSTALL_NATIVE_PYTHON" == "yes" && "$venv_machine" != "arm64' in shell


def test_diagnostic_identifies_rosetta_python_on_apple_silicon(
    tmp_path: Path,
    monkeypatch,
) -> None:
    diagnostic = DiagnoseAll(tmp_path, tmp_path / "diagnose.log", network=False)

    def command_text(arguments: list[str], *, timeout: int) -> str:
        del timeout
        if arguments[-1] == "hw.optional.arm64":
            return "1\n"
        if arguments[-1] == "sysctl.proc_translated":
            return "1\n"
        if arguments[-2:] == ["uname", "-m"]:
            return "x86_64\n"
        return ""

    monkeypatch.setattr("splunk_security_agent.diagnose_all.platform.system", lambda: "Darwin")
    monkeypatch.setattr("splunk_security_agent.diagnose_all.platform.machine", lambda: "x86_64")
    monkeypatch.setattr(diagnostic, "_command_text", command_text)

    with DiagnosticLog(diagnostic.log_path) as log:
        diagnostic._host(log)

    output = diagnostic.log_path.read_text(encoding="utf-8")
    assert "[WARN] Apple Silicon is using Intel Python under Rosetta" in output
    assert "hardware=arm64" in output
    assert "process=x86_64" in output
    assert "Local Transformers and SecureBERT require native arm64 Python" in output


def test_wheel_diagnostic_retries_restricted_index_with_isolated_public_pypi(
    tmp_path: Path,
    monkeypatch,
) -> None:
    diagnostic = DiagnoseAll(tmp_path, tmp_path / "diagnose.log", network=True)
    calls: list[dict[str, object]] = []

    def run_command(
        log: DiagnosticLog,
        label: str,
        arguments: list[str],
        *,
        timeout: int,
        failure_level: str = "FAIL",
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(
            {
                "label": label,
                "arguments": arguments,
                "timeout": timeout,
                "failure_level": failure_level,
                "env": env,
            }
        )
        if len(calls) == 1:
            output = "ERROR: No matching distribution found for huggingface-hub"
            log.record(failure_level, label, output)
            return subprocess.CompletedProcess(arguments, 1, "", output)
        log.record("PASS", label, "Would install public binary wheels")
        return subprocess.CompletedProcess(arguments, 0, "Would install public binary wheels", "")

    monkeypatch.setattr(diagnostic, "_run_command", run_command)
    monkeypatch.setenv("PIP_INDEX_URL", "https://user:secret@private.example/simple")
    monkeypatch.setenv("PIP_TRUSTED_HOST", "private.example")

    with DiagnosticLog(diagnostic.log_path) as log:
        diagnostic._runtime_wheel_compatibility(log)

    assert len(calls) == 2
    assert calls[0]["failure_level"] == "WARN"
    public_arguments = calls[1]["arguments"]
    assert isinstance(public_arguments, list)
    assert "--isolated" in public_arguments
    assert public_arguments[public_arguments.index("--index-url") + 1] == (
        "https://pypi.org/simple"
    )
    public_environment = calls[1]["env"]
    assert isinstance(public_environment, dict)
    assert public_environment["PIP_CONFIG_FILE"] == os.devnull
    assert "PIP_INDEX_URL" not in public_environment
    assert "PIP_TRUSTED_HOST" not in public_environment
    output = diagnostic.log_path.read_text(encoding="utf-8")
    assert "[WARN] Configured-index PyPI binary-wheel resolution" in output
    assert "[PASS] Credential-free public PyPI binary-wheel resolution fallback" in output


def test_artifact_probe_follows_delivery_path_without_retaining_content(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        status = 206
        headers = {"Content-Range": "bytes 0-0/1000"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, amount: int) -> bytes:
            captured["read"] = amount
            return b"x"

        def geturl(self) -> str:
            return "https://cdn.example.test/model.safetensors?signature=must-not-log"

    def fake_urlopen(request, *, timeout: int):
        captured["range"] = request.get_header("Range")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(diagnose_module, "urlopen", fake_urlopen)

    result = DiagnoseAll._http_artifact_probe(
        "https://huggingface.co/publisher/model/resolve/revision/model.safetensors"
    )

    assert captured == {"range": "bytes=0-0", "timeout": 20, "read": 1}
    assert result["status"] == 206
    assert result["bytes_read"] == 1
    assert result["redirect_target"] == "https://cdn.example.test/model.safetensors"
    assert "signature" not in str(result)
