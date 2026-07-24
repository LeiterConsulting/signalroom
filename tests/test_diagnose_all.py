import json
from pathlib import Path

from splunk_security_agent.diagnose_all import (
    RUNTIME_REQUIREMENTS,
    DiagnoseAll,
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
    assert "Decision: BLOCKED" in output


def test_installer_exposes_diagnose_all_command_and_log() -> None:
    shell = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")

    assert "--diagnose_all" in shell
    assert "--diagnose-all" in shell
    assert "signalroom-diagnose-all.log" in shell
    assert "src/splunk_security_agent/diagnose_all.py" in shell
