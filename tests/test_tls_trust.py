from __future__ import annotations

import sys
import types

import splunk_security_agent.tls_trust as tls_trust


def test_native_tls_trust_activation_is_cached_and_keeps_verification_enabled(monkeypatch):
    calls: list[str] = []
    fake = types.ModuleType("truststore")
    fake.inject_into_ssl = lambda: calls.append("inject")
    monkeypatch.setitem(sys.modules, "truststore", fake)
    monkeypatch.setattr(tls_trust, "_STATE", None)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)

    first = tls_trust.activate_system_tls_trust()
    second = tls_trust.system_tls_trust_state()

    assert calls == ["inject"]
    assert first == second
    assert first["active"] is True
    assert first["mode"] == "native-system"
    assert first["certificate_verification"] is True
    assert first["environment_bundle"] is False


def test_native_tls_trust_reports_explicit_bundle_presence(monkeypatch, tmp_path):
    bundle = tmp_path / "organization-ca.pem"
    bundle.write_text("synthetic certificate placeholder", encoding="utf-8")
    fake = types.ModuleType("truststore")
    fake.inject_into_ssl = lambda: None
    monkeypatch.setitem(sys.modules, "truststore", fake)
    monkeypatch.setattr(tls_trust, "_STATE", None)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))

    state = tls_trust.activate_system_tls_trust()

    assert state["environment_bundle"] is True
    assert state["environment_bundle_exists"] is True
    assert str(bundle) not in str(state)
