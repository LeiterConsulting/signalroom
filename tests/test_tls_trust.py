from __future__ import annotations

import ssl
import sys
import types

import splunk_security_agent.tls_trust as tls_trust


def test_native_tls_trust_activation_is_cached_and_keeps_verification_enabled(monkeypatch):
    calls: list[str] = []
    fake = types.ModuleType("truststore")

    class FakeContext:
        def __init__(self, _protocol):
            calls.append("context")

        def load_default_certs(self, _purpose):
            calls.append("defaults")

    fake.SSLContext = FakeContext
    fake.inject_into_ssl = lambda: calls.append("inject")
    monkeypatch.setitem(sys.modules, "truststore", fake)
    monkeypatch.setattr(tls_trust, "_STATE", None)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)

    first = tls_trust.activate_system_tls_trust()
    second = tls_trust.system_tls_trust_state()

    assert calls == ["context", "defaults"]
    assert first == second
    assert first["active"] is True
    assert first["mode"] == "native-system"
    assert first["scope"] == "public-clients"
    assert first["certificate_verification"] is True
    assert first["environment_bundle"] is False


def test_native_tls_trust_reports_explicit_bundle_presence(monkeypatch, tmp_path):
    bundle = tmp_path / "organization-ca.pem"
    bundle.write_text("synthetic certificate placeholder", encoding="utf-8")
    fake = types.ModuleType("truststore")

    class FakeContext:
        def __init__(self, _protocol):
            pass

        def load_default_certs(self, _purpose):
            pass

    fake.SSLContext = FakeContext
    monkeypatch.setitem(sys.modules, "truststore", fake)
    monkeypatch.setattr(tls_trust, "_STATE", None)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))

    state = tls_trust.activate_system_tls_trust()

    assert state["environment_bundle"] is True
    assert state["environment_bundle_exists"] is True
    assert str(bundle) not in str(state)


def test_private_connection_context_can_explicitly_disable_verification():
    context = tls_trust.connection_ssl_context(verify=False)

    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_verified_private_connection_context_keeps_hostname_validation():
    context = tls_trust.connection_ssl_context(verify=True)

    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_huggingface_native_trust_is_configured_without_global_ssl_injection(monkeypatch):
    factories = {}
    fake = types.ModuleType("huggingface_hub")
    fake.set_client_factory = lambda value: factories.update(sync=value)
    fake.set_async_client_factory = lambda value: factories.update(async_client=value)
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake)
    original_context = ssl.SSLContext

    mode = tls_trust.configure_huggingface_system_tls()

    assert mode == "httpx-native-system"
    assert set(factories) == {"sync", "async_client"}
    assert ssl.SSLContext is original_context
