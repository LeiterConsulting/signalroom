from __future__ import annotations

import os
import platform
import ssl
from pathlib import Path
from threading import Lock
from typing import Any

_STATE_LOCK = Lock()
_STATE: dict[str, Any] | None = None


def connection_ssl_context(
    *,
    verify: bool = True,
    ca_bundle: str | os.PathLike[str] | None = None,
) -> ssl.SSLContext:
    """Build an explicit TLS context for a user-configured private connection.

    Public package and model downloads use the operating-system trust store. Splunk MCP and
    other user-configured endpoints must instead honor their saved per-connection policy even
    after native trust has been activated for the process.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if ca_bundle:
        context.load_verify_locations(cafile=str(Path(ca_bundle).expanduser()))
    return context


def system_ssl_context() -> ssl.SSLContext:
    """Return a verified native-trust context for a public application-owned request."""
    try:
        import truststore

        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        return context
    except (ImportError, OSError, RuntimeError):
        return ssl.create_default_context()


def configure_huggingface_system_tls() -> str:
    """Scope native certificate trust to Hugging Face without patching private endpoints."""
    try:
        import httpx
        import huggingface_hub

        if hasattr(huggingface_hub, "set_client_factory"):
            huggingface_hub.set_client_factory(
                lambda: httpx.Client(
                    verify=system_ssl_context(),
                    follow_redirects=True,
                )
            )
            if hasattr(huggingface_hub, "set_async_client_factory"):
                huggingface_hub.set_async_client_factory(
                    lambda: httpx.AsyncClient(
                        verify=system_ssl_context(),
                        follow_redirects=True,
                    )
                )
            return "httpx-native-system"

        if hasattr(huggingface_hub, "configure_http_backend"):
            import requests
            from requests.adapters import HTTPAdapter

            class NativeTrustAdapter(HTTPAdapter):
                def init_poolmanager(
                    self,
                    connections: int,
                    maxsize: int,
                    block: bool = False,
                    **pool_kwargs: Any,
                ) -> None:
                    pool_kwargs["ssl_context"] = system_ssl_context()
                    super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

            def backend_factory() -> requests.Session:
                session = requests.Session()
                session.mount("https://", NativeTrustAdapter())
                return session

            huggingface_hub.configure_http_backend(backend_factory=backend_factory)
            return "requests-native-system"
    except ImportError:
        return "unavailable"

    return "python-default"


def activate_system_tls_trust() -> dict[str, Any]:
    """Prepare operating-system trust for scoped application-owned HTTPS clients.

    Native trust is never injected into Python globally because Splunk MCP, webhooks, and other
    private connections expose independent verify/private-CA policies. Public clients request a
    native context explicitly, preserving those policies while still honoring macOS Keychain,
    Windows CryptoAPI, or the Linux OpenSSL trust configuration.
    """
    global _STATE
    with _STATE_LOCK:
        if _STATE is not None:
            return dict(_STATE)
        environment_bundle = os.getenv("SSL_CERT_FILE", "").strip()
        try:
            import truststore

            context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
            del context
            _STATE = {
                "active": True,
                "mode": "native-system",
                "provider": "truststore",
                "scope": "public-clients",
                "system": platform.system(),
                "certificate_verification": True,
                "environment_bundle": bool(environment_bundle),
                "environment_bundle_exists": bool(
                    environment_bundle and Path(environment_bundle).expanduser().is_file()
                ),
            }
        except (ImportError, OSError, RuntimeError) as exc:
            _STATE = {
                "active": False,
                "mode": "python-default",
                "provider": "ssl",
                "scope": "public-clients",
                "system": platform.system(),
                "certificate_verification": True,
                "environment_bundle": bool(environment_bundle),
                "environment_bundle_exists": bool(
                    environment_bundle and Path(environment_bundle).expanduser().is_file()
                ),
                "reason": f"{type(exc).__name__}: {exc}",
            }
        return dict(_STATE)


def system_tls_trust_state() -> dict[str, Any]:
    """Return the active outbound HTTPS trust mode without exposing CA contents."""
    return activate_system_tls_trust()
