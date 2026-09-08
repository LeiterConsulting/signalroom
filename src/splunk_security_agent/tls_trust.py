from __future__ import annotations

import os
import platform
from pathlib import Path
from threading import Lock
from typing import Any

_STATE_LOCK = Lock()
_STATE: dict[str, Any] | None = None


def activate_system_tls_trust() -> dict[str, Any]:
    """Use the operating-system trust store for application-owned HTTPS clients.

    SignalRoom is an application rather than an imported networking library, so activating
    truststore once at process startup is intentional. Certificate verification remains enabled;
    the change lets Python honor roots administered through macOS Keychain, Windows CryptoAPI,
    or the Linux OpenSSL trust configuration.
    """
    global _STATE
    with _STATE_LOCK:
        if _STATE is not None:
            return dict(_STATE)
        environment_bundle = os.getenv("SSL_CERT_FILE", "").strip()
        try:
            import truststore

            truststore.inject_into_ssl()
            _STATE = {
                "active": True,
                "mode": "native-system",
                "provider": "truststore",
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
