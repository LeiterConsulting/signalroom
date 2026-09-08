from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

PUBLIC_RETRY_FAST_FAILURE_SECONDS = 45


def should_retry_public_source(value: Any, *, elapsed_seconds: float = 0) -> bool:
    """Admit one public-only retry for fast mirror, resolution, or credential failures."""
    if elapsed_seconds > PUBLIC_RETRY_FAST_FAILURE_SECONDS:
        return False
    lowered = str(value or "").lower()
    return any(
        phrase in lowered
        for phrase in (
            "no matching distribution found",
            "could not find a version that satisfies",
            "from versions: none",
            "no available distribution",
            "404 client error",
            "401 client error",
            "403 client error",
            "repository not found",
            "unauthorized",
            "forbidden",
            "name resolution",
            "connection refused",
            "timed out",
            "timeout",
        )
    )


def credential_free_pip_environment(
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an environment that cannot pass configured pip index settings or credentials."""
    source = os.environ if environ is None else environ
    public = {key: value for key, value in source.items() if not key.upper().startswith("PIP_")}
    public["PIP_CONFIG_FILE"] = os.devnull
    return public
