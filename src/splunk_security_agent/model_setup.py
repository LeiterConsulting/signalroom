from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .config import ConfigStore
from .providers.local_transformers import (
    LocalTransformersProvider,
    local_model_installed,
    local_runtime_available,
)
from .rag import EvidenceStore
from .schemas import ModelProfile
from .source_recovery import credential_free_pip_environment
from .source_recovery import should_retry_public_source as _should_retry_public_source
from .tls_trust import system_tls_trust_state

OLLAMA_DOWNLOAD_URL = "https://ollama.com/download"
HF_TOKEN_URL = "https://huggingface.co/settings/tokens"
LOCAL_RUNTIME_PACKAGES = (
    "huggingface-hub>=0.27,<2",
    "sentence-transformers>=3.4,<7",
    "torch>=2.5",
    "transformers>=4.48,<6",
)

MODEL_CATALOG_REVIEW: dict[str, Any] = {
    "reviewed_at": "2026-09-05",
    "status": "current-with-research-candidate",
    "summary": (
        "The shipped Foundation-Sec, SecureBERT 2.0, and Cisco Time Series Model choices "
        "remain current. Antares 1B is the only newly published Cisco-family model with a "
        "strong SignalRoom mission fit, but it requires a separate read-only repository workflow."
    ),
    "findings": [
        {
            "label": "Foundation-Sec chat specialists",
            "status": "current",
            "detail": (
                "Reasoning remains the security-analysis default; 1.1 Instruct remains the "
                "optional extraction and instruction-following profile."
            ),
            "source_url": "https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning",
        },
        {
            "label": "SecureBERT 2.0 specialists",
            "status": "current",
            "detail": (
                "The bi-encoder, cross-encoder, NER, and bounded code classifier remain the "
                "publisher's task-specific cybersecurity suite."
            ),
            "source_url": "https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder",
        },
        {
            "label": "Cisco Time Series Model",
            "status": "current",
            "detail": (
                "Version 1.0 remains the latest release and supersedes the deprecated 1.0-preview "
                "checkpoint. SignalRoom already uses 1.0 through its isolated local service."
            ),
            "source_url": "https://huggingface.co/cisco-ai/cisco-time-series-model-1.0",
        },
        {
            "label": "Antares 1B",
            "status": "evaluate",
            "detail": (
                "New gated vulnerability-localization model. It is cataloged for a future "
                "immutable, read-only repository-analysis workflow and is not routed today."
            ),
            "source_url": "https://huggingface.co/fdtn-ai/antares-1b",
        },
    ],
}

PUBLISHER_CATALOGS: tuple[str, ...] = ("cisco-ai", "fdtn-ai")


def _reviewed_model(
    revision: str,
    pipeline_tag: str,
    decision: str,
    purpose: str,
    *,
    gated: bool | str = False,
    license_id: str = "not-declared",
) -> dict[str, Any]:
    """Build one immutable publisher-intake decision."""
    return {
        "reviewed_revision": revision,
        "reviewed_at": MODEL_CATALOG_REVIEW["reviewed_at"],
        "pipeline_tag": pipeline_tag,
        "gated": gated,
        "license": license_id,
        "decision": decision,
        "purpose": purpose,
    }


# Repository names alone are not an adequate supply-chain review boundary. A new commit can
# change weights, code, a model card, access terms, or a declared task without changing the ID.
REVIEWED_PUBLISHER_MODELS: dict[str, dict[str, Any]] = {
    "cisco-ai/pase": _reviewed_model(
        "31b1cf14f41d4d7a1a469eaa45ce235825d900f0",
        "audio-to-audio",
        "out-of-scope",
        "Speech enhancement is not part of SignalRoom's Splunk security mission.",
    ),
    "cisco-ai/stupase": _reviewed_model(
        "539963f425ae201ac8c379b6480e3b182a4840ad",
        "audio-to-audio",
        "out-of-scope",
        "Speech enhancement is not part of SignalRoom's Splunk security mission.",
    ),
    "cisco-ai/SecureBERT2.0-biencoder": _reviewed_model(
        "b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0",
        "sentence-similarity",
        "admitted",
        "Local cybersecurity evidence embeddings and RAG retrieval.",
    ),
    "cisco-ai/mini-bart-g2p": _reviewed_model(
        "0fbbf8c590f9db920939a2bc4befbaac26eebc4c",
        "text-generation",
        "out-of-scope",
        "Grapheme-to-phoneme generation does not improve the analyst workflow.",
    ),
    "cisco-ai/cisco-time-series-model-1.0": _reviewed_model(
        "038831104abace772bd50bffe76da0c77c364c51",
        "time-series-forecasting",
        "admitted-preview",
        "Bounded local forecasting of explicitly selected Splunk time series.",
    ),
    "cisco-ai/cisco-time-series-model-1.0-preview": _reviewed_model(
        "bf56b7946c42912ddb05dbf14aabc59f0974d31b",
        "time-series-forecasting",
        "superseded",
        "Retained in the inventory only to detect drift from the superseded preview.",
    ),
    "cisco-ai/SecureBERT2.0-base": _reviewed_model(
        "7f7c16d1b2316c5046759667ed97f527aa1b7709",
        "fill-mask",
        "supporting-model",
        "Publisher base model; SignalRoom uses bounded task-specific descendants instead.",
    ),
    "cisco-ai/SecureBERT2.0-NER": _reviewed_model(
        "792db5b533118afee8c3fab86db119d09ab77ff6",
        "token-classification",
        "admitted",
        "Evidence-bounded cybersecurity entity candidates.",
    ),
    "cisco-ai/SecureBERT2.0-cross_encoder": _reviewed_model(
        "960b9235bd165911babab7d312fc7f252cdc9d6d",
        "sentence-similarity",
        "admitted",
        "Local reranking of retrieved evidence.",
    ),
    "cisco-ai/SecureBERT2.0-code-vuln-detection": _reviewed_model(
        "f260674279f97f85d75be257defa62484aa0239c",
        "text-classification",
        "admitted-preview",
        "Opt-in source-code review prioritization with explicit input boundaries.",
    ),
    "fdtn-ai/antares-350m": _reviewed_model(
        "cdf6d054fa5f491553ccb1704269cbd1954c6c6e",
        "text-generation",
        "research-candidate",
        "Gated vulnerability localization candidate; no automatic routing.",
        gated="auto",
    ),
    "fdtn-ai/antares-1b": _reviewed_model(
        "10417eb35641b32e7141157db19c76eb545193b6",
        "text-generation",
        "research-candidate",
        "Preferred Antares candidate for a future immutable repository workflow.",
        gated="auto",
    ),
    "fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF": _reviewed_model(
        "4a04f7b19513ff9f672169b8fe4288000ab87b07",
        "text-generation",
        "admitted",
        "Default local security-reasoning artifact.",
    ),
    "fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF": _reviewed_model(
        "010378322d06cccff4cb64ad62997411f2bd511f",
        "text-generation",
        "compatible-alternative",
        "Higher-memory quantization of the admitted security-reasoning model.",
    ),
    "fdtn-ai/Foundation-Sec-8B-Reasoning": _reviewed_model(
        "63c930c82d7646226d33502bec5870019738400e",
        "text-generation",
        "upstream-source",
        "Upstream weights for the admitted reasoning GGUF artifacts.",
    ),
    "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF": _reviewed_model(
        "0b58da4736f799f3cb5bbaffb8a39025f1c4e5df",
        "text-generation",
        "admitted",
        "Optional local security extraction and concise instruction following.",
    ),
    "fdtn-ai/Foundation-Sec-1.1-8B-Instruct": _reviewed_model(
        "243b27655e01c87cc04fdb88632be7cd9e55ac1f",
        "text-generation",
        "upstream-source",
        "Upstream weights for the admitted 1.1 Instruct GGUF artifact.",
    ),
    "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF": _reviewed_model(
        "02a3d8902fa521a170e98158642c6029f78c2392",
        "text-generation",
        "compatible-alternative",
        "Higher-memory quantization of the admitted 1.1 Instruct model.",
    ),
    "fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF": _reviewed_model(
        "16deb1934d4b1d28769f7020c15ae018aa537d1f",
        "text-generation",
        "superseded-family",
        "Reviewed predecessor retained for publisher-inventory drift detection.",
    ),
    "fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF": _reviewed_model(
        "0f21603d7793fdc62134345f018296d870714688",
        "text-generation",
        "superseded-family",
        "Reviewed predecessor retained for publisher-inventory drift detection.",
    ),
    "fdtn-ai/Foundation-Sec-8B-Q8_0-GGUF": _reviewed_model(
        "5036b13833f928dd3a4e23e66abd0150b2c23fe6",
        "text-generation",
        "superseded-family",
        "Reviewed predecessor retained for publisher-inventory drift detection.",
    ),
    "fdtn-ai/Foundation-Sec-8B-Instruct": _reviewed_model(
        "aa13cb996e7fc700e7efd6b7367992f14cf349c0",
        "text-generation",
        "superseded-family",
        "Reviewed predecessor retained for publisher-inventory drift detection.",
    ),
    "fdtn-ai/Foundation-Sec-8B": _reviewed_model(
        "9e6bb1f70b402e55bbf68cfd7abf88458daf09b3",
        "text-generation",
        "superseded-family",
        "Reviewed predecessor retained for publisher-inventory drift detection.",
    ),
}

EVALUATED_MODEL_CANDIDATES: tuple[dict[str, Any], ...] = (
    {
        "id": "securebert-code-vulnerability",
        "label": "SecureBERT 2.0 code vulnerability detection",
        "model": "cisco-ai/SecureBERT2.0-code-vuln-detection",
        "owner": "Cisco AI",
        "status": "admitted-preview",
        "runtime": "local-transformers",
        "profile_id": "securebert-code-vulnerability",
        "purpose": (
            "Assistive binary vulnerability screening for explicitly pasted C, C++, or Python "
            "source-code snippets."
        ),
        "constraint": (
            "Not suitable for SPL, Splunk inventory, event text, dynamic analysis, or autonomous "
            "remediation. A positive result is a review priority, never a vulnerability finding."
        ),
        "input_contract": "Explicit source code only · 1,024-token evaluated window · no automatic routing",
        "output_contract": (
            "Class 1 is treated as the positive review signal used by the publisher's binary "
            "evaluation. SignalRoom exposes confidence, truncation, input hash, and limitations."
        ),
        "automatic_use": False,
        "admission_gates": [
            {
                "name": "First-party source and safetensors",
                "status": "pass",
                "detail": "Cisco AI · Apache-2.0 · local snapshot with immutable revision",
            },
            {
                "name": "Bounded local runtime",
                "status": "pass",
                "detail": "Local Transformers only; hosted inference is not used by the screening workflow",
            },
            {
                "name": "Analyst-visible output contract",
                "status": "pass",
                "detail": "Assistive review signal with confidence, truncation, source hash, and caveats",
            },
            {
                "name": "Automatic Discovery / RAG routing",
                "status": "blocked",
                "detail": "Intentionally prohibited; model is out of scope for Splunk objects and event text",
            },
        ],
        "source_url": "https://huggingface.co/cisco-ai/SecureBERT2.0-code-vuln-detection",
    },
    {
        "id": "cisco-time-series-1",
        "label": "Cisco Time Series Model 1.0",
        "model": "cisco-ai/cisco-time-series-model-1.0",
        "owner": "Cisco AI",
        "status": "admitted-preview",
        "runtime": "dedicated-time-series",
        "profile_id": "",
        "purpose": (
            "Zero-shot forecasting for security event-rate, alert-volume, ingestion, and "
            "observability time series."
        ),
        "constraint": (
            "Runs only through a dedicated local/private cisco-tsm service. Public inference is "
            "blocked, source rows are not persisted, and no forecast can automatically change an "
            "alert, threshold, or capacity decision."
        ),
        "input_contract": (
            "Regular univariate numeric series · coarse/fine history · explicit interval and horizon"
        ),
        "output_contract": (
            "Mean and quantile forecast with source SPL, time bounds, imputation ratio, and backtest error"
        ),
        "automatic_use": False,
        "admission_gates": [
            {
                "name": "First-party source and model contract",
                "status": "pass",
                "detail": "Cisco AI / Splunk · Apache-2.0 · dedicated cisco-tsm package",
            },
            {
                "name": "Local forecast runtime adapter",
                "status": "pass",
                "detail": (
                    "Isolated Python 3.11 sidecar · local/private endpoints only · immutable "
                    "checkpoint revision reported when using the bundled runtime"
                ),
            },
            {
                "name": "Splunk numeric-series preparation",
                "status": "pass",
                "detail": (
                    "Exact read-only timechart · regular-interval validation · last-value "
                    "imputation ratio · query and series fingerprints"
                ),
            },
            {
                "name": "Backtest and promotion gate",
                "status": "pass",
                "detail": (
                    "Withheld holdout compared with a naive last-value baseline; eligible output "
                    "still requires analyst review and cannot auto-promote"
                ),
            },
            {
                "name": "Durable experiment and alert-draft boundary",
                "status": "pass",
                "detail": (
                    "Immutable run fingerprints · reviewed general/weekday baselines · "
                    "hard-budget shadow schedules · analyst-only drift dispositions"
                ),
            },
        ],
        "source_url": "https://huggingface.co/cisco-ai/cisco-time-series-model-1.0",
    },
    {
        "id": "antares-vulnerability-localization",
        "label": "Antares 1B repository vulnerability localization",
        "model": "fdtn-ai/antares-1b",
        "owner": "Foundation AI at Cisco",
        "status": "research-candidate",
        "runtime": "dedicated-repository-agent",
        "profile_id": "",
        "purpose": (
            "Localize files that deserve vulnerability review inside an immutable source-code "
            "snapshot using a small, cybersecurity-specialized read-only terminal agent."
        ),
        "constraint": (
            "The publisher repository is gated and no SignalRoom runtime adapter exists yet. "
            "Candidate paths are triage evidence, not vulnerability findings. Automatic chat, "
            "Splunk, write, network, and remediation access are prohibited."
        ),
        "input_contract": (
            "Immutable read-only repository snapshot · explicit vulnerability description or CWE · "
            "bounded grep/find/cat-style tools only"
        ),
        "output_contract": (
            "Evidence-linked candidate file paths, observed commands, confidence, limitations, and "
            "a reviewable SARIF-compatible result"
        ),
        "automatic_use": False,
        "admission_gates": [
            {
                "name": "First-party source and license",
                "status": "pass",
                "detail": "Foundation AI at Cisco · Apache-2.0 model card · 1B parameter checkpoint",
            },
            {
                "name": "SignalRoom mission fit",
                "status": "pass",
                "detail": (
                    "Repository-scale vulnerability localization can enrich detection engineering "
                    "and incident follow-up without treating the model as a generic chat agent"
                ),
            },
            {
                "name": "Access and immutable artifact provenance",
                "status": "blocked",
                "detail": (
                    "Publisher access is gated; explicit license acceptance, token handling, revision "
                    "pinning, and local artifact approval must be implemented"
                ),
            },
            {
                "name": "Read-only repository sandbox",
                "status": "blocked",
                "detail": (
                    "Needs a dedicated adapter with an immutable snapshot, bounded file tools, no "
                    "shell or network escape, timeouts, and a complete action transcript"
                ),
            },
            {
                "name": "SignalRoom benchmark and analyst output",
                "status": "blocked",
                "detail": (
                    "Requires representative repository cases, false-positive measurement, evidence "
                    "links, SARIF export, and explicit analyst disposition before admission"
                ),
            },
        ],
        "source_url": "https://huggingface.co/fdtn-ai/antares-1b",
    },
)


def _huggingface_repo(model: str) -> str:
    """Return the Hub repo behind an hf.co Ollama model, if one is explicit."""
    match = re.match(r"^hf\.co/([^/]+/[^:]+)(?::[^:]+)?$", model, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def _ollama_base(profile: ModelProfile) -> str:
    value = (profile.endpoint or "http://localhost:11434").rstrip("/")
    for suffix in ("/api/chat", "/api/tags", "/v1"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    return value


def _model_installed(requested: str, installed: list[str]) -> bool:
    requested_lower = requested.lower()
    aliases = {name.lower() for name in installed if name}
    if requested_lower in aliases:
        return True
    if ":" not in requested_lower and f"{requested_lower}:latest" in aliases:
        return True
    return False


def _models_match(requested: str, actual: str) -> bool:
    return _model_installed(requested, [actual])


def _candidate_runtime_installed(runtime: str) -> bool:
    """Report only runtimes SignalRoom can actually execute today."""
    if runtime == "local-transformers":
        return local_runtime_available()
    if runtime == "dedicated-time-series":
        return importlib.util.find_spec("cisco_tsm") is not None
    return False


_SETUP_SECRET = re.compile(
    r"(?i)\b(authorization|access[_-]?token|api[_-]?key|password|secret|token)"
    r"(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)"
)
_SETUP_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_SETUP_URL_USERINFO = re.compile(r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@")


def _safe_setup_detail(value: Any, limit: int = 1800) -> str:
    """Keep actionable installer output while removing common credential forms."""
    text = _SETUP_BEARER.sub("Bearer [REDACTED]", str(value or ""))
    text = _SETUP_URL_USERINFO.sub(r"\1[REDACTED]@", text)
    text = _SETUP_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        text,
    )
    try:
        home = str(Path.home())
        if home:
            text = text.replace(home, "~")
    except RuntimeError:
        pass
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    return text[-limit:]


def _model_host_context() -> dict[str, Any]:
    """Return the architecture facts that affect local binary-wheel compatibility."""
    system = platform.system()
    machine = platform.machine().lower() or "unknown"
    apple_silicon = False
    translated = False
    if system == "Darwin":
        try:
            arm_probe = subprocess.run(
                ["/usr/sbin/sysctl", "-in", "hw.optional.arm64"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            apple_silicon = arm_probe.stdout.strip() == "1"
        except (OSError, subprocess.SubprocessError):
            apple_silicon = machine == "arm64"
        try:
            translation_probe = subprocess.run(
                ["/usr/sbin/sysctl", "-in", "sysctl.proc_translated"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            translated = translation_probe.stdout.strip() == "1"
        except (OSError, subprocess.SubprocessError):
            translated = apple_silicon and machine != "arm64"
    return {
        "system": system,
        "machine": machine,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_platform": sysconfig.get_platform(),
        "apple_silicon": apple_silicon,
        "translated": translated,
        "architecture_ok": not (apple_silicon and machine != "arm64"),
        "outbound_tls_trust": system_tls_trust_state(),
    }


def _setup_failure(kind: str, stage: str, detail: Any, host: dict[str, Any]) -> dict[str, Any]:
    """Classify a failed installation into an operator-facing cause and remedy."""
    safe = _safe_setup_detail(detail)
    lowered = safe.lower()
    actions: list[dict[str, Any]] = []
    tls_trust = host.get("outbound_tls_trust") or {}
    if host.get("apple_silicon") and not host.get("architecture_ok"):
        code = "macos-rosetta-python"
        summary = "Apple Silicon is running an Intel Python environment"
        actions.extend(
            [
                {
                    "title": "Repair the native Python environment",
                    "detail": (
                        "Rerun ./install.sh and accept the native Apple Silicon Python repair, "
                        "then reopen SignalRoom and run this check again."
                    ),
                    "command": "./install.sh",
                    "external": False,
                },
                {
                    "title": "Capture the architecture evidence",
                    "detail": (
                        "Run the read-only collector and attach its redacted log if repair "
                        "still fails."
                    ),
                    "command": "./install.sh --diagnose_all",
                    "external": False,
                },
            ]
        )
    elif tls_trust.get("environment_bundle") and not tls_trust.get(
        "environment_bundle_exists"
    ):
        code = "tls-ca-bundle-missing"
        summary = "The configured outbound CA bundle does not exist"
        actions.append(
            {
                "title": "Correct or remove SSL_CERT_FILE",
                "detail": (
                    "Start SignalRoom with SSL_CERT_FILE pointing to an existing, approved PEM "
                    "bundle, or remove the variable to use the native operating-system trust store."
                ),
                "external": False,
            }
        )
    elif any(
        phrase in lowered
        for phrase in (
            "no matching distribution found",
            "could not find a version that satisfies",
            "not a supported wheel",
            "unsupported platform",
        )
    ):
        code = "binary-wheel-unavailable"
        summary = "A compatible local inference package is unavailable for this Python or architecture"
        actions.append(
            {
                "title": "Use a native supported Python",
                "detail": (
                    "Use native Python 3.11–3.13, rerun the installer to rebuild .venv, and retry. "
                    "Do not mix arm64 and x86_64 Python packages on macOS."
                ),
                "command": "./install.sh",
                "external": False,
            }
        )
    elif any(
        phrase in lowered
        for phrase in ("certificate verify failed", "certificate_verify_failed", "sslerror", "tls")
    ):
        code = "tls-trust"
        summary = "TLS certificate validation blocked the package or model download"
        if host.get("system") == "Darwin" and tls_trust.get("active"):
            actions.append(
                {
                    "title": "Repair the certificate chain in macOS Keychain",
                    "detail": (
                        "SignalRoom already used the native macOS trust store. Confirm "
                        "that the issuer or organization TLS-inspection root is installed and trusted "
                        "in Keychain Access, restart SignalRoom, and retry."
                    ),
                    "external": False,
                }
            )
        elif host.get("system") == "Darwin":
            actions.append(
                {
                    "title": "Update SignalRoom's native macOS trust support",
                    "detail": (
                        "Pull the current SignalRoom release and rerun the installer so outbound model "
                        "downloads can use certificates trusted by macOS Keychain."
                    ),
                    "command": "./install.sh --restart",
                    "external": False,
                }
            )
        actions.extend(
            [
                {
                    "title": "Use an explicit organization CA bundle when required",
                    "detail": (
                        "If policy distributes a PEM bundle instead of a Keychain root, set SSL_CERT_FILE "
                        "to that approved bundle before starting SignalRoom. Never disable verification."
                    ),
                    "command": (
                        "SSL_CERT_FILE=/absolute/path/to/approved-ca-bundle.pem "
                        "./install.sh --restart"
                    ),
                    "external": False,
                },
                {
                    "title": "Capture the outbound trust evidence",
                    "detail": (
                        "Run the read-only collector after restarting. It records the active trust mode, "
                        "CA-path presence, and Hugging Face verification result without "
                        "exporting certificates."
                    ),
                    "command": (
                        ".\\install.ps1 -DiagnoseAll"
                        if host.get("system") == "Windows"
                        else "./install.sh --diagnose_all"
                    ),
                    "external": False,
                },
            ]
        )
    elif any(phrase in lowered for phrase in ("no space left", "disk quota", "errno 28")):
        code = "storage"
        summary = "The model installation ran out of writable storage"
        actions.append(
            {
                "title": "Free local model storage",
                "detail": "Keep at least 10 GiB free in the SignalRoom data volume before retrying.",
                "external": False,
            }
        )
    elif any(
        phrase in lowered
        for phrase in (
            "permission denied",
            "operation not permitted",
            "read-only file system",
        )
    ):
        code = "filesystem-permission"
        summary = "SignalRoom cannot write the runtime or local model directory"
        actions.append(
            {
                "title": "Repair installation ownership",
                "detail": (
                    "Run SignalRoom from a user-writable directory and ensure .venv and data/models "
                    "belong to the account running the service."
                ),
                "external": False,
            }
        )
    elif any(phrase in lowered for phrase in ("401", "403", "unauthorized", "forbidden", "gated repo")):
        code = "source-authorization"
        summary = "The model source rejected this download"
        actions.append(
            {
                "title": "Check the model access boundary",
                "detail": (
                    "The shipped SecureBERT profiles are public and normally need no token. "
                    "Remove a stale token or save a valid fine-grained Hugging Face token for a gated source."
                ),
                "external": True,
            }
        )
    elif any(
        phrase in lowered
        for phrase in (
            "name resolution",
            "temporary failure",
            "connection refused",
            "timed out",
            "timeout",
            "network is unreachable",
        )
    ):
        code = "network"
        summary = "The configured model service or publisher could not be reached"
        actions.append(
            {
                "title": "Verify the correct network path",
                "detail": (
                    "Confirm the Ollama endpoint for Ollama failures, or HTTPS access to huggingface.co "
                    "for local specialist downloads, then retry."
                ),
                "external": kind == "local-transformers",
            }
        )
    elif kind == "ollama" and any(
        phrase in lowered for phrase in ("404", "not found", "manifest", "model does not exist")
    ):
        code = "ollama-model-unavailable"
        summary = "Ollama could not resolve the configured model identifier"
        actions.append(
            {
                "title": "Choose an installed or shipped profile",
                "detail": (
                    "Select an existing model from the Ollama inventory, or restore the shipped "
                    "profile identifier before retrying."
                ),
                "external": False,
            }
        )
    elif stage == "model-validation" and kind == "ollama":
        code = "ollama-inference-failed"
        summary = "The Ollama model is installed but failed a synthetic inference check"
        actions.append(
            {
                "title": "Check Ollama runtime capacity",
                "detail": (
                    "Review Ollama service output and available memory, then test a smaller shipped "
                    "Ollama profile to distinguish model capacity from service failure."
                ),
                "external": False,
            }
        )
    elif stage == "model-validation":
        code = "model-artifact-invalid"
        summary = "The downloaded specialist snapshot could not be loaded locally"
        actions.append(
            {
                "title": "Retry a shipped SecureBERT specialist",
                "detail": (
                    "Remove only the incomplete profile directory, retry its explicit install, "
                    "and use another shipped SecureBERT profile to distinguish repository-specific failure."
                ),
                "external": False,
            }
        )
    else:
        code = "unclassified-install-error"
        summary = "The model setup attempt failed at an identified stage"
        actions.append(
            {
                "title": "Collect the complete safe diagnostic",
                "detail": (
                    "Run the read-only diagnostic collector; it records Python, wheels, Ollama, "
                    "Hub access, and redacted service logs without downloading anything."
                ),
                "command": (
                    ".\\install.ps1 -DiagnoseAll"
                    if host.get("system") == "Windows"
                    else "./install.sh --diagnose_all"
                ),
                "external": False,
            }
        )
    return {
        "code": code,
        "stage": stage,
        "summary": summary,
        "detail": safe or "No additional installer output was returned.",
        "actions": actions,
    }


class ModelSetupService:
    """Readiness checks and explicit, profile-scoped local model downloads."""

    def __init__(
        self,
        config: ConfigStore,
        evidence: EvidenceStore | None = None,
        model_trust: Any | None = None,
    ):
        self.config = config
        self.evidence = evidence
        self.model_trust = model_trust
        self.jobs: dict[str, dict[str, Any]] = {}
        self.context_index_job: dict[str, Any] = {"status": "idle"}
        self.revision_state_path = self.config.root / "model_revisions.json"
        self.intake_queue_path = self.config.root / "model_intake.json"

    def catalog(self) -> dict[str, Any]:
        """Describe shipped capabilities and researched candidates without overstating support."""
        settings = self.config.load()
        configured = {profile.id for profile in settings.models}
        candidates = []
        for item in EVALUATED_MODEL_CANDIDATES:
            candidate = json.loads(json.dumps(item))
            profile_id = str(candidate.get("profile_id") or "")
            candidate["configured"] = bool(profile_id and profile_id in configured)
            candidate["runtime_installed"] = _candidate_runtime_installed(
                str(candidate.get("runtime") or "")
            )
            candidates.append(candidate)
        return {
            "configured": [profile.model_dump(mode="json") for profile in settings.models],
            "evaluated_candidates": candidates,
            "publisher_review": json.loads(json.dumps(MODEL_CATALOG_REVIEW)),
            "reviewed_publisher_models": len(REVIEWED_PUBLISHER_MODELS),
            "intake_queue": self._load_intake_queue(),
            "policy": (
                "Every model must pass source, runtime, input, output, evaluation, and routing gates. "
                "A useful publisher model is not treated as a SignalRoom capability until its exact "
                "analyst workflow is bounded and testable."
            ),
        }

    def _load_intake_queue(self) -> list[dict[str, Any]]:
        if not self.intake_queue_path.exists():
            return []
        try:
            value = json.loads(self.intake_queue_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return value if isinstance(value, list) else []

    def _save_intake_queue(self, values: list[dict[str, Any]]) -> None:
        self.intake_queue_path.write_text(
            json.dumps(values, indent=2, sort_keys=True), encoding="utf-8"
        )

    async def stage_publisher_intake(self, model: str) -> dict[str, Any]:
        """Create a durable, read-only review item for one first-party Hub repository."""
        publisher = model.split("/", 1)[0]
        if publisher not in PUBLISHER_CATALOGS:
            raise ValueError("Only monitored Cisco and Foundation AI publishers can be staged")
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                metadata = await self._hub_metadata(client, model)
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"The first-party model source could not be observed: {exc}") from exc
        reviewed = REVIEWED_PUBLISHER_MODELS.get(model, {})
        entry = {
            "model": model,
            "status": "pending-review",
            "staged_at": datetime.now(UTC).isoformat(),
            "reviewed_revision": str(reviewed.get("reviewed_revision") or ""),
            **metadata,
            "review_checklist": [
                "Confirm publisher, access terms, license, and immutable revision.",
                "Define one bounded analyst input and output contract.",
                "Implement synthetic evaluation controls before routing.",
                "Require exact local artifact approval before promotion.",
            ],
            "downloads_started": 0,
        }
        queue = [item for item in self._load_intake_queue() if item.get("model") != model]
        queue.insert(0, entry)
        self._save_intake_queue(queue[:50])
        return entry

    def discard_publisher_intake(self, model: str) -> dict[str, Any]:
        queue = self._load_intake_queue()
        retained = [item for item in queue if item.get("model") != model]
        if len(retained) == len(queue):
            raise KeyError(f"Model intake item not found: {model}")
        self._save_intake_queue(retained)
        return {"model": model, "discarded": True, "intake_queue": retained}

    @staticmethod
    def _normalized_ollama_endpoint(value: str) -> str:
        endpoint = (value or "http://localhost:11434").rstrip("/")
        for suffix in ("/api/chat", "/api/tags", "/v1"):
            if endpoint.endswith(suffix):
                endpoint = endpoint[: -len(suffix)]
        return endpoint

    async def stage_ollama_candidate(
        self,
        model: str,
        *,
        label: str = "",
        task: str = "chat",
        endpoint: str = "",
    ) -> dict[str, Any]:
        """Stage an installed Ollama model without changing a routed assignment."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,499}", model):
            raise ValueError("The Ollama model name contains unsupported characters")
        if task not in {"chat", "security_reasoning"}:
            raise ValueError("Candidates must target chat or security reasoning")
        settings = self.config.load()
        ollama_profiles = [item for item in settings.models if item.provider == "ollama"]
        configured_endpoints = {_ollama_base(item) for item in ollama_profiles}
        selected_endpoint = self._normalized_ollama_endpoint(
            endpoint or (_ollama_base(ollama_profiles[0]) if ollama_profiles else "")
        )
        if configured_endpoints and selected_endpoint not in configured_endpoints:
            raise ValueError("Candidate staging is limited to a configured Ollama endpoint")
        existing = next(
            (item for item in ollama_profiles if _models_match(model, item.model)), None
        )
        if existing is not None:
            qualifier = "already staged" if existing.lifecycle == "candidate" else "already configured"
            raise ValueError(f"{model} is {qualifier} as {existing.id}")
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                response = await client.get(f"{selected_endpoint}/api/tags")
                response.raise_for_status()
            values = [
                item
                for item in response.json().get("models", [])
                if isinstance(item, dict) and str(item.get("name") or "")
            ]
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"The configured Ollama inventory is unavailable: {exc}") from exc
        installed = next(
            (item for item in values if _models_match(model, str(item.get("name") or ""))),
            None,
        )
        if installed is None:
            raise ValueError("Only a model already installed at the configured Ollama endpoint can be staged")
        canonical_model = str(installed.get("name") or model)
        slug = re.sub(r"[^a-z0-9]+", "-", canonical_model.lower()).strip("-")[:48]
        suffix = hashlib.sha256(canonical_model.lower().encode()).hexdigest()[:8]
        profile_id = f"candidate-{slug or 'ollama'}-{suffix}"
        if any(item.id == profile_id for item in settings.models):
            raise ValueError(f"{canonical_model} is already staged as {profile_id}")
        staged_at = datetime.now(UTC).isoformat()
        profile = ModelProfile(
            id=profile_id,
            label=label.strip() or f"Evaluation · {canonical_model}",
            provider="ollama",
            model=canonical_model,
            task=task,
            endpoint=selected_endpoint,
            description=(
                "Temporary local evaluation profile. It cannot affect investigation routing until "
                "it wins a reviewed SignalRoom tournament and is explicitly promoted."
            ),
            provenance="Operator-staged installed Ollama model",
            lifecycle="candidate",
            staged_at=staged_at,
        )
        settings.models.append(profile)
        self.config.save(settings)
        return {
            "profile": profile.model_dump(mode="json"),
            "settings": self.config.public_payload(),
            "routing_unchanged": {
                "default_chat_model": settings.default_chat_model,
                "security_reasoning_model": settings.security_reasoning_model,
            },
            "local_digest": str(installed.get("digest") or ""),
        }

    def discard_ollama_candidate(self, profile_id: str) -> dict[str, Any]:
        settings = self.config.load()
        profile = next((item for item in settings.models if item.id == profile_id), None)
        if profile is None:
            raise KeyError(f"Unknown model profile: {profile_id}")
        if profile.lifecycle != "candidate":
            raise ValueError("Only a staged evaluation candidate can be discarded")
        if profile_id in {settings.default_chat_model, settings.security_reasoning_model}:
            raise ValueError("A routed model cannot be discarded; promote or roll back another model first")
        settings.models = [item for item in settings.models if item.id != profile_id]
        self.config.save(settings)
        state = self._load_revision_state()
        state.setdefault("profiles", {}).pop(profile_id, None)
        self._save_revision_state(state)
        return {
            "profile_id": profile_id,
            "discarded": True,
            "settings": self.config.public_payload(),
        }

    @staticmethod
    def _looks_like_source_code(code: str, language: str) -> bool:
        """Reject natural language, event text, and SPL before code-only classification."""
        value = code.strip()
        if re.search(
            r"(^|\s)\|\s*(stats|tstats|search|where|eval|timechart|table)\b",
            value,
            flags=re.IGNORECASE,
        ) or re.search(r"\b(index|sourcetype)\s*=", value, flags=re.IGNORECASE):
            return False
        language_patterns = {
            "python": (
                r"(^|\n)\s*(def|class|from|import)\s+",
                r"(^|\n)\s*(if|for|while|try|with)\b.*:",
                r"(^|\n)\s*return\b",
            ),
            "c": (
                r"#\s*include\b",
                r"\b(void|int|char|size_t|struct)\s+\w+\s*\(",
                r"[{};]",
            ),
            "cpp": (
                r"#\s*include\b",
                r"\b(namespace|template|class|std::)\b",
                r"[{};]",
            ),
        }
        return sum(
            bool(re.search(pattern, value, flags=re.IGNORECASE | re.MULTILINE))
            for pattern in language_patterns[language]
        ) >= 2

    async def screen_code_vulnerability(self, code: str, language: str) -> dict[str, Any]:
        """Run the admitted code classifier locally without persisting or forwarding source."""
        if not self._looks_like_source_code(code, language):
            raise ValueError(
                "The input does not match the selected source-code contract. "
                "Splunk objects, SPL, event text, and prose are intentionally rejected."
            )
        profile = next(
            (
                item
                for item in self.config.load().models
                if item.id == "securebert-code-vulnerability" and item.enabled
            ),
            None,
        )
        if not profile:
            raise KeyError("The SecureBERT code vulnerability profile is not enabled")
        if self.model_trust is not None:
            await self.model_trust.require_profile(
                profile.id, "local code vulnerability screening"
            )
        provider = LocalTransformersProvider(
            profile, self.config.local_model_path(profile.id)
        )
        health = await provider.health()
        if not health.get("ok"):
            raise RuntimeError(
                "The local code screening model is not ready. Install it from Models first."
            )
        result = await provider.classify(code)
        predictions = result.get("predictions") or []
        if not predictions:
            raise RuntimeError("The local classifier did not return a prediction")
        top = predictions[0]
        positive = int(top.get("class_id", -1)) == 1
        confidence = float(top.get("score") or 0)
        return {
            "ok": True,
            "capability_id": "securebert-code-vulnerability",
            "profile_id": profile.id,
            "model": profile.model,
            "runtime": "local-transformers",
            "network_inference": False,
            "language": language,
            "input_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "input_characters": len(code),
            "input_tokens": result.get("input_tokens", 0),
            "evaluated_tokens": result.get("evaluated_tokens", 0),
            "token_limit": result.get("token_limit", profile.context_window),
            "truncated": bool(result.get("truncated")),
            "prediction": {
                "class_id": int(top.get("class_id", -1)),
                "signal": (
                    "potential-vulnerability-review"
                    if positive
                    else "no-vulnerability-signal"
                ),
                "confidence": confidence,
                "scores": predictions,
            },
            "contract": {
                "finding": False,
                "automatic_routing": False,
                "source_persisted": False,
                "meaning": (
                    "Prioritize this snippet for static analysis and expert review."
                    if positive
                    else "The model did not produce a positive signal; this does not establish safety."
                ),
                "limitations": [
                    "The publisher reports 0.655 accuracy and 0.616 F1 on its evaluation data.",
                    "False positives and false negatives are expected.",
                    "The model does not perform dynamic analysis, data-flow proof, or remediation.",
                    "Corroborate with a static analyzer and manual code review.",
                ],
            },
        }

    def _load_revision_state(self) -> dict[str, Any]:
        if not self.revision_state_path.exists():
            return {"profiles": {}}
        try:
            value = json.loads(self.revision_state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"profiles": {}}
        except (OSError, ValueError):
            return {"profiles": {}}

    def _save_revision_state(self, value: dict[str, Any]) -> None:
        self.revision_state_path.write_text(json.dumps(value, indent=2), encoding="utf-8")

    async def _hub_metadata(
        self, client: httpx.AsyncClient, repo: str
    ) -> dict[str, Any]:
        headers = {}
        token = self.config.secret("huggingface_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await client.get(f"https://huggingface.co/api/models/{repo}", headers=headers)
        response.raise_for_status()
        metadata = response.json()
        card_data = metadata.get("cardData")
        if not isinstance(card_data, dict):
            card_data = {}
        return {
            "revision": str(metadata.get("sha") or ""),
            "last_modified": metadata.get("lastModified"),
            "pipeline_tag": metadata.get("pipeline_tag"),
            "gated": metadata.get("gated", False),
            "license": str(card_data.get("license") or "not-declared"),
            "source_url": f"https://huggingface.co/{repo}",
        }

    async def check_updates(self) -> dict[str, Any]:
        """Compare immutable local provenance with current first-party source revisions."""
        settings = self.config.load()
        tracking = self._load_revision_state().get("profiles", {})
        ollama_profiles = [profile for profile in settings.models if profile.provider == "ollama"]
        endpoints = {_ollama_base(profile) for profile in ollama_profiles}
        tags_by_endpoint: dict[str, dict[str, dict[str, Any]]] = {}
        endpoint_errors: dict[str, str] = {}
        repos = {
            profile.model if profile.provider == "huggingface" else _huggingface_repo(profile.model)
            for profile in settings.models
        } - {""}
        repos.update(str(item["model"]) for item in EVALUATED_MODEL_CANDIDATES)
        hub_metadata: dict[str, dict[str, Any]] = {}
        hub_errors: dict[str, str] = {}
        publisher_models: dict[str, list[dict[str, Any]]] = {}
        publisher_errors: dict[str, str] = {}
        publisher_incomplete: set[str] = set()

        async with httpx.AsyncClient(timeout=12) as client:
            async def load_tags(endpoint: str) -> None:
                try:
                    response = await client.get(f"{endpoint}/api/tags")
                    response.raise_for_status()
                    tags_by_endpoint[endpoint] = {
                        str(item.get("name") or "").lower(): item
                        for item in response.json().get("models", [])
                    }
                except (httpx.HTTPError, ValueError) as exc:
                    endpoint_errors[endpoint] = str(exc)

            async def load_hub(repo: str) -> None:
                try:
                    hub_metadata[repo] = await self._hub_metadata(client, repo)
                except (httpx.HTTPError, ValueError) as exc:
                    hub_errors[repo] = str(exc)

            async def load_publisher(publisher: str) -> None:
                try:
                    next_url = "https://huggingface.co/api/models"
                    params: dict[str, Any] | None = {
                        "author": publisher,
                        "limit": 100,
                        "full": "true",
                        "sort": "lastModified",
                        "direction": "-1",
                    }
                    observed: list[dict[str, Any]] = []
                    page_count = 0
                    while next_url and page_count < 10:
                        response = await client.get(next_url, params=params)
                        response.raise_for_status()
                        values = response.json()
                        if not isinstance(values, list):
                            raise ValueError("Publisher catalog returned an unexpected response.")
                        observed.extend(
                            {
                                "model": str(item.get("id") or ""),
                                "revision": str(item.get("sha") or ""),
                                "last_modified": item.get("lastModified"),
                                "pipeline_tag": item.get("pipeline_tag"),
                                "gated": item.get("gated", False),
                                "license": str((item.get("cardData") or {}).get("license") or "not-declared"),
                                "source_url": f"https://huggingface.co/{item.get('id')}",
                            }
                            for item in values
                            if isinstance(item, dict)
                            and str(item.get("id") or "").startswith(f"{publisher}/")
                            and not item.get("private", False)
                        )
                        page_count += 1
                        links = getattr(response, "links", {}) or {}
                        candidate_url = str((links.get("next") or {}).get("url") or "")
                        next_url = (
                            candidate_url
                            if candidate_url.startswith("https://huggingface.co/api/models")
                            else ""
                        )
                        params = None
                        if not next_url and len(values) >= 100:
                            publisher_incomplete.add(publisher)
                    if next_url:
                        publisher_incomplete.add(publisher)
                    publisher_models[publisher] = observed
                except (httpx.HTTPError, ValueError) as exc:
                    publisher_errors[publisher] = str(exc)

            await asyncio.gather(
                *(load_tags(endpoint) for endpoint in endpoints),
                *(load_hub(repo) for repo in repos),
                *(load_publisher(publisher) for publisher in PUBLISHER_CATALOGS),
            )

        results: list[dict[str, Any]] = []
        for profile in settings.models:
            base = {
                "profile_id": profile.id,
                "label": profile.label,
                "model": profile.model,
                "provider": profile.provider,
                "task": profile.task,
                "checked_at": datetime.now(UTC).isoformat(),
            }
            repo = profile.model if profile.provider == "huggingface" else _huggingface_repo(
                profile.model
            )
            remote = hub_metadata.get(repo, {})
            base.update(remote_revision=remote.get("revision", ""), **remote)
            if profile.provider == "huggingface":
                manifest_path = self.config.local_model_path(profile.id) / ".signalroom-model.json"
                manifest: dict[str, Any] = {}
                if manifest_path.exists():
                    try:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        manifest = {}
                installed = local_model_installed(self.config.local_model_path(profile.id))
                local_revision = str(manifest.get("revision") or "")
                base.update(installed=installed, local_revision=local_revision)
                if not installed:
                    base.update(status="not-installed", detail="Available for an explicit local install.")
                elif repo in hub_errors:
                    base.update(status="error", detail=hub_errors[repo])
                elif not local_revision:
                    base.update(
                        status="untracked",
                        detail=(
                            "Installed files predate immutable revision tracking; reinstall to "
                            "establish provenance."
                        ),
                    )
                elif local_revision != remote.get("revision"):
                    base.update(
                        status="update-available",
                        detail="The first-party Hub repository has a newer immutable revision.",
                    )
                else:
                    base.update(status="current", detail="Installed revision matches the Hub.")
                results.append(base)
                continue

            endpoint = _ollama_base(profile)
            tag = tags_by_endpoint.get(endpoint, {}).get(profile.model.lower())
            if tag is None and ":" not in profile.model:
                tag = tags_by_endpoint.get(endpoint, {}).get(f"{profile.model.lower()}:latest")
            installed = tag is not None
            local_digest = str((tag or {}).get("digest") or "")
            base.update(installed=installed, local_digest=local_digest)
            if endpoint in endpoint_errors:
                base.update(status="error", detail=endpoint_errors[endpoint])
            elif not installed:
                base.update(status="not-installed", detail="Available for an explicit Ollama download.")
            elif not repo:
                base.update(
                    status="check-unavailable",
                    detail=(
                        "Ollama exposes the local digest but no non-mutating registry freshness API; "
                        "use an explicit download to refresh."
                    ),
                )
            elif repo in hub_errors:
                base.update(status="error", detail=hub_errors[repo])
            else:
                installed_state = tracking.get(profile.id, {})
                tracked_revision = str(installed_state.get("source_revision") or "")
                tracked_digest = str(installed_state.get("local_digest") or "")
                base["local_revision"] = tracked_revision
                if (
                    not tracked_revision
                    or not tracked_digest
                    or not local_digest
                    or tracked_digest != local_digest
                ):
                    base.update(
                        status="untracked",
                        detail=(
                            "The model is installed, but SignalRoom did not perform the download that "
                            "would bind its Ollama digest to a Hub revision. Refresh once to begin tracking."
                        ),
                    )
                elif tracked_revision != remote.get("revision"):
                    base.update(
                        status="update-available",
                        detail="The first-party GGUF repository has a newer immutable revision.",
                    )
                else:
                    base.update(status="current", detail="Tracked Ollama digest matches the Hub revision.")
            results.append(base)

        counts = {
            status: sum(1 for item in results if item["status"] == status)
            for status in {
                "current",
                "update-available",
                "not-installed",
                "untracked",
                "check-unavailable",
                "error",
            }
        }
        candidate_sources = []
        for candidate in EVALUATED_MODEL_CANDIDATES:
            repo = str(candidate["model"])
            remote = hub_metadata.get(repo, {})
            candidate_sources.append(
                {
                    "candidate_id": candidate["id"],
                    "model": repo,
                    "status": "source-observed" if remote else "error",
                    "detail": (
                        "Observed the current immutable first-party Hub revision; no download started."
                        if remote
                        else hub_errors.get(repo, "The first-party source could not be observed.")
                    ),
                    **remote,
                }
            )
        publisher_catalogs = []
        for publisher in PUBLISHER_CATALOGS:
            observed = publisher_models.get(publisher, [])
            observed_by_id = {item["model"]: item for item in observed}
            observed_ids = {item["model"] for item in observed}
            reviewed_manifest = {
                model: review
                for model, review in REVIEWED_PUBLISHER_MODELS.items()
                if model.startswith(f"{publisher}/")
            }
            reviewed_ids = set(reviewed_manifest)
            unreviewed = [item for item in observed if item["model"] not in reviewed_ids]
            missing_reviewed = sorted(reviewed_ids - observed_ids)
            changed_reviewed = []
            for model in sorted(reviewed_ids & observed_ids):
                review = reviewed_manifest[model]
                current = observed_by_id[model]
                changes = []
                comparisons = (
                    (
                        "revision",
                        str(review.get("reviewed_revision") or ""),
                        str(current.get("revision") or ""),
                    ),
                    (
                        "pipeline_tag",
                        str(review.get("pipeline_tag") or ""),
                        str(current.get("pipeline_tag") or ""),
                    ),
                    (
                        "gated",
                        str(review.get("gated", False)).lower(),
                        str(current.get("gated", False)).lower(),
                    ),
                    (
                        "license",
                        str(review.get("license") or "not-declared"),
                        str(current.get("license") or "not-declared"),
                    ),
                )
                for field, reviewed_value, observed_value in comparisons:
                    if reviewed_value != observed_value:
                        changes.append(
                            {
                                "field": field,
                                "reviewed": reviewed_value,
                                "observed": observed_value,
                            }
                        )
                if changes:
                    changed_reviewed.append(
                        {
                            **current,
                            "reviewed_revision": review.get("reviewed_revision", ""),
                            "reviewed_at": review.get("reviewed_at", ""),
                            "decision": review.get("decision", ""),
                            "purpose": review.get("purpose", ""),
                            "changes": changes,
                        }
                    )
            error = publisher_errors.get(publisher, "")
            if error:
                status = "error"
                detail = error
            elif unreviewed or missing_reviewed or changed_reviewed or publisher in publisher_incomplete:
                status = "review-required"
                detail = (
                    "The publisher inventory differs from SignalRoom's immutable review manifest; "
                    "stage the exact source revision for review before changing a capability."
                )
            else:
                status = "current"
                detail = "Publisher catalog revisions and metadata match the dated intake manifest."
            publisher_catalogs.append(
                {
                    "publisher": publisher,
                    "status": status,
                    "observed_count": len(observed),
                    "reviewed_count": len(reviewed_ids),
                    "complete": publisher not in publisher_incomplete,
                    "unreviewed_models": unreviewed,
                    "missing_reviewed_models": missing_reviewed,
                    "changed_reviewed_models": changed_reviewed,
                    "detail": detail,
                }
            )
        source_attention = any(item["status"] != "current" for item in publisher_catalogs)
        runtime_failures = len(endpoint_errors)
        return {
            "checked_at": datetime.now(UTC).isoformat(),
            "profiles": results,
            "candidate_sources": candidate_sources,
            "publisher_catalogs": publisher_catalogs,
            "counts": counts,
            "health_axes": {
                "runtime": {
                    "status": "offline" if runtime_failures else "ready",
                    "failures": runtime_failures,
                    "detail": (
                        "One or more configured Ollama endpoints are unreachable."
                        if runtime_failures
                        else "Configured Ollama endpoints answered the local inventory check."
                    ),
                },
                "upstream": {
                    "status": "attention" if source_attention else "current",
                    "detail": (
                        "At least one publisher inventory requires review."
                        if source_attention
                        else "Publisher inventories match the immutable review manifest."
                    ),
                },
            },
            "downloads_started": 0,
            "policy": "Read-only check. SignalRoom never downloads, updates, or swaps a model here.",
        }

    async def _record_ollama_revision(self, profile: ModelProfile) -> dict[str, Any]:
        """Bind a completed explicit Ollama pull to its immutable Hub source revision."""
        repo = _huggingface_repo(profile.model)
        if not repo:
            return {"tracked": False, "reason": "No explicit Hugging Face source repository."}
        endpoint = _ollama_base(profile)
        async with httpx.AsyncClient(timeout=12) as client:
            tags_response, remote = await asyncio.gather(
                client.get(f"{endpoint}/api/tags"),
                self._hub_metadata(client, repo),
            )
            tags_response.raise_for_status()
        tag = next(
            (
                item
                for item in tags_response.json().get("models", [])
                if _model_installed(profile.model, [str(item.get("name") or "")])
            ),
            None,
        )
        if not tag:
            return {"tracked": False, "reason": "Ollama did not report the completed model."}
        local_digest = str(tag.get("digest") or "")
        if not local_digest:
            return {"tracked": False, "reason": "Ollama did not report a content digest."}
        state = self._load_revision_state()
        profiles = state.setdefault("profiles", {})
        profiles[profile.id] = {
            "model": profile.model,
            "source_repo": repo,
            "source_revision": remote["revision"],
            "local_digest": local_digest,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        self._save_revision_state(state)
        return {"tracked": True, **profiles[profile.id]}

    async def readiness(self) -> dict[str, Any]:
        settings = self.config.load()
        ollama_profiles = [profile for profile in settings.models if profile.provider == "ollama"]
        hf_profiles = [profile for profile in settings.models if profile.provider == "huggingface"]
        endpoint = _ollama_base(ollama_profiles[0]) if ollama_profiles else "http://localhost:11434"
        ollama: dict[str, Any] = {
            "ok": False,
            "endpoint": endpoint,
            "version": None,
            "models": [],
            "loaded_models": [],
            "profiles": [],
            "download_url": OLLAMA_DOWNLOAD_URL,
        }
        installed: list[str] = []
        loaded: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                tags_response, version_response = await asyncio.gather(
                    client.get(f"{endpoint}/api/tags"),
                    client.get(f"{endpoint}/api/version"),
                )
                tags_response.raise_for_status()
                version_response.raise_for_status()
                try:
                    running_response = await client.get(f"{endpoint}/api/ps")
                    running_response.raise_for_status()
                    loaded = [
                        item.get("name", "")
                        for item in running_response.json().get("models", [])
                    ]
                except (httpx.HTTPError, ValueError):
                    loaded = []
            installed = [item.get("name", "") for item in tags_response.json().get("models", [])]
            ollama.update(
                ok=True,
                version=version_response.json().get("version"),
                models=installed,
                loaded_models=loaded,
            )
        except (httpx.HTTPError, ValueError) as exc:
            ollama["error"] = str(exc)
        ollama["profiles"] = [
            {
                "id": profile.id,
                "label": profile.label,
                "model": profile.model,
                "installed": _model_installed(profile.model, installed),
                "loaded": _model_installed(profile.model, loaded),
                "pullable": bool(profile.enabled),
            }
            for profile in ollama_profiles
        ]

        local_profiles: list[dict[str, Any]] = []
        for profile in hf_profiles:
            model_path = self.config.local_model_path(profile.id)
            manifest_path = model_path / ".signalroom-model.json"
            manifest: dict[str, Any] = {}
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    manifest = {}
            local_profiles.append(
                {
                    "id": profile.id,
                    "label": profile.label,
                    "model": profile.model,
                    "task": profile.task,
                    "installed": local_model_installed(model_path),
                    "path": str(model_path),
                    "bytes": int(manifest.get("bytes") or 0),
                    "downloaded_at": manifest.get("downloaded_at"),
                    "revision": manifest.get("revision"),
                    "context_index": (
                        self.evidence.embedding_status(profile.id)
                        if self.evidence is not None and profile.task == "embedding"
                        else None
                    ),
                }
            )
        local_transformers: dict[str, Any] = {
            "selected": settings.specialist_runtime == "local",
            "runtime_installed": local_runtime_available(),
            "model_root": str(self.config.local_models_root),
            "profiles": local_profiles,
            "network_inference": False,
            "device": "available after runtime install",
            "index_job": self.context_index_job,
        }
        if local_transformers["runtime_installed"]:
            try:
                import torch

                local_transformers["device"] = "CUDA GPU" if torch.cuda.is_available() else "CPU"
            except Exception:
                local_transformers["device"] = "CPU"

        token = self.config.secret("huggingface_token")
        huggingface: dict[str, Any] = {
            "selected": settings.specialist_runtime == "cloud",
            "policy": settings.huggingface_policy,
            "token_configured": bool(token),
            "token_valid": None,
            "profiles": [],
            "token_url": HF_TOKEN_URL,
        }
        hf_enabled = (
            settings.specialist_runtime == "cloud"
            and settings.huggingface_policy != "disabled"
        )
        if token and hf_enabled:
            headers = {"Authorization": f"Bearer {token}"}
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    whoami = await client.get("https://huggingface.co/api/whoami-v2", headers=headers)
                    whoami.raise_for_status()
                huggingface["token_valid"] = True
            except (httpx.HTTPError, ValueError) as exc:
                huggingface["token_valid"] = False
                huggingface["error"] = str(exc)
        for profile in hf_profiles:
            item: dict[str, Any] = {
                "id": profile.id,
                "label": profile.label,
                "model": profile.model,
                "task": profile.task,
                "reachable": None,
            }
            if token and hf_enabled:
                try:
                    async with httpx.AsyncClient(timeout=8) as client:
                        response = await client.get(
                            f"https://huggingface.co/api/models/{profile.model}"
                            "?expand=inferenceProviderMapping",
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        response.raise_for_status()
                    metadata = response.json()
                    item["reachable"] = True
                    item["pipeline_tag"] = metadata.get("pipeline_tag")
                    item["inference_available"] = bool(metadata.get("inferenceProviderMapping"))
                except (httpx.HTTPError, ValueError) as exc:
                    item.update(reachable=False, error=str(exc))
            huggingface["profiles"].append(item)

        return {
            "host_os": platform.system(),
            "ollama": ollama,
            "local_transformers": local_transformers,
            "huggingface": huggingface,
            "ready": ollama["ok"] and any(item["installed"] for item in ollama["profiles"]),
        }

    def start_troubleshooting(
        self,
        ollama_profile_id: str = "ollama-general",
        local_profile_id: str = "securebert-ner",
    ) -> dict[str, Any]:
        """Start an explicit two-runtime install and capability drill."""
        settings = self.config.load()
        ollama_profile = next(
            (
                profile
                for profile in settings.models
                if profile.id == ollama_profile_id
                and profile.provider == "ollama"
                and profile.enabled
            ),
            None,
        )
        local_profile = next(
            (
                profile
                for profile in settings.models
                if profile.id == local_profile_id
                and profile.provider == "huggingface"
                and profile.enabled
                and profile.task in {"embedding", "ner", "reranking", "classification"}
            ),
            None,
        )
        if ollama_profile is None:
            raise KeyError(f"Enabled Ollama profile not found: {ollama_profile_id}")
        if local_profile is None:
            raise KeyError(f"Enabled local specialist profile not found: {local_profile_id}")
        existing = next(
            (
                job
                for job in self.jobs.values()
                if job.get("kind") == "guided-model-setup"
                and job.get("status") in {"queued", "running"}
            ),
            None,
        )
        if existing:
            return existing
        job_id = uuid.uuid4().hex
        host = _model_host_context()
        attempts = [
            {
                "provider": "ollama",
                "profile_id": ollama_profile.id,
                "label": ollama_profile.label,
                "model": ollama_profile.model,
                "task": ollama_profile.task,
                "status": "queued",
                "stage": "waiting",
                "detail": "Waiting for the Ollama installation check.",
                "download_started": False,
            },
            {
                "provider": "local-transformers",
                "profile_id": local_profile.id,
                "label": local_profile.label,
                "model": local_profile.model,
                "task": local_profile.task,
                "status": "queued",
                "stage": "waiting",
                "detail": "Waiting for the local Transformers installation check.",
                "download_started": False,
            },
        ]
        job = {
            "id": job_id,
            "profile_id": "",
            "kind": "guided-model-setup",
            "status": "queued",
            "decision": "pending",
            "stage": "host-preflight",
            "detail": "Inspecting local model runtime compatibility.",
            "progress": 0,
            "attempts": attempts,
            "host": host,
            "recommendations": [],
            "alternatives": self._setup_alternatives(settings, attempts),
            "downloads_started": 0,
            "created_at": datetime.now(UTC).isoformat(),
            "completed_at": None,
            "contract": (
                "Runs only after an explicit administrator action. Missing selected models may be "
                "downloaded; no route, trust policy, or cloud-inference policy is changed."
            ),
        }
        self.jobs[job_id] = job
        asyncio.create_task(self._run_troubleshooting(job_id))
        return job

    @staticmethod
    def _setup_alternatives(
        settings: Any, attempts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        selected = {str(item.get("profile_id") or "") for item in attempts}
        alternatives: list[dict[str, Any]] = []
        for profile in settings.models:
            if not profile.enabled or profile.id in selected:
                continue
            if profile.provider == "ollama":
                alternatives.append(
                    {
                        "kind": "ollama-profile",
                        "profile_id": profile.id,
                        "label": profile.label,
                        "model": profile.model,
                        "reason": (
                            "Shipped or operator-configured Ollama profile; test it without "
                            "changing routing."
                        ),
                        "external": False,
                    }
                )
            elif profile.provider == "huggingface" and profile.task in {
                "embedding",
                "ner",
                "reranking",
                "classification",
            }:
                alternatives.append(
                    {
                        "kind": "local-specialist",
                        "profile_id": profile.id,
                        "label": profile.label,
                        "model": profile.model,
                        "reason": (
                            "Shipped local Transformers specialist; useful for separating a "
                            "repository-specific problem from a shared runtime problem."
                        ),
                        "external": False,
                    }
                )
        alternatives.append(
            {
                "kind": "local-fallback",
                "profile_id": "",
                "label": "Lexical and deterministic specialist fallback",
                "model": "No additional model",
                "reason": (
                    "SignalRoom remains local and usable with FTS retrieval and deterministic "
                    "entity extraction while Transformers is repaired."
                ),
                "external": False,
            }
        )
        return alternatives[:8]

    async def _run_troubleshooting(self, job_id: str) -> None:
        job = self.jobs[job_id]
        job.update(status="running", stage="host-preflight", progress=3)
        host = job["host"]
        if not host.get("architecture_ok"):
            job["detail"] = "A local architecture mismatch was detected; both paths will still be checked."
        else:
            job["detail"] = "Host architecture is compatible; checking both selected runtimes."
        for index, attempt in enumerate(job["attempts"]):
            try:
                await self._run_setup_attempt(job, attempt, index)
            except Exception as exc:
                failure = attempt.get("failure") or _setup_failure(
                    str(attempt.get("provider") or ""),
                    str(attempt.get("stage") or "installation"),
                    exc,
                    host,
                )
                attempt.update(
                    status="error",
                    detail=failure["summary"],
                    failure=failure,
                )
            for action in (attempt.get("failure") or {}).get("actions", []):
                if action not in job["recommendations"]:
                    job["recommendations"].append(action)
        local_attempt = next(
            item for item in job["attempts"] if item["provider"] == "local-transformers"
        )
        if local_attempt["status"] == "error":
            job["recommendations"].extend(
                [
                    {
                        "title": "Continue safely without local Transformers",
                        "detail": (
                            "Keep the specialist runtime local. SignalRoom will use lexical RAG and "
                            "deterministic entity extraction until the specialist runtime is repaired."
                        ),
                        "external": False,
                    },
                    {
                        "title": "Use hosted specialists only as an explicit fallback",
                        "detail": (
                            "If policy permits external inference, select the cloud specialist runtime "
                            "and the Ask policy. This is optional and never enabled by this drill."
                        ),
                        "external": True,
                    },
                ]
            )
        ready = all(item["status"] == "complete" for item in job["attempts"])
        job.update(
            status="complete" if ready else "attention",
            decision="ready" if ready else "attention-required",
            stage="complete",
            detail=(
                "Both selected local model paths installed and passed their host-side checks."
                if ready
                else "At least one model path needs attention; use the stage-specific guidance below."
            ),
            progress=100,
            completed_at=datetime.now(UTC).isoformat(),
        )

    async def _run_setup_attempt(
        self,
        job: dict[str, Any],
        attempt: dict[str, Any],
        index: int,
    ) -> None:
        settings = self.config.load()
        profile = next(item for item in settings.models if item.id == attempt["profile_id"])
        base_progress = 8 if index == 0 else 53
        attempt.update(status="running", stage="service-check", detail="Checking current state.")
        job.update(
            stage=f"{attempt['provider']}:service-check",
            detail=f"Checking {attempt['label']} on this host.",
            progress=base_progress,
        )
        already_installed = False
        if attempt["provider"] == "ollama":
            endpoint = _ollama_base(profile)
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    response = await client.get(f"{endpoint}/api/tags")
                    response.raise_for_status()
                installed = [
                    str(item.get("name") or "")
                    for item in response.json().get("models", [])
                    if isinstance(item, dict)
                ]
                already_installed = _model_installed(profile.model, installed)
            except (httpx.HTTPError, ValueError) as exc:
                failure = _setup_failure("ollama", "service-check", exc, job["host"])
                attempt["failure"] = failure
                raise RuntimeError(failure["summary"]) from exc
        else:
            already_installed = local_model_installed(self.config.local_model_path(profile.id))

        if not already_installed:
            attempt.update(
                stage="installation",
                detail=f"Installing {profile.label} through its configured local provider.",
                download_started=True,
            )
            job["downloads_started"] += 1
            child = self.start_pull(profile.id)
            attempt["install_job_id"] = child["id"]
            while child.get("status") in {"queued", "pulling"}:
                attempt["detail"] = str(child.get("detail") or "Installing…")
                attempt["stage"] = str(child.get("stage") or "installation")
                child_progress = int(child.get("progress") or 0)
                job.update(
                    stage=f"{attempt['provider']}:{attempt['stage']}",
                    detail=attempt["detail"],
                    progress=min(base_progress + 38, base_progress + round(child_progress * 0.38)),
                )
                await asyncio.sleep(0.5)
                child = self.jobs[child["id"]]
            if child.get("public_retry"):
                attempt["public_retry"] = child["public_retry"]
            if child.get("tls_trust"):
                attempt["tls_trust"] = child["tls_trust"]
            if child.get("source_policy"):
                attempt["source_policy"] = child["source_policy"]
            if child.get("status") != "complete":
                failure = child.get("failure") or _setup_failure(
                    attempt["provider"],
                    str(child.get("stage") or "installation"),
                    child.get("diagnostic_tail") or child.get("detail") or "Installation failed",
                    job["host"],
                )
                attempt["diagnostic_tail"] = child.get("diagnostic_tail", "")
                attempt["failure"] = failure
                raise RuntimeError(failure["summary"])

        attempt.update(stage="model-validation", detail="Verifying the installed artifact locally.")
        job.update(
            stage=f"{attempt['provider']}:model-validation",
            detail=f"Verifying {profile.label} without changing SignalRoom routing.",
            progress=base_progress + 39,
        )
        if attempt["provider"] == "ollama":
            endpoint = _ollama_base(profile)
            async with httpx.AsyncClient(timeout=8) as client:
                response = await client.get(f"{endpoint}/api/tags")
                response.raise_for_status()
            installed = [
                str(item.get("name") or "")
                for item in response.json().get("models", [])
                if isinstance(item, dict)
            ]
            if not _model_installed(profile.model, installed):
                raise RuntimeError("Ollama completed the request but did not report the selected model")
            proof = await self._smoke_ollama_profile(profile)
            proof.update(inventory_visible=True, endpoint=endpoint)
        else:
            proof = await self._smoke_local_specialist(profile)
        attempt.update(
            status="complete",
            stage="complete",
            detail=(
                "Existing installation verified; no download was needed."
                if already_installed
                else "Installation completed and the local capability check passed."
            ),
            proof=proof,
        )
        job["progress"] = base_progress + 42

    async def _smoke_ollama_profile(self, profile: ModelProfile) -> dict[str, Any]:
        """Run a bounded synthetic generation and retain no response content."""
        endpoint = _ollama_base(profile)
        timeout = httpx.Timeout(connect=10, read=300, write=30, pool=10)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{endpoint}/api/chat",
                json={
                    "model": profile.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": (
                                "Synthetic SignalRoom setup probe. Reply with the single word READY."
                            ),
                        }
                    ],
                    "stream": False,
                    "keep_alive": "5m",
                    "options": {"temperature": 0, "num_predict": 8},
                },
            )
            response.raise_for_status()
        payload = response.json()
        content = str((payload.get("message") or {}).get("content") or "").strip()
        if not content:
            raise RuntimeError("Ollama returned no assistant content for the synthetic probe")
        return {
            "runtime": "ollama",
            "capability": "chat",
            "response_received": True,
            "output_retained": False,
        }

    async def _smoke_local_specialist(self, profile: ModelProfile) -> dict[str, Any]:
        """Load one installed specialist with synthetic input and retain value-free proof."""
        provider = LocalTransformersProvider(profile, self.config.local_model_path(profile.id))
        health = await provider.health()
        if not health.get("ok"):
            raise RuntimeError("The local runtime or model artifact is incomplete")
        if profile.task == "embedding":
            values = await provider.query_embedding("Synthetic security validation record")
            if not values:
                raise RuntimeError("The embedding model loaded but returned no vector")
            return {"runtime": "local-transformers", "capability": "embedding", "dimensions": len(values)}
        if profile.task == "reranking":
            values = await provider.rerank(
                "synthetic suspicious authentication",
                ["Synthetic authentication evidence for setup validation."],
            )
            if len(values) != 1:
                raise RuntimeError("The reranker loaded but returned an unexpected result shape")
            return {"runtime": "local-transformers", "capability": "reranking", "results": 1}
        if profile.task == "classification":
            value = await provider.classify(
                "int synthetic_copy(char *dst, const char *src) { return dst && src ? 0 : 1; }"
            )
            if not value.get("predictions"):
                raise RuntimeError("The classifier loaded but returned no prediction")
            return {
                "runtime": "local-transformers",
                "capability": "classification",
                "classes": len(value["predictions"]),
            }
        values = await provider.entities("Synthetic host demo-host observed CVE-2024-0001.")
        return {
            "runtime": "local-transformers",
            "capability": "ner",
            "invocation_ok": isinstance(values, list),
            "candidate_count": len(values),
        }

    async def activate(
        self, profile_id: str, unload_other_signalroom_models: bool = True
    ) -> dict[str, Any]:
        """Explicitly load one configured Ollama profile and optionally unload its peers."""
        settings = self.config.load()
        profile = next(
            (
                candidate
                for candidate in settings.models
                if candidate.id == profile_id
                and candidate.provider == "ollama"
                and candidate.enabled
            ),
            None,
        )
        if not profile:
            raise KeyError(f"Enabled Ollama profile not found: {profile_id}")
        trust = (
            await self.model_trust.require_profile(profile.id, "model activation")
            if self.model_trust is not None
            else None
        )
        endpoint = _ollama_base(profile)
        timeout = httpx.Timeout(connect=10, read=180, write=30, pool=10)
        unloaded: list[str] = []
        async with httpx.AsyncClient(timeout=timeout) as client:
            tags_response = await client.get(f"{endpoint}/api/tags")
            tags_response.raise_for_status()
            installed = [
                item.get("name", "") for item in tags_response.json().get("models", [])
            ]
            if not _model_installed(profile.model, installed):
                raise RuntimeError(f"Ollama model is not installed: {profile.model}")
            if unload_other_signalroom_models:
                try:
                    running_response = await client.get(f"{endpoint}/api/ps")
                    running_response.raise_for_status()
                    loaded = [
                        item.get("name", "")
                        for item in running_response.json().get("models", [])
                    ]
                except (httpx.HTTPError, ValueError):
                    loaded = []
                peers = [
                    candidate
                    for candidate in settings.models
                    if candidate.provider == "ollama"
                    and candidate.id != profile.id
                    and _model_installed(candidate.model, loaded)
                ]
                for peer in peers:
                    response = await client.post(
                        f"{endpoint}/api/generate",
                        json={
                            "model": peer.model,
                            "prompt": "",
                            "stream": False,
                            "keep_alive": 0,
                        },
                    )
                    response.raise_for_status()
                    unloaded.append(peer.model)
            response = await client.post(
                f"{endpoint}/api/generate",
                json={
                    "model": profile.model,
                    "prompt": "",
                    "stream": False,
                    "keep_alive": "15m",
                },
            )
            response.raise_for_status()
            activated = response.json()
            executed_model = str(activated.get("model") or profile.model)
            if not _models_match(profile.model, executed_model):
                raise RuntimeError(
                    f"Ollama loaded '{executed_model}' instead of requested '{profile.model}'"
                )
            try:
                running_response = await client.get(f"{endpoint}/api/ps")
                running_response.raise_for_status()
                loaded_after = [
                    item.get("name", "")
                    for item in running_response.json().get("models", [])
                ]
            except (httpx.HTTPError, ValueError):
                loaded_after = [executed_model]
        return {
            "ok": True,
            "profile_id": profile.id,
            "requested_model": profile.model,
            "executed_model": executed_model,
            "loaded_models": loaded_after,
            "unloaded_models": unloaded,
            "endpoint": endpoint,
            "trust": trust,
        }

    def start_pull(self, profile_id: str) -> dict[str, Any]:
        profile = next(
            (
                candidate
                for candidate in self.config.load().models
                if candidate.id == profile_id and candidate.enabled
            ),
            None,
        )
        if not profile:
            raise KeyError(f"Enabled model profile not found: {profile_id}")
        source_trust = (
            self.model_trust.validate_source(profile, "model installation")
            if self.model_trust is not None
            else None
        )
        if profile.provider == "huggingface" and profile.task not in {
            "embedding",
            "ner",
            "reranking",
            "classification",
        }:
            raise KeyError(f"Profile cannot be installed as a local specialist: {profile_id}")
        existing = next(
            (
                job
                for job in self.jobs.values()
                if job.get("profile_id") == profile_id
                and job.get("status") in {"queued", "pulling"}
            ),
            None,
        )
        if existing:
            return existing
        job_id = uuid.uuid4().hex
        job = {
            "id": job_id,
            "profile_id": profile.id,
            "model": profile.model,
            "kind": "ollama" if profile.provider == "ollama" else "local-transformers",
            "endpoint": _ollama_base(profile) if profile.provider == "ollama" else "huggingface-hub",
            "path": (
                "" if profile.provider == "ollama" else str(self.config.local_model_path(profile.id))
            ),
            "status": "queued",
            "detail": "Queued",
            "completed": 0,
            "total": 0,
            "progress": 0,
            "created_at": datetime.now(UTC).isoformat(),
            "source_trust": source_trust,
        }
        self.jobs[job_id] = job
        asyncio.create_task(self._pull(job_id))
        return job

    def get_job(self, job_id: str) -> dict[str, Any]:
        if job_id not in self.jobs:
            raise KeyError(f"Model pull job not found: {job_id}")
        return self.jobs[job_id]

    async def _pull(self, job_id: str) -> None:
        job = self.jobs[job_id]
        if job["kind"] == "local-transformers":
            await self._install_local_specialist(job)
            return
        job.update(status="pulling", stage="ollama-service", detail="Contacting Ollama")
        try:
            timeout = httpx.Timeout(connect=10, read=None, write=30, pool=10)
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    f"{job['endpoint']}/api/pull",
                    json={"model": job["model"], "stream": True},
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        event = json.loads(line)
                        if event.get("error"):
                            raise RuntimeError(event["error"])
                        completed = int(event.get("completed") or job["completed"])
                        total = int(event.get("total") or job["total"])
                        job.update(
                            stage="ollama-download",
                            detail=event.get("status", job["detail"]),
                            completed=completed,
                            total=total,
                            progress=round(completed * 100 / total) if total else job["progress"],
                        )
            profile = next(
                item for item in self.config.load().models if item.id == job["profile_id"]
            )
            try:
                job["revision_tracking"] = await self._record_ollama_revision(profile)
            except Exception as exc:
                job["revision_tracking"] = {"tracked": False, "reason": str(exc)}
            if self.model_trust is not None:
                job["trust"] = self.model_trust.assess(
                    await self.model_trust.observe(profile.id, verify_files=True)
                )
            job.update(status="complete", stage="complete", detail="Model ready", progress=100)
        except (httpx.HTTPError, ValueError, RuntimeError) as exc:
            failure = _setup_failure(
                "ollama",
                str(job.get("stage") or "ollama-download"),
                exc,
                _model_host_context(),
            )
            job.update(
                status="error",
                detail=failure["summary"],
                diagnostic_tail=failure["detail"],
                failure=failure,
            )

    async def _install_local_specialist(self, job: dict[str, Any]) -> None:
        job["tls_trust"] = system_tls_trust_state()
        job.update(
            status="pulling",
            stage="runtime-check",
            detail="Checking the local Transformers runtime",
            progress=5,
        )
        diagnostic_lines: list[str] = []
        try:
            if not local_runtime_available():
                job.update(
                    stage="runtime-install",
                    detail="Installing the local inference runtime",
                    progress=10,
                )
                creationflags = 0x08000000 if os.name == "nt" else 0
                initial_install_started = time.monotonic()
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    *LOCAL_RUNTIME_PACKAGES,
                    "--disable-pip-version-check",
                    "--no-input",
                    "--retries",
                    "1",
                    "--timeout",
                    "20",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    creationflags=creationflags,
                )
                if process.stdout:
                    async for line in process.stdout:
                        detail = line.decode("utf-8", errors="replace").strip()
                        if detail:
                            safe_detail = _safe_setup_detail(detail, 400)
                            diagnostic_lines.append(safe_detail)
                            diagnostic_lines = diagnostic_lines[-12:]
                            job["detail"] = safe_detail[-240:]
                return_code = await process.wait()
                importlib.invalidate_caches()
                initial_tail = "\n".join(diagnostic_lines)
                initial_install_seconds = time.monotonic() - initial_install_started
                if (
                    return_code != 0
                    and _should_retry_public_source(
                        initial_tail,
                        elapsed_seconds=initial_install_seconds,
                    )
                ):
                    public_pip_env = credential_free_pip_environment()
                    job.update(
                        stage="runtime-install-public-retry",
                        detail=(
                            "Configured package sources did not resolve the runtime; retrying "
                            "credential-free against public PyPI only"
                        ),
                        progress=16,
                        public_retry={
                            "attempted": True,
                            "source": "https://pypi.org/simple",
                            "credentials_sent": False,
                            "reason": _safe_setup_detail(initial_tail, 600),
                            "trigger": "fail-fast-source-resolution",
                            "initial_failure_seconds": round(initial_install_seconds, 2),
                        },
                    )
                    diagnostic_lines = []
                    process = await asyncio.create_subprocess_exec(
                        sys.executable,
                        "-m",
                        "pip",
                        "install",
                        "--isolated",
                        "--index-url",
                        "https://pypi.org/simple",
                        "--no-cache-dir",
                        "--no-input",
                        "--disable-pip-version-check",
                        "--retries",
                        "1",
                        "--timeout",
                        "20",
                        *LOCAL_RUNTIME_PACKAGES,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        creationflags=creationflags,
                        env=public_pip_env,
                    )
                    if process.stdout:
                        async for line in process.stdout:
                            detail = line.decode("utf-8", errors="replace").strip()
                            if detail:
                                safe_detail = _safe_setup_detail(detail, 400)
                                diagnostic_lines.append(safe_detail)
                                diagnostic_lines = diagnostic_lines[-12:]
                                job["detail"] = safe_detail[-240:]
                    return_code = await process.wait()
                    importlib.invalidate_caches()
                    job["public_retry"]["succeeded"] = (
                        return_code == 0 and local_runtime_available()
                    )
                if return_code != 0 or not local_runtime_available():
                    tail = "\n".join(diagnostic_lines) or (
                        f"pip exited with status {return_code}; one or more required modules "
                        "could not be imported afterward"
                    )
                    failure = _setup_failure(
                        "local-transformers",
                        "runtime-install",
                        tail,
                        _model_host_context(),
                    )
                    job.update(failure=failure, diagnostic_tail=failure["detail"])
                    raise RuntimeError(failure["summary"])

            job.update(
                stage="model-download",
                detail=f"Downloading {job['model']} from Hugging Face to local storage",
                progress=30,
            )
            profile = next(
                profile
                for profile in self.config.load().models
                if profile.id == job["profile_id"]
            )
            model_path = self.config.local_model_path(profile.id)
            model_path.mkdir(parents=True, exist_ok=True)
            token = self.config.secret("huggingface_token") or None
            reviewed = REVIEWED_PUBLISHER_MODELS.get(profile.model, {})
            public_source = bool(reviewed) and not bool(reviewed.get("gated"))
            job["source_policy"] = {
                "mode": "credential-free-public" if public_source else "configured-access",
                "source": "https://huggingface.co" if public_source else "configured Hugging Face",
                "credentials_sent": False if public_source else bool(token),
                "first_attempt": True,
                "reason": (
                    "The admitted publisher revision is public, so SignalRoom bypassed saved "
                    "credentials and alternate Hub endpoints."
                    if public_source
                    else "The repository is not admitted as public; configured access policy applies."
                ),
            }

            def download(*, public_only: bool = False) -> tuple[str, str]:
                from huggingface_hub import HfApi, snapshot_download

                selected_token: str | bool | None = False if public_only else token
                endpoint = "https://huggingface.co" if public_only else None
                revision = HfApi(endpoint=endpoint, token=selected_token).model_info(
                    profile.model
                ).sha

                snapshot = snapshot_download(
                    repo_id=profile.model,
                    revision=revision,
                    local_dir=model_path,
                    token=selected_token,
                    endpoint=endpoint,
                    ignore_patterns=[
                        "*.bin",
                        "*.h5",
                        "*.msgpack",
                        "*.onnx",
                        "*.ot",
                    ],
                )
                return snapshot, revision

            download_task = asyncio.create_task(
                asyncio.to_thread(download, public_only=public_source)
            )
            elapsed = 0
            while not download_task.done():
                await asyncio.sleep(1)
                elapsed += 1
                job.update(
                    detail=(
                        f"Downloading {profile.label} into SignalRoom local storage · "
                        f"{elapsed}s elapsed"
                    ),
                    progress=min(85, 30 + elapsed // 10),
                )
            _, revision = await download_task
            job.update(stage="model-validation", detail="Validating the downloaded model", progress=92)
            if not (model_path / "config.json").exists() or not any(
                model_path.glob("*.safetensors")
            ):
                raise RuntimeError("Downloaded snapshot is missing model configuration or weights")
            size = sum(
                item.stat().st_size
                for item in model_path.rglob("*")
                if item.is_file() and ".cache" not in item.parts
            )
            artifact = (
                await asyncio.to_thread(
                    self.model_trust.hash_local_artifact, model_path
                )
                if self.model_trust is not None
                else {}
            )
            (model_path / ".signalroom-model.json").write_text(
                json.dumps(
                    {
                        "profile_id": profile.id,
                        "model": profile.model,
                        "task": profile.task,
                        "revision": revision,
                        "bytes": size,
                        "downloaded_at": datetime.now(UTC).isoformat(),
                        "runtime": "local-transformers",
                        "artifact_sha256": artifact.get("artifact_sha256", ""),
                        "file_count": artifact.get("file_count", 0),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            if not local_model_installed(model_path):
                raise RuntimeError("Local model validation failed")
            if profile.task == "embedding" and self.evidence is not None:
                job.update(detail="Indexing SignalRoom Context locally", progress=95)
                await self._backfill_embeddings(profile, job)
            if self.model_trust is not None:
                job["trust"] = self.model_trust.assess(
                    await self.model_trust.observe(profile.id, verify_files=True)
                )
            job.update(
                status="complete",
                stage="complete",
                detail="Local specialist ready · no cloud inference required",
                progress=100,
                total=size,
                completed=size,
            )
        except Exception as exc:
            failure = job.get("failure") or _setup_failure(
                "local-transformers",
                str(job.get("stage") or "installation"),
                exc,
                _model_host_context(),
            )
            job.update(
                status="error",
                detail=failure["summary"],
                diagnostic_tail=job.get("diagnostic_tail") or failure["detail"],
                failure=failure,
            )

    async def _backfill_embeddings(
        self, profile: ModelProfile, job: dict[str, Any]
    ) -> dict[str, int]:
        if self.evidence is None:
            return {"total_chunks": 0, "indexed_chunks": 0, "pending_chunks": 0}
        provider = LocalTransformersProvider(profile, self.config.local_model_path(profile.id))
        status = self.evidence.embedding_status(profile.id)
        total = status["total_chunks"]
        while True:
            pending = self.evidence.pending_embeddings(profile.id, limit=64)
            if not pending:
                break
            vectors = await provider.document_embeddings([content for _, content in pending])
            values = [
                (chunk_id, vector)
                for (chunk_id, _), vector in zip(pending, vectors, strict=False)
                if vector
            ]
            if not values:
                raise RuntimeError("The local embedding model returned no Context vectors")
            self.evidence.save_embeddings(profile.id, values)
            status = self.evidence.embedding_status(profile.id)
            indexed = status["indexed_chunks"]
            job.update(
                detail=f"Indexed {indexed} of {total} local Context chunks",
                progress=min(99, 95 + round(4 * indexed / max(total, 1))),
                indexed_chunks=indexed,
                context_chunks=total,
            )
        return self.evidence.embedding_status(profile.id)

    def schedule_context_index(self) -> bool:
        """Queue incremental local Context indexing without delaying artifact writes."""
        if self.evidence is None or self.context_index_job.get("status") in {
            "queued",
            "pulling",
        }:
            return False
        settings = self.config.load()
        if settings.specialist_runtime != "local":
            return False
        profile = next(
            (
                item
                for item in settings.models
                if item.id == settings.embedding_model
                and item.enabled
                and item.task == "embedding"
            ),
            None,
        )
        if profile is None or not local_model_installed(self.config.local_model_path(profile.id)):
            return False
        self.context_index_job = {
            "status": "queued",
            "profile_id": profile.id,
            "detail": "Queued incremental Context indexing",
            "progress": 0,
        }
        asyncio.create_task(self._run_context_index(profile, self.context_index_job))
        return True

    async def _run_context_index(
        self, profile: ModelProfile, job: dict[str, Any]
    ) -> None:
        job.update(status="pulling", detail="Indexing new Context locally", progress=5)
        try:
            status = await self._backfill_embeddings(profile, job)
            job.update(
                status="complete",
                detail=f"Indexed {status['indexed_chunks']} local Context chunks",
                progress=100,
                **status,
            )
        except Exception as exc:
            job.update(status="error", detail=str(exc))


async def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Check or download SignalRoom model profiles")
    parser.add_argument("command", choices=["status", "pull"])
    parser.add_argument("profiles", nargs="*", help="Profile IDs; pull defaults to all Ollama profiles")
    args = parser.parse_args()
    root = Path(os.getenv("SIGNALROOM_ROOT", Path.cwd())).resolve()
    data = Path(os.getenv("SIGNALROOM_DATA_DIR", root / "data")).resolve()
    service = ModelSetupService(ConfigStore(data))
    if args.command == "status":
        print(json.dumps(await service.readiness(), indent=2))
        return 0
    settings = service.config.load()
    profile_ids = args.profiles or list(
        dict.fromkeys([settings.default_chat_model, settings.security_reasoning_model])
    )
    for profile_id in profile_ids:
        job = service.start_pull(profile_id)
        while job["status"] in {"queued", "pulling"}:
            print(f"{profile_id}: {job['detail']} ({job['progress']}%)", flush=True)
            await asyncio.sleep(1)
        print(f"{profile_id}: {job['detail']}")
        if job["status"] != "complete":
            return 1
    return 0


def run() -> None:
    raise SystemExit(asyncio.run(_cli()))


if __name__ == "__main__":
    run()
