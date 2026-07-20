from __future__ import annotations

import ipaddress
import math
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx


class CiscoTimeSeriesProvider:
    """Client for Cisco's dedicated Python 3.11 forecasting service."""

    MODEL_ID = "cisco-ai/cisco-time-series-model-1.0"

    def __init__(
        self,
        endpoint: str,
        token: str = "",
        verify_ssl: bool = True,
        ca_bundle: str | None = None,
    ):
        self.endpoint = self._normalize_endpoint(endpoint)
        self.token = token
        self.verify_ssl: bool | str = (
            str(Path(ca_bundle).expanduser()) if verify_ssl and ca_bundle else verify_ssl
        )

    @staticmethod
    def _normalize_endpoint(value: str) -> str:
        endpoint = value.strip().rstrip("/")
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Cisco TSM endpoint must be an http:// or https:// service URL")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Cisco TSM endpoint contains an invalid port") from exc
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Cisco TSM endpoint cannot contain credentials, query text, or fragments")
        if parsed.path not in {"", "/"}:
            raise ValueError("Cisco TSM endpoint must be the service root, without an API path")
        return endpoint

    @staticmethod
    def network_scope(endpoint: str) -> str:
        host = (urlsplit(endpoint).hostname or "").lower()
        if host in {"localhost", "host.docker.internal", "cisco-tsm"}:
            return "loopback"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                resolved = {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        host,
                        urlsplit(endpoint).port
                        or (443 if urlsplit(endpoint).scheme == "https" else 80),
                        type=socket.SOCK_STREAM,
                    )
                }
            except OSError:
                return "operator-private-dns"
            scopes = []
            for value in resolved:
                address = ipaddress.ip_address(value)
                scopes.append(
                    "loopback"
                    if address.is_loopback
                    else "private-network"
                    if address.is_private or address.is_link_local
                    else "public-network"
                )
            if "public-network" in scopes:
                return "public-network"
            return "loopback" if scopes and set(scopes) == {"loopback"} else "private-network"
        if address.is_loopback:
            return "loopback"
        if address.is_private or address.is_link_local:
            return "private-network"
        return "public-network"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def health(self) -> dict[str, Any]:
        scope = self.network_scope(self.endpoint)
        if scope == "public-network":
            return {
                "ok": False,
                "ready": False,
                "endpoint": self.endpoint,
                "network_scope": scope,
                "error": (
                    "Public Cisco TSM endpoints are blocked by the local-first adapter. "
                    "Use loopback, Docker service DNS, or a private-network host."
                ),
            }
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=12) as client:
                response = await client.get(f"{self.endpoint}/ready")
                try:
                    body = response.json()
                except ValueError as exc:
                    raise ValueError(
                        "Endpoint did not return Cisco TSM readiness JSON; "
                        "another local service may own this port"
                    ) from exc
                if isinstance(body.get("detail"), dict):
                    body = body["detail"]
                ready = response.status_code == 200 and body.get("status") == "ready"
                return {
                    **body,
                    "ok": ready,
                    "ready": ready,
                    "endpoint": self.endpoint,
                    "network_scope": scope,
                    "token_configured": bool(self.token),
                }
        except (httpx.HTTPError, ValueError) as exc:
            return {
                "ok": False,
                "ready": False,
                "endpoint": self.endpoint,
                "network_scope": scope,
                "token_configured": bool(self.token),
                "error": str(exc),
            }

    @staticmethod
    def _contexts(values: list[float]) -> tuple[list[float], list[float]]:
        fine = values[-512:]
        raw = values[-(512 * 60) :]
        remainder = len(raw) % 60
        aligned = raw[remainder:] if remainder else raw
        coarse = [
            sum(aligned[index : index + 60]) / 60
            for index in range(0, len(aligned), 60)
        ]
        if not coarse:
            coarse = [sum(raw) / len(raw)]
        return coarse[-512:], fine

    async def forecast(
        self,
        values: list[float],
        horizon: int,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if not 10 <= len(values) <= 30_720:
            raise ValueError("Cisco TSM requires between 10 and 30,720 prepared points")
        if not 1 <= horizon <= 128:
            raise ValueError("Cisco TSM forecast horizons must be between 1 and 128 points")
        if any(not math.isfinite(value) for value in values):
            raise ValueError("Prepared Cisco TSM input must contain only finite numeric values")
        scope = self.network_scope(self.endpoint)
        if scope == "public-network":
            raise PermissionError("Public forecasting endpoints are blocked by local-first policy")
        coarse, fine = self._contexts(values)
        correlation_id = request_id or uuid4().hex
        body = {
            "payload": [{"coarse_ctx": coarse, "fine_ctx": fine}],
            "model": "CDTSM",
            "metadata": {"quantiles": ["mean", "p10", "p50", "p90"]},
        }
        timeout = httpx.Timeout(connect=12, read=900, write=30, pool=12)
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=timeout) as client:
                response = await client.post(
                    f"{self.endpoint}/cdtsm/v1/ai/infer",
                    params={"horizon": horizon},
                    headers={**self._headers(), "request_id": correlation_id},
                    json=body,
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPStatusError as exc:
            try:
                error_body = exc.response.json()
                detail = error_body.get("error") or error_body.get("detail") or {}
                message = (
                    detail.get("message") or detail.get("detail")
                    if isinstance(detail, dict)
                    else str(detail)
                )
            except (ValueError, AttributeError):
                message = ""
            raise RuntimeError(
                str(message) or f"Cisco TSM returned HTTP {exc.response.status_code}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"Local Cisco TSM inference failed: {exc}") from exc
        predictions = payload.get("predictions") or []
        if len(predictions) != 1:
            raise RuntimeError("Cisco TSM returned an unexpected forecast batch")
        prediction = predictions[0]
        mean = [float(value) for value in prediction.get("mean") or []]
        quantiles = {
            key: [float(value) for value in values]
            for key, values in (prediction.get("quantiles") or {}).items()
            if key in {"p10", "p50", "p90"}
        }
        all_outputs = [mean, *quantiles.values()]
        if (
            len(mean) != horizon
            or set(quantiles) != {"p10", "p50", "p90"}
            or any(len(values) != horizon for values in quantiles.values())
            or any(not math.isfinite(value) for values in all_outputs for value in values)
        ):
            raise RuntimeError("Cisco TSM returned an incomplete forecast horizon")
        return {
            "request_id": str(payload.get("request_id") or correlation_id),
            "model": str(payload.get("model") or "CDTSM"),
            "mean": mean,
            "quantiles": quantiles,
            "context": {"coarse_points": len(coarse), "fine_points": len(fine)},
            "network_scope": scope,
        }
