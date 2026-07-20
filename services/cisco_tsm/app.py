from __future__ import annotations

import asyncio
import importlib.metadata
import math
import os
import secrets
import threading
from contextlib import asynccontextmanager
from typing import Any

import torch
from cisco_tsm import CiscoTsmMR, TimesFmCheckpoint, TimesFmHparams
from fastapi import FastAPI, Header, HTTPException, Query, Request
from huggingface_hub import HfApi, snapshot_download
from pydantic import BaseModel, Field, field_validator

MODEL_REPO = os.getenv(
    "CTS_MODEL_REPO", "cisco-ai/cisco-time-series-model-1.0"
).strip()
EXPECTED_REVISION = os.getenv("CTS_MODEL_REVISION", "").strip()
AUTH_TOKEN = os.getenv("CTS_AUTH_TOKEN", "").strip()
BACKEND_MODE = os.getenv("CTS_TORCH_BACKEND", "auto").strip().lower()
QUANTILES = [0.01, 0.05, 0.1, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9, 0.95, 0.99]
QUANTILE_KEYS = {"p10": "0.1", "p50": "0.5", "p90": "0.9"}


class SeriesPayload(BaseModel):
    coarse_ctx: list[float] = Field(min_length=1, max_length=512)
    fine_ctx: list[float] = Field(min_length=10, max_length=512)

    @field_validator("coarse_ctx", "fine_ctx")
    @classmethod
    def finite_values(cls, values: list[float]) -> list[float]:
        if any(not math.isfinite(value) for value in values):
            raise ValueError("series values must be finite")
        return values


class ForecastMetadata(BaseModel):
    quantiles: list[str] = Field(default_factory=lambda: ["mean", "p10", "p50", "p90"])


class ForecastRequest(BaseModel):
    payload: list[SeriesPayload] = Field(min_length=1, max_length=8)
    model: str = "CDTSM"
    metadata: ForecastMetadata = Field(default_factory=ForecastMetadata)


class RuntimeState:
    def __init__(self) -> None:
        self.model: CiscoTsmMR | None = None
        self.phase = "not_started"
        self.error = ""
        self.revision = ""
        self.backend = ""
        self.lock = threading.Lock()

    def load(self) -> None:
        self.phase = "loading"
        try:
            if not AUTH_TOKEN:
                raise RuntimeError("CTS_AUTH_TOKEN is required")
            if BACKEND_MODE not in {"auto", "cpu", "gpu"}:
                raise RuntimeError("CTS_TORCH_BACKEND must be auto, cpu, or gpu")
            if BACKEND_MODE == "gpu" and not torch.cuda.is_available():
                raise RuntimeError("GPU was required but CUDA is not available to PyTorch")
            self.backend = (
                "gpu"
                if BACKEND_MODE == "gpu"
                or (BACKEND_MODE == "auto" and torch.cuda.is_available())
                else "cpu"
            )
            info = HfApi().model_info(MODEL_REPO, revision=EXPECTED_REVISION or None)
            self.revision = str(info.sha)
            snapshot = snapshot_download(
                repo_id=MODEL_REPO,
                revision=self.revision,
                allow_patterns=["torch_model.pt", "config.json", "README.md"],
            )
            checkpoint_path = os.path.join(snapshot, "torch_model.pt")
            hparams = TimesFmHparams(
                num_layers=25,
                use_positional_embedding=False,
                backend=self.backend,
                quantiles=QUANTILES,
            )
            self.model = CiscoTsmMR(
                hparams=hparams,
                checkpoint=TimesFmCheckpoint(path=checkpoint_path),
            )
            self.phase = "ready"
        except Exception as exc:
            self.model = None
            self.phase = "failed"
            self.error = str(exc)


state = RuntimeState()


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(asyncio.to_thread(state.load))
    yield
    if not task.done():
        task.cancel()


app = FastAPI(title="SignalRoom Cisco TSM sidecar", version="1.0.0", lifespan=lifespan)


def authorize(value: str | None) -> None:
    supplied = value.removeprefix("Bearer ").strip() if value else ""
    if not AUTH_TOKEN or not secrets.compare_digest(supplied, AUTH_TOKEN):
        raise HTTPException(status_code=401, detail="Bearer token rejected")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "signalroom-cisco-tsm"}


@app.get("/ready")
async def ready() -> dict[str, Any]:
    body = {
        "status": "ready" if state.phase == "ready" else "not_ready",
        "service": "signalroom-cisco-tsm",
        "model_repo": MODEL_REPO,
        "model_revision": state.revision,
        "runtime_version": importlib.metadata.version("cisco-tsm"),
        "inference_backend": state.backend or None,
        "network_inference": False,
        "model_load": {"phase": state.phase},
    }
    if state.error:
        body["load_error"] = state.error
    if state.phase != "ready":
        raise HTTPException(status_code=503, detail=body)
    return body


def _quantile(raw: dict[Any, Any], key: str) -> list[float]:
    target = QUANTILE_KEYS[key]
    candidates: tuple[Any, ...] = (target, float(target))
    for candidate in candidates:
        if candidate in raw:
            return [float(value) for value in raw[candidate]]
    raise RuntimeError(f"Model response did not include {key}")


def _finite(values: Any, label: str) -> list[float]:
    normalized = [float(value) for value in values]
    if any(not math.isfinite(value) for value in normalized):
        raise RuntimeError(f"Model response included a non-finite {label} value")
    return normalized


@app.post("/cdtsm/v1/ai/infer")
async def infer(
    body: ForecastRequest,
    request: Request,
    horizon: int = Query(default=128, ge=1, le=128),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    authorize(authorization)
    if body.model != "CDTSM":
        raise HTTPException(status_code=400, detail="Only model CDTSM is supported")
    if state.model is None or state.phase != "ready":
        raise HTTPException(status_code=503, detail="Cisco TSM is still loading")
    pairs = [(item.coarse_ctx, item.fine_ctx) for item in body.payload]

    def execute() -> list[dict[str, Any]]:
        with state.lock:
            assert state.model is not None
            return state.model.forecast(
                pairs,
                horizon_len=horizon,
                batch_size=min(8, len(pairs)),
                restrict_quantiles=True,
            )

    try:
        raw = await asyncio.to_thread(execute)
        predictions = [
            {
                "mean": _finite(item["mean"], "mean"),
                "quantiles": {
                    key: _finite(
                        _quantile(item.get("quantiles") or {}, key), key
                    )
                    for key in ("p10", "p50", "p90")
                    if key in body.metadata.quantiles
                },
            }
            for item in raw
        ]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Forecast failed: {exc}") from exc
    return {
        "request_id": request.headers.get("request_id", ""),
        "model": "CDTSM",
        "horizon": horizon,
        "predictions": predictions,
        "runtime": {
            "model_repo": MODEL_REPO,
            "model_revision": state.revision,
            "network_inference": False,
        },
    }
