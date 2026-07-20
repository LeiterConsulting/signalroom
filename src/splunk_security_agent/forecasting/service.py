from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import socket
import statistics
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..cases import CaseStore
from ..config import ConfigStore
from ..progress import ProgressCallback, report_progress
from ..schemas import (
    TimeSeriesAlertCandidateCreate,
    TimeSeriesForecastRequest,
    TimeSeriesRuntimeUpdate,
    ValidationTaskCreate,
)
from ..splunk.guardrails import validate_read_only_spl
from ..validation import ValidationStore
from .provider import CiscoTimeSeriesProvider
from .store import TimeSeriesExperimentStore

RELATIVE_TIME = re.compile(r"^-(?P<count>\d{1,4})(?P<unit>[smhdw])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
MAX_WINDOW_SECONDS = 30 * 24 * 60 * 60


class TimeSeriesForecastService:
    """Bounded Splunk-series preparation, local forecasting, and promotion evidence."""

    def __init__(
        self,
        config: ConfigStore,
        splunk_factory: Callable[[], Any],
        runtime_root: Path | None = None,
        experiment_store: TimeSeriesExperimentStore | None = None,
        validations: ValidationStore | None = None,
        cases: CaseStore | None = None,
    ):
        self.config = config
        self.splunk_factory = splunk_factory
        self.runtime_root = (runtime_root or Path.cwd()).resolve()
        self.experiment_store = experiment_store
        self.validations = validations
        self.cases = cases

    def provider(self) -> CiscoTimeSeriesProvider:
        settings = self.config.load().time_series_runtime
        endpoint = os.getenv("SIGNALROOM_CISCO_TSM_ENDPOINT", "").strip() or settings.endpoint
        if Path("/.dockerenv").exists() and endpoint == "http://127.0.0.1:8080":
            endpoint = "http://cisco-tsm:8080"
        return CiscoTimeSeriesProvider(
            endpoint,
            self.config.secret("cisco_tsm_token"),
            settings.verify_ssl,
            settings.ca_bundle,
        )

    async def status(self) -> dict[str, Any]:
        settings = self.config.load().time_series_runtime
        health = await self.provider().health()
        return {
            "configured": bool(settings.endpoint),
            "verify_ssl": settings.verify_ssl,
            "ca_bundle_configured": bool(settings.ca_bundle),
            "runtime": "dedicated-python-3.11-service",
            "model": CiscoTimeSeriesProvider.MODEL_ID,
            "local_first": True,
            "automatic_routing": False,
            **health,
        }

    def experiments(self, limit: int = 30, tenant_scope_id: str = "") -> dict[str, Any]:
        if self.experiment_store is None:
            return {
                "runs": [],
                "series": [],
                "alert_candidates": [],
                "contract": {
                    "source_rows_persisted": False,
                    "runs_immutable": True,
                    "baseline_requires_exact_fingerprint": True,
                    "alert_candidate_executes_spl": False,
                    "alert_candidate_creates_validation_draft": True,
                },
            }
        return self.experiment_store.overview(limit, tenant_scope_id=tenant_scope_id)

    def experiment(self, run_id: str, tenant_scope_id: str = "") -> dict[str, Any] | None:
        return (
            self.experiment_store.get(run_id, tenant_scope_id) if self.experiment_store is not None else None
        )

    def accept_baseline(
        self,
        run_id: str,
        *,
        expected_fingerprint: str,
        actor: str,
        review_note: str,
        baseline_scope: str = "general",
    ) -> dict[str, Any]:
        if self.experiment_store is None:
            raise RuntimeError("The time-series experiment registry is unavailable")
        run = self.experiment_store.get(run_id)
        if run is None:
            raise KeyError(f"Unknown time-series run: {run_id}")
        slot = (
            self.experiment_store.seasonal_slot(run["result"])
            if baseline_scope == "matching-weekday"
            else "general"
        )
        return self.experiment_store.accept_baseline(
            run_id,
            expected_fingerprint=expected_fingerprint,
            actor=actor,
            review_note=review_note,
            slot=slot,
        )

    def create_alert_candidate(
        self,
        run_id: str,
        value: TimeSeriesAlertCandidateCreate,
        *,
        actor: str,
    ) -> dict[str, Any]:
        if self.experiment_store is None or self.validations is None:
            raise RuntimeError("The alert-candidate handoff is unavailable")
        run = self.experiment_store.get(run_id)
        if run is None:
            raise KeyError(f"Unknown time-series run: {run_id}")
        if run["run_fingerprint"] != value.expected_run_fingerprint:
            raise ValueError("The forecast run changed or the reviewed fingerprint does not match")
        if not run["baseline_slots"] or not run["promotion_ready"]:
            raise ValueError("Alert candidates require the exact current accepted baseline")
        existing = self.experiment_store.alert_candidate(run_id, value.direction)
        if existing is not None:
            validation = self.validations.get(existing["validation_task_id"])
            if validation is None:
                raise ValueError(
                    "This baseline already has a candidate whose validation draft is no longer available"
                )
            return {
                "candidate": existing,
                "validation": validation.model_dump(mode="json"),
                "reused": True,
                "contract": {
                    "splunk_executed": False,
                    "alert_created": False,
                    "validation_status": validation.status,
                    "separate_approval_required": True,
                },
            }
        result = run["result"]
        source = run.get("source") or result.get("source") or {}
        if value.case_id and (
            self.cases is None
            or self.cases.get(
                value.case_id,
                str(source.get("tenant_scope_id") or "workspace-primary"),
            )
            is None
        ):
            raise ValueError("Linked case not found")
        request = run["request"]
        forecast = result.get("forecast") or {}
        quantiles = forecast.get("quantiles") or {}
        if value.direction == "above":
            boundary = quantiles.get("p90") or []
            if not boundary:
                raise ValueError("The accepted run does not contain a p90 forecast boundary")
            threshold = max(float(item) for item in boundary)
            comparator = ">"
            threshold_source = "maximum forecast p90"
        else:
            boundary = quantiles.get("p10") or []
            if not boundary:
                raise ValueError("The accepted run does not contain a p10 forecast boundary")
            threshold = min(float(item) for item in boundary)
            comparator = "<"
            threshold_source = "minimum forecast p10"
        if not math.isfinite(threshold):
            raise ValueError("The accepted run does not contain a finite forecast boundary")
        value_field = str(request.get("value_field") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,159}", value_field):
            raise ValueError("The numeric field is not safe for an alert validation draft")
        proposed_spl = (
            f"{str(request.get('spl') or '').strip()} | where {value_field} {comparator} {threshold:.12g}"
        )
        validate_read_only_spl(proposed_spl)
        validation = self.validations.create(
            ValidationTaskCreate(
                title=value.title,
                rationale=(
                    f"{value.rationale.strip()}\n\n"
                    f"Forecast baseline {run_id} proposed a {value.direction}-range "
                    f"threshold from the {threshold_source}. This draft measures how "
                    "often the historical series crosses that fixed boundary. It is "
                    "not an alert and requires separate approval before one bounded "
                    "read-only execution."
                ),
                spl=proposed_spl,
                earliest_time=str(request.get("earliest_time") or "-24h"),
                latest_time=str(request.get("latest_time") or "now"),
                row_limit=min(500, int(request.get("row_limit") or 100)),
                evidence_refs=[],
                source_run_id=f"forecast:{run_id}",
                source_finding_ref=f"alert-{value.direction}",
                case_id=value.case_id,
                connection_alias=str(source.get("connection_alias") or "primary"),
                connection_fingerprint=str(source.get("connection_fingerprint") or ""),
                tenant_scope_id=str(source.get("tenant_scope_id") or "workspace-primary"),
            )
        )
        try:
            candidate = self.experiment_store.create_alert_candidate(
                run_id=run_id,
                run_fingerprint=value.expected_run_fingerprint,
                title=value.title.strip(),
                rationale=value.rationale.strip(),
                direction=value.direction,
                threshold=threshold,
                threshold_source=threshold_source,
                proposed_spl=proposed_spl,
                validation_task_id=validation.id,
                case_id=value.case_id,
                actor=actor,
            )
        except Exception:
            self.validations.delete(validation.id)
            raise
        return {
            "candidate": candidate,
            "validation": validation.model_dump(mode="json"),
            "reused": False,
            "contract": {
                "splunk_executed": False,
                "alert_created": False,
                "validation_status": "draft",
                "separate_approval_required": True,
            },
        }

    async def configure(self, value: TimeSeriesRuntimeUpdate) -> dict[str, Any]:
        provider = CiscoTimeSeriesProvider(
            value.endpoint,
            value.token or self.config.secret("cisco_tsm_token"),
            value.verify_ssl,
            value.ca_bundle,
        )
        if provider.network_scope(provider.endpoint) == "public-network":
            raise ValueError(
                "Public Cisco TSM endpoints are not accepted. Configure a local or private service."
            )
        settings = self.config.load()
        settings.time_series_runtime.endpoint = provider.endpoint
        settings.time_series_runtime.verify_ssl = value.verify_ssl
        settings.time_series_runtime.ca_bundle = value.ca_bundle if value.verify_ssl else None
        self.config.save(settings)
        self.config.update_secrets(cisco_tsm_token=value.token)
        return await self.status()

    async def start_bundled_runtime(self, progress: ProgressCallback | None = None) -> dict[str, Any]:
        """Explicitly build/start the isolated Docker sidecar and wait for readiness."""
        if Path("/.dockerenv").exists():
            raise RuntimeError(
                "One-click sidecar start is available from a process-based SignalRoom install. "
                "For container deployment, run docker compose --profile forecasting up -d --build."
            )
        docker = shutil.which("docker")
        compose = self.runtime_root / "compose.yaml"
        if not docker:
            raise RuntimeError("Docker was not found. Install Docker Desktop, then retry.")
        if not compose.is_file():
            raise RuntimeError(f"SignalRoom compose file was not found at {compose}")
        current = await self.status()
        if current.get("ok"):
            return current
        token = self.config.secret("cisco_tsm_token") or secrets.token_urlsafe(36)
        self.config.update_secrets(cisco_tsm_token=token)
        host_port = next(
            (port for port in range(8080, 8100) if self._port_available(port)),
            None,
        )
        if host_port is None:
            raise RuntimeError("No local port is available for Cisco TSM in the 8080-8099 range.")
        settings = self.config.load()
        settings.time_series_runtime.endpoint = f"http://127.0.0.1:{host_port}"
        settings.time_series_runtime.verify_ssl = True
        settings.time_series_runtime.ca_bundle = None
        self.config.save(settings)
        await report_progress(
            progress,
            "forecast-runtime:docker",
            "Starting the isolated Python 3.11 runtime",
            "Docker will build the pinned cisco-tsm service and reuse its persistent model cache.",
            progress=8,
            metrics={"host_port": host_port, "checkpoint_cache": "persistent"},
        )
        environment = dict(os.environ)
        environment["SIGNALROOM_CISCO_TSM_TOKEN"] = token
        environment["SIGNALROOM_CISCO_TSM_PORT"] = str(host_port)
        creationflags = 0x08000000 if os.name == "nt" else 0
        process = await asyncio.create_subprocess_exec(
            docker,
            "compose",
            "--progress",
            "plain",
            "--profile",
            "forecasting",
            "up",
            "--build",
            "-d",
            "cisco-tsm",
            cwd=self.runtime_root,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            creationflags=creationflags,
        )
        output: list[str] = []
        if process.stdout:
            async for line in process.stdout:
                detail = line.decode("utf-8", errors="replace").strip()
                if not detail:
                    continue
                output.append(detail[-500:])
                await report_progress(
                    progress,
                    "forecast-runtime:docker",
                    "Building the dedicated local runtime",
                    detail[-220:],
                    progress=min(62, 12 + len(output) // 3),
                )
        return_code = await process.wait()
        if return_code != 0:
            raise RuntimeError(
                "Docker could not start Cisco TSM: "
                + (" · ".join(output[-3:]) if output else f"exit code {return_code}")
            )
        await report_progress(
            progress,
            "forecast-runtime:model",
            "Runtime started; loading the immutable model checkpoint",
            "The first run downloads the pinned checkpoint into a persistent local Docker volume.",
            progress=68,
            metrics={"model": CiscoTimeSeriesProvider.MODEL_ID, "inference": "local"},
        )
        last: dict[str, Any] = {}
        for attempt in range(450):
            last = await self.status()
            if last.get("ok"):
                await report_progress(
                    progress,
                    "forecast-runtime:ready",
                    "Cisco TSM is ready for bounded local forecasts",
                    (
                        f"{last.get('inference_backend') or 'local backend'} · "
                        f"revision {str(last.get('model_revision') or '')[:12]}."
                    ),
                    progress=100,
                    status="complete",
                    metrics={"network_inference": False, "runtime_ready": True},
                )
                return last
            if last.get("model_load", {}).get("phase") == "failed":
                raise RuntimeError(str(last.get("load_error") or "Cisco TSM failed to load"))
            if attempt and attempt % 5 == 0:
                await report_progress(
                    progress,
                    "forecast-runtime:model",
                    "Loading the local model checkpoint",
                    str(
                        last.get("message")
                        or last.get("load_error")
                        or "Waiting for the model readiness probe."
                    ),
                    progress=min(96, 68 + attempt // 15),
                    metrics={"wait_seconds": attempt * 2},
                )
            await asyncio.sleep(2)
        raise RuntimeError(
            "Cisco TSM did not become ready within 15 minutes. Review docker compose logs cisco-tsm."
        )

    @staticmethod
    def _port_available(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind(("127.0.0.1", port))
            except OSError:
                return False
        return True

    @staticmethod
    def validate_contract(request: TimeSeriesForecastRequest) -> None:
        validate_read_only_spl(request.spl)
        timechart = re.search(
            r"\|\s*timechart\b[^|]*\bspan\s*=\s*(\d+)([smhd])\b",
            request.spl,
            flags=re.IGNORECASE,
        )
        if not timechart:
            raise ValueError("Forecast SPL must contain a timechart with an explicit span, such as span=5m")
        span_seconds = int(timechart.group(1)) * UNIT_SECONDS[timechart.group(2).lower()]
        if span_seconds != request.interval_seconds:
            raise ValueError(
                f"Selected interval is {request.interval_seconds} seconds, but SPL uses "
                f"span={timechart.group(1)}{timechart.group(2).lower()}"
            )
        match = RELATIVE_TIME.fullmatch(request.earliest_time.strip())
        if not match:
            raise ValueError("Earliest time must be bounded, such as -24h, -7d, or -30d")
        seconds = int(match.group("count")) * UNIT_SECONDS[match.group("unit")]
        if seconds > MAX_WINDOW_SECONDS:
            raise ValueError("Forecast source windows cannot exceed 30 days")
        if request.latest_time.strip() != "now":
            raise ValueError("Forecast source queries currently require latest_time=now")
        if request.backtest_points + 10 >= request.row_limit:
            raise ValueError("Row limit must leave at least ten context points before the backtest")

    @staticmethod
    def _rows(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            status_code = value.get("status_code")
            try:
                failed = status_code is not None and int(status_code) >= 400
            except (TypeError, ValueError):
                failed = False
            if failed or value.get("error"):
                detail = value.get("content") or value.get("error") or "query rejected"
                raise ValueError(f"Splunk MCP query failed: {detail}")
            for key in ("results", "items", "data"):
                if isinstance(value.get(key), list):
                    return value[key]
        return []

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=UTC)
        raw = str(value or "").strip()
        if not raw:
            raise ValueError("empty timestamp")
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except ValueError:
            pass
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    @classmethod
    def prepare_series(cls, rows: list[Any], request: TimeSeriesForecastRequest) -> dict[str, Any]:
        observed: dict[int, float | None] = {}
        parsed_rows = 0
        invalid_values = 0
        origin: datetime | None = None
        raw_points: list[tuple[datetime, float | None]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                timestamp = cls._timestamp(row.get(request.timestamp_field))
            except (TypeError, ValueError, OverflowError):
                continue
            raw = row.get(request.value_field)
            try:
                numeric = float(raw)
                if not math.isfinite(numeric):
                    raise ValueError
            except (TypeError, ValueError):
                numeric = None
                invalid_values += 1
            raw_points.append((timestamp, numeric))
            parsed_rows += 1
        if not raw_points:
            raise ValueError(
                f"Splunk returned no usable {request.timestamp_field}/{request.value_field} rows"
            )
        raw_points.sort(key=lambda item: item[0])
        dropped_partial_last_bucket = 0
        if len(raw_points) > 1 and raw_points[-1][0] + timedelta(
            seconds=request.interval_seconds
        ) > datetime.now(UTC):
            raw_points.pop()
            dropped_partial_last_bucket = 1
        origin = raw_points[0][0]
        tolerance = max(2.0, request.interval_seconds * 0.1)
        for timestamp, numeric in raw_points:
            offset = (timestamp - origin).total_seconds() / request.interval_seconds
            slot = round(offset)
            if abs(offset - slot) * request.interval_seconds > tolerance:
                raise ValueError(
                    "Splunk timestamps are not regular at the selected interval; edit timechart span"
                )
            if slot in observed:
                raise ValueError(
                    "Splunk returned duplicate time buckets; aggregate to one numeric value per bucket"
                )
            observed[slot] = numeric
        last_slot = max(observed)
        expected_points = last_slot + 1
        if expected_points > 30_720:
            raise ValueError("Prepared series exceeds Cisco TSM's 30,720-point context limit")
        first_valid = next((slot for slot in range(expected_points) if observed.get(slot) is not None), None)
        if first_valid is None:
            raise ValueError(f"Field {request.value_field} did not contain finite numeric values")
        values: list[float] = []
        timestamps: list[str] = []
        imputed = 0
        previous = float(observed[first_valid])
        for slot in range(first_valid, expected_points):
            numeric = observed.get(slot)
            if numeric is None:
                numeric = previous
                imputed += 1
            previous = float(numeric)
            values.append(previous)
            timestamps.append((origin + timedelta(seconds=slot * request.interval_seconds)).isoformat())
        if len(values) < request.backtest_points + 10:
            raise ValueError(
                "The prepared series is too short for the requested backtest; widen history or reduce holdout"
            )
        ratio = imputed / len(values)
        return {
            "values": values,
            "timestamps": timestamps,
            "source_rows": len(rows),
            "row_limit_reached": len(rows) >= request.row_limit,
            "parsed_rows": parsed_rows,
            "expected_points": len(values),
            "imputed_points": imputed,
            "imputation_ratio": ratio,
            "dropped_leading_points": first_valid,
            "dropped_partial_last_bucket": dropped_partial_last_bucket,
            "invalid_values": invalid_values,
            "start": timestamps[0],
            "end": timestamps[-1],
            "minimum": min(values),
            "maximum": max(values),
            "mean": statistics.fmean(values),
        }

    @staticmethod
    def _error_metrics(predicted: list[float], actual: list[float], last_value: float) -> dict[str, Any]:
        model_mae = statistics.fmean(
            abs(prediction - observation) for prediction, observation in zip(predicted, actual, strict=True)
        )
        naive_mae = statistics.fmean(abs(last_value - observation) for observation in actual)
        if naive_mae == 0:
            mase = 0.0 if model_mae == 0 else None
        else:
            mase = model_mae / naive_mae
        return {
            "mae": model_mae,
            "naive_last_value_mae": naive_mae,
            "mase_vs_last_value": mase,
            "beats_naive": mase is not None and mase < 1,
        }

    async def run(
        self,
        request: TimeSeriesForecastRequest,
        progress: ProgressCallback | None = None,
        *,
        actor: str = "local-operator",
        seasonal_comparison: bool = True,
        splunk_client: Any | None = None,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.validate_contract(request)
        run_id = f"forecast-{uuid4().hex[:16]}"
        provider = self.provider()
        await report_progress(
            progress,
            "forecast:runtime",
            "Checking the dedicated local forecast runtime",
            "No Splunk query is spent until Cisco TSM reports ready.",
            progress=8,
        )
        runtime = await provider.health()
        if not runtime.get("ok"):
            runtime_detail = (
                runtime.get("message") or runtime.get("load_error") or runtime.get("error") or "not ready"
            )
            raise RuntimeError(f"Cisco TSM is not ready at {provider.endpoint}: {runtime_detail}")
        await report_progress(
            progress,
            "forecast:guardrail",
            "Read-only forecast contract confirmed",
            (
                f"{request.earliest_time} to now · {request.row_limit} rows · "
                f"{request.interval_seconds}s buckets."
            ),
            progress=16,
            status="complete",
            metrics={"horizon": request.horizon, "backtest_points": request.backtest_points},
        )
        arguments = {
            "query": request.spl,
            "earliest_time": request.earliest_time,
            "latest_time": request.latest_time,
            "row_limit": request.row_limit,
        }
        splunk = splunk_client if splunk_client is not None else self.splunk_factory()
        await report_progress(
            progress,
            "forecast:splunk",
            "Extracting one regular numeric series through Splunk MCP",
            "SignalRoom is running the exact read-only timechart shown in the workbench.",
            progress=28,
            metrics={"tool": "run_query", "row_limit": request.row_limit},
        )
        if hasattr(splunk, "scope"):
            async with splunk.scope(f"forecast:{run_id}", progress):
                raw = await splunk.call("run_query", arguments)
        else:
            raw = await splunk.call("run_query", arguments)
        rows = self._rows(raw)
        prepared = self.prepare_series(rows, request)
        await report_progress(
            progress,
            "forecast:prepare",
            "Series resampled and quality-scored",
            (f"{prepared['expected_points']} points · {prepared['imputed_points']} last-value imputations."),
            progress=42,
            status="complete",
            metrics={
                "points": prepared["expected_points"],
                "imputation_percent": round(prepared["imputation_ratio"] * 100, 1),
            },
        )
        query_fingerprint = hashlib.sha256(json.dumps(arguments, sort_keys=True).encode("utf-8")).hexdigest()
        series_fingerprint = hashlib.sha256(
            json.dumps(prepared["values"], separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        base = {
            "run_id": run_id,
            "title": request.title,
            "status": "complete",
            "executed_at": datetime.now(UTC).isoformat(),
            "source": {
                "spl": request.spl,
                "earliest_time": request.earliest_time,
                "latest_time": request.latest_time,
                "row_limit": request.row_limit,
                "timestamp_field": request.timestamp_field,
                "value_field": request.value_field,
                "interval_seconds": request.interval_seconds,
                "query_fingerprint": query_fingerprint,
                "connection_alias": str((binding or {}).get("alias") or "primary"),
                "connection_fingerprint": str((binding or {}).get("fingerprint") or ""),
                "tenant_scope_id": str((binding or {}).get("tenant_scope_id") or "workspace-primary"),
            },
            "series": {key: value for key, value in prepared.items() if key not in {"values", "timestamps"}},
            "series_sha256": series_fingerprint,
            "runtime": {
                "endpoint": provider.endpoint,
                "network_scope": runtime.get("network_scope"),
                "service": runtime.get("service"),
                "model": runtime.get("model_repo") or CiscoTimeSeriesProvider.MODEL_ID,
                "source_revision": runtime.get("model_revision") or "",
                "backend": runtime.get("inference_backend") or runtime.get("torch_backend"),
                "network_inference": False,
            },
            "contract": {
                "automatic_alerting": False,
                "automatic_threshold_change": False,
                "source_persisted": False,
                "analyst_review_required": True,
            },
        }
        if prepared["imputation_ratio"] > 0.30:
            return self._retain(
                request,
                {
                    **base,
                    "status": "blocked-data-quality",
                    "forecast": None,
                    "backtest": None,
                    "promotion_gate": {
                        "ready": False,
                        "decision": "blocked",
                        "reasons": [
                            "More than 30% of the prepared series required imputation; "
                            "the publisher warns forecast quality deteriorates beyond this point."
                        ],
                    },
                },
                actor,
                seasonal_comparison,
            )
        holdout = request.backtest_points
        training = prepared["values"][:-holdout]
        actual = prepared["values"][-holdout:]
        await report_progress(
            progress,
            "forecast:backtest",
            "Running holdout backtest",
            f"Forecasting the final {holdout} known points without showing them to the model.",
            progress=55,
            metrics={"training_points": len(training), "holdout_points": holdout},
        )
        backtest_forecast = await provider.forecast(training, holdout, request_id=f"{run_id}-backtest")
        backtest = self._error_metrics(backtest_forecast["mean"], actual, training[-1])
        backtest.update(
            {
                "points": holdout,
                "actual": actual,
                "predicted": backtest_forecast["mean"],
            }
        )
        await report_progress(
            progress,
            "forecast:forecast",
            "Backtest complete; forecasting the unseen horizon",
            (
                "Cisco TSM beat the last-value baseline."
                if backtest["beats_naive"]
                else "Cisco TSM did not beat the last-value baseline; promotion will be held."
            ),
            progress=76,
            status="complete",
            metrics={
                "mase": (
                    round(backtest["mase_vs_last_value"], 3)
                    if backtest["mase_vs_last_value"] is not None
                    else "undefined"
                ),
                "beats_naive": backtest["beats_naive"],
            },
        )
        forecast = await provider.forecast(
            prepared["values"], request.horizon, request_id=f"{run_id}-forecast"
        )
        final_time = self._timestamp(prepared["timestamps"][-1])
        forecast_times = [
            (final_time + timedelta(seconds=request.interval_seconds * (index + 1))).isoformat()
            for index in range(request.horizon)
        ]
        revision = str(runtime.get("model_revision") or "")
        runtime_model = str(runtime.get("model_repo") or "")
        mase = backtest["mase_vs_last_value"]
        reasons: list[str] = []
        if runtime_model != CiscoTimeSeriesProvider.MODEL_ID:
            reasons.append("The runtime did not attest the expected Cisco Time Series Model repository.")
        if not re.fullmatch(r"[0-9a-f]{40,64}", revision, flags=re.IGNORECASE):
            reasons.append("The runtime did not attest a valid immutable model revision.")
        if mase is None or mase >= 1:
            reasons.append("The holdout forecast did not beat the naive last-value baseline.")
        if prepared["imputation_ratio"] > 0.10:
            reasons.append("More than 10% of the source series required last-value imputation.")
        if prepared["row_limit_reached"]:
            reasons.append("Splunk returned the configured row limit, so the source series may be truncated.")
        ready = not reasons
        await report_progress(
            progress,
            "forecast:gate",
            "Forecast promotion evidence assembled",
            (
                "Eligible for analyst review; no alert or threshold has been changed."
                if ready
                else "Forecast is visible, but promotion is held for the documented reasons."
            ),
            progress=96,
            status="complete",
            metrics={"promotion_ready": ready, "network_inference_calls": 0},
        )
        return self._retain(
            request,
            {
                **base,
                "forecast": {
                    "horizon": request.horizon,
                    "timestamps": forecast_times,
                    "mean": forecast["mean"],
                    "quantiles": forecast["quantiles"],
                    "context": forecast["context"],
                },
                "backtest": backtest,
                "promotion_gate": {
                    "ready": ready,
                    "decision": ("eligible-for-analyst-review" if ready else "hold"),
                    "reasons": reasons
                    or [
                        "Data quality passed, the model beat the naive baseline, and the "
                        "runtime attested an immutable revision."
                    ],
                },
            },
            actor,
            seasonal_comparison,
        )

    def _retain(
        self,
        request: TimeSeriesForecastRequest,
        result: dict[str, Any],
        actor: str,
        seasonal_comparison: bool = True,
    ) -> dict[str, Any]:
        if self.experiment_store is None:
            return result
        result.setdefault("contract", {})["experiment_persisted"] = True
        recorded = self.experiment_store.record(
            request.model_dump(mode="json"),
            result,
            actor=actor,
            seasonal_comparison=seasonal_comparison,
        )
        result["experiment"] = {
            "series_key": recorded["series_key"],
            "run_fingerprint": recorded["run_fingerprint"],
            "comparison": recorded["comparison"],
            "is_baseline": recorded["is_baseline"],
            "baseline_slots": recorded["baseline_slots"],
            "created_by": recorded["created_by"],
            "created_at": recorded["created_at"],
        }
        return result
