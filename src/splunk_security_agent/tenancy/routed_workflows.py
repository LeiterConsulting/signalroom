from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..assurance import AssuranceStore
from ..delivery import DeliveryStore
from ..detections import DetectionStore
from ..forecasting import TimeSeriesExperimentStore
from ..validation import ValidationStore
from .data_plane import TenantDataPlaneRegistry


def _tenant(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("tenant_scope_id") or "")
    return str(getattr(value, "tenant_scope_id", "") or "")


class _RoutedWorkflowStore:
    def __init__(
        self,
        registry: TenantDataPlaneRegistry,
        component: str,
        shared_filename: str,
        factory: Callable[[Any], Any],
    ):
        self.registry = registry
        self.component = component
        self.path = registry.data_root / shared_filename
        self._factory = factory
        self._stores: dict[str, Any] = {}

    def _store(self, tenant_scope_id: str) -> Any:
        path = self.registry.path_for(self.component, tenant_scope_id)
        return self._stores.setdefault(str(path), self._factory(path))

    def _shared(self) -> Any:
        return self._stores.setdefault(str(self.path), self._factory(self.path))

    def _isolated(self) -> set[str]:
        return {
            tenant
            for tenant in self.registry.isolated_tenants()
            if self.registry.component_isolated(self.component, tenant)
        }

    def _active(self) -> list[tuple[str, Any]]:
        return [(tenant, self._store(tenant)) for tenant in sorted(self._isolated())]

    def _note(self, tenant_scope_id: str) -> None:
        if self.registry.component_isolated(self.component, tenant_scope_id):
            self.registry.note_write(tenant_scope_id)

    def _find(self, record_id: str, getter: str = "get") -> tuple[Any, Any, str] | None:
        for tenant, store in self._active():
            value = getattr(store, getter)(record_id)
            if value is not None:
                return store, value, tenant
        value = getattr(self._shared(), getter)(record_id)
        if value is not None and _tenant(value) not in self._isolated():
            return self._shared(), value, _tenant(value)
        return None

    def _mutate(self, method: str, record_id: str, *args: Any, **kwargs: Any) -> Any:
        with self.registry.operation_lock:
            found = self._find(record_id)
            if not found:
                return None
            store, _, tenant = found
            result = getattr(store, method)(record_id, *args, **kwargs)
            if result is not None and result is not False:
                self._note(tenant)
            return result


class RoutedValidationStore(_RoutedWorkflowStore):
    def __init__(self, registry: TenantDataPlaneRegistry):
        super().__init__(registry, "validations", "validations.db", ValidationStore)

    def connect(self):
        return self._shared().connect()

    def bind_unbound(self, binding: dict[str, Any]) -> int:
        return self._shared().bind_unbound(binding)

    def create(self, value: Any) -> Any:
        tenant = _tenant(value) or "workspace-primary"
        with self.registry.operation_lock:
            result = self._store(tenant).create(value)
            self._note(tenant)
            return result

    def list(self, limit: int = 100, tenant_scope_id: str | None = None) -> list[Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list(limit, tenant_scope_id)
        isolated = self._isolated()
        values = [item for item in self._shared().list(limit) if _tenant(item) not in isolated]
        for tenant, store in self._active():
            values.extend(store.list(limit, tenant))
        return sorted(values, key=lambda item: item.updated_at, reverse=True)[:limit]

    def get(self, task_id: str, tenant_scope_id: str | None = None) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).get(task_id, tenant_scope_id)
        found = self._find(task_id)
        return found[1] if found else None

    def update(self, task_id: str, value: Any) -> Any:
        return self._mutate("update", task_id, value)

    def approve(self, task_id: str) -> Any:
        return self._mutate("approve", task_id)

    def mark_running(self, task_id: str) -> Any:
        return self._mutate("mark_running", task_id)

    def complete(self, task_id: str, result_count: int, result_preview: list[Any], artifact_id: str) -> Any:
        return self._mutate("complete", task_id, result_count, result_preview, artifact_id)

    def fail(self, task_id: str, error: str) -> Any:
        return self._mutate("fail", task_id, error)

    def requeue_interrupted(self, task_id: str, reason: str) -> Any:
        return self._mutate("requeue_interrupted", task_id, reason)

    def delete(self, task_id: str) -> bool:
        return bool(self._mutate("delete", task_id))

    def expire_due(self) -> int:
        total = self._shared().expire_due(self._isolated())
        for tenant, store in self._active():
            changed = store.expire_due()
            total += changed
            if changed:
                self._note(tenant)
        return total

    def recover_interrupted(self) -> int:
        total = self._shared().recover_interrupted(self._isolated())
        for tenant, store in self._active():
            changed = store.recover_interrupted()
            total += changed
            if changed:
                self._note(tenant)
        return total

    def find_reusable(self, query_fingerprint: str, tenant_scope_id: str | None = None) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).find_reusable(query_fingerprint, tenant_scope_id)
        values = [
            item
            for tenant, store in self._active()
            if (item := store.find_reusable(query_fingerprint, tenant)) is not None
        ]
        shared = self._shared().find_reusable(query_fingerprint)
        if shared and _tenant(shared) not in self._isolated():
            values.append(shared)
        return max(values, key=lambda item: item.updated_at) if values else None

    def find_latest_complete(
        self,
        query_fingerprint: str,
        exclude_task_id: str = "",
        tenant_scope_id: str | None = None,
    ) -> Any:
        if tenant_scope_id:
            return self._store(tenant_scope_id).find_latest_complete(
                query_fingerprint, exclude_task_id, tenant_scope_id
            )
        values = [
            item
            for tenant, store in self._active()
            if (item := store.find_latest_complete(query_fingerprint, exclude_task_id, tenant)) is not None
        ]
        shared = self._shared().find_latest_complete(query_fingerprint, exclude_task_id)
        if shared and _tenant(shared) not in self._isolated():
            values.append(shared)
        return max(values, key=lambda item: item.completed_at or item.updated_at) if values else None

    @staticmethod
    def fingerprint(spl: str, earliest_time: str, latest_time: str, row_limit: int) -> str:
        return ValidationStore.fingerprint(spl, earliest_time, latest_time, row_limit)


class RoutedDetectionStore(_RoutedWorkflowStore):
    def __init__(self, registry: TenantDataPlaneRegistry):
        super().__init__(registry, "detections", "detections.db", DetectionStore)

    def connect(self):
        return self._shared().connect()

    def bind_unbound(self, binding: dict[str, Any]) -> int:
        return self._shared().bind_unbound(binding)

    def create(
        self,
        detection_id: str,
        source_validation_id: str,
        case_id: str | None,
        content: dict[str, Any],
        **binding: Any,
    ) -> dict[str, Any]:
        tenant = str(binding.get("tenant_scope_id") or "workspace-primary")
        with self.registry.operation_lock:
            result = self._store(tenant).create(
                detection_id, source_validation_id, case_id, content, **binding
            )
            self._note(tenant)
            return result

    def list(self, limit: int = 200, tenant_scope_id: str | None = None) -> list[dict[str, Any]]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list(limit, tenant_scope_id)
        isolated = self._isolated()
        values = [item for item in self._shared().list(limit) if _tenant(item) not in isolated]
        for tenant, store in self._active():
            values.extend(store.list(limit, tenant))
        return sorted(values, key=lambda item: item["updated_at"], reverse=True)[:limit]

    def get(self, detection_id: str, tenant_scope_id: str | None = None) -> dict[str, Any] | None:
        if tenant_scope_id:
            return self._store(tenant_scope_id).get(detection_id, tenant_scope_id)
        found = self._find(detection_id)
        return found[1] if found else None

    def find_by_source(self, validation_task_id: str) -> dict[str, Any] | None:
        for _, store in self._active():
            value = store.find_by_source(validation_task_id)
            if value:
                return value
        value = self._shared().find_by_source(validation_task_id)
        return value if value and _tenant(value) not in self._isolated() else None

    def find_by_export(self, filename: str) -> dict[str, Any] | None:
        for _, store in self._active():
            if value := store.find_by_export(filename):
                return value
        value = self._shared().find_by_export(filename)
        return value if value and _tenant(value) not in self._isolated() else None

    def add_version(self, detection_id: str, content: dict[str, Any]) -> Any:
        return self._mutate("add_version", detection_id, content)

    def submit(self, detection_id: str) -> Any:
        return self._mutate("submit", detection_id)

    def review(self, detection_id: str, **kwargs: Any) -> Any:
        return self._mutate("review", detection_id, **kwargs)

    def retire(self, detection_id: str) -> Any:
        return self._mutate("retire", detection_id)

    def delete(self, detection_id: str) -> bool:
        return bool(self._mutate("delete", detection_id))

    def record_export(self, detection_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._mutate("record_export", detection_id, *args, **kwargs)

    def record_gate(self, detection_id: str, **kwargs: Any) -> Any:
        return self._mutate("record_gate", detection_id, **kwargs)

    def latest_gate(self, detection_id: str, content_sha256: str = "") -> Any:
        found = self._find(detection_id)
        return found[0].latest_gate(detection_id, content_sha256) if found else None

    def accepted_gate(self, detection_id: str) -> Any:
        found = self._find(detection_id)
        return found[0].accepted_gate(detection_id) if found else None

    @staticmethod
    def canonical(content: dict[str, Any]) -> str:
        return DetectionStore.canonical(content)

    @staticmethod
    def fingerprint(content: dict[str, Any]) -> str:
        return DetectionStore.fingerprint(content)


class RoutedTimeSeriesExperimentStore(_RoutedWorkflowStore):
    def __init__(self, registry: TenantDataPlaneRegistry):
        super().__init__(
            registry,
            "forecast-experiments",
            "time_series_experiments.db",
            TimeSeriesExperimentStore,
        )

    def connect(self):
        return self._shared().connect()

    def bind_unbound(self, binding: dict[str, Any]) -> int:
        return self._shared().bind_unbound(binding)

    def record(self, request: dict[str, Any], result: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        tenant = str((result.get("source") or {}).get("tenant_scope_id") or "workspace-primary")
        with self.registry.operation_lock:
            recorded = self._store(tenant).record(request, result, **kwargs)
            self._note(tenant)
            return recorded

    def get(self, run_id: str, tenant_scope_id: str = "") -> dict[str, Any] | None:
        if tenant_scope_id:
            return self._store(tenant_scope_id).get(run_id, tenant_scope_id)
        found = self._find(run_id)
        return found[1] if found else None

    def list(
        self, limit: int = 30, *, series_key: str = "", tenant_scope_id: str = ""
    ) -> list[dict[str, Any]]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list(
                limit, series_key=series_key, tenant_scope_id=tenant_scope_id
            )
        isolated = self._isolated()
        values = [
            item
            for item in self._shared().list(limit, series_key=series_key)
            if _tenant(item) not in isolated
        ]
        for tenant, store in self._active():
            values.extend(store.list(limit, series_key=series_key, tenant_scope_id=tenant))
        return sorted(values, key=lambda item: item["created_at"], reverse=True)[:limit]

    def _series_store(self, series_key: str) -> Any | None:
        for _, store in self._active():
            if store.list(1, series_key=series_key):
                return store
        return self._shared() if self._shared().list(1, series_key=series_key) else None

    def baseline(self, series_key: str) -> Any:
        store = self._series_store(series_key)
        return store.baseline(series_key) if store else None

    def baseline_for_slot(self, series_key: str, slot: str) -> Any:
        store = self._series_store(series_key)
        return store.baseline_for_slot(series_key, slot) if store else None

    def baselines(self, series_key: str, *, slots: list[str] | None = None) -> list[dict[str, Any]]:
        store = self._series_store(series_key)
        return store.baselines(series_key, slots=slots) if store else []

    def accept_baseline(self, run_id: str, **kwargs: Any) -> dict[str, Any]:
        return self._mutate("accept_baseline", run_id, **kwargs)

    def create_alert_candidate(self, *, run_id: str, **kwargs: Any) -> dict[str, Any]:
        with self.registry.operation_lock:
            found = self._find(run_id)
            if not found:
                raise KeyError(f"Unknown time-series run: {run_id}")
            store, _, tenant = found
            result = store.create_alert_candidate(run_id=run_id, **kwargs)
            self._note(tenant)
            return result

    def alert_candidate(self, run_id: str, direction: str) -> Any:
        found = self._find(run_id)
        return found[0].alert_candidate(run_id, direction) if found else None

    def list_alert_candidates(self, limit: int = 30, *, tenant_scope_id: str = "") -> list[dict[str, Any]]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).list_alert_candidates(limit, tenant_scope_id=tenant_scope_id)
        values = self._shared().list_alert_candidates(limit)
        isolated = self._isolated()
        values = [
            item
            for item in values
            if not self._shared().get(item["run_id"])
            or _tenant(self._shared().get(item["run_id"])) not in isolated
        ]
        for tenant, store in self._active():
            values.extend(store.list_alert_candidates(limit, tenant_scope_id=tenant))
        return sorted(values, key=lambda item: item["created_at"], reverse=True)[:limit]

    def overview(self, limit: int = 30, *, tenant_scope_id: str = "") -> dict[str, Any]:
        if tenant_scope_id:
            return self._store(tenant_scope_id).overview(limit, tenant_scope_id=tenant_scope_id)
        runs = self.list(limit)
        series: dict[str, dict[str, Any]] = {}
        for run in runs:
            item = series.setdefault(
                run["series_key"],
                {
                    "series_key": run["series_key"],
                    "title": run["title"],
                    "runs": 0,
                    "baseline_run_id": "",
                    "baseline_slots": {},
                    "latest_run_id": run["id"],
                    "latest_at": run["created_at"],
                },
            )
            item["runs"] += 1
            if run["is_baseline"]:
                item["baseline_run_id"] = run["id"]
            for slot in run["baseline_slots"]:
                item["baseline_slots"][slot] = run["id"]
        return {
            "runs": runs,
            "series": list(series.values()),
            "alert_candidates": self.list_alert_candidates(limit),
        }

    series_key = staticmethod(TimeSeriesExperimentStore.series_key)
    run_fingerprint = staticmethod(TimeSeriesExperimentStore.run_fingerprint)
    seasonal_slot = staticmethod(TimeSeriesExperimentStore.seasonal_slot)
    slot_label = staticmethod(TimeSeriesExperimentStore.slot_label)


class RoutedAssuranceStore(_RoutedWorkflowStore):
    """Keep assurance scheduling global while routing tenant-owned response records."""

    def __init__(self, registry: TenantDataPlaneRegistry):
        super().__init__(registry, "assurance-responses", "assurance.db", AssuranceStore)

    def connect(self):
        return self._shared().connect()

    def bind_unbound(self, binding: dict[str, Any]) -> dict[str, int]:
        return self._shared().bind_unbound(binding)

    # Singleton policy, run queue, events, and notifications remain global control-plane state.
    def policy(self):
        return self._shared().policy()

    def update_policy(self, value: Any):
        return self._shared().update_policy(value)

    def rebind_policy(self, *args: Any, **kwargs: Any):
        return self._shared().rebind_policy(*args, **kwargs)

    def advance_schedule(self, **kwargs: Any):
        return self._shared().advance_schedule(**kwargs)

    def create_run(self, *args: Any, **kwargs: Any):
        return self._shared().create_run(*args, **kwargs)

    def get_run(self, run_id: str):
        return self._shared().get_run(run_id)

    def list_runs(self, limit: int = 20):
        return self._shared().list_runs(limit)

    def active_run(self):
        return self._shared().active_run()

    def next_queued(self):
        return self._shared().next_queued()

    def mark_running(self, run_id: str):
        return self._shared().mark_running(run_id)

    def update_progress(self, *args: Any, **kwargs: Any):
        return self._shared().update_progress(*args, **kwargs)

    def complete_run(self, *args: Any, **kwargs: Any):
        return self._shared().complete_run(*args, **kwargs)

    def fail_run(self, *args: Any, **kwargs: Any):
        return self._shared().fail_run(*args, **kwargs)

    def requeue_for_restart(self, run_id: str):
        return self._shared().requeue_for_restart(run_id)

    def request_cancel(self, run_id: str):
        return self._shared().request_cancel(run_id)

    def recover_interrupted(self):
        return self._shared().recover_interrupted()

    def events(self, *args: Any, **kwargs: Any):
        return self._shared().events(*args, **kwargs)

    def add_notification(self, *args: Any, **kwargs: Any):
        return self._shared().add_notification(*args, **kwargs)

    def get_notification(self, notification_id: str):
        return self._shared().get_notification(notification_id)

    def notifications(self, limit: int = 30):
        return self._shared().notifications(limit)

    def acknowledge(self, notification_id: str):
        return self._shared().acknowledge(notification_id)

    def usage_today(self):
        return self._shared().usage_today()

    def correlate_signals(self, run_id: str, signals: list[dict[str, str]], **kwargs: Any):
        run = self._shared().get_run(run_id)
        if run is None:
            scope_key = str(kwargs.get("scope_key") or "")
            parts = scope_key.split("|", 2)
            tenant = parts[2] if len(parts) == 3 else "workspace-primary"
        else:
            tenant = run.tenant_scope_id
        with self.registry.operation_lock:
            store = self._store(tenant)
            # Isolated response databases intentionally do not copy the global run queue.
            if store is not self._shared() and run is not None:
                scope_key = str(kwargs.get("scope_key") or "")
                kwargs["scope_key"] = scope_key or "|".join(
                    (run.connection_alias, run.connection_fingerprint, run.tenant_scope_id)
                )
            result = store.correlate_signals(run_id, signals, **kwargs)
            self._note(tenant)
            return result

    def get_signal(self, fingerprint: str):
        for _, store in self._active():
            if value := store.get_signal(fingerprint):
                return value
        value = self._shared().get_signal(fingerprint)
        return value if value and _tenant(value) not in self._isolated() else None

    def signals(self, *, scope_key: str = "", tenant_scope_id: str = ""):
        if tenant_scope_id:
            return self._store(tenant_scope_id).signals(scope_key=scope_key, tenant_scope_id=tenant_scope_id)
        isolated = self._isolated()
        values = [
            item for item in self._shared().signals(scope_key=scope_key) if _tenant(item) not in isolated
        ]
        for tenant, store in self._active():
            values.extend(store.signals(scope_key=scope_key, tenant_scope_id=tenant))
        return sorted(values, key=lambda item: item["last_seen_at"], reverse=True)

    def signal_counts(self, *, scope_key: str = "", tenant_scope_id: str = ""):
        values = self.signals(scope_key=scope_key, tenant_scope_id=tenant_scope_id)
        return {
            "actionable": sum(item["status"] == "persistent" for item in values),
            "repeated": sum(
                item["status"] == "persistent" and item["consecutive_count"] >= 2 for item in values
            ),
            "severity_elevated": sum(
                item["status"] == "persistent" and item["consecutive_count"] < 2 for item in values
            ),
            "watching": sum(item["status"] == "watching" for item in values),
            "resolved": sum(item["status"] == "resolved" for item in values),
        }

    def create_package(self, run_id: str, *args: Any, **kwargs: Any):
        run = self._shared().get_run(run_id)
        tenant = run.tenant_scope_id if run else "workspace-primary"
        with self.registry.operation_lock:
            store = self._store(tenant)
            result = store.create_package(run_id, *args, **kwargs)
            self._note(tenant)
            return result

    def _find_package(self, package_id: str):
        for tenant, store in self._active():
            changed = store.expire_packages()
            if changed:
                self._note(tenant)
            if value := store.get_package(package_id, expire=False):
                return store, value, tenant
        self._shared().expire_packages(self._isolated())
        value = self._shared().get_package(package_id, expire=False)
        if value is not None and _tenant(value) not in self._isolated():
            return self._shared(), value, _tenant(value)
        return None

    def update_package_validations(self, package_id: str, task_ids: list[str]):
        with self.registry.operation_lock:
            found = self._find_package(package_id)
            if not found:
                return None
            store, _, tenant = found
            value = store.update_package_validations(package_id, task_ids)
            if value:
                self._note(tenant)
            return value

    def expire_packages(self) -> int:
        total = self._shared().expire_packages(self._isolated())
        for tenant, store in self._active():
            changed = store.expire_packages()
            total += changed
            if changed:
                self._note(tenant)
        return total

    def get_package(self, package_id: str, tenant_scope_id: str = ""):
        if tenant_scope_id:
            store = self._store(tenant_scope_id)
            changed = store.expire_packages()
            if changed:
                self._note(tenant_scope_id)
            return store.get_package(package_id, tenant_scope_id, expire=False)
        found = self._find_package(package_id)
        return found[1] if found else None

    def packages(self, limit: int = 20, *, tenant_scope_id: str = ""):
        if tenant_scope_id:
            store = self._store(tenant_scope_id)
            changed = store.expire_packages()
            if changed:
                self._note(tenant_scope_id)
            return store.packages(limit, tenant_scope_id=tenant_scope_id, expire=False)
        isolated = self._isolated()
        self._shared().expire_packages(isolated)
        values = [
            item for item in self._shared().packages(limit, expire=False) if _tenant(item) not in isolated
        ]
        for tenant, store in self._active():
            values.extend(store.packages(limit, tenant_scope_id=tenant, expire=False))
        return sorted(values, key=lambda item: item["created_at"], reverse=True)[:limit]

    def covered_signal_fingerprints(self, *, tenant_scope_id: str = ""):
        if tenant_scope_id:
            return self._store(tenant_scope_id).covered_signal_fingerprints(tenant_scope_id=tenant_scope_id)
        return {
            fingerprint
            for item in self.packages(100)
            if item["status"] == "review"
            for fingerprint in item["signal_fingerprints"]
        }

    def close_package(self, package_id: str):
        with self.registry.operation_lock:
            found = self._find_package(package_id)
            if not found:
                return None
            store, _, tenant = found
            value = store.close_package(package_id, expire=False)
            if value:
                self._note(tenant)
            return value

    scoped_signal_fingerprint = classmethod(
        lambda cls, scope_key, fingerprint: AssuranceStore.scoped_signal_fingerprint(scope_key, fingerprint)
    )


class RoutedDeliveryStore(_RoutedWorkflowStore):
    """Keep destination policy global while routing tenant-owned job history."""

    def __init__(self, registry: TenantDataPlaneRegistry):
        super().__init__(registry, "outbound-delivery", "delivery.db", DeliveryStore)

    def connect(self):
        return self._shared().connect()

    def bind_unbound(self, binding: dict[str, Any], package_resolver: Any = None):
        return self._shared().bind_unbound(binding, package_resolver)

    def policy(self):
        return self._shared().policy()

    def update_policy(self, value: Any):
        return self._shared().update_policy(value)

    def approve(self, **kwargs: Any):
        binding = kwargs.get("binding") or {}
        tenant = str(binding.get("tenant_scope_id") or "workspace-primary")
        with self.registry.operation_lock:
            value = self._store(tenant).approve(**kwargs)
            self._note(tenant)
            return value

    def get(self, job_id: str, tenant_scope_id: str = ""):
        if tenant_scope_id:
            return self._store(tenant_scope_id).get(job_id, tenant_scope_id)
        found = self._find(job_id)
        return found[1] if found else None

    def jobs(self, limit: int = 30, *, tenant_scope_id: str = ""):
        if tenant_scope_id:
            return self._store(tenant_scope_id).jobs(limit, tenant_scope_id=tenant_scope_id)
        isolated = self._isolated()
        values = [item for item in self._shared().jobs(limit) if _tenant(item) not in isolated]
        for tenant, store in self._active():
            values.extend(store.jobs(limit, tenant_scope_id=tenant))
        return sorted(values, key=lambda item: item["created_at"], reverse=True)[:limit]

    def next_due(self):
        values = [item for _, store in self._active() if (item := store.next_due())]
        shared = self._shared().next_due(self._isolated())
        if shared and _tenant(shared) not in self._isolated():
            values.append(shared)
        return min(values, key=lambda item: item["created_at"]) if values else None

    def mark_sending(self, job_id: str):
        return self._mutate("mark_sending", job_id)

    def record_attempt(self, job_id: str, **kwargs: Any):
        return self._mutate("record_attempt", job_id, **kwargs)

    def retry(self, job_id: str, additional_attempts: int):
        return self._mutate("retry", job_id, additional_attempts)

    def cancel(self, job_id: str, reason: str = "Cancelled by local operator"):
        return self._mutate("cancel", job_id, reason)

    def cancel_sending(self, job_id: str, reason: str):
        return self._mutate("cancel_sending", job_id, reason)

    def cancel_package(self, package_id: str, reason: str) -> int:
        total = 0
        shared_match = next(
            (
                item
                for item in self._shared().jobs(200)
                if item["package_id"] == package_id and _tenant(item) not in self._isolated()
            ),
            None,
        )
        if shared_match:
            total += self._shared().cancel_package(package_id, reason)
        for tenant, store in self._active():
            changed = store.cancel_package(package_id, reason)
            total += changed
            if changed:
                self._note(tenant)
        return total

    def cancel_pending(self, reason: str) -> int:
        total = self._shared().cancel_pending(reason, self._isolated())
        for tenant, store in self._active():
            changed = store.cancel_pending(reason)
            total += changed
            if changed:
                self._note(tenant)
        return total

    def fail_without_attempt(self, job_id: str, error: str):
        return self._mutate("fail_without_attempt", job_id, error)

    def record_external_record(self, job_id: str, **kwargs: Any):
        return self._mutate("record_external_record", job_id, **kwargs)

    def recover_interrupted(self):
        totals = self._shared().recover_interrupted(self._isolated())
        for tenant, store in self._active():
            changed = store.recover_interrupted()
            for key, count in changed.items():
                totals[key] = totals.get(key, 0) + count
            if any(changed.values()):
                self._note(tenant)
        return totals

    def attempts(self, job_id: str):
        found = self._find(job_id)
        return found[0].attempts(job_id) if found else []

    def record_reconciliation(self, job_id: str, **kwargs: Any):
        return self._mutate("record_reconciliation", job_id, **kwargs)

    def reconciliation(self, reconciliation_id: str):
        for _, store in self._active():
            if value := store.reconciliation(reconciliation_id):
                return value
        return self._shared().reconciliation(reconciliation_id)

    def reconciliations(self, job_id: str, limit: int = 20):
        found = self._find(job_id)
        return found[0].reconciliations(job_id, limit) if found else []
