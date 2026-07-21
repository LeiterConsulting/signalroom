from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

APPLICATION_VERSION = "0.1.0"
MANIFEST_SCHEMA_VERSION = 2
MINIMUM_PYTHON = (3, 11)
MINIMUM_FREE_BYTES = 512 * 1024 * 1024
RECOMMENDED_FREE_BYTES = 2 * 1024 * 1024 * 1024
ACTIVE_TENANT_STATUSES = {"copying", "applying"}
STAGED_TENANT_STATUSES = {"verified", "finalized-ready"}
SOURCE_ROOT_FILES = (
    "pyproject.toml",
    "install.ps1",
    "install.sh",
    "Dockerfile",
    "compose.yaml",
    ".dockerignore",
    ".gitignore",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def source_digest(root: Path) -> str:
    paths = [root / name for name in SOURCE_ROOT_FILES]
    source = root / "src"
    if source.exists():
        paths.extend(
            path
            for path in source.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}
        )
    digest = hashlib.sha256()
    for path in sorted((path for path in paths if path.exists()), key=lambda item: item.as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _release(value: str) -> tuple[int, int, int] | None:
    try:
        parts = value.split("-", 1)[0].split(".")
        if not 1 <= len(parts) <= 3:
            return None
        numbers = tuple(int(part) for part in parts)
        if any(part < 0 for part in numbers):
            return None
        return (numbers + (0, 0))[:3]  # type: ignore[return-value]
    except (AttributeError, TypeError, ValueError):
        return None


def _check(
    check_id: str,
    title: str,
    status: str,
    summary: str,
    *,
    evidence: dict[str, Any] | None = None,
    remediation: str = "",
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "summary": summary,
        "evidence": evidence or {},
        "remediation": remediation,
    }


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _sqlite_quick_check(path: Path) -> str:
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            row = db.execute("PRAGMA quick_check(1)").fetchone()
    except sqlite3.DatabaseError as exc:
        return str(exc)
    return "" if row and row[0] == "ok" else str(row[0] if row else "no result")


def _table_status_counts(path: Path, table: str) -> dict[str, int]:
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not exists:
                return {}
            rows = db.execute(f'SELECT status,COUNT(*) FROM "{table}" GROUP BY status').fetchall()
    except sqlite3.DatabaseError:
        return {}
    return {str(status): int(count) for status, count in rows}


class UpgradeReadinessService:
    def __init__(
        self,
        root: Path | str,
        data_root: Path | str,
        target_version: str = APPLICATION_VERSION,
        manifest_path: Path | str | None = None,
    ):
        self.root = Path(root).resolve()
        self.data_root = Path(data_root).resolve()
        self.target_version = target_version
        self.manifest_path = (
            Path(manifest_path).resolve()
            if manifest_path is not None
            else self.root / ".install_manifest.json"
        )

    def _manifest_and_version(self) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
        target = _release(self.target_version)
        if target is None:
            return None, "invalid-target", _check(
                "version-path",
                "Version transition",
                "block",
                f"Target version {self.target_version!r} is not a supported release identifier.",
                remediation="Use the application version declared by this SignalRoom source tree.",
            )
        if not self.manifest_path.exists():
            return None, "clean-install", _check(
                "version-path",
                "Version transition",
                "pass",
                f"No prior installation manifest exists; {self.target_version} is a clean install.",
                evidence={"installed_version": None, "target_version": self.target_version},
            )
        manifest = _read_json(self.manifest_path)
        if manifest is None:
            return None, "invalid-manifest", _check(
                "version-path",
                "Version transition",
                "block",
                "The existing installation manifest is unreadable or is not a JSON object.",
                evidence={"manifest": str(self.manifest_path)},
                remediation=(
                    "Do not delete retained data. Move the invalid lifecycle manifest aside, rebuild the "
                    "virtual environment, and rerun preflight."
                ),
            )
        installed_text = str(manifest.get("version") or "")
        installed = _release(installed_text)
        if installed is None:
            return manifest, "invalid-manifest", _check(
                "version-path",
                "Version transition",
                "block",
                "The installation manifest has no valid installed version.",
                evidence={"installed_version": installed_text, "target_version": self.target_version},
                remediation="Repair the lifecycle manifest or perform a clean environment rebuild.",
            )
        current_source_hash = source_digest(self.root)
        prior_source_hash = str(manifest.get("source_hash") or "")
        if installed == target:
            scenario = "current" if prior_source_hash == current_source_hash else "source-refresh"
            summary = (
                f"SignalRoom {self.target_version} is already installed and matches this source."
                if scenario == "current"
                else (
                    f"SignalRoom {self.target_version} is installed, but dependency source changed; "
                    "a controlled refresh and restart are required."
                )
            )
            return manifest, scenario, _check(
                "version-path",
                "Version transition",
                "pass",
                summary,
                evidence={
                    "installed_version": installed_text,
                    "target_version": self.target_version,
                    "source_changed": prior_source_hash != current_source_hash,
                    "installed_source_hash": prior_source_hash or None,
                    "current_source_hash": current_source_hash,
                },
            )
        if target < installed:
            return manifest, "downgrade", _check(
                "version-path",
                "Version transition",
                "block",
                f"An in-place downgrade from {installed_text} to {self.target_version} is not supported.",
                evidence={"installed_version": installed_text, "target_version": self.target_version},
                remediation=(
                    "Restore the matching source/container and a compatible encrypted recovery package in an "
                    "isolated rollback procedure."
                ),
            )
        if target[:2] != installed[:2]:
            return manifest, "release-line-change", _check(
                "version-path",
                "Version transition",
                "block",
                (
                    f"The transition from {installed_text} to {self.target_version} crosses a major/minor "
                    "release line and has no admitted migrator."
                ),
                evidence={
                    "installed_version": installed_text,
                    "target_version": self.target_version,
                    "policy": "same-major-minor",
                },
                remediation=(
                    "Follow a documented release-line migration instead of using the in-place installer."
                ),
            )
        return manifest, "patch-upgrade", _check(
            "version-path",
            "Version transition",
            "pass",
            f"Patch upgrade {installed_text} → {self.target_version} is supported in place.",
            evidence={
                "installed_version": installed_text,
                "target_version": self.target_version,
                "policy": "same-major-minor",
            },
        )

    def _runtime_check(self, manifest: dict[str, Any] | None) -> dict[str, Any]:
        current = tuple(sys.version_info[:3])
        recorded = str((manifest or {}).get("python", {}).get("version") or "")
        status = "pass" if current[:2] >= MINIMUM_PYTHON else "block"
        summary = (
            f"Python {platform.python_version()} satisfies the Python 3.11+ runtime contract."
            if status == "pass"
            else f"Python {platform.python_version()} cannot run this SignalRoom release."
        )
        return _check(
            "python-runtime",
            "Python runtime",
            status,
            summary,
            evidence={
                "active": platform.python_version(),
                "recorded_environment": recorded or None,
                "minimum": "3.11",
            },
            remediation="Install Python 3.11 or later and rebuild .venv." if status == "block" else "",
        )

    def _manifest_check(self, manifest: dict[str, Any] | None) -> dict[str, Any]:
        if manifest is None:
            return _check(
                "installer-manifest",
                "Installer ownership manifest",
                "pass",
                "The installer will create a versioned ownership manifest for this clean environment.",
            )
        schema = int(manifest.get("manifest_schema") or 1)
        virtual_env_text = str(manifest.get("virtual_env") or "")
        virtual_env = Path(virtual_env_text).resolve() if virtual_env_text else None
        warnings: list[str] = []
        if schema < MANIFEST_SCHEMA_VERSION:
            warnings.append("The legacy manifest will be upgraded to schema 2 after installation.")
        if virtual_env is None or not _inside(virtual_env, self.root):
            warnings.append("The recorded virtual environment is foreign and will be rebuilt locally.")
        recorded_os = str(manifest.get("os") or "")
        if recorded_os and recorded_os.casefold() not in platform.system().casefold():
            warnings.append("The recorded operating system differs; no virtual environment will be reused.")
        status = "warn" if warnings else "pass"
        return _check(
            "installer-manifest",
            "Installer ownership manifest",
            status,
            " ".join(warnings) if warnings else "The lifecycle manifest belongs to this workspace.",
            evidence={
                "manifest": str(self.manifest_path),
                "schema": schema,
                "target_schema": MANIFEST_SCHEMA_VERSION,
                "virtual_env": virtual_env_text or None,
                "recorded_os": recorded_os or None,
            },
        )

    def _storage_check(self) -> dict[str, Any]:
        probe = self.data_root if self.data_root.exists() else self.root
        try:
            usage = shutil.disk_usage(probe)
        except OSError as exc:
            return _check(
                "storage",
                "Writable retained storage",
                "block",
                f"Storage capacity could not be inspected: {exc}",
                remediation="Mount a writable data path and rerun preflight.",
            )
        writable = os.access(probe, os.W_OK)
        if not writable or usage.free < MINIMUM_FREE_BYTES:
            status = "block"
        elif usage.free < RECOMMENDED_FREE_BYTES:
            status = "warn"
        else:
            status = "pass"
        summary = (
            "The retained data path is not writable."
            if not writable
            else (
                f"Only {usage.free / 1024**3:.1f} GiB is free; at least 0.5 GiB is required."
                if usage.free < MINIMUM_FREE_BYTES
                else (
                    f"{usage.free / 1024**3:.1f} GiB is free; preserve headroom before model downloads."
                    if usage.free < RECOMMENDED_FREE_BYTES
                    else f"{usage.free / 1024**3:.1f} GiB is free on writable retained storage."
                )
            )
        )
        return _check(
            "storage",
            "Writable retained storage",
            status,
            summary,
            evidence={
                "data_root": str(self.data_root),
                "free_bytes": usage.free,
                "minimum_bytes": MINIMUM_FREE_BYTES,
                "writable": writable,
            },
            remediation="Free disk space or correct data-directory permissions before installing."
            if status == "block"
            else "",
        )

    def _data_contract_check(self) -> dict[str, Any]:
        if not self.data_root.exists():
            return _check(
                "retained-data",
                "Retained data compatibility",
                "pass",
                "No retained data directory exists; stores will be initialized by the clean install.",
                evidence={"databases": 0, "bytes": 0},
            )
        if not self.data_root.is_dir():
            return _check(
                "retained-data",
                "Retained data compatibility",
                "block",
                "The configured data path is not a directory.",
                remediation="Point SIGNALROOM_DATA_DIR at the retained SignalRoom data directory.",
            )
        config = self.data_root / "config.json"
        config_valid = not config.exists() or _read_json(config) is not None
        key_exists = (self.data_root / ".vault.key").is_file()
        secrets_exist = (self.data_root / "secrets.enc").is_file()
        vault_valid = not secrets_exist or key_exists
        databases = sorted(self.data_root.rglob("*.db"))
        failures = [
            {"path": str(path.relative_to(self.data_root)), "error": error}
            for path in databases
            if (error := _sqlite_quick_check(path))
        ]
        status = "pass" if config_valid and vault_valid and not failures else "block"
        summary = (
            f"Validated {len(databases)} retained SQLite stores, settings JSON, and vault pairing."
            if status == "pass"
            else "Retained control-plane data failed a read-only compatibility check."
        )
        return _check(
            "retained-data",
            "Retained data compatibility",
            status,
            summary,
            evidence={
                "databases": len(databases),
                "database_failures": failures,
                "config_valid": config_valid,
                "vault_pair_valid": vault_valid,
                "bytes": sum(path.stat().st_size for path in databases if path.exists()),
            },
            remediation=(
                "Stop the upgrade and restore or repair the exact failing component from a verified backup."
                if status == "block"
                else ""
            ),
        )

    def _recovery_check(self) -> dict[str, Any]:
        pending = self.data_root / "recovery" / "pending" / "pending.json"
        exports = self.data_root / "recovery" / "exports"
        export_count = len(list(exports.glob("*.signalroom-recovery"))) if exports.exists() else 0
        if pending.exists():
            marker = _read_json(pending)
            return _check(
                "recovery-boundary",
                "Recovery and rollback boundary",
                "block",
                "A control-plane restore is staged for the next start; source upgrade is frozen.",
                evidence={"pending_marker_valid": marker is not None, "recovery_exports": export_count},
                remediation="Apply or cancel the pending restore with its current release before upgrading.",
            )
        return _check(
            "recovery-boundary",
            "Recovery and rollback boundary",
            "warn" if export_count == 0 and self.manifest_path.exists() else "pass",
            (
                "No local encrypted recovery export was found; create and move one off-host before upgrading."
                if export_count == 0 and self.manifest_path.exists()
                else (
                    f"No restore is pending; {export_count} encrypted recovery export(s) "
                    "are retained locally."
                )
            ),
            evidence={"pending_restore": False, "recovery_exports": export_count},
        )

    def _tenant_migration_check(self) -> dict[str, Any]:
        path = self.data_root / "tenant_isolation.db"
        if not path.exists():
            return _check(
                "tenant-migrations",
                "Tenant data-plane transitions",
                "pass",
                "No tenant-isolation store exists in this deployment.",
            )
        migrations = _table_status_counts(path, "tenant_data_migrations")
        reverses = _table_status_counts(path, "tenant_reverse_migrations")
        active = sum(
            migrations.get(status, 0) + reverses.get(status, 0)
            for status in ACTIVE_TENANT_STATUSES
        )
        staged = sum(
            migrations.get(status, 0) + reverses.get(status, 0)
            for status in STAGED_TENANT_STATUSES
        )
        status = "block" if active else "warn" if staged else "pass"
        summary = (
            f"{active} tenant data-plane transition{'s' if active != 1 else ''} "
            f"{'are' if active != 1 else 'is'} actively copying or applying."
            if active
            else (
                f"{staged} tenant transition{'s' if staged != 1 else ''} "
                f"{'are' if staged != 1 else 'is'} verified but not finalized; preserve exact digests."
                if staged
                else "No active or staged tenant data-plane transition blocks restart."
            )
        )
        return _check(
            "tenant-migrations",
            "Tenant data-plane transitions",
            status,
            summary,
            evidence={"migrations": migrations, "reverse_migrations": reverses},
            remediation="Complete or roll back the active transition before upgrading." if active else "",
        )

    def _durable_work_check(self) -> dict[str, Any]:
        contracts = (
            ("discovery_jobs.db", "discovery_jobs"),
            ("assurance.db", "assurance_runs"),
            ("delivery.db", "delivery_attempts"),
        )
        counts: dict[str, dict[str, int]] = {}
        pending = 0
        for filename, table in contracts:
            path = self.data_root / filename
            if not path.exists():
                continue
            values = _table_status_counts(path, table)
            counts[f"{filename}:{table}"] = values
            pending += sum(values.get(status, 0) for status in ("queued", "running", "retrying"))
        return _check(
            "durable-work",
            "Durable work restart behavior",
            "warn" if pending else "pass",
            (
                f"{pending} queued, running, or retrying work item(s) will use their documented restart path."
                if pending
                else "No inspected durable work item is waiting for restart recovery."
            ),
            evidence={"pending_items": pending, "status_counts": counts},
        )

    def _model_check(self) -> dict[str, Any]:
        root = self.data_root / "models"
        manifests = list(root.rglob("*.json")) if root.exists() else []
        return _check(
            "local-models",
            "Optional local model preservation",
            "pass",
            (
                f"Local model storage is retained independently; {len(manifests)} manifest(s) were observed."
                if root.exists()
                else "No local Transformers store exists; model installation remains optional."
            ),
            evidence={"model_root": str(root), "manifests": len(manifests), "downloads_started": 0},
        )

    def _deployment_check(self) -> dict[str, Any]:
        compose = self.root / "compose.yaml"
        dockerfile = self.root / "Dockerfile"
        dockerignore = self.root / ".dockerignore"
        compose_text = compose.read_text(encoding="utf-8") if compose.exists() else ""
        docker_text = dockerfile.read_text(encoding="utf-8") if dockerfile.exists() else ""
        ignore_text = dockerignore.read_text(encoding="utf-8") if dockerignore.exists() else ""
        contracts = {
            "compose_data_mount": "./data:/app/data" in compose_text,
            "compose_configurable_bind": "SIGNALROOM_BIND_ADDRESS" in compose_text,
            "compose_healthcheck": "healthcheck:" in compose_text,
            "docker_data_excluded": "data/" in ignore_text,
            "dockerfile_does_not_copy_data": "COPY data" not in docker_text,
        }
        failures = [name for name, passed in contracts.items() if not passed]
        return _check(
            "deployment-contracts",
            "Process and container deployment contracts",
            "pass" if not failures else "block",
            (
                "Windows/Linux process installers and Docker Compose preserve the same "
                "external data boundary."
                if not failures
                else f"Deployment contract failures: {', '.join(failures)}."
            ),
            evidence=contracts,
            remediation=(
                "Repair the checked-in installer/container contract before promotion."
                if failures
                else ""
            ),
        )

    def _binding_check(self) -> dict[str, Any]:
        runtime = _read_json(self.root / ".signalroom.runtime.json") or {}
        host = str(runtime.get("host") or "")
        url = str(runtime.get("url") or "")
        exposed = host in {"0.0.0.0", "::"}
        return _check(
            "runtime-binding",
            "Runtime binding visibility",
            "warn" if exposed else "pass",
            (
                f"The current process is reachable beyond loopback through {host}; verify RBAC, "
                "HTTPS, and host firewall policy."
                if exposed
                else "The current process is loopback-bound or no managed runtime is active."
            ),
            evidence={"host": host or None, "url": url or None, "lan_capable": exposed},
        )

    def overview(self) -> dict[str, Any]:
        manifest, scenario, version_check = self._manifest_and_version()
        checks = [
            version_check,
            self._runtime_check(manifest),
            self._manifest_check(manifest),
            self._storage_check(),
            self._data_contract_check(),
            self._recovery_check(),
            self._tenant_migration_check(),
            self._durable_work_check(),
            self._model_check(),
            self._deployment_check(),
            self._binding_check(),
        ]
        blocked = sum(item["status"] == "block" for item in checks)
        warnings = sum(item["status"] == "warn" for item in checks)
        installed_version = str((manifest or {}).get("version") or "") or None
        actions = [
            "Create and move a password-encrypted control-plane recovery package to approved "
            "off-host storage.",
            "Run the platform installer; it will stop only its owned process after this preflight passes.",
            "Confirm health, connection identities, tenant routes, and model artifact approvals "
            "after restart.",
            "Run the source-bound release gate against the installed source before promotion.",
        ]
        if scenario == "clean-install":
            actions[0] = "Choose loopback or an explicitly governed LAN binding before first start."
        return {
            "generated_at": _now(),
            "source_sha256": source_digest(self.root),
            "decision": "blocked" if blocked else "ready",
            "scenario": scenario,
            "counts": {
                "passed": len(checks) - blocked - warnings,
                "warnings": warnings,
                "blocked": blocked,
                "total": len(checks),
            },
            "installation": {
                "installed_version": installed_version,
                "target_version": self.target_version,
                "manifest": str(self.manifest_path),
                "root": str(self.root),
                "data_root": str(self.data_root),
                "restart_required": scenario not in {"current", "clean-install"},
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "container": Path("/.dockerenv").exists(),
            },
            "checks": checks,
            "actions": actions,
            "command": "signalroom-upgrade-check --json",
        }

    def record(self, report: dict[str, Any]) -> Path:
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        receipt = {**report, "report_sha256": _sha256(canonical)}
        directory = self.data_root / "upgrade" / "preflight_receipts"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = directory / f"preflight-{stamp}-{receipt['report_sha256'][:12]}.json"
        payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, path)
        latest = directory.parent / "latest_preflight.json"
        latest_temporary = latest.with_suffix(".tmp")
        latest_temporary.write_text(payload, encoding="utf-8")
        os.replace(latest_temporary, latest)
        return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only SignalRoom install and retained-data compatibility preflight."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--target-version", default=APPLICATION_VERSION)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--source-digest", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.root.resolve()
    if args.source_digest:
        print(source_digest(root))
        return 0
    service = UpgradeReadinessService(
        root,
        (args.data_dir or root / "data").resolve(),
        args.target_version,
        args.manifest,
    )
    report = service.overview()
    if args.record:
        report["receipt_path"] = str(service.record(report))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"SignalRoom upgrade preflight: {report['decision'].upper()}")
        print(
            f"Scenario: {report['scenario']} | installed "
            f"{report['installation']['installed_version'] or 'none'} -> "
            f"{report['installation']['target_version']}"
        )
        for item in report["checks"]:
            print(f"[{item['status'].upper():5}] {item['title']}: {item['summary']}")
        if report.get("receipt_path"):
            print(f"Receipt: {report['receipt_path']}")
    return 0 if report["decision"] == "ready" else 2


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
