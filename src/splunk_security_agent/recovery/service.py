from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..schemas import AppSettings

FORMAT_NAME = "signalroom-recovery"
FORMAT_VERSION = 1
MAX_PACKAGE_BYTES = 25 * 1024 * 1024
MAX_COMPONENT_BYTES = 10 * 1024 * 1024
INSPECTION_LIFETIME_MINUTES = 30

COMPONENTS = {
    "config.json": {
        "category": "workspace-settings",
        "required": True,
        "description": "Splunk, model routing, local/cloud, and agent execution settings.",
    },
    ".vault.key": {
        "category": "credential-vault",
        "required": True,
        "description": "Local key required to decrypt the paired SignalRoom credential vault.",
    },
    "secrets.enc": {
        "category": "credential-vault",
        "required": False,
        "description": "Encrypted Splunk, model, OIDC, delivery, and audit destination secrets.",
    },
    "connection_registry.db": {
        "category": "connection-identities",
        "required": True,
        "description": "Admitted Splunk aliases, immutable revisions, and tenant-scope bindings.",
    },
    "auth.db": {
        "category": "access-control",
        "required": True,
        "description": "Optional RBAC users and OIDC policy; sessions and login attempts are excluded.",
    },
    "model_trust.db": {
        "category": "model-trust",
        "required": True,
        "description": "Model publisher policy and exact local artifact approvals.",
    },
    "model_trust_signing.key": {
        "category": "model-trust",
        "required": True,
        "description": "Ed25519 identity paired with the retained model approval history.",
    },
    "retention.db": {
        "category": "retention-policy",
        "required": False,
        "description": "Local retention policy and payload-free cleanup receipts.",
    },
}

EXCLUDED = [
    "Evidence, cases, discoveries, validations, detections, assurance, delivery history, and forecasts",
    "Work queues, schedules, audit history, exports, diagnostics, and benchmark run history",
    "Downloaded model weights, generated artifacts, repository checkouts, logs, and runtime files",
    "Environment-managed secrets, private CA file contents, and external service state",
]

SQLITE_TABLES = {
    "connection_registry.db": {
        "tenant_scopes",
        "connection_identities",
        "connection_aliases",
        "managed_splunk_connections",
    },
    "auth.db": {"auth_policy", "auth_users", "auth_oidc_policy"},
    "model_trust.db": {"model_trust_policy", "model_artifact_attestations"},
    "retention.db": {"retention_policy", "retention_cleanup_runs"},
}


class RecoveryPackageError(ValueError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _secure_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_component_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or len(path.parts) != 1 or path.name != value or value not in COMPONENTS:
        raise RecoveryPackageError(f"The package contains an unapproved component path: {value!r}")
    return value


def _derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def _validate_password(password: str) -> None:
    if len(password) < 16:
        raise RecoveryPackageError("Recovery package passwords must contain at least 16 characters.")
    if len(password) > 1024:
        raise RecoveryPackageError("The recovery package password is too long.")


def _encrypt(payload: dict[str, Any], password: str) -> bytes:
    _validate_password(password)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "kdf": {"name": "scrypt", "n": 2**15, "r": 8, "p": 1, "salt": base64.b64encode(salt).decode("ascii")},
        "cipher": {"name": "AES-256-GCM", "nonce": base64.b64encode(nonce).decode("ascii")},
    }
    ciphertext = AESGCM(_derive_key(password, salt)).encrypt(nonce, _canonical(payload), _canonical(header))
    envelope = {
        **header,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "ciphertext_sha256": _sha256(ciphertext),
    }
    return _canonical(envelope)


def _decrypt(package: bytes, password: str) -> dict[str, Any]:
    if len(package) > MAX_PACKAGE_BYTES:
        raise RecoveryPackageError("The recovery package exceeds the 25 MiB safety limit.")
    try:
        envelope = json.loads(package)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryPackageError("This is not a readable SignalRoom recovery package.") from exc
    if not isinstance(envelope, dict):
        raise RecoveryPackageError("The recovery package envelope is invalid.")
    if envelope.get("format") != FORMAT_NAME or envelope.get("format_version") != FORMAT_VERSION:
        raise RecoveryPackageError(
            "This recovery package format is not supported by this SignalRoom version."
        )
    kdf = envelope.get("kdf") or {}
    cipher = envelope.get("cipher") or {}
    if kdf.get("name") != "scrypt" or (kdf.get("n"), kdf.get("r"), kdf.get("p")) != (2**15, 8, 1):
        raise RecoveryPackageError("The recovery package KDF contract is not supported.")
    if cipher.get("name") != "AES-256-GCM":
        raise RecoveryPackageError("The recovery package cipher contract is not supported.")
    try:
        salt = base64.b64decode(kdf["salt"], validate=True)
        nonce = base64.b64decode(cipher["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryPackageError("The recovery package encryption metadata is invalid.") from exc
    if len(salt) != 16 or len(nonce) != 12 or _sha256(ciphertext) != envelope.get("ciphertext_sha256"):
        raise RecoveryPackageError("The recovery package ciphertext failed its integrity preflight.")
    header = {key: envelope[key] for key in ("format", "format_version", "kdf", "cipher")}
    try:
        plaintext = AESGCM(_derive_key(password, salt)).decrypt(nonce, ciphertext, _canonical(header))
    except Exception as exc:
        raise RecoveryPackageError("The password was not accepted or the package has been altered.") from exc
    try:
        value = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryPackageError("The decrypted recovery payload is invalid.") from exc
    if not isinstance(value, dict):
        raise RecoveryPackageError("The decrypted recovery payload is invalid.")
    return value


def _sqlite_snapshot(path: Path, *, sanitize_auth: bool = False) -> bytes:
    with tempfile.TemporaryDirectory(prefix="signalroom-recovery-") as directory:
        target = Path(directory) / path.name
        with closing(sqlite3.connect(path)) as source, closing(
            sqlite3.connect(target)
        ) as destination:
            source.backup(destination)
        if sanitize_auth:
            with closing(sqlite3.connect(target)) as db:
                for table in ("auth_sessions", "auth_login_attempts", "auth_oidc_transactions"):
                    db.execute(f"DELETE FROM {table}")
                db.commit()
        return target.read_bytes()


def _sqlite_validate(name: str, payload: bytes) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="signalroom-inspect-") as directory:
        path = Path(directory) / name
        path.write_bytes(payload)
        try:
            with closing(
                sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            ) as db:
                integrity = db.execute("PRAGMA integrity_check").fetchone()
                if not integrity or integrity[0] != "ok":
                    raise RecoveryPackageError(f"{name} failed SQLite integrity validation.")
                foreign_key_errors = list(db.execute("PRAGMA foreign_key_check"))
                if foreign_key_errors:
                    raise RecoveryPackageError(
                        f"{name} failed SQLite foreign-key validation."
                    )
                tables = {
                    str(row[0])
                    for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                missing = SQLITE_TABLES[name] - tables
                if missing:
                    raise RecoveryPackageError(
                        f"{name} is missing required tables: {', '.join(sorted(missing))}"
                    )
                result: dict[str, Any] = {"integrity": "ok", "tables": len(tables)}
                if name == "auth.db":
                    policy = db.execute("SELECT enabled FROM auth_policy WHERE id=1").fetchone()
                    enabled = bool(policy and policy[0])
                    local_admins = int(
                        db.execute(
                            """SELECT COUNT(*) FROM auth_users
                            WHERE active=1 AND role='admin' AND auth_source='local'"""
                        ).fetchone()[0]
                    )
                    if enabled and local_admins < 1:
                        raise RecoveryPackageError(
                            "The restored RBAC policy is enabled but has no active local "
                            "break-glass administrator."
                        )
                    result.update(rbac_enabled=enabled, active_local_admins=local_admins)
                if name == "model_trust.db":
                    result["active_attestations"] = int(
                        db.execute(
                            "SELECT COUNT(*) FROM model_artifact_attestations WHERE status='active'"
                        ).fetchone()[0]
                    )
                return result
        except sqlite3.DatabaseError as exc:
            raise RecoveryPackageError(f"{name} is not a valid SignalRoom SQLite database.") from exc


def _version_compatibility(package_version: str, current_version: str) -> dict[str, Any]:
    def release(value: str) -> tuple[int, int, int]:
        try:
            numbers = value.split("-", 1)[0].split(".")
            return tuple(int(numbers[index]) if index < len(numbers) else 0 for index in range(3))  # type: ignore[return-value]
        except (TypeError, ValueError):
            return (-1, -1, -1)

    package_release = release(package_version)
    current_release = release(current_version)
    compatible = package_release[:2] == current_release[:2] and package_release[0] >= 0
    warnings = []
    if package_release != current_release and compatible:
        warnings.append(
            "Package and runtime patch versions differ; the supported format and database contracts match."
        )
    if not compatible:
        warnings.append(
            "SignalRoom currently requires recovery packages from the same major and minor release line."
        )
    return {
        "compatible": compatible,
        "package_version": package_version,
        "current_version": current_version,
        "policy": "same-major-minor",
        "warnings": warnings,
    }


def _validate_payload(payload: dict[str, Any], current_version: str) -> dict[str, Any]:
    manifest = payload.get("manifest")
    files = payload.get("files")
    if not isinstance(manifest, dict) or not isinstance(files, dict):
        raise RecoveryPackageError("The decrypted package is missing its manifest or component map.")
    if manifest.get("schema_version") != FORMAT_VERSION or manifest.get("application") != "SignalRoom":
        raise RecoveryPackageError("The recovery manifest schema is not supported.")
    package_id = str(manifest.get("package_id") or "")
    try:
        uuid4_value = __import__("uuid").UUID(package_id)
    except (ValueError, AttributeError) as exc:
        raise RecoveryPackageError("The recovery manifest package identity is invalid.") from exc
    if str(uuid4_value) != package_id:
        raise RecoveryPackageError("The recovery manifest package identity is not canonical.")
    entries = manifest.get("components")
    if not isinstance(entries, list):
        raise RecoveryPackageError("The recovery manifest component inventory is invalid.")
    entry_map: dict[str, dict[str, Any]] = {}
    decoded: dict[str, bytes] = {}
    validations: dict[str, Any] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise RecoveryPackageError("The recovery manifest contains an invalid component entry.")
        name = _safe_component_path(str(entry.get("path") or ""))
        if name in entry_map:
            raise RecoveryPackageError(f"The recovery manifest repeats {name}.")
        encoded = files.get(name)
        if not isinstance(encoded, str):
            raise RecoveryPackageError(f"The recovery payload is missing {name}.")
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RecoveryPackageError(f"The recovery payload for {name} is invalid.") from exc
        if len(value) > MAX_COMPONENT_BYTES:
            raise RecoveryPackageError(f"The recovery component {name} exceeds its safety limit.")
        if int(entry.get("size") or -1) != len(value) or entry.get("sha256") != _sha256(value):
            raise RecoveryPackageError(f"The recovery component {name} failed manifest verification.")
        entry_map[name] = entry
        decoded[name] = value
    if set(files) != set(entry_map):
        raise RecoveryPackageError("The package contains files that are not declared in its manifest.")
    missing = [name for name, contract in COMPONENTS.items() if contract["required"] and name not in decoded]
    if missing:
        raise RecoveryPackageError(f"The recovery package is incomplete: {', '.join(missing)}")
    try:
        settings = AppSettings.model_validate(json.loads(decoded["config.json"]))
    except Exception as exc:
        raise RecoveryPackageError("config.json does not match this SignalRoom settings contract.") from exc
    validations["config.json"] = {
        "valid": True,
        "configured": settings.configured,
        "demo_mode": settings.demo_mode,
        "model_profiles": len(settings.models),
    }
    try:
        fernet = Fernet(decoded[".vault.key"])
        secrets = (
            json.loads(fernet.decrypt(decoded["secrets.enc"]).decode("utf-8"))
            if "secrets.enc" in decoded
            else {}
        )
        if not isinstance(secrets, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in secrets.items()
        ):
            raise ValueError("invalid secret map")
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RecoveryPackageError("The encrypted vault does not match the packaged vault key.") from exc
    validations["credential-vault"] = {"valid": True, "secret_entries": len(secrets)}
    for name in SQLITE_TABLES:
        if name in decoded:
            validations[name] = _sqlite_validate(name, decoded[name])
    with tempfile.TemporaryDirectory(prefix="signalroom-binding-") as directory:
        connection_path = Path(directory) / "connection_registry.db"
        auth_path = Path(directory) / "auth.db"
        connection_path.write_bytes(decoded["connection_registry.db"])
        auth_path.write_bytes(decoded["auth.db"])
        with closing(sqlite3.connect(connection_path)) as connection_db:
            aliases = {
                str(row[0])
                for row in connection_db.execute("SELECT alias FROM connection_aliases")
            }
        if "primary" not in aliases:
            raise RecoveryPackageError(
                "The packaged connection registry has no Primary Splunk alias."
            )
        with closing(sqlite3.connect(auth_path)) as auth_db:
            assigned_aliases: set[str] = set()
            for row in auth_db.execute("SELECT connection_ids FROM auth_users"):
                try:
                    assigned_aliases.update(str(value) for value in json.loads(row[0]))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RecoveryPackageError(
                        "A packaged user has an invalid Splunk connection assignment."
                    ) from exc
            oidc_row = auth_db.execute(
                "SELECT connection_group_mappings FROM auth_oidc_policy WHERE id=1"
            ).fetchone()
            try:
                oidc_aliases = {
                    str(item["connection_alias"])
                    for item in json.loads(oidc_row[0] if oidc_row else "[]")
                }
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise RecoveryPackageError(
                    "The packaged OIDC connection mapping is invalid."
                ) from exc
        missing_aliases = (assigned_aliases | oidc_aliases) - aliases
        if missing_aliases:
            raise RecoveryPackageError(
                "Packaged access policy references missing Splunk aliases: "
                + ", ".join(sorted(missing_aliases))
            )
        validations["access-bindings"] = {
            "valid": True,
            "connection_aliases": len(aliases),
            "assigned_aliases": len(assigned_aliases | oidc_aliases),
        }
    try:
        private_key = serialization.load_pem_private_key(
            decoded["model_trust_signing.key"], password=None
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("not Ed25519")
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = _sha256(public_der)
    except (ValueError, TypeError) as exc:
        raise RecoveryPackageError("The model trust signing key is not a valid Ed25519 private key.") from exc
    with tempfile.TemporaryDirectory(prefix="signalroom-trust-") as directory:
        path = Path(directory) / "model_trust.db"
        path.write_bytes(decoded["model_trust.db"])
        with closing(sqlite3.connect(path)) as db:
            foreign_keys = {
                str(row[0])
                for row in db.execute(
                    "SELECT DISTINCT key_id FROM model_artifact_attestations WHERE status='active'"
                )
            }
    if foreign_keys and foreign_keys != {key_id}:
        raise RecoveryPackageError(
            "The model trust signing key does not match every active packaged attestation."
        )
    validations["model-trust-key"] = {"valid": True, "key_id": key_id}
    compatibility = _version_compatibility(
        str(manifest.get("application_version") or ""), current_version
    )
    return {
        "manifest": manifest,
        "decoded": decoded,
        "validations": validations,
        "compatibility": compatibility,
    }


class RecoveryPackageService:
    def __init__(self, data_root: Path | str, application_version: str):
        self.data_root = Path(data_root).resolve()
        self.application_version = application_version
        self.root = self.data_root / "recovery"
        self.exports = self.root / "exports"
        self.inspections = self.root / "inspections"
        self.rehearsals = self.root / "rehearsals"
        self.rollbacks = self.root / "rollbacks"
        self.pending_root = self.root / "pending"
        for directory in (
            self.exports,
            self.inspections,
            self.rehearsals,
            self.rollbacks,
            self.pending_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    @property
    def pending_marker(self) -> Path:
        return self.pending_root / "pending.json"

    def overview(self) -> dict[str, Any]:
        self._purge_expired_inspections()
        pending = self._read_json(self.pending_marker)
        receipts = sorted((self.root / "receipts").glob("*.json"), reverse=True)[:5]
        return {
            "format": FORMAT_NAME,
            "format_version": FORMAT_VERSION,
            "application_version": self.application_version,
            "pending_restore": pending or None,
            "recent_receipts": [self._read_json(path) for path in receipts],
            "recent_rehearsals": [
                self._read_json(path)
                for path in sorted(self.rehearsals.glob("*.json"), reverse=True)[:10]
            ],
            "exports": [
                self._export_record(path)
                for path in sorted(
                    self.exports.glob("*.signalroom-recovery"), reverse=True
                )[:10]
            ],
            "rollbacks": [
                self._export_record(path)
                for path in sorted(
                    self.rollbacks.glob("*.signalroom-recovery"), reverse=True
                )[:10]
            ],
            "included": [
                {"path": path, **contract} for path, contract in COMPONENTS.items()
            ],
            "excluded": EXCLUDED,
            "contract": (
                "Recovery restores control-plane configuration and credential authority on restart. "
                "It never imports investigation records or starts retained work."
            ),
        }

    def rehearse(self, actor: str) -> dict[str, Any]:
        """Exercise the package cryptography and contracts without retaining a package."""
        password = "signalroom-local-rehearsal-" + os.urandom(32).hex()
        payload = self._build_payload(actor=actor, package_type="acceptance-rehearsal")
        package = _encrypt(payload, password)
        inspected = _validate_payload(_decrypt(package, password), self.application_version)
        receipt = {
            "id": str(uuid4()),
            "status": "pass",
            "created_at": _now(),
            "created_by": actor[:120],
            "application_version": self.application_version,
            "package_id": inspected["manifest"]["package_id"],
            "package_sha256": _sha256(package),
            "package_size": len(package),
            "components": [
                {
                    "path": item["path"],
                    "size": item["size"],
                    "sha256": item["sha256"],
                }
                for item in inspected["manifest"]["components"]
            ],
            "validations": sorted(inspected["validations"]),
            "compatible": bool(inspected["compatibility"]["compatible"]),
            "package_retained": False,
            "password_retained": False,
            "restore_staged": False,
            "live_state_changed": False,
        }
        filename = f"{receipt['created_at'].replace(':', '-')}-{receipt['id']}.json"
        _secure_write(self.rehearsals / filename, _canonical(receipt))
        for path in sorted(self.rehearsals.glob("*.json"), reverse=True)[20:]:
            path.unlink(missing_ok=True)
        return receipt

    def create(self, password: str, actor: str) -> dict[str, Any]:
        payload = self._build_payload(actor=actor, package_type="operator-backup")
        package = _encrypt(payload, password)
        package_id = payload["manifest"]["package_id"]
        filename = f"signalroom-control-plane-{package_id}.signalroom-recovery"
        path = self.exports / filename
        _secure_write(path, package)
        return {
            "package_id": package_id,
            "filename": filename,
            "sha256": _sha256(package),
            "size": len(package),
            "created_at": payload["manifest"]["created_at"],
            "download_url": f"/api/recovery/packages/{package_id}/download",
            "manifest": payload["manifest"],
        }

    def export_path(self, package_id: str, *, rollback: bool = False) -> Path:
        directory = self.rollbacks if rollback else self.exports
        matches = list(directory.glob(f"*{package_id}.signalroom-recovery"))
        if len(matches) != 1:
            raise KeyError(package_id)
        return matches[0]

    def inspect(self, package: bytes, password: str) -> dict[str, Any]:
        _validate_password(password)
        payload = _decrypt(package, password)
        inspected = _validate_payload(payload, self.application_version)
        inspection_id = str(uuid4())
        package_id = str(inspected["manifest"]["package_id"])
        expires_at = datetime.now(UTC) + timedelta(minutes=INSPECTION_LIFETIME_MINUTES)
        package_path = self.inspections / f"{inspection_id}.signalroom-recovery"
        metadata_path = self.inspections / f"{inspection_id}.json"
        _secure_write(package_path, package)
        metadata = {
            "inspection_id": inspection_id,
            "package_id": package_id,
            "package_sha256": _sha256(package),
            "created_at": _now(),
            "expires_at": expires_at.isoformat(),
            "manifest": inspected["manifest"],
            "compatibility": inspected["compatibility"],
            "validations": inspected["validations"],
        }
        _secure_write(metadata_path, _canonical(metadata))
        return {
            **metadata,
            "confirmation": f"RESTORE {package_id}",
            "restart_required": True,
            "sessions_revoked": True,
            "inspection_is_read_only": True,
        }

    def stage_restore(
        self,
        inspection_id: str,
        password: str,
        confirmation: str,
        actor: str,
    ) -> dict[str, Any]:
        if self.pending_marker.exists():
            raise RecoveryPackageError("A restore is already pending. Cancel it or restart SignalRoom.")
        metadata_path = self.inspections / f"{inspection_id}.json"
        package_path = self.inspections / f"{inspection_id}.signalroom-recovery"
        metadata = self._read_json(metadata_path)
        if not metadata or not package_path.exists():
            raise RecoveryPackageError("The read-only inspection expired or was not found.")
        try:
            if datetime.fromisoformat(str(metadata["expires_at"])) <= datetime.now(UTC):
                raise RecoveryPackageError("The read-only inspection expired. Inspect the package again.")
        except (KeyError, ValueError) as exc:
            raise RecoveryPackageError("The inspection record is invalid.") from exc
        expected = f"RESTORE {metadata['package_id']}"
        if confirmation.strip() != expected:
            raise RecoveryPackageError(f"Type {expected} exactly to stage this restore.")
        package = package_path.read_bytes()
        if _sha256(package) != metadata.get("package_sha256"):
            raise RecoveryPackageError("The inspected encrypted package changed after validation.")
        inspected = _validate_payload(_decrypt(package, password), self.application_version)
        if not inspected["compatibility"]["compatible"]:
            raise RecoveryPackageError("This package is not compatible with the running SignalRoom release.")
        if inspected["manifest"]["package_id"] != metadata["package_id"]:
            raise RecoveryPackageError("The decrypted package no longer matches its inspection record.")

        checkpoint_payload = self._build_payload(
            actor=actor,
            package_type="automatic-pre-restore-checkpoint",
            parent_package_id=str(metadata["package_id"]),
        )
        checkpoint = _encrypt(checkpoint_payload, password)
        checkpoint_id = checkpoint_payload["manifest"]["package_id"]
        checkpoint_name = f"pre-restore-{checkpoint_id}.signalroom-recovery"
        checkpoint_path = self.rollbacks / checkpoint_name
        _secure_write(checkpoint_path, checkpoint)

        stage = self.pending_root / str(metadata["package_id"])
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True, exist_ok=False)
        components = []
        for name, value in inspected["decoded"].items():
            target = stage / _safe_component_path(name)
            _secure_write(target, value)
            components.append({"path": name, "size": len(value), "sha256": _sha256(value)})
        marker = {
            "status": "pending-restart",
            "package_id": metadata["package_id"],
            "package_version": inspected["manifest"]["application_version"],
            "inspection_id": inspection_id,
            "staged_at": _now(),
            "staged_by": actor,
            "checkpoint": {
                "package_id": checkpoint_id,
                "filename": checkpoint_name,
                "sha256": _sha256(checkpoint),
                "password_contract": "same-password-as-restored-package",
            },
            "components": components,
            "restart_required": True,
            "mutation_freeze": True,
        }
        _secure_write(self.pending_marker, _canonical(marker))
        return marker

    def cancel_pending(self, actor: str) -> dict[str, Any]:
        marker = self._read_json(self.pending_marker)
        if not marker:
            raise RecoveryPackageError("No recovery restore is pending.")
        stage = self.pending_root / str(marker.get("package_id") or "")
        resolved = stage.resolve()
        if resolved.parent == self.pending_root.resolve() and resolved.exists():
            shutil.rmtree(resolved)
        self.pending_marker.unlink(missing_ok=True)
        return {
            "status": "cancelled",
            "package_id": marker.get("package_id"),
            "cancelled_at": _now(),
            "cancelled_by": actor,
            "checkpoint_retained": marker.get("checkpoint"),
        }

    def delete_export(self, package_id: str) -> None:
        self.export_path(package_id).unlink()

    def _build_payload(
        self,
        *,
        actor: str,
        package_type: str,
        parent_package_id: str = "",
    ) -> dict[str, Any]:
        files: dict[str, bytes] = {}
        for name in COMPONENTS:
            path = self.data_root / name
            if not path.exists():
                if COMPONENTS[name]["required"]:
                    raise RecoveryPackageError(f"Required control-plane component {name} is missing.")
                continue
            if name.endswith(".db"):
                files[name] = _sqlite_snapshot(path, sanitize_auth=name == "auth.db")
            else:
                files[name] = path.read_bytes()
            if len(files[name]) > MAX_COMPONENT_BYTES:
                raise RecoveryPackageError(f"Control-plane component {name} exceeds its safety limit.")
        components = [
            {
                "path": name,
                "category": COMPONENTS[name]["category"],
                "description": COMPONENTS[name]["description"],
                "size": len(value),
                "sha256": _sha256(value),
            }
            for name, value in files.items()
        ]
        manifest = {
            "application": "SignalRoom",
            "application_version": self.application_version,
            "schema_version": FORMAT_VERSION,
            "package_id": str(uuid4()),
            "package_type": package_type,
            "parent_package_id": parent_package_id,
            "created_at": _now(),
            "created_by": actor[:120],
            "components": components,
            "excluded": EXCLUDED,
            "restore_contract": {
                "apply": "validated-on-next-start",
                "sessions": "not-exported-and-revoked",
                "external_secrets": "not-included",
                "retained_work": "not-started-by-restore",
                "compatibility": "same-major-minor",
            },
        }
        payload = {
            "manifest": manifest,
            "files": {name: base64.b64encode(value).decode("ascii") for name, value in files.items()},
        }
        _validate_payload(payload, self.application_version)
        return payload

    def _purge_expired_inspections(self) -> None:
        now = datetime.now(UTC)
        for metadata_path in self.inspections.glob("*.json"):
            metadata = self._read_json(metadata_path)
            try:
                expired = datetime.fromisoformat(str(metadata.get("expires_at"))) <= now
            except (TypeError, ValueError):
                expired = True
            if expired:
                inspection_id = metadata_path.stem
                metadata_path.unlink(missing_ok=True)
                (self.inspections / f"{inspection_id}.signalroom-recovery").unlink(missing_ok=True)

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _export_record(path: Path) -> dict[str, Any]:
        stat = path.stat()
        package_id = path.stem[-36:]
        return {
            "package_id": package_id,
            "filename": path.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
            "sha256": _sha256(path.read_bytes()),
        }


def apply_pending_restore(data_root: Path | str) -> dict[str, Any] | None:
    """Apply a fully inspected restore before any SignalRoom store opens its files."""
    data = Path(data_root).resolve()
    root = data / "recovery"
    pending_root = root / "pending"
    marker_path = pending_root / "pending.json"
    if not marker_path.exists():
        return None
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("SignalRoom found an unreadable pending recovery marker.") from exc
    package_id = str(marker.get("package_id") or "")
    stage = (pending_root / package_id).resolve()
    if not package_id or stage.parent != pending_root.resolve() or not stage.is_dir():
        raise RuntimeError("SignalRoom found an unsafe pending recovery stage path.")
    components = marker.get("components")
    if not isinstance(components, list):
        raise RuntimeError("SignalRoom found an invalid pending recovery component inventory.")
    staged: dict[str, bytes] = {}
    for entry in components:
        try:
            name = _safe_component_path(str(entry["path"]))
            value = (stage / name).read_bytes()
        except (KeyError, OSError, RecoveryPackageError) as exc:
            raise RuntimeError("A staged recovery component is missing or unsafe.") from exc
        if len(value) != int(entry.get("size") or -1) or _sha256(value) != entry.get("sha256"):
            raise RuntimeError(f"Staged recovery component {name} failed its startup digest check.")
        staged[name] = value
    _validate_payload(
        {
            "manifest": {
                "application": "SignalRoom",
                "application_version": str(marker.get("package_version") or ""),
                "schema_version": FORMAT_VERSION,
                "package_id": package_id,
                "components": [
                    {
                        "path": name,
                        "size": len(value),
                        "sha256": _sha256(value),
                    }
                    for name, value in staged.items()
                ],
            },
            "files": {name: base64.b64encode(value).decode("ascii") for name, value in staged.items()},
        },
        str(marker.get("package_version") or ""),
    )

    originals = Path(tempfile.mkdtemp(prefix="signalroom-restore-originals-", dir=root))
    replaced: list[str] = []
    try:
        for name in staged:
            target = data / name
            if target.exists():
                shutil.copy2(target, originals / name)
        for name, value in staged.items():
            _secure_write(data / name, value)
            replaced.append(name)
        # Defense in depth: old sessions cannot survive a foreign package that bypassed export sanitation.
        if "auth.db" in staged:
            with sqlite3.connect(data / "auth.db") as db:
                for table in ("auth_sessions", "auth_login_attempts", "auth_oidc_transactions"):
                    db.execute(f"DELETE FROM {table}")
        receipt = {
            "status": "applied",
            "package_id": package_id,
            "applied_at": _now(),
            "staged_at": marker.get("staged_at"),
            "staged_by": marker.get("staged_by"),
            "components": list(staged),
            "checkpoint": marker.get("checkpoint"),
            "sessions_revoked": True,
        }
        receipts = root / "receipts"
        receipts.mkdir(parents=True, exist_ok=True)
        receipt_path = receipts / (
            f"{receipt['applied_at'].replace(':', '-')}-{package_id}.json"
        )
        _secure_write(receipt_path, _canonical(receipt))
        marker_path.unlink(missing_ok=True)
        shutil.rmtree(stage)
        return receipt
    except Exception:
        for name in reversed(replaced):
            backup = originals / name
            if backup.exists():
                _secure_write(data / name, backup.read_bytes())
        raise
    finally:
        shutil.rmtree(originals, ignore_errors=True)
