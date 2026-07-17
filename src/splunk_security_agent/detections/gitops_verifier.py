from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALLOWED_DETECTION_FILES = {
    "README.md",
    "detection.json",
    "detection.yml",
    "manifest.json",
    "manifest.sig",
    "savedsearches.conf",
}
SIGNED_DETECTION_FILES = ALLOWED_DETECTION_FILES - {"manifest.json", "manifest.sig"}
REQUIRED_SAVED_SEARCH_SETTINGS = {
    "action.notable": "0",
    "disabled": "1",
    "enableSched": "0",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_FILES = 100
MAX_ARCHIVE_MEMBER_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024


class VerificationError(ValueError):
    pass


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative(value: str) -> Path:
    item = PurePosixPath(value)
    if item.is_absolute() or ".." in item.parts or not item.parts:
        raise VerificationError(f"Unsafe repository path in manifest: {value}")
    return Path(*item.parts)


def _public_key(root: Path) -> tuple[Ed25519PublicKey, str]:
    path = root / ".signalroom" / "signalroom.pub"
    if not path.is_file() or path.is_symlink():
        raise VerificationError("Missing .signalroom/signalroom.pub")
    try:
        value = serialization.load_pem_public_key(path.read_bytes())
    except (ValueError, TypeError) as exc:
        raise VerificationError("SignalRoom public key is invalid") from exc
    if not isinstance(value, Ed25519PublicKey):
        raise VerificationError("SignalRoom public key is not Ed25519")
    der = value.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return value, _sha256(der)


def _saved_search_settings(value: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in value.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, item = line.split("=", 1)
        settings[key.strip()] = item.strip()
    return settings


def _verify_manifest(
    root: Path,
    path: Path,
    public_key: Ed25519PublicKey,
    key_id: str,
    trusted_key_sha256: str,
) -> dict[str, Any]:
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise VerificationError(f"Detection manifest escapes repository root: {path}") from exc
    if path.is_symlink():
        raise VerificationError(f"{path}: symbolic-link manifests are not allowed")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise VerificationError(f"{path}: manifest must be a JSON object")
    if manifest.get("schema_version") != "signalroom-detection-git-change/v1":
        raise VerificationError(f"{path}: unsupported manifest schema")
    signing = manifest.get("signing") or {}
    if signing.get("algorithm") != "Ed25519" or signing.get("key_id") != key_id:
        raise VerificationError(f"{path}: signing identity does not match public key")
    if trusted_key_sha256 and key_id != trusted_key_sha256:
        raise VerificationError(
            f"{path}: signing key {key_id} is not the trusted repository key"
        )
    if signing.get("signature_file") != "manifest.sig":
        raise VerificationError(f"{path}: unsupported manifest signature path")
    signature_path = path.parent / "manifest.sig"
    if not signature_path.is_file() or signature_path.is_symlink():
        raise VerificationError(f"{path}: missing manifest signature")
    try:
        signature = base64.b64decode(
            signature_path.read_text(encoding="ascii").strip(),
            validate=True,
        )
        public_key.verify(signature, _canonical(manifest))
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError(f"{path}: manifest signature is invalid") from exc

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise VerificationError(f"{path}: signed file inventory is missing")
    if set(files) != SIGNED_DETECTION_FILES:
        raise VerificationError(f"{path}: signed file inventory does not match policy")
    for name, expected in files.items():
        relative = _safe_relative(str(name))
        target = path.parent / relative
        if not target.is_file() or target.is_symlink():
            raise VerificationError(f"{path}: signed file is missing: {name}")
        if not SHA256.fullmatch(str(expected)) or _sha256(target.read_bytes()) != expected:
            raise VerificationError(f"{path}: signed file hash mismatch: {name}")
    actual_files = {
        item.relative_to(path.parent).as_posix()
        for item in path.parent.rglob("*")
        if item.is_file() or item.is_symlink()
    }
    if actual_files != ALLOWED_DETECTION_FILES:
        extra = sorted(actual_files - ALLOWED_DETECTION_FILES)
        missing = sorted(ALLOWED_DETECTION_FILES - actual_files)
        raise VerificationError(
            f"{path}: unexpected detection files; extra={extra}, missing={missing}"
        )

    review = manifest.get("review") or {}
    gate = manifest.get("promotion_gate") or {}
    policy = manifest.get("repository_policy") or {}
    authority = manifest.get("authority") or {}
    try:
        minimum_score = int(policy.get("minimum_gate_score", 80))
        gate_score = int(gate.get("score", 0))
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"{path}: gate score policy is invalid") from exc
    if review.get("status") != "approved":
        raise VerificationError(f"{path}: detection review is not approved")
    if (
        gate.get("status") != "pass"
        or gate_score < minimum_score
        or not gate.get("accepted_at")
    ):
        raise VerificationError(f"{path}: accepted promotion gate policy failed")
    if gate.get("content_sha256") != manifest.get("content_sha256"):
        raise VerificationError(f"{path}: gate is not bound to detection content")
    if any(
        authority.get(name) is not False
        for name in ("deploys_to_splunk", "enables_saved_search", "contains_raw_results")
    ):
        raise VerificationError(f"{path}: repository artifact exceeds export authority")

    expected_content = str(manifest.get("content_sha256") or "")
    if not SHA256.fullmatch(expected_content):
        raise VerificationError(f"{path}: approved content hash is invalid")
    content_path = path.parent / "detection.json"
    content = json.loads(content_path.read_text(encoding="utf-8"))
    if not isinstance(content, dict) or _sha256(_canonical(content)) != expected_content:
        raise VerificationError(f"{path}: canonical detection content hash is invalid")
    detection_yaml = (path.parent / "detection.yml").read_text(encoding="utf-8")
    content_binding = re.compile(
        rf'^content_sha256:\s*"{re.escape(expected_content)}"\s*$',
        re.MULTILINE,
    )
    if not content_binding.search(detection_yaml):
        raise VerificationError(f"{path}: detection.yml content hash is not bound")
    saved_search = (path.parent / "savedsearches.conf").read_text(encoding="utf-8")
    settings = _saved_search_settings(saved_search)
    for name, expected in REQUIRED_SAVED_SEARCH_SETTINGS.items():
        if settings.get(name) != expected:
            raise VerificationError(
                f"{path}: saved search policy requires {name} = {expected}"
            )
    return {
        "detection_id": manifest.get("detection_id"),
        "version": manifest.get("version"),
        "content_sha256": expected_content,
        "gate_id": gate.get("id"),
        "gate_score": gate.get("score"),
        "key_id": key_id,
    }


def verify_change_bundle(
    root: Path | str,
    trusted_key_sha256: str = "",
) -> dict[str, Any]:
    path = Path(root).resolve()
    trusted = trusted_key_sha256.strip().lower()
    if trusted and not SHA256.fullmatch(trusted):
        raise VerificationError("Trusted key fingerprint must be a lowercase SHA-256")
    if not path.is_dir():
        raise VerificationError(f"Repository change root is not a directory: {path}")
    public_key, key_id = _public_key(path)
    manifests = sorted(path.glob("detections/*/manifest.json"))
    if not manifests:
        raise VerificationError("No SignalRoom detection manifests were found")
    results = [
        _verify_manifest(path, item, public_key, key_id, trusted)
        for item in manifests
    ]
    return {
        "valid": True,
        "trust": "pinned" if trusted else "embedded-key-only",
        "key_id": key_id,
        "detections": results,
    }


def _safe_extract(archive: Path, target: Path) -> None:
    with zipfile.ZipFile(archive) as value:
        members = value.infolist()
        names = [item.filename for item in members]
        if len(members) > MAX_ARCHIVE_FILES:
            raise VerificationError("Archive contains too many members")
        if len(set(names)) != len(names):
            raise VerificationError("Archive contains duplicate member names")
        total_size = sum(item.file_size for item in members)
        if total_size > MAX_ARCHIVE_BYTES:
            raise VerificationError("Archive expands beyond the verification limit")
        for item in members:
            relative = PurePosixPath(item.filename)
            if (
                "\\" in item.filename
                or relative.is_absolute()
                or ".." in relative.parts
                or item.file_size > MAX_ARCHIVE_MEMBER_BYTES
            ):
                raise VerificationError(f"Unsafe archive member: {item.filename}")
        value.extractall(target)


def verify_path(
    path: Path | str,
    trusted_key_sha256: str = "",
) -> dict[str, Any]:
    value = Path(path)
    if value.is_dir():
        return verify_change_bundle(value, trusted_key_sha256)
    if value.is_file() and value.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(prefix="signalroom-verify-") as directory:
            root = Path(directory)
            _safe_extract(value, root)
            return verify_change_bundle(root, trusted_key_sha256)
    raise VerificationError("Verification target must be a repository directory or ZIP")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a signed SignalRoom detection change without network access"
    )
    parser.add_argument("path", help="Repository root or SignalRoom Git change ZIP")
    parser.add_argument(
        "--trusted-key-sha256",
        default=os.getenv("SIGNALROOM_TRUSTED_KEY_SHA256", ""),
        help="Pinned Ed25519 public-key SHA-256 (or SIGNALROOM_TRUSTED_KEY_SHA256)",
    )
    return parser


def run() -> None:
    args = build_parser().parse_args()
    try:
        result = verify_path(args.path, args.trusted_key_sha256)
    except (OSError, json.JSONDecodeError, VerificationError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    run()
