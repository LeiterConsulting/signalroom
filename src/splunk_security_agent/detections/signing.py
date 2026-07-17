from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class DetectionSigningKey:
    """Persistent local provenance key for repository-ready detection changes."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _private_key(self) -> Ed25519PrivateKey:
        if self.path.exists():
            value = serialization.load_pem_private_key(
                self.path.read_bytes(),
                password=None,
            )
            if not isinstance(value, Ed25519PrivateKey):
                raise ValueError("Detection signing key is not an Ed25519 private key")
            return value
        key = Ed25519PrivateKey.generate()
        payload = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return self._private_key()
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
        return key

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key().public_key()

    def public_pem(self) -> bytes:
        return self.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def key_id(self) -> str:
        value = self.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(value).hexdigest()

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._private_key().sign(payload)).decode("ascii")
