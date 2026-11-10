"""Signing and verification helpers.

Every result a scanner sends is signed with that scanner's Ed25519 private key.
The server holds only the public keys, so a compromised server cannot forge
results on behalf of a device.

Signatures cover a *canonical* JSON encoding of the payload (sorted keys, no
whitespace), so the same logical payload always produces the same bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for signing and hashing.

    Raises ValueError for NaN/Infinity, which have no stable JSON form.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def fingerprint(key: Ed25519PublicKey) -> str:
    """Short, human-checkable identifier for a public key (used in handover records)."""
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_hex(raw)[:16]


def sign_payload(key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    return base64.b64encode(key.sign(canonical_json(payload))).decode("ascii")


def verify_payload(key: Ed25519PublicKey, payload: dict[str, Any], signature: str) -> bool:
    try:
        sig = base64.b64decode(signature, validate=True)
        key.verify(sig, canonical_json(payload))
    except (InvalidSignature, ValueError, binascii.Error, TypeError):
        return False
    return True
