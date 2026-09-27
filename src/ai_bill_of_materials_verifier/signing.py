from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
except ImportError:  # pragma: no cover - native Windows ARM64 dependency skip path.
    InvalidSignature: Any = ValueError
    hashes: Any = None
    serialization: Any = None
    ec: Any = None
else:
    InvalidSignature = _InvalidSignature
    hashes = _hashes
    serialization = _serialization
    ec = _ec

from .manifest import canonical_json

DSSE_PAE_PREFIX = b"DSSEv1"


def crypto_available() -> bool:
    return ec is not None and hashes is not None and serialization is not None


def _require_crypto() -> None:
    if not crypto_available():
        raise RuntimeError("cryptography is unavailable on this platform")


def generate_private_key() -> Any:
    _require_crypto()
    return ec.generate_private_key(ec.SECP256R1())


def save_private_key(key: Any, path: str | Path) -> None:
    _require_crypto()
    data = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    Path(path).write_bytes(data)


def save_public_key(key: Any, path: str | Path) -> None:
    _require_crypto()
    data = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(path).write_bytes(data)


def load_private_key(path: str | Path) -> Any:
    _require_crypto()
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("expected EC private key")
    return key


def load_public_key(path: str | Path) -> Any:
    _require_crypto()
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("expected EC public key")
    return key


def sign_bytes(data: bytes, key: Any) -> str:
    _require_crypto()
    return base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode("ascii")


def verify_bytes(data: bytes, signature_b64: str, key: Any) -> bool:
    _require_crypto()
    try:
        key.verify(base64.b64decode(signature_b64), data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_manifest(manifest: dict[str, Any], private_key: str | Path) -> str:
    return sign_bytes(canonical_json(manifest), load_private_key(private_key))


def verify_manifest_signature(
    manifest: dict[str, Any], signature_b64: str, public_key: str | Path
) -> bool:
    return verify_bytes(canonical_json(manifest), signature_b64, load_public_key(public_key))


def _pae(payload_type: str, payload: bytes) -> bytes:
    return b" ".join(
        [
            DSSE_PAE_PREFIX,
            str(len(payload_type)).encode(),
            payload_type.encode(),
            str(len(payload)).encode(),
            payload,
        ]
    )


def dsse_envelope(
    payload: dict[str, Any], payload_type: str, private_key: str | Path, *, keyid: str = "local"
) -> dict[str, Any]:
    payload_bytes = canonical_json(payload)
    sig = sign_bytes(_pae(payload_type, payload_bytes), load_private_key(private_key))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": sig}],
    }


def verify_dsse(
    envelope: dict[str, Any], public_key: str | Path
) -> tuple[bool, dict[str, Any] | None]:
    payload_type = str(envelope.get("payloadType", ""))
    payload_raw = base64.b64decode(str(envelope.get("payload", "")))
    signatures = envelope.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        return False, None
    key = load_public_key(public_key)
    ok = any(
        isinstance(sig, dict)
        and verify_bytes(_pae(payload_type, payload_raw), str(sig.get("sig", "")), key)
        for sig in signatures
    )
    if not ok:
        return False, None
    payload = json.loads(payload_raw.decode("utf-8"))
    if not isinstance(payload, dict):
        return False, None
    return True, payload


def signature_to_cosign_blob(signature_b64: str, path: str | Path) -> None:
    Path(path).write_text(signature_b64 + "\n", encoding="utf-8")
