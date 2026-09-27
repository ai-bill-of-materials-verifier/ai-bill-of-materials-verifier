from __future__ import annotations

import hashlib
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:
    import blake3 as _blake3_import
except ImportError:  # pragma: no cover
    _blake3: Any = None
else:
    _blake3 = _blake3_import

DigestFactory = Callable[[bytes], bytes]


@dataclass(frozen=True, slots=True)
class HashAlgorithm:
    name: str
    digest_size: int
    digest: DigestFactory


def blake3_available() -> bool:
    return _blake3 is not None


def _blake3_digest(data: bytes) -> bytes:
    if _blake3 is None:  # pragma: no cover
        raise RuntimeError("BLAKE3 is not available on this platform")
    return bytes(_blake3.blake3(data, max_threads=_blake3.blake3.AUTO).digest())


def _sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def algorithm(name: str = "blake3") -> HashAlgorithm:
    normalized = name.lower().replace("-", "")
    if normalized == "blake3":
        if _blake3 is None:
            warnings.warn(
                "BLAKE3 unavailable; falling back to SHA-256", RuntimeWarning, stacklevel=2
            )
            return HashAlgorithm("sha256", hashlib.sha256().digest_size, _sha256_digest)
        return HashAlgorithm("blake3", 32, _blake3_digest)
    if normalized == "sha256":
        return HashAlgorithm("sha256", hashlib.sha256().digest_size, _sha256_digest)
    raise ValueError(f"unsupported hash algorithm: {name}")


def hash_bytes(data: bytes, alg: str = "blake3") -> str:
    return algorithm(alg).digest(data).hex()
