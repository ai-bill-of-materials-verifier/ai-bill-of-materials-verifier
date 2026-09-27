from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, BinaryIO

from .hashers import algorithm
from .manifest import (
    _build_levels,
    _leaf_hash,
    canonical_json,
    create_manifest,
    expected_chunk_count,
    file_id,
    proof_for_index,
    verify_proof,
)


class VerifyMode(StrEnum):
    FULL = "full"
    SAMPLED = "sampled"
    CACHED = "cached"
    INCREMENTAL = "incremental"
    STREAMING = "streaming"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    mode: VerifyMode
    reason: str
    checked_chunks: int
    detection_probability: float | None = None


def detection_probability(fraction_tampered: float, samples: int) -> float:
    if not 0.0 <= fraction_tampered <= 1.0:
        raise ValueError("fraction_tampered must be in [0, 1]")
    if samples < 0:
        raise ValueError("samples must be non-negative")
    return 1.0 - (1.0 - fraction_tampered) ** samples


def _deterministic_sample_indices(count: int, k: int, seed: int) -> list[int]:
    if k <= 0:
        return []
    if k >= count:
        return list(range(count))
    chosen: set[int] = set()
    counter = 0
    while len(chosen) < k:
        digest = hashlib.sha256(f"{seed}:{counter}".encode("ascii")).digest()
        chosen.add(int.from_bytes(digest[:8], "big") % count)
        counter += 1
    return sorted(chosen)


def _cache_key(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path.resolve()),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "file_id": file_id(path),
        "root": manifest["root"],
        "alg": manifest["alg"],
    }


def _cache_secret(cache_file: Path) -> bytes:
    secret_path = cache_file.with_suffix(cache_file.suffix + ".key")
    if secret_path.exists():
        return secret_path.read_bytes()
    secret = secrets.token_bytes(32)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_bytes(secret)
    return secret


def _cache_mac(secret: bytes, key: dict[str, Any]) -> str:
    return hmac.new(secret, canonical_json(key), "sha256").hexdigest()


def _trusted_cache_key(cache_file: Path) -> dict[str, Any] | None:
    if not cache_file.exists():
        return None
    record = json.loads(cache_file.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or not isinstance(record.get("key"), dict):
        return None
    key = record["key"]
    if not isinstance(key, dict):
        return None
    secret = _cache_secret(cache_file)
    expected = _cache_mac(secret, key)
    if not hmac.compare_digest(str(record.get("mac", "")), expected):
        return None
    return key


def write_cache(path: str | Path, manifest: dict[str, Any], cache_file: str | Path) -> None:
    p = Path(path)
    cf = Path(cache_file)
    key = _cache_key(p, manifest)
    secret = _cache_secret(cf)
    cf.parent.mkdir(parents=True, exist_ok=True)
    cf.write_text(
        json.dumps({"key": key, "mac": _cache_mac(secret, key)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def check_cache(path: str | Path, manifest: dict[str, Any], cache_file: str | Path) -> bool:
    cf = Path(cache_file)
    record_key = _trusted_cache_key(cf)
    if record_key is None:
        return False
    key = _cache_key(Path(path), manifest)
    return record_key == key


def verify_full(
    path: str | Path, manifest: dict[str, Any], *, threads: int = 1
) -> VerificationResult:
    actual = create_manifest(
        Path(path),
        chunk_size=int(manifest["chunk_size"]),
        alg=str(manifest["alg"]),
        threads=threads,
    )
    if actual["size"] != manifest["size"]:
        return VerificationResult(
            False, VerifyMode.FULL, "size mismatch", len(actual.get("leaves", []))
        )
    if actual["root"] != manifest["root"]:
        return VerificationResult(
            False, VerifyMode.FULL, "root mismatch", len(actual.get("leaves", []))
        )
    return VerificationResult(True, VerifyMode.FULL, "ok", len(actual.get("leaves", [])))


def verify_sampled(
    path: str | Path,
    manifest: dict[str, Any],
    *,
    samples: int = 8,
    seed: int = 0,
    fraction_tampered: float = 0.01,
) -> VerificationResult:
    p = Path(path)
    size = p.stat().st_size
    if size != int(manifest["size"]):
        return VerificationResult(False, VerifyMode.SAMPLED, "size mismatch", 0)
    count = expected_chunk_count(size, int(manifest["chunk_size"]))
    if count != len(manifest["leaves"]):
        return VerificationResult(False, VerifyMode.SAMPLED, "chunk count mismatch", 0)
    k = min(samples, count)
    indices = _deterministic_sample_indices(count, k, seed)
    alg = str(manifest["alg"])
    chunk_size = int(manifest["chunk_size"])
    checked = 0
    with p.open("rb") as fh:
        for idx in indices:
            fh.seek(idx * chunk_size)
            leaf = _leaf_hash(fh.read(chunk_size), alg).hex()
            proof = proof_for_index(manifest, idx)
            if leaf != proof.leaf or not verify_proof(
                leaf, str(manifest["root"]), proof.siblings, alg
            ):
                return VerificationResult(
                    False,
                    VerifyMode.SAMPLED,
                    f"sampled chunk {idx} mismatch",
                    checked + 1,
                    detection_probability(fraction_tampered, k),
                )
            checked += 1
    return VerificationResult(
        True, VerifyMode.SAMPLED, "ok", checked, detection_probability(fraction_tampered, k)
    )


def verify_cached(
    path: str | Path, manifest: dict[str, Any], cache_file: str | Path, *, threads: int = 1
) -> VerificationResult:
    if check_cache(path, manifest, cache_file):
        return VerificationResult(True, VerifyMode.CACHED, "cache hit", 0)
    result = verify_full(path, manifest, threads=threads)
    if result.ok:
        write_cache(path, manifest, cache_file)
        return VerificationResult(True, VerifyMode.CACHED, "cache refreshed", result.checked_chunks)
    return VerificationResult(False, VerifyMode.CACHED, result.reason, result.checked_chunks)


def _changed_chunk_indices(
    changed_ranges: list[tuple[int, int]], size: int, chunk_size: int
) -> list[int]:
    indices: set[int] = set()
    for start, length in changed_ranges:
        if start < 0 or length < 0:
            raise ValueError("changed ranges must be non-negative")
        if length == 0:
            continue
        end_exclusive = min(size, start + length)
        if start >= size or end_exclusive <= start:
            continue
        first = start // chunk_size
        last = (end_exclusive - 1) // chunk_size
        indices.update(range(first, last + 1))
    return sorted(indices)


def verify_incremental(
    path: str | Path,
    manifest: dict[str, Any],
    cache_file: str | Path,
    *,
    changed_ranges: list[tuple[int, int]] | None = None,
) -> VerificationResult:
    p = Path(path)
    cf = Path(cache_file)
    if check_cache(p, manifest, cf):
        return VerificationResult(True, VerifyMode.INCREMENTAL, "cache hit", 0)

    trusted_key = _trusted_cache_key(cf)
    if trusted_key is None:
        result = verify_full(p, manifest)
        if result.ok:
            write_cache(p, manifest, cf)
        return VerificationResult(
            result.ok, VerifyMode.INCREMENTAL, result.reason, result.checked_chunks
        )

    current_size = p.stat().st_size
    expected_size = int(manifest["size"])
    if current_size != expected_size or int(trusted_key.get("size", -1)) != expected_size:
        return VerificationResult(False, VerifyMode.INCREMENTAL, "size mismatch", 0)
    if trusted_key.get("root") != manifest.get("root") or trusted_key.get("alg") != manifest.get(
        "alg"
    ):
        return VerificationResult(False, VerifyMode.INCREMENTAL, "cache manifest mismatch", 0)
    if changed_ranges is None:
        result = verify_full(p, manifest)
        if result.ok:
            write_cache(p, manifest, cf)
        return VerificationResult(
            result.ok, VerifyMode.INCREMENTAL, result.reason, result.checked_chunks
        )

    chunk_size = int(manifest["chunk_size"])
    alg = str(manifest["alg"])
    leaves = [str(leaf) for leaf in manifest["leaves"]]
    indices = _changed_chunk_indices(changed_ranges, current_size, chunk_size)
    with p.open("rb") as fh:
        for idx in indices:
            fh.seek(idx * chunk_size)
            leaves[idx] = _leaf_hash(fh.read(chunk_size), alg).hex()
    root = recompute_root_from_leaves(leaves, alg)
    if root != manifest["root"]:
        return VerificationResult(
            False, VerifyMode.INCREMENTAL, "changed chunk root mismatch", len(indices)
        )
    write_cache(p, manifest, cf)
    return VerificationResult(True, VerifyMode.INCREMENTAL, "changed chunks match", len(indices))


class VerifiedReader:
    def __init__(self, file_obj: BinaryIO, manifest: dict[str, Any]) -> None:
        self._fh = file_obj
        self._alg = str(manifest["alg"])
        self._chunk_size = int(manifest["chunk_size"])
        self._expected_size = int(manifest.get("size", -1))
        self._leaves = [str(leaf) for leaf in manifest["leaves"]]
        self._chunk_index = 0
        self._buffer = b""
        self._offset = 0
        self._closed = False

    def __enter__(self) -> VerifiedReader:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        self._fh.close()

    def _load_next_chunk(self) -> bool:
        chunk = self._fh.read(self._chunk_size)
        if not chunk:
            return False
        if self._chunk_index >= len(self._leaves):
            raise OSError("stream has extra chunk")
        leaf = _leaf_hash(chunk, self._alg).hex()
        if leaf != self._leaves[self._chunk_index]:
            raise OSError(f"stream chunk {self._chunk_index} failed verification")
        self._chunk_index += 1
        self._buffer = chunk
        self._offset = 0
        return True

    def read(self, size: int = -1) -> bytes:
        if self._closed:
            raise ValueError("read of closed file")
        out = bytearray()
        while size < 0 or len(out) < size:
            if self._offset >= len(self._buffer) and not self._load_next_chunk():
                break
            need = len(self._buffer) - self._offset if size < 0 else size - len(out)
            take = min(need, len(self._buffer) - self._offset)
            out += self._buffer[self._offset : self._offset + take]
            self._offset += take
        return bytes(out)

    def finish(self) -> VerificationResult:
        while self.read(self._chunk_size):
            pass
        if self._expected_size == 0 and self._chunk_index == 0:
            return VerificationResult(True, VerifyMode.STREAMING, "ok", 1)
        if self._chunk_index != len(self._leaves):
            return VerificationResult(
                False, VerifyMode.STREAMING, "stream ended early", self._chunk_index
            )
        return VerificationResult(True, VerifyMode.STREAMING, "ok", self._chunk_index)


def open_verified(path: str | Path, manifest: dict[str, Any]) -> VerifiedReader:
    return VerifiedReader(Path(path).open("rb"), manifest)


def verify_streaming(path: str | Path, manifest: dict[str, Any]) -> VerificationResult:
    try:
        with open_verified(path, manifest) as reader:
            return reader.finish()
    except OSError as exc:
        return VerificationResult(False, VerifyMode.STREAMING, str(exc), 0)


def verify(
    path: str | Path,
    manifest: dict[str, Any],
    *,
    mode: VerifyMode | str = VerifyMode.FULL,
    samples: int = 8,
    seed: int = 0,
    cache_file: str | Path | None = None,
    threads: int = 1,
    changed_ranges: list[tuple[int, int]] | None = None,
) -> VerificationResult:
    selected = VerifyMode(mode)
    if selected is VerifyMode.FULL:
        return verify_full(path, manifest, threads=threads)
    if selected is VerifyMode.SAMPLED:
        return verify_sampled(path, manifest, samples=samples, seed=seed)
    if selected is VerifyMode.CACHED:
        return verify_cached(
            path,
            manifest,
            cache_file
            or Path(os.getenv("AI_BILL_OF_MATERIALS_CACHE", ".bill-of-materials-cache.json")),
            threads=threads,
        )
    if selected is VerifyMode.INCREMENTAL:
        return verify_incremental(
            path,
            manifest,
            cache_file
            or Path(os.getenv("AI_BILL_OF_MATERIALS_CACHE", ".bill-of-materials-cache.json")),
            changed_ranges=changed_ranges,
        )
    if selected is VerifyMode.STREAMING:
        return verify_streaming(path, manifest)
    raise ValueError(f"unsupported mode {mode}")


def recompute_root_from_leaves(leaves_hex: list[str], alg: str) -> str:
    leaves = [bytes.fromhex(leaf) for leaf in leaves_hex]
    return _build_levels(leaves, algorithm(alg).name)[-1][0].hex()
