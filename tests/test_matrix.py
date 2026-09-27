from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from ai_bill_of_materials_verifier.loader import load_bytes_streaming, verify_before_load
from ai_bill_of_materials_verifier.manifest import (
    create_manifest,
    proof_for_index,
    verify_proof,
    write_manifest,
)
from ai_bill_of_materials_verifier.verify import (
    check_cache,
    detection_probability,
    verify,
    write_cache,
)

PAYLOAD_CASES = [
    b"",
    b"a",
    b"ab",
    b"abcde",
    bytes(range(16)),
    bytes(range(31)),
    bytes(range(64)),
    bytes(range(128)),
    b"model" * 73,
    bytes(range(251)) * 3,
    b"\x00\xff" * 513,
    bytes((i * 17) % 256 for i in range(2049)),
]
CHUNK_SIZES = [1, 2, 3, 7, 16, 64]


@pytest.mark.parametrize("payload", PAYLOAD_CASES)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_manifest_verification_matrix(tmp_path: Path, payload: bytes, chunk_size: int) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(payload)
    manifest = create_manifest(target, chunk_size=chunk_size, alg="sha256")
    expected_chunks = 1 if not payload else math.ceil(len(payload) / chunk_size)
    assert len(manifest["leaves"]) == expected_chunks
    assert verify(target, manifest, mode="full").ok
    assert verify(target, manifest, mode="sampled", samples=expected_chunks, seed=42).ok
    assert verify(target, manifest, mode="streaming").ok


@pytest.mark.parametrize("payload", PAYLOAD_CASES[1:])
def test_proofs_reject_wrong_roots(tmp_path: Path, payload: bytes) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(payload)
    manifest = create_manifest(target, chunk_size=5, alg="sha256")
    proof = proof_for_index(manifest, len(manifest["leaves"]) // 2)
    assert verify_proof(proof.leaf, manifest["root"], proof.siblings, "sha256")
    wrong_root = "0" * len(manifest["root"])
    assert not verify_proof(proof.leaf, wrong_root, proof.siblings, "sha256")


@pytest.mark.parametrize("offset", [0, 1, 2, 3, 8, 13, 21, 34, 55, 89, 144, 233])
def test_full_verification_detects_position_tamper(tmp_path: Path, offset: int) -> None:
    payload = bytes((i * 11) % 256 for i in range(512))
    target = tmp_path / "artifact.bin"
    target.write_bytes(payload)
    manifest = create_manifest(target, chunk_size=17, alg="sha256")
    data = bytearray(payload)
    data[offset % len(data)] ^= 0x80
    target.write_bytes(data)
    assert not verify(target, manifest, mode="full").ok


@pytest.mark.parametrize("samples", list(range(0, 16)))
def test_sampled_detection_probability_formula(samples: int) -> None:
    fraction = 0.125
    assert detection_probability(fraction, samples) == pytest.approx(1 - (1 - fraction) ** samples)


@pytest.mark.parametrize("mutation", ["size", "mtime", "root", "alg", "mac"])
def test_signed_cache_rejects_stale_records(tmp_path: Path, mutation: str) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"cacheable-model")
    manifest = create_manifest(target, chunk_size=4, alg="sha256")
    cache = tmp_path / "cache.json"
    write_cache(target, manifest, cache)
    assert check_cache(target, manifest, cache)
    if mutation == "size":
        target.write_bytes(b"cacheable-model!")
    elif mutation == "mtime":
        stat = target.stat()
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    elif mutation == "root":
        manifest = {**manifest, "root": "f" * len(manifest["root"])}
    elif mutation == "alg":
        manifest = {**manifest, "alg": "blake3"}
    else:
        cache.write_text(cache.read_text(encoding="utf-8").replace("a", "b", 1), encoding="utf-8")
    assert not check_cache(target, manifest, cache)


@pytest.mark.parametrize("payload", PAYLOAD_CASES[:8])
def test_verify_before_load_streams_exact_bytes(tmp_path: Path, payload: bytes) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(payload)
    manifest = create_manifest(target, chunk_size=3, alg="sha256")
    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest, manifest_path)
    assert load_bytes_streaming(target, manifest_path) == payload
    assert verify_before_load(target, manifest_path, Path.read_bytes) == payload
