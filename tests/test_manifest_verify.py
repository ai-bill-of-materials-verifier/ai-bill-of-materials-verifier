from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ai_bill_of_materials_verifier.hashers import algorithm, blake3_available
from ai_bill_of_materials_verifier.manifest import (
    create_manifest,
    proof_for_index,
    verify_proof,
    write_manifest,
)
from ai_bill_of_materials_verifier.verify import (
    VerifyMode,
    detection_probability,
    open_verified,
    verify,
)


def test_file_manifest_and_verify_modes(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"abcdef" * 2000)
    manifest = create_manifest(target, chunk_size=1024, alg="sha256")
    assert manifest["kind"] == "file"
    assert verify(target, manifest, mode=VerifyMode.FULL).ok
    sampled = verify(target, manifest, mode="sampled", samples=3, seed=7)
    assert sampled.ok and sampled.checked_chunks == 3
    cache = tmp_path / "cache.json"
    assert verify(target, manifest, mode="cached", cache_file=cache).ok
    cached_hit = verify(target, manifest, mode="cached", cache_file=cache)
    assert cached_hit.ok and cached_hit.checked_chunks == 0
    assert verify(target, manifest, mode="streaming").ok


def test_tamper_first_middle_last_truncate_append_swap(tmp_path: Path) -> None:
    original = b"".join(bytes([i]) * 251 for i in range(50))
    target = tmp_path / "model.bin"
    target.write_bytes(original)
    manifest = create_manifest(target, chunk_size=251, alg="sha256")
    cases: list[bytes] = []
    for offset in (0, len(original) // 2, len(original) - 1):
        data = bytearray(original)
        data[offset] ^= 0xFF
        cases.append(bytes(data))
    cases.append(original[:-1])
    cases.append(original + b"x")
    chunks = [original[i : i + 251] for i in range(0, len(original), 251)]
    chunks[0], chunks[-1] = chunks[-1], chunks[0]
    cases.append(b"".join(chunks))
    for idx, data in enumerate(cases):
        tampered = tmp_path / f"tampered-{idx}.bin"
        tampered.write_bytes(data)
        assert not verify(tampered, manifest, mode="full").ok


def test_directory_manifest_and_proof(tmp_path: Path) -> None:
    (tmp_path / "a").write_text("alpha", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_text("beta", encoding="utf-8")
    manifest = create_manifest(tmp_path, chunk_size=4, alg="sha256")
    assert manifest["kind"] == "directory"
    assert len(manifest["files"]) == 2
    file_manifest = create_manifest(tmp_path / "a", chunk_size=2, alg="sha256")
    proof = proof_for_index(file_manifest, 1)
    assert verify_proof(proof.leaf, file_manifest["root"], proof.siblings, "sha256")


def test_streaming_reader_detects_chunk_tamper(tmp_path: Path) -> None:
    target = tmp_path / "x.bin"
    target.write_bytes(b"a" * 10 + b"b" * 10)
    manifest = create_manifest(target, chunk_size=10, alg="sha256")
    with open_verified(target, manifest) as reader:
        assert reader.read(5) == b"a" * 5
        assert reader.read() == b"a" * 5 + b"b" * 10
        assert reader.finish().ok
    target.write_bytes(b"a" * 10 + b"c" * 10)
    with pytest.raises(OSError), open_verified(target, manifest) as reader:
        reader.read()


def test_write_manifest_and_detection_probability(tmp_path: Path) -> None:
    target = tmp_path / "m.bin"
    target.write_bytes(b"hello")
    manifest = create_manifest(target, alg="sha256")
    out = tmp_path / "manifest.json"
    write_manifest(manifest, out)
    assert out.exists()
    assert detection_probability(0.1, 8) == pytest.approx(1 - 0.9**8)
    with pytest.raises(ValueError):
        detection_probability(1.1, 1)


@given(st.binary(min_size=0, max_size=4096), st.integers(min_value=1, max_value=512))
@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_manifest_roots_are_stable(tmp_path: Path, payload: bytes, chunk_size: int) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(payload)
    first = create_manifest(target, chunk_size=chunk_size, alg="sha256")
    second = create_manifest(target, chunk_size=chunk_size, alg="sha256")
    assert first["root"] == second["root"]
    assert verify(target, first, mode="full").ok


@pytest.mark.blake3
@pytest.mark.skipif(not blake3_available(), reason="blake3 wheel unavailable on this platform")
def test_blake3_available_on_linux() -> None:
    assert algorithm("blake3").name == "blake3"
