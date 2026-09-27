from __future__ import annotations

import json
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ai_bill_of_materials_verifier.corpus import (
    evaluate_corpus,
    generate_corpus,
    verify_corpus_case,
)
from ai_bill_of_materials_verifier.manifest import create_manifest
from ai_bill_of_materials_verifier.verify import VerifyMode, verify, write_cache


def test_structural_tamper_corpus_reports_by_class(tmp_path: Path) -> None:
    root = generate_corpus(tmp_path / "corpus")
    summary = evaluate_corpus(root, "test")
    assert summary.false_positive_rate["false_positives"] == 0
    assert summary.false_positive_rate["n"] == 200
    assert summary.tamper_detection_by_class
    for item in summary.tamper_detection_by_class.values():
        assert item["detected"] == item["n"]


def test_verifier_does_not_read_case_labels(tmp_path: Path) -> None:
    root = generate_corpus(tmp_path / "corpus")
    case_file = root / "test" / "gguf-single_bit_weights" / "case.json"
    assert not verify_corpus_case(case_file)
    case = json.loads(case_file.read_text(encoding="utf-8"))
    case["is_tampered"] = False
    case["tamper_class"] = "untampered"
    case_file.write_text(json.dumps(case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert not verify_corpus_case(case_file)


def test_incremental_verification_rehashes_only_changed_chunks(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"a" * 64 + b"b" * 64 + b"c" * 64)
    manifest = create_manifest(target, chunk_size=64, alg="sha256")
    cache = tmp_path / "cache.json"
    write_cache(target, manifest, cache)
    data = bytearray(target.read_bytes())
    data[80] ^= 1
    target.write_bytes(data)
    result = verify(
        target,
        manifest,
        mode=VerifyMode.INCREMENTAL,
        cache_file=cache,
        changed_ranges=[(80, 1)],
    )
    assert not result.ok
    assert result.checked_chunks == 1


def test_parallel_manifest_matches_single_thread_and_incremental_refresh(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(bytes(range(251)) * 16)
    single = create_manifest(target, chunk_size=251, alg="sha256")
    parallel = create_manifest(target, chunk_size=251, alg="sha256", threads=3)
    assert parallel["root"] == single["root"]
    cache = tmp_path / "cache.json"
    refreshed = verify(target, single, mode=VerifyMode.INCREMENTAL, cache_file=cache)
    assert refreshed.ok
    assert refreshed.checked_chunks == len(single["leaves"])
    hit = verify(target, single, mode=VerifyMode.INCREMENTAL, cache_file=cache)
    assert hit.ok
    assert hit.checked_chunks == 0


@given(st.binary(min_size=1, max_size=2048), st.integers(min_value=0, max_value=2047))
@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_single_byte_mutation_of_signed_artifact_is_detected(
    tmp_path: Path, payload: bytes, offset: int
) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(payload)
    manifest = create_manifest(target, chunk_size=127, alg="sha256")
    mutated = bytearray(payload)
    mutated[offset % len(mutated)] ^= 1
    target.write_bytes(mutated)
    assert not verify(target, manifest, mode="full").ok
