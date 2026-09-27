from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_bill_of_materials_verifier.bill_of_materials import manifest_root_from_bom
from ai_bill_of_materials_verifier.cli import build_parser, main
from ai_bill_of_materials_verifier.hashers import algorithm, hash_bytes
from ai_bill_of_materials_verifier.manifest import (
    create_manifest,
    manifest_from_json,
    proof_for_index,
)
from ai_bill_of_materials_verifier.verify import open_verified, recompute_root_from_leaves, verify


def test_cli_manifest_verify_modes_and_bill_of_materials(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"cli-model" * 17)
    manifest = tmp_path / "manifest.json"
    assert (
        main(["manifest", str(target), "--alg", "sha256", "--chunk-size", "9", "-o", str(manifest)])
        == 0
    )
    for mode in ["full", "sampled", "streaming", "cached"]:
        args = [
            "verify",
            str(target),
            str(manifest),
            "--mode",
            mode,
            "--cache",
            str(tmp_path / "cache.json"),
        ]
        assert main(args) == 0
    bom = tmp_path / "bom.json"
    assert (
        main(
            [
                "bill-of-materials",
                str(manifest),
                "-o",
                str(bom),
                "--model-name",
                "fixture",
                "--dataset",
                "ds",
                "--framework",
                "fw",
                "--check",
            ]
        )
        == 0
    )
    assert (
        manifest_root_from_bom(json.loads(bom.read_text(encoding="utf-8")))
        == json.loads(manifest.read_text(encoding="utf-8"))["root"]
    )


def test_cli_verify_reports_failures(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"before")
    manifest = tmp_path / "manifest.json"
    assert main(["manifest", str(target), "--alg", "sha256", "-o", str(manifest)]) == 0
    target.write_bytes(b"after")
    assert main(["verify", str(target), str(manifest)]) == 1


def test_cli_parser_lists_subcommands() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    for name in ["manifest", "sign", "verify", "bill-of-materials", "provenance", "bench"]:
        assert name in help_text


def test_hashers_reject_unknown_algorithm() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        algorithm("md5")
    assert len(hash_bytes(b"abc", alg="sha256")) == 64


def test_manifest_json_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        manifest_from_json(path)


def test_manifest_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        create_manifest(tmp_path / "missing.bin", alg="sha256")


def test_sampled_rejects_chunk_count_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"abcdef")
    manifest = create_manifest(target, chunk_size=2, alg="sha256")
    bad = {**manifest, "leaves": manifest["leaves"][:-1]}
    result = verify(target, bad, mode="sampled")
    assert not result.ok and "chunk count" in result.reason


def test_sampled_rejects_leaf_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"abcdef")
    manifest = create_manifest(target, chunk_size=2, alg="sha256")
    bad_leaves = list(manifest["leaves"])
    bad_leaves[0] = "0" * len(bad_leaves[0])
    bad = {
        **manifest,
        "leaves": bad_leaves,
        "root": recompute_root_from_leaves(bad_leaves, "sha256"),
    }
    result = verify(target, bad, mode="sampled", samples=1, seed=1)
    assert not result.ok and "sampled chunk" in result.reason


def test_reader_rejects_closed_and_extra_chunk(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"abcdef")
    manifest = create_manifest(target, chunk_size=3, alg="sha256")
    short_manifest = {**manifest, "leaves": manifest["leaves"][:1]}
    with (
        pytest.raises(OSError, match="extra chunk"),
        open_verified(target, short_manifest) as reader,
    ):
        reader.read()
    reader = open_verified(target, manifest)
    reader.close()
    with pytest.raises(ValueError, match="closed"):
        reader.read(1)


def test_proof_index_bounds(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"abcdef")
    manifest = create_manifest(target, chunk_size=2, alg="sha256")
    with pytest.raises(IndexError):
        proof_for_index(manifest, 99)
