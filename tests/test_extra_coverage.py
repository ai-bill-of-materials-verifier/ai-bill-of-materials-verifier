from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError

from ai_bill_of_materials_verifier.bill_of_materials import (
    manifest_root_from_bom,
    read_bill_of_materials,
    validate_bill_of_materials,
)
from ai_bill_of_materials_verifier.cli import main
from ai_bill_of_materials_verifier.loader import verify_onnx_path, verify_safetensors_path
from ai_bill_of_materials_verifier.manifest import create_manifest, write_manifest
from ai_bill_of_materials_verifier.provenance import (
    ProvenancePolicy,
    load_policy,
    verify_provenance_dsse,
)
from ai_bill_of_materials_verifier.signing import (
    crypto_available,
    dsse_envelope,
    generate_private_key,
    save_private_key,
    save_public_key,
    sign_manifest,
    signature_to_cosign_blob,
    verify_dsse,
    verify_manifest_signature,
)


def test_bill_of_materials_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        validate_bill_of_materials({"bomFormat": "CycloneDX"})
    path = tmp_path / "bad.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        read_bill_of_materials(path)
    with pytest.raises(ValueError, match="manifest root"):
        manifest_root_from_bom({"metadata": {"component": {"properties": []}}})
    with pytest.raises(ValueError, match="missing properties"):
        manifest_root_from_bom({"metadata": {"component": {"properties": "bad"}}})


def test_loader_helpers_and_failure(tmp_path: Path) -> None:
    target = tmp_path / "model.onnx"
    target.write_bytes(b"onnx-bytes")
    manifest = create_manifest(target, chunk_size=4, alg="sha256")
    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest, manifest_path)
    assert verify_onnx_path(target, manifest_path) == target
    assert verify_safetensors_path(target, manifest_path) == target
    target.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="verification failed"):
        verify_onnx_path(target, manifest_path)


@pytest.mark.skipif(not crypto_available(), reason="cryptography unavailable on this platform")
def test_cli_sign_dsse_and_provenance_paths(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"model")
    manifest_path = tmp_path / "manifest.json"
    assert main(["manifest", str(target), "--alg", "sha256", "-o", str(manifest_path)]) == 0
    key = tmp_path / "key.pem"
    sig = tmp_path / "manifest.sig"
    dsse = tmp_path / "manifest.dsse.json"
    assert (
        main(["sign", str(manifest_path), "--generate-key", "--key", str(key), "-o", str(sig)]) == 0
    )
    assert main(["sign", str(manifest_path), "--key", str(key), "-o", str(dsse), "--dsse"]) == 0
    bad_sig = tmp_path / "bad.sig"
    bad_sig.write_text(base64.b64encode(b"not-der").decode("ascii"), encoding="utf-8")
    assert (
        main(
            [
                "verify",
                str(target),
                str(manifest_path),
                "--signature",
                str(bad_sig),
                "--pubkey",
                str(key) + ".pub",
            ]
        )
        == 2
    )

    digest = "c" * 64
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "model.bin", "digest": {"sha256": digest}}],
        "predicate": {
            "builder": {"id": "local-builder"},
            "buildDefinition": {
                "buildType": "local",
                "resolvedDependencies": [{"uri": "git+file://repo"}],
            },
        },
    }
    env = dsse_envelope(statement, "application/vnd.in-toto+json", key)
    env_path = tmp_path / "prov.dsse.json"
    env_path.write_text(json.dumps(env), encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "builder_ids": ["local-builder"],
                "build_types": ["local"],
                "required_materials": ["git+file://repo"],
            }
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "provenance",
                str(env_path),
                "--pubkey",
                str(key) + ".pub",
                "--policy",
                str(policy_path),
                "--subject-name",
                "model.bin",
                "--subject-digest",
                digest,
            ]
        )
        == 0
    )


@pytest.mark.skipif(not crypto_available(), reason="cryptography unavailable on this platform")
def test_signing_and_provenance_negative_paths(tmp_path: Path) -> None:
    key_obj = generate_private_key()
    priv = tmp_path / "key.pem"
    pub = tmp_path / "key.pub"
    save_private_key(key_obj, priv)
    save_public_key(key_obj, pub)
    manifest = {"root": "a" * 64, "name": "model.bin"}
    sig = sign_manifest(manifest, priv)
    assert verify_manifest_signature(manifest, sig, pub)
    assert not verify_manifest_signature({"root": "b" * 64}, sig, pub)
    sig_file = tmp_path / "cosign.sig"
    signature_to_cosign_blob(sig, sig_file)
    assert sig_file.read_text(encoding="utf-8").strip() == sig
    assert verify_dsse(
        {"payloadType": "x", "payload": base64.b64encode(b"{}").decode(), "signatures": []}, pub
    ) == (False, None)

    env = dsse_envelope({"not": "statement"}, "application/vnd.in-toto+json", priv)
    policy = ProvenancePolicy({"builder"}, {"type"}, {"mat"})
    assert not verify_provenance_dsse(
        env, pub, subject_name="model.bin", subject_digest="a" * 64, policy=policy
    ).ok

    base_statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "model.bin", "digest": {"sha256": "a" * 64}}],
        "predicate": {
            "builder": {"id": "bad"},
            "buildDefinition": {"buildType": "bad", "resolvedDependencies": []},
        },
    }
    env = dsse_envelope(base_statement, "application/vnd.in-toto+json", priv)
    assert (
        "builder.id"
        in verify_provenance_dsse(
            env, pub, subject_name="model.bin", subject_digest="a" * 64, policy=policy
        ).reason
    )
    assert load_policy({"builder_ids": ["bad"]}).builder_ids == {"bad"}


def test_cli_bench_monkeypatched(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import bench.bench_verify as bench_verify

    called: list[list[str] | None] = []

    def fake_main(argv: list[str] | None = None) -> int:
        called.append(argv)
        return 0

    monkeypatch.setattr(bench_verify, "main", fake_main)
    assert main(["bench", "--output", str(tmp_path), "--quick"]) == 0
    assert called and "--quick" in (called[0] or [])
