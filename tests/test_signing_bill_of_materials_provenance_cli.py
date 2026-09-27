from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from ai_bill_of_materials_verifier.bill_of_materials import (
    generate_bill_of_materials,
    manifest_root_from_bom,
    read_bill_of_materials,
    write_bill_of_materials,
)
from ai_bill_of_materials_verifier.cli import main
from ai_bill_of_materials_verifier.manifest import create_manifest
from ai_bill_of_materials_verifier.provenance import ProvenancePolicy, verify_provenance_dsse
from ai_bill_of_materials_verifier.signing import (
    crypto_available,
    dsse_envelope,
    generate_private_key,
    save_private_key,
    save_public_key,
    sign_manifest,
    verify_dsse,
    verify_manifest_signature,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="cryptography unavailable on this platform"
)


def _keys(tmp_path: Path) -> tuple[Path, Path]:
    key = generate_private_key()
    priv = tmp_path / "key.pem"
    pub = tmp_path / "key.pem.pub"
    save_private_key(key, priv)
    save_public_key(key, pub)
    return priv, pub


def test_sign_manifest_and_dsse(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"model")
    manifest = create_manifest(target, alg="sha256")
    priv, pub = _keys(tmp_path)
    sig = sign_manifest(manifest, priv)
    assert base64.b64decode(sig)
    assert verify_manifest_signature(manifest, sig, pub)
    env = dsse_envelope(
        manifest, "application/vnd.ai-bill-of-materials-verifier.manifest.v1+json", priv
    )
    ok, payload = verify_dsse(env, pub)
    assert ok
    assert payload is not None and payload["root"] == manifest["root"]


def test_bill_of_materials_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "model.bin"
    target.write_bytes(b"model")
    manifest = create_manifest(target, alg="sha256")
    bom = generate_bill_of_materials(
        manifest, model_name="fixture", datasets=["ds"], frameworks=["pytorch"]
    )
    assert manifest_root_from_bom(bom) == manifest["root"]
    out = tmp_path / "bom.json"
    write_bill_of_materials(bom, out)
    assert read_bill_of_materials(out)["bomFormat"] == "CycloneDX"


def test_provenance_policy(tmp_path: Path) -> None:
    priv, pub = _keys(tmp_path)
    digest = "a" * 64
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "model.bin", "digest": {"sha256": digest}}],
        "predicate": {
            "builder": {"id": "local-builder"},
            "buildDefinition": {
                "buildType": "https://ai-bill-of-materials-verifier/build/v1",
                "resolvedDependencies": [{"uri": "git+file://repo"}],
            },
        },
    }
    env = dsse_envelope(statement, "application/vnd.in-toto+json", priv)
    policy = ProvenancePolicy(
        {"local-builder"}, {"https://ai-bill-of-materials-verifier/build/v1"}, {"git+file://repo"}
    )
    result = verify_provenance_dsse(
        env, pub, subject_name="model.bin", subject_digest=digest, policy=policy
    )
    assert result.ok
    bad = verify_provenance_dsse(
        env, pub, subject_name="model.bin", subject_digest="b" * 64, policy=policy
    )
    assert not bad.ok


def test_cli_end_to_end(tmp_path: Path) -> None:
    target = tmp_path / "m.bin"
    target.write_bytes(b"abc")
    manifest_path = tmp_path / "m.json"
    assert main(["manifest", str(target), "--alg", "sha256", "--output", str(manifest_path)]) == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    priv, pub = _keys(tmp_path)
    sig = tmp_path / "m.sig"
    assert main(["sign", str(manifest_path), "--key", str(priv), "--output", str(sig)]) == 0
    assert (
        main(
            [
                "verify",
                str(target),
                str(manifest_path),
                "--signature",
                str(sig),
                "--pubkey",
                str(pub),
            ]
        )
        == 0
    )
    bom = tmp_path / "bom.json"
    assert main(["bill-of-materials", str(manifest_path), "--output", str(bom), "--check"]) == 0
    assert (
        read_bill_of_materials(bom)["metadata"]["component"]["hashes"][0]["content"]
        == manifest["root"]
    )
