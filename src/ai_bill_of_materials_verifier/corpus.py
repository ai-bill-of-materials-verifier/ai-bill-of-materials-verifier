from __future__ import annotations

import json
import random
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bill_of_materials import (
    generate_bill_of_materials,
    manifest_root_from_bom,
    write_bill_of_materials,
)
from .manifest import create_manifest, write_manifest
from .signing import generate_private_key, save_private_key, save_public_key, sign_manifest
from .stats import wilson
from .verify import verify

DEFAULT_CORPUS_SEED = 2026092601
TRUSTED_ARCHITECTURES = {"llama", "mistral"}
BANNED_CHAT_TEMPLATE_TOKENS = ("{{system_shell}}", "<script", "powershell")


@dataclass(frozen=True, slots=True)
class CorpusSummary:
    split: str
    tamper_detection_by_class: dict[str, dict[str, Any]]
    false_positive_rate: dict[str, Any]


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _model_metadata(version: int, architecture: str = "llama") -> dict[str, Any]:
    return {
        "architecture": architecture,
        "tokenizer": "sentencepiece-v2",
        "chat_template": "{{ bos_token }}{{ user_message }}{{ eos_token }}",
        "version": version,
    }


def _tensor_payload(rng: random.Random, name: str, length: int) -> bytes:
    return bytes([(rng.randrange(256) ^ len(name) ^ i) & 0xFF for i in range(length)])


def _gguf_like(metadata: dict[str, Any], tensors: list[tuple[str, bytes]]) -> bytes:
    header = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    out = bytearray(b"GGUF")
    out += len(header).to_bytes(4, "little")
    out += header
    for name, payload in tensors:
        name_bytes = name.encode()
        out += b"TENS"
        out += len(name_bytes).to_bytes(2, "little")
        out += name_bytes
        out += len(payload).to_bytes(4, "little")
        out += payload
    return bytes(out)


def _safetensors_like(metadata: dict[str, Any], tensors: list[tuple[str, bytes]]) -> bytes:
    offset = 0
    header: dict[str, Any] = {"__metadata__": metadata}
    payload = bytearray()
    for name, tensor in tensors:
        header[name] = {
            "dtype": "U8",
            "shape": [len(tensor)],
            "data_offsets": [offset, offset + len(tensor)],
        }
        payload += tensor
        offset += len(tensor)
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return len(header_bytes).to_bytes(8, "little") + header_bytes + bytes(payload)


def _artifact_bytes(
    fmt: str, version: int, rng: random.Random, architecture: str = "llama"
) -> bytes:
    metadata = _model_metadata(version, architecture)
    tensors = [
        ("tok_embeddings.weight", _tensor_payload(rng, "embed", 96)),
        ("layers.0.attention.weight", _tensor_payload(rng, "attn", 96)),
        ("output.weight", _tensor_payload(rng, "out", 96)),
    ]
    if fmt == "gguf":
        return _gguf_like(metadata, tensors)
    return _safetensors_like(metadata, tensors)


def _base_bundle(path: Path, fmt: str, version: int, rng: random.Random) -> Path:
    bundle = path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / f"model.{fmt}").write_bytes(_artifact_bytes(fmt, version, rng))
    _write_json(bundle / "tokenizer.json", {"kind": "sentencepiece", "version": 2})
    _write_json(bundle / "config.json", {"hidden_size": 16, "layers": 1, "model_version": version})
    return bundle


def _flip(path: Path, offset: int) -> None:
    data = bytearray(path.read_bytes())
    data[offset % len(data)] ^= 0x01
    path.write_bytes(data)


def _swap_tensors(path: Path) -> None:
    data = path.read_bytes()
    midpoint = len(data) // 2
    path.write_bytes(data[:32] + data[midpoint:] + data[32:midpoint])


def _replace_header_text(path: Path, old: bytes, new: bytes) -> None:
    data = path.read_bytes()
    if old not in data:
        raise ValueError(f"{old!r} not found")
    path.write_bytes(data.replace(old, new, 1))


def _sha256_manifest(root: Path) -> None:
    import hashlib

    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "manifest.sha256"):
        entries.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}"
        )
    (root / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")


def _write_case(
    case_dir: Path,
    *,
    split: str,
    fmt: str,
    tamper_class: str,
    is_tampered: bool,
    trusted_key: Path,
    untrusted_key: Path,
    min_version: int,
    signer: str = "trusted",
    strip_signature: bool = False,
    drift_bom: bool = False,
) -> None:
    manifest = create_manifest(case_dir / "bundle", chunk_size=128, alg="sha256")
    write_manifest(manifest, case_dir / "manifest.json")
    bom = generate_bill_of_materials(manifest, model_name=f"synthetic-{fmt}")
    bom["metadata"]["component"]["version"] = str(
        json.loads((case_dir / "bundle" / "config.json").read_text(encoding="utf-8"))[
            "model_version"
        ]
    )
    if drift_bom:
        bom["metadata"]["component"]["properties"][0]["value"] = "0" * len(str(manifest["root"]))
    write_bill_of_materials(bom, case_dir / "bom.json")
    if not strip_signature:
        key = trusted_key if signer == "trusted" else untrusted_key
        (case_dir / "manifest.sig").write_text(
            sign_manifest(manifest, key) + "\n", encoding="utf-8"
        )
    _write_json(
        case_dir / "case.json",
        {
            "split": split,
            "format": fmt,
            "tamper_class": tamper_class,
            "is_tampered": is_tampered,
            "artifact_path": "bundle",
            "manifest_path": "manifest.json",
            "signature_path": None if strip_signature else "manifest.sig",
            "bom_path": "bom.json",
            "trusted_public_key_path": "../../keys/trusted.pem.pub",
            "minimum_version": min_version,
        },
    )


def generate_corpus(root: Path, *, seed: int = DEFAULT_CORPUS_SEED) -> Path:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    keys = root / "keys"
    keys.mkdir()
    trusted = generate_private_key()
    untrusted = generate_private_key()
    trusted_priv = keys / "trusted.pem"
    untrusted_priv = keys / "untrusted.pem"
    save_private_key(trusted, trusted_priv)
    save_public_key(trusted, keys / "trusted.pem.pub")
    save_private_key(untrusted, untrusted_priv)
    save_public_key(untrusted, keys / "untrusted.pem.pub")
    _write_json(
        root / "seed.json",
        {"seed": seed, "generator": "structural synthetic model artifact corpus"},
    )
    rng = random.Random(seed)  # nosec B311 - deterministic corpus generation.
    classes = [
        "single_bit_weights",
        "single_bit_header",
        "tensor_swap",
        "metadata_architecture_edit",
        "metadata_tokenizer_edit",
        "metadata_chat_template_injection",
        "truncation",
        "append",
        "substitution_same_name",
        "signature_stripping",
        "untrusted_signature",
        "bom_entry_drift",
        "dependency_swap",
        "rollback_older_signed_version",
    ]
    for split in ("dev", "test"):
        for fmt in ("gguf", "safetensors"):
            clean = root / split / f"{fmt}-untampered"
            bundle = _base_bundle(clean, fmt, 2, rng)
            _write_case(
                clean,
                split=split,
                fmt=fmt,
                tamper_class="untampered",
                is_tampered=False,
                trusted_key=trusted_priv,
                untrusted_key=untrusted_priv,
                min_version=2,
            )
            trusted_manifest = json.loads((clean / "manifest.json").read_text(encoding="utf-8"))
            trusted_bom = (clean / "bom.json").read_text(encoding="utf-8")
            if split == "test" and fmt == "gguf":
                for extra_index in range(198):
                    extra_clean = root / split / f"gguf-untampered-extra-{extra_index:03d}"
                    _base_bundle(
                        extra_clean,
                        fmt,
                        2,
                        random.Random(seed + 20_000 + extra_index),  # nosec B311
                    )
                    _write_case(
                        extra_clean,
                        split=split,
                        fmt=fmt,
                        tamper_class="untampered",
                        is_tampered=False,
                        trusted_key=trusted_priv,
                        untrusted_key=untrusted_priv,
                        min_version=2,
                    )
            for tamper_class in classes:
                case_dir = root / split / f"{fmt}-{tamper_class}"
                shutil.copytree(bundle, case_dir / "bundle")
                model = next((case_dir / "bundle").glob(f"model.{fmt}"))
                if tamper_class == "single_bit_weights":
                    _flip(model, len(model.read_bytes()) - 5)
                elif tamper_class == "single_bit_header":
                    _flip(model, 4)
                elif tamper_class == "tensor_swap":
                    _swap_tensors(model)
                elif tamper_class == "metadata_architecture_edit":
                    _replace_header_text(model, b"llama", b"qwen2")
                elif tamper_class == "metadata_tokenizer_edit":
                    _replace_header_text(model, b"sentencepiece-v2", b"bytepairencode-v2")
                elif tamper_class == "metadata_chat_template_injection":
                    _replace_header_text(model, b"user_message", b"{{system_shell}}")
                elif tamper_class == "truncation":
                    model.write_bytes(model.read_bytes()[:-7])
                elif tamper_class == "append":
                    model.write_bytes(model.read_bytes() + b"appended bytes")
                elif tamper_class == "substitution_same_name":
                    model.write_bytes(
                        _artifact_bytes(
                            fmt,
                            2,
                            random.Random(seed + 99),  # nosec B311
                            "mistral",
                        )
                    )
                elif tamper_class == "dependency_swap":
                    _write_json(
                        case_dir / "bundle" / "tokenizer.json", {"kind": "byte-pair", "version": 9}
                    )
                elif tamper_class == "rollback_older_signed_version":
                    shutil.rmtree(case_dir / "bundle")
                    _base_bundle(case_dir, fmt, 1, rng)

                if tamper_class in {
                    "single_bit_weights",
                    "single_bit_header",
                    "tensor_swap",
                    "metadata_architecture_edit",
                    "metadata_tokenizer_edit",
                    "metadata_chat_template_injection",
                    "truncation",
                    "append",
                    "substitution_same_name",
                    "dependency_swap",
                    "signature_stripping",
                    "untrusted_signature",
                    "bom_entry_drift",
                }:
                    write_manifest(trusted_manifest, case_dir / "manifest.json")
                    (case_dir / "bom.json").write_text(trusted_bom, encoding="utf-8")
                    if tamper_class == "signature_stripping":
                        strip_signature = True
                        signer = "trusted"
                    else:
                        strip_signature = False
                        signer = "untrusted" if tamper_class == "untrusted_signature" else "trusted"
                    if tamper_class == "bom_entry_drift":
                        bom = json.loads(trusted_bom)
                        bom["metadata"]["component"]["properties"][0]["value"] = "0" * len(
                            str(trusted_manifest["root"])
                        )
                        write_bill_of_materials(bom, case_dir / "bom.json")
                    if not strip_signature:
                        key = untrusted_priv if signer == "untrusted" else trusted_priv
                        (case_dir / "manifest.sig").write_text(
                            sign_manifest(trusted_manifest, key) + "\n", encoding="utf-8"
                        )
                    _write_json(
                        case_dir / "case.json",
                        {
                            "split": split,
                            "format": fmt,
                            "tamper_class": tamper_class,
                            "is_tampered": True,
                            "artifact_path": "bundle",
                            "manifest_path": "manifest.json",
                            "signature_path": None
                            if tamper_class == "signature_stripping"
                            else "manifest.sig",
                            "bom_path": "bom.json",
                            "trusted_public_key_path": "../../keys/trusted.pem.pub",
                            "minimum_version": 2,
                        },
                    )
                    continue

                _write_case(
                    case_dir,
                    split=split,
                    fmt=fmt,
                    tamper_class=tamper_class,
                    is_tampered=True,
                    trusted_key=trusted_priv,
                    untrusted_key=untrusted_priv,
                    min_version=2,
                )
            if split == "test" and fmt == "gguf":
                for extra_index in range(199):
                    case_dir = root / split / f"gguf-substitution_same_name-extra-{extra_index:03d}"
                    shutil.copytree(bundle, case_dir / "bundle")
                    model = case_dir / "bundle" / "model.gguf"
                    model.write_bytes(
                        _artifact_bytes(
                            fmt,
                            2,
                            random.Random(seed + 10_000 + extra_index),  # nosec B311
                            "mistral",
                        )
                    )
                    write_manifest(trusted_manifest, case_dir / "manifest.json")
                    (case_dir / "bom.json").write_text(trusted_bom, encoding="utf-8")
                    (case_dir / "manifest.sig").write_text(
                        sign_manifest(trusted_manifest, trusted_priv) + "\n", encoding="utf-8"
                    )
                    _write_json(
                        case_dir / "case.json",
                        {
                            "split": split,
                            "format": fmt,
                            "tamper_class": "substitution_same_name",
                            "is_tampered": True,
                            "artifact_path": "bundle",
                            "manifest_path": "manifest.json",
                            "signature_path": "manifest.sig",
                            "bom_path": "bom.json",
                            "trusted_public_key_path": "../../keys/trusted.pem.pub",
                            "minimum_version": 2,
                        },
                    )
    _sha256_manifest(root)
    return root


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())


def verify_corpus_case(case_file: Path) -> bool:
    case_dir = case_file.parent
    case = json.loads(case_file.read_text(encoding="utf-8"))
    manifest = json.loads((case_dir / case["manifest_path"]).read_text(encoding="utf-8"))
    signature_path = case.get("signature_path")
    if not signature_path:
        return False
    from .signing import verify_manifest_signature

    trusted_public_key = (case_dir / case["trusted_public_key_path"]).resolve()
    signature = (case_dir / signature_path).read_text(encoding="utf-8").strip()
    if not verify_manifest_signature(manifest, signature, trusted_public_key):
        return False

    bom = json.loads((case_dir / case["bom_path"]).read_text(encoding="utf-8"))
    try:
        bom_root = manifest_root_from_bom(bom)
    except ValueError:
        return False
    if bom_root != manifest["root"]:
        return False
    component = bom.get("metadata", {}).get("component", {})
    version = str(component.get("version", "0"))
    if _version_tuple(version) < _version_tuple(str(case["minimum_version"])):
        return False
    text = json.dumps(bom, sort_keys=True).lower()
    if any(token in text for token in BANNED_CHAT_TEMPLATE_TOKENS):
        return False
    return verify(case_dir / case["artifact_path"], manifest, mode="full").ok


def evaluate_corpus(root: Path, split: str) -> CorpusSummary:
    detected_by_class: dict[str, tuple[int, int]] = {}
    false_positives = 0
    clean_total = 0
    for case_file in sorted((root / split).glob("*/case.json")):
        case = json.loads(case_file.read_text(encoding="utf-8"))
        ok = verify_corpus_case(case_file)
        if case["is_tampered"]:
            detected, total = detected_by_class.get(case["tamper_class"], (0, 0))
            detected_by_class[case["tamper_class"]] = (detected + int(not ok), total + 1)
        else:
            clean_total += 1
            false_positives += int(not ok)
    return CorpusSummary(
        split=split,
        tamper_detection_by_class={
            name: {"detected": d, "n": n, "wilson": wilson(d, n).as_dict()}
            for name, (d, n) in sorted(detected_by_class.items())
        },
        false_positive_rate={
            "false_positives": false_positives,
            "n": clean_total,
            "wilson": wilson(false_positives, clean_total).as_dict(),
        },
    )
