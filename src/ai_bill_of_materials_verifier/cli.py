from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .bill_of_materials import (
    generate_bill_of_materials,
    read_bill_of_materials,
    write_bill_of_materials,
)
from .manifest import create_manifest, manifest_from_json, write_manifest
from .provenance import load_policy, verify_provenance_dsse
from .signing import (
    dsse_envelope,
    generate_private_key,
    save_private_key,
    save_public_key,
    sign_manifest,
    verify_manifest_signature,
)
from .verify import VerifyMode, verify


def _manifest_cmd(args: argparse.Namespace) -> int:
    manifest = create_manifest(args.path, chunk_size=args.chunk_size, alg=args.alg)
    if args.output:
        write_manifest(manifest, args.output)
    else:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def _sign_cmd(args: argparse.Namespace) -> int:
    manifest = manifest_from_json(args.manifest)
    if args.generate_key:
        key = generate_private_key()
        save_private_key(key, args.key)
        save_public_key(key, args.pubkey or str(args.key) + ".pub")
    sig = sign_manifest(manifest, args.key)
    if args.dsse:
        env = dsse_envelope(
            manifest, "application/vnd.ai-bill-of-materials-verifier.manifest.v1+json", args.key
        )
        Path(args.output).write_text(
            json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    else:
        Path(args.output).write_text(sig + "\n", encoding="utf-8")
    return 0


def _verify_cmd(args: argparse.Namespace) -> int:
    manifest = manifest_from_json(args.manifest)
    if args.signature and args.pubkey:
        signature = Path(args.signature).read_text(encoding="utf-8").strip()
        if not verify_manifest_signature(manifest, signature, args.pubkey):
            print("signature verification failed", file=sys.stderr)
            return 2
    result = verify(
        args.path,
        manifest,
        mode=args.mode,
        samples=args.samples,
        seed=args.seed,
        cache_file=args.cache,
        threads=args.threads,
        changed_ranges=[_parse_changed_range(value) for value in args.changed_range],
    )
    print(json.dumps(asdict(result), indent=2, sort_keys=True, default=str))
    return 0 if result.ok else 1


def _parse_changed_range(value: str) -> tuple[int, int]:
    start_text, separator, length_text = value.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("changed ranges must use start:length")
    return int(start_text), int(length_text)


def _bill_of_materials_cmd(args: argparse.Namespace) -> int:
    manifest = manifest_from_json(args.manifest)
    bom = generate_bill_of_materials(
        manifest, model_name=args.model_name, datasets=args.dataset, frameworks=args.framework
    )
    write_bill_of_materials(bom, args.output)
    if args.check:
        read_bill_of_materials(args.output)
    return 0


def _provenance_cmd(args: argparse.Namespace) -> int:
    envelope = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
    policy = load_policy(json.loads(Path(args.policy).read_text(encoding="utf-8")))
    result = verify_provenance_dsse(
        envelope,
        args.pubkey,
        subject_name=args.subject_name,
        subject_digest=args.subject_digest,
        policy=policy,
    )
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0 if result.ok else 1


def _bench_cmd(args: argparse.Namespace) -> int:
    from bench.bench_verify import main as bench_main

    bench_args = ["--out", args.output]
    if args.quick:
        bench_args.append("--quick")
    return bench_main(bench_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-bill-of-materials-verifier")
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("manifest")
    p.add_argument("path")
    p.add_argument("--output", "-o")
    p.add_argument("--chunk-size", type=int, default=16 * 1024 * 1024)
    p.add_argument("--alg", default="blake3")
    p.set_defaults(func=_manifest_cmd)
    p = sub.add_parser("sign")
    p.add_argument("manifest")
    p.add_argument("--key", required=True)
    p.add_argument("--pubkey")
    p.add_argument("--output", "-o", required=True)
    p.add_argument("--generate-key", action="store_true")
    p.add_argument("--dsse", action="store_true")
    p.set_defaults(func=_sign_cmd)
    p = sub.add_parser("verify")
    p.add_argument("path")
    p.add_argument("manifest")
    p.add_argument("--mode", choices=[m.value for m in VerifyMode], default="full")
    p.add_argument("--samples", type=int, default=8)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--cache")
    p.add_argument("--threads", type=int, default=1)
    p.add_argument("--changed-range", action="append", default=[])
    p.add_argument("--signature")
    p.add_argument("--pubkey")
    p.set_defaults(func=_verify_cmd)
    p = sub.add_parser("bill-of-materials")
    p.add_argument("manifest")
    p.add_argument("--output", "-o", required=True)
    p.add_argument("--model-name")
    p.add_argument("--dataset", action="append", default=[])
    p.add_argument("--framework", action="append", default=[])
    p.add_argument("--check", action="store_true")
    p.set_defaults(func=_bill_of_materials_cmd)
    p = sub.add_parser("provenance")
    p.add_argument("envelope")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--policy", required=True)
    p.add_argument("--subject-name", required=True)
    p.add_argument("--subject-digest", required=True)
    p.set_defaults(func=_provenance_cmd)
    p = sub.add_parser("bench")
    p.add_argument("--output", "-o", default="results")
    p.add_argument("--quick", action="store_true")
    p.set_defaults(func=_bench_cmd)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
