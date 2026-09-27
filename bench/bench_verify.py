# ruff: noqa: S311
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import mmap
import platform
import random
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_bill_of_materials_verifier.corpus import (
    DEFAULT_CORPUS_SEED,
    evaluate_corpus,
    generate_corpus,
    verify_corpus_case,
)
from ai_bill_of_materials_verifier.manifest import NODE_PREFIX, canonical_json
from ai_bill_of_materials_verifier.signing import (
    crypto_available,
    generate_private_key,
    save_private_key,
    save_public_key,
    sign_manifest,
    verify_manifest_signature,
)
from ai_bill_of_materials_verifier.stats import bootstrap_quantile_ci, mean_t_ci, wilson

try:
    import blake3
except ImportError:  # pragma: no cover
    blake3 = None

MIB = 1024 * 1024
GIB = 1024 * MIB
SIZES_FULL = [64 * MIB, 256 * MIB, 1 * GIB, 4 * GIB]
SIZES_QUICK = [1 * MIB, 4 * MIB]
TRIALS_REDUCED = {
    64 * MIB: 5,
    256 * MIB: 5,
    1 * GIB: 5,
    4 * GIB: 3,
}
CHUNK_SIZES = [4 * MIB, 16 * MIB, 64 * MIB]
FULL_STREAM_THREADS = [1, 4, 8, 12]
FAST_ALG = "blake3" if blake3 is not None else "sha256"
ALGORITHMS = ["blake3", "sha256"] if blake3 is not None else ["sha256"]
SAMPLED_K = [8, 32, 128]
LEAF_PREFIX = b"ai-bill-of-materials-verifier leaf v1\x00"
CACHE_SECRET = b"ai-bill-of-materials-verifier-bench-cache-secret-v1"
DETECTION_TRIALS = 200


@dataclass(frozen=True, slots=True)
class BenchManifest:
    size: int
    chunk_size: int
    alg: str
    thread_count: int
    leaves: list[str]
    root: str


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _run_id() -> str:
    return (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + socket.gethostname().split(".")[0][:12]
    )


def _platform_label() -> str:
    parts = platform.platform().split("-")
    return "-".join(
        part for part in parts if part.lower() != "standard" and not part.lower().endswith("soft")
    )


def _write_random(path: Path, size: int) -> None:
    chunk = 8 * MIB
    rng = random.Random(size)
    remaining = size
    with path.open("wb") as fh:
        while remaining:
            n = min(chunk, remaining)
            fh.write(rng.randbytes(n))
            remaining -= n


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(8 * MIB):
            h.update(chunk)
    return h.hexdigest()


def _new_hasher(alg: str, thread_count: int) -> Any:
    if alg == "sha256":
        return hashlib.sha256()
    if blake3 is None:  # pragma: no cover
        raise RuntimeError("blake3 unavailable")
    return blake3.blake3(max_threads=thread_count)


def _digest_parts(parts: Iterable[bytes | memoryview], alg: str, thread_count: int) -> bytes:
    hasher = _new_hasher(alg, thread_count)
    for part in parts:
        hasher.update(part)
    return bytes(hasher.digest())


def _digest(data: bytes, alg: str, thread_count: int) -> bytes:
    return _digest_parts([data], alg, thread_count)


def _whole_digest_file(path: Path, alg: str, thread_count: int) -> str:
    if alg == "sha256":
        h = hashlib.sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(8 * MIB):
                h.update(chunk)
        return h.hexdigest()
    if blake3 is None:  # pragma: no cover
        raise RuntimeError("blake3 unavailable")
    h = blake3.blake3(max_threads=thread_count)
    h.update_mmap(str(path))
    return str(h.hexdigest())


def _leaf_hash(chunk: bytes, alg: str, thread_count: int) -> bytes:
    return _digest_parts([LEAF_PREFIX, len(chunk).to_bytes(8, "big"), chunk], alg, thread_count)


def _leaf_hash_view(chunk: memoryview, alg: str, thread_count: int) -> bytes:
    return _digest_parts([LEAF_PREFIX, len(chunk).to_bytes(8, "big"), chunk], alg, thread_count)


def _node_hash(left: bytes, right: bytes, alg: str, thread_count: int) -> bytes:
    return _digest_parts([NODE_PREFIX, left, right], alg, thread_count)


def _build_root(leaves: list[bytes], alg: str, thread_count: int) -> str:
    if not leaves:
        leaves = [_leaf_hash(b"", alg, thread_count)]
    cur = leaves
    while len(cur) > 1:
        nxt: list[bytes] = []
        for idx in range(0, len(cur), 2):
            left = cur[idx]
            right = cur[idx + 1] if idx + 1 < len(cur) else left
            nxt.append(_node_hash(left, right, alg, thread_count))
        cur = nxt
    return cur[0].hex()


def _read_chunks(path: Path, chunk_size: int) -> Iterable[bytes]:
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _create_manifest(path: Path, chunk_size: int, alg: str, thread_count: int) -> BenchManifest:
    leaves: list[bytes] = []
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        view = memoryview(mm)
        try:
            for offset in range(0, len(view), chunk_size):
                chunk = view[offset : offset + chunk_size]
                try:
                    leaves.append(_leaf_hash_view(chunk, alg, thread_count))
                finally:
                    chunk.release()
        finally:
            view.release()
    return BenchManifest(
        size=path.stat().st_size,
        chunk_size=chunk_size,
        alg=alg,
        thread_count=thread_count,
        leaves=[leaf.hex() for leaf in leaves] or [_leaf_hash(b"", alg, thread_count).hex()],
        root=_build_root(leaves, alg, thread_count),
    )


def _verify_full(path: Path, manifest: BenchManifest) -> tuple[bool, int]:
    actual = _create_manifest(path, manifest.chunk_size, manifest.alg, manifest.thread_count)
    return actual.root == manifest.root and actual.size == manifest.size, len(actual.leaves)


def _verify_streaming(path: Path, manifest: BenchManifest) -> tuple[bool, int]:
    leaves: list[bytes] = []
    with path.open("rb") as fh:
        while chunk := fh.read(manifest.chunk_size):
            leaves.append(_leaf_hash(chunk, manifest.alg, manifest.thread_count))
    root = _build_root(leaves, manifest.alg, manifest.thread_count)
    return root == manifest.root and path.stat().st_size == manifest.size, len(leaves)


def _verify_incremental_one_chunk(path: Path, manifest: BenchManifest) -> tuple[bool, int]:
    leaves = list(manifest.leaves)
    with path.open("rb") as fh:
        chunk = fh.read(manifest.chunk_size)
    leaves[0] = _leaf_hash(chunk, manifest.alg, manifest.thread_count).hex()
    root = _build_root(
        [bytes.fromhex(leaf) for leaf in leaves], manifest.alg, manifest.thread_count
    )
    return root == manifest.root and path.stat().st_size == manifest.size, 1


def _verify_sampled(path: Path, manifest: BenchManifest, k: int, seed: int) -> tuple[bool, int]:
    count = len(manifest.leaves)
    samples = min(k, count)
    indices = sorted(random.Random(seed).sample(range(count), samples)) if samples else []
    checked = 0
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        view = memoryview(mm)
        try:
            for idx in indices:
                offset = idx * manifest.chunk_size
                chunk = view[offset : offset + manifest.chunk_size]
                try:
                    leaf = _leaf_hash_view(chunk, manifest.alg, manifest.thread_count)
                finally:
                    chunk.release()
                if leaf.hex() != manifest.leaves[idx]:
                    return False, checked + 1
                checked += 1
        finally:
            view.release()
    return True, checked


def _cache_record(path: Path, manifest: BenchManifest) -> dict[str, Any]:
    st = path.stat()
    key = {
        "path": str(path.resolve()),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "root": manifest.root,
        "alg": manifest.alg,
        "thread_count": manifest.thread_count,
    }
    mac = hmac.new(CACHE_SECRET, canonical_json(key), "sha256").hexdigest()
    return {"key": key, "mac": mac}


def _verify_cached(path: Path, manifest: BenchManifest, record: dict[str, Any]) -> tuple[bool, int]:
    actual = _cache_record(path, manifest)
    ok = (
        hmac.compare_digest(str(record["mac"]), str(actual["mac"]))
        and record["key"] == actual["key"]
    )
    return ok, 0


def _run_one(
    trial_id: int,
    path: Path,
    manifest: BenchManifest,
    mode: str,
    k: int | None,
    cache_record: dict[str, Any],
) -> dict[str, Any]:
    ts = _timestamp()
    start = time.perf_counter_ns()
    if mode == "full":
        ok, checked = _verify_full(path, manifest)
    elif mode == "streaming":
        ok, checked = _verify_streaming(path, manifest)
    elif mode == "cached":
        ok, checked = _verify_cached(path, manifest, cache_record)
    elif mode == "incremental-1-chunk":
        ok, checked = _verify_incremental_one_chunk(path, manifest)
    elif mode == "sampled" and k is not None:
        ok, checked = _verify_sampled(path, manifest, k, seed=trial_id)
    else:  # pragma: no cover
        raise ValueError(mode)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    hashed_bytes = checked * manifest.chunk_size
    if mode in {"full", "streaming"}:
        hashed_bytes = manifest.size
    if mode == "cached":
        hashed_bytes = 0
    return {
        "trial": trial_id,
        "timestamp_utc": ts,
        "size_bytes": manifest.size,
        "chunk_size": manifest.chunk_size,
        "mode": mode if k is None else f"sampled-{k}",
        "alg": manifest.alg,
        "thread_count": manifest.thread_count,
        "ok": ok,
        "elapsed_ms": elapsed_ms,
        "throughput_gbps": (hashed_bytes / (1024**3)) / (elapsed_ms / 1000)
        if elapsed_ms > 0 and hashed_bytes > 0
        else "",
        "checked_chunks": checked,
        "page_cache": "warm page cache; unprivileged container did not drop caches",
        "measurement_kind": "direct",
    }


def _trial_count(size: int, quick: bool, reduced: bool) -> int:
    if quick:
        return 5
    if reduced:
        return TRIALS_REDUCED[size]
    return 10 if size >= 4 * GIB else 30


def _flip_chunk_bytes(path: Path, chunk_size: int, indices: list[int]) -> None:
    with path.open("r+b") as fh:
        for idx in indices:
            fh.seek(idx * chunk_size)
            old = fh.read(1)
            if not old:
                continue
            fh.seek(idx * chunk_size)
            fh.write(bytes([old[0] ^ 0x80]))


def _sampled_detection_rows(
    start_trial: int, path: Path, manifest: BenchManifest, trials: int
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    rng = random.Random(20260925)
    chunk_size = manifest.chunk_size
    chunk_count = len(manifest.leaves)
    trial_id = start_trial
    for fraction in [0.001, 0.01, 0.1]:
        tampered_n = max(1, round(chunk_count * fraction))
        for k in SAMPLED_K:
            sample_n = min(k, chunk_count)
            theory = 1.0 - (1.0 - fraction) ** sample_n
            detected = 0
            for _ in range(trials):
                tampered = sorted(rng.sample(range(chunk_count), tampered_n))
                _flip_chunk_bytes(path, chunk_size, tampered)
                ts = _timestamp()
                start = time.perf_counter_ns()
                verifier_ok, checked = _verify_sampled(path, manifest, k, seed=trial_id)
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                _flip_chunk_bytes(path, chunk_size, tampered)
                detected_flag = not verifier_ok
                detected += int(detected_flag)
                rows.append(
                    {
                        "trial": trial_id,
                        "timestamp_utc": ts,
                        "size_bytes": manifest.size,
                        "chunk_size": chunk_size,
                        "mode": f"sampled-detection-{k}",
                        "alg": manifest.alg,
                        "thread_count": manifest.thread_count,
                        "ok": detected_flag,
                        "elapsed_ms": elapsed_ms,
                        "throughput_gbps": "",
                        "checked_chunks": checked,
                        "page_cache": (
                            "warm page cache; direct in-place chunk tamper and sampled verify"
                        ),
                        "tamper_fraction": fraction,
                        "effective_tamper_fraction": tampered_n / chunk_count,
                        "theory": theory,
                        "measurement_kind": "direct",
                    }
                )
                trial_id += 1
    return rows, trial_id


def _full_tamper_rows(
    start_trial: int, path: Path, manifest: BenchManifest, trials: int
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    rng = random.Random(20260926)
    trial_id = start_trial
    chunk_count = len(manifest.leaves)
    for _ in range(trials):
        tampered = [rng.randrange(chunk_count)]
        _flip_chunk_bytes(path, manifest.chunk_size, tampered)
        ts = _timestamp()
        start = time.perf_counter_ns()
        ok, checked = _verify_full(path, manifest)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        _flip_chunk_bytes(path, manifest.chunk_size, tampered)
        rows.append(
            {
                "trial": trial_id,
                "timestamp_utc": ts,
                "size_bytes": manifest.size,
                "chunk_size": manifest.chunk_size,
                "mode": "full-tamper-detection",
                "alg": manifest.alg,
                "thread_count": manifest.thread_count,
                "ok": not ok,
                "elapsed_ms": elapsed_ms,
                "throughput_gbps": "",
                "checked_chunks": checked,
                "page_cache": "warm page cache; direct in-place chunk tamper and FULL verify",
                "tamper_fraction": 1 / chunk_count,
                "measurement_kind": "direct",
            }
        )
        trial_id += 1
    return rows, trial_id


def _signature_rows(start_trial: int, trials: int, work: Path) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    if not crypto_available():
        return rows, start_trial
    key = generate_private_key()
    priv = work / "bench-key.pem"
    pub = work / "bench-key.pub"
    save_private_key(key, priv)
    save_public_key(key, pub)
    signed_manifest = {"name": "bench-model", "root": "a" * 64}
    signature = sign_manifest(signed_manifest, priv)
    trial_id = start_trial
    for _ in range(trials):
        ts = _timestamp()
        start = time.perf_counter_ns()
        ok = verify_manifest_signature(signed_manifest, signature, pub)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        rows.append(
            {
                "trial": trial_id,
                "timestamp_utc": ts,
                "size_bytes": len(canonical_json(signed_manifest)),
                "chunk_size": 0,
                "mode": "signature-verify",
                "alg": "ecdsa-p256-sha256",
                "thread_count": 0,
                "ok": ok,
                "elapsed_ms": elapsed_ms,
                "throughput_gbps": "",
                "checked_chunks": 0,
                "page_cache": "not applicable",
                "measurement_kind": "direct",
            }
        )
        trial_id += 1
    return rows, trial_id


def _corpus_rows(start_trial: int, work: Path) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    corpus_root = generate_corpus(work / "tamper-corpus", seed=DEFAULT_CORPUS_SEED)
    rows: list[dict[str, Any]] = []
    trial_id = start_trial
    for split in ("dev", "test"):
        for case_file in sorted((corpus_root / split).glob("*/case.json")):
            case = json.loads(case_file.read_text(encoding="utf-8"))
            ts = _timestamp()
            start = time.perf_counter_ns()
            verifier_ok = verify_corpus_case(case_file)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            tampered = bool(case["is_tampered"])
            rows.append(
                {
                    "trial": trial_id,
                    "timestamp_utc": ts,
                    "size_bytes": 0,
                    "chunk_size": 128,
                    "mode": "tamper-corpus",
                    "alg": "sha256",
                    "thread_count": 1,
                    "ok": (not verifier_ok) if tampered else verifier_ok,
                    "verifier_ok": verifier_ok,
                    "elapsed_ms": elapsed_ms,
                    "throughput_gbps": "",
                    "checked_chunks": "",
                    "page_cache": "small generated structural corpus",
                    "split": split,
                    "tamper_class": str(case["tamper_class"]),
                    "is_tampered": tampered,
                    "format": str(case["format"]),
                    "measurement_kind": "direct",
                }
            )
            trial_id += 1
    summary = {split: asdict(evaluate_corpus(corpus_root, split)) for split in ("dev", "test")}
    return rows, trial_id, summary


def _plans_for_size(size: int) -> list[tuple[str, int, int, str, int | None]]:
    plans: list[tuple[str, int, int, str, int | None]] = []
    seen: set[tuple[str, int, int, str, int | None]] = set()

    def add(alg: str, thread_count: int, chunk_size: int, mode: str, k: int | None = None) -> None:
        plan = (alg, thread_count, chunk_size, mode, k)
        if plan not in seen:
            seen.add(plan)
            plans.append(plan)

    for alg in ALGORITHMS:
        for thread_count in FULL_STREAM_THREADS:
            add(alg, thread_count, 16 * MIB, "full")
            add(alg, thread_count, 16 * MIB, "streaming")

    for k in SAMPLED_K:
        add(FAST_ALG, 12, 16 * MIB, "sampled", k)
    add(FAST_ALG, 12, 16 * MIB, "cached")
    add(FAST_ALG, 12, 16 * MIB, "incremental-1-chunk")

    if size == GIB:
        for chunk_size in [4 * MIB, 64 * MIB]:
            add(FAST_ALG, 12, chunk_size, "full")
            add(FAST_ALG, 12, chunk_size, "streaming")
            for k in SAMPLED_K:
                add(FAST_ALG, 12, chunk_size, "sampled", k)
            add(FAST_ALG, 12, chunk_size, "cached")
    return plans


def run_bench(
    out_root: Path, *, quick: bool = False, reduced: bool = False, work_dir: Path | None = None
) -> Path:
    run_dir = out_root / _run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    sizes = SIZES_QUICK if quick else SIZES_FULL
    work = work_dir or Path(".bench-work")
    cleanup_work = work_dir is None
    if cleanup_work and work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    trial_id = 1
    bench_start = time.perf_counter()
    try:
        files: dict[int, Path] = {}
        for size in sizes:
            file_path = work / f"random-{size}.bin"
            if not file_path.exists() or file_path.stat().st_size != size:
                print(f"generating {size} bytes at {file_path}", flush=True)
                _write_random(file_path, size)
            else:
                print(f"reusing {size} byte file at {file_path}", flush=True)
            files[size] = file_path
        for size, file_path in files.items():
            trials = _trial_count(size, quick, reduced)
            manifest_cache: dict[tuple[str, int, int], tuple[BenchManifest, dict[str, Any]]] = {}
            for alg, thread_count, chunk_size, mode, k in _plans_for_size(size):
                print(
                    "bench "
                    f"size={size} alg={alg} threads={thread_count} chunk={chunk_size} "
                    f"mode={mode}{'' if k is None else f'-{k}'}",
                    flush=True,
                )
                key = (alg, thread_count, chunk_size)
                if key not in manifest_cache:
                    manifest = _create_manifest(file_path, chunk_size, alg, thread_count)
                    manifest_cache[key] = (manifest, _cache_record(file_path, manifest))
                manifest, cache_record = manifest_cache[key]
                for _ in range(trials):
                    row = _run_one(trial_id, file_path, manifest, mode, k, cache_record)
                    rows.append(row)
                    trial_id += 1
        detection_size = GIB if GIB in files else max(files)
        detection_manifest = _create_manifest(files[detection_size], MIB, FAST_ALG, 12)
        detection_trials = 50 if (quick or reduced) else DETECTION_TRIALS
        detection, trial_id = _sampled_detection_rows(
            trial_id, files[detection_size], detection_manifest, detection_trials
        )
        rows.extend(detection)
        tamper_manifest = _create_manifest(files[detection_size], 16 * MIB, FAST_ALG, 12)
        full_tamper_trials = 6 if quick else (10 if reduced else 30)
        full_tamper, trial_id = _full_tamper_rows(
            trial_id, files[detection_size], tamper_manifest, full_tamper_trials
        )
        rows.extend(full_tamper)
        sig_rows, trial_id = _signature_rows(trial_id, 5 if quick else 30, work)
        rows.extend(sig_rows)
        corpus_rows, trial_id, corpus_summary = _corpus_rows(trial_id, work)
        rows.extend(corpus_rows)
    finally:
        if cleanup_work:
            shutil.rmtree(work, ignore_errors=True)
    _write_measurements(run_dir, rows)
    summary = summarize(rows, quick=quick)
    summary["structural_tamper_corpus"] = corpus_summary
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    env = {
        "python": sys.version,
        "platform": _platform_label(),
        "machine": platform.machine(),
        "cpu": platform.processor(),
        "package_versions": _pip_freeze(),
        "docker_images": ["python:3.12-slim"],
        "quick": quick,
        "profile": "quick" if quick else ("reduced" if reduced else "full"),
        "measurement_kind": "direct",
        "wall_clock_seconds": time.perf_counter() - bench_start,
        "page_cache": "warm; unprivileged container did not drop caches between trials",
        "matrix": {
            "sizes": sizes,
            "full_streaming": {
                "chunk_size": 16 * MIB,
                "thread_counts": FULL_STREAM_THREADS,
                "algorithms": ALGORITHMS,
            },
            "chunk_sweep": {
                "size": GIB,
                "chunk_sizes": CHUNK_SIZES,
                "thread_count": 12,
                "algorithm": FAST_ALG,
            },
            "sampled_cached": {
                "chunk_size": 16 * MIB,
                "thread_count": 12,
                "algorithm": FAST_ALG,
            },
            "tamper_corpus_seed": DEFAULT_CORPUS_SEED,
            "algorithms": ALGORITHMS,
            "sampled_k": SAMPLED_K,
            "verification_trials_by_size": {
                str(size): _trial_count(size, quick, reduced) for size in sizes
            },
            "sampled_detection_trials": detection_trials,
            "full_tamper_trials": full_tamper_trials,
        },
    }
    (run_dir / "env.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _manifest_sha256(run_dir)
    return run_dir


def _write_measurements(run_dir: Path, rows: list[dict[str, Any]]) -> None:
    keys: list[str] = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    with (run_dir / "measurements.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    log_dir = run_dir / "per-trial-logs"
    log_dir.mkdir(exist_ok=True)
    width = max(3, len(str(len(rows))))
    for row in rows:
        trial = int(row["trial"])
        (log_dir / f"trial-{trial:0{width}d}.json").write_text(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )


def summarize(rows: list[dict[str, Any]], *, quick: bool = False) -> dict[str, Any]:
    groups: dict[str, list[float]] = {}
    throughputs: dict[str, list[float]] = {}
    ok_count = 0
    for row in rows:
        ok_count += int(bool(row["ok"]))
        key = (
            f"{row['mode']}|{row['alg']}|{row['size_bytes']}|{row['chunk_size']}|"
            f"t{row['thread_count']}"
        )
        groups.setdefault(key, []).append(float(row["elapsed_ms"]))
        if row["throughput_gbps"] != "":
            throughputs.setdefault(key, []).append(float(row["throughput_gbps"]))
    metrics: dict[str, Any] = {}
    for key, values in groups.items():
        ci = mean_t_ci(values)
        p95 = bootstrap_quantile_ci(values, 0.95, resamples=500, seed=7)
        entry: dict[str, Any] = {"n": len(values), "mean_ms": ci.as_dict(), "p95_ms": p95.as_dict()}
        if key in throughputs:
            entry["throughput_gbps"] = mean_t_ci(throughputs[key]).as_dict()
        metrics[key] = entry
    detection = _summarize_detection(rows)
    full_tamper = _summarize_full_tamper(rows)
    hypotheses = _hypotheses(metrics, detection, full_tamper, quick=quick)
    return {
        "ok_rate": wilson(ok_count, len(rows)).as_dict(),
        "metrics": metrics,
        "sampled_detection": detection,
        "full_tamper_detection": full_tamper,
        "headline_4g": _headline_4g(metrics),
        "thread_scaling": _thread_scaling(metrics),
        "hypotheses": hypotheses,
    }


def _summarize_detection(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, tuple[int, int, float]] = {}
    for row in rows:
        if not str(row["mode"]).startswith("sampled-detection"):
            continue
        key = f"f={row['tamper_fraction']}|{row['mode']}"
        detected, total, theory = grouped.get(key, (0, 0, float(row["theory"])))
        grouped[key] = (detected + int(bool(row["ok"])), total + 1, theory)
    return {
        key: {"detected": d, "n": n, "wilson": wilson(d, n).as_dict(), "theory": theory}
        for key, (d, n, theory) in grouped.items()
    }


def _summarize_full_tamper(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tamper_rows = [row for row in rows if row["mode"] == "full-tamper-detection"]
    detected = sum(int(bool(row["ok"])) for row in tamper_rows)
    return {
        "detected": detected,
        "n": len(tamper_rows),
        "wilson": wilson(detected, len(tamper_rows)).as_dict(),
    }


def _hypotheses(
    metrics: dict[str, Any],
    detection: dict[str, Any],
    full_tamper: dict[str, Any],
    *,
    quick: bool = False,
) -> dict[str, Any]:
    four_g = [
        metric["mean_ms"]["point"]
        for key, metric in metrics.items()
        if f"|{4 * GIB}|" in key and key.startswith(("full|", "streaming|", "cached|", "sampled-"))
    ]
    h1_pass = bool(four_g) and max(four_g) <= 120
    h2_metric = metrics.get(f"full|blake3|{4 * GIB}|{16 * MIB}|t12")
    h2_ci = h2_metric.get("throughput_gbps") if h2_metric else None
    h4_pass = all(
        item["wilson"]["low"] <= item["theory"] <= item["wilson"]["high"]
        for item in detection.values()
    )
    sig_values = [
        metric["mean_ms"]["point"]
        for key, metric in metrics.items()
        if key.startswith("signature-verify|")
    ]
    return {
        "H1_4GB_verify_le_120ms": {
            "verdict": "inconclusive-quick" if quick else ("pass" if h1_pass else "fail"),
            "max_mean_ms": max(four_g) if four_g else None,
        },
        "H2_blake3_ge_1_2GBps": {
            "verdict": "pass" if h2_ci and h2_ci["point"] >= 1.2 else "fail",
            "throughput_gbps": h2_ci,
        },
        "H3_full_tamper_detection_100pct": {
            "verdict": "pass"
            if full_tamper["n"] > 0 and full_tamper["detected"] == full_tamper["n"]
            else "fail",
            "wilson": full_tamper["wilson"],
            "n": full_tamper["n"],
        },
        "H4_sampled_matches_theory": {"verdict": "pass" if h4_pass else "fail"},
        "H5_signature_verify_le_30ms": {
            "verdict": "pass" if sig_values and max(sig_values) <= 30 else "fail",
            "max_mean_ms": max(sig_values) if sig_values else None,
        },
    }


def _headline_4g(metrics: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, metric in metrics.items():
        parts = key.split("|")
        if len(parts) < 5 or parts[2] != str(4 * GIB):
            continue
        mode, alg, _, chunk, thread = parts
        if chunk != str(16 * MIB) or thread != "t12":
            continue
        out[f"{mode}|{alg}|{thread}|chunk16MiB"] = metric
    return out


def _thread_scaling(metrics: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, metric in metrics.items():
        parts = key.split("|")
        if len(parts) < 5:
            continue
        mode, alg, size, chunk, thread = parts
        if mode == "full" and alg == "blake3" and size == str(4 * GIB) and chunk == str(16 * MIB):
            out[thread] = metric.get("throughput_gbps", {})
    return out


def _pip_freeze() -> list[str]:
    try:
        out = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
    except (OSError, subprocess.CalledProcessError):
        return []
    return sorted(line for line in out.splitlines() if line)


def _manifest_sha256(run_dir: Path) -> None:
    entries = [
        f"{_sha256_file(path)}  {path.relative_to(run_dir).as_posix()}"
        for path in sorted(
            p for p in run_dir.rglob("*") if p.is_file() and p.name != "manifest.sha256"
        )
    ]
    (run_dir / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="results")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--reduced", action="store_true")
    parser.add_argument("--work-dir", default=None)
    args = parser.parse_args(argv)
    if args.quick and args.reduced:
        parser.error("--quick and --reduced are mutually exclusive")
    work_dir = Path(args.work_dir) if args.work_dir else None
    print(run_bench(Path(args.out), quick=args.quick, reduced=args.reduced, work_dir=work_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
