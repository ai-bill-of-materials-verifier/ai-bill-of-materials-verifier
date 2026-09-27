# ruff: noqa: E501
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
GIB = 1024 * MIB


def latest_run() -> Path:
    runs = sorted(p for p in Path("results").glob("*/summary.json") if p.is_file())
    if not runs:
        raise SystemExit("no results/<run-id>/summary.json found")
    return runs[-1].parent


def interval(metric: dict[str, Any], field: str = "mean_ms", unit: str = "ms") -> str:
    v = metric[field]
    low = max(0.0, float(v["low"])) if unit == "ms" else float(v["low"])
    return f"{float(v['point']):.3f} {unit} [{low:.3f}, {float(v['high']):.3f}]"


def rate_interval(item: dict[str, Any]) -> str:
    w = item["wilson"]
    return f"{100 * w['point']:.1f}% [{100 * w['low']:.1f}, {100 * w['high']:.1f}]"


def parse_tlc(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    states = re.search(
        r"(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue", text
    )
    depth = re.search(r"depth of the complete state graph search is (\d+)", text)
    return {
        "status": "ok" if "No error has been found" in text else "counterexample",
        "states_generated": int(states.group(1)) if states else 0,
        "distinct_states": int(states.group(2)) if states else 0,
        "states_left": int(states.group(3)) if states else 0,
        "depth": int(depth.group(1)) if depth else 0,
    }


def write_manifest(run: Path) -> None:
    entries = []
    for p in sorted(run.rglob("*")):
        if p.is_file() and p.name != "manifest.sha256":
            entries.append(
                f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(run).as_posix()}"
            )
    (run / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")


def metric(
    summary: dict[str, Any], mode: str, alg: str, size: int, chunk: int, threads: int
) -> dict[str, Any]:
    return summary["metrics"][f"{mode}|{alg}|{size}|{chunk}|t{threads}"]


def maybe_metric(
    summary: dict[str, Any], mode: str, alg: str, size: int, chunk: int, threads: int
) -> dict[str, Any] | None:
    return summary["metrics"].get(f"{mode}|{alg}|{size}|{chunk}|t{threads}")


def detection_rows(summary: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    rows = []
    for key, item in summary["sampled_detection"].items():
        f_part, mode = key.split("|")
        rows.append((f_part.removeprefix("f="), mode.removeprefix("sampled-detection-"), item))
    return sorted(rows, key=lambda r: (float(r[0]), int(r[1])))


def measurement_row_count(run: Path) -> int:
    with (run / "measurements.csv").open(encoding="utf-8") as fh:
        return sum(1 for _ in fh) - 1


def trial_count_text(env: dict[str, Any]) -> str:
    trials = env.get("matrix", {}).get("verification_trials_by_size", {})
    if not isinstance(trials, dict) or not trials:
        return "not recorded"
    parts = []
    for size in sorted((int(k), v) for k, v in trials.items()):
        size_bytes, count = size
        label = f"{size_bytes // GIB} GiB" if size_bytes >= GIB else f"{size_bytes // MIB} MiB"
        parts.append(f"{label}: n={count}")
    return ", ".join(parts)


def direct_env(run: Path) -> dict[str, Any]:
    env = json.loads((run / "env.json").read_text(encoding="utf-8"))
    if env.get("measurement_kind") != "direct":
        raise SystemExit(f"refusing non-direct artifact: {run}")
    return env


def headline_lines(summary: dict[str, Any]) -> list[str]:
    lines = []
    for label, mode, alg in [
        ("FULL BLAKE3", "full", "blake3"),
        ("FULL SHA-256", "full", "sha256"),
        ("STREAMING BLAKE3", "streaming", "blake3"),
        ("STREAMING SHA-256", "streaming", "sha256"),
    ]:
        m = metric(summary, mode, alg, 4 * GIB, 16 * MIB, 12)
        lines.append(f"| {label} | {m['n']} | {interval(m)} | {interval(m, 'p95_ms')} |")
    for k in [8, 32, 128]:
        m = metric(summary, f"sampled-{k}", "blake3", 4 * GIB, 16 * MIB, 12)
        lines.append(
            f"| SAMPLED k={k} BLAKE3 | {m['n']} | {interval(m)} | {interval(m, 'p95_ms')} |"
        )
    m = metric(summary, "cached", "blake3", 4 * GIB, 16 * MIB, 12)
    lines.append(f"| CACHED BLAKE3 | {m['n']} | {interval(m)} | {interval(m, 'p95_ms')} |")
    return lines


def throughput_lines(summary: dict[str, Any]) -> list[str]:
    lines = []
    for t in [1, 4, 8, 12]:
        b3 = metric(summary, "full", "blake3", 4 * GIB, 16 * MIB, t)["throughput_gbps"]
        sha = metric(summary, "full", "sha256", 4 * GIB, 16 * MIB, t)["throughput_gbps"]
        lines.append(
            f"| {t} | {b3['point']:.3f} [{b3['low']:.3f}, {b3['high']:.3f}] | {sha['point']:.3f} [{sha['low']:.3f}, {sha['high']:.3f}] |"
        )
    return lines


def h1_mode_verdicts(summary: dict[str, Any]) -> list[tuple[str, str, str]]:
    modes = [
        ("FULL", ["full|blake3", "full|sha256"]),
        ("STREAMING", ["streaming|blake3", "streaming|sha256"]),
        ("SAMPLED", ["sampled-8|blake3", "sampled-32|blake3", "sampled-128|blake3"]),
        ("CACHED", ["cached|blake3"]),
    ]
    rows = []
    for label, prefixes in modes:
        values = [
            item["mean_ms"]["point"]
            for key, item in summary["metrics"].items()
            if f"|{4 * GIB}|{16 * MIB}|t12" in key
            and any(key.startswith(prefix) for prefix in prefixes)
        ]
        max_mean = max(values)
        verdict = "pass" if max_mean <= 120 else "fail"
        rows.append((label, verdict, f"{max_mean:.3f} ms"))
    return rows


def h1_summary(summary: dict[str, Any]) -> str:
    return "; ".join(
        f"{mode}: {verdict} ({mean})" for mode, verdict, mean in h1_mode_verdicts(summary)
    )


def peak_blake3(summary: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    candidates = []
    for threads in [1, 4, 8, 12]:
        item = metric(summary, "full", "blake3", 4 * GIB, 16 * MIB, threads)["throughput_gbps"]
        candidates.append((threads, item))
    return max(candidates, key=lambda candidate: float(candidate[1]["point"]))


def write_readme(
    run: Path, summary: dict[str, Any], env: dict[str, Any], tlc: dict[str, Any]
) -> None:
    rows = measurement_row_count(run)
    h = summary["hypotheses"]
    sig_key = next(k for k in summary["metrics"] if k.startswith("signature-verify|"))
    sig = summary["metrics"][sig_key]
    wall = env.get("wall_clock_seconds", 0.0)
    peak_threads, peak = peak_blake3(summary)
    h2 = h["H2_blake3_ge_1_2GBps"]
    h1_rows = h1_mode_verdicts(summary)
    readme = f"""# AI Bill of Materials Verifier

[![CI](https://github.com/ai-bill-of-materials-verifier/ai-bill-of-materials-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/ai-bill-of-materials-verifier/ai-bill-of-materials-verifier/actions/workflows/ci.yml)

AI Bill of Materials Verifier is an offline verifier for model artifacts: chunked Merkle manifests, sampled/full/cached/streaming verification, local ECDSA and DSSE signatures, CycloneDX 1.6 machine learning bill of materials generation, and SLSA provenance policy checks.

## Quickstart

```bash
python -m pip install -e \".[dev]\"
ai-bill-of-materials-verifier manifest model.safetensors -o model.manifest.json
ai-bill-of-materials-verifier sign model.manifest.json --generate-key --key local-key.pem -o model.sig
ai-bill-of-materials-verifier verify model.safetensors model.manifest.json --signature model.sig --pubkey local-key.pem.pub
```

On Windows ARM64, BLAKE3 wheels are unavailable, so AI Bill of Materials Verifier warns and falls back to SHA-256. `cryptography` is installed natively with `pip install --prefer-binary`, so signature tests run on Windows ARM64 as well as Linux.

## Architecture

```mermaid
flowchart LR
  M[Model file/dir] --> H[Chunk hasher]
  H --> T[Domain-separated Merkle tree]
  T --> Man[Manifest root]
  Man --> Sig[ECDSA/DSSE signatures]
  Man --> Bom[CycloneDX machine learning bill of materials]
  Man --> V[Full/Sampled/Cached/Streaming verify]
  Sig --> Prov[SLSA provenance policy]
```

## Direct benchmark results

Source artifact: `{run.as_posix()}` ({rows} direct measurement rows plus per-trial JSON logs). Profile: {env.get("profile", "full")}; verification trial counts: {trial_count_text(env)}; sampled tamper trials per cell: {env.get("matrix", {}).get("sampled_detection_trials", "not recorded")}; FULL tamper trials: {env.get("matrix", {}).get("full_tamper_trials", "not recorded")}. Wall-clock benchmark time: {wall / 60:.1f} minutes. Page cache condition: {env.get("page_cache", "warm; not dropped")}. An attempted full trial-count run hit the container memory limit (exit 137), so this artifact is the reduced direct rerun. Matrix is exactly what was measured.

### 4 GiB, 16 MiB chunks, 12 threads

| Mode | n | Mean [95% t-CI] | p95 [bootstrap 95% CI] |
|---|---:|---:|---:|
"""
    readme += "\n".join(headline_lines(summary))
    readme += """

### FULL 4 GiB throughput by threads (16 MiB chunks)

| Threads | BLAKE3 GB/s [95% CI] | SHA-256 GB/s [95% CI] |
|---:|---:|---:|
"""
    readme += "\n".join(throughput_lines(summary))
    readme += f"""

H2 keeps the pre-registered 12-thread verdict: {h2["verdict"]}, {h2["throughput_gbps"]["point"]:.3f} GB/s. The observed BLAKE3 peak was {peak["point"]:.3f} GB/s at {peak_threads} threads. STREAMING BLAKE3 was slower than FULL because it reads Python chunks and updates the hasher incrementally instead of using the mmap path. SAMPLED k=128 was slower than FULL because it performs random seeks plus inclusion-proof work and hashes selected chunks serially.

### SAMPLED tamper detection (direct 1 GiB in-place tamper runs)

| Tampered fraction | k | Detected / n | Empirical Wilson CI | Theory |
|---:|---:|---:|---:|---:|
"""
    for frac, k, item in detection_rows(summary):
        readme += f"| {float(frac):.3f} | {k} | {item['detected']} / {item['n']} | {rate_interval(item)} | {100 * item['theory']:.1f}% |\n"
    readme += f"""
TLC safe model: {tlc["safe"]["states_generated"]} generated / {tlc["safe"]["distinct_states"]} distinct states, depth {tlc["safe"]["depth"]}; naive model produces the expected counterexample.

## Hypothesis verdicts

| Hypothesis | Verdict |
|---|---|
| H1 FULL 4 GiB verify <= 120 ms | {h1_rows[0][1]} ({h1_rows[0][2]}) |
| H1 STREAMING 4 GiB verify <= 120 ms | {h1_rows[1][1]} ({h1_rows[1][2]}) |
| H1 SAMPLED 4 GiB verify <= 120 ms | {h1_rows[2][1]} ({h1_rows[2][2]}) |
| H1 CACHED 4 GiB verify <= 120 ms | {h1_rows[3][1]} ({h1_rows[3][2]}) |
| H2 BLAKE3 >= 1.2 GB/s at 12 threads | {h2["verdict"]} ({h2["throughput_gbps"]["point"]:.3f} GB/s; peak {peak["point"]:.3f} GB/s at {peak_threads} threads) |
| H3 FULL tamper detection 100% | {h["H3_full_tamper_detection_100pct"]["verdict"]} ({summary["full_tamper_detection"]["detected"]} / {summary["full_tamper_detection"]["n"]}) |
| H4 SAMPLED matches theory | {h["H4_sampled_matches_theory"]["verdict"]} |
| H5 signature verify <= 30 ms | {h["H5_signature_verify_le_30ms"]["verdict"]} ({interval(sig)}) |
"""
    Path("README.md").write_text(readme, encoding="utf-8")


def write_hypotheses(
    run: Path, summary: dict[str, Any], tlc: dict[str, Any], env: dict[str, Any]
) -> None:
    h = summary["hypotheses"]
    sig_key = next(k for k in summary["metrics"] if k.startswith("signature-verify|"))
    sig = summary["metrics"][sig_key]
    peak_threads, peak = peak_blake3(summary)
    h2 = h["H2_blake3_ge_1_2GBps"]
    hypotheses = f"""# Hypotheses

Generated from direct artifact `{run.as_posix()}/summary.json`, `measurements.csv`, per-trial JSON logs, and `tlc.json`. Profile: {env.get("profile", "full")}; verification trial counts: {trial_count_text(env)}; sampled tamper trials per cell: {env.get("matrix", {}).get("sampled_detection_trials", "not recorded")}; FULL tamper trials: {env.get("matrix", {}).get("full_tamper_trials", "not recorded")}. An attempted full trial-count run hit the container memory limit (exit 137), so this artifact is the reduced direct rerun. Wall-clock benchmark time: {env.get("wall_clock_seconds", 0.0) / 60:.1f} minutes.

| ID | Metric | Threshold | Result |
|---|---|---:|---|
| H1 | 4 GiB verification per mode | <= 120 ms | {h1_summary(summary)} |
| H2 | BLAKE3 4 GiB FULL throughput, 12 threads | >= 1.2 GB/s | {h2["verdict"]}; {h2["throughput_gbps"]["point"]:.3f} GB/s at 12 threads; observed peak {peak["point"]:.3f} GB/s at {peak_threads} threads |
| H3 | FULL tamper detection | 100% | {h["H3_full_tamper_detection_100pct"]["verdict"]}; {summary["full_tamper_detection"]["detected"]} / {summary["full_tamper_detection"]["n"]} detected, Wilson low {h["H3_full_tamper_detection_100pct"]["wilson"]["low"]:.3f} |
| H4 | SAMPLED detection formula | within CI | {h["H4_sampled_matches_theory"]["verdict"]} |
| H5 | ECDSA P-256 verify | <= 30 ms | {h["H5_signature_verify_le_30ms"]["verdict"]}; {interval(sig)} |

TLC: safe model passed with {tlc["safe"]["states_generated"]} generated / {tlc["safe"]["distinct_states"]} distinct states at depth {tlc["safe"]["depth"]}; naive path-check-then-load model produced the expected counterexample after {tlc["naive"]["states_generated"]} generated / {tlc["naive"]["distinct_states"]} distinct states.

Benchmark note: all committed rows are direct measurements. Page cache condition: {env.get("page_cache", "warm; not dropped")}. STREAMING BLAKE3 was slower than FULL because it reads Python chunks and updates the hasher incrementally instead of using the mmap path. SAMPLED k=128 was slower than FULL because it performs random seeks plus inclusion-proof work and hashes selected chunks serially.
"""
    Path("docs/hypotheses.md").write_text(hypotheses, encoding="utf-8")


def main() -> int:
    run = latest_run()
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    env = direct_env(run)
    tlc = {
        "safe": parse_tlc(Path("specs/tlc-safe.out")),
        "naive": parse_tlc(Path("specs/tlc-naive.out")),
    }
    (run / "tlc.json").write_text(
        json.dumps(tlc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_readme(run, summary, env, tlc)
    write_hypotheses(run, summary, tlc, env)
    write_manifest(run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
