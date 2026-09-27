# Claims tested

Version 1 is `results/20260926T071158Z-6985cae672f8`. The current large-artifact run is `results/20260927T060546Z-Parag-Surfac`; the structural tamper corpus run is `results/20260927T063400Z-Parag-Surfac-corpus`. All rows are direct measurements with per-trial logs and `manifest.sha256` files.

| Claim | Metric | Threshold | Result | Outcome |
|---|---|---:|---|---|
| Full cold verification latency | 4 GiB full Merkle SHA-256 | <= 120 ms | 19324.6 ms, 0.207 GiB/s | Not met; every byte must be read and hashed |
| Warm cached verification latency | Trusted cached-root metadata check | <= 120 ms | 0.504 ms | Met, but not equivalent to full hashing |
| Incremental verification latency | One declared 16 MiB changed chunk | <= 120 ms | 65.5 ms | Met for declared changed-range security only |
| GGUF same-name model swap | Generated test split | 200 / 200 blocked | 200 / 200 blocked, Wilson low 0.981 | Met |
| Structural tamper detection | All generated test tamper classes | 100 percent | 227 / 227 detected, Wilson low 0.983 | Met |
| False positives | Untampered generated test artifacts | 0 percent | 0 / 200, Wilson high 0.019 | Met in point estimate |
| Signature verification | ECDSA P-256 verify | <= 30 ms | 0.613 ms | Met |

## Large-artifact latency table

| Size | Cold full Merkle verify | Streaming Merkle verify | Cached-root check | Incremental one-chunk check | Sampled 8 chunks |
|---:|---:|---:|---:|---:|---:|
| 256 MiB | 1397.0 ms, 0.180 GiB/s | 1403.2 ms, 0.179 GiB/s | 0.353 ms | 111.5 ms | 742.0 ms |
| 1 GiB | 6270.5 ms, 0.160 GiB/s | 5333.3 ms, 0.188 GiB/s | 0.525 ms | 86.4 ms | 655.5 ms |
| 4 GiB | 19324.6 ms, 0.207 GiB/s | 17537.0 ms, 0.228 GiB/s | 0.504 ms | 65.5 ms | 574.6 ms |

## Per-class tamper detection on test split

| Class | Detected / n | Wilson 95 percent interval |
|---|---:|---:|
| Single-bit weights | 2 / 2 | 34.2 to 100.0 percent |
| Single-bit header | 2 / 2 | 34.2 to 100.0 percent |
| Tensor swap | 2 / 2 | 34.2 to 100.0 percent |
| Architecture metadata edit | 2 / 2 | 34.2 to 100.0 percent |
| Tokenizer metadata edit | 2 / 2 | 34.2 to 100.0 percent |
| Chat template injection | 2 / 2 | 34.2 to 100.0 percent |
| Truncation | 2 / 2 | 34.2 to 100.0 percent |
| Append | 2 / 2 | 34.2 to 100.0 percent |
| Same-name model substitution | 201 / 201 | 98.1 to 100.0 percent |
| Signature stripping | 2 / 2 | 34.2 to 100.0 percent |
| Untrusted signature | 2 / 2 | 34.2 to 100.0 percent |
| Model bill of materials entry drift | 2 / 2 | 34.2 to 100.0 percent |
| Dependency swap | 2 / 2 | 34.2 to 100.0 percent |
| Rollback to older signed version | 2 / 2 | 34.2 to 100.0 percent |

## Ablation

| Version | Change | Detection rate | False-positive rate | Representative latency |
|---|---|---:|---:|---:|
| Version 1 | Original direct run | 10 / 10 | Not measured | 3483.9 ms BLAKE3 full cold; 0.131 ms cached |
| Version 2a | Structural generated corpus | 227 / 227 | 0 / 200 | Not a latency change |
| Version 2b | Merkle tree cold verification | 10 / 10 full tamper cases plus corpus above | 0 / 200 | 19324.6 ms SHA-256 full cold |
| Version 2c | Warm cached-root check | Same detection after trusted cache setup | 0 / 200 | 0.504 ms |
| Final | Incremental declared changed chunk | Same detection for declared changed chunks | 0 / 200 | 65.5 ms for one 16 MiB chunk |

## Negative results and reasons

- The full cold 4 GiB verification claim remains unmet. Reading and hashing 4 GiB dominates latency; the measured SHA-256 Merkle path took 19.3 seconds on this Windows host, while the earlier BLAKE3 Linux run took 3.48 seconds.
- Cached-root verification meets 120 ms but reads no model bytes. It is a cache validity check, not a full verification.
- Incremental verification meets 120 ms for one changed chunk, but only when changed byte ranges are trustworthy and complete.
- Most per-class intervals remain wide because only the same-name GGUF swap and clean-control counts were expanded to 200 examples.
