from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from ai_bill_of_materials_verifier.corpus import (
    DEFAULT_CORPUS_SEED,
    evaluate_corpus,
    generate_corpus,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="corpus/tamper-corpus")
    parser.add_argument("--seed", type=int, default=DEFAULT_CORPUS_SEED)
    args = parser.parse_args()
    root = generate_corpus(Path(args.out), seed=args.seed)
    summary = {split: asdict(evaluate_corpus(root, split)) for split in ("dev", "test")}
    (root / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
