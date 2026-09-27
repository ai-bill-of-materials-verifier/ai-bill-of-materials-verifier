#!/usr/bin/env python
from __future__ import annotations

import argparse
import json

from ai_bill_of_materials_verifier.stats import wilson


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("k", type=int)
    parser.add_argument("n", type=int)
    args = parser.parse_args()
    print(json.dumps(wilson(args.k, args.n).as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
