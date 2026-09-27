#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest -q --cov=ai_bill_of_materials_verifier --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
