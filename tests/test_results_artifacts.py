from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path


def test_committed_results_are_direct_measurements() -> None:
    for env_path in Path("results").glob("*/env.json"):
        for artifact in env_path.parent.rglob("*"):
            if artifact.is_file():
                text = artifact.read_text(encoding="utf-8", errors="ignore")
                lowered = text.lower()
                for marker in ("calibrated", "model-expanded", "modelled", "modeled"):
                    assert marker not in lowered, artifact
        env = json.loads(env_path.read_text(encoding="utf-8"))
        assert "calibrated" not in env, env_path
        assert env.get("measurement_kind") == "direct", env_path
        rows_path = env_path.parent / "measurements.csv"
        assert rows_path.is_file(), rows_path
        with rows_path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows, rows_path
        for row in rows:
            assert row.get("measurement_kind") == "direct", row
            timestamp = row.get("timestamp_utc", "")
            assert timestamp, row
            datetime.fromisoformat(timestamp)
            elapsed_ms = float(row.get("elapsed_ms", ""))
            assert elapsed_ms > 0.0, row
        log_dir = env_path.parent / "per-trial-logs"
        assert log_dir.is_dir(), log_dir
        assert len(list(log_dir.glob("trial-*.json"))) == len(rows)
