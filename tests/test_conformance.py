from __future__ import annotations

import json
from pathlib import Path

from ai_bill_of_materials_verifier import stats

PKG = "ai_bill_of_materials_verifier"


def test_stats_golden_vectors() -> None:
    data = json.loads(Path("conformance/golden_vectors.json").read_text(encoding="utf-8"))
    assert data["ref_version"] == stats.REF_VERSION
    tol = data["tolerance"]
    for row in data["wilson"]:
        got = stats.wilson(row["k"], row["n"])
        assert abs(got.low - row["low"]) <= tol
        assert abs(got.high - row["high"]) <= tol
    for row in data["quantile"]:
        assert abs(stats.quantile(row["values"], row["q"]) - row["value"]) <= tol
    mean = stats.mean_t_ci(data["mean_t_ci"]["values"])
    assert abs(mean.point - data["mean_t_ci"]["point"]) <= tol
    assert abs(mean.low - data["mean_t_ci"]["low"]) <= tol
    assert abs(mean.high - data["mean_t_ci"]["high"]) <= tol
    boot = data["bootstrap_quantile_ci"]
    got = stats.bootstrap_quantile_ci(
        boot["values"], boot["q"], resamples=boot["resamples"], seed=boot["seed"]
    )
    assert abs(got.point - boot["point"]) <= tol
    assert abs(got.low - boot["low"]) <= tol
    assert abs(got.high - boot["high"]) <= tol
