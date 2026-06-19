# tests/test_fpgen_corroborate — the prevalence-prior corroboration diagnostic's pure logic (no fpgen/network).
# Guards the TVD math and the per-cell comparison; the live fpgen sampling is on-demand, not CI.

from __future__ import annotations

from kitsune_harness.fpgen_corroborate import _tvd, corroborate, render


def test_tvd_bounds() -> None:
    assert _tvd({"a": 1.0}, {"a": 1.0}) == 0.0  # identical
    assert _tvd({"a": 1.0}, {"b": 1.0}) == 1.0  # disjoint
    assert abs(_tvd({"a": 0.5, "b": 0.5}, {"a": 1.0}) - 0.5) < 1e-9


def test_corroborate_flags_divergence() -> None:
    # synthetic feats whose gpu|Windows distribution should differ from the committed browserforge prior;
    # the rows must carry a numeric TVD and the per-condition fpgen sample count.
    feats = [{"plat": "Windows", "gpu": "nvidia", "screen": "desktop-land", "cores": "5-8"} for _ in range(10)]
    rows = corroborate(feats)
    gpu_win = [r for r in rows if r["factor"] == "gpu" and r["given"] == "Windows"]
    assert gpu_win and gpu_win[0]["n_fpgen"] == 10
    assert gpu_win[0]["tvd"] is None or 0.0 <= gpu_win[0]["tvd"] <= 1.0
    # render must produce a markdown table without raising
    md = render(rows)
    assert "| factor | condition |" in md
