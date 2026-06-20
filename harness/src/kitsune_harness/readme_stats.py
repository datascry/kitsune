# harness/readme_stats — generate the README "What it detects" stats from contracts/rules/registry.yaml.
# Splices the rule count + per-class table between GENERATED markers so the headline metrics never drift.

"""Generate the README's ``## What it detects`` stats block from the single source of truth.

The README headline metrics — total rule count, the active/experimental/retired split, and the per-class
breakdown — are derived entirely from ``contracts/rules/registry.yaml``. Hand-maintaining them guarantees
drift (they were stale by 17 rules before this generator). This module renders them between
``<!-- GENERATED:readme-stats:start -->`` / ``<!-- GENERATED:readme-stats:end -->`` markers, leaving the
curated prose untouched. The per-class *descriptions* are curated constants here; only the *counts* are derived.

    uv run python -m kitsune_harness.readme_stats            # rewrite the generated block in place
    uv run python -m kitsune_harness.readme_stats --check    # exit 1 if the committed block is stale (CI)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[3]
_REGISTRY = _ROOT / "contracts" / "rules" / "registry.yaml"
_README = _ROOT / "README.md"
_START = "<!-- GENERATED:readme-stats:start -->"
_END = "<!-- GENERATED:readme-stats:end -->"

_CONVICTING = {"coherence", "automation", "artifact"}

# Display order: convicting classes first (these can push a session to `bot`), then corroborating. Each
# carries a curated one-line description of what that class catches (the counts are derived from the registry).
_CLASSES: list[tuple[str, str]] = [
    ("coherence", "cross-vector contradictions (TLS↔TCP↔UA↔JS↔h2↔QUIC) — the thesis core"),
    ("automation", "the framework surface: `webdriver`, CDP runtime, Electron, isolated-world leaks"),
    ("artifact", "anti-detect *implementation* flaws: tampered natives, spoof placeholders"),
    ("environment", "stripped/headless capability gaps (corroborating only — see precision)"),
    ("behavioral", "mouse/keystroke biomechanics — path straightness, velocity CV, entropy floors"),
    ("reputation", "datacenter ASN / known proxy exit / WebRTC-leaked origin"),
    ("prevalence", "statistically-improbable-but-coherent fingerprints"),
]


def generate_stats_md(registry_path: Path = _REGISTRY) -> str:
    """Render the README stats block (the content between the GENERATED markers)."""
    doc = yaml.safe_load(registry_path.read_text())
    rules: list[dict[str, Any]] = doc["rules"]
    version = doc["ruleset_version"]

    def status(r: dict[str, Any]) -> str:
        return str(r.get("status", "active"))

    live = [r for r in rules if status(r) != "retired"]
    active = sum(1 for r in rules if status(r) == "active")
    experimental = sum(1 for r in rules if status(r) == "experimental")
    retired = sum(1 for r in rules if status(r) == "retired")
    convicting = sum(1 for r in live if r.get("category") in _CONVICTING)

    per_class: dict[str, int] = {}
    for r in live:
        per_class[str(r.get("category", "?"))] = per_class.get(str(r.get("category", "?")), 0) + 1

    out: list[str] = []
    out.append(
        f"**{len(live)} live rules** ({active} active · {experimental} experimental; {retired} retired, ruleset "
        f"`{version}`) — each a small predicate over the correlated session. **{convicting} can convict** "
        f"(coherence/automation/artifact); the rest only corroborate. Grouped by detection class:"
    )
    out.append("")
    out.append("| Class | Rules | Convicts? | What it catches |")
    out.append("|---|---:|:--:|---|")
    for name, desc in _CLASSES:
        n = per_class.get(name, 0)
        convicts = "✦" if name in _CONVICTING else "—"
        out.append(f"| **{name}** | {n} | {convicts} | {desc} |")
    # Any class not in the curated list (a new category) still shows, so the table can't silently omit rules.
    for name in sorted(per_class):
        if name not in {c for c, _ in _CLASSES}:
            out.append(f"| **{name}** | {per_class[name]} | ? | _(new class — add a description in readme_stats.py)_ |")
    out.append("")
    out.append(
        "_✦ convicting · — corroborating-only. The conviction gate means corroborating "
        "signals can never reach `bot` alone._"
    )
    return "\n".join(out).rstrip() + "\n"


def render_into(readme_path: Path = _README, registry_path: Path = _REGISTRY) -> str:
    """Return the README text with the GENERATED block replaced by current stats. Does not write."""
    text = readme_path.read_text()
    if _START not in text or _END not in text:
        raise SystemExit(f"{readme_path} is missing the {_START} / {_END} markers")
    pre = text[: text.index(_START) + len(_START)]
    post = text[text.index(_END) :]
    return f"{pre}\n{generate_stats_md(registry_path)}\n{post}"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    new = render_into()
    if "--check" in args:
        if _README.read_text() != new:  # pragma: no cover - stale path is a CI-failure branch
            print("README 'What it detects' stats are STALE — run `task docs`", file=sys.stderr)
            return 1
        print("README stats are up to date")
        return 0
    _README.write_text(new)  # pragma: no cover - write path exercised via `task docs`
    print(f"wrote README stats into {_README.relative_to(_ROOT)}")  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - thin CLI
    raise SystemExit(main())
