# harness/rule_catalog — generate the COMPLETE detection-rule registry from contracts/rules/registry.yaml.
# Splices a grouped table of every rule into docs/detection-catalog.md between GENERATED markers; --check gates CI.

"""Generate the complete rule registry section of ``docs/detection-catalog.md``.

The catalog's primary purpose is to be an exhaustive, always-current list of EVERY detection rule Kitsune
leverages — generated from the single source of truth (``contracts/rules/registry.yaml``) so it cannot drift.
This module renders one table per layer (rules grouped by category, convicting categories first) and splices
it between ``<!-- GENERATED:rules:start -->`` / ``<!-- GENERATED:rules:end -->`` markers, leaving the curated
frontier/findings prose around them untouched.

    uv run python -m kitsune_harness.rule_catalog            # rewrite the generated block in place
    uv run python -m kitsune_harness.rule_catalog --check    # exit 1 if the committed block is stale (CI)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[3]
_REGISTRY = _ROOT / "contracts" / "rules" / "registry.yaml"
_CATALOG = _ROOT / "docs" / "detection-catalog.md"
_START = "<!-- GENERATED:rules:start -->"
_END = "<!-- GENERATED:rules:end -->"

# Display order: layers top-to-bottom, categories convicting-first (coherence/automation/artifact convict;
# the rest only ever corroborate). Anything unlisted sorts last alphabetically.
_LAYER_ORDER = ["network", "browser", "behavioral", "reputation"]
_CATEGORY_ORDER = ["coherence", "automation", "artifact", "environment", "prevalence", "behavioral", "reputation"]
_CONVICTING = {"coherence", "automation", "artifact"}


def _rank(seq: list[str], value: str) -> tuple[int, str]:
    return (seq.index(value) if value in seq else len(seq), value)


def _cell(text: str) -> str:
    """Make a string safe for a one-line markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def generate_registry_md(registry_path: Path = _REGISTRY) -> str:
    """Render the full rule registry as markdown (the content that lives between the GENERATED markers)."""
    doc = yaml.safe_load(registry_path.read_text())
    rules: list[dict[str, Any]] = doc["rules"]
    version = doc["ruleset_version"]

    active = sum(1 for r in rules if r.get("status", "active") == "active")
    experimental = sum(1 for r in rules if r.get("status") == "experimental")
    retired = sum(1 for r in rules if r.get("status") == "retired")
    convicting = sum(1 for r in rules if r.get("category") in _CONVICTING and r.get("status") != "retired")

    out: list[str] = []
    out.append("## Complete rule registry")
    out.append("")
    out.append(
        f"> Every detection rule Kitsune leverages — **generated** from `contracts/rules/registry.yaml` "
        f"(ruleset `{version}`); regenerate with `task catalog`, do not edit by hand. "
        f"**{len(rules)} rules**: {active} active · {experimental} experimental · {retired} retired; "
        f"{convicting} convicting (coherence/automation/artifact — only these can convict a `bot`; "
        f"environment/behavioral/reputation/prevalence corroborate only)."
    )
    out.append("")

    by_layer: dict[str, list[dict[str, Any]]] = {}
    for r in rules:
        for layer in r.get("layers", ["?"]):
            by_layer.setdefault(layer, []).append(r)

    for layer in sorted(by_layer, key=lambda v_layer: _rank(_LAYER_ORDER, v_layer)):
        layer_rules = by_layer[layer]
        out.append(f"### {layer} layer ({len(layer_rules)})")
        out.append("")
        out.append("| rule | category | predicate | wt | status | what it catches |")
        out.append("|---|---|---|---|---|---|")
        ordered = sorted(
            layer_rules,
            key=lambda r: (_rank(_CATEGORY_ORDER, r.get("category", "?")), r["id"]),
        )
        for r in ordered:
            cat = r.get("category", "—")
            convict = "✦" if cat in _CONVICTING and r.get("status") != "retired" else ""
            out.append(
                f"| `{r['id']}` | {cat}{convict} | {r.get('predicate', '—')} | "
                f"{r.get('weight', '—')} | {r.get('status', 'active')} | {_cell(str(r.get('title', '')))} |"
            )
        out.append("")

    out.append("_✦ = a convicting category (can push a session to `bot`); all others corroborate only._")
    return "\n".join(out).rstrip() + "\n"


def render_into(catalog_path: Path = _CATALOG, registry_path: Path = _REGISTRY) -> str:
    """Return the catalog text with the GENERATED block replaced by the current registry. Does not write."""
    text = catalog_path.read_text()
    if _START not in text or _END not in text:
        raise SystemExit(f"{catalog_path} is missing the {_START} / {_END} markers")
    pre = text[: text.index(_START) + len(_START)]
    post = text[text.index(_END) :]
    block = generate_registry_md(registry_path)
    return f"{pre}\n{block}\n{post}"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    check = "--check" in args
    new = render_into()
    if check:
        if _CATALOG.read_text() != new:
            print("docs/detection-catalog.md rule registry is STALE — run `task catalog`", file=sys.stderr)
            return 1
        print("rule registry is up to date")
        return 0
    _CATALOG.write_text(new)
    print(f"wrote rule registry into {_CATALOG.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
