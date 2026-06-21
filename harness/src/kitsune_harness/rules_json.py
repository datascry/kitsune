# harness/rules_json — export the coherence-rule registry as browser-consumable JSON.
# Emits each evaluable rule plus a clientEvaluable flag (true iff every read is a browser/behavioral signal).

"""Export the rule registry as JSON for the live in-browser detection page.

The live page (a static GitHub Pages site) evaluates the browser/behavioral subset of the rules
client-side. This CLI serialises the validated registry — the same one the detector loads — to JSON,
annotating each rule with ``clientEvaluable``: true when *every* signal it reads lives on the browser
or behavioral layer (so a browser with no edge can resolve it). Network/reputation/cross-layer rules
are emitted too (clientEvaluable=false) so the page can list them honestly as "requires Kitsune edge".

    python -m kitsune_harness.rules_json            # JSON to stdout
"""

from __future__ import annotations

import json
import sys
from typing import Any

from kitsune_detector.contracts import load_rule_registry

CLIENT_LAYERS = frozenset({"browser", "behavioral"})


def _client_evaluable(rule: dict[str, Any]) -> bool:
    """True iff every read resolves to a browser/behavioral signal (no edge needed)."""
    reads: list[str] = rule.get("reads", [])
    # bool(reads) guards the vacuous-true: a rule with no reads is NOT client-evaluable (an empty all() is
    # True, which would wrongly mark an unevaluable rule clientEvaluable).
    return bool(reads) and all(ref.split(".", 1)[0] in CLIENT_LAYERS for ref in reads)


def build() -> dict[str, Any]:
    version, rules = load_rule_registry()
    out_rules = [
        {
            "id": r["id"],
            "title": r["title"],
            "layers": r["layers"],
            "reads": r.get("reads", []),
            "predicate": r["predicate"],
            "threshold": r.get("threshold"),
            "weight": r["weight"],
            "category": r["category"],
            "status": r["status"],
            "clientEvaluable": _client_evaluable(r),
        }
        for r in rules
        if r.get("status") != "retired"
    ]
    return {"ruleset_version": version, "rules": out_rules}


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    _ = sys.argv[1:] if argv is None else argv
    print(json.dumps(build(), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
