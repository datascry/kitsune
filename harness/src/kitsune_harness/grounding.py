# harness/grounding — turnkey grounding sweep over a directory of REAL captured sessions.
# Runs per-session FP/recall + coordination grading + optional prevalence-prior rebuild; reports what grounds.

"""Grounding harness — turn operator-supplied REAL captures into grounded detection.

The recurring unlock (docs/grounding.md): every blocked frontier — real-traffic prevalence, coordination
IP-reputation, real-device coverage — needs data the sandbox cannot self-generate. This module is the
*consumer*: drop a directory of REAL session captures (the collector/edge shape — e.g. ``corpus/sessions/``,
a hosted-demo opt-in export, or a residential-proxy-fleet capture) and it runs the full grounding sweep in
one command, so the moment real data exists the blocked detections evaluate themselves.

1. **Per-session verdict** over the captures. With ``--expect legit`` (real users) any non-``human`` verdict
   is a FALSE POSITIVE (reported with the rules that fired) — the FP gate against REAL traffic, not synthetic
   browserforge. With ``--expect bot`` (a known-bad capture, e.g. a proxy fleet) any non-``bot`` is a MISS
   (the recall gate).
2. **Coordination grading** (:func:`coordination.score_corpus`) across the captures — on a legit corpus a
   ``fleet`` label is a coordination FP; on a bot corpus it is the detection.
3. **Optional prevalence-prior rebuild** (``--build-prior OUT``) from the real sessions — the Tier-3 prior
   that gives ``br.fingerprint_improbable`` detection power against generator-sampled fingerprints.

    cd harness && uv run python -m kitsune_harness.grounding /path/to/captures --expect legit
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from kitsune_detector.detector import Detector
from kitsune_detector.models import Label, Session
from kitsune_detector.scoring import CONVICTING_CATEGORIES

from .coordination import FleetVerdict, score_corpus


@dataclass(frozen=True)
class SessionOutcome:
    name: str
    label: str
    convicting: list[str]  # convicting (coherence/automation/artifact) rule ids that fired
    fired: list[str]  # all fired rule ids


@dataclass(frozen=True)
class GroundingReport:
    expect: str  # "legit" | "bot"
    outcomes: list[SessionOutcome]
    fleets: list[FleetVerdict]
    label_counts: dict[str, int] = field(default_factory=dict)

    @property
    def _fleet_members(self) -> set[str]:
        return {m for v in self.fleets for m in v.members}

    @property
    def misclassified(self) -> list[SessionOutcome]:
        """Sessions that violate the expectation. Under `legit`: any non-`human` (a false positive). Under
        `bot`: any session caught by NEITHER a per-session `bot` verdict NOR membership in a coordination
        fleet — a genuine miss (the thesis allows a per-session mimic to be caught at the cluster layer)."""
        if self.expect == "bot":
            return [o for o in self.outcomes if o.label != Label.bot.value and o.name not in self._fleet_members]
        return [o for o in self.outcomes if o.label != Label.human.value]

    @property
    def ok(self) -> bool:
        """A legit corpus grounds clean iff nothing misclassifies AND no coordination fleet fires; a bot
        corpus grounds iff every session is caught per-session or as a fleet member (no residual miss)."""
        if self.expect == "bot":
            return not self.misclassified
        return not self.misclassified and not self.fleets


def evaluate(detector: Detector, corpus: list[tuple[str, Session]], *, expect: str = "legit") -> GroundingReport:
    """Score every captured session + grade coordination. Pure over a loaded corpus (no IO)."""
    outcomes: list[SessionOutcome] = []
    counts: dict[str, int] = {}
    for name, session in corpus:
        verdict = detector.score(session)
        fired = [c.rule_id for c in verdict.contradictions]
        convicting = [c.rule_id for c in verdict.contradictions if c.category in CONVICTING_CATEGORIES]
        counts[verdict.label.value] = counts.get(verdict.label.value, 0) + 1
        outcomes.append(SessionOutcome(name=name, label=verdict.label.value, convicting=convicting, fired=fired))
    fleets = [v for v in score_corpus(corpus) if v.label == "fleet"]
    return GroundingReport(expect=expect, outcomes=outcomes, fleets=fleets, label_counts=counts)


def render(report: GroundingReport) -> str:
    """Render the grounding sweep as markdown."""
    n = len(report.outcomes)
    lines = [
        f"# Grounding sweep — {n} real capture(s), expecting `{report.expect}`",
        "",
        f"- verdicts: {', '.join(f'{k} {v}' for k, v in sorted(report.label_counts.items())) or '(none)'}",
        f"- coordination: {len(report.fleets)} fleet verdict(s)",
        f"- **{'GROUNDS CLEAN' if report.ok else 'NEEDS ATTENTION'}**",
        "",
    ]
    bad = report.misclassified
    if bad:
        kind = "missed bots (non-`bot`)" if report.expect == "bot" else "false positives (non-`human`)"
        lines.append(f"## {len(bad)} {kind}")
        for o in bad:
            tells = ", ".join(f"`{r}`" for r in (o.convicting or o.fired)) or "(score-only, no convicting tell)"
            lines.append(f"- `{o.name}` → **{o.label}**: {tells}")
        lines.append("")
    if report.fleets:
        lines.append("## coordination fleets")
        for v in report.fleets:
            lines.append(f"- `{v.label}` score {v.score:.2f} · {len(v.members)} members · cluster `{v.ja4}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> tuple[str, str, str | None]:
    """Parse the grounding CLI args → ``(directory, expect, build_prior_out)``.

    Recognises ``--expect <legit|bot>`` and ``--build-prior <out>`` in any position; the first non-flag token
    that is not an option *value* is the corpus directory (default ``../corpus/sessions``). Crucially BOTH
    option values are consumed, so ``--build-prior out.json`` placed before the positional directory no longer
    makes ``out.json`` get mistaken for the corpus path (the old index-based scan only excluded ``--expect``'s
    value). Unknown ``--flags`` are skipped; a missing value for a known flag is ignored rather than crashing.
    """
    expect = "legit"
    build_prior: str | None = None
    positionals: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--expect" and i + 1 < len(argv):
            expect, i = argv[i + 1], i + 2
        elif a == "--build-prior" and i + 1 < len(argv):
            build_prior, i = argv[i + 1], i + 2
        elif a.startswith("--"):
            i += 1  # unknown/value-less flag — skip
        else:
            positionals.append(a)
            i += 1
    return (positionals[0] if positionals else "../corpus/sessions"), expect, build_prior


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI / IO
    from .browserforge_corpus import build_prior_from_sessions
    from .corpus import load_corpus

    directory, expect, build_prior = parse_args(sys.argv[1:] if argv is None else argv)
    corpus = load_corpus(directory)
    print(render(evaluate(Detector(), corpus, expect=expect)), end="")
    if build_prior is not None:
        n = build_prior_from_sessions(directory, build_prior)
        print(f"\nrebuilt prevalence prior from {n} real sessions -> {build_prior}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    main()
