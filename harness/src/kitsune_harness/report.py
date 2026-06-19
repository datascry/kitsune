# harness/report — VirusTotal-style detection aggregator over the recorded corpus.
# Scores each evader recording against every rule; renders compact, fixed-width per-evader + per-rule views.

"""Detection aggregator.

Treats each recorded session as a "sample" and scores it against every detection rule, then renders two
FIXED-WIDTH views (so column count never grows with the evader fleet): a per-evader verdict table (each
evader's score + the convicting tells that caught it) and a per-rule coverage table (catches per rule),
plus the per-class breakdown and the zero-catch gaps. Runs in-process in well under a second, so it is the
rapid tester for both adding rules and adding evasions. (The old rule-rows x evader-columns grid grew
unreadably wide as the fleet grew; these transposed views replace it.)
"""

from __future__ import annotations

from kitsune_detector.coherence import load_registry
from kitsune_detector.coherence.rules import CoherenceRule
from kitsune_detector.detector import Detector
from kitsune_detector.models import Layer, Session, Verdict


def evaluable_detectors() -> list[CoherenceRule]:
    """The active detection rules: every non-retired rule in the registry."""
    return load_registry().evaluable_rules


def coverage(
    detector: Detector,
    corpus: list[tuple[str, Session]],
) -> tuple[list[CoherenceRule], dict[str, set[str]], dict[str, Verdict]]:
    """Score the corpus; return (detectors, {sample: fired rule ids}, {sample: verdict})."""
    detectors = evaluable_detectors()
    fired: dict[str, set[str]] = {}
    verdicts: dict[str, Verdict] = {}
    for name, session in corpus:
        verdict = detector.score(session)
        verdicts[name] = verdict
        fired[name] = {c.rule_id for c in verdict.contradictions}
    return detectors, fired, verdicts


def zero_catch(detectors: list[CoherenceRule], fired: dict[str, set[str]]) -> list[str]:
    """Detectors that flagged nothing in the corpus — the iteration backlog."""
    return [rule.id for rule in detectors if all(rule.id not in s for s in fired.values())]


def corpus_signal_kinds(corpus: list[tuple[str, Session]]) -> set[str]:
    """Every ``layer.kind`` signal present anywhere in the corpus — what the recordings can exercise."""
    present: set[str] = set()
    for _name, session in corpus:
        for layer in Layer:
            for sig in session.signals.of(layer):
                present.add(f"{layer.value}.{sig.kind}")
    return present


def classify_gaps(
    detectors: list[CoherenceRule],
    fired: dict[str, set[str]],
    present_kinds: set[str],
) -> tuple[list[str], list[str]]:
    """Split the zero-catch rules into (evaded, unexercised).

    A rule is *unexercised* when one of its ``reads`` is absent from the whole corpus, so no recording
    could ever trip it (the common case for a freshly added signal the recordings predate). It is
    *evaded* when its reads are present somewhere but every sample passed the check — a real coverage
    gap. Conflating the two makes a validated-but-uncaptured rule look like dead weight.
    """
    by_id = {rule.id: rule for rule in detectors}
    evaded: list[str] = []
    unexercised: list[str] = []
    for rid in zero_catch(detectors, fired):
        if any(read not in present_kinds for read in by_id[rid].reads):
            unexercised.append(rid)
        else:
            evaded.append(rid)
    return evaded, unexercised


def render_gaps(
    detectors: list[CoherenceRule],
    fired: dict[str, set[str]],
    present_kinds: set[str] | None = None,
) -> str:
    """Render the coverage backlog. When ``present_kinds`` is given, separate genuinely evaded rules
    from those the corpus cannot exercise (so the latter are not misread as dead weight)."""
    gaps = zero_catch(detectors, fired)
    lines = [f"## Coverage gaps — {len(gaps)}/{len(detectors)} rules catch nothing yet", ""]
    if present_kinds is None:
        lines += [f"- `{rid}`" for rid in gaps] or ["- (none — every rule catches something)"]
        return "\n".join(lines) + "\n"
    evaded, unexercised = classify_gaps(detectors, fired, present_kinds)
    lines.append(f"**Evaded** ({len(evaded)}) — reads present in the corpus, but every sample passed:")
    lines += [f"- `{rid}`" for rid in evaded] or ["- (none — every exercised rule catches something)"]
    lines += [
        "",
        f"**Unexercised** ({len(unexercised)}) — a read signal is absent from every recording, so the "
        "corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the "
        "detector unit + precision tests, and need a corpus refresh to appear here:",
    ]
    lines += [f"- `{rid}`" for rid in unexercised] or ["- (none)"]
    return "\n".join(lines) + "\n"


# Convicting categories (mirror detector/scoring.py): a `bot` label needs one of these; the rest only
# corroborate. Surfacing the convicting tells per evader is what makes the per-evader view actionable.
_CONVICTING = frozenset({"coherence", "automation", "artifact"})


def render_evaders(
    detectors: list[CoherenceRule],
    fired: dict[str, set[str]],
    verdicts: dict[str, Verdict],
) -> str:
    """Per-evader verdict + the convicting tells that caught it (the actionable, fixed-width view).

    Replaces the old rule x evader grid, whose column count grew with every evader (unreadable past a
    handful). Here columns are fixed; rows grow linearly with the fleet — sustainable as the fleet grows.
    """
    n = len(detectors)
    rows = [
        "## Per-evader verdict — score and the convicting tells that caught each evader",
        "",
        "| Evader | verdict | score | fired | convicting tells |",
        "|---|---|---|---:|---|",
    ]
    for name in fired:
        v = verdicts[name]
        conv = [c.rule_id for c in v.contradictions if c.category.value in _CONVICTING]
        shown = ", ".join(f"`{r}`" for r in conv[:3]) + (f" +{len(conv) - 3}" if len(conv) > 3 else "")
        rows.append(f"| `{name}` | {v.label.value} | {v.score:.2f} | {len(fired[name])}/{n} | {shown or '—'} |")
    return "\n".join(rows) + "\n"


def render_rule_catches(
    detectors: list[CoherenceRule],
    fired: dict[str, set[str]],
) -> str:
    """Per-rule catch counts (fixed-width), highest first; 0-catch rules go to the Gaps section."""
    counts = {rule.id: sum(rule.id in fired[name] for name in fired) for rule in detectors}
    active = sorted(
        (rule for rule in detectors if counts[rule.id] > 0),
        key=lambda r: (-counts[r.id], r.id),
    )
    rows = [
        f"## Per-rule coverage — {len(active)}/{len(detectors)} rules catch ≥1 evader (rest in Gaps)",
        "",
        "| Detector | layer | category | catches |",
        "|---|---|---|---:|",
    ]
    for rule in active:
        layers = ",".join(layer.value for layer in rule.layers)
        rows.append(f"| `{rule.id}` | {layers} | {rule.category.value} | {counts[rule.id]} |")
    return "\n".join(rows) + "\n"


_CATEGORIES = ["coherence", "artifact", "automation", "environment", "behavioral", "reputation"]


def render_categories(verdicts: dict[str, Verdict]) -> str:
    """Per-evader fired-rule counts by detection class — separates spoofing from a stripped environment.

    The thesis made measurable: ``coherence``/``artifact`` counts are genuine anti-detect catches,
    while ``environment``/``automation`` also fire on a stock headless browser (the no-spoof baseline).
    """
    names = list(verdicts)
    header = "| Evader | verdict | " + " | ".join(_CATEGORIES) + " |"
    divider = "|" + "---|" * (len(_CATEGORIES) + 2)
    rows = [
        "## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too",
        "",
        header,
        divider,
    ]
    for name in names:
        counts = {cat: 0 for cat in _CATEGORIES}
        for c in verdicts[name].contradictions:
            counts[c.category.value] = counts.get(c.category.value, 0) + 1
        cells = " | ".join(str(counts[cat]) or "·" for cat in _CATEGORIES)
        rows.append(f"| `{name}` | {verdicts[name].label.value} | {cells} |")
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    import sys

    from .corpus import DEFAULT_CORPUS, load_corpus

    argv = sys.argv[1:] if argv is None else argv
    directory = argv[0] if argv else DEFAULT_CORPUS
    detector = Detector()
    corpus = load_corpus(directory)
    detectors, fired, verdicts = coverage(detector, corpus)
    bots = sum(v.label.value == "bot" for v in verdicts.values())
    print(f"# Kitsune detection matrix — {len(detectors)} rules vs {len(verdicts)} evaders\n")
    print(f"_{bots}/{len(verdicts)} evaders caught (`bot`). Generated from the committed captures._\n")
    print(render_evaders(detectors, fired, verdicts))
    print(render_rule_catches(detectors, fired))
    print(render_categories(verdicts))
    print(render_gaps(detectors, fired, corpus_signal_kinds(corpus)), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
