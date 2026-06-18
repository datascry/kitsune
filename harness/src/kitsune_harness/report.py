# harness/report — VirusTotal-style detection aggregator over the recorded corpus.
# Samples = evader recordings, engines = detection rules; renders a detector x evader coverage matrix.

"""Detection aggregator.

Treats each detection rule as an "engine" and each recorded session as a "sample": score the corpus
and report, per sample, how many of the N detectors flagged it (``X/N``), plus a coverage matrix
(detector rows x evader columns) that reveals what catches what — and the gaps. Runs in-process in
well under a second, so it is the rapid tester for both adding detectors and adding evasions.
"""

from __future__ import annotations

from kitsune_detector.coherence import load_registry
from kitsune_detector.coherence.rules import CoherenceRule
from kitsune_detector.detector import Detector
from kitsune_detector.models import Session, Verdict


def evaluable_detectors() -> list[CoherenceRule]:
    """The active "engines": every non-retired rule in the registry."""
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


def render_gaps(detectors: list[CoherenceRule], fired: dict[str, set[str]]) -> str:
    """Render the coverage backlog: detectors with no triggering sample yet."""
    gaps = zero_catch(detectors, fired)
    lines = [f"## Coverage gaps — {len(gaps)}/{len(detectors)} engines catch nothing yet", ""]
    lines += [f"- `{rid}`" for rid in gaps] or ["- (none — every engine catches something)"]
    return "\n".join(lines) + "\n"


def render_matrix(
    detectors: list[CoherenceRule],
    fired: dict[str, set[str]],
    verdicts: dict[str, Verdict],
) -> str:
    """Render the detector x evader coverage matrix as Markdown (✓ caught, · evaded)."""
    names = list(fired)
    n = len(detectors)
    header = "| Detector | layer | " + " | ".join(names) + " | catches |"
    divider = "|" + "---|" * (len(names) + 3)
    rows = [header, divider]
    for rule in detectors:
        cells = ["✓" if rule.id in fired[name] else "·" for name in names]
        catches = sum(rule.id in fired[name] for name in names)
        layers = ",".join(layer.value for layer in rule.layers)
        rows.append(f"| `{rule.id}` | {layers} | " + " | ".join(cells) + f" | {catches} |")

    flagged = " | ".join(f"**{len(fired[name])}/{n}**" for name in names)
    labels = " | ".join(f"**{verdicts[name].label.value}**" for name in names)
    rows.append(f"| **flagged** |  | {flagged} |  |")
    rows.append(f"| **verdict** |  | {labels} |  |")
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
    detectors, fired, verdicts = coverage(detector, load_corpus(directory))
    print(f"# Kitsune detection matrix — {len(detectors)} engines\n")
    print(render_matrix(detectors, fired, verdicts))
    print(render_categories(verdicts))
    print(render_gaps(detectors, fired), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
