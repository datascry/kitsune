# harness/readme_redteam — generate the README "red team" headline + sample matrix from the scored corpus.
# Splices the true caught/total count + a representative evader table between GENERATED markers (no drift).

"""Generate the README's ``## The red team`` headline and sample matrix from the committed corpus.

The README claimed a hand-written "All currently score ``bot``" with a frozen 6-row sample — both drift
the moment a harder evader lands or a rule changes (it was already wrong: the headful/engine-level frontier
is pinned to ``suspicious`` by the conviction gate, not ``bot``). This module scores the committed corpus
and renders the true label split plus a representative, deterministically-ordered sample between
``<!-- GENERATED:readme-redteam:start -->`` / ``<!-- GENERATED:readme-redteam:end -->`` markers.

    uv run python -m kitsune_harness.readme_redteam            # rewrite the generated block in place
    uv run python -m kitsune_harness.readme_redteam --check    # exit 1 if the committed block is stale (CI)
"""

from __future__ import annotations

import sys
from pathlib import Path

from kitsune_detector.coherence import load_registry
from kitsune_detector.detector import Detector
from kitsune_detector.models import Verdict
from kitsune_detector.scoring import CONVICTING_CATEGORIES

from .corpus import load_corpus

_ROOT = Path(__file__).resolve().parents[3]
_README = _ROOT / "README.md"
# Resolve the corpus from the repo root so the generator is CWD-independent (the marker-spliced output must
# be byte-identical whether `task docs` runs it from harness/ or a CI step runs it from the repo root).
_CORPUS = str(_ROOT / "corpus" / "sessions")
_START = "<!-- GENERATED:readme-redteam:start -->"
_END = "<!-- GENERATED:readme-redteam:end -->"

# A representative walk DOWN the ladder of REAL anti-detect tools/techniques — scripted transport → CDP
# driver → stealth stack → real anti-detect browser → coherence/within-session escalation → mobile spoof.
# Each is a committed corpus session; any absent name is skipped (the table shrinks rather than breaking),
# so the teaser stays stable as the fleet grows. The "Caught by" column renders each one's actual top
# convicting tell, so the table shows the DETECTION mechanism, not just an abstract score.
_SAMPLE: list[str] = [
    "curl-impersonate",
    "nodriver",
    "full-stealth",
    "camoufox",
    "ios-ua-spoof",
]


def _top_convicting(v: Verdict) -> str | None:
    """The highest-weight CONVICTING (coherence/automation/artifact) tell — what actually flags the evader."""
    conv = [c for c in v.contradictions if c.category in CONVICTING_CATEGORIES]
    return max(conv, key=lambda c: c.weight).rule_id if conv else None


def _top_corroborating(v: Verdict, n: int = 2) -> list[str]:
    """The top non-convicting tells an evader trips — what the frontier cases have INSTEAD of a hard tell."""
    corr = sorted(
        (c for c in v.contradictions if c.category not in CONVICTING_CATEGORIES),
        key=lambda c: c.weight,
        reverse=True,
    )
    return [c.rule_id for c in corr[:n]]


def _score(directory: str | None = None) -> dict[str, Verdict]:
    detector = Detector()
    corpus = load_corpus(directory or _CORPUS)
    return {name: detector.score(session) for name, session in corpus}


def generate_redteam_md(directory: str | None = None) -> str:
    """Render the red-team block (the content between the GENERATED markers)."""
    verdicts = _score(directory)
    total = len(verdicts)
    bot = sum(1 for v in verdicts.values() if v.label.value == "bot")
    suspicious = sum(1 for v in verdicts.values() if v.label.value == "suspicious")
    human = sum(1 for v in verdicts.values() if v.label.value == "human")
    version = load_registry().ruleset_version

    out: list[str] = []
    headline = f"**{bot} of {total} evaders score `bot`** ([full matrix](docs/matrix.md), ruleset `{version}`)."
    if suspicious:
        headline += (
            f" The remaining {suspicious} reach only `suspicious` — the conviction-gate frontier "
            "(top evaders, below): they defeat every *convicting* rule and trip only corroborating tells, "
            "which can never reach `bot` alone."
        )
    if human:
        headline += f" ({human} score `human` — an open red-team gap.)"
    out.append(headline)
    out.append("")

    # The ladder — representative REAL tools and the convicting tell that catches each (not just a score).
    out.append("Each evader is a real anti-detect tool/technique; **Caught by** is the top convicting tell:")
    out.append("")
    out.append("| Evader | Caught by (top convicting tell) | Incoh. | Score | Label |")
    out.append("|---|---|---|---|---|")
    for name in _SAMPLE:
        v = verdicts.get(name)
        if v is None:
            continue
        tell = _top_convicting(v)
        caught = f"`{tell}`" if tell else "_corroborating only_"
        out.append(f"| `{name}` | {caught} | {v.incoherence_score:.2f} | {v.score:.2f} | {v.label.value} |")

    # Top evaders — the conviction-gate frontier, auto-derived: every `suspicious` evader, hardest first.
    frontier = sorted(
        ((n, v) for n, v in verdicts.items() if v.label.value == "suspicious"),
        key=lambda kv: kv[1].score,
        reverse=True,
    )
    if frontier:
        out.append("")
        out.append(
            f"**Top evaders — the conviction-gate frontier ({len(frontier)}).** These real tools defeat every "
            "*convicting* (coherence/automation/artifact) rule and trip only corroborating tells, so the gate "
            "holds them at `suspicious` — never `bot` on corroboration alone:"
        )
        out.append("")
        out.append("| Evader | Trips (corroborating only) | Score | Label |")
        out.append("|---|---|---|---|")
        for name, v in frontier:
            corr = _top_corroborating(v)
            trips = ", ".join(f"`{r}`" for r in corr) if corr else "_(score-only)_"
            out.append(f"| `{name}` | {trips} | {v.score:.2f} | {v.label.value} |")
    return "\n".join(out).rstrip() + "\n"


def render_into(readme_path: Path = _README, directory: str | None = None) -> str:
    """Return the README text with the GENERATED block replaced by the current teaser. Does not write."""
    text = readme_path.read_text()
    if _START not in text or _END not in text:
        raise SystemExit(f"{readme_path} is missing the {_START} / {_END} markers")
    pre = text[: text.index(_START) + len(_START)]
    post = text[text.index(_END) :]
    return f"{pre}\n{generate_redteam_md(directory)}\n{post}"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    new = render_into()
    if "--check" in args:
        if _README.read_text() != new:  # pragma: no cover - stale path is a CI-failure branch
            print("README red-team teaser is STALE — run `task docs`", file=sys.stderr)
            return 1
        print("README red-team teaser is up to date")
        return 0
    _README.write_text(new)  # pragma: no cover - write path exercised via `task docs`
    print(f"wrote README red-team teaser into {_README.relative_to(_ROOT)}")  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - thin CLI
    raise SystemExit(main())
