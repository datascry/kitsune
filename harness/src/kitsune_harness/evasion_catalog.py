# harness/evasion_catalog — generate the COMPLETE evasion-technique registry for docs/evasion-catalog.md.
# Renders the evader fleet (tools) + every exercised technique (corpus sessions scored) between GENERATED markers.

"""Generate the complete evasion registry section of ``docs/evasion-catalog.md``.

The red-team analog of ``rule_catalog``: an exhaustive, always-current list of every evasion technique Kitsune
leverages, generated from the source of truth (the ``evaders/`` fleet + the recorded ``corpus/sessions/`` runs
scored against the live ruleset) so it cannot drift. Two tables are spliced between
``<!-- GENERATED:evasion:start -->`` / ``<!-- GENERATED:evasion:end -->`` markers:

* **Fleet** — every evader tool, its language, and its one-line purpose (from the script's 2-line header).
* **Techniques exercised** — every captured session, its verdict, and the convicting tells that caught it
  (or ``EVADES`` if it is not convicted) — the red-team scoreboard that proves each technique is handled.

    uv run python -m kitsune_harness.evasion_catalog            # rewrite the generated block in place
    uv run python -m kitsune_harness.evasion_catalog --check    # exit 1 if the committed block is stale (CI)
"""

from __future__ import annotations

import sys
from pathlib import Path

from kitsune_detector.detector import Detector
from kitsune_detector.scoring import CONVICTING_CATEGORIES

from .corpus import load_corpus

_ROOT = Path(__file__).resolve().parents[3]
_EVADERS = _ROOT / "evaders"
_SESSIONS = _ROOT / "corpus" / "sessions"
_CATALOG = _ROOT / "docs" / "evasion-catalog.md"
_START = "<!-- GENERATED:evasion:start -->"
_END = "<!-- GENERATED:evasion:end -->"

# Where each evader's 2-line header lives + the language it implies (checked in order).
_MAIN_CANDIDATES = ["run.mjs", "run.py", "run.go", "forge.go", "main.go", "runner.py"]
_LANG = {".mjs": "TS/Node", ".js": "TS/Node", ".py": "Python", ".go": "Go"}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _evader_main(evader_dir: Path) -> Path | None:
    """The evader's primary script (its 2-line header is the description). Falls back to any nested runner.py."""
    for name in _MAIN_CANDIDATES:
        candidate = evader_dir / name
        if candidate.exists():
            return candidate
    nested = sorted(evader_dir.glob("src/*/runner.py"))  # vanilla/primp keep their runner under src/<pkg>/
    return nested[0] if nested else None


def _header_desc(script: Path) -> str:
    """Line 1 of the 2-line header, stripped of the comment marker and the 'evaders/x/y — ' prefix."""
    first = script.read_text().splitlines()[0] if script.read_text() else ""
    first = first.lstrip("/# ").strip()
    return first.split(" — ", 1)[1] if " — " in first else first


def _fleet_rows() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for evader_dir in sorted(p for p in _EVADERS.iterdir() if p.is_dir()):
        script = _evader_main(evader_dir)
        if script is None:
            continue
        lang = _LANG.get(script.suffix, "?")
        rows.append((evader_dir.name, lang, _header_desc(script)))
    return rows


def generate_evasion_md() -> str:
    """Render the full evasion registry as markdown (the content between the GENERATED markers)."""
    fleet = _fleet_rows()
    detector = Detector()
    corpus = load_corpus(_SESSIONS)
    scored = []
    for name, session in corpus:
        verdict = detector.score(session)
        convicting = sorted(c.rule_id for c in verdict.contradictions if c.category in CONVICTING_CATEGORIES)
        scored.append((name, verdict.label.value, convicting))
    scored.sort(key=lambda r: r[0])
    convicted = sum(1 for _, label, _ in scored if label == "bot")

    out: list[str] = []
    out.append("## Complete evasion registry")
    out.append("")
    out.append(
        f"> Every evasion technique Kitsune leverages — **generated** from the `evaders/` fleet and the "
        f"recorded `corpus/sessions/` runs scored against the live ruleset; regenerate with `task evasion-catalog`, "
        f"do not edit by hand. **{len(fleet)} evader tools**, **{len(scored)} exercised techniques** "
        f"({convicted} convicted `bot`, {len(scored) - convicted} not). A technique with no convicting tell "
        f"`EVADES` — the red-team's next target."
    )
    out.append("")
    out.append(f"### Fleet — the evader tools ({len(fleet)})")
    out.append("")
    out.append("| evader | lang | what it is |")
    out.append("|---|---|---|")
    for name, lang, desc in fleet:
        out.append(f"| `{name}` | {lang} | {_cell(desc)} |")
    out.append("")
    out.append(f"### Techniques exercised — scored against the live ruleset ({len(scored)})")
    out.append("")
    out.append("| technique (captured session) | verdict | convicting tells that catch it |")
    out.append("|---|---|---|")
    for name, label, convicting in scored:
        if label == "bot":
            caught = ", ".join(f"`{r}`" for r in convicting) if convicting else "—"
        else:
            caught = f"⚠ **EVADES** ({label}) — no convicting tell"
        out.append(f"| `{name}` | {label} | {caught} |")
    return "\n".join(out).rstrip() + "\n"


def render_into() -> str:
    """Return the catalog text with the GENERATED block replaced by the current registry. Does not write."""
    text = _CATALOG.read_text()
    if _START not in text or _END not in text:
        raise SystemExit(f"{_CATALOG} is missing the {_START} / {_END} markers")
    pre = text[: text.index(_START) + len(_START)]
    post = text[text.index(_END) :]
    return f"{pre}\n{generate_evasion_md()}\n{post}"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    new = render_into()
    if "--check" in args:
        if _CATALOG.read_text() != new:  # pragma: no cover - stale path is a CI-failure branch
            print("docs/evasion-catalog.md registry is STALE — run `task evasion-catalog`", file=sys.stderr)
            return 1
        print("evasion registry is up to date")
        return 0
    _CATALOG.write_text(new)  # pragma: no cover - write path exercised via `task evasion-catalog`
    print(f"wrote evasion registry into {_CATALOG.relative_to(_ROOT)}")  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - thin CLI
    raise SystemExit(main())
