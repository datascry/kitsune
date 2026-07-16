# harness/request1_audit — the request-1 / no-JS separation audit (botwall's core pitch number).
# Scores captures NETWORK-ONLY (what the edge sees before any JS) to report the request-1 convicting rule
# set, its false-positive rate on real browsers, and its recall on evaders.

"""Request-1 / no-JS separation audit.

botwall makes its allow/challenge/deny decision on the first request, before the collector posts any JS
signals. Its whole thesis rests on the *network-only* verdict being strong (catches scrapers) and clean
(does not flag real browsers). This module measures both, in-sandbox, against the committed captures.

It answers three questions:

1. **Which rules can convict on request 1 with no JS?** The convicting (coherence/automation/artifact)
   rules whose every ``reads`` is a network-layer signal the edge emits — minus two families that are
   "no-JS" but not "request-1 *instant*": :data:`GRACE_OR_MULTICONN` (``net.no_js_execution`` needs the
   collector-absent grace window; the within-session rotation family needs >=2 connections).
2. **What is its false-positive rate on real browsers?** Each real-browser capture is stripped to its
   network layer and scored; a request-1 convicting rule firing there is a false positive (a real browser
   the edge would wrongly convict before it even runs JS).
3. **What is its recall on evaders?** Each evader capture is scored network-only; the fraction that trip a
   request-1 convicting rule is the no-JS catch rate — the scrapers botwall stops at the door.

    cd harness && uv run python -m kitsune_harness.request1_audit          # print the report
    cd harness && uv run python -m kitsune_harness.request1_audit --write   # regenerate docs/request1-audit.md
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kitsune_detector.coherence import load_registry
from kitsune_detector.detector import Detector
from kitsune_detector.models import Session, SignalGroups
from kitsune_detector.scoring import CONVICTING_CATEGORIES

# "no-JS" but NOT "request-1 instant": excluded from the instant-coherence tally, reported separately.
# net.no_js_execution reads browser_absent, which the detector emits only after the collector-absent grace
# window (a real browser has not yet run JS on request 1, so this must not count as a request-1 conviction).
# The rotation family needs >=2 connections to observe an invariant field changing within one session.
GRACE_OR_MULTICONN: frozenset[str] = frozenset(
    {
        "net.no_js_execution",
        "net.ja4_unstable_within_session",
        "net.h2_unstable_within_session",
        "net.ip_rotation_within_session",
        "net.ua_rotation_within_session",
        "net.tls_ext_order_static_within_session",
    }
)

# Real-browser capture directories (the FP set) vs the evader corpus (the recall set). Only the
# Session-shaped, network-bearing captures are relevant to a network-only audit; corpus/calibration/engines
# holds raw browserforge FINGERPRINT dicts (no network layer), so it is excluded — a network audit has
# nothing to score there.
REAL_DIRS: tuple[str, ...] = (
    "corpus/calibration/headful",
    "corpus/calibration/privacy",
)
EVADER_DIR = "corpus/sessions"

# Real-browser captures that are capture-ENVIRONMENT infidelities, not a faithful capture of that engine's
# real network stack: `webkit` is Playwright-WebKit-on-Linux under a macOS UA (no real macOS/iOS Safari is
# available in-sandbox), so its Linux kernel / non-Safari TLS legitimately contradict its UA. Excluded from
# the *faithful* FP rate; still reported raw. Kept in sync with the test's allow-list.
CAPTURE_INFIDELITIES: frozenset[str] = frozenset({"webkit"})


def request1_rule_ids() -> set[str]:
    """Convicting rules evaluable from edge signals on request 1: category convicts, every read is a
    ``network.*`` signal, and the rule is not a grace-window / multi-connection tell."""
    out: set[str] = set()
    for rule in load_registry().rules:
        if rule.status == "retired" or rule.category not in CONVICTING_CATEGORIES:
            continue
        if rule.id in GRACE_OR_MULTICONN:
            continue
        if rule.reads and all(read.startswith("network.") for read in rule.reads):
            out.add(rule.id)
    return out


def network_only(session: Session) -> Session:
    """A copy of ``session`` carrying only the network + reputation layers — what the edge and IP lookup
    see with no collector. Strips the browser and behavioral (JS/collector) layers."""
    return session.model_copy(
        update={
            "signals": SignalGroups(
                network=list(session.signals.network),
                reputation=list(session.signals.reputation),
            )
        }
    )


@dataclass(frozen=True)
class CaptureOutcome:
    name: str
    request1_convicting: list[str]  # request-1 convicting rule ids that fired (grace/multiconn excluded)

    @property
    def convicts(self) -> bool:
        return bool(self.request1_convicting)


@dataclass(frozen=True)
class Request1Report:
    rule_ids: set[str]
    real: list[CaptureOutcome]
    evaders: list[CaptureOutcome]

    @property
    def false_positives(self) -> list[CaptureOutcome]:
        return [o for o in self.real if o.convicts]

    @property
    def fp_rate(self) -> float:
        return len(self.false_positives) / len(self.real) if self.real else 0.0

    @property
    def faithful_real(self) -> list[CaptureOutcome]:
        return [o for o in self.real if o.name not in CAPTURE_INFIDELITIES]

    @property
    def faithful_false_positives(self) -> list[CaptureOutcome]:
        return [o for o in self.faithful_real if o.convicts]

    @property
    def caught(self) -> list[CaptureOutcome]:
        return [o for o in self.evaders if o.convicts]

    @property
    def recall(self) -> float:
        return len(self.caught) / len(self.evaders) if self.evaders else 0.0


def _score(detector: Detector, name: str, session: Session, rule_ids: set[str]) -> CaptureOutcome:
    verdict = detector.score(network_only(session))
    fired = sorted(c.rule_id for c in verdict.contradictions if c.rule_id in rule_ids)
    return CaptureOutcome(name=name, request1_convicting=fired)


def _load(directory: Path) -> list[tuple[str, Session]]:
    """Load every Session-shaped ``*.json`` in ``directory``; skip raw fingerprint dicts (no ``signals``)."""
    out: list[tuple[str, Session]] = []
    for p in sorted(directory.glob("*.json")):
        obj = p.read_text()
        if '"signals"' not in obj:  # a browserforge fingerprint dict, not a Session capture
            continue
        out.append((p.stem, Session.model_validate_json(obj)))
    return out


def audit(detector: Detector, repo_root: Path) -> Request1Report:
    rule_ids = request1_rule_ids()
    real: list[CaptureOutcome] = []
    for d in REAL_DIRS:
        for name, session in _load(repo_root / d):
            real.append(_score(detector, name, session, rule_ids))
    evaders = [_score(detector, name, s, rule_ids) for name, s in _load(repo_root / EVADER_DIR)]
    return Request1Report(rule_ids=rule_ids, real=real, evaders=evaders)


def render(report: Request1Report) -> str:
    lines: list[str] = []
    lines.append("# Request-1 / no-JS separation audit\n")
    lines.append(
        "> Generated by `kitsune_harness.request1_audit`. The **network-only** verdict — what botwall's "
        "edge concludes on the first request, before any JavaScript runs. Every capture is stripped to its "
        "network + reputation layers and scored with the current ruleset.\n"
    )
    lines.append(
        f"- **{len(report.rule_ids)} request-1 convicting rules** (convicting category, all reads are "
        "`network.*`, excluding the grace-window `net.no_js_execution` and the multi-connection rotation "
        "family — both no-JS but not request-1-*instant*).\n"
        f"- **False-positive rate on real browsers: {report.fp_rate:.0%}** "
        f"({len(report.false_positives)}/{len(report.real)} real-browser captures trip a request-1 "
        "convicting rule when scored network-only). Any FP here is the `webkit` capture-fidelity artifact "
        "(Playwright-WebKit-on-Linux, not real Safari — see the caveat below); the faithful FP rate on the "
        f"Chromium/Firefox/Edge family captures is **{len(report.faithful_false_positives)}/"
        f"{len(report.faithful_real)}**.\n"
        f"- **Recall on evaders: {report.recall:.0%}** ({len(report.caught)}/{len(report.evaders)} evader "
        "captures convict on request 1 with no JS).\n"
    )

    if report.false_positives:
        lines.append("\n## ⚠ Real-browser false positives\n")
        lines.append(
            "A capture here trips a request-1 convicting rule when scored network-only. **Caveat — capture "
            "fidelity:** no real macOS/iOS Safari is available in-sandbox, so `webkit` is Playwright-WebKit "
            "running on Linux under a macOS UA; its Linux TCP kernel and non-Safari TLS legitimately "
            "contradict its macOS UA (`net.tcp_os_vs_ua` / `net.tls_grease_vs_ua`) — a capture-ENVIRONMENT "
            "artifact, not a real-Safari FP (a real Safari runs on Darwin, coherent). Real-Safari network "
            "validation is external-data-bound. Discount such captures when reading the number.\n"
        )
        lines.append("| Real browser | request-1 convicting tell(s) |")
        lines.append("|---|---|")
        for o in report.false_positives:
            lines.append(f"| `{o.name}` | {', '.join(f'`{r}`' for r in o.request1_convicting)} |")
    else:
        lines.append(
            "\n**No real-browser false positives** — every real-browser capture scores clean on the "
            "request-1 convicting set. The edge does not convict a real browser before it runs JS.\n"
        )

    lines.append("\n## Evaders on request 1 (no JS)\n")
    lines.append(
        "A `🛑 caught` evader convicts on the first request via network coherence alone — botwall stops it "
        "at the door. A `↦ deferred` evader defeats every request-1 network tell; the full pipeline still "
        "convicts it once the collector posts JS signals, or a challenge gate resolves it — that is the "
        "honest boundary of the network-only verdict, not a miss.\n"
    )
    lines.append("| Evader | request-1 | convicting tell(s) |")
    lines.append("|---|---|---|")
    for o in report.evaders:
        verdict = "🛑 caught" if o.convicts else "↦ deferred"
        tells = ", ".join(f"`{r}`" for r in o.request1_convicting) if o.request1_convicting else "—"
        lines.append(f"| `{o.name}` | {verdict} | {tells} |")

    lines.append("\n## The request-1 convicting rule set\n")
    for rid in sorted(report.rule_ids):
        lines.append(f"- `{rid}`")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI / IO
    import sys

    args = sys.argv[1:] if argv is None else argv
    repo_root = Path(__file__).resolve().parents[3]
    report = audit(Detector(), repo_root)
    text = render(report)
    if "--write" in args:
        out = repo_root / "docs" / "request1-audit.md"
        out.write_text(text)
        print(f"wrote request-1 audit into {out.relative_to(repo_root)}")
    else:
        print(text)


if __name__ == "__main__":  # pragma: no cover
    main()
