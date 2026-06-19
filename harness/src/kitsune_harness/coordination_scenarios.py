# harness/coordination_scenarios — precision/recall of the fleet detector across realistic shapes.
# The coordination analog of the calibration FP gate: legit cohorts must never label `fleet`; real fleets must.

"""A trusted-but-verified gate for the coordination frontier.

The per-session detector has the calibration harness measuring its false-positive rate on real browsers.
The coordination detector had only scattered unit tests and no measured precision/recall. This module is
the analog: a deterministic battery of *legitimate* cohorts (which must never be convicted as a `fleet`)
and *malicious* fleets (one per convicting coordination signal, which must all be caught), scored through
``score_cluster``, reported as precision (no legit cohort labeled fleet) and recall (every fleet shape
caught). It is the closest non-blocked approximation of the live proxy/coordination harness — the
scenarios stand in for residential-proxy traffic the lab cannot capture.

The discriminating principle under test is the conviction gate: a real diverse cohort on one browser build
shares a JA4 and has divergent JS and distinct IPs (the paradox + spread), so those cannot convict alone;
only a signal a real cohort cannot produce — per-launch JA4_c randomization, a fingerprint collision, a
pointer-trace collision, or a shared WebRTC origin behind distinct proxies — may label `fleet`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from .coordination import FleetVerdict, score_cluster

_BASE = datetime(2026, 6, 19, 12, 0, 0, tzinfo=UTC)


def _session(
    name: str,
    ja4: str,
    *,
    hw: int | None = None,
    plat: str | None = None,
    offset_s: float = 0.0,
    observed_ip: str | None = None,
    webrtc_ip: str | None = None,
    fp_hash: str | None = None,
    trace_hash: str | None = None,
) -> Session:
    when = _BASE + timedelta(seconds=offset_s)

    def mk(layer: Layer, kind: str, value: object) -> Signal:
        return Signal(session_id=name, layer=layer, kind=kind, value=value, source=Source.edge, observed_at=when)

    sigs: list[Signal] = [mk(Layer.network, "ja4", ja4)]
    if hw is not None:
        sigs.append(mk(Layer.browser, "hardware_concurrency", hw))
    if plat is not None:
        sigs.append(mk(Layer.browser, "nav_platform_os", plat))
    if observed_ip is not None:
        sigs.append(mk(Layer.network, "observed_ip", observed_ip))
    if webrtc_ip is not None:
        sigs.append(mk(Layer.browser, "webrtc_public_ip", webrtc_ip))
    if fp_hash is not None:
        sigs.append(mk(Layer.browser, "fp_hash", fp_hash))
    if trace_hash is not None:
        sigs.append(mk(Layer.behavioral, "trace_hash", trace_hash))
    return group_signals(sigs)[0]


@dataclass(frozen=True)
class Scenario:
    name: str
    malicious: bool  # True => must score `fleet`; False (legit cohort) => must NOT
    detail: str
    members: list[tuple[str, Session]]


def _ip(n: int) -> str:
    return f"{10 + n}.{n}.{n}.{n}"  # distinct, varied source IPs


# A stable full JA4 shared by a real Chrome cohort: JA4_c is identical (real Chrome does not randomize it).
_CHROME = "t13d1516h2_8daaf6152771_e5627efa2ab1"
_PREFIX = "t13d1516h2_8daaf6152771"


def scenarios() -> list[Scenario]:
    """A deterministic battery covering the legit cohorts the gate must clear and one fleet per signal."""
    out: list[Scenario] = []

    # --- LEGITIMATE cohorts (must NOT be `fleet`) ---
    out.append(
        Scenario(
            "legit-diverse-cohort",
            False,
            "distinct real users on one Chrome build: diverse hw/OS, distinct IPs+fps+traces, spread timing",
            [
                (
                    f"u{i}",
                    _session(
                        f"u{i}",
                        _CHROME,
                        hw=hw,
                        plat=plat,
                        offset_s=i * 240.0,
                        observed_ip=_ip(i),
                        fp_hash=f"real{i:02d}",
                        trace_hash=f"path{i:02d}",
                    ),
                )
                for i, (hw, plat) in enumerate([(4, "Windows"), (8, "Windows"), (16, "MacIntel"), (12, "Linux x86_64")])
            ],
        )
    )
    out.append(
        Scenario(
            "legit-large-cohort",
            False,
            "8 distinct users on one build — paradox + IP spread at scale must still not convict",
            [
                (
                    f"b{i}",
                    _session(
                        f"b{i}",
                        _CHROME,
                        hw=[4, 8, 12, 16, 6, 10, 20, 8][i],
                        plat=["Windows", "MacIntel", "Linux x86_64"][i % 3],
                        offset_s=i * 90.0,
                        observed_ip=_ip(i),
                        fp_hash=f"big{i:02d}",
                        trace_hash=f"trc{i:02d}",
                    ),
                )
                for i in range(8)
            ],
        )
    )
    out.append(
        Scenario(
            "legit-nat-cohort",
            False,
            "5 distinct users behind ONE NAT IP — collisions need distinct IPs, so a shared IP never convicts",
            [
                (
                    f"n{i}",
                    _session(
                        f"n{i}",
                        _CHROME,
                        hw=[4, 8, 8, 12, 16][i],
                        plat="Windows",
                        offset_s=i * 30.0,
                        observed_ip="203.0.113.7",  # one shared egress IP
                        fp_hash=f"nat{i:02d}",
                        trace_hash=f"ntr{i:02d}",
                    ),
                )
                for i in range(5)
            ],
        )
    )
    out.append(
        Scenario(
            "legit-homogeneous-pair",
            False,
            "two users, identical JS (same build+config) but distinct fps/traces — a benign same-build pair",
            [
                (
                    "h0",
                    _session("h0", _CHROME, hw=8, plat="Windows", observed_ip=_ip(0), fp_hash="ha", trace_hash="ta"),
                ),
                (
                    "h1",
                    _session("h1", _CHROME, hw=8, plat="Windows", observed_ip=_ip(1), fp_hash="hb", trace_hash="tb"),
                ),
            ],
        )
    )

    # --- MALICIOUS fleets (must be `fleet`), one per convicting signal ---
    out.append(
        Scenario(
            "fleet-ja4c-randomizer",
            True,
            "Camoufox-style: shared cipher prefix but per-launch JA4_c randomization, diverse JS, distinct IPs",
            [
                (
                    f"c{i}",
                    _session(f"c{i}", f"{_PREFIX}_rand{i:04d}", hw=4 + i * 4, observed_ip=_ip(i), offset_s=i * 5.0),
                )
                for i in range(3)
            ],
        )
    )
    out.append(
        Scenario(
            "fleet-cloned-fingerprint",
            True,
            "BotBrowser-style: homogeneous JS but one fp_hash cloned across distinct IPs",
            [
                (f"f{i}", _session(f"f{i}", _CHROME, hw=8, plat="Windows", observed_ip=_ip(i), fp_hash="cloned-fp"))
                for i in range(3)
            ],
        )
    )
    out.append(
        Scenario(
            "fleet-cloned-trace",
            True,
            "behavioural clone: distinct fps but one canned pointer trace replayed across distinct IPs",
            [
                (
                    f"t{i}",
                    _session(
                        f"t{i}", _CHROME, hw=8, plat="Windows", observed_ip=_ip(i), fp_hash=f"d{i}", trace_hash="canned"
                    ),
                )
                for i in range(3)
            ],
        )
    )
    out.append(
        Scenario(
            "fleet-shared-origin",
            True,
            "proxies fronting one origin: diverse JS, distinct proxy IPs, ONE shared WebRTC-leaked real IP",
            [
                (f"p{i}", _session(f"p{i}", _CHROME, hw=4 + i * 4, observed_ip=_ip(i), webrtc_ip="198.51.100.9"))
                for i in range(3)
            ],
        )
    )
    return out


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    malicious: bool
    detail: str
    verdict: FleetVerdict

    @property
    def is_fleet(self) -> bool:
        return self.verdict.label == "fleet"

    @property
    def correct(self) -> bool:
        return self.is_fleet == self.malicious


def evaluate(scens: list[Scenario] | None = None) -> list[ScenarioResult]:
    scens = scenarios() if scens is None else scens
    return [ScenarioResult(s.name, s.malicious, s.detail, score_cluster(s.name, s.members)) for s in scens]


def precision_recall(results: list[ScenarioResult]) -> tuple[float, float]:
    """precision = malicious among fleet-labeled; recall = malicious caught. Perfect gate => (1.0, 1.0)."""
    tp = sum(1 for r in results if r.is_fleet and r.malicious)
    fp = sum(1 for r in results if r.is_fleet and not r.malicious)
    fn = sum(1 for r in results if not r.is_fleet and r.malicious)
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    return precision, recall


def render(results: list[ScenarioResult]) -> str:
    precision, recall = precision_recall(results)
    lines = [
        "# Coordination scenarios — precision/recall of the fleet detector",
        "",
        f"- **precision: {precision:.0%}** (no legitimate cohort labelled `fleet`)",
        f"- **recall: {recall:.0%}** (every fleet shape caught)",
        "",
        "| scenario | expected | label | ✓ | why |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(results, key=lambda x: (x.malicious, x.name)):
        exp = "fleet" if r.malicious else "not-fleet"
        ok = "✓" if r.correct else "✗"
        lines.append(f"| `{r.name}` | {exp} | `{r.verdict.label}` | {ok} | {r.detail} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    print(render(evaluate()), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
