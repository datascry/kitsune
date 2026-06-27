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
shares a JA4 and has divergent JS and distinct IPs (the paradox + spread), so those cannot convict alone.
A `fleet` label needs a CONVICTING signal, which split two ways: UNAMBIGUOUS solo-convict signals a real
cohort cannot produce (a pointer-trace collision; a shared WebRTC origin behind distinct proxies), and
AMBIGUOUS signals a real cohort CAN produce — a fingerprint collision (a standardized corporate fleet hashes
alike) and JA4_c divergence (a multi-browser-VERSION cohort ships different extension/sig-alg sets; GROUNDED
2026-06-20: real Camoufox does NOT randomize JA4_c per launch — concurrent launches emit an identical JA4_c,
so the fleet-ja4c-randomizer scenario synthesises the divergence) — which convict only when corroborated by an
unambiguous signal, a per-session automation tell, or an IP-reputation flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from .coordination import FleetVerdict, score_cluster
from .template_calibration import distinct_human_descriptors, humanizer_descriptors

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
    trace_descriptor: list[float] | None = None,
    tls_ticket_id: str | None = None,
    webdriver: bool = False,
    datacenter: bool = False,
) -> Session:
    when = _BASE + timedelta(seconds=offset_s)

    def mk(layer: Layer, kind: str, value: object) -> Signal:
        return Signal(session_id=name, layer=layer, kind=kind, value=value, source=Source.edge, observed_at=when)

    sigs: list[Signal] = [mk(Layer.network, "ja4", ja4)]
    if webdriver:  # a per-session automation tell — corroborates an fp-collision as a CLONED bot fleet
        sigs.append(mk(Layer.browser, "webdriver", True))
    if datacenter:  # IP-reputation flag — corroborates a CLEAN clone on datacenter/proxy infrastructure
        sigs.append(mk(Layer.reputation, "asn_is_datacenter", True))
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
    if trace_descriptor is not None:
        sigs.append(mk(Layer.behavioral, "trace_descriptor", trace_descriptor))
    if tls_ticket_id is not None:
        sigs.append(mk(Layer.network, "tls_ticket_id", tls_ticket_id))
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
            "uTLS-style fingerprint randomizer: shared cipher prefix but per-launch JA4_c randomization (NOT "
            "Camoufox — real Camoufox emits a stable JA4_c per config, grounded 2026-06-20), diverse JS, distinct "
            "IPs, AUTOMATED (webdriver) — the automation tell corroborates the JA4_c divergence as a fleet, not a "
            "benign multi-browser-version cohort (which also diverges JA4_c, hence the corroboration gate)",
            [
                (
                    f"c{i}",
                    _session(
                        f"c{i}",
                        f"{_PREFIX}_rand{i:04d}",
                        hw=4 + i * 4,
                        observed_ip=_ip(i),
                        offset_s=i * 5.0,
                        webdriver=True,
                    ),
                )
                for i in range(3)
            ],
        )
    )
    out.append(
        Scenario(
            "legit-multi-version-cohort",
            False,
            "real Chrome users spanning auto-update versions: ONE cipher prefix but a few distinct JA4_c (JA4_c "
            "varies across Chrome versions), distinct IPs + fps + traces, NO automation — diverges JA4_c but is a "
            "real cohort; must cap at candidate, not `fleet` (the JA4_c-randomizer-vs-multi-version FP)",
            [
                (
                    f"v{i}",
                    _session(
                        f"v{i}",
                        f"{_PREFIX}_{['027a', '027a', 'd8a2', 'd8a2'][i]}",  # 2 real JA4_c across 4 users
                        hw=8,
                        plat="Windows",
                        observed_ip=_ip(i),
                        fp_hash=f"realfp{i}",
                        trace_hash=f"human-{i}",
                    ),
                )
                for i in range(4)
            ],
        )
    )
    out.append(
        Scenario(
            "fleet-cloned-fingerprint",
            True,
            "BotBrowser-style: homogeneous JS but one fp_hash cloned across distinct IPs, AUTOMATED (webdriver) "
            "— the automation tell corroborates the collision as a cloned bot fleet, not standardized hardware",
            [
                (
                    f"f{i}",
                    _session(
                        f"f{i}", _CHROME, hw=8, plat="Windows", observed_ip=_ip(i), fp_hash="cloned-fp", webdriver=True
                    ),
                )
                for i in range(3)
            ],
        )
    )
    out.append(
        Scenario(
            "fleet-cloned-datacenter",
            True,
            "a CLEAN native anti-detect clone (BotBrowser-style, no automation tell, no JS divergence) but on "
            "DATACENTER IPs — the IP-reputation flag corroborates the fp-collision as a bot fleet where no "
            "automation tell does; distinguishes it from a residential corporate cohort",
            [
                (
                    f"dc{i}",
                    _session(
                        f"dc{i}",
                        _CHROME,
                        hw=8,
                        plat="Windows",
                        observed_ip=_ip(i),
                        fp_hash="cloned-clean-fp",
                        datacenter=True,
                    ),
                )
                for i in range(3)
            ],
        )
    )
    out.append(
        Scenario(
            "legit-corporate-fleet",
            False,
            "a STANDARDIZED corporate fleet: identical laptop model + locked image hashes byte-identically, on "
            "distinct WFH residential IPs, with DISTINCT human traces and NO automation tell — fp collides but "
            "the cohort is real; must cap at candidate, not `fleet` (the fp-collision-vs-corporate FP)",
            [
                (
                    f"corp{i}",
                    _session(
                        f"corp{i}",
                        _CHROME,
                        hw=8,
                        plat="Windows",
                        observed_ip=_ip(i),
                        fp_hash="standardized-image-fp",
                        trace_hash=f"human-trace-{i}",
                    ),
                )
                for i in range(4)
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
    # The SIMILARITY frontier: a fleet that jitters its pointer trace per node (one humanizer model sampled N
    # times) so every trace_hash differs — the exact trace-collision rule finds nothing — but the traces cluster
    # below the human floor. Ambiguous (could be one human's own sessions), so corroborated by datacenter IPs.
    _model = [list(d) for d in humanizer_descriptors(3)]
    out.append(
        Scenario(
            "fleet-template-similarity",
            True,
            "humanizer fleet: distinct fps AND distinct trace_hashes (jittered), but pointer-trace descriptors "
            "cluster below the human floor across distinct DATACENTER IPs — one humanization model sampled per "
            "node; the IP-reputation flag corroborates the similarity tell (defeats exact trace-collision)",
            [
                (
                    f"sim{i}",
                    _session(
                        f"sim{i}",
                        _CHROME,
                        hw=8,
                        plat="Windows",
                        observed_ip=_ip(i),
                        fp_hash=f"simfp{i}",
                        trace_hash=f"simtrace{i}",  # DISTINCT per node — exact trace-collision finds nothing
                        trace_descriptor=_model[i],
                        datacenter=True,
                    ),
                )
                for i in range(3)
            ],
        )
    )
    # The FP control for the rung: distinct real humans share a JA4 but their trace descriptors spread WIDE
    # (motor noise) on residential IPs — must NOT trip template-similarity (median above the floor).
    _humans = [list(d) for d in distinct_human_descriptors(4)]
    out.append(
        Scenario(
            "legit-distinct-traces",
            False,
            "4 distinct real users on one build, residential IPs, each with a genuinely different pointer trace "
            "(descriptors spread above the human floor) — must NOT trip template-similarity",
            [
                (
                    f"ht{i}",
                    _session(
                        f"ht{i}",
                        _CHROME,
                        hw=[4, 8, 12, 16][i],
                        plat=["Windows", "MacIntel", "Windows", "Linux x86_64"][i],
                        offset_s=i * 120.0,
                        observed_ip=_ip(i),
                        fp_hash=f"htfp{i}",
                        trace_descriptor=_humans[i],
                    ),
                )
                for i in range(4)
            ],
        )
    )
    # A JA4-rotating + fuzzed fleet bound by a REUSED TLS-resumption ticket (one TLS session across the nodes) —
    # the binding that survives JA4 rotation and fp/trace fuzzing. Ambiguous (a roaming user resumes too), so
    # corroborated by datacenter IPs. The edge captures the id from pre_shared_key / session_ticket.
    out.append(
        Scenario(
            "fleet-ticket-reuse",
            True,
            "rotated JA4 + fuzzed fp/trace, but ONE reused TLS-resumption ticket across distinct DATACENTER IPs — "
            "one TLS session shared fleet-wide; the IP-reputation flag corroborates the ambiguous ticket-reuse tell",
            [
                (
                    f"tk{i}",
                    _session(
                        f"tk{i}",
                        f"{_PREFIX}_rot{i:04d}",  # rotated JA4_c per node
                        hw=8,
                        plat="Windows",
                        observed_ip=_ip(i),
                        fp_hash=f"tkfp{i}",  # fuzzed
                        tls_ticket_id="one-fleet-ticket",  # the surviving binding
                        datacenter=True,
                    ),
                )
                for i in range(3)
            ],
        )
    )
    # FP control: the SAME reused ticket across 2 residential IPs with no automation/datacenter is one roaming
    # user (home → mobile resumption). Must cap at candidate, not botnet-label a person.
    out.append(
        Scenario(
            "legit-roaming-ticket",
            False,
            "one user resuming a TLS session from two residential IPs (home → mobile) — a reused ticket across 2 "
            "IPs with NO automation/datacenter flag is a roaming person, not a fleet; must cap at candidate",
            [
                (
                    f"rm{i}",
                    _session(
                        f"rm{i}",
                        _CHROME,
                        hw=8,
                        plat="Windows",
                        offset_s=i * 600.0,  # sequential, not lockstep — a person roaming over time
                        observed_ip=_ip(i),
                        fp_hash=f"rmfp{i}",
                        tls_ticket_id="roaming-user-ticket",
                    ),
                )
                for i in range(2)
            ],
        )
    )
    # A cloned-profile fleet that SPREADS its arrivals over time (beyond the 120s lockstep window) to look
    # organic. It sheds only the lockstep CORROBORATION — the fp-collision + automation binding still convicts,
    # proving timing-stagger is a weak evasion (lockstep was never load-bearing for conviction).
    out.append(
        Scenario(
            "fleet-staggered",
            True,
            "cloned fp across distinct IPs + automation, but arrivals spread 10min apart (no lockstep) — the "
            "binding convicts whatever the timing; staggering only costs the lockstep corroboration",
            [
                (
                    f"sg{i}",
                    _session(
                        f"sg{i}",
                        _CHROME,
                        hw=8,
                        plat="Windows",
                        offset_s=i * 600.0,  # 10 min apart → span 1200s, well beyond the 120s lockstep window
                        observed_ip=_ip(i),
                        fp_hash="staggered-clone-fp",
                        webdriver=True,
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
