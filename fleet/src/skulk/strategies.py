# fleet/skulk/strategies — the modular fleet shapes: cloned / randomizer / trace-replay / fuzzy.
# Each maps an attacker's coordination strategy to N FleetMembers; the registry makes them pluggable.

"""Fleet strategies — the red-team menu, each grounding a blue coordination signal.

Every strategy is a deterministic generator (seeded → reproducible) of N :class:`FleetMember`. They model the
two escape routes a coordinated fleet has and their evolution:

  * ``cloned``       — one pinned anti-detect profile across distinct IPs (the BotBrowser/clone class). The
                       high-entropy ``fp_hash`` is byte-identical fleet-wide → an exact fp-collision a detector
                       convicts (the cloned-profile-behind-proxies shape).
  * ``randomizer``   — per-instance COHERENT fingerprints sharing one JA4 across distinct IPs (the Multilogin/
                       GoLogin multi-accounting class). The TLS/JS paradox; convicts only when corroborated
                       (automation tell or IP-reputation flag), else a real diverse cohort produces this shape.
  * ``trace-replay`` — one canned "humanised" pointer trace replayed across distinct IPs (engagement/review-
                       farm class). The ``trace_hash`` is identical fleet-wide → an unambiguous trace-collision.
  * ``fuzzy``        — the EVOLVED adversary: jitter the fingerprint AND the trace per instance so NOTHING is
                       byte-identical. It defeats exact-hash collision (caps a per-session-saturated scorer at
                       *candidate*) — the frontier that needs template-SIMILARITY clustering, not exact match.
  * ``similarity``   — the SAME evolved adversary, now profiled: its jittered traces are all sampled from ONE
                       humanizer model, so the collector's trace DESCRIPTORS cluster below the human floor even
                       though every ``trace_hash`` differs. The blue rung that closes ``fuzzy`` — caught by
                       template-similarity when corroborated (it runs on datacenter/proxy egress).
  * ``fuzzy-rotate`` — the hardest shape: ROTATE the JA4 per node (defeats prefix clustering) AND fuzz fp/trace
                       (defeats exact collision). Pure similarity clustering can't convict it FP-safely; it is
                       caught only by the binding that survives rotation — one shared WebRTC origin behind the
                       proxies — with template-similarity corroborating inside the recovered cluster.
  * ``ticket-reuse`` — the same rotated-JA4 + fuzzed shape, but the surviving binding is a reused TLS-resumption
                       ticket (one ``tls_ticket_id`` across distinct IPs — a fleet resuming ONE TLS session
                       fleet-wide). The edge captures it from pre_shared_key / session_ticket; corroboration-gated
                       (a roaming user could resume from a second IP), so it runs on datacenter egress.
  * ``ipv6-rotate``  — a cloned fleet that rotates IPv6 /128s inside a FEW real /64s to inflate its apparent IP
                       count (free interface-id rotation). The /64 origin-fold collapses the spray back to its
                       true origin count (one /64 = one subscriber), so it cannot fake distinct-IP spread — and a
                       cloned fp across >=2 distinct /64s still convicts on fp-collision. The IPv6 evasion that
                       buys nothing: spread still costs genuinely distinct /64 subscriptions.
  * ``tool-fleet``   — a NO-JS automation-tool fleet (curl/Go/Python) sharing one tool JA4, bound by a reused
                       TLS ticket across clean RESIDENTIAL IPs. It carries no JS automation tell (it runs no
                       JavaScript) and no datacenter flag, so the only corroborator is the non-browser JA4 itself
                       (``ja4_client_hint``) — the network-layer twin of the automation tell that closes the
                       no-JS coordination gap (a real cohort runs browsers, not curl/Go).
  * ``staggered``    — a cloned-profile fleet whose arrivals are SPREAD OVER TIME (beyond the lockstep window)
                       to look organic. The timing axis: it sheds only the lockstep CORROBORATION, never the
                       conviction — the fp-collision + automation binding convicts whatever the arrival spread.
  * ``httpflood``    — an L7 application-layer HTTP flood (MHDDoS class): MANY no-JS tool sources sharing one
                       flood-tool JA4, hammering in LOCKSTEP across many distinct origins. It carries NO per-node
                       binding (no cloned fp, no replayed trace, no shared ticket — a pure HTTP flood runs no
                       browser), so exact-match collision finds nothing; it is caught by the AGGREGATE flood
                       shape (large + lockstep + many origins) corroborated by the non-browser tool JA4 — the
                       bot⇄DDoS convergence, where the coordination scorer doubles as the L7-flood attributor.
                       (Skulk emits a coordination-shaped fleet, NOT request volume — it is not a DoS tool.)

To add a strategy: subclass / duck-type :class:`~skulk.strategy.Strategy` and ``register`` it.
"""

from __future__ import annotations

import hashlib
import random

from .model import FleetMember
from .strategy import register


def _h(*parts: object) -> str:
    """A stable 16-hex digest of the parts — stands in for a high-entropy fp_hash / trace_hash."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


# A plausible point in the collector's normalized trace-descriptor space (power-law exponent, fit, sub-movement
# rate, pause ratio, velocity CV, straightness — each in [0,1]) for one humanizer model. The `similarity`
# strategy emits this base with tiny per-node jitter, modelling what the collector would compute for a fleet
# whose pointer paths are all sampled from ONE humanizer: distinct trace_hashes, but descriptors that cluster
# far below the human floor. (Skulk models the collector's OUTPUT, as it does for fp_hash — the realism of the
# tightness is grounded harness-side against real human motion in template_calibration.)
_HUMANIZER_DESCRIPTOR = (0.22, 0.60, 0.10, 0.20, 0.30, 0.70)
_DESCRIPTOR_JITTER = 0.012  # stddev per component -> median pairwise ~0.04, well under the 0.10 floor


def _descriptor(seed: int, i: int) -> list[float]:
    """One humanizer-model trace descriptor with small per-node jitter (a tight, sub-floor family)."""
    rng = random.Random(_h("descriptor", seed, i))
    return [min(1.0, max(0.0, c + rng.gauss(0, _DESCRIPTOR_JITTER))) for c in _HUMANIZER_DESCRIPTOR]


# A WIDER jitter so the descriptors cluster JUST ABOVE the hard template floor: median pairwise ~0.13 (jitter
# 0.04 → ~0.04*sqrt(2*6)), above the 0.10 floor (so template_similarity stays SILENT) yet within axis A's 0.15
# soft eps (so the aggregate descriptor dimension still links them). The evolved humanizer tuned to the floor.
_DIFFUSE_JITTER = 0.04


def _diffuse_descriptor(seed: int, i: int) -> list[float]:
    """A humanizer descriptor tuned just above the hard floor — escapes template_similarity, caught by axis A."""
    rng = random.Random(_h("diffuse", seed, i))
    return [min(1.0, max(0.0, c + rng.gauss(0, _DIFFUSE_JITTER))) for c in _HUMANIZER_DESCRIPTOR]


def _ip(seed: int, i: int) -> str:
    """A distinct source IP per node (the in-sandbox analog of one proxy egress per fleet member)."""
    return f"10.77.{seed % 254 + 1}.{i + 1}"


def _ip6(seed: int, i: int, nets: int) -> str:
    """A distinct IPv6 /128 per node, but only ``nets`` distinct /64 PREFIXES across the fleet — models a fleet
    that rotates the interface-id (low 64 bits) inside a FEW real /64 subscriptions to inflate its apparent IP
    count. The /64 fold (harness ``coordination._ip_origin``) collapses each /128 back to its /64 origin, so the
    fleet's true origin count is ``nets`` no matter how many /128s it sprays."""
    prefix = i % nets  # which of the few real /64 subscriptions this node sits in
    suffix = _h("v6suffix", seed, i)[:4]  # a free, distinct interface-id (low 64 bits) per node
    return f"2001:db8:{seed % 0xFFFF:x}:{prefix}::{suffix}"


def _ja4(seed: int) -> str:
    """One shared JA4 (the TLS engine the whole fleet runs — below the JS spoofing layer)."""
    return "t13d1516h2_" + _h("ja4", seed)[:12] + "_" + _h("ext", seed)[:12]


def _ja4_rot(seed: int, i: int) -> str:
    """A DISTINCT JA4 per node (a uTLS-randomized / mixed-build fleet) — defeats JA4-prefix clustering, so each
    node lands in its own singleton cluster and is never graded by the prefix path."""
    return "t13d" + _h("rotpre", seed, i)[:4] + "h2_" + _h("rotja4", seed, i)[:12] + "_" + _h("rotext", seed, i)[:12]


@register
class ClonedProfile:
    name = "cloned"
    summary = "One pinned anti-detect profile cloned across N distinct IPs (BotBrowser class) — exact fp-collision."

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4, fp = _ja4(seed), _h("clonedfp", seed)
        return [
            FleetMember(
                f"cloned-{i}", ja4, _ip(seed, i), fp_hash=fp, hardware_concurrency=8, platform="Win32", automation=True
            )
            for i in range(n)
        ]


@register
class CoherentRandomizer:
    name = "randomizer"
    summary = "Coherent per-instance fingerprints, one JA4, distinct IPs (Multilogin class) — the TLS/JS paradox."

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4 = _ja4(seed)
        rng = random.Random(seed)
        plats = ["Win32", "MacIntel", "Linux x86_64"]
        return [
            FleetMember(
                f"rand-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("randfp", seed, i),
                hardware_concurrency=rng.choice([4, 8, 12, 16]),
                platform=rng.choice(plats),
                automation=False,
            )
            for i in range(n)
        ]


@register
class TraceReplay:
    name = "trace-replay"
    summary = (
        "One canned pointer trace replayed across N distinct IPs (engagement-farm class) — unambiguous trace-collision."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4, trace = _ja4(seed), _h("trace", seed)
        return [
            FleetMember(f"trace-{i}", ja4, _ip(seed, i), fp_hash=_h("tfp", seed, i), trace_hash=trace) for i in range(n)
        ]


@register
class Similarity:
    name = "similarity"
    summary = (
        "EVOLVED + profiled: one humanizer model sampled per node — distinct trace_hashes but near-identical "
        "trace DESCRIPTORS; caught by template-similarity when corroborated (the blue rung that closes fuzzy)."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4 = _ja4(seed)
        # Each node jitters its fingerprint AND its trace_hash (so every EXACT hash differs — exact-match finds
        # nothing, exactly like `fuzzy`). But all pointer paths come from ONE humanizer model, so the collector's
        # trace DESCRIPTORS cluster below the human floor. On datacenter/proxy egress (the realistic botnet
        # infrastructure) the IP-reputation flag corroborates the similarity tell → the cluster convicts.
        return [
            FleetMember(
                f"sim-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("simfp", seed, i),
                trace_hash=_h("simtrace", seed, i),
                trace_descriptor=_descriptor(seed, i),
                hardware_concurrency=8,
                platform="Win32",
                automation=False,
                datacenter=True,
            )
            for i in range(n)
        ]


@register
class FuzzyRotate:
    name = "fuzzy-rotate"
    summary = (
        "JA4-rotating + fuzzed: a distinct JA4, fp AND trace per node (defeats prefix clustering AND exact "
        "collision) — caught ONLY by the binding that survives rotation: one shared WebRTC origin behind the proxies."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # The hardest fleet shape: rotate the JA4 per node (so JA4-prefix clustering files each as a singleton)
        # AND fuzz fp/trace per node (so no exact collision). Pure descriptor-similarity clustering CANNOT
        # convict this FP-safely (a large distinct-human population always contains a coincidentally-tighter
        # subset — grounded in template_calibration's cross-JA4 measurement). What DOES catch it is the binding
        # rotation can't touch: one WebRTC-leaked real origin behind the distinct proxy IPs (unambiguous,
        # same-origin). Template-similarity then corroborates within that recovered cluster.
        origin = "198.51." + str(seed % 254) + "." + str(seed % 200 + 1)
        return [
            FleetMember(
                f"rot-{i}",
                _ja4_rot(seed, i),  # DISTINCT JA4 per node
                _ip(seed, i),
                fp_hash=_h("rotfp", seed, i),  # fuzzed → no fp-collision
                trace_hash=_h("rottrace", seed, i),  # fuzzed → no exact trace-collision
                trace_descriptor=_descriptor(seed, i),  # one humanizer (corroborating, not primary)
                webrtc_public_ip=origin,  # the surviving binding: one origin behind the proxies
                hardware_concurrency=8,
                platform="Win32",
                automation=False,
            )
            for i in range(n)
        ]


@register
class TicketReuse:
    name = "ticket-reuse"
    summary = (
        "JA4-rotating + fuzzed, bound by a reused TLS-resumption ticket: distinct JA4/fp/trace per node but ONE "
        "shared tls_ticket_id across the IPs — the session-reuse binding that survives rotation (corroboration-gated)."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # Like fuzzy-rotate but the surviving binding is a reused TLS session ticket (a fleet that resumes ONE
        # TLS session across nodes to save full handshakes) rather than a WebRTC origin. The edge captures the
        # pre_shared_key / session_ticket id; one id across distinct IPs is one TLS identity shared fleet-wide.
        # Ambiguous (a roaming user could resume from a 2nd IP), so it runs on datacenter egress to corroborate.
        ticket = _h("ticket", seed)
        return [
            FleetMember(
                f"tkt-{i}",
                _ja4_rot(seed, i),  # rotated JA4
                _ip(seed, i),
                fp_hash=_h("tktfp", seed, i),  # fuzzed
                trace_hash=_h("tkttrace", seed, i),  # fuzzed
                tls_ticket_id=ticket,  # the surviving binding: ONE reused resumption ticket
                hardware_concurrency=8,
                platform="Win32",
                automation=False,
                datacenter=True,  # corroborates the ambiguous ticket-reuse tell
            )
            for i in range(n)
        ]


@register
class IPv6Rotate:
    name = "ipv6-rotate"
    summary = (
        "A cloned fleet rotating IPv6 /128s inside a FEW real /64s to inflate apparent IP count — folds to the "
        "true origin count (one /64 = one subscriber), so it cannot fake spread and a cloned fp across distinct "
        "/64s still convicts."
    )

    # The distinct /64 subscriptions the fleet actually holds. Every node sprays its own /128 inside one of these,
    # but the /64 fold collapses the fleet to exactly this many origins — so it still spans >=2 origins (convicts
    # via fp-collision) without the /128 rotation buying any extra apparent spread.
    _NETS = 2

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4, fp = _ja4(seed), _h("v6fp", seed)
        return [
            FleetMember(
                f"v6rot-{i}",
                ja4,
                _ip6(seed, i, self._NETS),
                fp_hash=fp,  # one cloned profile across the /64s — convicts on >=2 distinct origins
                hardware_concurrency=8,
                platform="Win32",
                automation=True,  # corroborates the (ambiguous) fp-collision as a bot fleet, not a cohort
            )
            for i in range(n)
        ]


@register
class DiffuseCampaign:
    name = "diffuse-campaign"
    summary = (
        "the MAXIMAL evader: shared build (one JA4) + lockstep arrival + a humanizer tuned JUST ABOVE the hard "
        "template floor, with DISTINCT fp/trace/IP per node and clean IPs — no single pairwise binding, so the "
        "per-cluster scorer caps at candidate; caught only by axis A (aggregate multi-dimensional density)."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # The diversified fleet that defeats every pairwise binding: distinct fp (no fp_collision), distinct
        # trace_hash (no exact trace_collision), descriptors tuned ABOVE the 0.10 floor (template_similarity
        # silent), no shared WebRTC origin / ticket, clean residential IPs (no datacenter flag). What remains is
        # AGGREGATE correlation: one JA4 build + co-timed arrival + a descriptor family within axis A's soft eps.
        ja4 = _ja4(seed)
        return [
            FleetMember(
                f"camp-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("campfp", seed, i),  # distinct → no fp_collision
                trace_hash=_h("camptrace", seed, i),  # distinct → no exact trace_collision
                trace_descriptor=_diffuse_descriptor(seed, i),  # just above the floor → template_similarity silent
                hardware_concurrency=8,
                platform="Win32",
                automation=False,  # clean: no JS automation tell, no datacenter — only aggregate structure remains
            )
            for i in range(n)
        ]


@register
class DiffuseScheduled:
    name = "diffuse-scheduled"
    summary = (
        "diffuse-campaign that STAGGERS on a fixed SCHEDULE (regular gaps past the lockstep window) instead of "
        "co-arriving — sheds the lockstep co-arrival dim, but the REGULAR inter-arrival cadence restores the "
        "timing layer (independent users are Poisson, CV~1; a schedule is CV~0), so axis A still flags a "
        "campaign. A Poisson-RANDOM stagger evades — but then the timing is indistinguishable from N independent "
        "users, the genuine external wall."
    )
    _INTERVAL_S = 300.0  # regular cadence, well past the 120s lockstep window

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # Identical to diffuse-campaign (no pairwise binding) EXCEPT arrivals fall on a fixed schedule rather than
        # co-timed — the scheduled-stagger shape that co.`_arrival_regularity` restores the timing dim on.
        ja4 = _ja4(seed)
        return [
            FleetMember(
                f"sched-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("schedfp", seed, i),  # distinct → no fp_collision
                trace_hash=_h("schedtrace", seed, i),  # distinct → no exact trace_collision
                trace_descriptor=_diffuse_descriptor(seed, i),  # just above the floor → template_similarity silent
                hardware_concurrency=8,
                platform="Win32",
                automation=False,
                offset_seconds=i * self._INTERVAL_S,  # REGULAR schedule → the scheduled-stagger timing tell
            )
            for i in range(n)
        ]


@register
class DiffuseAutomated:
    name = "diffuse-automated"
    summary = (
        "the SLOPPY-but-diversified bot: a diffuse fleet (no pairwise binding, distinct fp/trace/IP, one build) "
        "STAGGERED on Poisson gaps (only a 2-dim candidate — evades lockstep AND the scheduled tell) that LEAKS a "
        "per-session automation tell. Axis-A corroboration lifts the 2-dim candidate to a campaign on the bot "
        "signal; a fully-clean diffuse fleet (no tell) stays a candidate — the real-browser frontier."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # diffuse-campaign shape (no pairwise binding) + Poisson stagger (2 soft dims, no timing tell) + the SLIP:
        # a per-session webdriver tell. The corroboration in co.score_campaigns keys on it to convict the cohort.
        ja4 = _ja4(seed)
        rng = random.Random(seed ^ 0xA5)
        offs: list[float] = []
        t = 0.0
        for _ in range(n):
            offs.append(t)
            t += rng.expovariate(1.0 / 300.0)  # Poisson gaps -> no lockstep, no scheduled -> exactly 2 soft dims
        return [
            FleetMember(
                f"auto-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("autofp", seed, i),
                trace_hash=_h("autotrace", seed, i),
                trace_descriptor=_diffuse_descriptor(seed, i),
                hardware_concurrency=8,
                platform="Win32",
                automation=True,  # the slip: a per-session webdriver tell the corroboration keys on
                offset_seconds=offs[i],
            )
            for i in range(n)
        ]


@register
class Diffuse:
    name = "diffuse"
    summary = (
        "the MAXIMAL in-sandbox evader: diffuse-campaign's shape (one build + a humanizer descriptor family, but "
        "distinct fp/trace/IP per node — no pairwise binding) POISSON-staggered and FULLY CLEAN (no automation "
        "tell). Only 2 soft dims (ja4 + descriptor), no timing tell (Poisson CV~1), no bot signal — so it stays a "
        "`candidate` on BOTH axes. Conviction is EXTERNAL-DATA-bound (IP reputation / prevalence baselines). The "
        "economic bind: shedding the last correlation (distinct builds + real-hardware fps + clean residential "
        "egress) = becoming N independent real users. This is the frontier the whole ladder converges on."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4 = _ja4(seed)
        rng = random.Random(seed ^ 0xD1FF)
        offs: list[float] = []
        t = 0.0
        for _ in range(n):
            offs.append(t)
            t += rng.expovariate(1.0 / 300.0)  # Poisson gaps -> no lockstep, no scheduled -> exactly 2 soft dims
        return [
            FleetMember(
                f"diff-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("difffp", seed, i),
                trace_hash=_h("difftrace", seed, i),
                trace_descriptor=_diffuse_descriptor(seed, i),
                hardware_concurrency=8,
                platform="Win32",
                automation=False,  # fully clean: no tell for the corroboration to key on
                offset_seconds=offs[i],
            )
            for i in range(n)
        ]


@register
class ToolFleet:
    name = "tool-fleet"
    summary = (
        "A no-JS automation-tool fleet (curl/Go/Python) sharing one tool JA4, bound by a reused TLS ticket "
        "across clean residential IPs — no JS tell, no datacenter flag; the non-browser JA4 corroborates the "
        "ambiguous ticket-reuse binding as a bot fleet (the no-JS coordination gap)."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # Scripted HTTP clients run NO JavaScript (no fp_hash/trace, no webdriver tell) on CLEAN residential IPs
        # (no datacenter flag), so the only corroborator is the JA4 itself — the edge classifies it as a
        # non-browser HTTP stack (ja4_client). They share ONE reused TLS-resumption ticket, the ambiguous binding
        # a no-JS fleet CAN produce (fp/trace collisions need a browser). A real captured go-http JA4 prefix.
        ja4 = "t13d131100_f57a46bbacb6_" + _h("toolext", seed)[:12]
        ticket = _h("toolticket", seed)
        return [
            FleetMember(
                f"tool-{i}",
                ja4,
                _ip(seed, i),
                tls_ticket_id=ticket,  # the surviving ambiguous binding: one TLS session reused fleet-wide
                ja4_client="go-http",  # the corroborator: a non-browser HTTP stack (no JS tell needed)
                automation=False,  # no JS → no webdriver/CDP tell
                datacenter=False,  # clean residential egress → no IP-reputation flag
            )
            for i in range(n)
        ]


@register
class Staggered:
    name = "staggered"
    summary = (
        "A cloned-profile fleet whose arrivals are SPREAD OVER TIME (beyond the lockstep window) to look "
        "organic — sheds only the lockstep corroboration; the fp-collision binding still convicts."
    )

    # Members arrive this far apart (seconds). > the engine's 120s lockstep window, so the cluster earns no
    # lockstep bonus — the educational point: timing-stagger defeats a CORROBORATING tell, not the conviction.
    _STEP_S = 300.0

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4, fp = _ja4(seed), _h("stagfp", seed)
        return [
            FleetMember(
                f"stag-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=fp,  # one cloned profile across distinct IPs — the convicting binding
                hardware_concurrency=8,
                platform="Win32",
                automation=True,  # the corroboration; fp_collision + automation convicts regardless of timing
                offset_seconds=i * self._STEP_S,  # spread arrivals beyond the lockstep window
            )
            for i in range(n)
        ]


@register
class HttpFlood:
    name = "httpflood"
    summary = (
        "An L7 HTTP flood (MHDDoS class): many no-JS tool sources share one flood-tool JA4 and hammer in "
        "lockstep across many distinct origins — no per-node binding; caught by the aggregate flood shape "
        "corroborated by the non-browser tool JA4 (the coordination scorer as L7-flood attributor). Skulk emits "
        "a coordination-shaped fleet, NOT request volume — it is not a DoS tool."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        # A pure HTTP flood runs NO JavaScript (no fp_hash/trace, no webdriver tell) and opens its own TLS
        # session per bot (no shared ticket), so it has NO per-node collision binding at all — only the AGGREGATE
        # is coordinated: N sources sharing one flood-tool JA4, in lockstep (offset 0), across N distinct origins.
        # Clean RESIDENTIAL egress (no datacenter flag) proves the point — the non-browser tool JA4 (ja4_client)
        # alone corroborates the ambiguous flood shape, so the flood convicts even without an IP-reputation flag.
        # A real captured go-http JA4 prefix (the same MHDDoS-class HTTP libraries drive these floods).
        ja4 = "t13d131100_f57a46bbacb6_" + _h("floodext", seed)[:12]
        return [
            FleetMember(
                f"flood-{i}",
                ja4,
                _ip(seed, i),  # one distinct origin per source (the botnet spread)
                ja4_client="go-http",  # the non-browser flood tool — the sole corroborator of the flood shape
                automation=False,  # no JS → no webdriver/CDP tell
                datacenter=False,  # clean residential egress → no IP-reputation flag; the tool JA4 carries it
            )
            for i in range(n)
        ]


@register
class Fuzzy:
    name = "fuzzy"
    summary = "EVOLVED: jittered fingerprint + trace per instance — evades exact-hash (the similarity frontier)."

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4 = _ja4(seed)
        # Every node's fp_hash and trace_hash is DISTINCT (jittered) — no two are byte-identical, so an
        # exact-match collision detector finds nothing and caps the cluster at `candidate`. The members are
        # still one fleet (shared JA4, lockstep, one IP block); only SIMILARITY clustering catches them.
        return [
            FleetMember(
                f"fuzzy-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("fuzzyfp", seed, i),
                trace_hash=_h("fuzzytrace", seed, i),
                hardware_concurrency=8,
                platform="Win32",
                automation=False,
            )
            for i in range(n)
        ]
