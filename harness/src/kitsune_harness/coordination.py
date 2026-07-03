# harness/coordination — grade a JA4 cluster into a fleet verdict via the TLS-vs-JS paradox.
# A real same-build cluster shares JS traits too; an anti-detect fleet randomizes JS yet shares one JA4.

"""Coordination scoring.

Coordination groups sessions by JA4 (the TLS-engine identity below the JS spoofing layer). But a JA4
cluster alone is only a *candidate* — millions of real users run the same Chrome build and share a
JA4. The discriminator is a paradox an anti-detect fleet cannot avoid:

    A genuine same-browser cohort that shares one JA4 also shares its JS-visible identity
    (hardwareConcurrency, platform, plugin set) — they are literally the same build on similar
    machines. An anti-detect fleet deliberately *randomizes* those JS traits per instance to look
    like distinct users — but it cannot randomize the TLS handshake, which is the engine's.

**identical TLS + divergent JS within one cluster** is suggestive — but on its own it is NOT a
conviction, because it is also the shape of a real diverse cohort: distinct users on the *same Chrome
build* share a JA4 (TLS is per-build, not per-machine) yet legitimately differ in hardware_concurrency,
device_memory and OS-platform (Win/Mac/Linux Chrome share a JA4). So the JS-divergence paradox, the IP
spread and lockstep timing are **corroborating** signals; a `fleet` *conviction* requires at least one
signal a real cohort cannot produce — see the conviction gate in ``score_cluster``. This is the durable
bots/DDoS signal — it survives any per-session fingerprint spoof because it is a property of the
*cluster*, not the instance.

A native anti-detect browser (BotBrowser) can dodge the paradox by going the *other* way: clone one
fingerprint profile across the fleet, so the JS is homogeneous and the cluster reads as a real cohort.
The complement closes it — a high-entropy ``fp_hash`` (canvas+audio+WebGL) that is byte-identical across
*distinct* source IPs cannot be organic (real machines each hash differently), so it convicts the
cloned-profile fleet on the same cluster-property logic. A fleet must either randomize JS (paradox) or
reuse one identity (collision); it cannot do neither.
"""

from __future__ import annotations

import ipaddress
import itertools
import logging
import statistics
from collections.abc import Callable
from dataclasses import dataclass, field

from kitsune_detector.models import MISSING, Layer, Session

_log = logging.getLogger(__name__)


def _ip_origin(ip: str) -> str:
    """Normalize a source IP to its *origin* — the unit a single subscriber controls — so "distinct source
    IPs" counts distinct ORIGINS, not distinct addresses. For IPv4 the address is the origin. For IPv6 the
    origin is the /64 prefix: every residential / mobile subscriber is handed a whole /64 (often a /56 or
    larger), and a single host freely mints unlimited /128s inside it (SLAAC + RFC 4941 privacy addresses
    rotate hourly). Counting raw /128s would (a) FALSE-FIRE — one real user's privacy-address rotation within
    their /64 looks like a multi-IP "fleet" — and (b) be EVADABLE — a cloned fleet on one /64 could manufacture
    "distinct" /128s for free to fake IP spread / satisfy the >=2-distinct-IP collision gate. Bucketing to /64
    closes both. A malformed/private/unparseable value is returned unchanged (e.g. a hostname placeholder)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
    return ip


# JS-visible traits an anti-detect tool randomizes per instance to fake diversity. A real
# same-JA4 cohort is homogeneous here; divergence across a JA4 cluster is the paradox.
_SPOOFABLE_TRAITS: list[tuple[Layer, str]] = [
    (Layer.browser, "nav_platform_os"),
    (Layer.browser, "ua_platform"),
    (Layer.browser, "hardware_concurrency"),
    (Layer.browser, "plugins_count"),
    (Layer.browser, "device_memory"),
]

_BASE_CANDIDATE = 0.30  # a shared-JA4 cluster, on its own (humans do this too)
_PARADOX_BONUS = 0.55  # identical TLS + divergent JS — the spoofing-fleet shape
_PER_MEMBER = 0.05  # each member beyond the second, capped
_MAX_MEMBER_BONUS = 0.15
_LOCKSTEP_WINDOW_S = 120.0  # sessions sharing a JA4 all arriving within this window are synchronized
_LOCKSTEP_BONUS = 0.12  # tightens confidence; kept < the fleet threshold so the JS paradox stays primary
# JA4_c (extensions + signature algorithms) divergence under a shared cipher-suite prefix. JA4 *sorts*
# extensions specifically to be robust to Chrome's order shuffling, so a varying JA4_c means the actual
# extension/sig-alg set differs across the cluster. GROUNDED 2026-06-20: this is NOT per-launch randomization
# by Camoufox — 2 concurrent Camoufox launches (+ the committed cf1/cf2 and the 3 camoufox-* captures) all
# emit an IDENTICAL JA4_c per config, so a real Camoufox FLEET does NOT diverge. The signal is produced by a
# multi-VERSION cohort (different Chrome/Firefox builds ship different extension/sig-alg sets) or a uTLS-style
# fingerprint randomizer — both REAL, which is exactly why ja4c_divergent is AMBIGUOUS (corroboration-gated):
# a benign mix of auto-update states diverges JA4_c too. (The fleet-ja4c-randomizer scenario + rp1/rp2 synthesise
# the divergence by combining the two real Camoufox-config JA4_c values; no single fleet tool produces it live.)
_JA4C_BONUS = 0.30
# The *complement* of the JS-divergence paradox. A randomizing fleet (Camoufox) varies its JS to fake
# distinct users; a native anti-detect browser (BotBrowser) does the opposite — it clones ONE fingerprint
# profile across every instance, so the high-entropy fp_hash (canvas+audio+WebGL) is byte-identical fleet-
# wide. Real machines, even on one browser build, each hash differently (GPU/driver/OS/font variance), so
# an identical fp_hash across *distinct* source IPs cannot be organic — it is one cloned profile behind
# proxies. Strong on its own: a homogeneous cluster this catches would otherwise read as a real cohort.
_FP_COLLISION_BONUS = 0.55
# The SIMILARITY analog of the exact trace-collision. A fleet that jitters its pointer trace per instance (one
# "humanizer" model sampled N times) defeats exact-hash trace_collision — every node's trace_hash differs — yet
# all N traces are drawn from ONE generative model, so their motion-feature descriptors cluster far tighter than
# N distinct humans' do. AMBIGUOUS like fp_collision (not unambiguous like the EXACT trace-collision): a tight
# trace cluster across distinct IPs cannot be N distinct humans (their motor noise spreads them well above the
# floor — grounded vs SapiMouse in template_calibration), but COULD be one real human across their own few
# sessions, so it convicts only when corroborated (automation tell / IP-reputation flag), exactly as fp_collision
# does for the standardized-corporate-fleet case.
_TEMPLATE_SIMILARITY_BONUS = 0.55
# The human floor: median pairwise descriptor distance BELOW which a cluster is one model, not N people. Set
# safely under the tightest distinct-human cohort (synthetic floor ≈ 0.166; SapiMouse second source via
# `task template-calibrate`) and well above a one-humanizer family (median ≈ 0.05-0.07). See template_calibration.
_TEMPLATE_EPSILON = 0.10
_TEMPLATE_MIN_MEMBERS = 3  # < 3 traces can't yield a meaningful median, and a 2-IP pair could be one human
# A reused TLS-resumption ticket (pre_shared_key / session_ticket id, captured by the edge) shared across distinct
# IPs. A resumption ticket is client-specific session material the server issued to ONE client, so the same id
# from distinct source IPs is one TLS identity shared across machines — a binding that survives JA4 rotation AND
# fp/trace fuzzing (the last thing a fully-fuzzed JA4-rotating fleet still shares if it reuses one session).
# AMBIGUOUS like fp_collision (a single roaming user CAN resume from a second IP — home then mobile — and some
# servers permit ticket reuse), so it convicts only when corroborated; a clean roaming user on residential IPs
# caps at candidate.
_TICKET_BONUS = 0.55
# A *confirmed* spoofing fleet (paradox or JA4_c) that is also spread across many distinct source IPs is
# the residential-proxy botnet pattern: the IP diversity is there to look like distinct users and defeat
# IP rate-limiting / datacenter-ASN rules, but the shared engine identity binds them. A modest escalation
# (IP diversity alone is the null hypothesis — many real users share a JA4 prefix — so it only adds once a
# spoofing tell is already present).
_PROXY_FLEET_BONUS = 0.10
# Diverse observed (proxy) IPs but ONE shared WebRTC-leaked real IP: proxies fronting a single origin.
# Very hard to explain innocently — a strong same-origin signal.
_SHARED_ORIGIN_BONUS = 0.30
# L7 application-layer flood attribution (the bot⇄DDoS convergence). An HTTP flood from a botnet presents
# per-connection as N independent clients, but its DDoS signature is the AGGREGATE: many sources hammering
# ONE target in synchrony over a shared engine — which is exactly a coordination cluster, so the coordination
# scorer attributes the flood the same way it attributes a scraping fleet. The flood SHAPE (a large, lockstep
# cluster spread across many distinct origins) is AMBIGUOUS — a legit flash-crowd (a sale drop, a viral link)
# is also many users arriving together from many IPs — so it convicts only when corroborated (a non-browser
# tool JA4, an h2/slow-HTTP DoS tell, a per-session automation tell, or datacenter/abuse IP reputation). A
# flash-crowd is real browsers on residential IPs (none of those) → capped at candidate; a botnet flood carries
# at least one → fleet. A coordinated flood cannot hide its aggregate any more than a scraping fleet can.
_FLOOD_MIN_ORIGINS = 6  # a flood is distributed across MANY sources — well above the 2-origin fleet floor
_FLOOD_BONUS = 0.30  # the ambiguous flood-shape bonus (corroboration-gated, like fp_collision)


@dataclass(frozen=True)
class FleetVerdict:
    """A graded coordination verdict for one JA4-prefix cluster."""

    ja4: str  # the shared JA4 prefix (JA4_a + JA4_b: TLS version/ALPN + cipher-suite hash)
    members: list[str]
    diverged_traits: dict[str, int]  # trait kind -> distinct value count (only those > 1)
    score: float
    label: str  # "fleet" | "candidate" | "benign"
    span_seconds: float | None = None  # first_seen spread across members (None if < 2 timestamps)
    ja4c_divergent: bool = False  # members share the cipher prefix but differ in extensions/sig-algs
    distinct_observed_ips: int = 0  # distinct source IPs across the cluster (proxy spread)
    cloned_fingerprint: str | None = None  # one high-entropy fp_hash shared across distinct IPs (reuse)
    cloned_trace: str | None = None  # one pointer-trajectory trace_hash shared across distinct IPs (replay)
    template_radius: float | None = None  # median pairwise trace-descriptor distance when below the human floor
    shared_ticket: str | None = None  # one TLS-resumption ticket id reused across distinct IPs (session reuse)
    shared_real_ip: str | None = None  # one WebRTC-leaked real IP behind diverse proxy IPs (same origin)
    request_volume: int = 0  # aggregate request_count across the cluster (DDoS severity, not confidence)
    arrival_rate_per_min: float | None = None  # sessions per minute over the arrival window (burst rate)
    l7_flood: bool = False  # attributed as an L7 application-layer flood (a corroborated flood-shape cluster)
    evidence: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """Operational threat level from scale + arrival rate — distinct from the fleet *confidence*
        ``score``. A confirmed fleet maxes the score whether it is 3 nodes or 3000; severity triages it."""
        if self.label != "fleet":
            return "n/a"
        rate = self.arrival_rate_per_min or 0.0
        if len(self.members) >= 50 or self.request_volume >= 500 or rate >= 60:
            return "critical"
        if len(self.members) >= 10 or self.request_volume >= 100 or rate >= 15:
            return "high"
        return "moderate"


def _ja4(session: Session) -> str | None:
    v = session.value(Layer.network, "ja4")
    return None if v is MISSING else str(v)


def _ja4_prefix(ja4: str) -> str:
    """JA4_a + JA4_b (the engine's TLS version/ALPN + cipher-suite identity), dropping the
    randomizable JA4_c (extensions/sig-algs). For ``t13d1717h2_5b57614c22b0_3cbfd9..`` →
    ``t13d1717h2_5b57614c22b0``. Robust to per-launch extension randomization."""
    return "_".join(ja4.split("_")[:2])


def _first_seen_span(sessions: list[Session]) -> float | None:
    """Seconds between the earliest and latest first_seen across the cluster (None if < 2)."""
    stamps = sorted(s.first_seen for s in sessions)
    if len(stamps) < 2:
        return None
    return (stamps[-1] - stamps[0]).total_seconds()


def _diverged_traits(sessions: list[Session]) -> dict[str, int]:
    """For each spoofable trait, the count of distinct non-missing values across the cluster."""
    out: dict[str, int] = {}
    for layer, kind in _SPOOFABLE_TRAITS:
        values = {session.value(layer, kind) for session in sessions}
        values.discard(MISSING)
        if len(values) > 1:
            out[kind] = len(values)
    return out


def _distinct_values(sessions: list[Session], layer: Layer, kind: str) -> set[object]:
    """The set of distinct non-missing values for one signal across the cluster."""
    vals = {session.value(layer, kind) for session in sessions}
    vals.discard(MISSING)
    return vals


def _distinct_origins(sessions: list[Session]) -> set[str]:
    """The set of distinct source-IP *origins* (IPv4 address / IPv6 /64 — see :func:`_ip_origin`) across the
    cluster. This is the "distinct source IPs" unit for IP-spread scoring: one IPv6 subscriber's many privacy
    addresses collapse to their single /64 origin, so they neither inflate the proxy-spread bonus nor let a
    one-/64 fleet fake IP diversity."""
    return {_ip_origin(str(ip)) for ip in _distinct_values(sessions, Layer.network, "observed_ip")}


def _fp_collision(sessions: list[Session]) -> tuple[str, int] | None:
    """A high-entropy ``fp_hash`` shared by members spanning >= 2 *distinct* observed IPs — the cloned-
    profile-reuse tell. Identical fp_hash from one IP is one machine over many sessions (benign), so the
    discriminator is the same hash arriving from different sources. Returns ``(hash, distinct_ip_count)``
    for the widest such collision, else ``None``."""
    by_hash: dict[str, set[str]] = {}
    for session in sessions:
        fp = session.value(Layer.browser, "fp_hash")
        ip = session.value(Layer.network, "observed_ip")
        if fp is MISSING or ip is MISSING:
            continue
        by_hash.setdefault(str(fp), set()).add(_ip_origin(str(ip)))
    best: tuple[str, int] | None = None
    for fp, ips in by_hash.items():
        if len(ips) >= 2 and (best is None or len(ips) > best[1]):
            best = (fp, len(ips))
    return best


def _trace_collision(sessions: list[Session]) -> tuple[str, int] | None:
    """A pointer-trajectory ``trace_hash`` shared by members spanning >= 2 *distinct* observed IPs — the
    behavioural analog of ``_fp_collision``. Two real users never trace the same path, so an identical
    trace_hash from distinct sources is one tool replaying a canned "humanised" trajectory across the fleet.
    Catches a fleet that clones *behaviour* even when each instance has a distinct fingerprint. Returns
    ``(hash, distinct_ip_count)`` for the widest such collision, else ``None``."""
    by_hash: dict[str, set[str]] = {}
    for session in sessions:
        th = session.value(Layer.behavioral, "trace_hash")
        ip = session.value(Layer.network, "observed_ip")
        if th is MISSING or ip is MISSING:
            continue
        by_hash.setdefault(str(th), set()).add(_ip_origin(str(ip)))
    best: tuple[str, int] | None = None
    for th, ips in by_hash.items():
        if len(ips) >= 2 and (best is None or len(ips) > best[1]):
            best = (th, len(ips))
    return best


def _shared_ticket(sessions: list[Session]) -> tuple[str, int] | None:
    """A TLS-resumption ``tls_ticket_id`` shared by members spanning >= 2 *distinct* observed IPs — the
    session-reuse binding. Identical to :func:`_fp_collision` in shape (same id from one IP is one client over
    many sessions; the discriminator is distinct sources). Returns ``(ticket_id, distinct_ip_count)`` for the
    widest such reuse, else ``None``."""
    by_ticket: dict[str, set[str]] = {}
    for session in sessions:
        tid = session.value(Layer.network, "tls_ticket_id")
        ip = session.value(Layer.network, "observed_ip")
        if tid is MISSING or ip is MISSING:
            continue
        by_ticket.setdefault(str(tid), set()).add(_ip_origin(str(ip)))
    best: tuple[str, int] | None = None
    for tid, ips in by_ticket.items():
        if len(ips) >= 2 and (best is None or len(ips) > best[1]):
            best = (tid, len(ips))
    return best


def _as_descriptor(value: object) -> tuple[float, ...] | None:
    """Parse a wire ``trace_descriptor`` (a JSON array of numbers) into a float tuple, or None if malformed."""
    if not isinstance(value, (list, tuple)) or not value:
        return None
    try:
        return tuple(float(x) for x in value)
    except (TypeError, ValueError):
        return None


def _template_similarity(sessions: list[Session]) -> tuple[float, int] | None:
    """The SIMILARITY analog of :func:`_trace_collision`. Among members carrying a ``trace_descriptor`` and
    spanning >= 2 DISTINCT observed IPs, return ``(median_pairwise_distance, distinct_ip_count)`` when that
    median sits BELOW the human floor ``_TEMPLATE_EPSILON`` — i.e. the traces are too mutually similar to be N
    distinct humans (one humanizer model sampled per node), even though every ``trace_hash`` differs so the
    exact-collision rule found nothing. Needs >= ``_TEMPLATE_MIN_MEMBERS`` descriptors (a meaningful median; a
    2-member pair could be one real person on two networks). Returns ``None`` otherwise. The median (not max)
    is the cohesion statistic so a single mixed-in real trace cannot mask an otherwise tight fleet cluster."""
    pairs = [
        (d, _ip_origin(str(ip)))
        for s in sessions
        if (d := _as_descriptor(s.value(Layer.behavioral, "trace_descriptor"))) is not None
        and (ip := s.value(Layer.network, "observed_ip")) is not MISSING
    ]
    if len(pairs) < _TEMPLATE_MIN_MEMBERS or len({ip for _, ip in pairs}) < 2:
        return None
    from .biomech import descriptor_distance

    dists = [descriptor_distance(a, b) for (a, _), (b, _) in itertools.combinations(pairs, 2)]
    median = statistics.median(dists)
    if median <= _TEMPLATE_EPSILON:
        return round(median, 4), len({ip for _, ip in pairs})
    return None


# Per-session AUTOMATION / headless / injection tells a clean corporate real browser never carries. Their
# presence on a cluster member is what tells a CLONED-profile bot fleet (automated) apart from a STANDARDIZED
# corporate fleet (clean real browsers on identical hardware) — the one case fp_collision alone cannot
# distinguish (see the conviction gate in score_cluster).
_AUTOMATION_TELLS: frozenset[str] = frozenset(
    {
        "webdriver",
        "webdriver_spoofed",
        "cdp_runtime_enabled",
        "automation_globals",
        "cdc_artifacts",
        "csp_bypassed",
        "ch_he_headless",
        "ua_is_headless",
        "chrome_object_missing",
        "chrome_runtime_missing",
    }
)


def _has_automation_tell(sessions: list[Session]) -> bool:
    """True iff any cluster member carries a per-session automation/headless/injection tell — the corroboration
    that an identical-fingerprint cluster is a CLONED bot fleet, not a clean standardized corporate cohort."""
    return any(session.value(Layer.browser, kind) is True for session in sessions for kind in _AUTOMATION_TELLS)


def _has_ip_reputation_flag(sessions: list[Session]) -> bool:
    """True iff any cluster member's source IP is flagged datacenter/hosting, a known proxy/VPN/Tor exit, or
    abuse-listed (the ``reputation.asn_is_datacenter`` / ``is_proxy_exit`` / ``is_abuse_listed`` signals the
    detector emits via the curated CIDR feed — abuse = Spamhaus DROP + IPsum, hijacked/criminal infra). This is
    the IP-reputation disambiguator the ambiguous signals need: a CLONED/randomizer bot fleet
    runs on datacenter or residential-PROXY infrastructure, whereas a standardized corporate fleet or a
    multi-Chrome-version cohort is on genuine RESIDENTIAL IPs (no flag). So an IP-reputation flag corroborates
    an fp-collision / JA4_c divergence as a real bot fleet even when no per-session automation tell is present
    (a clean native anti-detect clone). A private/residential IP yields (False, False) — never a flag — so it
    cannot corroborate a real cohort."""
    return any(
        session.value(Layer.reputation, "asn_is_datacenter") is True
        or session.value(Layer.reputation, "is_proxy_exit") is True
        or session.value(Layer.reputation, "is_abuse_listed") is True
        for session in sessions
    )


def _has_known_automation_ja4(sessions: list[Session]) -> bool:
    """True iff any cluster member's JA4 is classified as a KNOWN NON-BROWSER HTTP client (curl / Go net/http /
    Python urllib …) — the edge's ``network.ja4_client_hint`` (see ``net.ja4_tool_vs_ua``). It is the
    network-layer twin of :func:`_has_automation_tell`: a per-session automation tell (webdriver, CDP) is a JS
    signal absent from a no-JS scraper, but a non-browser TLS handshake is itself proof the client is an
    automation tool, not a real browser. So a cluster of automation-tool clients sharing an AMBIGUOUS
    coordination binding (a reused TLS ticket, divergent JA4_c) is a bot fleet even on clean residential IPs
    with no JS automation tell — the no-JS gap the datacenter/proxy IP-reputation flag alone could not close. A
    real diverse cohort runs real BROWSERS (a browser hint, never a client hint), so this can only flag a
    genuine automation-tool cluster."""
    return any(session.value(Layer.network, "ja4_client_hint") is not MISSING for session in sessions)


# Network-layer DoS tells the edge emits for an application-layer flood: HTTP/2 frame-abuse floods (the
# H2FrameScanner — rapid-reset / continuation / control-frame / MadeYouReset) and the slow-HTTP header-hold
# (the SlowLorisScanner). Their presence is itself proof of an automated volumetric attack — the network-layer
# twin of an automation tell for a flood cluster — so they corroborate the ambiguous flood SHAPE exactly as a
# tool JA4 or a datacenter IP does. (``slow_http_attack`` is listed ahead of its edge wiring so the flood
# attributor already recognises it once the slow-HTTP h1 path emits it.)
_DOS_TELLS: frozenset[str] = frozenset(
    {
        "h2_rapid_reset",
        "h2_continuation_flood",
        "h2_control_flood",
        "h2_madeyoureset",
        "slow_http_attack",
    }
)


def _has_dos_tell(sessions: list[Session]) -> bool:
    """True iff any cluster member carries an edge DoS tell — an HTTP/2 frame-abuse flood or a slow-HTTP
    header-hold. A flood that presents via frame abuse rather than a recognised tool JA4 is still corroborated
    as an automated attack by these (the G16 edge scanners feeding the G17 coordination attributor)."""
    return any(session.value(Layer.network, kind) is True for session in sessions for kind in _DOS_TELLS)


def score_cluster(prefix: str, members: list[tuple[str, Session]], basis: str = "JA4 cipher prefix") -> FleetVerdict:
    """Grade one cluster of >= 2 sessions sharing a binding invariant. ``basis`` names that invariant: the
    default ``JA4 cipher prefix`` (the cipher-suite engine identity) or, for a JA4-ROTATING fleet caught by
    :func:`_collision_clusters`, the cross-instance binding it shares (cloned fingerprint / replayed trace /
    shared WebRTC origin). The conviction logic is identical either way — it reads the sessions, not the key."""
    names = sorted(n for n, _ in members)
    sessions = [s for _, s in members]
    diverged = _diverged_traits(sessions)
    full_ja4s = {_ja4(s) for s in sessions}
    full_ja4s.discard(None)
    ja4c_divergent = len(full_ja4s) > 1

    score = _BASE_CANDIDATE
    evidence = [f"{len(names)} sessions share {basis} `{prefix}`"]
    score += min((len(names) - 2) * _PER_MEMBER, _MAX_MEMBER_BONUS)

    if diverged:
        score += _PARADOX_BONUS
        detail = ", ".join(f"{k} x{v}" for k, v in sorted(diverged.items()))
        evidence.append(f"cipher suites identical but JS divergent across members: {detail}")
    else:
        evidence.append("JS traits homogeneous across members — consistent with a real cohort")

    if ja4c_divergent:
        score += _JA4C_BONUS
        evidence.append(
            f"cipher suites identical but JA4 extensions/sig-algs divergent "
            f"({len(full_ja4s)} variants) — per-launch TLS randomization"
        )

    # Fingerprint-collision: the complement of the paradox. Identical high-entropy fp_hash across distinct
    # source IPs is one cloned anti-detect profile behind proxies — a homogeneous cluster that would
    # otherwise read as a benign same-build cohort.
    collision = _fp_collision(sessions)
    cloned_fingerprint = collision[0] if collision else None
    if collision is not None:
        score += _FP_COLLISION_BONUS
        evidence.append(
            f"identical high-entropy fingerprint `{collision[0]}` across {collision[1]} distinct "
            f"source IPs — cloned-profile reuse (one anti-detect profile shared fleet-wide)"
        )

    # Trace-collision: the behavioural analog of the fingerprint collision. An identical pointer-trajectory
    # trace_hash across distinct source IPs is one canned "humanised" path replayed fleet-wide — it convicts
    # a fleet that randomises its *fingerprint* per instance but reuses one recorded mouse trace.
    trace_collision = _trace_collision(sessions)
    cloned_trace = trace_collision[0] if trace_collision else None
    if trace_collision is not None:
        score += _FP_COLLISION_BONUS
        evidence.append(
            f"identical pointer trace `{trace_collision[0]}` across {trace_collision[1]} distinct "
            f"source IPs — replayed canned trajectory (two real users never trace the same path)"
        )

    # Template-similarity: the SIMILARITY analog of the trace collision. Members whose pointer-trace descriptors
    # cluster below the human floor are one humanizer model sampled per node — caught even though each instance
    # jittered its trace to a distinct trace_hash (defeating the EXACT trace-collision rule). Ambiguous, so
    # corroboration-gated below alongside fp_collision.
    template = _template_similarity(sessions)
    template_radius = template[0] if template else None
    if template is not None:
        score += _TEMPLATE_SIMILARITY_BONUS
        evidence.append(
            f"pointer traces cluster below the human floor (median descriptor distance {template[0]:.3f} "
            f"≤ {_TEMPLATE_EPSILON}) across {template[1]} distinct source IPs — one humanizer model sampled "
            f"per node (distinct trace_hash per instance, so exact-match found nothing)"
        )

    # Shared TLS-resumption ticket: a binding that survives JA4 rotation AND fp/trace fuzzing. One ticket id
    # across distinct IPs is one TLS session reused across machines. Ambiguous (a roaming user could resume from
    # a second IP), so corroboration-gated below alongside fp_collision / template_similarity.
    ticket = _shared_ticket(sessions)
    shared_ticket = ticket[0] if ticket else None
    if ticket is not None:
        score += _TICKET_BONUS
        evidence.append(
            f"reused TLS-resumption ticket `{ticket[0]}` across {ticket[1]} distinct source IPs — one TLS "
            f"session shared across machines (a resumption ticket is client-specific; survives JA4 rotation)"
        )

    span = _first_seen_span(sessions)
    if span is not None and span <= _LOCKSTEP_WINDOW_S:
        score += _LOCKSTEP_BONUS
        evidence.append(f"timing lockstep: all members arrived within {span:.0f}s")
    elif span is not None:
        evidence.append(f"arrivals spread over {span:.0f}s — no lockstep")

    # IP topology: residential-proxy spread + same-origin-behind-proxies (the bots/DDoS frontier).
    observed = _distinct_origins(sessions)
    webrtc = _distinct_values(sessions, Layer.browser, "webrtc_public_ip")
    distinct_observed = len(observed)
    shared_real_ip: str | None = None
    if (diverged or ja4c_divergent or collision is not None or trace_collision is not None) and distinct_observed > 1:
        score += _PROXY_FLEET_BONUS
        evidence.append(
            f"distributed across {distinct_observed} distinct source IPs — residential-proxy fleet "
            f"pattern (IP diversity masks one shared engine, defeating IP/ASN rules)"
        )
    if distinct_observed > 1 and len(webrtc) == 1:
        shared_real_ip = str(next(iter(webrtc)))
        score += _SHARED_ORIGIN_BONUS
        evidence.append(
            f"{distinct_observed} proxy IPs front one real IP `{shared_real_ip}` (WebRTC) — same-origin fleet"
        )

    # L7 flood shape: a large cluster in timing lockstep across many distinct origins is the aggregate signature
    # of an application-layer HTTP flood (a coordinated botnet hammering one target, not N independent clients).
    # Ambiguous with a legit flash-crowd (also many users arriving together from many IPs), so corroboration-
    # gated below alongside fp_collision — a residential real-browser flash-crowd carries no corroborator.
    flood_shape = span is not None and span <= _LOCKSTEP_WINDOW_S and distinct_observed >= _FLOOD_MIN_ORIGINS
    if flood_shape:
        score += _FLOOD_BONUS
        evidence.append(
            f"L7 flood shape: {len(names)} sources in timing lockstep across {distinct_observed} distinct "
            f"origins — the aggregate signature of an application-layer flood (a coordinated botnet, not N "
            f"independent clients)"
        )

    # Threat severity (scale + rate) — operational triage, separate from the fleet-confidence score.
    request_volume = sum(s.request_count for s in sessions)
    arrival_rate: float | None = None
    if span is not None and span > 0:
        arrival_rate = round(len(names) / (span / 60.0), 1)

    # Conviction gate: a `fleet` label needs a *convicting* coordination signal — one a real diverse cohort
    # CANNOT produce. The signals split into UNAMBIGUOUS (solo-convict) and AMBIGUOUS (corroboration-gated):
    #
    # UNAMBIGUOUS — no real cohort, however standardized, can produce these:
    #   - trace_collision: an identical pointer trajectory across distinct IPs (two real users never trace the
    #     same path — it is one canned/replayed "humanised" path).
    #   - shared_real_ip: distinct proxy IPs fronting ONE WebRTC-leaked origin.
    #
    # AMBIGUOUS — a real cohort CAN produce these, so they convict only when corroborated:
    #   - fp_collision: an identical high-entropy fp_hash across distinct IPs is ALSO a STANDARDIZED CORPORATE
    #     FLEET (same laptop model + locked OS/browser image hashes byte-identically) on distinct WFH IPs —
    #     grounded: 4 clean Windows laptops, one fp, 4 residential IPs scored `fleet 1.00`. "Real machines each
    #     hash differently" is FALSE for identical hardware.
    #   - ja4c_divergent: a divergent JA4_c across a shared cipher prefix is ALSO a MULTI-CHROME-VERSION cohort
    #     — JA4_c (extensions/sig-algs) varies across Chrome versions while the cipher prefix stays (grounded:
    #     the fleet captures show 2 real JA4_c under one prefix from a Chromium version bump), so a normal mix
    #     of auto-update states diverges JA4_c. "Real Chrome's JA4_c is stable" holds per-LAUNCH, not per-VERSION;
    #     a 4-user clean 2-version cohort on distinct IPs scored `fleet 0.92`.
    #   - flood_shape: a large lockstep cluster across many distinct origins is ALSO a legit FLASH-CROWD (a sale
    #     drop / viral link — many real users arriving together from many IPs). The corroborator (tool JA4, DoS
    #     tell, automation, datacenter/abuse IP) is what tells a botnet L7 flood from an organic crowd.
    # Corroboration = an unambiguous signal OR a per-session AUTOMATION/headless tell on a cluster member (a bot
    # fleet is automated; a real corporate/multi-version cohort is clean real browsers). An uncorroborated
    # ambiguous cluster caps at `candidate` for operator review — the disambiguator is IP reputation
    # (datacenter/proxy = bot, residential = legit), the still-blocked coordination half. The JS-divergence
    # paradox, IP spread and lockstep stay corroborating-only (a real diverse cohort produces them too).
    unambiguous = trace_collision is not None or shared_real_ip is not None
    # Corroboration = an unambiguous signal, a per-session automation tell, an IP-reputation flag
    # (datacenter/proxy/Tor exit), OR a known-automation-tool JA4 (network.ja4_client_hint — curl/Go/Python).
    # The IP-reputation flag is the production disambiguator: a bot fleet runs on datacenter/proxy infrastructure
    # (flagged), a corporate / multi-version real cohort on residential IPs (never flagged), so it convicts a
    # CLEAN native clone on datacenter IPs that carries no automation tell. The tool-JA4 flag is the network-layer
    # twin for a NO-JS fleet: a curl/Go/Python cluster carries no JS automation tell and may run on clean
    # residential IPs, but its non-browser TLS handshake proves it is automation — so an ambiguous binding it
    # shares (a reused TLS ticket, divergent JA4_c) convicts where datacenter/automation corroboration is absent.
    corroborated = (
        unambiguous
        or _has_automation_tell(sessions)
        or _has_ip_reputation_flag(sessions)
        or _has_known_automation_ja4(sessions)
        or _has_dos_tell(sessions)
    )
    fp_collision_convicts = collision is not None and corroborated
    ja4c_convicts = ja4c_divergent and corroborated
    # template-similarity is ambiguous (one humanizer OR one real human across sessions), so it convicts only
    # when corroborated — exactly like fp_collision. A real diverse cohort never produces it (their traces
    # spread above the floor), so its only innocent source is one person's own sessions, which the same
    # automation-tell / IP-reputation corroboration disambiguates.
    template_convicts = template is not None and corroborated
    # A reused TLS ticket is ambiguous like fp_collision (a roaming user can resume from a second IP), so it
    # convicts only when corroborated.
    ticket_convicts = ticket is not None and corroborated
    # The L7 flood shape is ambiguous like fp_collision (a legit flash-crowd produces it too), so it convicts
    # only when corroborated — a non-browser tool JA4, a DoS tell, an automation tell, or datacenter/abuse IP
    # reputation. A residential real-browser flash-crowd carries none, so it caps at candidate.
    flood_convicts = flood_shape and corroborated
    convicting = (
        unambiguous or fp_collision_convicts or ja4c_convicts or template_convicts or ticket_convicts or flood_convicts
    )
    _any_ambiguous = (
        collision is not None or ja4c_divergent or template is not None or ticket is not None or flood_shape
    )
    if _any_ambiguous and _has_known_automation_ja4(sessions):
        evidence.append(
            "cluster shares a known automation-tool JA4 (non-browser HTTP client) — corroborates the ambiguous "
            "coordination binding as a bot fleet (a real cohort runs browsers, not curl/Go/Python)"
        )
    if _any_ambiguous and not corroborated:
        which = " + ".join(
            w
            for w, on in (
                ("identical-fingerprint collision", collision is not None),
                ("JA4_c divergence", ja4c_divergent),
                ("template-similar traces", template is not None),
                ("reused TLS ticket", ticket is not None),
                ("L7 flood shape", flood_shape),
            )
            if on
        )
        evidence.append(
            f"{which} is UNCORROBORATED (no automation tell, tool-JA4, DoS tell, cloned trace or shared "
            f"origin) — ambiguous between a bot fleet / flood and a real cohort or flash-crowd (standardized "
            f"hardware hashes alike; a multi-version cohort diverges JA4_c); capped at candidate pending IP "
            f"reputation"
        )
    score = max(0.0, min(1.0, score))
    if score >= 0.60 and convicting:
        label = "fleet"
    elif score >= 0.30:
        label = "candidate"
        if score >= 0.60:
            evidence.append(
                "shared JA4 + JS divergence / IP spread but NO convicting coordination signal "
                "(per-launch TLS randomization, cloned-profile collision, or shared WebRTC origin) — "
                "a real diverse cohort on one browser build produces this shape, so capped at candidate"
            )
    else:
        label = "benign"
    return FleetVerdict(
        ja4=prefix,
        members=names,
        diverged_traits=diverged,
        score=round(score, 3),
        label=label,
        span_seconds=span,
        ja4c_divergent=ja4c_divergent,
        distinct_observed_ips=distinct_observed,
        cloned_fingerprint=cloned_fingerprint,
        cloned_trace=cloned_trace,
        template_radius=template_radius,
        shared_ticket=shared_ticket,
        shared_real_ip=shared_real_ip,
        request_volume=request_volume,
        arrival_rate_per_min=arrival_rate,
        l7_flood=flood_convicts,
        evidence=evidence,
    )


# Cross-instance binding invariants that are INDEPENDENT of JA4. A fleet that rotates its JA4 per node
# (uTLS egress / mixed builds) to defeat JA4-prefix clustering still shares one of these — a cloned
# fingerprint, a replayed pointer trace, or one WebRTC-leaked origin behind its proxies.
_COLLISION_KEYS: list[tuple[Layer, str, str]] = [
    (Layer.browser, "fp_hash", "cloned fingerprint"),
    (Layer.behavioral, "trace_hash", "replayed pointer trace"),
    (Layer.browser, "webrtc_public_ip", "shared WebRTC origin"),
    (Layer.network, "tls_ticket_id", "reused TLS session ticket"),
]


def _collision_clusters(
    corpus: list[tuple[str, Session]],
) -> dict[tuple[str, str], tuple[str, list[tuple[str, Session]]]]:
    """Clusters bound by a cross-instance invariant that does NOT depend on JA4 — one cloned ``fp_hash``, one
    replayed ``trace_hash``, or one shared ``webrtc_public_ip`` — each spanning >= 2 DISTINCT observed IPs.

    JA4-prefix clustering (``score_corpus`` / ``FleetTracker``) misses a fleet that rotates its JA4 per node:
    each instance lands in its own singleton cluster and is never graded, so its convicting collision tells
    are never computed (grounded: a cloned-fp / replayed-trace / shared-origin fleet with a distinct JA4 per
    node scores zero clusters). This recovers those fleets by their actual binding. The >= 2-distinct-IP gate
    is the same discriminator the per-cluster collision checks use — one machine over many sessions is one IP,
    so it cannot collide with itself. Keyed by ``(kind, value)``; the value is the shared invariant."""
    out: dict[tuple[str, str], tuple[str, list[tuple[str, Session]]]] = {}
    for layer, kind, basis in _COLLISION_KEYS:
        by_val: dict[str, dict[str, tuple[str, Session]]] = {}
        for name, session in corpus:
            value = session.value(layer, kind)
            ip = session.value(Layer.network, "observed_ip")
            if value is MISSING or ip is MISSING:
                continue
            by_val.setdefault(str(value), {})[name] = (name, session)
        for value, members in by_val.items():
            ips = {_ip_origin(str(m[1].value(Layer.network, "observed_ip"))) for m in members.values()}
            if len(members) >= 2 and len(ips) >= 2:
                out[(kind, value)] = (basis, list(members.values()))
    return out


def _clusters(corpus: list[tuple[str, Session]]) -> list[tuple[str, str, list[tuple[str, Session]]]]:
    """Every graded-eligible coordination cluster as ``(basis, key, members)``: JA4-prefix clusters of >= 2
    members, PLUS collision clusters (:func:`_collision_clusters`) not already covered by a JA4 cluster — so a
    JA4-rotating fleet is caught by its binding while a fleet that shares both JA4 and a collision is reported
    once (the collision cluster is dropped when its members are a subset of a graded JA4 cluster)."""
    out: list[tuple[str, str, list[tuple[str, Session]]]] = []
    ja4_clusters: dict[str, list[tuple[str, Session]]] = {}
    for name, session in corpus:
        ja4 = _ja4(session)
        if ja4 is not None:
            ja4_clusters.setdefault(_ja4_prefix(ja4), []).append((name, session))
    graded_sets: list[frozenset[str]] = []
    for prefix, members in ja4_clusters.items():
        if len(members) > 1:
            out.append(("JA4 cipher prefix", prefix, members))
            graded_sets.append(frozenset(n for n, _ in members))
    for (_kind, value), (basis, members) in _collision_clusters(corpus).items():
        member_set = frozenset(n for n, _ in members)
        if any(member_set <= g for g in graded_sets):
            continue  # already caught (and reported) by a JA4 cluster — don't double-count
        out.append((basis, value, members))
    return out


_SEVERITY_RANK = {"n/a": 0, "moderate": 1, "high": 2, "critical": 3}


class FleetTracker:
    """Online coordination detector: ingest sessions one at a time (arrival order) and emit an alert the
    moment a JA4-prefix cluster crosses the ``fleet`` threshold or escalates severity. This is how a
    production bots/DDoS detector works — incremental clustering with threshold alerting — versus the
    offline ``score_corpus`` snapshot. Each ``observe`` re-scores only the affected cluster.
    """

    def __init__(self, window_seconds: float | None = None) -> None:
        # window_seconds: only cluster members within this many seconds of the latest arrival count — a
        # burst over a sliding window, not slow all-time accumulation. None = unbounded (accumulate all).
        self._window = window_seconds
        self._members: list[tuple[str, Session]] = []
        self._label: dict[str, str] = {}  # cluster key ("basis|value") -> last label
        self._severity: dict[str, str] = {}

    def observe(self, name: str, session: Session) -> FleetVerdict | None:
        """Add one session; return a FleetVerdict iff this arrival newly raised a cluster's alert state
        (became a ``fleet``, or a ``fleet`` escalated to a higher severity tier). Otherwise ``None``.

        Clusters by JA4 prefix AND by cross-instance collision (see :func:`_clusters`), so a fleet that
        rotates its JA4 per node alerts the moment its shared binding (cloned fp / replayed trace / shared
        origin) spans a second distinct IP — not only the JA4-sharing case the per-prefix grouping caught."""
        self._members.append((name, session))
        if self._window is not None:
            # Age out members older than the window relative to this arrival (the stream's clock).
            cutoff = session.first_seen.timestamp() - self._window
            self._members[:] = [(n, s) for (n, s) in self._members if s.first_seen.timestamp() >= cutoff]
        best: FleetVerdict | None = None
        active: set[str] = set()
        for basis, key, members in _clusters(self._members):
            ck = f"{basis}|{key}"
            active.add(ck)
            verdict = score_cluster(key, members, basis=basis)
            prev_label = self._label.get(ck, "benign")
            prev_sev = self._severity.get(ck, "n/a")
            self._label[ck] = verdict.label
            self._severity[ck] = verdict.severity
            became_fleet = verdict.label == "fleet" and prev_label != "fleet"
            escalated = verdict.label == "fleet" and _SEVERITY_RANK[verdict.severity] > _SEVERITY_RANK[prev_sev]
            if (became_fleet or escalated) and (best is None or verdict.score > best.score):
                best = verdict
        # A cluster whose members all aged out of the window resets, so a fresh burst re-alerts.
        for ck in list(self._label):
            if ck not in active:
                self._label[ck] = "benign"
                self._severity[ck] = "n/a"
        return best


def score_corpus(corpus: list[tuple[str, Session]]) -> list[FleetVerdict]:
    """Grade every coordination cluster, strongest first. Clusters by JA4 *prefix* (cipher-suite identity)
    AND by cross-instance collision (cloned fp / replayed trace / shared origin across distinct IPs), so a
    JA4-rotating fleet is caught by its binding rather than slipping past JA4-only clustering (see
    :func:`_clusters`)."""
    verdicts = [score_cluster(key, members, basis=basis) for basis, key, members in _clusters(corpus)]
    return sorted(verdicts, key=lambda v: -v.score)


# ── Axis A: population/aggregate coordination (the campaign detector) ──────────────────────────────────────
# The per-cluster scorer above convicts on a PAIRWISE binding a real cohort cannot produce (cloned fp, replayed
# trace, shared origin, reused ticket, template-tight traces). A fully-diversified fleet removes every such
# binding — distinct fp per node, distinct trace, descriptors tuned just ABOVE the hard template floor, no shared
# origin/ticket — and slips through as singletons (the maximal in-sandbox evader). But even with no single hard
# binding, a coordinated campaign is correlated IN AGGREGATE across several INDEPENDENT weak dimensions at once;
# a real diverse population (even a flash crowd, tight on time+build only) is not. This is the lab's coherence
# thesis lifted from the session to the COHORT: flag a community that is dense across >= _CAMPAIGN_MIN_DENSE_DIMS
# independent soft dimensions. Conviction posture: CANDIDATE-grade intelligence — the RELATIVE multi-dimensional
# structure is groundable in-sandbox, but the ABSOLUTE thresholds (what an organic population's density is) are
# external-data-bound (real traffic), so this surfaces a `campaign` for operator review, not an auto-conviction.
_CAMPAIGN_SOFT_EPS = 0.15  # descriptor distance below which two traces are "similar" (looser than the 0.10 floor)
_CAMPAIGN_WINDOW_S = 120.0  # arrivals within this many seconds are co-timed
_CAMPAIGN_EDGE_DIMS = 2  # a pair links when similar on >= this many independent dimensions
_CAMPAIGN_DENSITY = 0.5  # a dimension is "dense" in a community when >= this fraction of its pairs share it
_CAMPAIGN_MIN_DENSE_DIMS = 3  # a community is a `campaign` when dense on >= this many independent dimensions
_CAMPAIGN_MIN_MEMBERS = 3
_CAMPAIGN_REGULARITY_CV = 0.35  # inter-arrival CV below which a community's arrivals are SCHEDULED, not organic
_CAMPAIGN_REGULARITY_MIN = 5  # need >= 5 arrivals (4 gaps) before an inter-arrival CV is a meaningful estimate


def _arrival_regularity(sessions: list[Session]) -> float | None:
    """Inter-arrival coefficient of variation of a community's arrivals — the SCHEDULED-STAGGER timing tell.
    Independent users arrive as a Poisson process (exponential gaps, CV -> 1); a fleet that staggers PAST the
    lockstep co-arrival window but on a REGULAR schedule has near-constant gaps (CV -> 0). BASELINE-FREE: the
    Poisson CV=1 is intrinsic to independent arrivals, not a population statistic, so a CV well below 1 marks a
    scheduled cohort regardless of the absolute rate. Returns the CV, or None when too few arrivals for a
    meaningful estimate or when arrivals are simultaneous (that is lockstep, handled by its own dim)."""
    if len(sessions) < _CAMPAIGN_REGULARITY_MIN:
        return None
    ts = sorted(s.first_seen.timestamp() for s in sessions)
    gaps = [b - a for a, b in itertools.pairwise(ts)]
    mean = statistics.mean(gaps)
    if mean <= 0:
        return None
    return statistics.pstdev(gaps) / mean


def _session_rep_flag(s: Session) -> bool:
    """True iff the session carries any IP-reputation flag (datacenter / proxy / abuse) — shared-infra class."""
    return (
        s.value(Layer.reputation, "asn_is_datacenter") is True
        or s.value(Layer.reputation, "is_proxy_exit") is True
        or s.value(Layer.reputation, "is_abuse_listed") is True
    )


#: The independent SOFT dimensions a coordinated cohort correlates on (none is a conviction alone). Each is a
#: pairwise predicate over two sessions; a real diverse population is correlated on at most one or two of these.
_CAMPAIGN_DIMS: list[tuple[str, Callable[[Session, Session], bool]]] = []


def _campaign_dim(name: str) -> Callable[[Callable[[Session, Session], bool]], Callable[[Session, Session], bool]]:
    def reg(fn: Callable[[Session, Session], bool]) -> Callable[[Session, Session], bool]:
        _CAMPAIGN_DIMS.append((name, fn))
        return fn

    return reg


@_campaign_dim("ja4_prefix")
def _dim_ja4(a: Session, b: Session) -> bool:
    ja, jb = _ja4(a), _ja4(b)
    return ja is not None and jb is not None and _ja4_prefix(ja) == _ja4_prefix(jb)


@_campaign_dim("descriptor")
def _dim_descriptor(a: Session, b: Session) -> bool:
    da = _as_descriptor(a.value(Layer.behavioral, "trace_descriptor"))
    db = _as_descriptor(b.value(Layer.behavioral, "trace_descriptor"))
    if da is None or db is None:
        return False
    from .biomech import descriptor_distance

    return descriptor_distance(da, db) <= _CAMPAIGN_SOFT_EPS


@_campaign_dim("lockstep")
def _dim_lockstep(a: Session, b: Session) -> bool:
    return abs((a.first_seen - b.first_seen).total_seconds()) <= _CAMPAIGN_WINDOW_S


@_campaign_dim("origin_reputation")
def _dim_origin_rep(a: Session, b: Session) -> bool:
    return _session_rep_flag(a) and _session_rep_flag(b)


@_campaign_dim("prevalence_tail")
def _dim_prevalence(a: Session, b: Session) -> bool:
    return a.value(Layer.browser, "prevalence_low") is True and b.value(Layer.browser, "prevalence_low") is True


_NATIVE_MSS = 1452  # >= this is a native ethernet path; below is a tunnel/VPN/mobile-reduced MSS (mirrors demo.py)


def _session_mss(session: Session) -> int | None:
    """The TCP MSS from the session's JA4T fingerprint (``window_options_MSS_scale``). None if absent/unparseable."""
    v = session.value(Layer.network, "ja4t")
    if v is MISSING:
        return None
    parts = str(v).split("_")
    if len(parts) < 3:
        return None
    try:
        return int(parts[2])
    except ValueError:
        return None


@_campaign_dim("proxy_egress")
def _dim_proxy_egress(a: Session, b: Session) -> bool:
    """Two members share a REDUCED (tunnel/VPN) MSS AND the SAME value — a shared proxy/tunnel egress that the
    datacenter/proxy IP-reputation feed misses on RESIDENTIAL exits. The TRANSPORT layer, independent of ja4
    (TLS) and descriptor (behaviour). FP-SAFE as a SOFT dim: a single reduced MSS is a legit VPN/mobile path
    (demo.py marks it informational), and independent users VARY their MSS by access network — so this fires only
    when a cohort shares ONE reduced value, and it convicts only inside the >= 3-independent-dim gate. A legit VPN/
    mobile COHORT shares an MSS but carries HUMAN traces, so the descriptor dim is denied and the community caps at
    2 dims (candidate) — the residential-proxy analog of the origin_reputation dim for datacenter egress."""
    ma, mb = _session_mss(a), _session_mss(b)
    return ma is not None and mb is not None and ma == mb and ma < _NATIVE_MSS


@dataclass(frozen=True)
class CampaignVerdict:
    """A graded population/aggregate coordination verdict for one community (axis A)."""

    members: list[str]
    dense_dimensions: list[str]  # the independent soft dimensions the community is dense on (>= _CAMPAIGN_DENSITY)
    distinct_origins: int
    score: float
    label: str  # "campaign" | "candidate"
    evidence: list[str] = field(default_factory=list)


# Per-bucket candidate-pair cap: a single blocking bucket larger than this (a same-build flood or a busy
# arrival window — the flash-crowd/DDoS shape, which the severity-graded FleetTracker already triages) is
# down-sampled for campaign analysis rather than spending O(b^2). NEVER silent: the drop is logged.
_CAMPAIGN_MAX_BUCKET = 4000


def _campaign_candidate_pairs(corpus: list[tuple[str, Session]]) -> set[tuple[int, int]]:
    """Blocking-based candidate pairs — the sub-quadratic replacement for the O(n^2) all-pairs scan. Two sessions
    can only form an edge if they share >= 2 soft dimensions; every such pair co-occurs in at least one EXACT
    blocking bucket — the JA4 cipher prefix, or a time window (lockstep). So we enumerate within-bucket pairs of
    those two indices (time windows also paired with the adjacent bucket, since a within-window pair can straddle
    a boundary), yielding a candidate superset of the true edges. The verify step (`_CAMPAIGN_DIMS`) is unchanged,
    so the campaigns returned are IDENTICAL to the exact scan for any campaign whose members share a build or
    arrive co-timed (the realistic case + every grounded fixture). A pair correlated ONLY on rep/prevalence/
    descriptor with distinct builds AND spread arrivals is the documented blind spot — caught by the offline exact
    path, not the streaming one. Buckets over _CAMPAIGN_MAX_BUCKET (a flood) are down-sampled with a logged drop."""
    by_ja4: dict[str, list[int]] = {}
    by_time: dict[int, list[int]] = {}
    for i, (_n, s) in enumerate(corpus):
        ja4 = _ja4(s)
        if ja4 is not None:
            by_ja4.setdefault(_ja4_prefix(ja4), []).append(i)
        by_time.setdefault(int(s.first_seen.timestamp() // _CAMPAIGN_WINDOW_S), []).append(i)

    pairs: set[tuple[int, int]] = set()

    def _add_within(idxs: list[int], kind: str, key: object) -> None:
        if len(idxs) > _CAMPAIGN_MAX_BUCKET:
            _log.warning(
                "campaign blocking: %s bucket %r has %d sessions (> %d cap) — down-sampling for candidate "
                "generation; the offline exact score_campaigns covers the full bucket",
                kind,
                key,
                len(idxs),
                _CAMPAIGN_MAX_BUCKET,
            )
            idxs = idxs[:_CAMPAIGN_MAX_BUCKET]
        for a, b in itertools.combinations(idxs, 2):
            pairs.add((a, b) if a < b else (b, a))

    for prefix, idxs in by_ja4.items():
        _add_within(idxs, "ja4", prefix)
    for bucket, idxs in by_time.items():
        _add_within(idxs, "time", bucket)
        nxt = by_time.get(bucket + 1)  # a within-window pair can straddle the bucket boundary → pair across it
        if nxt:
            for a in idxs:
                for b in nxt:
                    pairs.add((a, b) if a < b else (b, a))
    return pairs


def _campaign_components(corpus: list[tuple[str, Session]]) -> list[list[int]]:
    """Union-find connected components over the multi-dimensional similarity graph: an edge links two sessions
    that are similar on >= _CAMPAIGN_EDGE_DIMS independent dimensions. Edges are verified only over blocking-
    derived CANDIDATE pairs (:func:`_campaign_candidate_pairs`), not all-pairs — sub-quadratic at fleet scale."""
    n = len(corpus)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i, j in _campaign_candidate_pairs(corpus):
        si, sj = corpus[i][1], corpus[j][1]
        if sum(1 for _name, fn in _CAMPAIGN_DIMS if fn(si, sj)) >= _CAMPAIGN_EDGE_DIMS:
            parent[find(i)] = find(j)
    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    return [g for g in groups.values() if len(g) >= _CAMPAIGN_MIN_MEMBERS]


def score_campaigns(corpus: list[tuple[str, Session]]) -> list[CampaignVerdict]:
    """Grade population-level coordination: communities dense across multiple INDEPENDENT soft dimensions — the
    diversified fleet that leaks no single pairwise binding (so :func:`score_corpus` misses it) yet is correlated
    in aggregate. Strongest first. A community spanning >= 2 distinct origins and dense on >= 3 independent
    dimensions is a `campaign`; dense on exactly 2 is a `candidate` (a flash crowd shape — review, not convict)."""
    verdicts: list[CampaignVerdict] = []
    for comp in _campaign_components(corpus):
        members = sorted(corpus[i][0] for i in comp)
        sessions = [corpus[i][1] for i in comp]
        origins = len(_distinct_origins(sessions))
        if origins < 2:
            continue  # a single origin's own sessions are not a multi-node campaign
        pairs = list(itertools.combinations(comp, 2))
        dense: list[str] = []
        for name, fn in _CAMPAIGN_DIMS:
            hits = sum(1 for i, j in pairs if fn(corpus[i][1], corpus[j][1]))
            if pairs and hits / len(pairs) >= _CAMPAIGN_DENSITY:
                dense.append(name)
        # PROXY_EGRESS is a soft transport tell (a shared reduced tunnel MSS) that a LEGIT VPN/mobile cohort ALSO
        # carries — so on its own it must NOT lift ja4 + timing to a campaign (that false-convicts a corporate-VPN
        # cohort with regular logins). Gate it on the DESCRIPTOR dim: a shared tunnel MSS convicts only alongside a
        # humanizer-trace cluster (the one dim a real cohort's human traces cannot fake). This makes it the
        # residential-proxy analog of origin_reputation — a corroborator of a humanizer fleet, not a standalone dim.
        if "proxy_egress" in dense and "descriptor" not in dense:
            dense.remove("proxy_egress")
        # TIMING layer via SCHEDULED REGULARITY: a fleet that staggers past the lockstep co-arrival window but
        # arrives on a REGULAR schedule still leaks the timing layer (independent users arrive Poisson, CV~1; a
        # scheduled fleet regular, CV<<1). Count it ONLY when lockstep is not already dense, so the timing layer
        # contributes AT MOST ONE dimension (no double-count that would inflate the independent-dim tally).
        if "lockstep" not in dense:
            cv = _arrival_regularity(sessions)
            if cv is not None and cv <= _CAMPAIGN_REGULARITY_CV:
                dense.append("scheduled")
        if len(dense) < 2:
            continue
        # CORROBORATION (the axis-A analog of score_cluster's conviction gate): a 2-dim community is only a
        # `candidate` on soft correlation alone — but if a member carries a per-session BOT tell (an automation/
        # headless/injection signal) or the community's shared build is a KNOWN automation-tool JA4, the cohort is
        # a coordinated BOT campaign, not an ambiguous 2-dim coincidence. The tell is an INDEPENDENT layer
        # (browser-automation / non-browser-stack), so it lifts the candidate to a campaign. FP-SAFE: a legit
        # cohort never BOTH forms a 2-dim community (human descriptors spread past the eps; distinct real builds
        # shed the ja4 dim) AND carries an automation tell / tool JA4 — the per-session bot signals are absent on
        # real browsers by construction. Only baseline-free in-sandbox tells corroborate here (NOT IP reputation).
        if len(dense) == 2 and (_has_automation_tell(sessions) or _has_known_automation_ja4(sessions)):
            dense.append("automation")
        label = "campaign" if len(dense) >= _CAMPAIGN_MIN_DENSE_DIMS else "candidate"
        score = min(1.0, 0.3 + 0.18 * len(dense))
        evidence = [
            f"{len(members)} sessions across {origins} distinct origins form a community dense on "
            f"{len(dense)} independent dimension(s): {', '.join(dense)}",
            "no single pairwise binding required — aggregate multi-dimensional correlation a diverse cohort "
            "(even a flash crowd, tight on build+time only) does not produce; candidate-grade pending an "
            "organic-traffic baseline (absolute thresholds external-data-bound)",
        ]
        verdicts.append(
            CampaignVerdict(
                members=members,
                dense_dimensions=dense,
                distinct_origins=origins,
                score=round(score, 3),
                label=label,
                evidence=evidence,
            )
        )
    return sorted(verdicts, key=lambda v: -v.score)


def render_campaigns(corpus: list[tuple[str, Session]]) -> str:
    """Render the population/aggregate campaign verdicts (axis A) as markdown."""
    verdicts = score_campaigns(corpus)
    lines = [f"## Campaigns (aggregate) — {len(verdicts)} community(ies) across {len(corpus)} sessions", ""]
    if not verdicts:
        return "\n".join([*lines, "- (no multi-dimensional community)"]) + "\n"
    for v in verdicts:
        lines.append(
            f"### `{v.label}` — score **{v.score:.2f}** · {len(v.members)} sessions · dims {v.dense_dimensions}"
        )
        lines.append(f"- members: {', '.join(v.members)}")
        for e in v.evidence:
            lines.append(f"- {e}")
        lines.append("")
    return "\n".join(lines) + "\n"


def replay_campaigns(
    corpus: list[tuple[str, Session]], window_seconds: float = 900.0
) -> list[tuple[str, CampaignVerdict]]:
    """Streaming axis A: feed the corpus in arrival (first_seen) order through a sliding window, re-scoring the
    window incrementally and emitting ``(trigger_session, campaign)`` the first time each campaign community
    appears — the online analog of :func:`replay_stream`. The window bounds both memory and the per-step blocked
    re-score cost (only recent sessions are held), so it runs in real time at fleet scale. ``window_seconds``
    ages out members older than that relative to the latest arrival (default 15 min)."""
    ordered = sorted(corpus, key=lambda nv: nv[1].first_seen)
    buf: list[tuple[str, Session]] = []
    alerted: set[str] = set()  # members of campaigns already alerted — a growing campaign must not re-fire
    alerts: list[tuple[str, CampaignVerdict]] = []
    for name, session in ordered:
        buf.append((name, session))
        cutoff = session.first_seen.timestamp() - window_seconds
        buf[:] = [(n, s) for (n, s) in buf if s.first_seen.timestamp() >= cutoff]
        for v in score_campaigns(buf):
            if v.label != "campaign":
                continue
            # A campaign that overlaps an already-alerted one is the SAME campaign accreting members — not new.
            if alerted.isdisjoint(v.members):
                alerts.append((name, v))
            alerted.update(v.members)
    return alerts


def render_coordination(corpus: list[tuple[str, Session]]) -> str:
    """Render graded fleet verdicts as markdown."""
    verdicts = score_corpus(corpus)
    lines = [f"## Coordination — {len(verdicts)} graded cluster(s) across {len(corpus)} sessions", ""]
    if not verdicts:
        return "\n".join([*lines, "- (no JA4 cluster of size > 1)"]) + "\n"
    for v in verdicts:
        lines.append(f"### `{v.label}` — score **{v.score:.2f}** · {len(v.members)} sessions")
        if v.label == "fleet":
            rate = f", {v.arrival_rate_per_min}/min" if v.arrival_rate_per_min is not None else ""
            lines.append(f"- **severity: {v.severity}** ({v.request_volume} requests{rate})")
        lines.append(f"- members: {', '.join(v.members)}")
        for e in v.evidence:
            lines.append(f"- {e}")
        lines.append("")
    return "\n".join(lines) + "\n"


def replay_stream(
    corpus: list[tuple[str, Session]], window_seconds: float | None = None
) -> list[tuple[str, FleetVerdict]]:
    """Feed the corpus through a FleetTracker in arrival (first_seen) order; return (trigger_session,
    alert_verdict) for each arrival that raised the alert state — the online detector's alert log."""
    ordered = sorted(corpus, key=lambda nv: nv[1].first_seen)
    tracker = FleetTracker(window_seconds=window_seconds)
    alerts: list[tuple[str, FleetVerdict]] = []
    for name, session in ordered:
        verdict = tracker.observe(name, session)
        if verdict is not None:
            alerts.append((name, verdict))
    return alerts


def render_stream(corpus: list[tuple[str, Session]]) -> str:
    """Render the online alert log: which arriving session tripped each fleet/severity alert."""
    alerts = replay_stream(corpus)
    lines = [f"## Online coordination — {len(alerts)} alert(s) over {len(corpus)} arrivals", ""]
    if not alerts:
        return "\n".join([*lines, "- (no fleet crossed the alert threshold)"]) + "\n"
    for trigger, v in alerts:
        lines.append(
            f"- on `{trigger}` → **{v.label}** (severity {v.severity}, {len(v.members)} nodes, "
            f"score {v.score:.2f}) cluster `{v.ja4}`"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    import sys

    from .corpus import load_corpus

    argv = sys.argv[1:] if argv is None else argv
    stream = "--stream" in argv
    paths = [a for a in argv if a != "--stream"]
    directory = paths[0] if paths else "corpus/fleet"
    corpus = load_corpus(directory)
    print((render_stream if stream else render_coordination)(corpus), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
