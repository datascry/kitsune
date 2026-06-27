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
import statistics
from dataclasses import dataclass, field

from kitsune_detector.models import MISSING, Layer, Session


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
    """True iff any cluster member's source IP is flagged datacenter/hosting or a known proxy/VPN/Tor exit
    (the ``reputation.asn_is_datacenter`` / ``is_proxy_exit`` signals the detector emits via the curated CIDR
    feed). This is the IP-reputation disambiguator the ambiguous signals need: a CLONED/randomizer bot fleet
    runs on datacenter or residential-PROXY infrastructure, whereas a standardized corporate fleet or a
    multi-Chrome-version cohort is on genuine RESIDENTIAL IPs (no flag). So an IP-reputation flag corroborates
    an fp-collision / JA4_c divergence as a real bot fleet even when no per-session automation tell is present
    (a clean native anti-detect clone). A private/residential IP yields (False, False) — never a flag — so it
    cannot corroborate a real cohort."""
    return any(
        session.value(Layer.reputation, "asn_is_datacenter") is True
        or session.value(Layer.reputation, "is_proxy_exit") is True
        for session in sessions
    )


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
    # Corroboration = an unambiguous signal OR a per-session AUTOMATION/headless tell on a cluster member (a bot
    # fleet is automated; a real corporate/multi-version cohort is clean real browsers). An uncorroborated
    # ambiguous cluster caps at `candidate` for operator review — the disambiguator is IP reputation
    # (datacenter/proxy = bot, residential = legit), the still-blocked coordination half. The JS-divergence
    # paradox, IP spread and lockstep stay corroborating-only (a real diverse cohort produces them too).
    unambiguous = trace_collision is not None or shared_real_ip is not None
    # Corroboration = an unambiguous signal, a per-session automation tell, OR an IP-reputation flag
    # (datacenter/proxy/Tor exit). The IP-reputation flag is the production disambiguator: a bot fleet runs on
    # datacenter/proxy infrastructure (flagged), a corporate / multi-version real cohort on residential IPs
    # (never flagged), so it convicts a CLEAN native clone on datacenter IPs that carries no automation tell.
    corroborated = unambiguous or _has_automation_tell(sessions) or _has_ip_reputation_flag(sessions)
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
    convicting = unambiguous or fp_collision_convicts or ja4c_convicts or template_convicts or ticket_convicts
    if (collision is not None or ja4c_divergent or template is not None or ticket is not None) and not corroborated:
        which = " + ".join(
            w
            for w, on in (
                ("identical-fingerprint collision", collision is not None),
                ("JA4_c divergence", ja4c_divergent),
                ("template-similar traces", template is not None),
                ("reused TLS ticket", ticket is not None),
            )
            if on
        )
        evidence.append(
            f"{which} is UNCORROBORATED (no automation tell, cloned trace or shared origin) — ambiguous "
            f"between a bot fleet and a real cohort (standardized hardware hashes alike; a multi-version "
            f"cohort diverges JA4_c); capped at candidate pending IP reputation"
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
