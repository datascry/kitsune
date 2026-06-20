# tests/test_coordination — graded fleet verdicts via the TLS-identical-but-JS-divergent paradox.
# A real same-JA4 cohort is JS-homogeneous; an anti-detect fleet diverges JS yet shares one JA4.

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from kitsune_harness.coordination import (
    FleetTracker,
    render_coordination,
    render_stream,
    replay_stream,
    score_cluster,
    score_corpus,
)
from kitsune_harness.corpus import load_corpus

from .conftest import FIXED


def _repo_corpus(name: str) -> Path:
    # corpus/ lives at the repo root (harness/tests/<file> -> parents[2] == repo root).
    return Path(__file__).resolve().parents[2] / "corpus" / name


def test_real_residential_proxy_fleet_is_convicted() -> None:
    # Ground the coordination detector on the REAL captured residential-proxy fleet (came through the edge),
    # not just synthetic sessions: rp1/rp2/rp3 must score `fleet` via the convicting signals a real diverse
    # cohort cannot produce — per-launch JA4_c randomization AND one WebRTC-leaked origin behind 3 proxy IPs.
    verdicts = score_corpus(load_corpus(_repo_corpus("fleet-proxy")))
    assert len(verdicts) == 1
    v = verdicts[0]
    assert sorted(v.members) == ["rp1", "rp2", "rp3"]
    assert v.label == "fleet"
    assert v.ja4c_divergent and v.shared_real_ip is not None
    assert v.distinct_observed_ips == 3


def test_real_cloned_fleet_online_alert() -> None:
    # The ONLINE (production-mode) FleetTracker, grounded on the real captured cloned fleet: replaying
    # cn1/cn2/cn3 in arrival order must raise exactly one `fleet` alert, on the SECOND arrival — the moment
    # the cloned fp_hash spans two distinct IPs and the collision becomes observable. Complements the offline
    # score_corpus grounding (test_real_cloned_fingerprint_fleet_is_convicted) with the streaming detector.
    corpus = load_corpus(_repo_corpus("fleet-cloned"))
    alerts = replay_stream(corpus)
    assert len(alerts) == 1
    _trigger, verdict = alerts[0]
    assert verdict.label == "fleet"
    assert verdict.cloned_fingerprint is not None
    assert len(verdict.members) == 2  # alert raised the instant the 2nd distinct-IP member collides


def test_real_cloned_fingerprint_fleet_is_convicted() -> None:
    # Ground the cloned-fingerprint convicting path on a REAL captured fleet (previously only synthetic): three
    # instances of one anti-detect image, run CONCURRENTLY through the live edge so each held a distinct
    # container IP, share one deterministic high-entropy fp_hash across 3 distinct observed IPs — the
    # cloned-profile-behind-proxies shape (the complement of the JS-divergence paradox). cn1/cn2/cn3 must
    # score `fleet` via the cloned-fingerprint collision alone — NOT JA4_c (their TLS is identical) and NOT a
    # shared WebRTC origin — so it exercises a different convicting signal than the fleet-proxy fixture.
    verdicts = score_corpus(load_corpus(_repo_corpus("fleet-cloned")))
    assert len(verdicts) == 1
    v = verdicts[0]
    assert sorted(v.members) == ["cn1", "cn2", "cn3"]
    assert v.label == "fleet"
    assert v.cloned_fingerprint is not None  # one fp_hash across distinct IPs — the convicting signal
    assert v.distinct_observed_ips == 3
    assert v.ja4c_divergent is False  # convicted by the collision, not per-launch TLS randomization


def test_real_camoufox_two_node_cohort_is_candidate_not_fleet() -> None:
    # Trusted-but-verified: the synthetic scenarios assume camoufox randomizes its JA4_c per launch, but the
    # REAL camoufox capture (cf1/cf2) shows STABLE JA4_c and homogeneous JS — indistinguishable from two real
    # users on one build. The conviction gate correctly WITHHOLDS `fleet` (no convicting coordination signal),
    # grading it `candidate`. Convicting a homogeneous 2-node same-JA4 cohort would be a botnet verdict on a
    # browser's user base.
    verdicts = score_corpus(load_corpus(_repo_corpus("fleet")))
    assert len(verdicts) == 1
    v = verdicts[0]
    assert sorted(v.members) == ["cf1", "cf2"]
    assert v.label == "candidate"
    assert not v.ja4c_divergent
    assert v.cloned_fingerprint is None and v.cloned_trace is None and v.shared_real_ip is None


def test_canvas_randomized_cloned_profile_fleet_caps_at_candidate() -> None:
    # A KNOWN coordination evasion, locked here so a future change cannot "close" it FP-unsafely. A fleet that
    # clones ONE non-canvas profile (identical hardware_concurrency + platform) but RANDOMIZES its canvas/audio
    # per instance (so fp_hash differs) across distinct IPs falls through every convicting signal: no JS-paradox
    # (traits identical, not divergent), no fp_collision (fp_hash differs), no JA4_c divergence, no trace/shared
    # origin. It correctly grades `candidate`, NOT `fleet`.
    #
    # The tempting fix — a HARDWARE-PROFILE collision (identical screen/cores/GPU across distinct IPs) — is
    # deliberately NOT built because it is not FP-safe: (a) those traits are LOW-entropy (1920x1080 + 8 cores +
    # a common GPU is the modal config, so a real cohort collides by coincidence), and (b) "identical hardware
    # but different fp_hash" is exactly a PRIVACY-BROWSER cohort (Brave/Tor farble canvas, so identical corporate
    # laptops hash differently) — convicting it would botnet-label real privacy-browser users. The high-entropy
    # fp_hash collision is the right discriminator precisely because it avoids both. This shape is the
    # coordination analog of the per-session EVADES mimics: catching it needs a signal a real cohort cannot share.
    cluster = [
        (
            f"clone{i}",
            _sess(
                f"clone{i}",
                "t13d1517h2_8daaf6152771_v1",
                hw=8,
                plat="Windows",
                observed_ip=f"5.5.5.{i}",
                fp_hash=f"canvas{i}",
            ),
        )
        for i in range(4)
    ]
    v = score_cluster("t13d1517h2_8daaf6152771", cluster)
    assert v.label != "fleet", v.evidence  # the FP-safe boundary: no convicting signal, never a botnet verdict
    assert v.cloned_fingerprint is None  # fp_hash differs per instance — the collision tell does not fire


def _sess(
    name: str,
    ja4: str | None,
    hw: int | None = None,
    plat: str | None = None,
    *,
    offset_s: float = 0.0,
    observed_ip: str | None = None,
    webrtc_ip: str | None = None,
    fp_hash: str | None = None,
    trace_hash: str | None = None,
    webdriver: bool = False,
) -> Session:
    when = FIXED + timedelta(seconds=offset_s)

    def mk(layer: Layer, kind: str, value: object, src: Source) -> Signal:
        return Signal(session_id=name, layer=layer, kind=kind, value=value, source=src, observed_at=when)

    sigs: list[Signal] = []
    if ja4 is not None:
        sigs.append(mk(Layer.network, "ja4", ja4, Source.edge))
    if webdriver:  # per-session automation tell — corroborates an fp-collision as a cloned bot fleet
        sigs.append(mk(Layer.browser, "webdriver", True, Source.collector))
    if hw is not None:
        sigs.append(mk(Layer.browser, "hardware_concurrency", hw, Source.collector))
    if plat is not None:
        sigs.append(mk(Layer.browser, "nav_platform_os", plat, Source.collector))
    if observed_ip is not None:
        sigs.append(mk(Layer.network, "observed_ip", observed_ip, Source.edge))
    if webrtc_ip is not None:
        sigs.append(mk(Layer.browser, "webrtc_public_ip", webrtc_ip, Source.collector))
    if fp_hash is not None:
        sigs.append(mk(Layer.browser, "fp_hash", fp_hash, Source.collector))
    if trace_hash is not None:
        sigs.append(mk(Layer.behavioral, "trace_hash", trace_hash, Source.collector))
    return group_signals(sigs)[0]


def test_paradox_alone_is_capped_at_candidate() -> None:
    # JS-divergence paradox with NO convicting coordination signal is the null hypothesis too: real
    # distinct users on one Chrome build share a JA4 yet differ in hardware_concurrency. High score,
    # but capped at "candidate" — convicting needs a signal real diversity cannot produce.
    members = [("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32)), ("c", _sess("c", "X", 8))]
    v = score_cluster("X", members)
    assert v.label == "candidate"
    assert v.score >= 0.60  # the score is high, but the conviction gate withholds the fleet label
    assert v.diverged_traits == {"hardware_concurrency": 2}
    assert any("NO convicting coordination signal" in e for e in v.evidence)


def test_legit_diverse_cohort_is_not_a_fleet() -> None:
    # Regression: 4 distinct real users on ONE Chrome build (identical full JA4 → JA4_c stable), diverse
    # hardware/OS, distinct fp_hash, distinct IPs, spread over 15 min. This is a popular browser's user
    # base, not a botnet — it must NOT convict, despite paradox + IP-spread both firing.
    ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"  # identical full JA4 across all → not JA4_c-divergent
    members = [
        ("u1", _sess("u1", ja4, 4, "Windows", offset_s=0, observed_ip="71.10.0.1", fp_hash="aa01")),
        ("u2", _sess("u2", ja4, 8, "Windows", offset_s=300, observed_ip="98.20.0.2", fp_hash="bb02")),
        ("u3", _sess("u3", ja4, 16, "MacIntel", offset_s=620, observed_ip="24.30.0.3", fp_hash="cc03")),
        ("u4", _sess("u4", ja4, 12, "Windows", offset_s=900, observed_ip="63.40.0.4", fp_hash="dd04")),
    ]
    v = score_cluster("t13d1516h2_8daaf6152771", members)
    assert v.label == "candidate"  # NOT fleet — no convicting signal
    assert v.ja4c_divergent is False and v.cloned_fingerprint is None and v.shared_real_ip is None


def test_homogeneous_cluster_is_only_a_candidate() -> None:
    # Same JA4 AND identical JS — looks like a real same-build cohort, not a spoofing fleet.
    members = [("a", _sess("a", "X", 8, "Windows")), ("b", _sess("b", "X", 8, "Windows"))]
    v = score_cluster("X", members)
    assert v.label == "candidate"
    assert v.diverged_traits == {}
    assert any("homogeneous" in e for e in v.evidence)


def test_profile_reuse_fleet_is_caught() -> None:
    # The BotBrowser shape: homogeneous JS (one cloned profile, so it would otherwise read as a benign
    # same-build cohort) but the SAME high-entropy fp_hash arriving from DISTINCT source IPs — one
    # anti-detect profile fronted by proxies. The fp-collision signal must lift this to "fleet" where the
    # JS-divergence paradox cannot (JS is identical, not divergent). The instances are AUTOMATED (webdriver),
    # which corroborates the fp-collision as a CLONED bot fleet rather than a standardized corporate cohort
    # (identical hardware also hashes alike — see test_corporate_fleet_fp_collision_is_not_convicted).
    members = [
        ("a", _sess("a", "X", 8, "Windows", observed_ip="1.1.1.1", fp_hash="deadbeef", webdriver=True)),
        ("b", _sess("b", "X", 8, "Windows", observed_ip="2.2.2.2", fp_hash="deadbeef", webdriver=True)),
        ("c", _sess("c", "X", 8, "Windows", observed_ip="3.3.3.3", fp_hash="deadbeef", webdriver=True)),
    ]
    v = score_cluster("X", members)
    assert v.label == "fleet"
    assert v.diverged_traits == {}  # JS homogeneous — the paradox did NOT fire
    assert v.cloned_fingerprint == "deadbeef"
    assert any("cloned-profile reuse" in e for e in v.evidence)


def test_datacenter_ip_corroborates_a_clean_clone() -> None:
    # The IP-reputation disambiguator: a CLEAN native clone (no automation tell) sharing one fp across distinct
    # DATACENTER IPs IS a bot fleet — the reputation.asn_is_datacenter flag corroborates the fp-collision where
    # no automation tell does. (A residential corporate cohort with the same fp-collision but no flag stays
    # candidate — test_corporate_fleet_fp_collision_is_not_convicted.)
    def dc(name: str, ip: str) -> Session:
        s = _sess(name, "X", 8, "Windows", observed_ip=ip, fp_hash="clean-clone")
        extra = Signal(
            session_id=name,
            layer=Layer.reputation,
            kind="asn_is_datacenter",
            value=True,
            source=Source.detector,
            observed_at=FIXED,
        )
        return group_signals(list(s.signals.network) + list(s.signals.browser) + [extra])[0]

    members = [("d0", dc("d0", "11.0.0.1")), ("d1", dc("d1", "22.0.0.2")), ("d2", dc("d2", "33.0.0.3"))]
    v = score_cluster("X", members)
    assert v.cloned_fingerprint == "clean-clone"
    assert v.label == "fleet"  # datacenter IP-reputation flag corroborates the collision — no automation needed


def test_corporate_fleet_fp_collision_is_not_convicted() -> None:
    # FP guard: a STANDARDIZED corporate fleet (identical laptop model + locked image hashes byte-identically)
    # on distinct WFH residential IPs produces the SAME identical-fp-across-distinct-IPs shape as a cloned bot
    # fleet — but they are clean real browsers (no automation tell) with DISTINCT human traces. fp-collision
    # alone must NOT convict them as a `fleet` (a botnet verdict on a corporate cohort); capped at candidate.
    members = [
        ("c0", _sess("c0", "X", 8, "Windows", observed_ip="73.1.1.1", fp_hash="image-fp", trace_hash="human0")),
        ("c1", _sess("c1", "X", 8, "Windows", observed_ip="73.2.2.2", fp_hash="image-fp", trace_hash="human1")),
        ("c2", _sess("c2", "X", 8, "Windows", observed_ip="73.3.3.3", fp_hash="image-fp", trace_hash="human2")),
    ]
    v = score_cluster("X", members)
    assert v.cloned_fingerprint == "image-fp"  # the collision IS detected
    assert v.label != "fleet"  # but it does NOT convict — uncorroborated (clean, residential, distinct traces)
    assert any("UNCORROBORATED" in e for e in v.evidence)


def test_fp_collision_same_ip_is_benign() -> None:
    # Identical fp_hash from ONE source IP is one machine over many sessions — not a fleet. The collision
    # signal requires distinct IPs, so this stays a candidate (homogeneous, single origin).
    members = [
        ("a", _sess("a", "X", 8, "Windows", observed_ip="1.1.1.1", fp_hash="deadbeef")),
        ("b", _sess("b", "X", 8, "Windows", observed_ip="1.1.1.1", fp_hash="deadbeef")),
    ]
    v = score_cluster("X", members)
    assert v.cloned_fingerprint is None
    assert v.label == "candidate"


def test_trace_collision_fleet_is_caught() -> None:
    # The behavioural-clone shape: each instance has a DISTINCT fingerprint (no fp-collision) and homogeneous
    # JS (no paradox), but the SAME canned pointer trace is replayed across DISTINCT IPs — a fleet that
    # randomises its fingerprint yet reuses one recorded "humanised" trajectory. Two real users never trace
    # the same path, so the trace-collision convicts it where the fp-collision and paradox both stay silent.
    members = [
        ("a", _sess("a", "X", 8, "Windows", observed_ip="1.1.1.1", fp_hash="aaaa", trace_hash="cafe")),
        ("b", _sess("b", "X", 8, "Windows", observed_ip="2.2.2.2", fp_hash="bbbb", trace_hash="cafe")),
        ("c", _sess("c", "X", 8, "Windows", observed_ip="3.3.3.3", fp_hash="cccc", trace_hash="cafe")),
    ]
    v = score_cluster("X", members)
    assert v.label == "fleet"
    assert v.cloned_trace == "cafe"
    assert v.cloned_fingerprint is None  # distinct fps — the fp-collision did NOT fire
    assert any("replayed canned trajectory" in e for e in v.evidence)


def test_trace_collision_same_ip_is_benign() -> None:
    # Identical trace from ONE IP is one machine repeating itself — not a fleet (needs distinct IPs).
    members = [
        ("a", _sess("a", "X", 8, "Windows", observed_ip="1.1.1.1", trace_hash="cafe")),
        ("b", _sess("b", "X", 8, "Windows", observed_ip="1.1.1.1", trace_hash="cafe")),
    ]
    v = score_cluster("X", members)
    assert v.cloned_trace is None
    assert v.label == "candidate"


def test_distinct_fingerprints_are_not_a_collision() -> None:
    # Real machines on one browser build each hash differently — distinct fp_hash, no collision tell.
    members = [
        ("a", _sess("a", "X", 8, "Windows", observed_ip="1.1.1.1", fp_hash="aaaa1111")),
        ("b", _sess("b", "X", 8, "Windows", observed_ip="2.2.2.2", fp_hash="bbbb2222")),
    ]
    v = score_cluster("X", members)
    assert v.cloned_fingerprint is None
    assert v.label == "candidate"


def test_larger_fleet_scores_higher() -> None:
    small = score_cluster("X", [("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32))])
    big = score_cluster("X", [(n, _sess(n, "X", hw)) for n, hw in [("a", 8), ("b", 32), ("c", 16), ("d", 4)]])
    assert big.score > small.score


def test_score_corpus_clusters_and_sorts() -> None:
    corpus = [
        # share the cipher prefix `X_a`, JA4_c-divergent per launch + AUTOMATED → convicted fleet (the
        # automation tell corroborates the divergence as per-launch randomization, not a multi-version cohort)
        ("cf1", _sess("cf1", "X_a_1", 8, webdriver=True)),
        ("cf2", _sess("cf2", "X_a_2", 32, webdriver=True)),
        ("solo", _sess("solo", "Y", 4)),  # alone → not graded
        ("noja4", _sess("noja4", None, 4)),  # no JA4 → skipped
    ]
    verdicts = score_corpus(corpus)
    assert len(verdicts) == 1
    assert verdicts[0].members == ["cf1", "cf2"]
    assert verdicts[0].label == "fleet"


def test_timing_lockstep_adds_confidence() -> None:
    # Same JA4 + same JS, but tight vs spread arrival → lockstep raises the score.
    tight = score_cluster("X", [("a", _sess("a", "X", 8, offset_s=0)), ("b", _sess("b", "X", 8, offset_s=30))])
    spread = score_cluster("X", [("a", _sess("a", "X", 8, offset_s=0)), ("b", _sess("b", "X", 8, offset_s=9999))])
    assert tight.score > spread.score
    assert tight.span_seconds == 30.0
    assert any("lockstep" in e for e in tight.evidence)
    assert any("no lockstep" in e for e in spread.evidence)


def test_ja4c_randomization_is_a_fleet() -> None:
    # Shared cipher-suite prefix, homogeneous JS, but DIFFERENT JA4_c (extensions) per launch — the
    # Camoufox TLS-randomization shape. Clusters by prefix and the JA4_c divergence makes it a fleet.
    members = [
        ("a", _sess("a", "t13d_aaaa_1111", 8, "Windows", webdriver=True)),
        ("b", _sess("b", "t13d_aaaa_2222", 8, "Windows", webdriver=True)),
        ("c", _sess("c", "t13d_aaaa_3333", 8, "Windows", webdriver=True)),
    ]
    v = score_corpus([(n, s) for n, s in members])[0]
    assert v.ja4 == "t13d_aaaa"  # keyed on the stable prefix, not the randomized full JA4
    assert v.ja4c_divergent is True
    assert v.diverged_traits == {}  # JS is homogeneous — the catch is purely the TLS randomization
    assert v.label == "fleet"
    assert any("extensions/sig-algs divergent" in e for e in v.evidence)


def test_shared_full_ja4_not_divergent() -> None:
    # Members sharing the *full* JA4 (real same-build cohort) → no JA4_c divergence flag.
    v = score_cluster("p", [("a", _sess("a", "p_q_r", 8, "Windows")), ("b", _sess("b", "p_q_r", 8, "Windows"))])
    assert v.ja4c_divergent is False


def test_residential_proxy_fleet_escalates() -> None:
    # A confirmed spoofing fleet (here JA4_c-divergent, homogeneous JS, spread timing so the base is
    # mid-range — not clamped) spread across distinct source IPs = residential-proxy botnet: the IP
    # diversity masks the shared engine. Should score higher than the same fleet on one IP.
    diverse = [
        ("a", _sess("a", "p_q_1", 8, offset_s=0, observed_ip="11.0.0.1")),
        ("b", _sess("b", "p_q_2", 8, offset_s=9999, observed_ip="22.0.0.2")),
    ]
    same_ip = [
        ("a", _sess("a", "p_q_1", 8, offset_s=0, observed_ip="11.0.0.1")),
        ("b", _sess("b", "p_q_2", 8, offset_s=9999, observed_ip="11.0.0.1")),
    ]
    vd = score_cluster("p_q", diverse)
    vs = score_cluster("p_q", same_ip)
    assert vd.distinct_observed_ips == 2
    assert vd.ja4c_divergent and not vd.diverged_traits  # confirmed fleet via TLS, JS homogeneous
    assert vd.score > vs.score
    assert any("residential-proxy" in e for e in vd.evidence)


def test_same_origin_behind_proxies() -> None:
    # Diverse proxy IPs but one shared WebRTC-leaked real IP → proxies fronting a single origin.
    members = [
        ("a", _sess("a", "X", 8, observed_ip="11.0.0.1", webrtc_ip="203.0.113.9")),
        ("b", _sess("b", "X", 32, observed_ip="22.0.0.2", webrtc_ip="203.0.113.9")),
    ]
    v = score_cluster("X", members)
    assert v.shared_real_ip == "203.0.113.9"
    assert v.label == "fleet"
    assert any("same-origin" in e for e in v.evidence)


def test_distinct_public_ips_do_not_share_origin() -> None:
    # FP guard for the shared_real_ip signal: a real cohort of distinct users each leaks its OWN public
    # WebRTC IP (the collector emits only the srflx/PUBLIC candidate, never a shared private 192.168.x).
    # Distinct WebRTC IPs across distinct observed IPs is the legit shape — shared_real_ip must stay None,
    # so the signal cannot convict a real diverse cohort (it requires a genuinely shared public origin).
    members = [
        ("a", _sess("a", "X", 8, observed_ip="11.0.0.1", webrtc_ip="203.0.113.9", trace_hash="t_a")),
        ("b", _sess("b", "X", 8, observed_ip="22.0.0.2", webrtc_ip="198.51.100.7", trace_hash="t_b")),
    ]
    v = score_cluster("X", members)
    assert v.shared_real_ip is None
    assert v.label != "fleet"  # no shared origin, no other convicting signal → not a fleet


def test_severity_critical_on_burst() -> None:
    # A JA4_c-divergent fleet of 5 arriving within ~4s → high arrival rate → critical severity (separate
    # from the fleet-confidence score, which a 3-node fleet already maxes).
    members = [(f"n{i}", _sess(f"n{i}", f"X_c_{i}", 8 + i * 4, offset_s=i, webdriver=True)) for i in range(5)]
    v = score_cluster("X", members)
    assert v.label == "fleet"
    assert v.arrival_rate_per_min is not None and v.arrival_rate_per_min >= 60
    assert v.severity == "critical"


def test_severity_high_on_volume() -> None:
    # 12-node JA4_c-divergent fleet spread over minutes → low arrival rate, but member count alone is "high".
    members = [(f"n{i}", _sess(f"n{i}", f"X_c_{i}", 8 + i, offset_s=i * 60, webdriver=True)) for i in range(12)]
    v = score_cluster("X", members)
    assert v.label == "fleet"
    assert (v.arrival_rate_per_min or 0) < 15  # not a burst
    assert v.severity == "high"


def test_severity_na_for_candidate() -> None:
    # A homogeneous JA4 cluster is only a candidate — severity is not applicable, and render omits it.
    members = [("a", _sess("a", "X", 8, plat="Windows")), ("b", _sess("b", "X", 8, plat="Windows"))]
    v = score_cluster("X", members)
    assert v.label == "candidate"
    assert v.severity == "n/a"
    md = render_coordination([("a", members[0][1]), ("b", members[1][1])])
    assert "candidate" in md and "severity" not in md  # non-fleet clusters omit the severity line


def test_tracker_alerts_on_becoming_fleet() -> None:
    # First session: no cluster. Second (paradox): cluster becomes a fleet → alert fires once.
    t = FleetTracker()
    assert t.observe("a", _sess("a", "X_a_1", 8, webdriver=True)) is None  # singleton, no alert
    v = t.observe("b", _sess("b", "X_a_2", 32, webdriver=True))  # JA4_c-divergent + automated pair → fleet
    assert v is not None and v.label == "fleet"
    # A third confirming member at the same severity does not re-alert.
    assert t.observe("c", _sess("c", "X_a_3", 16, webdriver=True)) is None


def test_tracker_alerts_on_cloned_profile_fleet() -> None:
    # The streaming analog of the cloned-profile (BotBrowser) case: JS is homogeneous, so the JS-divergence
    # paradox never fires — but an identical fp_hash arriving from a SECOND distinct IP is the collision.
    # The online tracker must alert the moment that second clone arrives, not only in an offline snapshot.
    t = FleetTracker()
    first = _sess("a", "X", 8, "Windows", observed_ip="1.1.1.1", fp_hash="deadbeef", webdriver=True)
    assert t.observe("a", first) is None  # singleton, no alert
    second = _sess("b", "X", 8, "Windows", observed_ip="2.2.2.2", fp_hash="deadbeef", webdriver=True)
    v = t.observe("b", second)
    assert v is not None and v.label == "fleet"
    assert v.cloned_fingerprint == "deadbeef" and v.diverged_traits == {}  # convicted by collision, not paradox


def test_tracker_ignores_no_ja4_and_singletons() -> None:
    t = FleetTracker()
    assert t.observe("x", _sess("x", None, 8)) is None  # no JA4 → ignored
    assert t.observe("y", _sess("y", "Z", 8)) is None  # first of a cluster → no alert


def test_replay_stream_orders_by_arrival_and_alerts() -> None:
    corpus = [
        ("late", _sess("late", "X_a_1", 32, offset_s=50, webdriver=True)),
        ("early", _sess("early", "X_a_2", 8, offset_s=0, webdriver=True)),
    ]
    alerts = replay_stream(corpus)
    assert len(alerts) == 1
    # The alert fires on the *second* arrival in time order ("late"), once the JA4_c divergence is observable.
    assert alerts[0][0] == "late" and alerts[0][1].label == "fleet"
    md = render_stream(corpus)
    assert "alert(s)" in md and "fleet" in md
    assert "no fleet" in render_stream([("solo", _sess("solo", "Q", 4))])


def test_windowed_tracker_alerts_on_burst_within_window() -> None:
    # Two paradox members within a 60s window → fleet alert.
    t = FleetTracker(window_seconds=60)
    assert t.observe("a", _sess("a", "X_a_1", 8, offset_s=0, webdriver=True)) is None
    assert t.observe("b", _sess("b", "X_a_2", 32, offset_s=10, webdriver=True)) is not None  # within window → alert


def test_windowed_tracker_ignores_slow_trickle() -> None:
    # The same two members spread beyond the window never coexist → no fleet.
    t = FleetTracker(window_seconds=60)
    assert t.observe("a", _sess("a", "X", 8, offset_s=0)) is None
    assert t.observe("b", _sess("b", "X", 32, offset_s=600)) is None  # 'a' aged out → singleton again


def test_windowed_tracker_re_alerts_after_burst_ages_out() -> None:
    # A burst alerts, ages out, then a fresh burst re-alerts (state reset on expiry).
    t = FleetTracker(window_seconds=60)
    t.observe("a", _sess("a", "X_a_1", 8, offset_s=0, webdriver=True))
    assert t.observe("b", _sess("b", "X_a_2", 32, offset_s=10, webdriver=True)) is not None  # first burst alerts
    # Far-future fresh burst: old members aged out, then a new JA4_c-divergent pair re-alerts.
    assert t.observe("c", _sess("c", "X_a_3", 8, offset_s=1000, webdriver=True)) is None  # singleton in new window
    assert t.observe("d", _sess("d", "X_a_4", 32, offset_s=1005, webdriver=True)) is not None  # new burst → re-alert


def test_single_member_cluster_has_no_span() -> None:
    # Defensive: score_cluster with one member yields no timing span and no lockstep evidence.
    v = score_cluster("X", [("solo", _sess("solo", "X", 8))])
    assert v.span_seconds is None
    assert not any("lockstep" in e for e in v.evidence)


def test_render_coordination() -> None:
    assert "no JA4 cluster" in render_coordination([("solo", _sess("solo", "Z", 2))])
    md = render_coordination([("a", _sess("a", "X_a_1", 8)), ("b", _sess("b", "X_a_2", 32))])
    assert "fleet" in md and "score" in md and "cf" not in md
