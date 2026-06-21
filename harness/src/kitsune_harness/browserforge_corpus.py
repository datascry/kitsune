# harness/browserforge_corpus — Tier-1 calibration corpus from real browserforge fingerprints.
# Generates real-browser fingerprint distributions and scores them for false positives. CLI: see __main__.

"""browserforge real-fingerprint corpus (Tier-1 calibration data).

browserforge samples from a Bayesian network of *real* browser fingerprints (the same data anti-detect
tools use to look real), so its output is a stand-in for legitimate-browser distributions across
OS/engine — exactly what we need to measure rule false-positive rates without a live device farm. This
module is the thin generator glue (lazy ``browserforge`` import, excluded from coverage); the scoring +
report logic lives in ``calibration``.

    uv run --with browserforge python -m kitsune_harness.browserforge_corpus --n 400
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from typing import Any

from kitsune_detector.detector import Detector

from .calibration import calibrate, fingerprint_coherence, render_report, signals_from_fingerprint


def _fingerprint_to_dict(fp: Any) -> dict[str, Any]:
    """Flatten a browserforge Fingerprint into the nested dict shape the signal mapper reads."""
    nav, scr = fp.navigator, fp.screen
    vc = fp.videoCard
    return {
        "navigator": {
            "userAgent": nav.userAgent,
            "platform": nav.platform,
            "languages": list(nav.languages or []),
            # navigator.language IS navigator.languages[0] on every real browser (HTML standard). browserforge
            # carries only the list, so derive the singular faithfully — without it the mapper's
            # language_list_incoherent coherence check has no left-hand value and silently never runs.
            "language": getattr(nav, "language", None) or (next(iter(nav.languages)) if nav.languages else None),
            "hardwareConcurrency": nav.hardwareConcurrency,
            "deviceMemory": getattr(nav, "deviceMemory", None),
            # browserforge represents Firefox's real navigator.vendor === "" as None; normalise it to the
            # empty STRING here so the mapper sees Firefox's true value (→ vendor_engine "firefox", coherent)
            # rather than an ABSENT vendor (which the mapper abstains on). Chrome/Safari fps carry a real brand.
            "vendor": getattr(nav, "vendor", "") or "",
            "productSub": getattr(nav, "productSub", ""),
            "oscpu": getattr(nav, "oscpu", None),
            "maxTouchPoints": getattr(nav, "maxTouchPoints", 0),
            "webdriver": getattr(nav, "webdriver", False),
        },
        "userAgentData": getattr(nav, "userAgentData", None),
        "screen": {
            "width": scr.width,
            "height": scr.height,
            "availWidth": scr.availWidth,
            "availHeight": scr.availHeight,
            "colorDepth": scr.colorDepth,
            "devicePixelRatio": scr.devicePixelRatio,
            "outerWidth": scr.outerWidth,
            "outerHeight": scr.outerHeight,
        },
        "videoCard": {"renderer": getattr(vc, "renderer", ""), "vendor": getattr(vc, "vendor", "")} if vc else {},
        "audioCodecs": fp.audioCodecs or {},
        "videoCodecs": fp.videoCodecs or {},
        "multimediaDevices": fp.multimediaDevices or {},
        "fonts": list(fp.fonts or []),
        "pluginsData": fp.pluginsData or {},
    }


def generate_profiles(n: int, now: datetime) -> list[tuple[str, list[Any]]]:  # pragma: no cover - external data
    """Generate n real-browser profiles as (label, signals) via browserforge."""
    from browserforge.fingerprints import FingerprintGenerator

    fg = FingerprintGenerator()
    profiles: list[tuple[str, list[Any]]] = []
    dropped: dict[str, int] = {}
    attempts = 0
    # browserforge cross-samples fields, so a fraction of its output is internally incoherent (a Windows UA
    # with a Linux navigator.platform, a UA/CH version skew, a HeadlessChrome brand set) — NOT legit-browser
    # samples. Those are flagged CORRECTLY by the convicting rules, so keeping them would over-report the FP
    # rate; exclude them (and report the count, never a silent drop). Oversample to still reach n coherent.
    while len(profiles) < n and attempts < n * 6:
        attempts += 1
        fp = _fingerprint_to_dict(fg.generate())
        coherent, reason = fingerprint_coherence(fp)
        if not coherent:
            dropped[reason] = dropped.get(reason, 0) + 1
            continue
        sid = f"bf-{len(profiles):04d}"
        profiles.append((sid, signals_from_fingerprint(fp, sid, now)))
    if dropped:
        total = sum(dropped.values())
        hist = ", ".join(f"{k}={v}" for k, v in sorted(dropped.items()))
        print(
            f"NOTE: excluded {total} internally-incoherent browserforge fingerprints from the legit corpus "
            f"({hist}) — not real-browser samples (the convicting rules flag them correctly). FP rate below "
            f"is measured over {len(profiles)} coherent fingerprints.",
            file=sys.stderr,
        )
    return profiles


def profiles_from_dir(path: str, now: datetime) -> list[tuple[str, list[Any]]]:  # pragma: no cover - IO
    """Load real-captured fingerprint JSONs from a directory as calibration profiles (Tier-2/Tier-3).

    A second, independent data source to corroborate the browserforge (Tier-1) findings — never act on a
    single-source false-positive number. Each *.json is one captured browser fingerprint (the shape
    ``signals_from_fingerprint`` reads); e.g. corpus/calibration/engines/ holds real Chromium/Firefox/WebKit.
    """
    import json
    from pathlib import Path

    out: list[tuple[str, list[Any]]] = []
    for p in sorted(Path(path).glob("*.json")):
        fp = json.loads(p.read_text())
        out.append((p.stem, signals_from_fingerprint(fp, p.stem, now)))
    return out


def write_prior(feats: list[Any], out_path: str, source: str, *, threshold_feats: list[Any] | None = None) -> float:
    """Build the prevalence prior (joint-frequency tables) from features and write it to JSON. Returns the
    p1 threshold. Shared by the browserforge (Tier-1) and real-capture (Tier-3) builders.

    The threshold is the 1st-percentile log-prevalence below which ``br.fingerprint_improbable`` fires. By
    default it is the SELF-p1 (the 1% tail of the prior's own training set) — but that over-flags an
    INDEPENDENT dataset (an fpgen second source falls below the browserforge self-p1 at ~4-6%, not 1%; the
    threshold is over-fit to browserforge's narrower distribution — see docs/prevalence-model.md). When
    ``threshold_feats`` (an independent calibration set) is given, the threshold is the CONSERVATIVE bound —
    the deeper of the self-p1 and the independent set's p1 — so it flags <=1% of BOTH distributions, per the
    standing constraint's "corroborate the single-source number / never raise the legit-browser flag rate".
    """
    import json

    from .prevalence import build_prior, log_prevalence

    prior = build_prior(feats)

    def _p1(fs: list[Any]) -> float:
        scores = sorted(log_prevalence(f, prior) for f in fs)
        return scores[len(scores) // 100]

    threshold = _p1(feats)
    calibration = "self-p1"
    if threshold_feats:
        threshold = min(threshold, _p1(threshold_feats))  # conservative: flag <=1% of both → strictly FP-safer
        calibration = "cross-source-conservative"
    with open(out_path, "w") as fh:
        json.dump(
            {
                "n": len(feats),
                "source": source,
                "threshold": threshold,
                "threshold_calibration": calibration,
                "prior": prior,
            },
            fh,
        )
    return threshold


def build_prior_file(n: int, out_path: str) -> None:  # pragma: no cover - external data
    """Sample n browserforge fingerprints and write the prevalence prior (joint-frequency tables) to JSON.

    Calibrates the threshold against an INDEPENDENT second source (fpgen, if installed) so it is not
    browserforge-self-referential — which over-flags independent data ~4-6x (docs/prevalence-model.md). Falls
    back to the self-p1 if fpgen is unavailable.
    """
    from browserforge.fingerprints import FingerprintGenerator

    from .prevalence import features_from_fingerprint

    fg = FingerprintGenerator()
    feats = [features_from_fingerprint(_fingerprint_to_dict(fg.generate())) for _ in range(n)]
    threshold_feats = None
    try:
        import fpgen

        from .fpgen_coherence import fingerprint_from_fpgen

        threshold_feats = [features_from_fingerprint(fingerprint_from_fpgen(fpgen.generate())) for _ in range(n // 2)]
    except Exception:  # fpgen optional — fall back to the (less FP-safe) self-p1 with a warning in the output
        print("WARNING: fpgen unavailable — threshold falls back to browserforge self-p1 (over-flags independent data)")
    threshold = write_prior(feats, out_path, "browserforge", threshold_feats=threshold_feats)
    print(f"wrote prevalence prior from {n} browserforge fingerprints (threshold {threshold:.2f}) -> {out_path}")


def build_prior_from_dir(dir_path: str, out_path: str, source: str = "real-capture") -> int:
    """Build the prevalence prior from a DIRECTORY of real-captured fingerprint JSONs — the turnkey SECOND
    source the standing constraint calls for.

    The shipped prior is browserforge-only, which is *same-source-blind*: a generator-based attacker samples
    from the same distribution, so its fingerprints are probable in our prior by construction (see
    docs/evasion-catalog.md "Prevalence / likelihood model"). Drop real-traffic fingerprint captures — the
    shape ``signals_from_fingerprint`` reads, e.g. a hosted-demo opt-in or a real-device matrix — into a
    directory and run this to rebuild the prior from REAL ground truth. The detector then scores improbability
    against real traffic and gains *detection power* against generator-sampled fingerprints that are probable
    in browserforge yet improbable in reality. Returns the number of fingerprints used.
    """
    import json
    from pathlib import Path

    from .prevalence import features_from_fingerprint

    paths = sorted(Path(dir_path).glob("*.json"))
    if not paths:
        raise SystemExit(f"no *.json fingerprints in {dir_path}")
    feats = [features_from_fingerprint(json.loads(p.read_text())) for p in paths]
    threshold = write_prior(feats, out_path, source)
    print(f"wrote prior from {len(feats)} {source} fingerprints (p1 threshold {threshold:.2f}) -> {out_path}")
    return len(feats)


def build_prior_from_sessions(dir_path: str, out_path: str, source: str = "real-traffic") -> int:
    """Build the prevalence prior from a directory of SESSION JSONs — the shape the collector+edge actually
    produce (what a hosted-demo opt-in or live real-traffic capture yields, e.g. ``corpus/sessions/*.json``).

    Complements :func:`build_prior_from_dir` (which reads raw browserforge-shape fingerprint dicts): real
    captures arrive as sessions of layered signals, not fingerprint dicts. This uses the DETECTOR's own
    ``features_from_session`` — the exact extraction the scorer runs on live sessions — so the prior's features
    match what the detector computes at scoring time. The turnkey real-traffic path for the prevalence second
    source (see docs/prevalence-model.md). Returns the number of sessions used.
    """
    from kitsune_detector.prevalence import features_from_session

    from .corpus import load_corpus

    corpus = load_corpus(dir_path)
    if not corpus:
        raise SystemExit(f"no session JSONs in {dir_path}")
    feats = [features_from_session(session) for _name, session in corpus]
    threshold = write_prior(feats, out_path, source)
    print(f"wrote prior from {len(feats)} {source} sessions (p1 threshold {threshold:.2f}) -> {out_path}")
    return len(feats)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    argv = sys.argv[1:] if argv is None else argv
    now = datetime.now(UTC)
    default_out = "../detector/src/kitsune_detector/data/prevalence_prior.json"
    if "--build-prior-from-sessions" in argv:
        # Turnkey Tier-3: rebuild the prevalence prior from real-traffic SESSION captures (collector shape).
        src = argv[argv.index("--build-prior-from-sessions") + 1]
        out = argv[argv.index("--out") + 1] if "--out" in argv else default_out
        build_prior_from_sessions(src, out)
        return
    if "--build-prior-from-dir" in argv:
        # Turnkey Tier-3: rebuild the prevalence prior from a directory of REAL-captured fingerprint dicts.
        src = argv[argv.index("--build-prior-from-dir") + 1]
        out = argv[argv.index("--out") + 1] if "--out" in argv else default_out
        build_prior_from_dir(src, out)
        return
    if "--build-prior" in argv:
        n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 5000
        build_prior_file(n, argv[argv.index("--build-prior") + 1])
        return
    detector = Detector()
    if "--from-dir" in argv:
        report = calibrate(detector, profiles_from_dir(argv[argv.index("--from-dir") + 1], now))
    else:
        n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 400
        report = calibrate(detector, generate_profiles(n, now))
    print(render_report(report, fp_threshold=0.0), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
