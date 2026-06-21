# harness/calibration — measure rule false-positive rates against real-browser fingerprints.
# Maps a real fingerprint to the signals a genuine browser emits, scores it, and reports per-rule FP.

"""Real-browser calibration.

The evader scoreboard proves rules *catch bots*; this proves they *don't flag humans*. A real but
unusual browser (Linux desktop, VM with no GPU, ad-blocker, no webcam) trips single-layer ``environment``
tells that noisy-or then accumulates into a ``bot`` verdict — a false positive. This module maps a corpus
of *real* browser fingerprints to the browser-layer signals a genuine browser would emit, scores each
through the detector, and reports, per rule, how often it fired on a legitimate browser. Rules above a
false-positive threshold are candidates to demote to corroborating-only / down-weight / prune — the same
discipline the biomech rules got from the Balabit calibration, generalised to the fingerprint layer.

The fingerprint source (e.g. browserforge real-fingerprint distributions) lives in
``browserforge_corpus``; this module is the pure, source-agnostic scorer + reporter.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from kitsune_detector.contracts import load_rule_registry
from kitsune_detector.detector import Detector
from kitsune_detector.models import Label, Layer, Signal, Source

# The browser signal kinds this mapper can derive from a static fingerprint. A rule is "calibrated" only
# if every signal it reads is in here; rules reading runtime-only probes (canvas/CDP/engine/tamper) are
# n/a — they are correctly absent on a real fingerprint and are not the false-positive-prone tells anyway.
DERIVABLE_KINDS = frozenset(
    {
        "webdriver",
        "ua_platform",
        "ua_engine",
        "ua_render",
        "vendor_engine",
        "ch_platform",
        "ch_he_headless",
        "ch_he_version_vs_ua",
        "nav_platform_os",
        "oscpu_os",
        "hardware_concurrency",
        "plugins_count",
        "mimetypes_empty",
        "productsub_render",
        "languages_empty",
        "language_list_incoherent",
        "platform_empty",
        "webgl_os_hint",
        "webgl_software",
        "webgl_renderer_artifact",
        "webgl_not_angle",
        "color_depth_anomaly",
        "devicepixelratio_anomaly",
        "screen_zero",
        "screen_impossible",
        "screen_avail_invalid",
        "macos_dpr1",
        "mobile_no_touch",
        "media_devices_empty",
        "codec_os_incoherent",
        "font_os_hint",
        "font_linux_leak",
        "font_mac_internal",
        "chrome_no_devicememory",
        "chrome_no_pdfviewer",
    }
)

_WIN_FONTS = ("Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma")
_MAC_FONTS = ("Helvetica Neue", "Lucida Grande", "Geneva", "Menlo", "Monaco")
_LINUX_FONTS = ("DejaVu Sans", "Liberation Sans", "Ubuntu", "Cantarell", "Noto Sans")


def _ua_platform(ua: str) -> str:
    if "Windows" in ua:
        return "Windows"
    if re.search(r"Macintosh|Mac OS X", ua):
        return "macOS"
    if "Android" in ua:
        return "Android"
    if "Linux" in ua:
        return "Linux"
    return "unknown"


def _ua_engine(ua: str) -> str:
    if re.search(r"Firefox/", ua):
        return "firefox"
    if re.search(r"Edg/|Chrome/", ua):
        return "chromium"
    if re.search(r"Safari/", ua):
        return "safari"
    return "other"


def _vendor_engine(vendor: str) -> str:
    if re.search(r"Google", vendor, re.I):
        return "chromium"
    if vendor == "":
        return "firefox"
    if re.search(r"Apple", vendor, re.I):
        return "safari"
    return "other"


def _is_ios(ua: str) -> bool:
    """An iOS UA, where navigator.vendor decouples from the UA-derived engine (so vendor_vs_ua abstains).

    Apple forces WebKit for Safari AND every iOS browser, but navigator.vendor follows the BRAND, not the
    engine: real-traffic Chrome-iOS (``CriOS …Safari/604.1`` → ua_engine "safari") reports vendor
    "Google Inc." → vendor_engine "chromium", and iOS in-app WebViews (no Safari token → ua_engine "other")
    report vendor "Apple…" — both legitimate, both tripped br.vendor_vs_ua on the Intoli real-traffic source
    (122/10000) until this gate. iOS UA-spoofs on a Chromium host stay caught structurally by
    apple_ua_nonwebkit (window.chrome/userAgentData on a claimed-WebKit host), so no coverage is lost.
    """
    return bool(re.search(r"iPhone|iPad|iPod", ua))


def _webgl_os(renderer: str) -> str:
    # OS hint ONLY from OS-exclusive GPU stacks (v0.74.4). Direct3D = Windows-only ANGLE backend; Metal/Apple
    # = macOS-only; Mesa/GLX = Linux/X11 stacks Windows/macOS never use. Vulkan/OpenGL/SwiftShader/llvmpipe
    # are CROSS-PLATFORM — a real Windows/macOS browser reports them via a non-default ANGLE backend or
    # software rendering (VM/RDP/GPU-blacklist), so mapping them to Linux false-fired webgl_os_vs_ua.
    if re.search(r"Direct3D|D3D[0-9]", renderer, re.I):
        return "Windows"
    if re.search(r"Metal|Apple", renderer, re.I):
        return "macOS"
    if re.search(r"Mesa|GLX", renderer, re.I):
        return "Linux"
    return ""


def _nav_platform_os(platform: str) -> str:
    if re.search(r"Mac", platform, re.I):
        return "macOS"
    if re.search(r"Win", platform, re.I):
        return "Windows"
    if re.search(r"Linux|X11", platform, re.I):
        return "Linux"
    if re.search(r"Android", platform, re.I):
        return "Android"
    return ""


def _os_family(os_hint: str, ua_plat: str) -> str:
    """Resolve a derived OS hint to the device's true OS FAMILY relative to the UA platform.

    Android's navigator.platform / oscpu / WebGL report the Linux KERNEL ("Linux armv8l", Mesa /
    OpenGL ES) because Android *is* Linux. Under an Android UA that "Linux" is the coherent, genuine
    value — not a spoof — so it resolves to "Android". Without this, the platform-coherence rules
    (navplatform_vs_ua, webgl_os_vs_ua, oscpu_vs_ua) false-fire on every real Android visitor: the
    Intoli real-traffic source measured navplatform_vs_ua firing on 73% of legitimate sessions, all
    Android. The desktop cases (Linux/Windows/macOS impersonating each other) are untouched, so the
    Camoufox / anti-detect counter still fires on a Linux host that claims a Windows UA.
    """
    if ua_plat == "Android" and os_hint == "Linux":
        return "Android"
    return os_hint


def fingerprint_coherence(fp: dict[str, Any]) -> tuple[bool, str]:
    """Is this fingerprint an internally-coherent LEGITIMATE-browser sample?

    browserforge cross-samples ``userAgent`` / ``navigator.platform`` / ``userAgentData`` semi-independently
    from its Bayesian network, so it emits fingerprints no single real device produces: a Windows UA with
    ``navigator.platform`` ``"Linux x86_64"``, a UA Chrome major that disagrees with the UA-CH major, or a
    ``HeadlessChrome`` brand set. These are NOT legitimate-browser samples — the convicting coherence rules
    (``br.navplatform_vs_ua``, ``br.ch_he_version_vs_ua``) and the headless tell (``br.ch_he_headless``) fire
    on them CORRECTLY (a real browser's UA/platform/CH come from one binary and cannot disagree). Counting
    them as false positives over-reports the FP rate and masks genuine FPs, and risks pressure to weaken a
    correct convicting rule to chase a number that is a corpus artifact, not a real-browser misfire. The
    false-positive corpus must therefore contain only coherent real browsers; the caller excludes the
    artifacts and REPORTS the count (never a silent drop).

    Returns ``(coherent, reason)`` — ``reason`` is ``""`` when coherent, else a short tag for the histogram.
    Mirrors the same derivations ``signals_from_fingerprint`` uses, so it excludes exactly the incoherences
    the rules key on (Android's Linux-kernel platform under an Android UA stays coherent via ``_os_family``).
    """
    nav = fp.get("navigator", {})
    uad = fp.get("userAgentData") or {}
    ua = str(nav.get("userAgent", ""))
    brands = (uad.get("fullVersionList") or []) + (uad.get("brands") or [])
    if any(re.search(r"headless", str(b.get("brand", "")), re.I) for b in brands):
        return False, "headless-brand"
    ua_plat = _ua_platform(ua)
    nav_os = _os_family(_nav_platform_os(str(nav.get("platform", ""))), ua_plat)
    if ua_plat in ("Windows", "macOS", "Linux", "Android") and nav_os and nav_os != ua_plat:
        return False, "ua-vs-navplatform-os"
    if _ua_engine(ua) == "chromium":
        fvl = uad.get("fullVersionList") or []
        ch_brand = next((b for b in fvl if re.search(r"chrom", str(b.get("brand", "")), re.I)), None)
        ch_major = str((ch_brand or {}).get("version", uad.get("uaFullVersion", ""))).split(".")[0]
        m = re.search(r"Chrome/(\d+)", ua)
        if ch_major and m and ch_major != m.group(1):
            return False, "ua-vs-ch-version"
    return True, ""


def _font_os(fonts: list[str]) -> str:
    present = set(fonts)
    best, best_n = "", 1  # require >= 2 signature fonts before classifying (mirrors demo.py)
    for os_name, sig in (("Windows", _WIN_FONTS), ("macOS", _MAC_FONTS), ("Linux", _LINUX_FONTS)):
        n = sum(1 for f in sig if f in present)
        if n > best_n:
            best, best_n = os_name, n
    return best


def signals_from_fingerprint(fp: dict[str, Any], session_id: str, now: datetime) -> list[Signal]:
    """Map a real browser fingerprint to the browser-layer signals a genuine browser would emit.

    Mirrors the detector demo collector's emission logic for every signal derivable from a static
    fingerprint; runtime-only probes (canvas/CDP/engine/tamper/permissions) are omitted (correctly
    absent on a real browser). A coherent real fingerprint should therefore produce no contradictions.
    """
    nav = fp.get("navigator", {})
    scr = fp.get("screen", {})
    uad = fp.get("userAgentData") or {}
    video_card = fp.get("videoCard") or {}
    ua = str(nav.get("userAgent", ""))
    out: list[Signal] = []

    def sig(kind: str, value: Any) -> None:
        out.append(
            Signal(
                session_id=session_id,
                layer=Layer.browser,
                kind=kind,
                value=value,
                source=Source.collector,
                observed_at=now,
            )
        )

    plat = _ua_platform(ua)
    engine = _ua_engine(ua)
    is_chromium = engine == "chromium"
    renderer = str(video_card.get("renderer", ""))

    # Always-emitted identity values (the "other side" of the coherence checks).
    sig("webdriver", bool(nav.get("webdriver", False)))
    sig("ua_platform", plat)
    sig("ua_engine", engine)
    sig("ua_render", "gecko" if engine == "firefox" else "webkit")
    # vendor_engine drives br.vendor_vs_ua. Abstain (don't emit it) in three cases — "unknown never fires":
    # (1) iOS, where vendor follows the browser BRAND while the engine is always WebKit, so the axes decouple
    # legitimately (see _is_ios); (2) an UNCLASSIFIABLE UA engine ("other"); (3) the source did NOT provide a
    # vendor (None) — a real browser ALWAYS has navigator.vendor (a string; "" on Firefox), so an ABSENT vendor
    # means the SOURCE omitted it (fpgen nulls vendor), NOT that the browser has an empty one. The empty STRING
    # "" is Firefox's real value (→ vendor_engine "firefox", coherent) and IS emitted; `None` abstains. Each
    # source represents vendor faithfully (browserforge maps Firefox's empty vendor to "" in _fingerprint_to_dict;
    # fpgen leaves the key out). Conflating None with "" mapped absent-vendor Chrome fps to "firefox" → a false
    # br.vendor_vs_ua on 88% of fpgen fps; abstaining on None fixes it for every source.
    vendor = nav.get("vendor")
    if vendor is not None and not _is_ios(ua) and engine != "other":
        sig("vendor_engine", _vendor_engine(str(vendor)))
    sig("hardware_concurrency", int(nav.get("hardwareConcurrency", 0) or 0))
    # Desktop-only tells (mirror the collector): a real desktop browser ships a standardized 5 plugins / 2
    # mimeTypes / pdfViewerEnabled=true, so a zero there is a stripped-browser signature — but every real
    # MOBILE browser legitimately reports 0 plugins / 0 mimeTypes / no PDF viewer (browserforge: 98% of
    # Android). Gate emission to non-mobile so no_plugins/mimetypes_empty/chrome_no_pdfviewer fire only where
    # zero is genuinely anomalous, not on every real Android/iOS user.
    is_mobile = bool(re.search(r"Mobile|Android|iPhone|iPad", ua))
    plugins = (fp.get("pluginsData") or {}).get("plugins", []) or []
    if not is_mobile:
        sig("plugins_count", len(plugins))
    # Spatial UA<->capability coherence (br.mobile_no_touch): a phone/tablet UA is a touchscreen device, so
    # maxTouchPoints == 0 under a Mobile/iPhone/iPad token is a desktop wearing a mobile UA (mirrors demo.py;
    # scoped off bare "Android" to exclude touch-less Android TV). Faithful — browserforge carries maxTouchPoints.
    if re.search(r"iPhone|iPad|iPod|Mobile", ua) and int(nav.get("maxTouchPoints", 0) or 0) == 0:
        sig("mobile_no_touch", True)

    # UA Client Hints (navigator.userAgentData) exist ONLY on Chromium — Firefox/Safari/iOS report it
    # undefined, so the collector emits no ch_* for them. Gate the UA-CH-derived signals on the engine so a
    # source that erroneously attaches a userAgentData to a non-Chromium UA (a generation artifact) cannot make
    # the mapper invent ch_* and falsely trip br.ua_platform_vs_ch_platform / br.ch_he_* (a fidelity bug a real
    # non-Chromium browser never produces). Matches demo.py, which reads userAgentData only where it exists.
    if is_chromium and uad.get("platform"):
        sig("ch_platform", "macOS" if uad["platform"] == "macOS" else uad["platform"])
    nav_os = _os_family(_nav_platform_os(str(nav.get("platform", ""))), plat)
    if nav_os:
        sig("nav_platform_os", nav_os)
    oscpu = str(nav.get("oscpu") or "")
    if oscpu:
        oc = _os_family(_nav_platform_os(oscpu) or _webgl_os(oscpu), plat)
        if oc:
            sig("oscpu_os", oc)
    ps = {"20030107": "webkit", "20100101": "gecko"}.get(str(nav.get("productSub", "")), "")
    if ps:
        sig("productsub_render", ps)
    wo = _os_family(_webgl_os(renderer), plat)
    if wo:
        sig("webgl_os_hint", wo)
    fo = _font_os(fp.get("fonts") or [])
    if fo:
        sig("font_os_hint", fo)

    # Conditional "tell" signals — emitted only when the bot-like condition holds (so they fire on a
    # legitimate-but-unusual fingerprint exactly when the rule would false-positive on the real machine).
    if re.search(r"Headless", ua, re.I):
        pass  # ua_is_headless: not a browser-only derivable in DERIVABLE_KINDS scope
    fvl = uad.get("fullVersionList") or []
    brands = fvl + (uad.get("brands") or [])
    # UA-CH-derived (see the ch_platform note above): Chromium-only — a non-Chromium UA has no userAgentData.
    if is_chromium and any(re.search(r"headless", str(b.get("brand", "")), re.I) for b in brands):
        sig("ch_he_headless", True)
    ch_brand = next((b for b in fvl if re.search(r"chrom", str(b.get("brand", "")), re.I)), None)
    ch_major = str((ch_brand or {}).get("version", uad.get("uaFullVersion", ""))).split(".")[0]
    ua_major_m = re.search(r"Chrome/(\d+)", ua)
    if is_chromium and ch_major and ua_major_m and ch_major != ua_major_m.group(1):
        sig("ch_he_version_vs_ua", True)

    if renderer:
        sig("webgl_renderer", renderer)  # raw value — feeds the prevalence model (gpu family)
    if re.search(r"swiftshader|llvmpipe|software|mesa", renderer, re.I):
        sig("webgl_software", True)
    if re.search(r",\s*or similar|generic renderer|placeholder", renderer, re.I):
        sig("webgl_renderer_artifact", True)
    if is_chromium and renderer and not renderer.startswith("ANGLE ("):
        sig("webgl_not_angle", True)

    langs = nav.get("languages") or []
    if len(langs) == 0:
        sig("languages_empty", True)
    # Spec invariant: navigator.language IS navigator.languages[0] (HTML standard) — a real browser never
    # disagrees, so this never fires on a coherent fingerprint; a sloppy JS locale spoof makes them differ.
    lang = str(nav.get("language", "") or "")
    if lang and langs and lang != str(langs[0]):
        sig("language_list_incoherent", True)
    if nav.get("platform", "") == "":
        sig("platform_empty", True)
    mimetypes = (fp.get("pluginsData") or {}).get("mimeTypes", []) or []
    if len(mimetypes) == 0 and not is_mobile:
        sig("mimetypes_empty", True)

    width, height = int(scr.get("width", 0) or 0), int(scr.get("height", 0) or 0)
    avail_w, avail_h = int(scr.get("availWidth", 0) or 0), int(scr.get("availHeight", 0) or 0)
    dpr = scr.get("devicePixelRatio", 0) or 0
    color = int(scr.get("colorDepth", 0) or 0)
    if width and height:
        sig("screen_resolution", f"{width}x{height}")  # raw values — feed the prevalence model
    if color:
        sig("color_depth", color)
    if not width or not height or not scr.get("outerWidth") or not scr.get("outerHeight"):
        sig("screen_zero", True)
    if avail_w > width or avail_h > height:
        sig("screen_impossible", True)
        sig("screen_avail_invalid", True)
    if color and color not in (24, 30, 32):
        sig("color_depth_anomaly", True)
    if not dpr > 0:
        sig("devicepixelratio_anomaly", True)
    if plat == "macOS" and dpr == 1:
        sig("macos_dpr1", True)

    devices = fp.get("multimediaDevices") or {}
    total_devices = sum(len(devices.get(k, []) or []) for k in ("speakers", "micros", "webcams"))
    if isinstance(devices, dict) and total_devices == 0:
        sig("media_devices_empty", True)

    h264 = (fp.get("videoCodecs") or {}).get("h264", "")
    aac = (fp.get("audioCodecs") or {}).get("aac", "")
    if plat not in ("", "Linux", "unknown") and h264 == "" and aac == "":
        sig("codec_os_incoherent", True)

    fonts = fp.get("fonts") or []
    if plat not in ("", "Linux", "unknown") and any(f in fonts for f in ("Arimo", "Cousine", "Tinos")):
        sig("font_linux_leak", True)
    if any(f in fonts for f in (".Aqua Kana", ".Apple Color Emoji UI")):
        sig("font_mac_internal", True)

    if is_chromium and nav.get("deviceMemory") is None:
        sig("chrome_no_devicememory", True)
    if is_chromium and not is_mobile and not any("pdf" in str(p.get("name", "")).lower() for p in plugins):
        sig("chrome_no_pdfviewer", True)

    return out


@dataclass
class RuleStat:
    rule_id: str
    category: str
    weight: float
    calibrated: bool
    fired: int = 0
    total: int = 0

    @property
    def fp_rate(self) -> float:
        return self.fired / self.total if self.total else 0.0


@dataclass
class CalibrationReport:
    n_profiles: int
    label_counts: dict[str, int]
    rule_stats: list[RuleStat]
    hard_fps: list[tuple[str, str, list[str]]] = field(default_factory=list)  # (profile, label, fired rules)


def calibrate(detector: Detector, profiles: list[tuple[str, list[Signal]]]) -> CalibrationReport:
    """Score each legitimate profile and aggregate per-rule false-positive rates."""
    _, rules = load_rule_registry()
    derivable_refs = {f"browser.{k}" for k in DERIVABLE_KINDS}
    stats: dict[str, RuleStat] = {}
    for r in rules:
        if r.get("status") == "retired" or not set(r["layers"]) <= {"browser"}:
            continue
        calibrated = bool(r.get("reads")) and all(ref in derivable_refs for ref in r["reads"])
        stats[r["id"]] = RuleStat(r["id"], r["category"], r["weight"], calibrated)

    label_counts: dict[str, int] = defaultdict(int)
    hard_fps: list[tuple[str, str, list[str]]] = []
    for name, signals in profiles:
        verdict = detector.ingest_and_score(signals)[0]
        label_counts[verdict.label.value] += 1
        fired = [c.rule_id for c in verdict.contradictions]
        for st in stats.values():
            if st.calibrated:
                st.total += 1
                if st.rule_id in fired:
                    st.fired += 1
        if verdict.label != Label.human:
            hard_fps.append((name, verdict.label.value, fired))

    ordered = sorted(stats.values(), key=lambda s: (-s.fp_rate, -s.weight, s.rule_id))
    return CalibrationReport(len(profiles), dict(label_counts), ordered, hard_fps)


def render_report(report: CalibrationReport, *, fp_threshold: float = 0.02) -> str:
    """Render the calibration report: verdict distribution, per-rule FP, and re-tier candidates."""
    lines = [
        f"# Kitsune calibration — {report.n_profiles} real-browser fingerprints",
        "",
        "Legitimate browsers should score **human**. Any `suspicious`/`bot` is a false positive.",
        "",
        "## Verdict distribution",
    ]
    for label in ("human", "suspicious", "bot"):
        n = report.label_counts.get(label, 0)
        lines.append(f"- **{label}**: {n} ({n / report.n_profiles:.0%})" if report.n_profiles else f"- {label}: 0")

    offenders = [s for s in report.rule_stats if s.calibrated and s.fp_rate > fp_threshold]
    lines += ["", f"## Re-tier candidates (FP > {fp_threshold:.0%})"]
    if offenders:
        lines.append("| rule | category | weight | FP rate | fired/total |")
        lines.append("|---|---|---|---|---|")
        for s in offenders:
            lines.append(
                f"| `{s.rule_id}` | {s.category} | {s.weight:.2f} | **{s.fp_rate:.1%}** | {s.fired}/{s.total} |"
            )
    else:
        lines.append("_None — no calibrated rule fired above threshold on the legitimate corpus._")

    n_cal = sum(1 for s in report.rule_stats if s.calibrated)
    lines += ["", "## Coverage", f"- calibrated browser rules: **{n_cal}** of {len(report.rule_stats)}"]
    lines.append(f"- not calibrated (runtime-only / data absent): {len(report.rule_stats) - n_cal}")

    if report.hard_fps:
        lines += ["", "## Hard false positives (legit browser scored non-human)"]
        for name, label, fired in report.hard_fps[:25]:
            lines.append(f"- `{name}` → **{label}**: {', '.join(f'`{r}`' for r in fired)}")
    return "\n".join(lines) + "\n"
