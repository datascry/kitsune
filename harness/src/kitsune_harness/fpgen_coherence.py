# harness/fpgen_coherence — second-source FP-check for the UA-coherence rules fpgen can faithfully exercise.
# browserforge is single-source for font/webgl/platform/productSub coherence; fpgen (Scrapfly data) corroborates.

"""Second-source coherence FP-check (the standing constraint's "corroborate the single-source number").

A handful of convicting COHERENCE rules are FP-checked against **browserforge alone** — Intoli cannot reach
them (it carries no fonts / WebGL renderer / reliable platform). **fpgen** (Scrapfly's ``fingerprint-generator``)
is the only available second data source with those fields, so it corroborates whether these rules false-fire
on an independently-generated population:

* ``br.font_os_vs_ua``      (installed-font OS signature vs UA platform)
* ``br.webgl_os_vs_ua``     (WebGL renderer OS hint vs UA platform)
* ``br.navplatform_vs_ua``  (navigator.platform OS vs UA platform)
* ``br.productsub_vs_ua``   (navigator.productSub engine vs UA render)

Only these four are scope-faithful: their operands all derive from fpgen fields we can map cleanly (UA,
platform, screen, productSub, WebGL renderer, ``allFonts``). fpgen does NOT faithfully populate
``navigator.vendor`` (null) or ``oscpu`` ("undefined"), so ``vendor_vs_ua`` / ``oscpu_vs_ua`` are deliberately
NOT tested here (mapping them would fabricate artifacts — see docs/calibration.md "fpgen calibration-scope").
A firing on the four is interpreted as fpgen GENERATION incoherence the rule correctly catches (e.g. a Windows
UA generated with macOS fonts), not a real-browser FP — fpgen is a generator, so like browserforge its
incoherent joints trip coherence rules. A SPIKE above the generator's incoherence floor would flag a real FP.

On-demand (fpgen fetches its model over the network, so not a CI gate):
``uv run --with fpgen python -m kitsune_harness.fpgen_coherence --n 400``.
"""

from __future__ import annotations

import argparse
import collections
import re
from datetime import UTC, datetime
from typing import Any

from kitsune_detector.config import SCHEMA_VERSION
from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Signal, Source

from .calibration import signals_from_fingerprint

#: The convicting coherence rules whose operands map faithfully from fpgen fields (others are out of scope).
COHERENCE_RULES = (
    "br.font_os_vs_ua",
    "br.webgl_os_vs_ua",
    "br.navplatform_vs_ua",
    "br.productsub_vs_ua",
    # voice_os_hint + webgpu_vendor_mismatch are runtime-derived (signals_from_fingerprint doesn't emit them),
    # so fpgen_coherence replicates the collector's exact derivation below to reach these two least-calibrated
    # convicting rules (their only prior FP grounding was unit tests + 3 headful captures).
    "br.voice_os_vs_ua",
    "br.webgpu_vendor_vs_webgl",
)
_NOW = datetime(2026, 6, 19, tzinfo=UTC)


def _gpu_family(s: str) -> str:
    """GPU vendor family from a renderer/vendor string — mirrors demo.py ``gpuFam`` exactly."""
    s = s.lower()
    if re.search(r"nvidia|geforce|rtx|gtx", s):
        return "nvidia"
    if re.search(r"intel|hd graphics|\biris\b|uhd", s):
        return "intel"
    if re.search(r"\bamd\b|radeon|\bati\b", s):
        return "amd"
    if re.search(r"apple|\bm1\b|\bm2\b|\bm3\b", s):
        return "apple"
    if re.search(r"adreno|\bmali\b|powervr", s):
        return "mobile"
    return ""


def _voice_os(voices: list[dict[str, Any]]) -> str:
    """OS implied by the installed TTS voice names — mirrors demo.py's voice_os_hint regex exactly."""
    names = " ".join(f"{v.get('name', '')} {v.get('voiceURI', '')}" for v in voices)
    if re.search(r"Microsoft|Windows|David|Zira|Hazel", names, re.I):
        return "Windows"
    if re.search(r"Apple|Siri|Alex|Samantha|Victoria|macOS", names, re.I):
        return "macOS"
    if re.search(r"espeak|eSpeak|Linux", names, re.I):
        return "Linux"
    return ""


def _sig(kind: str, value: Any, session_id: str) -> Signal:
    return Signal(
        schema_version=SCHEMA_VERSION,
        session_id=session_id,
        layer=Layer.browser,
        kind=kind,
        value=value,
        source=Source.collector,
        observed_at=_NOW,
    )


def extra_coherence_signals(fp: dict[str, Any], session_id: str = "fpgen") -> list[Signal]:
    """Runtime-derived browser signals signals_from_fingerprint omits: voice_os_hint + webgpu_vendor_mismatch.

    Derived from fpgen's ``voices`` and ``gpuInfo`` with the COLLECTOR's exact logic, so the two extra rules
    are exercised faithfully (a divergence here would be the collector's derivation, validated by the tests).
    The session_id MUST match the rest of the session's signals or group_signals splits them apart.
    """
    out: list[Signal] = []
    voices = fp.get("voices") or []
    if voices:
        vos = _voice_os(voices)
        if vos:
            out.append(_sig("voice_os_hint", vos, session_id))
    # webgpu_vendor_mismatch: WebGL renderer GPU family must match the WebGPU adapter's vendor family.
    renderer = str(fp.get("gpu", {}).get("renderer", ""))
    adapter = fp.get("gpuInfo", {}).get("adapterInfo") or {}
    fam_gl = _gpu_family(renderer)
    fam_gpu = _gpu_family(f"{adapter.get('vendor', '')} {adapter.get('architecture', '')}")
    if fam_gl and fam_gpu and fam_gl != fam_gpu:
        out.append(_sig("webgpu_vendor_mismatch", True, session_id))
    return out


def fingerprint_from_fpgen(fp: dict[str, Any]) -> dict[str, Any]:
    """Map an fpgen fingerprint to the (faithful-fields-only) shape ``signals_from_fingerprint`` reads.

    Maps only fields fpgen populates like a real browser — UA / platform / screen / hardwareConcurrency /
    productSub / WebGL renderer / installed fonts. ``navigator.vendor`` and ``oscpu`` are intentionally left
    out (fpgen nulls them), so the out-of-scope vendor/oscpu rules abstain rather than fabricate a firing.
    """
    nav = fp.get("navigator", {})
    return {
        "navigator": {
            "userAgent": nav.get("userAgent"),
            "platform": nav.get("platform"),
            "hardwareConcurrency": nav.get("hardwareConcurrency"),
            "productSub": nav.get("productSub"),
            "languages": nav.get("languages"),
        },
        "screen": fp.get("screen", {}),
        "videoCard": {"renderer": fp.get("gpu", {}).get("renderer", "")},
        "fonts": fp.get("allFonts") or [],
    }


def coherence_firings(fingerprints: list[dict[str, Any]], detector: Detector | None = None) -> collections.Counter[str]:
    """Score each fpgen-derived fingerprint and count, per in-scope coherence rule, how many fire."""
    det = detector or Detector()
    fired: collections.Counter[str] = collections.Counter()
    for i, fp in enumerate(fingerprints):
        signals = signals_from_fingerprint(fingerprint_from_fpgen(fp), f"f{i}", _NOW)
        signals += extra_coherence_signals(fp, f"f{i}")  # voice_os_hint + webgpu_vendor_mismatch (same session)
        verdict = det.score(group_signals(signals)[0])
        for c in verdict.contradictions:
            if c.rule_id in COHERENCE_RULES:
                fired[c.rule_id] += 1
    return fired


def render(fired: collections.Counter[str], n: int) -> str:
    out = ["# fpgen second-source coherence FP-check", ""]
    out.append(f"scored {n} fpgen fingerprints. Firings = fpgen generation incoherence the rule catches")
    out.append("(NOT real-browser FPs); a spike above the generator floor would flag a true FP.")
    out.append("")
    out.append("| rule | fired | rate |")
    out.append("|---|---|---|")
    for r in COHERENCE_RULES:
        rate = f"{100 * fired[r] / n:.1f}%" if n else "—"
        out.append(f"| `{r}` | {fired[r]}/{n} | {rate} |")
    return "\n".join(out)


def _sample_fpgen(n: int) -> list[dict[str, Any]]:  # pragma: no cover - external data/network
    import fpgen

    combos = [("Chrome", "Windows"), ("Firefox", "Windows"), ("Chrome", "Linux")]
    out: list[dict[str, Any]] = []
    for i in range(n):
        br, os_ = combos[i % len(combos)]
        try:
            out.append(fpgen.generate(browser=br, os=os_))
        except Exception:  # a generator hiccup on one draw must not abort the whole run
            continue
    return out


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI over external data
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=400, help="number of fpgen fingerprints to sample")
    args = ap.parse_args(argv)
    fps = _sample_fpgen(args.n)
    print(render(coherence_firings(fps), len(fps)))


if __name__ == "__main__":  # pragma: no cover
    main()
