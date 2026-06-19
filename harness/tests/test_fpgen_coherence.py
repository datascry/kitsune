# tests/test_fpgen_coherence — the fpgen second-source coherence FP-check logic (no fpgen/network).
# Guards the fpgen->fingerprint mapping + that an in-scope rule fires on incoherence, stays quiet on coherence.

from __future__ import annotations

import collections

from kitsune_harness.fpgen_coherence import (
    COHERENCE_RULES,
    _gpu_family,
    _voice_os,
    coherence_firings,
    extra_coherence_signals,
    fingerprint_from_fpgen,
    render,
)

_WIN_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
_WIN_FONTS = ["Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma", "Arial"]
_MAC_FONTS = ["Helvetica Neue", "Lucida Grande", "Geneva", "Menlo", "Monaco", "Al Bayan"]


_WIN_VOICES = [{"name": "Microsoft David - English (United States)", "voiceURI": "Microsoft David"}]
_MAC_VOICES = [{"name": "Samantha", "voiceURI": "com.apple.speech.synthesis.voice.samantha"}]


def _fpgen(
    fonts: list[str],
    voices: list[dict[str, str]] | None = None,
    renderer: str = "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
    adapter_vendor: str = "intel",
) -> dict[str, object]:
    # a minimal fpgen-shaped fingerprint: a Windows Chrome with the given fonts / voices / GPU
    return {
        "navigator": {"userAgent": _WIN_UA, "platform": "Win32", "hardwareConcurrency": 8, "productSub": "20030107"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "gpu": {"renderer": renderer},
        "gpuInfo": {"adapterInfo": {"vendor": adapter_vendor, "architecture": "gen-9"}},
        "allFonts": fonts,
        "voices": voices or _WIN_VOICES,
    }


def test_voice_os_and_gpu_family_derivations() -> None:
    # the collector-mirrored helpers must classify correctly (the fidelity guard for the replicated logic)
    assert _voice_os(_WIN_VOICES) == "Windows"
    assert _voice_os(_MAC_VOICES) == "macOS"
    assert _voice_os([{"name": "espeak-ng english", "voiceURI": "x"}]) == "Linux"
    assert _voice_os([{"name": "Google Deutsch", "voiceURI": "x"}]) == ""  # no OS keyword → no hint
    assert _gpu_family("ANGLE (Intel, Intel(R) UHD Graphics...)") == "intel"
    assert _gpu_family("nvidia geforce rtx") == "nvidia"
    assert _gpu_family("AMD Radeon RX") == "amd"
    assert _gpu_family("Apple M2") == "apple"
    assert _gpu_family("Adreno 640") == "mobile"
    assert _gpu_family("some unknown gpu") == ""


def test_render_produces_a_markdown_table() -> None:
    fired: collections.Counter[str] = collections.Counter({"br.font_os_vs_ua": 3})
    md = render(fired, 300)
    assert "| rule | fired | rate |" in md
    assert "`br.font_os_vs_ua` | 3/300 | 1.0%" in md
    assert "`br.voice_os_vs_ua` | 0/300" in md  # a non-firing rule still appears
    assert render(collections.Counter(), 0).count("—") >= 1  # n=0 renders an em-dash rate


def test_incoherent_voices_trip_voice_os_vs_ua() -> None:
    # a Windows UA with macOS (Apple/Samantha) TTS voices → voice_os_vs_ua fires (fpgen incoherence, caught)
    fired = coherence_firings([_fpgen(_WIN_FONTS, voices=_MAC_VOICES)])
    assert fired["br.voice_os_vs_ua"] == 1


def test_mismatched_gpu_families_trip_webgpu_vendor_vs_webgl() -> None:
    # WebGL says Intel but the WebGPU adapter says nvidia → webgpu_vendor_vs_webgl fires
    extra = {s.kind for s in extra_coherence_signals(_fpgen(_WIN_FONTS, adapter_vendor="nvidia"))}
    assert "webgpu_vendor_mismatch" in extra
    fired = coherence_firings([_fpgen(_WIN_FONTS, adapter_vendor="nvidia")])
    assert fired["br.webgpu_vendor_vs_webgl"] == 1


def test_mapping_extracts_faithful_fields_only() -> None:
    fp = fingerprint_from_fpgen(_fpgen(_WIN_FONTS))
    assert fp["navigator"]["userAgent"] == _WIN_UA
    assert fp["fonts"] == _WIN_FONTS
    assert fp["videoCard"]["renderer"].startswith("ANGLE")
    # vendor / oscpu are deliberately NOT mapped (fpgen nulls them) so the out-of-scope rules abstain
    assert "vendor" not in fp["navigator"]
    assert "oscpu" not in fp["navigator"]


def test_coherent_fpgen_does_not_trip_coherence_rules() -> None:
    # a Windows fingerprint with Windows fonts is OS-coherent → none of the in-scope rules fire
    fired = coherence_firings([_fpgen(_WIN_FONTS)])
    assert sum(fired.values()) == 0


def test_incoherent_fonts_trip_font_os_vs_ua() -> None:
    # a Windows UA generated with macOS fonts (the fpgen generation incoherence we observed live) is caught
    fired = coherence_firings([_fpgen(_MAC_FONTS)])
    assert fired["br.font_os_vs_ua"] == 1
    assert "br.font_os_vs_ua" in COHERENCE_RULES
