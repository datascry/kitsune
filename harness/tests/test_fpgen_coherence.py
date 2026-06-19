# tests/test_fpgen_coherence — the fpgen second-source coherence FP-check logic (no fpgen/network).
# Guards the fpgen->fingerprint mapping + that an in-scope rule fires on incoherence, stays quiet on coherence.

from __future__ import annotations

from kitsune_harness.fpgen_coherence import COHERENCE_RULES, coherence_firings, fingerprint_from_fpgen

_WIN_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
_WIN_FONTS = ["Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma", "Arial"]
_MAC_FONTS = ["Helvetica Neue", "Lucida Grande", "Geneva", "Menlo", "Monaco", "Al Bayan"]


def _fpgen(fonts: list[str]) -> dict[str, object]:
    # a minimal fpgen-shaped fingerprint: a Windows Chrome with the given installed-font list
    return {
        "navigator": {"userAgent": _WIN_UA, "platform": "Win32", "hardwareConcurrency": 8, "productSub": "20030107"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "gpu": {"renderer": "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"},
        "allFonts": fonts,
    }


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
