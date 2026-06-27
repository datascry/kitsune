# harness/evasions — the structured registry of the red-team evasion ladder (named technique → image + env).
# Lets the fleet manager compose fleets from NAMED evasions (camoufox-linux, zendriver-uach) not raw image+env.

"""A structured registry of the existing red-team evasions.

The ``evaders/`` tree holds the real anti-detect tools, but the only machine-readable index of them was the
GENERATED ``docs/evasion-catalog.md`` (produced by running them). This is the authored source that index always
wanted: each fleet-relevant evasion as a named ``Evasion`` (image + the env knobs that select its mode), so the
:mod:`~kitsune_harness.fleet_manager` can build a fleet from ``--evasion camoufox-linux --evasion zendriver-uach``
instead of the operator having to remember image tags and ``KS_*`` flags.

Scope: the **browser** evaders that make natural coordinated-fleet nodes (each runs a real stealth browser that
mints a session through the edge). The single-session *artifact* modes of the ``stealth`` tool (electron-leak,
canvas-lie, …) light individual detector rules and are exercised via the lit-rule captures, not composed into
fleets, so only the ``stealth`` base mode is registered here. Add an evasion by calling :func:`_reg`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Evasion:
    """One named evasion: the evader image and the env that selects its mode, plus how it presents."""

    name: str
    image: str
    family: str  # the engine/tool family, for grouping (camoufox / chromium-cdp / chromium-stealth / control)
    summary: str
    env: dict[str, str] = field(default_factory=dict)

    def env_with(self, extra: dict[str, str] | None) -> dict[str, str]:
        return {**self.env, **(extra or {})}


_REGISTRY: dict[str, Evasion] = {}


def _reg(name: str, image: str, family: str, summary: str, env: dict[str, str] | None = None) -> None:
    _REGISTRY[name] = Evasion(name=name, image=image, family=family, summary=summary, env=env or {})


# --- the control ---
_reg("vanilla", "kitsune-vanilla:latest", "control", "stock Playwright Chromium — the no-evasion control (convicted)")

# --- Camoufox: C++-level fingerprint injection (Firefox engine); the strongest per-session evader ---
_C = "kitsune-camoufox:latest"
_reg("camoufox", _C, "camoufox", "Camoufox default — per-launch fingerprint randomization")
_reg("camoufox-linux", _C, "camoufox", "Camoufox pinned to a Linux profile, coherent with the host", {"KS_LINUX": "1"})
_reg("camoufox-macos", _C, "camoufox", "Camoufox pinned to a macOS profile (bundled-fonts tell)", {"KS_MACOS": "1"})
_reg("camoufox-hardened", _C, "camoufox", "Camoufox with the hardened anti-detect config", {"KS_HARDENED": "1"})
_reg("camoufox-behave", _C, "camoufox", "Camoufox + behavioral synthesis (humanized pointer)", {"KS_BEHAVE": "1"})
_reg("camoufox-headful", _C, "camoufox", "Camoufox headful (xvfb) — beats headless-only tells", {"KS_HEADFUL": "1"})
_reg("camoufox-touch", _C, "camoufox", "Camoufox desktop with touch>0 — incoherent touch-desktop", {"KS_TOUCH": "1"})

# --- Chromium CDP-stealth tools (the modern undetectable-automation class) ---
_Z = "kitsune-zendriver:latest"
_reg("zendriver", _Z, "chromium-cdp", "zendriver (nodriver fork) — CDP automation, default")
_reg("zendriver-uach", _Z, "chromium-cdp", "zendriver + UA-CH fix — clears the convicting layer", {"KS_UACH": "1"})
_reg("zendriver-uach-behave", _Z, "chromium-cdp", "UA-CH + behavioral capstone", {"KS_UACH": "1", "KS_BEHAVE": "1"})
_reg("nodriver", "kitsune-nodriver:latest", "chromium-cdp", "nodriver — CDP automation, no chromedriver")
_reg("pydoll", "kitsune-pydoll:latest", "chromium-cdp", "pydoll — async CDP automation")
_reg("undetected", "kitsune-undetected:latest", "chromium-cdp", "undetected-chromedriver — Selenium-stealth patch")
_reg("selenium-driverless", "kitsune-selenium-driverless:latest", "chromium-cdp", "Selenium, no webdriver")

# --- Other browser evaders ---
_reg("playwright-extra", "kitsune-playwright-extra:latest", "chromium-stealth", "playwright-extra + stealth plugin")
_reg("brave", "kitsune-brave:latest", "chromium-stealth", "real Brave — native farbling (privacy browser)")
_reg("stealth", "kitsune-stealth:latest", "chromium-stealth", "puppeteer-extra-stealth base mode", {"STEALTH": "1"})


def get(name: str) -> Evasion:
    """Resolve a named evasion, or raise ``KeyError`` with the available names."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown evasion {name!r}; known: {', '.join(sorted(_REGISTRY))}") from None


def all_evasions() -> list[Evasion]:
    """Every registered evasion, sorted by family then name."""
    return sorted(_REGISTRY.values(), key=lambda e: (e.family, e.name))


def families() -> dict[str, list[Evasion]]:
    """Evasions grouped by family (camoufox / chromium-cdp / …)."""
    out: dict[str, list[Evasion]] = {}
    for ev in all_evasions():
        out.setdefault(ev.family, []).append(ev)
    return out
