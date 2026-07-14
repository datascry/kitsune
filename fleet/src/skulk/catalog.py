# fleet/skulk/catalog — generate the coordination-strategy catalog (the red⇄blue ladder) for the README.
# Renders every registered strategy + the blue binding that catches it + its verdict tier, between GENERATED markers.

"""Generate the coordination-strategy catalog — the fleet analog of ``evasion_catalog``.

Where the per-session evasion catalog scores one captured session (human/suspicious/bot), a fleet is a *shape*
emitted across N sessions, graded at the COORDINATION axis (benign/candidate/fleet/campaign). This renders every
registered Skulk strategy, the real-world attacker class it models, the blue binding that convicts it, and its
verdict tier — the scannable red⇄blue ladder, generated from the strategy registry so it cannot drift.

The verdict tier + binding are authored here (``_GRADE``) from the ladder; the completeness check asserts every
REGISTERED strategy has an entry (a new strategy with no catalog row fails CI), and the live ``grade.assess``
self-check is cross-referenced so an exact-match binding cannot silently disagree with the code.

    uv run python -m skulk.catalog            # rewrite the generated block in fleet/README.md
    uv run python -m skulk.catalog --check    # exit 1 if the committed block is stale (CI)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from . import strategies as _strategies  # noqa: F401 - import registers the built-in strategies
from .grade import assess
from .strategy import Strategy, all_strategies

_ROOT = Path(__file__).resolve().parents[3]
_README = _ROOT / "fleet" / "README.md"
_START = "<!-- GENERATED:coordination:start -->"
_END = "<!-- GENERATED:coordination:end -->"


@dataclass(frozen=True)
class Grade:
    """One strategy's catalog row: the attacker it models, the blue binding that convicts it, its verdict tier."""

    attacker: str  # the real-world attacker class this shape models
    binding: str  # the blue coordination signal that catches it (or "none" at the frontier)
    tier: str  # verdict tier key -> see _TIERS


#: Verdict tiers, weakest→strongest conviction, each with a badge + one-line gloss (rendered as the legend).
_TIERS: dict[str, tuple[str, str]] = {
    "below": (
        "⬜ below-candidate",
        "sheds even the 2-dim candidate binding in-sandbox — no in-box coordination tell",
    ),
    "candidate": (
        "🔶 candidate",
        "flagged, not convicted — conviction is external-data-bound (IP-rep / prevalence): the frontier",
    ),
    "campaign": (
        "✅ campaign",
        "convicted at the POPULATION axis (Axis A) — ≥3 independent correlated dimensions",
    ),
    "fleet": (
        "✅ fleet",
        "convicted at the per-CLUSTER axis (Axis B) — a binding catches the JA4-prefix cluster",
    ),
}

#: The red⇄blue ladder, one entry per registered strategy — transcribed from the ladder in this README's prose.
#: The completeness check asserts this covers every registered strategy, so it cannot drift out of sync.
_GRADE: dict[str, Grade] = {
    "cloned": Grade(
        "BotBrowser — one pinned profile cloned fleet-wide",
        "`fp_collision` — identical high-entropy fp across distinct IPs",
        "fleet",
    ),
    "trace-replay": Grade(
        "engagement / review farm — one canned mouse path replayed",
        "`trace_collision` — identical trace across distinct IPs (unambiguous)",
        "fleet",
    ),
    "similarity": Grade(
        "the evolved adversary, profiled — jittered traces from one humanizer model",
        "`template_similarity` — descriptors cluster below the human floor (corroboration-gated)",
        "fleet",
    ),
    "fuzzy-rotate": Grade(
        "the hardest shape — rotate JA4 per node AND fuzz fp/trace",
        "`shared_real_ip` — one WebRTC origin survives rotation (+ template_similarity)",
        "fleet",
    ),
    "ticket-reuse": Grade(
        "rotated JA4 + fuzzed, bound by a reused TLS-resumption ticket",
        "`shared_ticket` — one `tls_ticket_id` across distinct IPs (corroboration-gated)",
        "fleet",
    ),
    "tool-fleet": Grade(
        "no-JS automation-tool fleet (curl / Go / Python), one tool JA4",
        "`shared_ticket` + the non-browser JA4 (`ja4_client_hint`) corroborates",
        "fleet",
    ),
    "staggered": Grade(
        "a cloned fleet spreading arrivals over time to look organic",
        "`fp_collision` still convicts — lockstep is corroborating-only",
        "fleet",
    ),
    "ipv6-rotate": Grade(
        "cloned fleet spraying IPv6 /128s inside a few /64s to fake IP spread",
        "the /64 origin-fold collapses the spray; `fp_collision` still convicts",
        "fleet",
    ),
    "httpflood": Grade(
        "L7 HTTP flood (MHDDoS class) — many no-JS tool sources in lockstep",
        "the aggregate flood shape (large + lockstep + many origins) + tool JA4",
        "fleet",
    ),
    "diffuse-scheduled": Grade(
        "a diffuse fleet that staggers on a fixed SCHEDULE",
        "`arrival_regularity` — scheduled CV≈0 vs independent-user Poisson CV≈1",
        "campaign",
    ),
    "diffuse-automated": Grade(
        "a diffuse fleet that leaks a per-session automation tell (webdriver)",
        "the automation tell lifts a 2-dim community to campaign (Axis-A corroboration)",
        "campaign",
    ),
    "residential-proxy": Grade(
        "a diffuse fleet on clean residential IPs behind one tunnel pool",
        "`proxy_egress` — a shared reduced tunnel MSS (WireGuard-class), gated on descriptor",
        "campaign",
    ),
    "socks-proxy": Grade(
        "a diffuse fleet on a SOCKS pool that re-originates TCP",
        "`proxy_egress` — shared SYN-stack-vs-UA-OS divergence, gated on descriptor",
        "campaign",
    ),
    "diffuse-campaign": Grade(
        "the maximal evader base — shared build + lockstep + one humanizer",
        "none in-sandbox — a 2-dim (ja4_prefix + descriptor) candidate",
        "candidate",
    ),
    "diffuse": Grade(
        "the maximal in-sandbox evader — diffuse, Poisson-staggered, fully clean",
        "none in-sandbox — conviction is external-data-bound (the frontier the ladder converges on)",
        "candidate",
    ),
    "fuzzy": Grade(
        "the evolved adversary — jitter the fp *and* the trace per instance",
        "none yet — defeats exact-hash matching",
        "candidate",
    ),
    "randomizer": Grade(
        "Multilogin / GoLogin multi-accounting — coherent per-instance fps, one JA4",
        "the TLS/JS paradox — shared JA4 + divergent JS (needs corroboration)",
        "candidate",
    ),
    "morph-diffuse": Grade(
        "the distinct-coherent-build diffuse fleet — one real engine per node",
        "sheds the shared build → `ja4_prefix` no longer dense (drops below candidate)",
        "below",
    ),
}

#: Which live ``grade.assess`` signals a declared binding must mention, so an exact-match row can't lie.
_SIGNAL_TOKENS = {
    "fp_hash": "fp_collision",
    "trace_hash": "trace_collision",
    "shared_ticket": "shared_ticket",
    "shared_origin": "shared_real_ip",
    "template_similarity": "template_similarity",
}


def _cell(text: str) -> str:
    return text.replace("\n", " ").strip()


def _self_check_signal(s: Strategy) -> str:
    """The strategy's own exact-match/similarity self-check signal (ground-truth from the generated members)."""
    return assess(s.members(6, seed=1)).signal


def _cross_check(strategies: list[Strategy]) -> None:
    """Guard: when the fleet-native self-check DOES catch a strategy, its declared binding must name that signal —
    so the catalog cannot claim a binding the code contradicts. (Frontier strategies self-check to `none`; their
    verdict is the richer Axis-A/campaign grade the exact-match self-check does not model, so they are exempt.)"""
    for s in strategies:
        signal = _self_check_signal(s)
        token = _SIGNAL_TOKENS.get(signal)
        if token and token not in _GRADE[s.name].binding:
            raise SystemExit(
                f"catalog binding for `{s.name}` omits its live self-check signal `{token}` "
                f"(assess()={signal!r}) — update _GRADE so the catalog matches the code"
            )


def generate_catalog_md() -> str:
    """Render the coordination catalog markdown (the content spliced between the GENERATED markers)."""
    strategies = all_strategies()
    missing = [s.name for s in strategies if s.name not in _GRADE]
    if missing:
        raise SystemExit(f"strategies missing a catalog entry (add to _GRADE): {', '.join(missing)}")
    _cross_check(strategies)

    by_tier = {t: sum(1 for s in strategies if _GRADE[s.name].tier == t) for t in _TIERS}
    out: list[str] = []
    out.append("### Every fleet shape, and the blue binding that catches it")
    out.append("")
    out.append(
        f"> **Generated** from the Skulk strategy registry (`uv run python -m skulk.catalog`) — do not edit by "
        f"hand. **{len(strategies)} strategies**: {by_tier['fleet']} convicted at the cluster axis (`fleet`), "
        f"{by_tier['campaign']} at the population axis (`campaign`), {by_tier['candidate']} `candidate` at the "
        f"external-data-bound frontier, {by_tier['below']} shed even that in-sandbox. A fleet is a *shape* across "
        f"N sessions, graded at the COORDINATION axis — not a per-session human/bot verdict."
    )
    out.append("")
    out.append("**Verdict tiers** (weakest→strongest conviction):")
    out.append("")
    for _key, (badge, gloss) in _TIERS.items():
        out.append(f"- **{badge}** — {gloss}")
    out.append("")
    out.append("| strategy | attacker class it models | blue binding that catches it | verdict |")
    out.append("|---|---|---|---|")
    # Order rows by conviction strength (fleet → campaign → candidate → below), then alphabetically within a tier.
    order = {t: i for i, t in enumerate(("fleet", "campaign", "candidate", "below"))}
    for s in sorted(strategies, key=lambda s: (order[_GRADE[s.name].tier], s.name)):
        g = _GRADE[s.name]
        badge = _TIERS[g.tier][0]
        out.append(f"| `{s.name}` | {_cell(g.attacker)} | {_cell(g.binding)} | {badge} |")
    out.append("")
    out.append(
        "> The `candidate` frontier (`fuzzy`, `randomizer`, `diffuse*`) is where conviction becomes "
        "external-data-bound: a fleet that sheds every in-sandbox binding — distinct builds, real-hardware fps, "
        "clean residential egress, Poisson-random timing — is, by construction, indistinguishable from N "
        "independent real users without IP-reputation or real-traffic prevalence data. That is the economic wall, "
        "not a missing rule. Grade any fleet on the live detector view with `task coordination-live`."
    )
    return "\n".join(out).rstrip() + "\n"


def render_into() -> str:
    """Return the README text with the GENERATED block replaced by the current catalog. Does not write."""
    text = _README.read_text()
    if _START not in text or _END not in text:
        raise SystemExit(f"{_README} is missing the {_START} / {_END} markers")
    pre = text[: text.index(_START) + len(_START)]
    post = text[text.index(_END) :]
    return f"{pre}\n{generate_catalog_md()}\n{post}"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    new = render_into()
    if "--check" in args:
        if _README.read_text() != new:  # pragma: no cover - stale path is a CI-failure branch
            print("fleet/README.md coordination catalog is STALE — run the coordination-catalog task", file=sys.stderr)
            return 1
        print("coordination catalog is up to date")
        return 0
    _README.write_text(new)  # pragma: no cover - write path exercised via the task target
    print(f"wrote coordination catalog into {_README.relative_to(_ROOT)}")  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - thin CLI
    raise SystemExit(main())
