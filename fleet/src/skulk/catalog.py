# fleet/skulk/catalog — generate the coordination-strategy catalog (the red⇄blue ladder) + its blue-signal glossary.
# Renders every strategy + the binding that catches it into fleet/README.md and docs/coordination-catalog.md.

"""Generate the coordination-strategy catalog — the fleet analog of ``evasion_catalog``.

Where the per-session evasion catalog scores one captured session (human/suspicious/bot), a fleet is a *shape*
emitted across N sessions, graded at the COORDINATION axis (benign/candidate/fleet/campaign). This renders every
registered Skulk strategy, the real-world attacker class it models, the blue binding that convicts it, and its
verdict tier — followed by a glossary of those blue signals (what each catches; unambiguous vs corroboration-
gated), which the ladder's bindings link into. Generated from the strategy registry so it cannot drift.

The same generated block is spliced into TWO files: ``fleet/README.md`` (the kit's own docs) and
``docs/coordination-catalog.md`` (served on the site at ``/coordination``). The verdict tier + binding are
authored here (``_GRADE``) from the ladder; the completeness check asserts every REGISTERED strategy has an
entry, and the live ``grade.assess`` self-check is cross-referenced so an exact-match binding cannot silently
disagree with the code.

    uv run python -m skulk.catalog            # rewrite the generated block in both files
    uv run python -m skulk.catalog --check    # exit 1 if either committed block is stale (CI)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from . import strategies as _strategies  # noqa: F401 - import registers the built-in strategies
from .grade import assess
from .strategy import Strategy, all_strategies

_ROOT = Path(__file__).resolve().parents[3]
#: Every file carrying the GENERATED markers that this catalog is spliced into.
_TARGETS = (_ROOT / "fleet" / "README.md", _ROOT / "docs" / "coordination-catalog.md")
_START = "<!-- GENERATED:coordination:start -->"
_END = "<!-- GENERATED:coordination:end -->"


@dataclass(frozen=True)
class Grade:
    """One strategy's catalog row: the attacker it models, the blue binding that convicts it, its verdict tier,
    and the primary blue signal id (linked into the glossary); ``signal`` is None at the external-bound frontier."""

    attacker: str
    binding: str
    tier: str
    signal: str | None = None


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

#: The blue coordination signals the ladder targets — id → (what it catches, the conviction gate). Rendered as
#: the glossary; each strategy's binding links to its signal here. Kept in the fleet's own docs because it is the
#: red team's map of the blue signals it aims at (the detector owns the scorer; this is the target list).
_SIGNALS: dict[str, tuple[str, str]] = {
    "fp_collision": (
        "an identical high-entropy fingerprint (canvas + audio + WebGL) across ≥2 distinct IPs",
        "**ambiguous** — corroboration-gated: an exact high-entropy collision across distinct IPs is strong, "
        "but a standardized corporate image needs an independent bot corroborator",
    ),
    "trace_collision": (
        "an identical pointer-trajectory hash across ≥2 distinct IPs",
        "**unambiguous** — a replayed human mouse-path has no benign explanation",
    ),
    "template_similarity": (
        "pointer-trace *descriptors* clustering below the human-motion floor across ≥2 IPs — one humanizer "
        "model, even when every trace_hash differs",
        "**ambiguous** — corroboration-gated (calibrated against real human motion so it stays FP-safe)",
    ),
    "shared_real_ip": (
        "one WebRTC-leaked origin behind ≥2 distinct proxy IPs",
        "**unambiguous** — the same real origin behind the proxies; survives JA4 rotation + fp/trace fuzzing",
    ),
    "shared_ticket": (
        "one TLS-resumption ticket (`tls_ticket_id`) reused across ≥2 distinct IPs",
        "**ambiguous** — corroboration-gated (a roaming user resumes from a second IP too)",
    ),
    "flood_shape": (
        "a large cluster in timing lockstep across many distinct origins with no per-node binding",
        "**aggregate** — corroborated by a non-browser tool JA4; the coordination scorer as L7-flood attributor",
    ),
    "arrival_regularity": (
        "scheduled inter-arrival (coefficient-of-variation ≈0) vs independent users' Poisson arrivals (CV≈1)",
        "**Axis-A dimension** — restores timing as an independent correlated dim; a Poisson-random stagger evades",
    ),
    "proxy_egress": (
        "a shared reduced tunnel MSS (WireGuard-class), or a shared re-originated SYN-stack (proxy kernel ≠ "
        "UA-claimed OS), across the fleet",
        "**Axis-A dimension** — gated on the descriptor dim so a legit VPN/mobile cohort stays clean",
    ),
}

#: The live ``grade.assess`` signal → the glossary id it must correspond to, so an exact-match row can't lie.
_SIGNAL_TOKENS = {
    "fp_hash": "fp_collision",
    "trace_hash": "trace_collision",
    "shared_ticket": "shared_ticket",
    "shared_origin": "shared_real_ip",
    "template_similarity": "template_similarity",
}

#: The red⇄blue ladder, one entry per registered strategy — transcribed from the ladder in fleet/README.md's
#: prose. The completeness check asserts this covers every registered strategy, so it cannot drift out of sync.
_GRADE: dict[str, Grade] = {
    "cloned": Grade(
        "BotBrowser — one pinned profile cloned fleet-wide",
        "`fp_collision` — identical high-entropy fp across distinct IPs",
        "fleet",
        signal="fp_collision",
    ),
    "trace-replay": Grade(
        "engagement / review farm — one canned mouse path replayed",
        "`trace_collision` — identical trace across distinct IPs (unambiguous)",
        "fleet",
        signal="trace_collision",
    ),
    "similarity": Grade(
        "the evolved adversary, profiled — jittered traces from one humanizer model",
        "`template_similarity` — descriptors cluster below the human floor (corroboration-gated)",
        "fleet",
        signal="template_similarity",
    ),
    "fuzzy-rotate": Grade(
        "the hardest shape — rotate JA4 per node AND fuzz fp/trace",
        "`shared_real_ip` — one WebRTC origin survives rotation (+ template_similarity)",
        "fleet",
        signal="shared_real_ip",
    ),
    "ticket-reuse": Grade(
        "rotated JA4 + fuzzed, bound by a reused TLS-resumption ticket",
        "`shared_ticket` — one `tls_ticket_id` across distinct IPs (corroboration-gated)",
        "fleet",
        signal="shared_ticket",
    ),
    "tool-fleet": Grade(
        "no-JS automation-tool fleet (curl / Go / Python), one tool JA4",
        "`shared_ticket` + the non-browser JA4 (`ja4_client_hint`) corroborates",
        "fleet",
        signal="shared_ticket",
    ),
    "staggered": Grade(
        "a cloned fleet spreading arrivals over time to look organic",
        "`fp_collision` still convicts — lockstep is corroborating-only",
        "fleet",
        signal="fp_collision",
    ),
    "ipv6-rotate": Grade(
        "cloned fleet spraying IPv6 /128s inside a few /64s to fake IP spread",
        "the /64 origin-fold collapses the spray; `fp_collision` still convicts",
        "fleet",
        signal="fp_collision",
    ),
    "httpflood": Grade(
        "L7 HTTP flood (MHDDoS class) — many no-JS tool sources in lockstep",
        "`flood_shape` — the aggregate flood shape (large + lockstep + many origins) + tool JA4",
        "fleet",
        signal="flood_shape",
    ),
    "diffuse-scheduled": Grade(
        "a diffuse fleet that staggers on a fixed SCHEDULE",
        "`arrival_regularity` — scheduled CV≈0 vs independent-user Poisson CV≈1",
        "campaign",
        signal="arrival_regularity",
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
        signal="proxy_egress",
    ),
    "socks-proxy": Grade(
        "a diffuse fleet on a SOCKS pool that re-originates TCP",
        "`proxy_egress` — shared SYN-stack-vs-UA-OS divergence, gated on descriptor",
        "campaign",
        signal="proxy_egress",
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


def _cell(text: str) -> str:
    return text.replace("\n", " ").strip()


def _linked_binding(g: Grade) -> str:
    """The binding cell with its primary signal token linked into the glossary (a same-page ``#anchor``)."""
    binding = _cell(g.binding)
    if g.signal:
        token = f"`{g.signal}`"
        binding = binding.replace(token, f"[{token}](#{g.signal})", 1)
    return binding


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
    """Render the coordination catalog + glossary (the content spliced between the GENERATED markers)."""
    strategies = all_strategies()
    missing = [s.name for s in strategies if s.name not in _GRADE]
    if missing:
        raise SystemExit(f"strategies missing a catalog entry (add to _GRADE): {', '.join(missing)}")
    bad_signal = [g.signal for g in _GRADE.values() if g.signal and g.signal not in _SIGNALS]
    if bad_signal:
        raise SystemExit(f"catalog references unknown blue signal(s) (add to _SIGNALS): {', '.join(bad_signal)}")
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
        out.append(f"| `{s.name}` | {_cell(g.attacker)} | {_linked_binding(g)} | {_TIERS[g.tier][0]} |")
    out.append("")
    out.append("### The blue signals it targets")
    out.append("")
    out.append(
        "> Each binding above links here. **Unambiguous** signals convict alone; **ambiguous** ones need an "
        "independent corroborator (an automation tell, a datacenter/proxy IP, a non-browser JA4); **Axis-A "
        "dimensions** convict only as one of ≥3 independent correlations. The scorer lives in the detector "
        "(`kitsune_harness.coordination`); this is the red team's map of what it targets."
    )
    out.append("")
    for sig, (catches, gate) in _SIGNALS.items():
        out.append(f"#### {sig}")
        out.append("")
        out.append(f"{catches}. {gate}.")
        out.append("")
    out.append(
        "> The `candidate` frontier (`fuzzy`, `randomizer`, `diffuse*`) is where conviction becomes "
        "external-data-bound: a fleet that sheds every in-sandbox binding — distinct builds, real-hardware fps, "
        "clean residential egress, Poisson-random timing — is, by construction, indistinguishable from N "
        "independent real users without IP-reputation or real-traffic prevalence data. That is the economic wall, "
        "not a missing rule. Grade any fleet on the live detector view with `task coordination-live`."
    )
    return "\n".join(out).rstrip() + "\n"


def render_into(path: Path) -> str:
    """Return ``path``'s text with its GENERATED block replaced by the current catalog. Does not write."""
    text = path.read_text()
    if _START not in text or _END not in text:
        raise SystemExit(f"{path} is missing the {_START} / {_END} markers")
    pre = text[: text.index(_START) + len(_START)]
    post = text[text.index(_END) :]
    return f"{pre}\n{generate_catalog_md()}\n{post}"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--check" in args:
        stale = [p for p in _TARGETS if p.read_text() != render_into(p)]
        if stale:  # pragma: no cover - stale path is a CI-failure branch
            names = ", ".join(str(p.relative_to(_ROOT)) for p in stale)
            print(f"coordination catalog is STALE in {names} — run the coordination-catalog task", file=sys.stderr)
            return 1
        print("coordination catalog is up to date")
        return 0
    for p in _TARGETS:  # pragma: no cover - write path exercised via the task target
        p.write_text(render_into(p))
        print(f"wrote coordination catalog into {p.relative_to(_ROOT)}")
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - thin CLI
    raise SystemExit(main())
