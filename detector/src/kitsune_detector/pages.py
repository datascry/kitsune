# detector/pages — themed HTML shell for the markdown-rendered doc pages.
# Wraps rendered markdown in the forensic shell (nav + footer + per-page SEO head), reusing the palette.

"""Shared shell for the doc pages (/matrix, /evasions, /detections, /how-it-works, /research).

The detector renders selected ``docs/*.md`` to HTML at request time and wraps them here so they share
the live page's forensic aesthetic, navigation, and SEO scaffolding (title/description/canonical/OG).
"""

from __future__ import annotations

import html
import re
from typing import Any

SITE_ORIGIN = "https://kitsune.id"

#: Top-nav links shared across the doc pages (and mirrored in the live page's nav).
NAV_LINKS: list[tuple[str, str]] = [
    ("/", "Test"),
    ("/matrix", "Matrix"),
    ("/evasions", "Evasions"),
    ("/detections", "Detections"),
    ("/how-it-works", "How it works"),
    ("/research", "Research"),
    ("https://github.com/datascry/kitsune", "GitHub"),
]

DOC_CSS = """
:root{--bg:#0a0a0c;--panel:#0e0e12;--panel-2:#121218;--line:#20202a;--line-bright:#34343f;--ink:#eae7df;--muted:#797985;--fox:#e8482b;--jade:#5fb89a;--mono:ui-monospace,"SF Mono","JetBrains Mono","Menlo","Consolas","Liberation Mono",monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13.5px;line-height:1.6;-webkit-font-smoothing:antialiased;letter-spacing:.01em}
nav.top{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;max-width:64rem;margin:0 auto;padding:.9rem 1.5rem;border-bottom:1px solid var(--line)}
nav.top a{color:var(--muted);text-decoration:none;font-size:.78rem;letter-spacing:.06em}
nav.top a:hover{color:var(--fox)}
nav.top a.brand{display:flex;align-items:center;gap:.5rem;color:var(--ink);font-weight:700;letter-spacing:.22em;text-transform:uppercase;font-size:.95rem}
nav.top a.brand::before{content:"";width:.5rem;height:1.1rem;background:var(--fox)}
nav.top .spacer{flex:1}
main.doc{max-width:64rem;margin:0 auto;padding:1.5rem 1.5rem 3rem}
main.doc h1{font-size:1.7rem;font-weight:700;margin:.6rem 0 1rem}
main.doc h2{font-size:1rem;text-transform:uppercase;letter-spacing:.1em;color:var(--ink);margin:2rem 0 .6rem;display:flex;align-items:center;gap:.6rem}
main.doc h2::before{content:"§";color:var(--fox)}
main.doc h3{font-size:.82rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:1.3rem 0 .4rem}
main.doc p,main.doc li{color:var(--muted)}
main.doc strong{color:var(--ink)}
main.doc em{color:var(--ink);font-style:italic}
main.doc a{color:var(--fox);text-decoration:none}
main.doc a:hover{text-decoration:underline}
main.doc code{font-family:var(--mono);color:var(--fox);font-size:.92em;word-break:break-word}
main.doc pre{background:var(--panel-2);border:1px solid var(--line);padding:.8rem 1rem;overflow:auto}
main.doc pre code{color:var(--ink)}
main.doc table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.82rem;display:block;overflow-x:auto}
main.doc th,main.doc td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
main.doc th{color:var(--muted);text-transform:uppercase;font-size:.7rem;letter-spacing:.08em;white-space:nowrap}
main.doc blockquote{border-left:2px solid var(--fox);margin:1rem 0;padding:.2rem 0 .2rem 1rem}
main.doc hr{border:0;border-top:1px solid var(--line);margin:2rem 0}
footer{max-width:64rem;margin:0 auto;color:var(--muted);font-size:.78rem;border-top:1px solid var(--line);padding:1rem 1.5rem 2.5rem}
footer a{color:var(--fox);text-decoration:none}
/* --- customer-facing cards / badges / stats --- */
.lead{font-size:1.02rem;color:var(--ink);max-width:48rem;margin:.4rem 0 1rem}
.stat-row{display:flex;flex-wrap:wrap;gap:.8rem 2rem;margin:.4rem 0 1.4rem}
.stat{display:flex;flex-direction:column;line-height:1.1}
.stat strong{font-size:2rem;color:var(--fox)}
.stat span{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(19rem,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin:.8rem 0 1.6rem}
.card{background:var(--panel);padding:.7rem .9rem;min-width:0}
.card .ct{display:flex;justify-content:space-between;align-items:baseline;gap:.5rem}
.card .cn{font-weight:700;color:var(--ink);overflow-wrap:anywhere}
.card .cd{color:var(--muted);font-size:.8rem;margin-top:.35rem;overflow-wrap:anywhere}
.card .cm{color:var(--muted);font-size:.72rem;margin-top:.35rem}
.card .cm code{color:var(--fox)}
a.card{text-decoration:none;color:inherit;display:block}
a.card:hover{background:var(--panel-2)}a.card:hover .cn{color:var(--fox)}
.rrow .rid a{color:inherit;text-decoration:none}.rrow .rid a:hover code{text-decoration:underline}
.badge{font-size:.6rem;text-transform:uppercase;letter-spacing:.08em;padding:.12rem .4rem;border:1px solid var(--line-bright);color:var(--muted);white-space:nowrap;flex:none}
.badge.bot{color:var(--fox);border-color:var(--fox)}
.badge.suspicious{color:var(--amber);border-color:var(--amber)}
.badge.human,.badge.convicting{color:var(--jade);border-color:var(--jade)}
.lgrp{margin:1.4rem 0}
.lgrp>h3{display:flex;align-items:baseline;gap:.6rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.12em;color:var(--ink);margin:0 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.lgrp>h3 .c{color:var(--muted);font-weight:400}
.rrow{display:flex;justify-content:space-between;align-items:baseline;gap:.6rem;padding:.35rem .1rem;border-bottom:1px solid var(--line);font-size:.84rem}
.rrow .rid{color:var(--fox);overflow-wrap:anywhere}
.rrow .rt{color:var(--muted);text-align:right;flex:1}
@media (max-width:640px){.cards{grid-template-columns:1fr}.stat strong{font-size:1.5rem}.rrow{flex-direction:column;gap:.15rem}.rrow .rt{text-align:left}}
html,body{overflow-x:hidden;max-width:100%}
main.doc code,main.doc td,main.doc th,main.doc li,main.doc p{overflow-wrap:anywhere}
@media (max-width:640px){
  nav.top,main.doc,footer{padding-left:1rem;padding-right:1rem}
  nav.top{gap:.7rem .9rem}
  nav.top a{font-size:.72rem}
  nav.top a.brand{font-size:.85rem;letter-spacing:.16em}
  main.doc h1{font-size:1.35rem}
  main.doc h2{font-size:.9rem}
  main.doc table{font-size:.74rem}
}
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


def _nav() -> str:
    links = "".join(f'<a href="{h}">{_esc(label)}</a>' for h, label in NAV_LINKS)
    return f'<nav class="top"><a class="brand" href="/">Kitsune</a>{links}<span class="spacer"></span></nav>'


def render_doc_page(title: str, description: str, canonical_path: str, body_html: str, noindex: bool = False) -> str:
    """Wrap ``body_html`` in the shared shell with per-page SEO head (noindex for thin pages)."""
    t, d = _esc(title), _esc(description)
    # Escape the canonical/OG url: canonical_path can carry a path param (drill-down slug/rule id), so
    # treat it as untrusted before it lands in an href/content attribute.
    url = _esc(f"{SITE_ORIGIN}{canonical_path}")
    robots = "noindex, follow" if noindex else "index, follow"
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{t} — Kitsune</title>"
        f'<meta name="description" content="{d}">'
        f'<link rel="canonical" href="{url}">'
        f'<meta name="robots" content="{robots}"><meta name="theme-color" content="#0a0a0c">'
        f'<meta property="og:type" content="article"><meta property="og:title" content="{t} — Kitsune">'
        f'<meta property="og:description" content="{d}"><meta property="og:url" content="{url}">'
        f'<meta property="og:image" content="{SITE_ORIGIN}/og.png">'
        '<meta name="twitter:card" content="summary_large_image">'
        f'<meta name="twitter:title" content="{t} — Kitsune"><meta name="twitter:description" content="{d}">'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
        '<link rel="icon" href="/favicon.ico" sizes="any">'
        '<link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="manifest" href="/site.webmanifest">'
        f"<style>{DOC_CSS}</style></head><body>{_nav()}"
        f'<main class="doc">{body_html}</main>'
        '<footer><p>The blue-team side of a <a href="https://github.com/datascry/kitsune">bot detection ⇄ '
        'evasion lab</a>. <a href="/">Run the live test →</a></p></footer></body></html>'
    )


# ----- customer-facing renderers: curated, mobile-first views built from structured data -----


def _cellhtml(s: str) -> str:
    """Escape a markdown table cell and turn `code` spans into <code>."""
    out, last = [], 0
    for m in re.finditer(r"`([^`]+)`", s):
        out.append(html.escape(s[last : m.start()]))
        out.append("<code>" + html.escape(m.group(1)) + "</code>")
        last = m.end()
    out.append(html.escape(s[last:]))
    return "".join(out)


def _slug(cell: str) -> str:
    """A table cell like `accept-lang-spoof` -> the bare slug used in drill-down URLs."""
    return cell.strip().strip("`").strip()


def _md_table(md: str, after: str) -> tuple[list[str], list[list[str]]]:
    """Extract the first markdown table appearing after a line containing ``after``."""
    lines = md.splitlines()
    i = 0
    while i < len(lines) and after not in lines[i]:
        i += 1
    while i < len(lines) and not lines[i].lstrip().startswith("|"):
        i += 1
    header: list[str] | None = None
    rows: list[list[str]] = []
    while i < len(lines) and lines[i].lstrip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        i += 1
        if cells and all(set(c) <= set("-:") for c in cells):
            continue  # separator row
        if header is None:
            header = cells
        else:
            rows.append(cells)
    return header or [], rows


def render_detections_page(rules: list[dict[str, Any]]) -> str:
    """A clean, per-layer view of the rule registry (no predicate/weight/status noise)."""
    layers = ["network", "browser", "behavioral", "reputation"]
    groups: dict[str, list[dict[str, Any]]] = {k: [] for k in [*layers, "cross-layer"]}
    for r in rules:
        ly = r.get("layers") or []
        key = "cross-layer" if len(ly) > 1 else (ly[0] if ly else "browser")
        groups.setdefault(key, []).append(r)
    convicting = sum(1 for r in rules if r.get("convicting"))
    body = [
        "<h1>Detection catalog</h1>",
        '<p class="lead">Every check Kitsune runs, grouped by signal layer. '
        "<strong>Convicting</strong> rules (coherence · automation · artifact) can label a session a bot; "
        "the rest corroborate.</p>",
        '<div class="stat-row">'
        f'<div class="stat"><strong>{len(rules)}</strong><span>checks</span></div>'
        f'<div class="stat"><strong>{convicting}</strong><span>convicting</span></div>'
        f'<div class="stat"><strong>{len([k for k in groups if groups[k]])}</strong><span>layers</span></div>'
        "</div>",
    ]
    for key in ["cross-layer", *layers]:
        grp = groups.get(key) or []
        if not grp:
            continue
        rows = "".join(
            f'<div class="rrow"><span class="rid">'
            f'<a href="/detections/{html.escape(r["id"])}"><code>{html.escape(r["id"])}</code></a> '
            f'<span class="badge {"convicting" if r.get("convicting") else "corroborating"}">'
            f"{'convicts' if r.get('convicting') else 'corroborates'}</span></span>"
            f'<span class="rt">{html.escape(r.get("title", ""))}</span></div>'
            for r in sorted(grp, key=lambda r: (not r.get("convicting"), r["id"]))
        )
        body.append(f'<div class="lgrp"><h3>{html.escape(key)} <span class="c">{len(grp)}</span></h3>{rows}</div>')
    return "".join(body)


def render_matrix_page(md: str) -> str:
    """Responsive per-evader cards from the matrix's verdict table (drops the rule/coverage sections)."""
    _, rows = _md_table(md, "Per-evader verdict")
    caught = sum(1 for r in rows if len(r) > 1 and r[1] == "bot")
    susp = sum(1 for r in rows if len(r) > 1 and r[1] == "suspicious")
    cards = []
    for r in rows:
        if len(r) < 5:
            continue
        name, verdict, score, _fired, tells = r[0], r[1], r[2], r[3], r[4]
        cards.append(
            f'<a class="card" href="/evasions/{html.escape(_slug(name))}"><div class="ct">'
            f'<span class="cn">{_cellhtml(name)}</span>'
            f'<span class="badge {html.escape(verdict)}">{html.escape(verdict)}</span></div>'
            f'<div class="cd">score {html.escape(score)}</div>'
            f'<div class="cm">{_cellhtml(tells)}</div></a>'
        )
    return (
        "<h1>Detection matrix</h1>"
        '<p class="lead">Kitsune\'s red-team fleet — real anti-detect tools and browsers — run against the '
        "detector. Each card is one evader: its verdict and the convicting tells that caught it.</p>"
        '<div class="stat-row">'
        f'<div class="stat"><strong>{len(rows)}</strong><span>evaders</span></div>'
        f'<div class="stat"><strong>{caught}</strong><span>caught (bot)</span></div>'
        f'<div class="stat"><strong>{susp}</strong><span>suspicious</span></div>'
        "</div>"
        f'<div class="cards">{"".join(cards)}</div>'
    )


def render_evasions_page(md: str) -> str:
    """Clean fleet list from the evasion catalog (drops the frontier prose)."""
    _, rows = _md_table(md, "Fleet —")
    cards = []
    for r in rows:
        if len(r) < 3:
            continue
        name, lang, what = r[0], r[1], r[2]
        cards.append(
            f'<a class="card" href="/evasions/{html.escape(_slug(name))}"><div class="ct">'
            f'<span class="cn">{_cellhtml(name)}</span>'
            f'<span class="badge">{html.escape(lang)}</span></div>'
            f'<div class="cd">{_cellhtml(what)}</div></a>'
        )
    return (
        "<h1>Evasion catalog</h1>"
        '<p class="lead">The red-team fleet Kitsune tests itself against — real anti-detect tools, stealth '
        "browsers, and TLS/HTTP forgers. Every one is exercised against the live detector.</p>"
        '<div class="stat-row">'
        f'<div class="stat"><strong>{len(rows)}</strong><span>evader tools</span></div>'
        "</div>"
        f'<div class="cards">{"".join(cards)}</div>'
    )


#: The signal layers, for the How-it-works card grid (name -> what Kitsune reads from it).
_LAYERS: list[tuple[str, str]] = [
    ("TLS", "JA3 / JA4 from your ClientHello — the TLS library, read before any HTTP."),
    ("HTTP/2", "Frame order, SETTINGS and pseudo-header order — the client's H2 fingerprint."),
    ("QUIC / HTTP-3", "The HTTP-3 transport fingerprint the application layer never sees."),
    ("TCP / IP", "The OS stack beneath TLS — a p0f-style kernel tell from the raw SYN."),
    ("Browser", "Canvas, WebGL, audio, fonts and Client Hints — the classic JS surface."),
    ("Behavioral", "Mouse dynamics and keystroke timing — biomechanics a script can't fake."),
    ("IP reputation", "Datacenter / proxy / residential signals on the connecting address."),
]


def _section(title: str, *paras: str) -> str:
    body = "".join(f"<p>{p}</p>" for p in paras)
    return f"<h2>{html.escape(title)}</h2>{body}"


def render_how_it_works_page() -> str:
    """A concise, scannable explainer (not the full architecture doc)."""
    cards = "".join(
        f'<div class="card"><div class="ct"><span class="cn">{html.escape(n)}</span></div>'
        f'<div class="cd">{html.escape(d)}</div></div>'
        for n, d in _LAYERS
    )
    return (
        "<h1>How Kitsune works</h1>"
        '<p class="lead">Most tools flag <em>bad signals</em>. Kitsune flags <strong>incoherence across '
        "layers</strong> — the contradictions a real browser can't produce but a spoofed or automated one "
        "does.</p>"
        + _section(
            "The one idea",
            "A real visit is <strong>one device telling one story</strong>. Its TLS handshake, HTTP/2 frames, "
            "TCP/IP stack, GPU, JavaScript surface and behaviour all agree. Kitsune's edge ties them to a "
            "single session and checks they line up. When the User-Agent says Chrome-on-Windows but the JA4 "
            "says Firefox and the TCP stack says Linux, that disagreement is the tell.",
        )
        + "<h2>Seven layers, one device</h2>"
        + f'<div class="cards">{cards}</div>'
        + _section(
            "How a session is judged",
            "Only <strong>cross-layer contradictions, automation artifacts and implementation flaws</strong> "
            "can convict — a single odd value never does. Everything else (a stripped capability, unusual "
            "behaviour, a datacenter IP) only corroborates, nudging toward <em>suspicious</em> but never "
            "<em>bot</em> on its own. That conviction gate is what keeps real, unusual humans from being flagged.",
        )
        + _section(
            "Why it's hard to beat",
            "An anti-detect browser can spoof the User-Agent and patch <code>navigator.webdriver</code> in "
            "seconds. Making the JA4, the HTTP/2 frame order, the TCP/IP stack, the GPU renderer and the JS "
            "feature-set <em>all</em> describe one coherent, real device at the same time is far harder — and "
            "that is exactly what this page measures live.",
        )
        + _section(
            "Calibrated, not guessed",
            "No rule ships until a real evader has exercised it <strong>and</strong> a calibration gate proves "
            "it doesn't flag real browsers — trusted-but-verified against multiple independent fingerprint "
            "sources.",
        )
        + '<p class="lead"><a href="/">Run the live test →</a> &nbsp;·&nbsp; '
        '<a href="https://github.com/datascry/kitsune/blob/main/docs/architecture.md">Full architecture doc</a></p>'
    )


#: Headline research findings (title -> one-line takeaway), drawn from docs/findings.md.
_FINDINGS: list[tuple[str, str]] = [
    (
        "The arms-race ladder",
        "Each anti-detect rung defeats the one below it; the detector answers each with a new cross-layer check.",
    ),
    (
        "Coordination, not the instance",
        "A single polished bot can hide; a fleet can't — shared JA4/fingerprint/trace collisions across sessions are the durable signal.",
    ),
    (
        "Camoufox is the frontier",
        "Engine-level anti-detect Firefox is the hardest case, reaching only ~suspicious — the bar everything else is measured against.",
    ),
    (
        "Realm coherence",
        "Many spoofs patch the main JavaScript scope but forget the Worker/iframe realm — the two disagree, and that convicts.",
    ),
    (
        "Tells below the application",
        "JA3/JA4, the HTTP/2 preface, QUIC and the TCP/IP stack betray automation before a single line of page JS runs.",
    ),
    (
        "Behavioral is the weakest layer",
        "Mouse/keystroke biomechanics are corroborating-only — humanizers are improving, so it never convicts alone.",
    ),
    (
        "Precision is the hard part",
        "Real, unusual humans (Brave, Tor, mobile, privacy browsers) must never be flagged — calibration against real-traffic sources is the gate.",
    ),
]


def render_research_page() -> str:
    """A concise findings overview (not the 99KB findings doc)."""
    cards = "".join(
        f'<div class="card"><div class="ct"><span class="cn">{html.escape(t)}</span></div>'
        f'<div class="cd">{html.escape(d)}</div></div>'
        for t, d in _FINDINGS
    )
    return (
        "<h1>Research</h1>"
        '<p class="lead">What Kitsune has actually measured, running real anti-detect tools through the live '
        "edge → detector. The thesis holds: <strong>incoherence across layers — not any single bad signal — "
        "is what survives anti-detect tooling.</strong></p>"
        '<div class="stat-row">'
        '<div class="stat"><strong>86/96</strong><span>evaders caught</span></div>'
        '<div class="stat"><strong>127</strong><span>detection rules</span></div>'
        '<div class="stat"><strong>7</strong><span>signal layers</span></div>'
        "</div>"
        "<h2>What we've learned</h2>"
        f'<div class="cards">{cards}</div>'
        + _section(
            "How it's grounded",
            "Findings come from running each evader through the real stack, not from synthetic tests. Detections "
            "are held to a calibration gate against multiple independent fingerprint sources, so a rule that "
            "would flag real humans never ships.",
        )
        + '<p class="lead"><a href="/matrix">See the full matrix →</a> &nbsp;·&nbsp; '
        '<a href="https://github.com/datascry/kitsune/blob/main/docs/findings.md">Full findings doc</a></p>'
    )


# ----- drill-down pages: one per evader and per detection rule -----


def parse_matrix(md: str) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """From matrix.md: per-evader verdicts (slug -> {verdict,score,tells,more}) and rule catch-counts."""
    evaders: dict[str, dict[str, Any]] = {}
    _, rows = _md_table(md, "Per-evader verdict")
    for r in rows:
        if len(r) < 5:
            continue
        tells = re.findall(r"`([^`]+)`", r[4])
        more = re.search(r"\+(\d+)", r[4])
        evaders[_slug(r[0])] = {
            "verdict": r[1],
            "score": r[2],
            "fired": r[3],
            "tells": tells,
            "more": int(more.group(1)) if more else 0,
        }
    catch: dict[str, str] = {}
    _, crows = _md_table(md, "Per-rule coverage")
    for r in crows:
        if len(r) >= 4:
            catch[_slug(r[0])] = r[3].strip()
    return evaders, catch


def parse_fleet(md: str) -> dict[str, dict[str, str]]:
    """From evasion-catalog.md: the fleet (slug -> {lang, what})."""
    fleet: dict[str, dict[str, str]] = {}
    _, rows = _md_table(md, "Fleet —")
    for r in rows:
        if len(r) >= 3:
            fleet[_slug(r[0])] = {"lang": r[1], "what": r[2]}
    return fleet


def render_evasion_detail(slug: str, ev: dict[str, Any] | None, fleet: dict[str, str] | None) -> str | None:
    """One evader: what it is, its verdict, and the tells that caught it (linking to detections)."""
    if ev is None and fleet is None:
        return None
    parts = [f"<h1>{html.escape(slug)}</h1>"]
    if fleet:
        parts.append(f'<p class="lead">{_cellhtml(fleet["what"])}</p>')
    stats = ""
    if ev:
        stats += f'<div class="stat"><strong>{html.escape(ev["verdict"])}</strong><span>verdict</span></div>'
        stats += f'<div class="stat"><strong>{html.escape(ev["score"])}</strong><span>score</span></div>'
        stats += f'<div class="stat"><strong>{html.escape(ev["fired"])}</strong><span>checks fired</span></div>'
    if fleet:
        stats += f'<div class="stat"><strong>{html.escape(fleet["lang"])}</strong><span>language</span></div>'
    if stats:
        parts.append(f'<div class="stat-row">{stats}</div>')
    if ev and ev["tells"]:
        rows = "".join(
            f'<div class="rrow"><span class="rid">'
            f'<a href="/detections/{html.escape(t)}"><code>{html.escape(t)}</code></a></span></div>'
            for t in ev["tells"]
        )
        more = f' <span class="c">+{ev["more"]} more</span>' if ev["more"] else ""
        parts.append(f'<div class="lgrp"><h3>Convicting tells{more}</h3>{rows}</div>')
    parts.append(
        '<p class="lead"><a href="/matrix">← all evaders</a> &nbsp;·&nbsp; <a href="/evasions">the fleet</a></p>'
    )
    return "".join(parts)


def render_detection_detail(rule: dict[str, Any] | None, catch_count: str | None) -> str | None:
    """One detection rule: what it catches, the signals it reads, and how it fires."""
    if rule is None:
        return None
    convicts = bool(rule.get("convicting"))
    badge = "convicting" if convicts else "corroborating"
    parts = [
        f"<h1>{html.escape(rule.get('title', rule['id']))}</h1>",
        f'<p class="lead"><code>{html.escape(rule["id"])}</code> &nbsp;·&nbsp; '
        f'<span class="badge {badge}">{"convicts" if convicts else "corroborates"}</span></p>',
    ]
    stats = (
        f'<div class="stat"><strong>{html.escape(", ".join(rule.get("layers") or []))}</strong><span>layer</span></div>'
    )
    stats += (
        f'<div class="stat"><strong>{html.escape(str(rule.get("category", "")))}</strong><span>category</span></div>'
    )
    if catch_count:
        stats += f'<div class="stat"><strong>{html.escape(catch_count)}</strong><span>evaders caught</span></div>'
    parts.append(f'<div class="stat-row">{stats}</div>')
    src = rule.get("source")
    if src:
        parts.append(_section("What it catches", _cellhtml(str(src))))
    reads = rule.get("reads") or []
    if reads:
        parts.append(_section("Signals it reads", " &nbsp; ".join(f"<code>{html.escape(x)}</code>" for x in reads)))
    pred = rule.get("predicate")
    if pred:
        thr = rule.get("threshold")
        extra = f" (threshold {html.escape(str(thr))})" if thr is not None else ""
        parts.append(_section("How it fires", f"<code>{html.escape(str(pred))}</code>{extra}"))
    parts.append('<p class="lead"><a href="/detections">← all detections</a></p>')
    return "".join(parts)
