# detector/pages — themed HTML shell for the markdown-rendered doc pages.
# Wraps rendered markdown in the forensic shell (nav + footer + per-page SEO head), reusing the palette.

"""Shared shell for the doc pages (/matrix, /evasions, /detections, /how-it-works, /research).

The detector renders selected ``docs/*.md`` to HTML at request time and wraps them here so they share
the live page's forensic aesthetic, navigation, and SEO scaffolding (title/description/canonical/OG).
"""

from __future__ import annotations

import html
import json
import os
import posixpath
import re
from pathlib import Path
from typing import Any

import markdown as _markdown

from .styles import SHARED_CSS

#: Canonical public origin — used for robots/sitemap absolute URLs and every page's canonical/OG tags.
SITE_ORIGIN = "https://kitsune.id"
#: Base keyword set woven into every doc page's structured data (each page appends its own specifics).
SEO_KEYWORDS = (
    "bot detection, browser fingerprinting, antidetect browser, TLS JA3 JA4, HTTP/2 fingerprint, "
    "QUIC fingerprint, TCP/IP fingerprint, automation detection, headless browser detection"
)
#: /llms.txt — the llmstxt.org convention: a concise, link-first map of the site for LLM agents (H1 +
#: blockquote summary + curated sections). Mirrors the SEO head's structured data in a plain-text form.
LLMS_TXT = """# Kitsune

> Kitsune is a bot detection ⇄ evasion lab: a blue-team detector and a red-team anti-detect evader
> fleet, run against each other to produce a per-layer scoreboard. The live page fingerprints a
> visitor's browser across every layer — TLS/JA4, HTTP/2, QUIC, TCP/IP, the JavaScript runtime and
> behavior — correlated at the edge, and returns a real bot-detection verdict. Its thesis: catch the
> incoherence across layers, not any single signal.

## Live tool
- [Bot-detection & fingerprint test](https://kitsune.id/): fingerprints this browser and returns a live
  verdict (human / suspicious / bot) across every layer.

## Get the result as JSON (programmatic access)
- In the live page: after scoring, the full verdict is embedded as JSON in the
  `<script type="application/json" id="ks-verdict">` tag and mirrored on `window.ksResult` (a
  `kitsune:result` DOM event also fires). It starts as `{"status":"collecting"}`; poll until `status`
  is `"complete"`. Fields: `status`, `label`, `score`, `incoherence_score`, `layer_scores`,
  `contradictions[]` (rule_id, category, weight, detail), `session_id`, and a `wire` block
  (`ja3`, `ja4`, `h2`, `tcp_os`, `quic`, `ip`, `geo`, `reputation`).
- `POST https://kitsune.id/ingest`: send collector signal envelopes; the response is the same verdict JSON.
- [Rule registry (JSON)](https://kitsune.id/rules.json): the full machine-readable detection-rule registry
  (rule id, title, layers, category, and whether each rule can convict).
- [API docs](https://kitsune.id/api): interactive OpenAPI/Swagger UI; the schema is at
  [/openapi.json](https://kitsune.id/openapi.json). All docs are indexed at [/docs](https://kitsune.id/docs).

## Documentation
- [How it works](https://kitsune.id/how-it-works): the cross-layer incoherence thesis and the signal layers.
- [Detection catalog](https://kitsune.id/detections): every detection rule and the exact signal it exploits.
- [Evasion catalog](https://kitsune.id/evasions): every anti-detect tool and technique tested, with verdicts.
- [Coverage matrix](https://kitsune.id/matrix): every detection rule x every evader.
- [Fleet & Skulk](https://kitsune.id/fleet): Skulk — the fleet adversary-emulation kit — and how the
  detector catches coordinated bot fleets by cross-session coherence (the axis per-session spoofing can't beat).
- [Frontier](https://kitsune.id/frontier): the live state of the detection-vs-evasion arms race.
- [Research](https://kitsune.id/research): findings from the detection-vs-evasion arms race.

## Source
- [Source on GitHub](https://github.com/datascry/kitsune): MIT — detector, edge, collector, evader fleet.
"""

#: Published doc pages: slug -> (markdown file, title, meta description). Internal docs are NOT listed.
DOC_PAGES: dict[str, tuple[str, str, str]] = {
    "matrix": (
        "matrix.md",
        "Detection matrix",
        "Which antidetect tools and bots Kitsune catches — per-evader verdicts and the tells that convict each.",
    ),
    "evasions": (
        "evasion-catalog.md",
        "Evasion catalog",
        "Every evasion technique in the red-team ladder and the anti-detect tools that implement it.",
    ),
    "detections": (
        "detection-catalog.md",
        "Detection catalog",
        "Every detection rule Kitsune runs and the exact signal it exploits, across all layers.",
    ),
    "how-it-works": (
        "architecture.md",
        "How it works",
        "Kitsune's architecture and the cross-layer incoherence thesis behind its bot detection.",
    ),
    "research": (
        "findings.md",
        "Research",
        "Findings from the Kitsune detection-vs-evasion arms race.",
    ),
    "fleet": (
        "fleet.md",
        "Fleet & Skulk",
        "Skulk — Kitsune's fleet adversary-emulation kit — and how the detector catches coordinated bot "
        "fleets by cross-session coherence, the axis per-session spoofing can't cheaply beat.",
    ),
    "frontier": (
        "frontier.md",
        "Frontier",
        "The live state of Kitsune's detection-vs-evasion arms race — what's saturated, what's an open "
        "vein, and what's blocked on external data.",
    ),
}


def _docs_dir() -> Path:
    env = os.environ.get("KITSUNE_DOCS_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "docs"


#: docs/*.md link to other repo files by relative path (../fleet/README.md, research-radar.md, a source
#: file). Those aren't served routes, so on the site they 404 — rewrite them to the file on GitHub instead.
_GH_BLOB = "https://github.com/datascry/kitsune/blob/main/"


def _rewrite_doc_link(match: re.Match[str]) -> str:
    href = match.group(1)
    if href.startswith(("http://", "https://", "#", "mailto:", "/")):
        return match.group(0)  # absolute, anchor, or already a site path — leave it
    frag = ""
    if "#" in href:
        href, frag = href.split("#", 1)
        frag = "#" + frag
    # The doc lives in docs/, so resolve the relative path against it, then point at the GitHub source.
    repo_path = posixpath.normpath(posixpath.join("docs", href)).lstrip("/")
    return f'href="{_GH_BLOB}{repo_path}{frag}"'


def render_markdown_doc(md_text: str) -> str:
    """Render a full markdown document to HTML for the doc shell — headings, lists, tables, fenced code,
    links and blockquotes all inherit the shared ``main.doc`` styling. Used for the general docs (fleet,
    frontier, …) that aren't one of the hand-curated / table-parsed pages. Relative links (to other docs or
    to source files, which aren't served routes) are rewritten to the file on GitHub so nothing dead-ends."""
    html_out = _markdown.markdown(
        md_text,
        extensions=["extra", "sane_lists", "admonition"],
        output_format="html",
    )
    return re.sub(r'href="([^"]+)"', _rewrite_doc_link, html_out)


#: Human names for URL path segments, for breadcrumbs + page titles in structured data.
_SECTION_NAMES: dict[str, str] = {
    "matrix": "Detection matrix",
    "evasions": "Evasion catalog",
    "detections": "Detection catalog",
    "how-it-works": "How it works",
    "research": "Research",
    "arena": "Arena",
    "gate": "Challenge",
}

#: Top-nav links shared across the doc pages (and mirrored in the live page's nav). Ordered to follow the
#: visitor journey: test → understand → explore the evidence catalogs → research.
#: A lean top nav: the two things a visitor DOES (test, arena), the pitch, one Docs home, and source. The
#: catalogs/fleet/frontier/research/API all live under the /docs hub instead of each taking a nav slot.
NAV_LINKS: list[tuple[str, str]] = [
    ("/arena", "Arena"),
    ("/how-it-works", "How it works"),
    ("/docs", "Docs"),
    ("https://github.com/datascry/kitsune", "GitHub"),
]

#: Everything that lives under the "Docs" nav item — so viewing any of these highlights Docs in the nav.
_DOCS_SECTION: tuple[str, ...] = (
    "/docs",
    "/matrix",
    "/detections",
    "/evasions",
    "/fleet",
    "/frontier",
    "/research",
    "/api",
)

DOC_CSS = (
    SHARED_CSS
    + """
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13.5px;line-height:1.6;-webkit-font-smoothing:antialiased;letter-spacing:.01em}
nav.top a.active,nav.top a[aria-current]{color:var(--fox)}
.crumbs{max-width:64rem;margin:0 auto;padding:.7rem 1.5rem 0;font-size:.74rem;color:var(--muted)}
.crumbs a{color:var(--muted);text-decoration:none}.crumbs a:hover{color:var(--fox)}
.crumbs .sep{color:var(--muted);margin:0 .4rem}
.filter-box{width:100%;max-width:24rem;box-sizing:border-box;padding:.5rem .7rem;margin:.4rem 0 1rem;border:1px solid var(--line-bright);background:var(--panel);color:var(--ink);font:inherit;border-radius:3px}
nav.top{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;max-width:64rem;margin:0 auto;padding:.9rem 1.5rem;border-bottom:1px solid var(--line)}
nav.top a{color:var(--muted);text-decoration:none;font-size:.78rem;letter-spacing:.06em}
nav.top a:hover{color:var(--fox)}
nav.top a.brand{display:flex;align-items:center;gap:.5rem;color:var(--ink);font-weight:700;letter-spacing:.22em;text-transform:uppercase;font-size:.95rem}
nav.top a.brand::before{content:"";width:.5rem;height:1.1rem;background:var(--fox)}
nav.top .spacer{flex:1}
main.doc{max-width:64rem;margin:0 auto;padding:1.5rem 1.5rem 3rem}
main.doc h1{font-family:var(--display);font-size:2.15rem;font-weight:700;line-height:1.08;letter-spacing:-.015em;margin:.5rem 0 1rem}
main.doc h2{font-size:1rem;text-transform:uppercase;letter-spacing:.1em;color:var(--ink);margin:2rem 0 .6rem;display:flex;align-items:center;gap:.6rem}
main.doc h2::before{content:"§";color:var(--fox)}
main.doc h3{font-size:.82rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:1.3rem 0 .4rem}
main.doc p,main.doc li{color:var(--muted)}
main.doc strong{color:var(--ink)}
main.doc em{color:var(--ink);font-style:italic}
main.doc a{color:var(--fox);text-decoration:none}
main.doc a:hover{text-decoration:underline}
/* Links inside prose carry a persistent underline — distinguishable without colour alone (WCAG 1.4.1). */
main.doc p a,main.doc li a,.lead a{text-decoration:underline;text-underline-offset:2px}
main.doc code{font-family:var(--mono);color:var(--fox);font-size:.92em;word-break:break-word}
main.doc pre{background:var(--panel-2);border:1px solid var(--line);padding:.8rem 1rem;overflow:auto}
main.doc pre code{color:var(--ink)}
main.doc table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.82rem;display:block;overflow-x:auto}
main.doc th,main.doc td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
main.doc th{color:var(--muted);text-transform:uppercase;font-size:.7rem;letter-spacing:.08em;white-space:nowrap}
main.doc blockquote{border-left:2px solid var(--fox);margin:1rem 0;padding:.2rem 0 .2rem 1rem}
main.doc hr{border:0;border-top:1px solid var(--line);margin:2rem 0}
footer{max-width:64rem;margin:0 auto;color:var(--muted);font-size:.78rem;border-top:1px solid var(--line);padding:1rem 1.5rem 2.5rem}
footer a{color:var(--fox);text-decoration:underline;text-underline-offset:2px}
/* --- customer-facing cards / badges / stats --- */
.lead{font-size:1.02rem;color:var(--ink);max-width:48rem;margin:.4rem 0 1rem}
.stat-row{display:flex;flex-wrap:wrap;gap:.8rem 2rem;margin:.4rem 0 1.4rem}
.stat{display:flex;flex-direction:column;line-height:1.1}
.stat strong{font-family:var(--display);font-size:2rem;color:var(--fox);letter-spacing:-.01em}
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
.lgrp>h3,.lgrp>h2.lgrp-h{display:flex;align-items:baseline;gap:.6rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.12em;color:var(--ink);margin:0 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.lgrp>h2.lgrp-h::before,.lgrp>h2.lgrp-h::after{content:none;display:none}
.lgrp>h3 .c,.lgrp>h2.lgrp-h .c{color:var(--muted);font-weight:400}
.rrow{display:flex;justify-content:space-between;align-items:baseline;gap:.6rem;padding:.35rem .1rem;border-bottom:1px solid var(--line);font-size:.84rem}
.rrow .rid{color:var(--fox);overflow-wrap:anywhere}
.rrow .rt{color:var(--muted);text-align:right;flex:1}
.chiplist{display:flex;flex-wrap:wrap;gap:.35rem .7rem;font-size:.82rem}.chiplist a{text-decoration:none}.chiplist a:hover code{text-decoration:underline}
@media (max-width:640px){.cards{grid-template-columns:1fr}.stat strong{font-size:1.5rem}.rrow{flex-direction:column;gap:.15rem}.rrow .rt{text-align:left}}
html,body{overflow-x:hidden;max-width:100%}
main.doc code,main.doc td,main.doc th,main.doc li,main.doc p{overflow-wrap:anywhere}
@media (max-width:640px){
  nav.top,main.doc,footer{padding-left:1rem;padding-right:1rem}
  .crumbs{padding-left:1rem;padding-right:1rem}
  nav.top{gap:.5rem .9rem}
  nav.top a{font-size:.72rem;min-height:44px;display:inline-flex;align-items:center}
  nav.top a.brand{font-size:.85rem;letter-spacing:.16em}
  main.doc h1{font-size:1.6rem}
  main.doc h2{font-size:.9rem}
  main.doc table{font-size:.74rem}
}
/* --- redesign: display face for heroes/verdicts. Space Grotesk if the visitor has it, else the mono at heavy
   weight — NO external font fetch (the footer promises no visitor data leaves the page). --- */
.display{font-family:"Space Grotesk",var(--mono);font-weight:700;letter-spacing:-.015em;color:var(--ink)}
main.doc h1.display{font-size:2.15rem;line-height:1.08;margin:.5rem 0 1rem}
main.doc h1.display .fox{color:var(--fox)}
/* --- redesign: detection matrix — a scannable table (suspicious-first), verdict pills + score bars --- */
table.mtx{width:100%;border-collapse:collapse;margin:.3rem 0 1.6rem;font-size:.82rem;display:table}
table.mtx thead th{text-align:left;color:var(--muted);text-transform:uppercase;font-size:.64rem;letter-spacing:.11em;font-weight:400;padding:.35rem .6rem;border-bottom:1px solid var(--line-bright);white-space:nowrap}
table.mtx td{padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:middle;overflow-wrap:anywhere}
table.mtx tbody tr:hover td{background:var(--panel)}
table.mtx a.ev{color:var(--ink);text-decoration:none;font-weight:600}
table.mtx tbody tr:hover a.ev{color:var(--fox)}
table.mtx .tells{color:var(--muted);font-size:.76rem}
.sbar{display:flex;align-items:center;gap:.55rem;min-width:9rem}
.sbar .trk{position:relative;flex:1;height:4px;min-width:3rem;background:var(--line);border-radius:2px;overflow:hidden}
.sbar .trk i{position:absolute;top:0;bottom:0;left:0;border-radius:2px}
.sbar .num{font-variant-numeric:tabular-nums;color:var(--muted);font-size:.74rem;min-width:2.4rem;text-align:right}
@media (max-width:720px){table.mtx,table.mtx thead,table.mtx tbody,table.mtx tr,table.mtx td{display:block}table.mtx thead{display:none}table.mtx tbody tr{border-bottom:1px solid var(--line-bright);padding:.55rem 0}table.mtx td{border:0;padding:.15rem .2rem}}
/* --- redesign: § filling-hairline layer headers (re-enable the § the lgrp-h base rule strips) --- */
.lgrp>h2.lgrp-h{border-bottom:0;padding-bottom:.15rem}
.lgrp>h2.lgrp-h::before{content:"§";color:var(--fox);display:inline;font-weight:400}
.lgrp>h2.lgrp-h .fill{flex:1;height:1px;min-width:1.5rem;background:var(--line);align-self:center}
"""
)


def _esc(s: str) -> str:
    # html.escape (not a hand-rolled .replace chain) so static analysis recognises it as an HTML sanitizer;
    # quote=True also escapes ' and " for attribute contexts (canonical/OG href + content).
    return html.escape(s, quote=True)


def _filter_ui(placeholder: str) -> str:
    """A client-side substring filter over a catalog's cards/rows — instant findability, no backend.

    Hides non-matching .card/.rrow items on input and collapses any .lgrp group left with no visible rows.
    """
    return (
        '<input class="filter-box" type="search" id="ks-filter" autocomplete="off" '
        f'aria-label="Filter this list" placeholder="{html.escape(placeholder)}">'
        "<script>(function(){var f=document.getElementById('ks-filter');if(!f)return;"
        "var items=document.querySelectorAll('main .card,main .rrow,main table.mtx tbody tr');"
        "f.addEventListener('input',function(){var q=f.value.toLowerCase(),i,it;"
        "for(i=0;i<items.length;i++){it=items[i];"
        "it.style.display=(!q||it.textContent.toLowerCase().indexOf(q)>=0)?'':'none';}"
        "var g=document.querySelectorAll('main .lgrp'),j,rows,any,k;"
        "for(j=0;j<g.length;j++){rows=g[j].querySelectorAll('.rrow');if(!rows.length)continue;any=false;"
        "for(k=0;k<rows.length;k++){if(rows[k].style.display!=='none'){any=true;break;}}"
        "g[j].style.display=any?'':'none';}});})();</script>"
    )


def _nav(current_path: str = "") -> str:
    links = ""
    for h, label in NAV_LINKS:
        if h == "/docs":  # the Docs hub lights up for any page that lives under it
            active = current_path.startswith(_DOCS_SECTION)
        else:
            active = h == current_path or (h != "/" and current_path.startswith(h))
        attr = ' class="active" aria-current="page"' if active else ""
        links += f'<a href="{h}"{attr}>{_esc(label)}</a>'
    return (
        f'<nav class="top" aria-label="Primary"><a class="brand" href="/">Kitsune</a>'
        f'{links}<span class="spacer"></span></nav>'
    )


#: Image dimensions of the shared OG card (static/og.png) — declared so crawlers don't have to fetch it.
_OG_W, _OG_H = "1200", "630"
_OG_ALT = "Kitsune — a bot detection ⇄ evasion lab"


def _crumbs(canonical_path: str, title: str) -> list[tuple[str, str]]:
    """Home → section → page crumbs (name, path) derived from the URL path."""
    crumbs = [("Home", "/")]
    segs = [s for s in canonical_path.split("/") if s]
    acc = ""
    for i, seg in enumerate(segs):
        acc += "/" + seg
        name = title if i == len(segs) - 1 else _SECTION_NAMES.get(seg, seg)
        crumbs.append((name, acc))
    return crumbs


def _breadcrumb(canonical_path: str, title: str) -> list[dict[str, Any]]:
    """The crumb trail as a BreadcrumbList rich result (JSON-LD)."""
    return [
        {"@type": "ListItem", "position": i + 1, "name": name, "item": f"{SITE_ORIGIN}{path}"}
        for i, (name, path) in enumerate(_crumbs(canonical_path, title))
    ]


def _crumbs_html(canonical_path: str, title: str) -> str:
    """The same crumb trail rendered visibly (the SEO data was emitted but never shown to humans)."""
    crumbs = _crumbs(canonical_path, title)
    if len(crumbs) < 2:
        return ""  # home / top level — no trail to show
    sep = '<span class="sep">/</span>'
    parts = [
        (f"<span>{_esc(name)}</span>" if i == len(crumbs) - 1 else f'<a href="{_esc(path)}">{_esc(name)}</a>')
        for i, (name, path) in enumerate(crumbs)
    ]
    return f'<nav class="crumbs" aria-label="Breadcrumb">{sep.join(parts)}</nav>'


def _ld_json(
    title: str,
    description: str,
    canonical_path: str,
    page_type: str,
    keywords: str | None,
    extra: list[dict[str, Any]] | None,
) -> str:
    """A JSON-LD ``@graph`` (WebSite + Organization + this page + breadcrumb, plus any extra nodes).

    Built with ``json.dumps`` (correct escaping) and a ``<`` → ``\\u003c`` pass so no field can close the
    script tag. Gives every doc/drill-down page the structured data the main page already had.
    """
    url = f"{SITE_ORIGIN}{canonical_path}"
    org = {
        "@type": "Organization",
        "@id": f"{SITE_ORIGIN}/#org",
        "name": "Kitsune",
        "url": f"{SITE_ORIGIN}/",
        "logo": {"@type": "ImageObject", "url": f"{SITE_ORIGIN}/icon-512.png"},
        "sameAs": ["https://github.com/datascry/kitsune"],
    }
    website = {
        "@type": "WebSite",
        "@id": f"{SITE_ORIGIN}/#website",
        "url": f"{SITE_ORIGIN}/",
        "name": "Kitsune",
        "description": "A bot detection ⇄ evasion lab: cross-layer fingerprint, TLS/JA4, HTTP-2, QUIC, "
        "TCP/IP and behavioral bot detection.",
        "publisher": {"@id": f"{SITE_ORIGIN}/#org"},
        "inLanguage": "en-US",
    }
    image = {
        "@type": "ImageObject",
        "url": f"{SITE_ORIGIN}/og.png",
        "width": _OG_W,
        "height": _OG_H,
    }
    page: dict[str, Any] = {
        "@type": page_type,
        "@id": f"{url}#webpage",
        "url": url,
        "name": f"{title} — Kitsune",
        "description": description,
        "isPartOf": {"@id": f"{SITE_ORIGIN}/#website"},
        "publisher": {"@id": f"{SITE_ORIGIN}/#org"},
        "primaryImageOfPage": image,
        "inLanguage": "en-US",
        "breadcrumb": {"@id": f"{url}#breadcrumb"},
    }
    if keywords:
        page["keywords"] = keywords
    breadcrumb = {
        "@type": "BreadcrumbList",
        "@id": f"{url}#breadcrumb",
        "itemListElement": _breadcrumb(canonical_path, title),
    }
    graph = {"@context": "https://schema.org", "@graph": [org, website, page, breadcrumb, *(extra or [])]}
    payload = json.dumps(graph, ensure_ascii=False).replace("<", "\\u003c")
    return f'<script type="application/ld+json">{payload}</script>'


def render_not_found(path: str = "/404") -> str:
    """A branded 404 page on the shared shell (noindex) — the friendly dead-end for a missing URL."""
    body = (
        '<h1 class="display">404 &mdash; the trail went cold</h1>'
        '<p class="lead">That page isn\'t here. A fox is good at leaving no tracks.</p>'
        "<p>Pick up the scent again:</p>"
        '<ul class="nf-links">'
        '<li><a href="/">Run the live bot-detection test</a> &mdash; fingerprint this browser, get a verdict.</li>'
        '<li><a href="/arena">Challenge the arena gates</a> &mdash; beat a gate, watch the detector convict anyway.</li>'
        '<li><a href="/how-it-works">How Kitsune works</a> &mdash; the cross-layer incoherence thesis.</li>'
        '<li><a href="/matrix">Detection matrix</a> &middot; <a href="/detections">detections</a> '
        '&middot; <a href="/evasions">evasions</a> &middot; <a href="/fleet">fleet &amp; Skulk</a></li>'
        "</ul>"
    )
    return render_doc_page(
        title="404 — not found",
        description="That page isn't here. Run the live bot-detection test, challenge the arena, or browse the catalogs.",
        canonical_path=path or "/404",
        body_html=body,
        noindex=True,
    )


#: The /docs hub: the single home for everything that isn't the tool or the arena — grouped so the nav
#: can stay lean. (path, name, one-line description) per card.
_DOCS_HUB: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        "Understand",
        [
            (
                "/how-it-works",
                "How it works",
                "The cross-layer incoherence thesis and the seven signal layers Kitsune scores.",
            ),
        ],
    ),
    (
        "Catalogs",
        [
            (
                "/matrix",
                "Detection matrix",
                "Every anti-detect tool run against the detector — verdicts and the tells that convict each.",
            ),
            (
                "/detections",
                "Detection catalog",
                "Every detection rule Kitsune runs and the exact signal it exploits, by layer.",
            ),
            (
                "/evasions",
                "Evasion catalog",
                "Every anti-detect tool and technique in the red-team ladder, with a plain description.",
            ),
        ],
    ),
    (
        "Coordination",
        [
            (
                "/fleet",
                "Fleet & Skulk",
                "The Skulk fleet adversary-emulation kit and cross-session coordination detection.",
            ),
            (
                "/frontier",
                "Frontier",
                "The live state of the detection-vs-evasion arms race — saturated, open, external-bound.",
            ),
        ],
    ),
    (
        "Reference",
        [
            ("/research", "Research", "Findings from the detection-vs-evasion arms race."),
            (
                "/api",
                "API reference",
                "Interactive OpenAPI / Swagger docs — POST to /ingest, read /rules.json.",
            ),
        ],
    ),
]


def render_docs_hub() -> str:
    """The /docs hub — one home for the catalogs, fleet/frontier, research and API, grouped into sections."""
    groups = []
    for section, items in _DOCS_HUB:
        cards = "".join(
            f'<a class="card" href="{h}"><div class="ct"><span class="cn">{_esc(name)}</span></div>'
            f'<div class="cd">{_esc(desc)}</div></a>'
            for h, name, desc in items
        )
        groups.append(
            f'<div class="lgrp"><h2 class="lgrp-h">{_esc(section)}</h2><div class="cards">{cards}</div></div>'
        )
    body = (
        '<h1 class="display">Documentation</h1>'
        '<p class="lead">Everything beyond the live test and the arena — how Kitsune works, the detection and '
        "evasion catalogs, the coordination-fleet work, research, and the API.</p>" + "".join(groups)
    )
    return render_doc_page(
        title="Documentation",
        description="Kitsune documentation: how it works, the detection/evasion catalogs, the coordination fleet, research, and the API.",
        canonical_path="/docs",
        body_html=body,
        page_type="CollectionPage",
    )


def render_doc_page(
    title: str,
    description: str,
    canonical_path: str,
    body_html: str,
    noindex: bool = False,
    page_type: str = "WebPage",
    keywords: str | None = None,
    extra_ld: list[dict[str, Any]] | None = None,
    extra_head: str = "",
) -> str:
    """Wrap ``body_html`` in the shared shell with a full per-page SEO head (noindex for thin pages).

    ``page_type`` sets the JSON-LD type (WebPage / CollectionPage / TechArticle); ``keywords`` and
    ``extra_ld`` enrich the structured data for catalog and drill-down pages. ``extra_head`` injects
    page-specific markup before ``</head>`` (e.g. a component ``<style>`` block for the arena widgets).
    """
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
        '<meta name="author" content="Kitsune">'
        f'<link rel="canonical" href="{url}">'
        f'<meta name="robots" content="{robots}">'
        '<meta name="googlebot" content="index, follow, max-image-preview:large, max-snippet:-1">'
        '<meta name="theme-color" content="#0a0a0c">'
        '<meta property="og:type" content="article"><meta property="og:site_name" content="Kitsune">'
        '<meta property="og:locale" content="en_US">'
        f'<meta property="og:title" content="{t} — Kitsune">'
        f'<meta property="og:description" content="{d}"><meta property="og:url" content="{url}">'
        f'<meta property="og:image" content="{SITE_ORIGIN}/og.png">'
        f'<meta property="og:image:width" content="{_OG_W}"><meta property="og:image:height" content="{_OG_H}">'
        f'<meta property="og:image:alt" content="{_esc(_OG_ALT)}">'
        '<meta name="twitter:card" content="summary_large_image">'
        f'<meta name="twitter:title" content="{t} — Kitsune"><meta name="twitter:description" content="{d}">'
        f'<meta name="twitter:image" content="{SITE_ORIGIN}/og.png">'
        f'<meta name="twitter:image:alt" content="{_esc(_OG_ALT)}">'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
        '<link rel="icon" href="/favicon.ico" sizes="any">'
        '<link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="manifest" href="/site.webmanifest">'
        f"{_ld_json(title, description, canonical_path, page_type, keywords, extra_ld)}"
        f"<style>{DOC_CSS}</style>{extra_head}</head><body>"
        '<a class="skip-link" href="#main">Skip to content</a>'
        f"{_nav(canonical_path)}{_crumbs_html(canonical_path, title)}"
        f'<main id="main" class="doc">{body_html}</main>'
        '<footer><p>The blue-team side of a <a href="https://github.com/datascry/kitsune">bot detection ⇄ '
        "evasion lab</a>. <strong>No visitor data is captured</strong> "
        '(<a href="https://github.com/datascry/kitsune/blob/main/docs/privacy.md">privacy</a>). '
        '<a href="/">Run the live test →</a></p></footer></body></html>'
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
        '<h1 class="display">Detection catalog</h1>',
        '<p class="lead">Every check Kitsune runs, by layer. A '
        '<strong style="color:var(--fox)">convicting</strong> check — a cross-layer contradiction, an automation '
        "artifact, a forged native — can call a session a bot on its own. The rest only add weight.</p>",
        '<div class="stat-row">'
        f'<div class="stat"><strong>{len(rules)}</strong><span>checks</span></div>'
        f'<div class="stat"><strong>{convicting}</strong><span>convicting</span></div>'
        f'<div class="stat"><strong>{len([k for k in groups if groups[k]])}</strong><span>layers</span></div>'
        "</div>",
        _filter_ui("Filter checks by rule id or title…"),
    ]
    for key in ["cross-layer", *layers]:
        grp = groups.get(key) or []
        if not grp:
            continue
        rows = "".join(
            f'<div class="rrow"><span class="rid">'
            f'<a href="/detections/{html.escape(r["id"])}"><code>{html.escape(r["id"])}</code></a> '
            f'<span class="badge {"convicting" if r.get("convicting") else "corroborating"}">'
            f"{'convicts' if r.get('convicting') else 'corrob.'}</span></span>"
            f'<span class="rt">{html.escape(r.get("title", ""))}</span></div>'
            for r in sorted(grp, key=lambda r: (not r.get("convicting"), r["id"]))
        )
        body.append(
            f'<div class="lgrp"><h2 class="lgrp-h">{html.escape(key)} '
            f'<span class="c">{len(grp)}</span><span class="fill"></span></h2>{rows}</div>'
        )
    return "".join(body)


#: verdict -> the CSS colour var (used for pills + score-bar fill; bot=fox, suspicious=amber, human=jade).
_VERDICT_VAR = {"bot": "var(--fox)", "suspicious": "var(--amber)", "human": "var(--jade)"}


def _score_frac(score: str) -> float:
    """Parse a matrix score cell (e.g. '0.49', '1.00', 'n/a') to a 0..1 fraction; 0.0 if unparseable."""
    try:
        return max(0.0, min(1.0, float(score)))
    except (TypeError, ValueError):
        return 0.0


def render_matrix_page(md: str) -> str:
    """A scannable per-evader matrix from the verdict table — verdict pills + score bars, the near-miss
    (suspicious) rows sorted FIRST since the tools that almost evade are the story."""
    _, rows = _md_table(md, "Per-evader verdict")
    verdict_rows = [r for r in rows if len(r) >= 5]
    caught = sum(1 for r in verdict_rows if r[1] == "bot")
    susp = sum(1 for r in verdict_rows if r[1] == "suspicious")
    # suspicious first (by ascending score within), then everything else by ascending score
    verdict_rows.sort(key=lambda r: (r[1] != "suspicious", _score_frac(r[2])))
    body = []
    for name, verdict, score, _fired, tells in ((r[0], r[1], r[2], r[3], r[4]) for r in verdict_rows):
        col = _VERDICT_VAR.get(verdict, "var(--muted)")
        pct = round(_score_frac(score) * 100)
        bar = (
            f'<span class="sbar"><span class="trk"><i style="width:{pct}%;background:{col}"></i></span>'
            f'<span class="num">{pct}%</span></span>'
        )
        body.append(
            f'<tr><td><a class="ev" href="/evasions/{html.escape(_slug(name))}">{_cellhtml(name)}</a></td>'
            f'<td><span class="badge {html.escape(verdict)}">{html.escape(verdict)}</span></td>'
            f"<td>{bar}</td>"
            f'<td class="tells">{_cellhtml(tells)}</td></tr>'
        )
    table = (
        '<table class="mtx"><thead><tr><th>Evader</th><th>Verdict</th><th>Score</th>'
        f"<th>Convicting tells</th></tr></thead><tbody>{''.join(body)}</tbody></table>"
    )
    return (
        '<h1 class="display">Detection matrix</h1>'
        '<p class="lead">Real anti-detect tools and stealth browsers, run against the detector — one row '
        "each. You get its verdict, its coherence score, and exactly which <em>tells</em> gave it away. The "
        '<span style="color:var(--amber)">suspicious</span> near-misses sort to the top. For what each tool '
        'actually is, see the annotated <a href="/evasions">evasion catalog</a>.</p>'
        '<div class="stat-row">'
        f'<div class="stat"><strong>{len(verdict_rows)}</strong><span>evaders</span></div>'
        f'<div class="stat"><strong>{caught}</strong><span>caught (bot)</span></div>'
        f'<div class="stat"><strong style="color:var(--amber)">{susp}</strong><span>suspicious</span></div>'
        "</div>"
        f"{_filter_ui('Filter evaders by name or tell…')}"
        f"{table}"
    )


def render_evasions_page(evaders: dict[str, dict[str, Any]]) -> str:
    """Every evader *config* (96) — fleet tools, technique probes and mode variants — each with a
    verdict badge and a real description, linking to its drill-down."""
    cards = []
    caught = susp = 0
    for slug in sorted(evaders):
        ev = evaders[slug]
        verdict = str(ev.get("verdict", "")).strip()
        if verdict == "bot":
            caught += 1
        elif verdict == "suspicious":
            susp += 1
        cards.append(
            f'<a class="card" href="/evasions/{html.escape(slug)}"><div class="ct">'
            f'<span class="cn">{html.escape(slug)}</span>'
            f'<span class="badge {html.escape(verdict)}">{html.escape(verdict)}</span></div>'
            f'<div class="cd">{html.escape(evader_description(slug))}</div></a>'
        )
    return (
        '<h1 class="display">Evasion catalog</h1>'
        '<p class="lead">Every red-team configuration Kitsune tests itself against — real anti-detect '
        "tools, stealth browsers, TLS/HTTP forgers and single-surface technique probes — each with a plain "
        "description. For the exact tells that caught each, see the "
        '<a href="/matrix">detection matrix</a>.</p>'
        '<div class="stat-row">'
        f'<div class="stat"><strong>{len(evaders)}</strong><span>configs</span></div>'
        f'<div class="stat"><strong>{caught}</strong><span>caught (bot)</span></div>'
        f'<div class="stat"><strong>{susp}</strong><span>suspicious</span></div>'
        "</div>"
        f"{_filter_ui('Filter evaders by name or description…')}"
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


def render_research_page(rules_total: int = 0, evaders_caught: int = 0, evaders_total: int = 0) -> str:
    """A concise findings overview (not the 99KB findings doc). Stats are passed in live from the registry +
    matrix so they never drift from /detections and /matrix (the hardcoded 127/7 once contradicted them)."""
    cards = "".join(
        f'<div class="card"><div class="ct"><span class="cn">{html.escape(t)}</span></div>'
        f'<div class="cd">{html.escape(d)}</div></div>'
        for t, d in _FINDINGS
    )
    caught_stat = f"{evaders_caught}/{evaders_total}" if evaders_total else "—"
    rules_stat = str(rules_total) if rules_total else "—"
    return (
        "<h1>Research</h1>"
        '<p class="lead">What Kitsune has actually measured, running real anti-detect tools through the live '
        "edge → detector. The thesis holds: <strong>incoherence across layers — not any single bad signal — "
        "is what survives anti-detect tooling.</strong></p>"
        '<div class="stat-row">'
        f'<div class="stat"><strong>{caught_stat}</strong><span>evaders caught</span></div>'
        f'<div class="stat"><strong>{rules_stat}</strong><span>detection rules</span></div>'
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


def parse_techniques(md: str) -> dict[str, dict[str, Any]]:
    """From evasion-catalog.md 'Techniques exercised': slug -> {verdict, tells (FULL list), evades}.

    Richer than matrix.md's per-evader column (which truncates the tells); also flags EVADES cases.
    """
    tech: dict[str, dict[str, Any]] = {}
    _, rows = _md_table(md, "Techniques exercised")
    for r in rows:
        if len(r) < 3:
            continue
        cell = r[2]
        tech[_slug(r[0])] = {
            "verdict": r[1].strip(),
            "tells": re.findall(r"`([^`]+)`", cell),
            "evades": "EVADES" in cell,
        }
    return tech


def reverse_index(tech: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """rule_id -> sorted list of evader slugs whose convicting tells include it (for detection pages)."""
    idx: dict[str, list[str]] = {}
    for slug, t in tech.items():
        for rule_id in t.get("tells", []):
            idx.setdefault(rule_id, []).append(slug)
    for rule_id in idx:
        idx[rule_id] = sorted(set(idx[rule_id]))
    return idx


def bypass_index(tech: dict[str, dict[str, Any]], rules_by_id: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """rule_id -> the FRONTIER evaders that this check does NOT stop (the honest arms-race inverse).

    A "bypass" is only meaningful for an evader that actually reaches the detector uncaught — one scored
    ``suspicious`` / that EVADES conviction (no single convicting tell). An evader scored ``bot`` was stopped
    by *some* tell, so it did not bypass the detector; and an evader that is merely coherent on this rule's
    axis (nothing to catch) is not "bypassing" it either — which is why this is scoped to the frontier rather
    than to every evader the rule happens not to fire on. Each frontier evader is listed under every rule that
    did not flag it: the red-team targets this specific detection still has to convict.
    """
    frontier = [
        slug for slug, t in tech.items() if t.get("evades") or str(t.get("verdict", "")).strip() == "suspicious"
    ]
    idx: dict[str, list[str]] = {}
    for rid in rules_by_id:
        missed = sorted(s for s in frontier if rid not in set(tech[s].get("tells") or []))
        if missed:
            idx[rid] = missed
    return idx


#: Hand-authored, customer-facing descriptions per evader tool — what it actually is and how it evades
#: (the fleet table's one-liners are terse internal headers). Mode variants resolve to their base tool.
EVADER_DESCRIPTIONS: dict[str, str] = {
    "agent": "An LLM agent that drives a remote Chromium with model-chosen actions — realistic, "
    "human-like automation rather than a fixed script.",
    "apify-fp-inject": "Playwright Chromium with an Apify-style fingerprint overlay injected over the real "
    "browser — it spoofs JS-visible surfaces while the underlying engine stays Chromium.",
    "azuretls": "A Go HTTP client (azuretls) that forges a real browser's TLS (JA3/JA4) and HTTP/2 "
    "fingerprint with no browser engine at all — pure wire-layer impersonation.",
    "brave": "The real Brave browser, which farbles canvas and audio by design as a privacy feature — a "
    "legitimate human browser, used as a control to keep the detector honest.",
    "camoufox": "Engine-level anti-detect Firefox: it patches the Gecko C++ engine itself instead of "
    "injecting JavaScript, so the spoof leaves no JS-detectable seams. The hardest case in the fleet.",
    "curl-impersonate": "curl_cffi / curl-impersonate — an HTTP client that replays a real browser's exact "
    "TLS and HTTP/2 fingerprint with no browser and no JavaScript execution.",
    "firefox-os-spoof": "A Firefox automation that fakes its User-Agent OS but forgets to spoof "
    "navigator.oscpu — a deliberate cross-layer coherence break.",
    "go-tls": "Forges a real-browser TLS ClientHello with uTLS (Go) — a pure wire-layer JA3/JA4 spoof, no "
    "browser engine.",
    "h2-rapid-reset": "Not a stealth tool: an HTTP/2 frame-abuse flooder (rapid-reset CVE-2023-44487, "
    "CONTINUATION flood, control-frame floods) that pressure-tests the edge's DoS detection.",
    "mobile-emulation": "Desktop Chromium emulating an Android phone via Playwright's Pixel 5 device — tests "
    "whether a mobile UA and viewport stay coherent with a desktop stack.",
    "nodriver": "The successor to undetected-chromedriver: drives Chrome directly over CDP with no "
    "Selenium/webdriver surface at all, async-first.",
    "playwright-extra": "Playwright plus puppeteer-extra-plugin-stealth — a stack of JavaScript patches that "
    "mask the common headless and automation tells.",
    "pow": "A proof-of-work challenge primitive (anubis / friendlycaptcha / altcha families) — exercises "
    "PoW-style anti-bot gates rather than fingerprint evasion.",
    "primp": "A browser-impersonating HTTP client: forges the TLS and HTTP/2 stack of a real browser for a "
    "single request, with no JavaScript.",
    "pydoll": "Async, CDP-native Python automation with no webdriver dependency — drives Chrome through the "
    "DevTools protocol directly.",
    "selenium-driverless": "Selenium-style automation driven purely over CDP, avoiding the WebDriver "
    "protocol that classic Selenium leaks.",
    "stealth": "A plain real Chromium driven through the edge — the baseline 'just a real browser, automated' case.",
    "undetected": "undetected-chromedriver — a patched ChromeDriver that strips the classic Selenium/CDP "
    "webdriver giveaways.",
    "vanilla": "A single plain HTTP request through the edge — the no-evasion baseline everything else is "
    "measured against.",
    "webkit-ua-spoof": "A WebKit-engine bot faking a Chrome User-Agent — its TLS/engine fingerprint "
    "contradicts the claimed browser.",
    "xtest-coalesce": "A pressure-test: injects mouse motion via X11 XTEST to see whether synthetic input "
    "can defeat the coalesced-pointer-events tell.",
    "zendriver": "A maintained successor to nodriver — CDP-native Chrome automation with no webdriver surface.",
}


#: Hand-authored descriptions for the standalone *technique* tests (matrix configs that aren't a fleet
#: tool, e.g. canvas-lie, electron-leak). Each is a captured session probing one detection surface.
_TECHNIQUE_DESCRIPTIONS: dict[str, str] = {
    "accept-lang-spoof": "A headless Chromium that forges its Accept-Language header out of step with "
    "navigator.languages — a network-vs-JavaScript language mismatch.",
    "audio-noise": "A bot that adds random noise to the Web Audio fingerprint to defeat audio hashing — "
    "the injected noise signature is itself the tell.",
    "audio-readback-spoof": "Spoofs the AudioBuffer read-back values to fake a stable audio fingerprint; "
    "the readback noise gives it away.",
    "baseline-firefox": "A plain automated Firefox with no stealth — the WebDriver flag is left exposed. "
    "A control case.",
    "brave-fake": "A non-Brave browser faking Brave's farbling and brave APIs — the spoofed Brave "
    "identity is itself detectable.",
    "brave-fake-proxy": "A non-Brave browser faking Brave, relayed through a proxy — the spoofed Brave "
    "identity still shows through.",
    "canvas-geometry-spoof": "Perturbs canvas geometry (text and shape metrics) to dodge canvas hashing; "
    "the geometry noise is detectable.",
    "canvas-lie": "Returns a fixed, fabricated canvas image instead of rendering — a toDataURL the engine "
    "never actually produced.",
    "canvas-spoof": "Injects per-pixel noise into the canvas to randomize its hash; the noise and the "
    "worker-vs-main mismatch convict it.",
    "cdc-leak": "An automated Chrome still carrying the `cdc_` ChromeDriver artifact variables — the "
    "classic Selenium leak.",
    "ch-ua-hardcoded": "An HTTP client with a hardcoded Client-Hints brand list that lacks the GREASE "
    "brand a real Chrome always emits.",
    "chrome-clone-1": "A cloned Chrome fingerprint replayed across sessions (clone 1 of a coordinated "
    "pair) — the collision with its twin is the durable tell.",
    "chrome-clone-2": "The second member of a cloned-Chrome fleet — its fingerprint collides with "
    "clone 1 across sessions.",
    "coalesce-proxy": "Injects synthetic pointer events through a proxy; the coalesced events are "
    "untrusted (isTrusted=false).",
    "coalesce-spoof": "Fakes coalesced pointer events to mimic high-frequency mouse input; the toString "
    "patch betrays the spoof.",
    "csp-bypass": "A bot that bypasses the page Content-Security-Policy to inject its automation hooks — "
    "the bypass is observable.",
    "curl-http2": "curl driving raw HTTP/2 with a browser User-Agent — its header order, TLS and TCP "
    "stack all contradict the claimed Chrome.",
    "datacenter-origin-proxied": "Traffic relayed from a datacenter origin through a proxy — the true "
    "origin still reads as datacenter despite the exit node.",
    "domrect-spoof": "Spoofs getBoundingClientRect to fake element geometry; the DOMRect values are "
    "invariant where a real layout varies.",
    "electron-leak": "An Electron-app bot leaking its process and automation globals — it reports as "
    "Chrome but the Electron runtime shows through.",
    "firefox-coherent": "A carefully coherent automated Firefox — every spoof lines up except the "
    "exposed WebDriver flag.",
    "floor-spoof": "A minimal 'floor' spoof patching only the obvious tells (webdriver, notifications); "
    "the patched getters' toString gives it away.",
    "font-os-leak": "Its installed-font set and Client-Hints betray a different OS than the User-Agent claims.",
    "fp-rotation": "Rotates its fingerprint mid-session to dodge hashing — the within-session "
    "instability is itself the tell.",
    "full-stealth": "A maximal stealth stack patching dozens of surfaces at once; the WebGL and "
    "worker-realm spoofs still diverge.",
    "h2-continuation-flood": "An HTTP/2 CONTINUATION-frame flood (DoS) — exercises the edge's "
    "frame-abuse detection, not fingerprint evasion.",
    "h2-control-flood": "An HTTP/2 control-frame flood (PING/SETTINGS abuse) pressure-testing the edge's DoS guard.",
    "h2-settings-split": "Sends HTTP/2 SETTINGS out of the expected order — a frame-sequence tell "
    "mismatched with the claimed browser.",
    "honeypot": "A bot that interacts with hidden honeypot elements a human would never see or click.",
    "http2-naive": "A naive HTTP/2 client with a browser User-Agent but mismatched header order, TLS and TCP stack.",
    "human-mouse": "Automation replaying recorded human mouse traces — the motion looks human but the "
    "headless/CDP surface still convicts.",
    "iframe-spoof": "Patches the main realm but not nested iframes; the iframe realm reports different "
    "values — a realm divergence.",
    "ios-ua-spoof": "Claims to be Safari on iOS while running a non-WebKit engine — an Apple UA without "
    "the matching WebKit APIs.",
    "ip-rotation": "Rotates its source IP within a single session — the address changes mid-session "
    "where a real client's would not.",
    "keystroke-human": "Replays human-like keystroke timing, but the headless/CDP runtime underneath "
    "still gives it away.",
    "lang-list-spoof": "navigator.language disagrees with navigator.languages — the singular value and "
    "the list contradict.",
    "lang-spoof": "Spoofs the page language, but the Worker realm reports a different language than the main thread.",
    "linear-bot": "A bot moving the cursor in perfectly straight, constant-velocity lines — non-human "
    "kinematics over a headless base.",
    "max-stealth": "An aggressive stealth profile spoofing the webdriver flag and chrome object; the "
    "spoof's own seams remain.",
    "measuretext-spoof": "Spoofs Canvas measureText metrics; they disagree with the OffscreenCanvas "
    "measurement of the same text.",
    "naive-tz-spoof": "Naively overrides the timezone — the offset, Intl zone and Worker-realm timezone all disagree.",
    "native-spoof": "Overrides native functions to fake values, but violates a native invariant the "
    "real engine always preserves.",
    "os-spoof": "Claims a different OS than its real platform — navigator.platform, WebGL and the TCP "
    "stack betray the true one.",
    "patchright": "Patchright (a patched Playwright) — strips many headless tells, but the Client-Hints "
    "headless markers remain.",
    "patchright-headful": "Patchright run headful — reaches only suspicious, with no single convicting "
    "tell. A frontier case.",
    "quic-no-grease": "A QUIC/HTTP-3 client whose ClientHello omits the GREASE values a real browser always includes.",
    "rebrowser": "Rebrowser-patches stealth Chromium — masks the common automation tells but leaves "
    "headless and webdriver traces.",
    "renderer-spoof": "Spoofs the WebGL renderer string; the getParameter patch and the worker-realm "
    "renderer disagree.",
    "screen-impossible": "Reports screen dimensions that cannot physically exist (e.g. available larger "
    "than total) — an impossible display.",
    "spoof-ua": "Claims one browser in its User-Agent while the engine, TLS and HTTP/2 stack describe another.",
    "stale-engine": "Its User-Agent claims a current version but the engine feature-set is from an older "
    "build — a stale template.",
    "tls-stale-template": "Replays a real browser's TLS fingerprint from an outdated template — the "
    "GREASE and key-share no longer match the claimed UA.",
    "trace-replay": "Replays a recorded behavioral trace verbatim — identical within-session repetition "
    "betrays the replay.",
    "tz-spoof": "Spoofs the timezone; the offset, the Intl resolved zone and the Worker-realm timezone "
    "contradict each other.",
    "ua-rotation": "Rotates its User-Agent within one session — the UA changes mid-session where a real "
    "client's stays fixed.",
    "uach-coherent": "A bot that makes its Client-Hints internally coherent, yet the automation runtime "
    "(CDP/webdriver) still shows.",
    "webkit-safari-coherent": "A coherent WebKit/Safari profile — but its fonts, platform, TLS and "
    "HTTP/2 stack still betray the real OS.",
    "webrtc-leak": "Leaks its real IP via WebRTC despite a proxy — reaches only suspicious, a frontier "
    "corroborating case.",
    "webrtc-origin-datacenter": "A WebRTC candidate revealing a datacenter origin behind the proxied connection.",
    "worker-proxy": "Proxies Worker-thread calls back to the main realm to hide divergence; the Worker "
    "constructor patch shows.",
    "worker-proxy-fix": "A refined Worker proxy that rewrites the worker source to hide the seam — the "
    "rewrite is itself detectable.",
    "worker-spoof": "Spoofs the main thread, but the Worker realm still diverges from it.",
    "worker-wrap": "Wraps the Worker constructor to intercept realm checks — the tampered constructor is the tell.",
}

#: Suffix → clause appended to a base tool's description for a mode variant (zendriver-uach-behave →
#: zendriver's description + "spoofing UA Client-Hints with humanized behaviour").
_MODE_NOTES: dict[str, str] = {
    "fake": "faking the identity rather than running the real browser",
    "fake-proxy": "faking the identity, relayed through a proxy",
    "hardened": "with maximum anti-detect hardening",
    "hardened-behave": "hardened and driven with humanized behaviour",
    "headful": "run headful, with a real display",
    "linux": "on Linux",
    "linux-coherent": "on Linux, kept cross-layer coherent",
    "macos": "on macOS",
    "socks-webrtc": "behind a SOCKS proxy with WebRTC masking",
    "touch-incoherent": "with a deliberately incoherent touch/pointer profile",
    "h2-rotate": "rotating its HTTP/2 fingerprint mid-session",
    "rotate": "rotating its TLS/JA4 fingerprint mid-session",
    "coherent": "with its cross-layer values kept coherent",
    "naive": "with only naive patches applied",
    "patched": "with extra stealth patches applied",
    "uach": "spoofing UA Client-Hints",
    "uach-behave": "spoofing UA Client-Hints with humanized behaviour",
}


def _humanize(slug: str) -> str:
    """Last-resort readable description from a slug (every known config has an authored entry above)."""
    return f"A red-team configuration exercising the {slug.replace('-', ' ')} technique."


def evader_description(slug: str, fallback: str = "") -> str:
    """Curated description for any evader config — fleet tool, standalone technique, or a mode variant.

    Mode variants (camoufox-hardened, zendriver-uach-behave) resolve to the base tool's description
    and append a mode-specific clause, so every one of the matrix configs gets a real description.
    """
    if slug in EVADER_DESCRIPTIONS:
        return EVADER_DESCRIPTIONS[slug]
    if slug in _TECHNIQUE_DESCRIPTIONS:
        return _TECHNIQUE_DESCRIPTIONS[slug]
    parts = slug.split("-")
    while len(parts) > 1:
        parts = parts[:-1]
        base = "-".join(parts)
        if base in EVADER_DESCRIPTIONS:
            desc = EVADER_DESCRIPTIONS[base]
            note = _MODE_NOTES.get(slug[len(base) + 1 :])
            return f"{desc.rstrip('.')} — {note}." if note else desc
    return fallback or _humanize(slug)


def _chiplist(items: list[str], href: str) -> str:
    links = " ".join(f'<a href="{href}{html.escape(s)}"><code>{html.escape(s)}</code></a>' for s in items)
    return f'<div class="chiplist">{links}</div>'


def render_evasion_detail(
    slug: str,
    ev: dict[str, Any] | None,
    fleet: dict[str, str] | None,
    tech: dict[str, Any] | None,
    rules: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """One evader: what it is, its verdict, and the FULL convicting-tell list (linking to detections)."""
    if ev is None and fleet is None and tech is None:
        return None
    verdict = (tech or {}).get("verdict") or (ev or {}).get("verdict")
    parts = [f"<h1>{html.escape(slug)}</h1>"]
    desc = evader_description(slug, fleet["what"] if fleet else "")
    if desc:
        parts.append(f'<p class="lead">{html.escape(desc)}</p>')
    stats = ""
    if verdict:
        stats += f'<div class="stat"><strong>{html.escape(str(verdict))}</strong><span>verdict</span></div>'
    if ev:
        stats += f'<div class="stat"><strong>{html.escape(ev["score"])}</strong><span>score</span></div>'
        stats += f'<div class="stat"><strong>{html.escape(ev["fired"])}</strong><span>checks fired</span></div>'
    if fleet:
        stats += f'<div class="stat"><strong>{html.escape(fleet["lang"])}</strong><span>language</span></div>'
    if stats:
        parts.append(f'<div class="stat-row">{stats}</div>')
    if tech and tech.get("evades"):
        parts.append(
            '<p class="lead">⚠ This evader <strong>evades conviction</strong> — it reaches only '
            "<em>suspicious</em>, with no single convicting tell. It is the frontier the detector is still "
            "chasing.</p>"
        )
    tells = (tech or {}).get("tells") or (ev or {}).get("tells") or []
    if tells:
        rules = rules or {}
        rows = "".join(
            f'<div class="rrow"><span class="rid">'
            f'<a href="/detections/{html.escape(t)}"><code>{html.escape(t)}</code></a></span>'
            f'<span class="rt">{html.escape(str(rules.get(t, {}).get("title", "")))}</span></div>'
            for t in tells
        )
        parts.append(
            f'<div class="lgrp"><h2 class="lgrp-h">Convicting tells <span class="c">{len(tells)}</span></h2>{rows}</div>'
        )
    parts.append(
        '<p class="lead"><a href="/evasions">← all evaders</a> &nbsp;·&nbsp; <a href="/matrix">the detection matrix</a></p>'
    )
    return "".join(parts)


def render_detection_detail(
    rule: dict[str, Any] | None,
    catch_count: str | None,
    caught: list[str] | None = None,
    bypassed: list[str] | None = None,
) -> str | None:
    """One detection rule: what it catches, the signals it reads, how it fires, who it caught — and who slips past."""
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
    if caught:
        parts.append(
            f'<div class="lgrp"><h2 class="lgrp-h">Evaders it caught <span class="c">{len(caught)}</span></h2>'
            f"{_chiplist(caught, '/evasions/')}</div>"
        )
    if bypassed and convicts:
        parts.append(
            f'<div class="lgrp"><h2 class="lgrp-h">Bypassed by <span class="c">{len(bypassed)}</span></h2>'
            f'<p class="lead">Frontier evaders that reach the detector <em>uncaught</em> (scored only '
            f"<em>suspicious</em>, defeating every convicting tell) — this check is not one that stops them. "
            f"The red-team frontier this detection still has to convict.</p>"
            f"{_chiplist(bypassed, '/evasions/')}</div>"
        )
    parts.append('<p class="lead"><a href="/detections">← all detections</a></p>')
    return "".join(parts)
