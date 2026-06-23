# detector/pages — themed HTML shell for the markdown-rendered doc pages.
# Wraps rendered markdown in the forensic shell (nav + footer + per-page SEO head), reusing the palette.

"""Shared shell for the doc pages (/matrix, /evasions, /detections, /how-it-works, /research).

The detector renders selected ``docs/*.md`` to HTML at request time and wraps them here so they share
the live page's forensic aesthetic, navigation, and SEO scaffolding (title/description/canonical/OG).
"""

from __future__ import annotations

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
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


def _nav() -> str:
    links = "".join(f'<a href="{h}">{_esc(label)}</a>' for h, label in NAV_LINKS)
    return f'<nav class="top"><a class="brand" href="/">Kitsune</a>{links}<span class="spacer"></span></nav>'


def render_doc_page(title: str, description: str, canonical_path: str, body_html: str) -> str:
    """Wrap rendered-markdown ``body_html`` in the shared shell with per-page SEO head."""
    t, d = _esc(title), _esc(description)
    url = f"{SITE_ORIGIN}{canonical_path}"
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{t} — Kitsune</title>"
        f'<meta name="description" content="{d}">'
        f'<link rel="canonical" href="{url}">'
        '<meta name="robots" content="index, follow"><meta name="theme-color" content="#0a0a0c">'
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
