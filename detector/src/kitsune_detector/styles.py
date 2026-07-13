# detector/styles — the shared CSS foundation for the live page and the doc pages.
# One source for design tokens + a11y rules so the two surfaces (demo.py, pages.py) can't drift apart.

#: Design tokens (colour palette + a documented 7-step type scale) + box-sizing reset + the
#: keyboard-accessibility rules (focus-visible, skip link). These are byte-identical across the homepage
#: (``demo.py``) and the doc-page shell (``pages.py``); both inject this constant instead of redeclaring it,
#: which is what stops the colour/contrast drift the UX review flagged. Page-specific rules (the verdict
#: panels, the doc cards, etc.) stay in each module — only the shared foundation lives here.
#:
#: ``demo.py`` substitutes the ``/*__SHARED_CSS__*/`` placeholder in its inline <style>; ``pages.py``
#: prepends it to ``DOC_CSS``.
SHARED_CSS = """\
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/jetbrains-mono-400.woff2) format("woff2")}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:500;font-display:swap;src:url(/fonts/jetbrains-mono-500.woff2) format("woff2")}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-weight:700;font-display:swap;src:url(/fonts/jetbrains-mono-700.woff2) format("woff2")}
@font-face{font-family:"Space Grotesk";font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/space-grotesk-400.woff2) format("woff2")}
@font-face{font-family:"Space Grotesk";font-style:normal;font-weight:500;font-display:swap;src:url(/fonts/space-grotesk-500.woff2) format("woff2")}
@font-face{font-family:"Space Grotesk";font-style:normal;font-weight:600;font-display:swap;src:url(/fonts/space-grotesk-600.woff2) format("woff2")}
@font-face{font-family:"Space Grotesk";font-style:normal;font-weight:700;font-display:swap;src:url(/fonts/space-grotesk-700.woff2) format("woff2")}
:root{--bg:#0a0a0c;--panel:#0e0e12;--panel-2:#121218;--line:#20202a;--line-bright:#45454f;--ink:#eae7df;--muted:#8a8a97;--fox:#e8482b;--jade:#5fb89a;--amber:#d6a44e;--display:"Space Grotesk",var(--mono);--mono:"JetBrains Mono",ui-monospace,"SF Mono","Menlo","Consolas","Liberation Mono",monospace;--fs-xs:.68rem;--fs-sm:.78rem;--fs-base:.84rem;--fs-md:.92rem;--fs-lg:1.05rem;--fs-xl:1.4rem;--fs-2xl:2rem}
*{box-sizing:border-box}
a:focus-visible,button:focus-visible,summary:focus-visible,input:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--fox);outline-offset:2px;border-radius:2px}
.skip-link{position:absolute;left:-9999px;top:0;background:var(--fox);color:var(--bg);padding:.5rem .9rem;z-index:100;font-weight:700}
.skip-link:focus{left:.5rem;top:.5rem}
abbr[title]{text-decoration:underline dotted;text-underline-offset:2px;cursor:help}
"""
