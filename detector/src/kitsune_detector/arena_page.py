# detector/arena_page — the public /arena: an index of challenge gates, each on its own page.
# Reuses the doc-page shell (nav + footer + design system) so every gate renders in the site's aesthetic.

"""The ``/arena`` section — a live, interactive reproduction of documented OPEN web challenge mechanisms.

The arena is now a small site of its own: ``/arena`` lists every gate as a card, and each gate gets its
own page at ``/arena/gate/<slug>`` with just that challenge's widget plus the dual verdict (the gate's: did
you solve it? — and the detector's: does your client cohere?). Every page is built on the shared doc-page
shell (:func:`kitsune_detector.pages.render_doc_page`), so it carries the site nav, footer, SEO head, and —
crucially — the full design system, instead of the half-styled standalone page this used to be.

The gates only ever model documented, open mechanisms and only ever talk to the owned ``arena`` service
(relayed by the detector); the page carries a vendor-neutral disclaimer. The thesis the arena makes live:
a solved challenge is a *cost* or *Turing* test, not a bot/human discriminator — a script can pass the gate
and still be convicted on the network layer. Coherence + attestation is the durable signal, not the puzzle.
"""

from __future__ import annotations

import json

from .pages import SITE_ORIGIN, render_doc_page

#: The challenge registry. Each gate is its own page; ``mode`` selects the in-browser flow (see arena.js).
#: ``family`` is the documented open mechanism it reproduces (vendor-neutral), ``blurb`` the one-line pitch.
CHALLENGES: list[dict[str, str]] = [
    {
        "slug": "checkbox",
        "label": "Verify-you-are-human checkbox",
        "family": "reCAPTCHA-v2 / Turnstile checkbox",
        "mode": "checkbox",
        "blurb": 'The familiar "click to confirm you are human" checkbox. The click triggers a silent '
        "coherence check — a coherent client passes on the click with no puzzle; an incoherent one is "
        "stepped up to a proof-of-work. The detector AS the gate.",
    },
    {
        "slug": "managed",
        "label": "Managed challenge",
        "family": "Turnstile-style ladder",
        "mode": "managed",
        "blurb": "A silent coherence check first — a coherent client passes with no puzzle; only an "
        "incoherent one is stepped up to a proof-of-work. The detector AS the gate.",
    },
    {
        "slug": "hashcash",
        "label": "Hashcash proof-of-work",
        "family": "Proof-of-work · anubis",
        "mode": "pow",
        "blurb": "A SHA-256 leading-zeros proof-of-work, solved in your browser. A cost gate — not a "
        "human test: a script solves it just as well.",
    },
    {
        "slug": "many-small",
        "label": "Many-small proof-of-work",
        "family": "Proof-of-work · friendly-captcha",
        "mode": "pow",
        "blurb": "N small SHA-256 sub-puzzles (the friendly-captcha shape), solved in-browser.",
    },
    {
        "slug": "memory-hard",
        "label": "Memory-hard proof-of-work",
        "family": "Proof-of-work · Argon2id",
        "mode": "pow",
        "blurb": "An Argon2id memory-hard puzzle — GPU/ASIC-resistant by design. Bring the reference "
        "solver; the browser just shows the challenge.",
    },
    {
        "slug": "text",
        "label": "Distorted-text CAPTCHA",
        "family": "CAPTCHA · distorted image",
        "mode": "captcha",
        "blurb": "Read the warped, noisy text rendered to an image — the answer is in pixels, not markup, "
        "so it falls only to OCR. The gate the HuggingFace TrOCR evader beats.",
    },
    {
        "slug": "math",
        "label": "Arithmetic CAPTCHA",
        "family": "CAPTCHA · logic",
        "mode": "captcha",
        "blurb": "Answer a small arithmetic question — the classic text Turing test.",
    },
    {
        "slug": "clock",
        "label": "Analog-clock CAPTCHA",
        "family": "CAPTCHA · read-the-clock",
        "mode": "captcha",
        "blurb": "Read the analog clock face and type the time it shows (H:MM) — a clock rendered at a random time "
        "(owned procedural, zero-license). A visual-reasoning task (interpret the hour + minute hands), distinct "
        "from glyph OCR; minutes are a multiple of 5.",
    },
    {
        "slug": "honeypot",
        "label": "Honeypot trap",
        "family": "CAPTCHA · hidden field",
        "mode": "captcha",
        "blurb": "A hidden field a human never sees but a naive form-filling bot fills. Leave it empty "
        "to pass — submitting a value trips the trap.",
    },
    {
        "slug": "slider",
        "label": "Slider puzzle",
        "family": "CAPTCHA · GeeTest-style drag",
        "mode": "slider",
        "blurb": "Drag the block into the gap. The gate scores the drop position AND the drag "
        "trajectory's velocity variation — a constant-velocity glide or a teleport is rejected.",
    },
    {
        "slug": "image-select",
        "label": "Image-select grid (emoji)",
        "family": "CAPTCHA · reCAPTCHA-v2 style",
        "mode": "image-select",
        "kind": "image-select",
        "blurb": 'Pick every tile matching the prompt ("select every animal") from a grid of real emoji '
        "glyphs (Noto Emoji, OFL) — a category-recognition task that needs a real CV/VLM, not a shape "
        "classifier.",
    },
    {
        "slug": "doodle",
        "label": "Image-select grid (doodles)",
        "family": "CAPTCHA · reCAPTCHA-v2 style",
        "mode": "image-select",
        "kind": "image-doodle",
        "blurb": 'Pick every tile matching the prompt ("select every animal") from a grid of hand-drawn '
        "sketches (Google Quick, Draw!, CC BY 4.0) — open wobbly polylines with huge intra-class variance, "
        "even harder for CV than the emoji grid.",
    },
    {
        "slug": "rotate",
        "label": "Rotate-upright puzzle",
        "family": "CAPTCHA · Arkose/FunCaptcha style",
        "mode": "rotate",
        "blurb": "Drag the object upright. The gate scores the rotation trajectory, so a bare submitted "
        "angle won't pass — you must actually drag it round (variable angular velocity = human).",
    },
    {
        "slug": "pact",
        "label": "PACT personhood token",
        "family": "Defense · Private Access Tokens",
        "mode": "pact",
        "blurb": "An anonymous proof-of-personhood token that SKIPS the challenge — the frontier defense. "
        "The honest caveat: the issuer mints freely here, so it is also the documented bypass.",
    },
    {
        "slug": "audio",
        "label": "Audio spoken-digit CAPTCHA",
        "family": "reCAPTCHA / hCaptcha audio (accessibility)",
        "mode": "audio",
        "blurb": "Transcribe a spoken-digit clip — the ASR-benchmark twin of the distorted-text (OCR) gate. "
        "The clip is synthesised in pure Go from an embedded spoken-digit corpus, distorted per level; a correct "
        "answer faster than the clip's real-time playback is ASR automation (server-observed), so a solver passes "
        "the gate but is convicted on coherence.",
    },
    {
        "slug": "spatial",
        "label": "3D spatial cube grid",
        "family": "Arkose / FunCaptcha 3D object",
        "mode": "spatial",
        "blurb": "Select every cube with the target colour on top — a grid of isometric cubes rendered at random "
        "3D orientations. Spatial reasoning (identify the TOP face of a rotated cube), not a 2D glyph; a correct "
        "selection faster than a human can scan the grid is automation, convicted on coherence.",
    },
    {
        "slug": "shell",
        "label": "Shell game",
        "family": "Track-under-occlusion (anti-LLM)",
        "mode": "shell",
        "blurb": "Watch the ball, then click the cup hiding it after the shuffle — an original track-under-occlusion "
        "gate (not a wild-captcha clone). The ball is invisible during the swaps, so a snapshot-then-reason agent "
        "cannot follow it; a correct answer faster than the shuffle runtime was precomputed from the payload.",
    },
    {
        "slug": "timing",
        "label": "Motor-timing precision",
        "family": "Motor-timing (Grillmaster-style)",
        "mode": "timing",
        "blurb": "Press and hold each target for its shown duration, then release — an original motor-precision gate "
        "(not a wild-captcha clone). The release-error spread across targets convicts a bot: superhuman precision "
        "(target-exact or a flat constant offset) or claiming more total hold time than the solve took.",
    },
    {
        "slug": "keymap",
        "label": "Broken keyboard",
        "family": "Input-integrity (remapped keys)",
        "mode": "keymap",
        "blurb": "The keyboard is silently remapped — discover the mapping by trying keys, then type the target — an "
        "original input-integrity gate (not a wild-captcha clone). A correct answer with no exploration (no "
        "backspaces) means the client decoded the remap from the payload instead of probing it.",
    },
    {
        "slug": "presshold",
        "label": "Press and hold",
        "family": "Press-and-hold (Cloudflare / DataDome / HUMAN)",
        "mode": "presshold",
        "blurb": "Press and hold the button for the shown duration, then release. The held-pointer tremor convicts a "
        "scripted hold — a real hand drifts continuously while an injected hold pins its samples to one coordinate "
        "(no jitter); claiming a longer hold than the whole solve window is also impossible.",
    },
    {
        "slug": "sequence",
        "label": "Click in order",
        "family": "Ordered click-in-sequence (GeeTest / NetEase Yidun)",
        "mode": "sequence",
        "blurb": "Click the numbered tiles in order. Solving faster than a human can visually locate and click N "
        "ordered targets, or with a metronomic fixed-delay cadence, convicts a bot — the ordering + timing are the "
        "tell, not the puzzle.",
    },
    {
        "slug": "locate",
        "label": "Click the center",
        "family": "Point localization (hCaptcha / AWS WAF)",
        "mode": "locate",
        "blurb": "Click the center of the named target among distractors on a free canvas. A CV solver computes the "
        "centroid and clicks it pixel-perfect (distance ~0, below human aim variance), or solves faster than a human "
        "can locate and aim — either convicts. Free-canvas localization, not tile-select.",
    },
    {
        "slug": "match",
        "label": "Faces the same way",
        "family": "Orientation match / odd-one-out (Arkose / hCaptcha)",
        "mode": "match",
        "blurb": "Click the arrow that points the same way as the reference — a relational task, comparing the "
        "reference against each candidate (not classifying one tile). Solving faster than a human can scan a "
        "reference plus N candidates convicts a bot or VLM.",
    },
    {
        "slug": "slide",
        "label": "Sliding puzzle",
        "family": "Sliding-tile (KeyCAPTCHA / 15-puzzle)",
        "mode": "slide",
        "blurb": "Slide the 8-puzzle into order — click a tile next to the blank to slide it. Solving in the exact "
        "minimum number of moves (which a human wandering never hits on a deep scramble), or faster than a human can "
        "slide the tiles, convicts. The plan optimality + timing are the tell.",
    },
    {
        "slug": "pattern",
        "label": "Trace the pattern",
        "family": "Connect-the-dots / pattern-lock",
        "mode": "pattern",
        "blurb": "Draw one line through the dots in order without lifting. A synthetic stroke hugs the ideal path "
        "with almost no deviation (too straight for a human hand, which wobbles), or draws through the waypoints "
        "faster than a human can move the pointer — either convicts. The path fidelity + timing are the tell.",
    },
    {
        "slug": "reaction",
        "label": "Click when green",
        "family": "Reaction-time (click when ready)",
        "mode": "reaction",
        "blurb": "Wait for the box to turn green, then click it as fast as you can. A reaction latency below the "
        "human physiological floor (~150ms), or a click that reaches the server before the go (anticipation), "
        "convicts — a bot reacts faster than any human hand-eye loop. Server-observed, unforgeable in the too-fast "
        "direction.",
    },
    {
        "slug": "spotdiff",
        "label": "Spot the difference",
        "family": "Spot-the-difference",
        "mode": "spotdiff",
        "blurb": "The two panels differ in a few spots — click each difference on the right panel. A bot pixel-diffs "
        "the panels and clicks the exact centroid of each change (pixel-perfect) and finds them all instantly, while "
        "a human eyeballs and needs seconds per difference — either convicts.",
    },
    {
        "slug": "pursuit",
        "label": "Follow the dot",
        "family": "Smooth-pursuit tracking",
        "mode": "pursuit",
        "blurb": "Keep your cursor on the moving dot for a few seconds. Human eye-hand pursuit trails a moving "
        "target with tens of pixels of error, while a bot that computes the dot's path holds the cursor within a few "
        "pixels — superhuman tracking accuracy convicts. A continuous-tracking tell, distinct from a click.",
    },
    {
        "slug": "count",
        "label": "Count the circles",
        "family": "Counting",
        "mode": "count",
        "blurb": "How many circles of the named colour are there? A bot CV-counts the shapes instantly, while a "
        "human scans each one — a correct answer faster than a human can scan the whole scene convicts. Reuses the "
        "solve-speed tell.",
    },
]

_BY_SLUG: dict[str, dict[str, str]] = {c["slug"]: c for c in CHALLENGES}


def challenge(slug: str) -> dict[str, str] | None:
    """Return the registry entry for ``slug``, or ``None`` if it is not a known gate."""
    return _BY_SLUG.get(slug)


# The arena component CSS — injected into the doc shell's <head> via render_doc_page(extra_head=...). The
# layout / nav / footer / typography come from the shared DOC_CSS; only the widget-specific rules live here.
ARENA_CSS = '<link rel="stylesheet" href="/arena.css">'

# The shared arena client now lives in static/arena.js (a real, cacheable file), served at /arena.js and
# loaded per gate by _gate_script after it pins window.__ARENA__ = {slug, mode} for that gate.

# Reused HTML fragments (trusted markup; inserted raw into the doc-shell <main>).
# The dual verdict, rebuilt as two EQUAL heroes (redesign 2b). The element ids are preserved so arena.js keeps
# driving them: fetchDetectorVerdict() sets #ks-det-verdict (+ .big pass/fail); each gate handler sets
# #ks-gate-verdict / #ks-gate-note / #ks-token. The card border follows the inner verdict class via :has().
_VERDICTS_HTML = """
<div class="dual-head">
  <div class="vh" id="ks-headline">Solve the puzzle &mdash; then meet the detector.</div>
  <p class="vline" id="ks-vline">Pass the gate on the left. Kitsune&rsquo;s coherence engine scores your client from the edge at the same time &mdash; because solving a gate is a <b>cost</b> or <b>Turing</b> test, not proof you&rsquo;re human.</p>
</div>
<div class="dual">
  <div class="vcard">
    <h2>Gate verdict</h2>
    <div class="big" id="ks-gate-verdict">&mdash;</div>
    <p class="gloss" id="ks-gate-note">did you solve the puzzle?</p>
    <div id="ks-token"></div>
  </div>
  <div class="vcard det">
    <span class="vscan" aria-hidden="true"></span>
    <h2>Detector verdict</h2>
    <div class="big" id="ks-det-verdict">&mdash;</div>
    <p class="gloss" id="ks-det-note">does your client hold together?</p>
  </div>
</div>
"""

_ETHICS_HTML = """
<details class="ks-disclose" style="margin-top:1.5rem"><summary>How this works &amp; the ethics</summary>
<p class="note">The gate is a self-hosted service Kitsune runs (the owned <code>arena</code> service). It reproduces the
<i>documented, open</i> mechanism above &mdash; it <b>never</b> contacts, proxies to, or solves a third-party
challenge (Cloudflare Turnstile, reCAPTCHA, hCaptcha). The reference solvers only ever talk to our own gates. The detector
verdict comes from the same coherence engine that scores the home page, reading your client over the edge.</p></details>
"""

_DESC = (
    "Every bot-blocking gate on the web — proof-of-work, CAPTCHA, sliders, rotate, personhood tokens — "
    "rebuilt on our own infrastructure. Beat a gate in your browser and see whether Kitsune's detector "
    "still knows what you are."
)


# Gates with no difficulty axis: honeypot (trap-or-not), pact (token-or-not), checkbox + managed
# (coherence-gated — the difficulty is the client's own coherence, not an operator dial).
_NO_LEVEL_SLUGS = frozenset({"honeypot", "pact", "checkbox", "managed"})


def _has_levels(c: dict[str, str]) -> bool:
    """Whether this gate exposes an easy/medium/hard difficulty (a cost dial). False for honeypot/pact."""
    return c["slug"] not in _NO_LEVEL_SLUGS


def _gate_script(c: dict[str, str]) -> str:
    """The per-page <script>: pin window.__ARENA__ to this gate, then run the shared arena JS."""
    cfg = json.dumps(
        {
            "slug": c["slug"],
            "mode": c["mode"],
            "kind": c.get("kind", c["mode"]),  # image-select gates carry the captcha kind (emoji vs doodle)
            "level": "medium",
            "levels": _has_levels(c),
        }
    )
    # Pin the per-gate config inline, then load the shared client from /arena.js (runs after, in order).
    return f'<script>window.__ARENA__={cfg}</script><script src="/arena.js"></script>'


def _endpoints(c: dict[str, str]) -> list[tuple[str, str]]:
    """The owned arena-gate HTTP endpoints a scripted bypass targets for this challenge (method, path)."""
    slug, mode = c["slug"], c["mode"]
    if mode in ("managed", "checkbox"):
        return [("GET", "/arena/managed?step=1")]
    if mode == "pow":
        return [("GET", f"/arena/challenge?gate={slug}"), ("POST", "/arena/verify")]
    if mode == "captcha":
        return [("GET", f"/arena/captcha?kind={slug}"), ("POST", "/arena/captcha/verify")]
    if mode == "image-select":
        kind = c.get("kind", "image-select")
        return [("GET", f"/arena/captcha?kind={kind}"), ("POST", "/arena/captcha/verify")]
    if mode == "pact":
        return [("GET", "/arena/pact"), ("POST", "/arena/pact/verify")]
    return [("GET", f"/arena/{slug}"), ("POST", f"/arena/{slug}/verify")]  # slider, rotate


def _endpoints_html(c: dict[str, str]) -> str:
    """A disclosure listing the gate's HTTP endpoints so a bypass tester can script straight against it."""
    rows = "".join(f'<li><span class="m">{method}</span> <code>{path}</code></li>' for method, path in _endpoints(c))
    return (
        '<details class="ks-disclose" style="margin-top:1rem"><summary>Endpoints &mdash; point your own '
        "solver here</summary>"
        '<p class="note">The gate is just an HTTP protocol on Kitsune&rsquo;s owned <code>arena</code> service '
        "(allow-list-scoped &mdash; it only ever talks to itself). Script a bypass against:</p>"
        f'<ul class="arena-endpoints">{rows}</ul></details>'
    )


# --- Redesign IA: each gate's category (chip filter + card accent). Keyed by slug; the category is the gate's
# PRIMARY discriminator. cost = a proof-of-work / silent cost gate; turing = an AI-hard perception/reasoning puzzle
# (beaten by OCR/CV/VLM); behavioral = a biomechanics/motor-timing gate (beaten by a humanized solver); anti = an
# anti-LLM structural gate; defense = a defensive protocol (token / rate / queue). ---
_GATE_CAT: dict[str, str] = {
    "checkbox": "defense",
    "managed": "defense",
    "hashcash": "cost",
    "many-small": "cost",
    "memory-hard": "cost",
    "text": "turing",
    "math": "turing",
    "clock": "turing",
    "honeypot": "turing",
    "image-select": "turing",
    "doodle": "turing",
    "spatial": "turing",
    "count": "turing",
    "audio": "turing",
    "spotdiff": "turing",
    "match": "turing",
    "slider": "behavioral",
    "rotate": "behavioral",
    "timing": "behavioral",
    "keymap": "behavioral",
    "presshold": "behavioral",
    "sequence": "behavioral",
    "pattern": "behavioral",
    "reaction": "behavioral",
    "pursuit": "behavioral",
    "locate": "behavioral",
    "slide": "behavioral",
    "shell": "anti",
    "pact": "defense",
}
#: category -> (chip label, CSS colour, "beaten by" gloss). The gloss is category-derived (the per-gate
#: strings in docs/arena.md are finer, but the registry doesn't carry them).
_CAT_META: dict[str, tuple[str, str, str]] = {
    "cost": ("Cost", "var(--amber)", "any solver — it's a cost gate"),
    "turing": ("Turing", "var(--muted)", "real OCR / CV / VLM"),
    "behavioral": ("Biomechanics", "var(--jade)", "a humanized solver"),
    "anti": ("Anti-LLM", "var(--fox)", "nothing clean — it's built to catch"),
    "defense": ("Defense", "#7f8fa6", "a real credential, or just staying in budget"),
}
_CAT_ORDER: list[str] = ["cost", "turing", "behavioral", "anti", "defense"]


def arena_index_html() -> str:
    """The ``/arena`` index: the thesis hero + category chips + a category-accented card grid linking to every
    challenge's own page."""
    cards = []
    for c in CHALLENGES:
        cat = _GATE_CAT.get(c["slug"], "turing")
        label, col, beaten = _CAT_META[cat]
        cards.append(
            f'<a class="gate-card" data-cat="{cat}" href="/arena/gate/{c["slug"]}" style="--cat:{col}">'
            f'<div class="gc-top"><span class="gc-label">{c["label"]}</span>'
            f'<span class="gc-tag">{label}</span></div>'
            f'<div class="gc-fam">{c["family"]}</div>'
            f'<div class="gc-beat">beaten by <b>{beaten}</b></div></a>'
        )
    chips = '<button class="chip active" data-filter="all">All</button>' + "".join(
        f'<button class="chip" data-filter="{cat}">{_CAT_META[cat][0]}</button>' for cat in _CAT_ORDER
    )
    body = f"""
<div class="arena-hero">
<div class="eyebrow">Challenge the gates · meet the detector</div>
<h1 class="display arena-h1">Every gate falls to the right bot.<br><span class="fox">The detector convicts it anyway.</span></h1>
<p class="lead">Every bot-blocking gate on the web &mdash; proof-of-work, CAPTCHA, sliders, personhood tokens &mdash;
rebuilt here on our own infrastructure. Bring a browser, a bot, or your own solver and <b>beat one</b>. You get
<b>two verdicts</b>: whether you passed the gate, and whether Kitsune still knows what you are.</p>
<p class="note">Solving a gate proves you paid the cost or passed the puzzle &mdash; not that you&rsquo;re human. A
script can beat every gate here and still get caught. <b>The puzzle is theatre; the fingerprint is the tell.</b></p>
</div>
<div class="arena-chips" role="group" aria-label="Filter gates by category">{chips}</div>
<div class="gate-grid">{"".join(cards)}</div>
{_ETHICS_HTML}
<script>(function(){{var chips=document.querySelectorAll('.arena-chips .chip'),cards=document.querySelectorAll('.gate-card');
chips.forEach(function(ch){{ch.addEventListener('click',function(){{var f=ch.getAttribute('data-filter');
chips.forEach(function(c){{c.classList.toggle('active',c===ch);}});
cards.forEach(function(cd){{cd.style.display=(f==='all'||cd.getAttribute('data-cat')===f)?'':'none';}});}});}});}})();</script>
"""
    return render_doc_page(
        title="The Arena — challenge the gates, meet the detector",
        description=_DESC,
        canonical_path="/arena",
        body_html=body,
        page_type="CollectionPage",
        keywords="captcha, proof of work, bot detection, challenge, turnstile, recaptcha, arena",
        extra_head=ARENA_CSS,
    )


def arena_gate_html(slug: str) -> str | None:
    """A single challenge's page at ``/arena/gate/<slug>`` — its widget + the dual verdict. ``None`` if unknown."""
    c = challenge(slug)
    if c is None:
        return None
    levels_html = ""
    if _has_levels(c):
        levels_html = (
            '<div class="arena-levels-wrap"><div class="arena-levels" id="ks-levels" role="group" '
            'aria-label="difficulty">'
            '<button data-level="easy" aria-pressed="false">Easy</button>'
            '<button data-level="medium" aria-pressed="true">Medium</button>'
            '<button data-level="hard" aria-pressed="false">Hard</button></div>'
            '<p class="note">Difficulty is a <b>cost</b> dial, not a security dial &mdash; harder = more work, '
            "never a better bot/human test. The detector convicts at every level.</p></div>"
        )
    body = f"""
<p class="crumb-back"><a href="/arena">&larr; All challenges</a></p>
<h1 class="display">{c["label"]}</h1>
<p class="arena-family">{c["family"]}</p>
<div class="gate-body">
  <div class="gate-left">
    <div class="gl-eyebrow">The gate</div>
    {levels_html}
    <section class="arena-stage" aria-label="challenge">
      <div class="arena-log" id="ks-log">Loading the challenge&hellip;</div>
      <div id="ks-captcha"></div>
      <p class="arena-again-wrap">The challenge auto-serves on load &middot; <a href="#" id="ks-again" class="arena-again">&#8635; new challenge</a></p>
    </section>
  </div>
  <div class="gate-right">
    {_VERDICTS_HTML}
    {_endpoints_html(c)}
  </div>
</div>
<p class="note arena-foot">{c["blurb"]} A self-hosted reproduction of the documented mechanism &mdash; never a
third-party widget. The detector reads the same coherence engine that scores the home page.</p>
{_ETHICS_HTML}
{_gate_script(c)}
"""
    return render_doc_page(
        title=c["label"],
        description=f"{c['blurb']} A self-hosted reproduction of the {c['family']} mechanism.",
        canonical_path=f"/arena/gate/{slug}",
        body_html=body,
        page_type="WebPage",
        extra_head=ARENA_CSS,
    )


#: Canonical URLs for every gate page, for the sitemap.
ARENA_URLS: list[str] = [f"{SITE_ORIGIN}/arena"] + [f"{SITE_ORIGIN}/arena/gate/{c['slug']}" for c in CHALLENGES]
