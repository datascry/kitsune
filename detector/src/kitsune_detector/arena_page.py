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

#: The challenge registry. Each gate is its own page; ``mode`` selects the in-browser flow (see ARENA_JS).
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
        "label": "Image-select grid",
        "family": "CAPTCHA · reCAPTCHA-v2 style",
        "mode": "image-select",
        "blurb": 'Pick every tile matching the prompt ("select every animal") from a grid of real emoji '
        "glyphs (Noto Emoji, OFL) — a category-recognition task that needs a real CV/VLM, not a shape "
        "classifier.",
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
]

_BY_SLUG: dict[str, dict[str, str]] = {c["slug"]: c for c in CHALLENGES}


def challenge(slug: str) -> dict[str, str] | None:
    """Return the registry entry for ``slug``, or ``None`` if it is not a known gate."""
    return _BY_SLUG.get(slug)


# The arena component CSS — injected into the doc shell's <head> via render_doc_page(extra_head=...). The
# layout / nav / footer / typography come from the shared DOC_CSS; only the widget-specific rules live here.
ARENA_CSS = """<style>
.arena-family{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.12em;margin:.1rem 0 1rem}
.note{color:var(--muted);font-size:.82rem}
.crumb-back{margin:.2rem 0 .8rem;font-size:.8rem}
.crumb-back a{color:var(--muted);text-decoration:none}.crumb-back a:hover{color:var(--fox)}
.arena-stage{margin:1.1rem 0}
.arena-run{font:inherit;font-weight:600;padding:.6rem 1.2rem;border:0;border-radius:8px;background:var(--fox);color:#fff;cursor:pointer;min-height:44px}
.arena-run:disabled{opacity:.5;cursor:default}
.verdicts{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:1.5rem}
.vcard{border:1px solid var(--line);border-radius:10px;padding:1rem;background:var(--panel)}
.vcard h3{margin:0 0 .4rem;font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.vcard .big{font-size:1.4rem;font-weight:700}
.vcard .pass{color:var(--jade)}.vcard .fail{color:var(--fox)}
.vcard code{font-size:.78rem;word-break:break-all;color:var(--fox)}
.arena-log{font-family:var(--mono);font-size:.78rem;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem;margin-top:.6rem;white-space:pre-wrap;min-height:1.4rem;color:var(--ink)}
#ks-captcha{margin-top:.8rem}
#ks-captcha img{vertical-align:middle;border:1px solid var(--line);border-radius:6px;background:#fff;margin-bottom:.5rem}
#ks-captcha input{font:inherit;padding:.5rem;border:1px solid var(--line-bright);border-radius:6px;min-height:44px;margin-right:.5rem;background:var(--panel);color:var(--ink)}
#ks-captcha button{font:inherit;font-weight:600;padding:.5rem 1rem;border:0;border-radius:6px;background:var(--fox);color:#fff;cursor:pointer;min-height:44px}
#ks-captcha .slider-track{position:relative;height:44px;max-width:100%;background:var(--panel-2);border:1px solid var(--line-bright);border-radius:8px;margin:.6rem 0;touch-action:none}
#ks-captcha .slider-gap{position:absolute;top:5px;height:34px;width:42px;border:2px dashed var(--muted);border-radius:6px;box-sizing:border-box}
#ks-captcha .slider-handle{position:absolute;top:3px;height:38px;width:42px;background:var(--fox);border-radius:6px;cursor:grab;box-sizing:border-box;touch-action:none}
#ks-captcha .tiles{display:grid;grid-template-columns:repeat(3,64px);gap:6px;margin:.6rem 0}
#ks-captcha .tiles img{width:64px;height:64px;border:2px solid var(--line);border-radius:6px;cursor:pointer;background:#fff}
#ks-captcha .tiles img.sel{border-color:var(--fox);box-shadow:0 0 0 2px var(--fox)}
#ks-captcha .rot img{width:96px;height:96px;transition:transform .1s;touch-action:none}
.arena-levels{display:inline-flex;border:1px solid var(--line-bright);border-radius:8px;overflow:hidden;margin:.2rem 0 .4rem}
.arena-levels button{font:inherit;font-size:.78rem;padding:.4rem .9rem;border:0;border-right:1px solid var(--line-bright);background:var(--panel);color:var(--muted);cursor:pointer;min-height:40px}
.arena-levels button:last-child{border-right:0}
.arena-levels button[aria-pressed=true]{background:var(--fox);color:#fff;font-weight:600}
.arena-levels-wrap{margin:.2rem 0 .8rem}
.ks-checkbox{display:inline-flex;align-items:center;gap:.8rem;border:1px solid var(--line-bright);background:var(--panel);border-radius:6px;padding:.7rem 1rem;cursor:pointer;min-width:300px;user-select:none}
.ks-checkbox:hover{border-color:var(--muted)}
.ks-cb-box{position:relative;width:26px;height:26px;border:2px solid var(--line-bright);border-radius:4px;background:var(--bg);flex:none}
.ks-cb-mark{position:absolute;inset:0;display:none;align-items:center;justify-content:center;color:var(--jade);font-weight:700;font-size:18px;line-height:1}
.ks-cb-spin{position:absolute;inset:3px;display:none;border:2px solid var(--line-bright);border-top-color:var(--fox);border-radius:50%;animation:ks-spin .7s linear infinite}
.ks-checkbox.checking{cursor:default}
.ks-checkbox.checking .ks-cb-spin{display:block}
.ks-checkbox.ok .ks-cb-mark{display:flex}
.ks-checkbox.ok .ks-cb-box{border-color:var(--jade)}
.ks-checkbox.fail .ks-cb-box{border-color:var(--fox)}
.ks-cb-label{font-size:.95rem;color:var(--ink)}
.ks-cb-brand{margin-left:auto;font-size:.58rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)}
@keyframes ks-spin{to{transform:rotate(360deg)}}
.arena-again-wrap{margin:.7rem 0 0}
.arena-again{font-size:.78rem;color:var(--muted);text-decoration:none}
.arena-again:hover{color:var(--fox)}
.arena-endpoints{list-style:none;padding:0;margin:.5rem 0 0;display:flex;flex-direction:column;gap:.3rem}
.arena-endpoints li code{color:var(--fox);font-size:.82rem}
.arena-endpoints .m{display:inline-block;min-width:3rem;color:var(--muted)}
@media (max-width:640px){.verdicts{grid-template-columns:1fr}}
</style>"""

# The shared client. window.__ARENA__ = {slug, mode} is injected per page (see _gate_script); this script
# runs ONLY that gate. Identical solver logic across pages — each page just dispatches its own mode.
ARENA_JS = r"""
(function(){
  "use strict";
  var A = window.__ARENA__ || {slug:"managed", mode:"managed"};
  var gate = A.slug;
  var LEVEL = A.level || "medium";
  // Append the chosen difficulty to a gate MINT url (a cost dial — the gate raises work, never detection).
  // Skipped for gates with no level axis (honeypot/pact) and for the verdict read (/arena/managed step 0).
  function withLevel(u){ if(!A.levels) return u; return u + (u.indexOf("?")>=0?"&":"?") + "level=" + encodeURIComponent(LEVEL); }
  var enc = new TextEncoder();
  function hexToBytes(h){ var a=new Uint8Array(h.length/2); for(var i=0;i<a.length;i++){ a[i]=parseInt(h.substr(i*2,2),16);} return a; }
  function leadingZeroBits(d){ var n=0; for(var i=0;i<d.length;i++){ var b=d[i]; if(b===0){ n+=8; continue;} var x=b,c=0; while((x&0x80)===0){ c++; x=(x<<1)&0xff;} n+=c; break;} return n; }
  async function workDigest(subNonce, nonceBytes, counter){
    var sn=enc.encode(subNonce);
    var buf=new Uint8Array(sn.length+nonceBytes.length+8);
    buf.set(sn,0); buf.set(nonceBytes,sn.length);
    new DataView(buf.buffer).setBigUint64(sn.length+nonceBytes.length, BigInt(counter), true);
    var d=await crypto.subtle.digest("SHA-256", buf);
    return new Uint8Array(d);
  }
  async function solvePuzzle(subNonce, nonceBytes, difficulty){
    for(var c=0;c<5e7;c++){ var d=await workDigest(subNonce,nonceBytes,c); if(leadingZeroBits(d)>=difficulty){ return c; } }
    throw new Error("gave up");
  }
  function subNonces(c){ if(c.class!=="many-small"){ return [""]; } var out=[]; var n=c.count||1; for(var i=0;i<n;i++){ out.push(i+":"); } return out; }

  var log=document.getElementById("ks-log");
  function say(m){ if(log) log.textContent=m; }

  // The detector panel reads the PUBLIC, cookie-scoped /arena/managed (only your OWN session's decision) —
  // not the admin-gated /verdict — so it works on the live site too.
  async function fetchDetectorVerdict(){
    var out=document.getElementById("ks-det-verdict"); if(!out) return;
    try{
      var r=await fetch("/arena/managed");
      if(!r.ok){ out.textContent="—"; return; }
      var v=await r.json();
      var label=String(v.label||"?");
      out.textContent=label.toUpperCase();
      out.className="big "+(label==="human"||label==="verified"?"pass":"fail");
    }catch(_){ out.textContent="—"; }
  }

  async function solveAndVerify(c, gv, gn, tok){
    if(!(window.crypto&&crypto.subtle&&crypto.subtle.digest)){
      say("In-browser proof-of-work needs the Web Crypto API (a secure HTTPS context). Solve it with the reference evaders/pow solver against the endpoints below."); return false;
    }
    if(c.class==="memory-hard"){
      say("memory-hard (Argon2id) resists cheap solving — that's the point. Bring your own solver (the reference evaders/pow solver), or try hashcash / many-small.\nChallenge: "+JSON.stringify(c));
      gn.textContent="Not solved in-browser — memory-hard is the GPU/ASIC-resistant family."; return false;
    }
    var nb=hexToBytes(c.nonce), subs=subNonces(c), counters=[];
    var t0=performance.now();
    for(var i=0;i<subs.length;i++){ say("Solving puzzle "+(i+1)+"/"+subs.length+" ("+c.difficulty+" bits)…"); counters.push(await solvePuzzle(subs[i], nb, c.difficulty)); }
    var cost=Math.round(performance.now()-t0);
    say("Solved in "+cost+" ms. Verifying with the gate…");
    var vr=await fetch("/arena/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(Object.assign({},c,{counters:counters}))});
    var v=await vr.json();
    if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Proof-of-work accepted in "+cost+" ms (cost-per-token)."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Gate PASSED in "+cost+" ms."); return true; }
    gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="The gate rejected the solution."; say("Gate rejected the solution."); return false;
  }

  async function runCaptcha(kind, gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    say("Requesting a "+kind+" CAPTCHA…");
    var cr=await fetch(withLevel("/arena/captcha?kind="+encodeURIComponent(kind)));
    if(!cr.ok){ say("CAPTCHA gate unavailable ("+cr.status+")."); return; }
    var c=await cr.json();
    var wrap=document.createElement("div");
    if(c.image){ var img=document.createElement("img"); img.src=c.image; img.alt="text challenge"; wrap.appendChild(img); wrap.appendChild(document.createElement("br")); }
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; wrap.appendChild(p);
    var submit=document.createElement("button");
    if(kind==="honeypot"){
      var hn=document.createElement("p"); hn.className="note"; hn.textContent="(A hidden field '"+c.field+"' must stay empty — a bot that fills every field trips it.)"; wrap.appendChild(hn);
      submit.textContent="Submit form";
      submit.onclick=function(){ verifyCaptcha(kind, c.id, "", gv, gn, tok); };
    } else {
      var inp=document.createElement("input"); inp.type="text"; inp.autocomplete="off"; inp.placeholder="Your answer"; wrap.appendChild(inp);
      submit.textContent="Submit answer";
      submit.onclick=function(){ verifyCaptcha(kind, c.id, inp.value, gv, gn, tok); };
      inp.addEventListener("keydown", function(e){ if(e.key==="Enter"){ submit.click(); } });
    }
    wrap.appendChild(submit); box.appendChild(wrap);
    say("Solve the CAPTCHA and submit.");
  }
  async function verifyCaptcha(kind, id, answer, gv, gn, tok){
    var v=await (await fetch("/arena/captcha/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({kind:kind,id:id,answer:answer})})).json();
    if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="CAPTCHA solved — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("CAPTCHA PASSED."); }
    else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Wrong answer (or the challenge expired)."; say("CAPTCHA rejected."); }
    document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
  }

  async function runSlider(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    say("Requesting a slider challenge…");
    var s=await (await fetch(withLevel("/arena/slider"))).json();
    var hint=document.createElement("p"); hint.className="note"; hint.textContent="Drag the block into the dashed gap."; box.appendChild(hint);
    var track=document.createElement("div"); track.className="slider-track"; track.style.width=s.track_w+"px";
    var gap=document.createElement("div"); gap.className="slider-gap"; gap.style.left=s.gap_x+"px"; track.appendChild(gap);
    var handle=document.createElement("div"); handle.className="slider-handle"; handle.style.left="0px"; track.appendChild(handle);
    box.appendChild(track);
    var dragging=false, t0=0, traj=[], hx=0, maxX=s.track_w-s.piece_w, half=s.piece_w/2;
    handle.addEventListener("pointerdown", function(e){ dragging=true; t0=performance.now(); traj=[]; handle.setPointerCapture(e.pointerId); e.preventDefault(); });
    handle.addEventListener("pointermove", function(e){ if(!dragging) return; var rect=track.getBoundingClientRect(); hx=Math.max(0, Math.min(maxX, e.clientX-rect.left-half)); handle.style.left=hx+"px"; traj.push({t:performance.now()-t0, x:hx}); });
    handle.addEventListener("pointerup", async function(){ if(!dragging) return; dragging=false;
      say("Verifying the drag…");
      var v=await (await fetch("/arena/slider/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:s.id, x:hx, trajectory:traj})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Slider fit the gap with a human-like drag."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Slider PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Rejected: "+(v.reason||"try again"); say("Slider rejected: "+(v.reason||"")); }
      box.innerHTML=""; fetchDetectorVerdict();
    });
    say("Drag the block into the gap.");
  }

  async function runImageSelect(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/captcha?kind=image-select"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var grid=document.createElement("div"); grid.className="tiles"; var sel={};
    c.tiles.forEach(function(src,i){ var img=document.createElement("img"); img.src=src; img.alt="tile "+(i+1);
      img.onclick=function(){ if(sel[i]){ delete sel[i]; img.classList.remove("sel"); } else { sel[i]=1; img.classList.add("sel"); } }; grid.appendChild(img); });
    box.appendChild(grid);
    var submit=document.createElement("button"); submit.textContent="Verify selection";
    submit.onclick=function(){ var idx=Object.keys(sel).map(Number).sort(function(a,b){return a-b;}).join(","); verifyCaptcha("image-select", c.id, idx, gv, gn, tok); };
    box.appendChild(submit); say("Select the matching tiles and verify.");
  }

  async function runRotate(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/rotate"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent="Drag the arrow to point straight up."; box.appendChild(p);
    var wrap=document.createElement("div"); wrap.className="rot";
    var img=document.createElement("img"); img.src=c.image; img.alt="rotate target"; img.draggable=false; img.style.transform="rotate("+c.angle+"deg)"; wrap.appendChild(img); box.appendChild(wrap);
    var dragging=false, t0=0, traj=[], cur=c.angle;
    function angleAt(e){ var r=img.getBoundingClientRect(); var a=Math.atan2(e.clientY-(r.top+r.height/2), e.clientX-(r.left+r.width/2))*180/Math.PI; return a+90; }
    img.addEventListener("pointerdown", function(e){ dragging=true; t0=performance.now(); traj=[]; img.setPointerCapture(e.pointerId); e.preventDefault(); });
    img.addEventListener("pointermove", function(e){ if(!dragging) return; cur=angleAt(e); img.style.transform="rotate("+cur+"deg)"; traj.push({t:performance.now()-t0, angle:cur}); });
    img.addEventListener("pointerup", async function(){ if(!dragging) return; dragging=false; say("Verifying the rotation…");
      var v=await (await fetch("/arena/rotate/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, trajectory:traj})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Rotated upright with a human-like drag."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Rotate PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Rejected: "+(v.reason||"try again"); say("Rotate rejected: "+(v.reason||"")); }
      box.innerHTML=""; fetchDetectorVerdict();
    });
    say("Drag the arrow to point up.");
  }

  async function runPACT(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    say("Requesting an anonymous personhood token from the issuer…");
    var t=await (await fetch("/arena/pact")).json();
    var v=await (await fetch("/arena/pact/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token:t.token})})).json();
    if(v.decision==="allow"){
      gv.textContent="SKIPPED"; gv.className="big pass";
      gn.textContent="Valid personhood token → challenge skipped (the PACT behaviour). Note: the issuer mints freely in-sandbox, so this is also the bypass — a token is only as strong as the issuer's proof + key secrecy.";
      tok.innerHTML='<p class="note">token <code>'+String(t.token||"").slice(0,28)+'…</code></p>'; say("PACT: challenge skipped on a valid token.");
    } else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Token rejected: "+(v.reason||""); say("PACT rejected: "+(v.reason||"")); }
    fetchDetectorVerdict();
  }

  // reCAPTCHA-v2 / Turnstile-style checkbox: render the "Verify you are human" box; the CLICK triggers the
  // managed coherence check. A coherent client passes on the click (no puzzle, the silent success); an
  // incoherent one is stepped up to a proof-of-work — the documented managed ladder, behind the iconic widget.
  async function runCheckbox(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var cb=document.createElement("div"); cb.className="ks-checkbox"; cb.id="ks-cb";
    cb.setAttribute("role","checkbox"); cb.setAttribute("aria-checked","false"); cb.tabIndex=0;
    cb.innerHTML='<span class="ks-cb-box"><span class="ks-cb-mark">✓</span><span class="ks-cb-spin"></span></span>'+
      '<span class="ks-cb-label">Verify you are human</span><span class="ks-cb-brand">Kitsune&nbsp;Arena</span>';
    box.appendChild(cb);
    say("Click the box to verify.");
    var done=false;
    async function go(){
      if(done) return; done=true;
      cb.classList.add("checking"); cb.setAttribute("aria-busy","true"); say("Verifying…");
      try{
        var m=await (await fetch("/arena/managed?step=1")).json();
        if(m.decision==="allow"){
          cb.classList.remove("checking"); cb.classList.add("ok"); cb.setAttribute("aria-checked","true");
          gv.textContent="VERIFIED"; gv.className="big pass";
          gn.textContent="Passed on the click — your client looks coherent ("+m.label+"). A human clicks and is through, no puzzle (the Turnstile/reCAPTCHA-v2 checkbox behaviour).";
          say("Verified — passed on the click, no challenge.");
        } else {
          gn.textContent="Stepping up — your client looks "+(m.label||"unknown")+", so the checkbox escalates to a proof-of-work.";
          say("Additional verification — solving the escalated proof-of-work…");
          var ok=false; if(m.challenge){ ok=await solveAndVerify(m.challenge, gv, gn, tok); }
          cb.classList.remove("checking");
          if(ok){ cb.classList.add("ok"); cb.setAttribute("aria-checked","true"); }
          else { cb.classList.add("fail"); if(!m.challenge){ gv.textContent="STEP-UP"; gv.className="big fail"; say("Step-up required, but the PoW gate is unavailable."); } }
        }
      }catch(err){ cb.classList.remove("checking"); cb.classList.add("fail"); say("Error: "+(err&&err.message||err)); }
      fetchDetectorVerdict();
    }
    cb.addEventListener("click", go);
    cb.addEventListener("keydown", function(e){ if(e.key===" "||e.key==="Enter"){ e.preventDefault(); go(); } });
  }

  async function runManaged(gv, gn, tok){
    say("Managed challenge — reading your client silently…");
    var m=await (await fetch(withLevel("/arena/managed?step=1"))).json();
    if(m.decision==="allow"){
      gv.textContent="ALLOWED"; gv.className="big pass";
      gn.textContent="Passed silently — your client looks coherent ("+m.label+"). No puzzle shown, like a managed challenge's non-interactive success.";
      say("Allowed silently (label "+m.label+").");
    } else {
      gn.textContent="Stepping up — your client looks "+(m.label||"unknown")+", so the ladder escalates to a proof-of-work.";
      say("Step-up: solving the escalated proof-of-work…");
      if(m.challenge){ await solveAndVerify(m.challenge, gv, gn, tok); }
      else { gv.textContent="STEP-UP"; gv.className="big fail"; say("Step-up required, but the PoW gate is unavailable."); }
    }
  }

  // The challenge serves itself: no "run" button — start() fires on page load and renders the widget (or
  // auto-solves, for the non-interactive PoW / PACT / managed gates). A subtle "new challenge" link re-runs it.
  var running=false;
  async function start(){
    if(running) return; running=true;
    var gv=document.getElementById("ks-gate-verdict"), gn=document.getElementById("ks-gate-note"), tok=document.getElementById("ks-token");
    gv.textContent="—"; gv.className="big"; gn.textContent="Did your solution satisfy the challenge?"; tok.innerHTML=""; document.getElementById("ks-captcha").innerHTML="";
    try{
      if(A.mode==="checkbox"){ await runCheckbox(gv, gn, tok); }
      else if(A.mode==="pact"){ await runPACT(gv, gn, tok); }
      else if(A.mode==="slider"){ await runSlider(gv, gn, tok); }
      else if(A.mode==="image-select"){ await runImageSelect(gv, gn, tok); }
      else if(A.mode==="rotate"){ await runRotate(gv, gn, tok); }
      else if(A.mode==="captcha"){ await runCaptcha(gate, gv, gn, tok); }
      else if(A.mode==="managed"){ await runManaged(gv, gn, tok); }
      else {
        say("Requesting a "+gate+" ("+LEVEL+") challenge…");
        var cr=await fetch(withLevel("/arena/challenge?gate="+encodeURIComponent(gate)));
        if(!cr.ok){ say("Gate unavailable ("+cr.status+")."); }
        else { await solveAndVerify(await cr.json(), gv, gn, tok); }
      }
    }catch(err){ say("Error: "+(err&&err.message||err)); }
    running=false;
    fetchDetectorVerdict();
  }
  var again=document.getElementById("ks-again");
  if(again){ again.addEventListener("click", function(e){ e.preventDefault(); start(); }); }
  // Difficulty selector (cost dial): switch level → re-serve the challenge at the new cost.
  var lvls=document.getElementById("ks-levels");
  if(lvls){ lvls.addEventListener("click", function(e){
    var b=e.target.closest("button[data-level]"); if(!b) return;
    LEVEL=b.getAttribute("data-level");
    Array.prototype.forEach.call(this.querySelectorAll("button"), function(x){ x.setAttribute("aria-pressed", String(x===b)); });
    start();
  }); }
  fetchDetectorVerdict();
  start();
})();
"""

# Reused HTML fragments (trusted markup; inserted raw into the doc-shell <main>).
_VERDICTS_HTML = """
<div class="verdicts">
  <div class="vcard">
    <h3>Gate verdict</h3>
    <div class="big" id="ks-gate-verdict">&mdash;</div>
    <p class="note" id="ks-gate-note">Did your solution satisfy the challenge?</p>
    <div id="ks-token"></div>
  </div>
  <div class="vcard">
    <h3>Detector verdict</h3>
    <div class="big" id="ks-det-verdict">&mdash;</div>
    <p class="note" id="ks-det-note">What Kitsune&rsquo;s coherence engine independently makes of your client over the edge. For your full fingerprint, run the <a href="/">detector</a>.</p>
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
    "Faithful reproductions of documented open web challenge mechanisms — proof-of-work, CAPTCHA, "
    "slider, rotate, and a PACT personhood token. Solve a gate in your browser and see what Kitsune's "
    "bot detector independently makes of your client."
)


# Gates with no difficulty axis: honeypot (trap-or-not), pact (token-or-not), checkbox + managed
# (coherence-gated — the difficulty is the client's own coherence, not an operator dial).
_NO_LEVEL_SLUGS = frozenset({"honeypot", "pact", "checkbox", "managed"})


def _has_levels(c: dict[str, str]) -> bool:
    """Whether this gate exposes an easy/medium/hard difficulty (a cost dial). False for honeypot/pact."""
    return c["slug"] not in _NO_LEVEL_SLUGS


def _gate_script(c: dict[str, str]) -> str:
    """The per-page <script>: pin window.__ARENA__ to this gate, then run the shared arena JS."""
    cfg = json.dumps({"slug": c["slug"], "mode": c["mode"], "level": "medium", "levels": _has_levels(c)})
    return f"<script>window.__ARENA__={cfg};{ARENA_JS}</script>"


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
        return [("GET", "/arena/captcha?kind=image-select"), ("POST", "/arena/captcha/verify")]
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


def arena_index_html() -> str:
    """The ``/arena`` index: the thesis intro + a card grid linking to every challenge's own page."""
    cards = "".join(
        f'<a class="card" href="/arena/gate/{c["slug"]}">'
        f'<div class="cn">{c["label"]}</div>'
        f'<div class="cm">{c["family"]}</div>'
        f'<div class="cd">{c["blurb"]}</div></a>'
        for c in CHALLENGES
    )
    body = f"""
<h1>The Arena</h1>
<p class="lead">Faithful, self-hosted reproductions of <b>documented, open</b> web challenge mechanisms. Each
gate has its <b>own page that auto-serves the challenge</b> &mdash; go there with a browser, a bot, or your own
solver and <b>test the bypass</b>. You get <b>two verdicts at once</b>: did you pass the gate &mdash; and what does
Kitsune&rsquo;s detector independently make of your client over the edge?</p>
<p class="note">The punchline the arena makes live: a solved challenge is a <b>cost</b> or <b>Turing</b> test, not a
bot/human discriminator. A script can bypass any gate here and still be convicted on the network layer &mdash;
<b>coherence + attestation</b> is the durable signal, not the puzzle.</p>
<h2>Pick a gate to bypass</h2>
<div class="cards">{cards}</div>
{_ETHICS_HTML}
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
<h1>{c["label"]}</h1>
<p class="arena-family">{c["family"]}</p>
<p class="lead">{c["blurb"]}</p>
<p class="note">This gate <b>auto-serves on load</b> &mdash; bring a browser, a bot, or your own solver and try to
<b>bypass it</b>. You get two verdicts: did you pass the gate &mdash; and does Kitsune&rsquo;s detector independently
convict your client over the edge?</p>
{levels_html}
<section class="arena-stage" aria-label="challenge">
  <div class="arena-log" id="ks-log">Loading the challenge&hellip;</div>
  <div id="ks-captcha"></div>
  <p class="arena-again-wrap"><a href="#" id="ks-again" class="arena-again">&#8635; New challenge</a></p>
</section>
{_VERDICTS_HTML}
{_endpoints_html(c)}
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
