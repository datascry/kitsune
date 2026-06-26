# detector/arena_page — the public /arena page: challenge our gates, meet our detector.
# In-browser SHA-256 PoW solver (hashcash/many-small) + the dual gate-vs-detector verdict, on owned gates only.

"""The ``/arena`` page — the live, interactive reproduction of documented OPEN web challenge mechanisms.

A visitor picks a gate, gets a real PoW challenge from the owned ``arena`` service (relayed by the detector),
solves it in-browser (SHA-256 families) or brings their own solver (memory-hard), and sees TWO verdicts: the
gate's (did you solve the proof-of-work?) and the detector's (does your client cohere?). The point the page
makes live: a PoW gate is a *cost* test, not a bot/human discriminator — a script can pass the gate and still
be convicted on the network layer. The gates only ever model documented open mechanisms and only ever talk to
themselves; the page carries a vendor-neutral disclaimer.
"""

from __future__ import annotations

from .styles import SHARED_CSS

ARENA_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>The Arena — challenge the gates, meet the detector · Kitsune</title>
<meta name="description" content="Faithful reproductions of documented open web challenge mechanisms (proof-of-work). Solve the gate in your browser and see what Kitsune's bot detector independently sees about your client.">
<link rel="icon" href="/favicon.svg">
<style>
/*__SHARED_CSS__*/
.arena-gates{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}
.arena-gates button{font:inherit;padding:.5rem .9rem;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--ink);cursor:pointer;min-height:44px}
.arena-gates button[aria-pressed=true]{border-color:var(--fox);color:var(--fox);font-weight:600}
.arena-run{font:inherit;font-weight:600;padding:.6rem 1.2rem;border:0;border-radius:8px;background:var(--fox);color:#fff;cursor:pointer;min-height:44px}
.arena-run:disabled{opacity:.5;cursor:default}
.verdicts{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:1.25rem}
.vcard{border:1px solid var(--line);border-radius:10px;padding:1rem}
.vcard h3{margin:0 0 .4rem;font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.vcard .big{font-size:1.4rem;font-weight:700}
.vcard .pass{color:#1f9d55}.vcard .fail{color:var(--fox)}
.vcard code{font-size:.8rem;word-break:break-all}
.arena-log{font-family:ui-monospace,monospace;font-size:.78rem;background:rgba(127,127,127,.08);border-radius:8px;padding:.6rem .8rem;margin-top:.6rem;white-space:pre-wrap;min-height:1.4rem}
#ks-captcha{margin-top:.8rem}
#ks-captcha img{vertical-align:middle;border:1px solid var(--line);border-radius:6px;background:#fff;margin-bottom:.5rem}
#ks-captcha input{font:inherit;padding:.5rem;border:1px solid var(--line);border-radius:6px;min-height:44px;margin-right:.5rem}
#ks-captcha button{font:inherit;font-weight:600;padding:.5rem 1rem;border:0;border-radius:6px;background:var(--fox);color:#fff;cursor:pointer;min-height:44px}
#ks-captcha .slider-track{position:relative;height:44px;max-width:100%;background:rgba(127,127,127,.12);border:1px solid var(--line);border-radius:8px;margin:.5rem 0;touch-action:none}
#ks-captcha .slider-gap{position:absolute;top:5px;height:34px;width:42px;border:2px dashed var(--muted);border-radius:6px;box-sizing:border-box}
#ks-captcha .slider-handle{position:absolute;top:3px;height:38px;width:42px;background:var(--fox);border-radius:6px;cursor:grab;box-sizing:border-box;touch-action:none}
#ks-captcha .tiles{display:grid;grid-template-columns:repeat(3,60px);gap:6px;margin:.5rem 0}
#ks-captcha .tiles img{width:60px;height:60px;border:2px solid var(--line);border-radius:6px;cursor:pointer;background:#fff}
#ks-captcha .tiles img.sel{border-color:var(--fox);box-shadow:0 0 0 2px var(--fox)}
#ks-captcha .rot img{width:90px;height:90px;transition:transform .1s}
@media (max-width:640px){.verdicts{grid-template-columns:1fr}}
</style>
</head>
<body>
<nav class="top"><a class="brand" href="/">KITSUNE</a> <a href="/">Detector</a> <a href="/arena">Arena</a> <a href="/detections">Detections</a></nav>
<main>
<h1 class="page">The Arena</h1>
<p class="lead">Faithful reproductions of <b>documented, open</b> web challenge mechanisms &mdash; a <b>managed-challenge ladder</b>
(Turnstile-style escalation), proof-of-work gates in the <abbr title="TecharoHQ/anubis">anubis</abbr>,
<abbr title="friendlycaptcha">friendly-captcha</abbr> and <abbr title="altcha-org/altcha">altcha</abbr> families,
and self-hosted <b>CAPTCHA</b> gates: distorted-text image, arithmetic, honeypot, a GeeTest-style drag <b>slider</b>,
an <b>image-select</b> tile grid, and a <b>rotate</b>-upright puzzle.
Pick a gate, run it in your browser, and see <b>two verdicts at once</b>: did you pass the gate &mdash; and what does Kitsune&rsquo;s detector independently make of your client?</p>
<p class="note">In the <b>managed</b> gate, the silent first step <i>is</i> the coherence detector: a coherent client passes with no puzzle; only an incoherent one is stepped up to a proof-of-work &mdash; exactly the documented managed-challenge ladder.</p>
<p class="note">The punchline: a proof-of-work gate is a <b>cost</b> test, not a bot/human test. A script can solve the gate and still be convicted on the network layer &mdash; coherence is the durable signal, not cost.</p>

<section aria-label="challenge gate">
  <h2>1 · Pick a gate</h2>
  <div class="arena-gates" id="ks-gates">
    <button data-gate="managed" aria-pressed="true">managed <span class="note">&middot; Turnstile-style ladder</span></button>
    <button data-gate="hashcash" aria-pressed="false">hashcash <span class="note">&middot; SHA-256 leading-zeros</span></button>
    <button data-gate="many-small" aria-pressed="false">many-small <span class="note">&middot; N sub-puzzles</span></button>
    <button data-gate="memory-hard" aria-pressed="false">memory-hard <span class="note">&middot; Argon2id</span></button>
    <button data-gate="text" aria-pressed="false">captcha&middot;text <span class="note">&middot; distorted image</span></button>
    <button data-gate="math" aria-pressed="false">captcha&middot;math <span class="note">&middot; arithmetic</span></button>
    <button data-gate="honeypot" aria-pressed="false">captcha&middot;honeypot <span class="note">&middot; hidden trap</span></button>
    <button data-gate="slider" aria-pressed="false">captcha&middot;slider <span class="note">&middot; GeeTest-style drag</span></button>
    <button data-gate="image-select" aria-pressed="false">captcha&middot;image <span class="note">&middot; select matching tiles</span></button>
    <button data-gate="rotate" aria-pressed="false">captcha&middot;rotate <span class="note">&middot; rotate upright</span></button>
  </div>
  <button class="arena-run" id="ks-run">Run the gate</button>
  <div class="arena-log" id="ks-log">Ready.</div>
  <div id="ks-captcha"></div>
</section>

<div class="verdicts">
  <div class="vcard">
    <h3>Gate verdict</h3>
    <div class="big" id="ks-gate-verdict">&mdash;</div>
    <p class="note" id="ks-gate-note">Did your solution satisfy the proof-of-work?</p>
    <div id="ks-token"></div>
  </div>
  <div class="vcard">
    <h3>Detector verdict</h3>
    <div class="big" id="ks-det-verdict">&mdash;</div>
    <p class="note" id="ks-det-note">What Kitsune&rsquo;s coherence engine makes of your client over the edge. For your full fingerprint, run the <a href="/">detector</a>.</p>
  </div>
</div>

<details class="ks-disclose" style="margin-top:1.5rem"><summary>How this works &amp; the ethics</summary>
<p class="note">The gate is a self-hosted service Kitsune runs (the owned <code>arena</code> service). It reproduces the
<i>documented, open</i> proof-of-work mechanisms above &mdash; it <b>never</b> contacts, proxies to, or solves a third-party
challenge (Cloudflare Turnstile, reCAPTCHA, hCaptcha). The reference solvers only ever talk to our own gates. The detector
verdict comes from the same coherence engine that scores the home page, reading your client over the edge.</p></details>

</main>
<footer><p>Kitsune &mdash; the blue-team side of a bot detection &#8644; evasion lab. The arena gates are reproductions of documented open mechanisms for detection research; <b>not affiliated with any named vendor</b>, and they never contact third-party endpoints. <a href="https://github.com/datascry/kitsune">Source on GitHub</a>.</p></footer>

<script>
(function(){
  "use strict";
  var enc = new TextEncoder();
  function hexToBytes(h){ var a=new Uint8Array(h.length/2); for(var i=0;i<a.length;i++){ a[i]=parseInt(h.substr(i*2,2),16);} return a; }
  function leadingZeroBits(d){ var n=0; for(var i=0;i<d.length;i++){ var b=d[i]; if(b===0){ n+=8; continue;} var x=b,c=0; while((x&0x80)===0){ c++; x=(x<<1)&0xff;} n+=c; break;} return n; }
  // workDigest mirrors the Go gate: sha256( subNonce_bytes || nonce_bytes || uint64_le(counter) ).
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

  var gate="managed";
  var CAPTCHA=["text","math","honeypot"]; // the self-hosted CAPTCHA families (human-answered, not auto-solved)
  var log=document.getElementById("ks-log");
  function say(m){ log.textContent=m; }
  document.getElementById("ks-gates").addEventListener("click", function(e){
    var b=e.target.closest("button[data-gate]"); if(!b) return;
    gate=b.getAttribute("data-gate");
    Array.prototype.forEach.call(this.querySelectorAll("button"), function(x){ x.setAttribute("aria-pressed", String(x===b)); });
  });

  // The detector panel reads the PUBLIC, cookie-scoped /arena/managed (only your OWN session's decision) —
  // not the admin-gated /verdict — so it works on the live site too.
  async function fetchDetectorVerdict(){
    var out=document.getElementById("ks-det-verdict");
    try{
      var r=await fetch("/arena/managed");
      if(!r.ok){ out.textContent="—"; return; }
      var v=await r.json();
      var label=String(v.label||"?");
      out.textContent=label.toUpperCase();
      out.className="big "+(label==="human"||label==="verified"?"pass":"fail");
    }catch(_){ out.textContent="—"; }
  }

  // Solve a PoW challenge in-browser (SHA-256 families) and verify it with the gate. Returns true on PASS.
  async function solveAndVerify(c, gv, gn, tok){
    if(c.class==="memory-hard"){
      say("memory-hard (Argon2id) resists cheap solving — that's the point. Bring your own solver (the reference evaders/pow solver), or try hashcash / many-small here.\\nChallenge: "+JSON.stringify(c));
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

  // CAPTCHA flow: fetch a self-hosted challenge, render it (image/prompt + answer box, or a honeypot trap),
  // and verify the human's answer. A challenge is a Turing test, not a coherence test — see the detector panel.
  async function runCaptcha(kind, gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    say("Requesting a "+kind+" CAPTCHA…");
    var cr=await fetch("/arena/captcha?kind="+encodeURIComponent(kind));
    if(!cr.ok){ say("CAPTCHA gate unavailable ("+cr.status+")."); return; }
    var c=await cr.json();
    var wrap=document.createElement("div");
    if(c.image){ var img=document.createElement("img"); img.src=c.image; img.alt="text challenge"; wrap.appendChild(img); wrap.appendChild(document.createElement("br")); }
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; wrap.appendChild(p);
    var submit=document.createElement("button");
    if(kind==="honeypot"){
      var hn=document.createElement("p"); hn.className="note"; hn.textContent="(A hidden field '"+c.field+"' must stay empty — a bot that fills every field trips it.)"; wrap.appendChild(hn);
      submit.textContent="Submit form";
      submit.onclick=function(){ verifyCaptcha(kind, c.id, "", gv, gn, tok); }; // the trap is left empty
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

  // Slider (GeeTest-style): drag the block into the gap. The gate checks the drop position AND the drag
  // trajectory's velocity variation — a constant-velocity glide or a teleport is rejected (the on-thesis part).
  async function runSlider(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    say("Requesting a slider challenge…");
    var s=await (await fetch("/arena/slider")).json();
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

  // Image-select (reCAPTCHA-v2 category): pick the tiles matching the prompt. Tiles are unlabelled owned SVGs.
  async function runImageSelect(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch("/arena/captcha?kind=image-select")).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var grid=document.createElement("div"); grid.className="tiles"; var sel={};
    c.tiles.forEach(function(src,i){ var img=document.createElement("img"); img.src=src; img.alt="tile "+(i+1);
      img.onclick=function(){ if(sel[i]){ delete sel[i]; img.classList.remove("sel"); } else { sel[i]=1; img.classList.add("sel"); } }; grid.appendChild(img); });
    box.appendChild(grid);
    var submit=document.createElement("button"); submit.textContent="Verify selection";
    submit.onclick=function(){ var idx=Object.keys(sel).map(Number).sort(function(a,b){return a-b;}).join(","); verifyCaptcha("image-select", c.id, idx, gv, gn, tok); };
    box.appendChild(submit); say("Select the matching tiles and verify.");
  }
  // Rotate (Arkose/FunCaptcha category): rotate the object upright. The page tracks the displayed angle.
  async function runRotate(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch("/arena/captcha?kind=rotate")).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var cur=c.angle, wrap=document.createElement("div"); wrap.className="rot";
    var img=document.createElement("img"); img.src=c.image; img.alt="rotate target"; img.style.transform="rotate("+cur+"deg)"; wrap.appendChild(img); box.appendChild(wrap);
    var ctrl=document.createElement("div");
    function mk(label,delta){ var b=document.createElement("button"); b.textContent=label; b.style.marginRight=".4rem"; b.onclick=function(){ cur=(cur+delta+360)%360; img.style.transform="rotate("+cur+"deg)"; }; return b; }
    ctrl.appendChild(mk("\\u21ba \\u221215\\u00b0",-15)); ctrl.appendChild(mk("+15\\u00b0 \\u21bb",15));
    var submit=document.createElement("button"); submit.textContent="Verify"; submit.onclick=function(){ verifyCaptcha("rotate", c.id, String(cur), gv, gn, tok); };
    ctrl.appendChild(submit); box.appendChild(ctrl); say("Rotate the arrow upright and verify.");
  }

  document.getElementById("ks-run").addEventListener("click", async function(){
    var btn=this; btn.disabled=true;
    var gv=document.getElementById("ks-gate-verdict"), gn=document.getElementById("ks-gate-note"), tok=document.getElementById("ks-token");
    gv.textContent="—"; gv.className="big"; tok.innerHTML=""; document.getElementById("ks-captcha").innerHTML="";
    try{
      if(gate==="slider"){ await runSlider(gv, gn, tok); btn.disabled=false; return; }
      if(gate==="image-select"){ await runImageSelect(gv, gn, tok); btn.disabled=false; return; }
      if(gate==="rotate"){ await runRotate(gv, gn, tok); btn.disabled=false; return; }
      if(CAPTCHA.indexOf(gate)>=0){ await runCaptcha(gate, gv, gn, tok); btn.disabled=false; return; }
      if(gate==="managed"){
        // The Turnstile-style ladder: the SILENT step is the detector's coherence verdict; only an
        // incoherent client is stepped up to a proof-of-work.
        say("Managed challenge — reading your client silently…");
        var m=await (await fetch("/arena/managed?step=1")).json();
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
      } else {
        // A modest difficulty keeps the in-browser SHA-256 solve near-instant; the gate accepts the param.
        var diff = gate==="many-small" ? 10 : 16;
        say("Requesting a "+gate+" challenge…");
        var cr=await fetch("/arena/challenge?gate="+encodeURIComponent(gate)+"&difficulty="+diff);
        if(!cr.ok){ say("Gate unavailable ("+cr.status+")."); btn.disabled=false; return; }
        await solveAndVerify(await cr.json(), gv, gn, tok);
      }
    }catch(err){ say("Error: "+(err&&err.message||err)); }
    btn.disabled=false;
    fetchDetectorVerdict();
  });

  fetchDetectorVerdict();
})();
</script>
</body>
</html>
"""

ARENA_PAGE = ARENA_PAGE.replace("/*__SHARED_CSS__*/", SHARED_CSS.rstrip())
