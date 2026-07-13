// detector/arena.js — the shared arena challenge-gate client (was arena_page.py's inline ARENA_JS).
// Reads window.__ARENA__ (slug, mode) set per page, then runs that one gate's solver/wait flow.
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
      var cls=(label==="human"||label==="verified")?"pass":(label==="unknown"||label==="?")?"unknown":"fail";
      out.className="big "+cls;
    }catch(_){ out.textContent="—"; }
  }

  async function solveAndVerify(c, gv, gn, tok){
    if(!(window.crypto&&crypto.subtle&&crypto.subtle.digest)){
      say("In-browser proof-of-work needs the Web Crypto API (a secure HTTPS context). Solve it with the reference evaders/pow solver against the endpoints below."); return false;
    }
    if(c.class==="memory-hard"){
      say("memory-hard (Argon2id) resists cheap solving — that's the point. Bring your own solver (the reference evaders/pow solver), or try hashcash / many-small.");
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
  async function runAudio(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    say("Requesting an audio CAPTCHA…");
    var cr=await fetch(withLevel("/arena/audio"));
    if(!cr.ok){ say("Audio gate unavailable ("+cr.status+")."); return; }
    var c=await cr.json();
    var wrap=document.createElement("div");
    var au=document.createElement("audio"); au.controls=true; au.src=c.clip; wrap.appendChild(au); wrap.appendChild(document.createElement("br"));
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt+" ("+c.digits+" digits)"; wrap.appendChild(p);
    var inp=document.createElement("input"); inp.type="text"; inp.inputMode="numeric"; inp.autocomplete="off"; inp.placeholder="The digits you hear"; wrap.appendChild(inp);
    var submit=document.createElement("button"); submit.textContent="Submit answer";
    submit.onclick=function(){ verifyAudio(c.id, inp.value, gv, gn, tok); };
    inp.addEventListener("keydown", function(e){ if(e.key==="Enter"){ submit.click(); } });
    wrap.appendChild(submit); box.appendChild(wrap);
    say("Play the clip, type the digits you hear, and submit.");
  }
  async function verifyAudio(id, answer, gv, gn, tok){
    var v=await (await fetch("/arena/audio/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:id,answer:answer})})).json();
    if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Audio solved — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Audio PASSED."); }
    else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Wrong answer (or the challenge expired)."; say("Audio rejected."); }
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
    var kind=A.kind||"image-select"; // emoji grid or Quick-Draw doodle grid
    var c=await (await fetch(withLevel("/arena/captcha?kind="+kind))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var grid=document.createElement("div"); grid.className="tiles"; var sel={};
    c.tiles.forEach(function(src,i){ var img=document.createElement("img"); img.src=src; img.alt="tile "+(i+1);
      img.onclick=function(){ if(sel[i]){ delete sel[i]; img.classList.remove("sel"); } else { sel[i]=1; img.classList.add("sel"); } }; grid.appendChild(img); });
    box.appendChild(grid);
    var submit=document.createElement("button"); submit.textContent="Verify selection";
    submit.onclick=function(){ var idx=Object.keys(sel).map(Number).sort(function(a,b){return a-b;}).join(","); verifyCaptcha(kind, c.id, idx, gv, gn, tok); };
    box.appendChild(submit); say("Select the matching tiles and verify.");
  }

  async function runSpatial(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/spatial"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var grid=document.createElement("div"); grid.className="tiles"; var sel={};
    c.tiles.forEach(function(tile,i){ var img=document.createElement("img"); img.src=tile.image; img.alt="cube "+(i+1);
      img.onclick=function(){ if(sel[i]){ delete sel[i]; img.classList.remove("sel"); } else { sel[i]=1; img.classList.add("sel"); } }; grid.appendChild(img); });
    box.appendChild(grid);
    var submit=document.createElement("button"); submit.textContent="Verify selection";
    submit.onclick=function(){ var idx=Object.keys(sel).map(Number).sort(function(a,b){return a-b;}); verifySpatial(c.id, idx, gv, gn, tok); };
    box.appendChild(submit); say("Select every cube with the named colour on top, then verify.");
  }
  async function verifySpatial(id, selected, gv, gn, tok){
    var v=await (await fetch("/arena/spatial/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:id,selected:selected})})).json();
    if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Spatial grid solved — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Spatial PASSED."); }
    else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Wrong selection (or the challenge expired)."; say("Spatial rejected."); }
    document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
  }

  async function runShell(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/shell"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var arena=document.createElement("div"); arena.style.cssText="position:relative;height:92px;margin:.5rem 0"; box.appendChild(arena);
    var N=c.cups, slotW=Math.min(96,Math.floor(360/N)), cupW=slotW-8;
    function slotX(s){ return s*slotW+4; }
    var cups=[], slotOfCup=[], cupInSlot=[];
    for(var i=0;i<N;i++){ var cup=document.createElement("div");
      cup.style.cssText="position:absolute;top:22px;width:"+cupW+"px;height:60px;background:var(--fox);border-radius:9px 9px 0 0;cursor:default;left:"+slotX(i)+"px;";
      arena.appendChild(cup); cups.push(cup); slotOfCup.push(i); cupInSlot[i]=i; }
    var ball=document.createElement("div");
    ball.style.cssText="position:absolute;top:58px;width:18px;height:18px;border-radius:50%;background:#fff;border:2px solid #333;left:"+(slotX(c.start)+cupW/2-9)+"px;";
    arena.appendChild(ball);
    var wait=function(ms){ return new Promise(function(r){ setTimeout(r,ms); }); };
    say("Watch the ball…");
    cups[c.start].style.transition="top .3s"; cups[c.start].style.top="-14px"; await wait(750);
    cups[c.start].style.top="22px"; ball.style.display="none"; await wait(400);
    for(var k=0;k<c.swaps.length;k++){ var sw=c.swaps[k];
      var ci=cupInSlot[sw.a], cj=cupInSlot[sw.b];
      cups[ci].style.transition="left "+sw.ms+"ms ease-in-out"; cups[cj].style.transition="left "+sw.ms+"ms ease-in-out";
      cups[ci].style.left=slotX(sw.b)+"px"; cups[cj].style.left=slotX(sw.a)+"px";
      slotOfCup[ci]=sw.b; slotOfCup[cj]=sw.a; cupInSlot[sw.a]=cj; cupInSlot[sw.b]=ci;
      await wait(sw.ms); }
    say("Click the cup hiding the ball.");
    cups.forEach(function(cup,idx){ cup.style.cursor="pointer";
      cup.onclick=function(){ verifyShell(c.id, String(slotOfCup[idx]), gv, gn, tok); }; });
  }
  async function verifyShell(id, choice, gv, gn, tok){
    var v=await (await fetch("/arena/shell/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:id,choice:choice})})).json();
    if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Shell game solved — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Shell PASSED."); }
    else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Wrong cup (or the challenge expired)."; say("Shell rejected."); }
    document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
  }

  async function runTiming(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/timing"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var label=document.createElement("p"); label.className="note"; box.appendChild(label);
    var btn=document.createElement("button"); btn.textContent="Hold"; btn.style.minWidth="130px"; box.appendChild(btn);
    var track=document.createElement("div"); track.style.cssText="position:relative;height:16px;max-width:320px;margin:.7rem 0;background:var(--panel-2);border:1px solid var(--line-bright);border-radius:8px;overflow:hidden";
    var win=document.createElement("div"); win.style.cssText="position:absolute;top:0;bottom:0;background:rgba(95,184,154,.28);border-left:1.5px solid var(--jade);border-right:1.5px solid var(--jade)"; track.appendChild(win);
    var fill=document.createElement("div"); fill.style.cssText="position:absolute;left:0;top:0;bottom:0;width:0;background:var(--fox);opacity:.85"; track.appendChild(fill);
    box.appendChild(track);
    var status=document.createElement("p"); status.className="note"; box.appendChild(status);
    var holds=[], idx=0, t0=0, raf=0, curT=0, curTol=0, curMax=1000;
    function showTarget(){
      if(idx>=c.targets.length){ submit(); return; }
      var t=c.targets[idx]; curT=t.hold_ms; curTol=t.tolerance_ms;
      curMax=curT+curTol+Math.max(Math.round(curT*0.4), 300);
      win.style.left=((curT-curTol)/curMax*100)+"%"; win.style.width=((2*curTol)/curMax*100)+"%"; fill.style.width="0";
      label.textContent="Target "+(idx+1)+"/"+c.targets.length+": hold for "+curT+" ms (±"+curTol+") — release in the green window";
    }
    function tick(){ if(!t0) return; var ms=performance.now()-t0;
      fill.style.width=Math.min(100, ms/curMax*100)+"%";
      var inWin=ms>=curT-curTol && ms<=curT+curTol; fill.style.background=inWin?"var(--jade)":"var(--fox)";
      status.textContent=(inWin?"release now — ":"holding… ")+Math.round(ms)+" / "+curT+" ms"; raf=requestAnimationFrame(tick);
    }
    btn.addEventListener("pointerdown", function(e){ e.preventDefault(); t0=performance.now(); raf=requestAnimationFrame(tick); });
    btn.addEventListener("pointerup", function(e){ if(!t0) return; if(raf) cancelAnimationFrame(raf); var ms=Math.round(performance.now()-t0); t0=0;
      holds.push(ms); var t=c.targets[idx]; var err=ms-t.hold_ms;
      status.textContent="held "+ms+" ms ("+(err>=0?"+":"")+err+" ms)"; idx++; setTimeout(showTarget, 600); });
    async function submit(){
      btn.disabled=true; label.textContent="Verifying…";
      var v=await (await fetch("/arena/timing/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, holds:holds})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Timing solved — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Timing PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Some holds were out of tolerance — try again."; say("Timing rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    }
    showTarget(); say("Press and hold the button for each shown duration, then release.");
  }

  async function runKeymap(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/keymap"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var tgt=document.createElement("p"); tgt.className="note"; tgt.innerHTML="Target: <code>"+c.target+"</code>"; box.appendChild(tgt);
    var out=document.createElement("div"); out.style.cssText="font:1.2rem monospace;min-height:1.4rem;letter-spacing:2px;border:1px solid var(--line-bright);border-radius:6px;padding:.4rem;margin:.4rem 0;background:var(--panel)"; box.appendChild(out);
    var kb=document.createElement("div"); kb.style.cssText="display:flex;flex-wrap:wrap;gap:4px;margin:.4rem 0"; box.appendChild(kb);
    var trace=[], buf="";
    function render(){ out.textContent=buf; }
    Object.keys(c.remap).sort().forEach(function(k){
      var b=document.createElement("button"); b.textContent=k; b.style.cssText="min-width:34px;min-height:34px;padding:0;font:inherit";
      b.onclick=function(){ trace.push(k); buf+=c.remap[k]; render(); }; kb.appendChild(b);
    });
    var back=document.createElement("button"); back.textContent="⌫"; back.style.cssText="min-width:44px;min-height:34px";
    back.onclick=function(){ trace.push("BACK"); buf=buf.slice(0,-1); render(); }; kb.appendChild(back);
    var submit=document.createElement("button"); submit.textContent="Submit"; submit.style.cssText="display:block;margin-top:.5rem;font-weight:600";
    submit.onclick=async function(){
      var v=await (await fetch("/arena/keymap/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, trace:trace})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Keyboard solved — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Keymap PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="That is not the target (or the challenge expired)."; say("Keymap rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    };
    box.appendChild(submit);
    render(); say("Try keys to learn the remap, type the target, then submit.");
  }

  async function runPresshold(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/presshold"))).json();
    var target=c.hold_ms, tol=c.tolerance_ms;
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var label=document.createElement("p"); label.className="note"; label.textContent="Hold for "+target+" ms (±"+tol+") — release when the bar reaches the green window."; box.appendChild(label);
    var btn=document.createElement("button"); btn.textContent="Press & Hold"; btn.style.minWidth="150px"; btn.style.minHeight="46px"; box.appendChild(btn);
    // Live timer: a progress bar whose fill tracks the elapsed hold, with a green window marking the target
    // release band (target ± tolerance) — so the user aims for a visible zone instead of guessing.
    var track=document.createElement("div"); track.style.cssText="position:relative;height:16px;max-width:320px;margin:.7rem 0;background:var(--panel-2);border:1px solid var(--line-bright);border-radius:8px;overflow:hidden";
    var win=document.createElement("div"); win.style.cssText="position:absolute;top:0;bottom:0;background:rgba(95,184,154,.28);border-left:1.5px solid var(--jade);border-right:1.5px solid var(--jade)"; track.appendChild(win);
    var fill=document.createElement("div"); fill.style.cssText="position:absolute;left:0;top:0;bottom:0;width:0;background:var(--fox);opacity:.85"; track.appendChild(fill);
    box.appendChild(track);
    var status=document.createElement("p"); status.className="note"; box.appendChild(status);
    var maxMs=target+tol+Math.max(Math.round(target*0.4), 300);  // scale so the target window sits well inside the bar
    win.style.left=((target-tol)/maxMs*100)+"%"; win.style.width=((2*tol)/maxMs*100)+"%";
    var t0=0, samples=[], holding=false, raf=0;
    function tick(){ if(!holding) return; var ms=performance.now()-t0;
      fill.style.width=Math.min(100, ms/maxMs*100)+"%";
      var inWin=ms>=target-tol && ms<=target+tol;
      fill.style.background=inWin?"var(--jade)":"var(--fox)";
      status.textContent=(inWin?"release now — ":"holding… ")+Math.round(ms)+" / "+target+" ms";
      raf=requestAnimationFrame(tick);
    }
    btn.addEventListener("pointerdown", function(e){ e.preventDefault(); try{ btn.setPointerCapture(e.pointerId); }catch(_){}
      t0=performance.now(); holding=true; samples=[]; raf=requestAnimationFrame(tick); });
    btn.addEventListener("pointermove", function(e){ if(holding) samples.push([e.clientX, e.clientY]); });
    async function release(){
      if(!holding) return; holding=false; if(raf) cancelAnimationFrame(raf); var ms=Math.round(performance.now()-t0); t0=0;
      status.textContent="held "+ms+" ms"; btn.disabled=true; label.textContent="Verifying…";
      var v=await (await fetch("/arena/presshold/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, held_ms:ms, samples:samples})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Held — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Press-and-hold PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Hold was out of tolerance — try again."; say("Press-and-hold rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    }
    btn.addEventListener("pointerup", release); btn.addEventListener("pointercancel", release);
    say("Press and hold the button for the shown duration, then release.");
  }

  async function runSequence(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/sequence"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var field=document.createElement("div"); field.style.cssText="position:relative;width:320px;height:240px;border:1px solid var(--line-bright);border-radius:6px;background:var(--panel);margin:.4rem 0"; box.appendChild(field);
    var status=document.createElement("p"); status.className="note"; box.appendChild(status);
    var t0=performance.now(), clicks=[], times=[], next=1, done=false;
    async function submit(){
      if(done) return; done=true;
      var v=await (await fetch("/arena/sequence/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, clicks:clicks, times:times})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Clicked in order — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Sequence PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Wrong order (or the challenge expired) — try again."; say("Sequence rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    }
    c.tiles.forEach(function(t){
      var b=document.createElement("button"); b.textContent=t.id;
      b.style.cssText="position:absolute;left:"+t.x+"px;top:"+t.y+"px;min-width:34px;min-height:34px;padding:0;font:inherit";
      b.onclick=function(){
        clicks.push(t.id); times.push(Math.round(performance.now()-t0));
        if(t.id===next){ b.disabled=true; b.style.opacity=".4"; next++; }
        status.textContent="clicked "+clicks.length+"/"+c.tiles.length;
        if(clicks.length>=c.tiles.length) submit();
      };
      field.appendChild(b);
    });
    say("Click the numbered tiles in order.");
  }

  async function runLocate(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/locate"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var img=document.createElement("img"); img.src=c.image; img.alt="localization target"; img.draggable=false;
    img.style.cssText="display:block;border:1px solid var(--line-bright);border-radius:6px;cursor:crosshair;touch-action:none";
    img.width=c.width; img.height=c.height; box.appendChild(img);
    var status=document.createElement("p"); status.className="note"; status.textContent="Click the target's center."; box.appendChild(status);
    var done=false;
    img.addEventListener("click", async function(e){
      if(done) return; done=true;
      var rect=img.getBoundingClientRect();
      var x=Math.round(e.clientX-rect.left), y=Math.round(e.clientY-rect.top);
      var v=await (await fetch("/arena/locate/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, x:x, y:y})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Located — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Locate PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Not close enough to the target center — try again."; say("Locate rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    });
    say("Click the center of the named target.");
  }

  async function runMatch(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/match"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var refWrap=document.createElement("div"); refWrap.className="note"; refWrap.style.cssText="display:flex;align-items:center;gap:.5rem;margin:.3rem 0";
    var refLbl=document.createElement("span"); refLbl.textContent="Reference:"; refWrap.appendChild(refLbl);
    var refImg=document.createElement("img"); refImg.src=c.reference; refImg.alt="reference"; refImg.width=48; refImg.height=48; refImg.style.cssText="border:2px solid var(--line-bright);border-radius:6px"; refWrap.appendChild(refImg);
    box.appendChild(refWrap);
    var grid=document.createElement("div"); grid.style.cssText="display:flex;flex-wrap:wrap;gap:6px;margin:.4rem 0;max-width:340px"; box.appendChild(grid);
    var done=false;
    c.tiles.forEach(function(t){
      var b=document.createElement("button"); b.style.cssText="padding:2px;border:1px solid var(--line-bright);border-radius:6px;background:var(--panel);cursor:pointer";
      var im=document.createElement("img"); im.src=t.image; im.alt="candidate"; im.width=56; im.height=56; im.draggable=false; b.appendChild(im);
      b.onclick=async function(){
        if(done) return; done=true;
        var v=await (await fetch("/arena/match/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, clicked:t.index})})).json();
        if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Matched — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Match PASSED."); }
        else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="That one faces a different way (or the challenge expired) — try again."; say("Match rejected."); }
        document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
      };
      grid.appendChild(b);
    });
    say("Click the arrow that faces the same way as the reference.");
  }

  async function runSlide(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/slide"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var grid=document.createElement("div"); grid.style.cssText="display:grid;grid-template-columns:repeat(3,54px);gap:4px;margin:.4rem 0"; box.appendChild(grid);
    var status=document.createElement("p"); status.className="note"; box.appendChild(status);
    var board=c.board.slice(), moves=[], done=false, GOAL=[1,2,3,4,5,6,7,8,0];
    function blank(){ return board.indexOf(0); }
    function adj(i,j){ return Math.abs(Math.floor(i/3)-Math.floor(j/3))+Math.abs((i%3)-(j%3))===1; }
    function solved(){ for(var i=0;i<9;i++){ if(board[i]!==GOAL[i]) return false; } return true; }
    function render(){
      grid.innerHTML="";
      board.forEach(function(v, idx){
        var b=document.createElement("button"); b.textContent=v===0?"":String(v);
        b.style.cssText="width:54px;height:54px;font:1.2rem/1 monospace;padding:0"+(v===0?";visibility:hidden":"");
        b.onclick=function(){ move(idx); }; grid.appendChild(b);
      });
    }
    async function move(idx){
      if(done || !adj(idx, blank())) return;
      var bl=blank(); board[bl]=board[idx]; board[idx]=0; moves.push(idx); render();
      if(solved()){
        done=true; status.textContent="Verifying…";
        var v=await (await fetch("/arena/slide/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, moves:moves})})).json();
        if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Solved in "+v.moves+" moves (optimal "+v.optimal+") — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Slide PASSED."); }
        else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Not solved (or the challenge expired)."; say("Slide rejected."); }
        document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
      }
    }
    render(); say("Slide the tiles into order — click a tile next to the blank.");
  }

  async function runPattern(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/pattern"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var field=document.createElement("div"); field.style.cssText="position:relative;width:300px;height:200px;border:1px solid var(--line-bright);border-radius:6px;background:var(--panel);margin:.4rem 0;touch-action:none;cursor:crosshair"; box.appendChild(field);
    var status=document.createElement("p"); status.className="note"; status.textContent="Press and drag through the dots in order."; box.appendChild(status);
    c.dots.forEach(function(d){
      var el=document.createElement("div"); el.textContent=String(d.index+1);
      el.style.cssText="position:absolute;left:"+(d.x-11)+"px;top:"+(d.y-11)+"px;width:22px;height:22px;border-radius:50%;background:var(--line-bright);color:#000;font:12px/22px monospace;text-align:center;pointer-events:none";
      field.appendChild(el);
    });
    var stroke=[], drawing=false, done=false;
    function pt(e){ var r=field.getBoundingClientRect(); return [Math.round(e.clientX-r.left), Math.round(e.clientY-r.top)]; }
    field.addEventListener("pointerdown", function(e){ e.preventDefault(); try{ field.setPointerCapture(e.pointerId); }catch(_){}
      drawing=true; stroke=[pt(e)]; status.textContent="drawing…"; });
    field.addEventListener("pointermove", function(e){ if(drawing) stroke.push(pt(e)); });
    async function end(){
      if(!drawing || done) return; drawing=false; done=true; status.textContent="Verifying…";
      var v=await (await fetch("/arena/pattern/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, stroke:stroke})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Traced — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Pattern PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="The stroke did not pass through the dots in order (or the challenge expired)."; say("Pattern rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    }
    field.addEventListener("pointerup", end); field.addEventListener("pointercancel", end);
    say("Draw one line through the dots in order without lifting.");
  }

  async function runReaction(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/reaction"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var pad=document.createElement("button"); pad.textContent="Wait…"; pad.disabled=true;
    pad.style.cssText="display:block;width:220px;height:90px;font:1.2rem sans-serif;background:#a33;color:#fff;border:none;border-radius:8px;margin:.5rem 0;cursor:default"; box.appendChild(pad);
    var done=false, armed=false;
    setTimeout(function(){ pad.textContent="CLICK!"; pad.style.background="#2a7d2a"; pad.style.cursor="pointer"; pad.disabled=false; armed=true; }, c.delay_ms);
    pad.onclick=async function(){
      if(done || !armed) return; done=true; pad.disabled=true; pad.textContent="…";
      var v=await (await fetch("/arena/reaction/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Reacted in "+v.reaction_ms+" ms — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Reaction PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Reaction too fast to be human (or the challenge expired)."; say("Reaction rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    };
    say("Wait for the box to turn green, then click it as fast as you can.");
  }

  async function runSpotdiff(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/spotdiff"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt+" ("+c.count+" to find)"; box.appendChild(p);
    var img=document.createElement("img"); img.src=c.image; img.alt="spot the difference"; img.draggable=false;
    img.style.cssText="display:block;border:1px solid var(--line-bright);border-radius:6px;cursor:crosshair;touch-action:none";
    img.width=c.width; img.height=c.height; box.appendChild(img);
    var status=document.createElement("p"); status.className="note"; box.appendChild(status);
    var clicks=[], done=false;
    function upd(){ status.textContent="found "+clicks.length+"/"+c.count; }
    upd();
    img.addEventListener("click", async function(e){
      if(done) return;
      var rect=img.getBoundingClientRect();
      clicks.push([Math.round(e.clientX-rect.left), Math.round(e.clientY-rect.top)]); upd();
      if(clicks.length>=c.count){
        done=true; status.textContent="Verifying…";
        var v=await (await fetch("/arena/spotdiff/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, clicks:clicks})})).json();
        if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Found the differences — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Spot-the-difference PASSED."); }
        else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Those are not all the differences (or the challenge expired)."; say("Spot-the-difference rejected."); }
        document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
      }
    });
    say("Click each difference between the two panels.");
  }

  async function runPursuit(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/pursuit"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var field=document.createElement("div"); field.style.cssText="position:relative;width:"+c.width+"px;height:"+c.height+"px;border:1px solid var(--line-bright);border-radius:6px;background:var(--panel);margin:.4rem 0;touch-action:none;cursor:crosshair"; box.appendChild(field);
    var dot=document.createElement("div"); dot.style.cssText="position:absolute;width:20px;height:20px;border-radius:50%;background:#2a7d2a;pointer-events:none;margin:-10px 0 0 -10px;left:"+(c.width/2)+"px;top:"+(c.height/2)+"px"; field.appendChild(dot);
    var status=document.createElement("p"); status.className="note"; box.appendChild(status);
    var pathf=c.path, samples=[], start=null, cur={x:c.width/2, y:c.height/2}, done=false;
    function target(t){ var s=t/1000; return {x:pathf.cx+pathf.a*Math.sin(pathf.w1*s+pathf.p1), y:pathf.cy+pathf.b*Math.sin(pathf.w2*s+pathf.p2)}; }
    field.addEventListener("pointermove", function(e){ var r=field.getBoundingClientRect(); cur={x:e.clientX-r.left, y:e.clientY-r.top}; });
    async function submit(){
      if(done) return; done=true; status.textContent="Verifying…";
      var v=await (await fetch("/arena/pursuit/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, samples:samples})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Tracked (mean error "+Math.round(v.mean_err_px)+"px) — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Pursuit PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Did not stay on the dot (or the challenge expired) — try again."; say("Pursuit rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    }
    function frame(ts){
      if(start===null) start=ts;
      var t=ts-start, tg=target(t);
      dot.style.left=tg.x+"px"; dot.style.top=tg.y+"px";
      samples.push({t:t, x:cur.x, y:cur.y});
      status.textContent="follow the dot… "+Math.round(t/1000)+"s";
      if(t<c.duration_ms) requestAnimationFrame(frame); else submit();
    }
    requestAnimationFrame(frame);
    say("Keep your cursor on the moving dot until it stops.");
  }

  async function runCount(gv, gn, tok){
    var box=document.getElementById("ks-captcha"); box.innerHTML="";
    var c=await (await fetch(withLevel("/arena/count"))).json();
    var p=document.createElement("p"); p.className="note"; p.textContent=c.prompt; box.appendChild(p);
    var img=document.createElement("img"); img.src=c.image; img.alt="count the circles"; img.draggable=false;
    img.style.cssText="display:block;border:1px solid var(--line-bright);border-radius:6px"; img.width=c.width; img.height=c.height; box.appendChild(img);
    var row=document.createElement("div"); row.style.cssText="display:flex;gap:.5rem;margin:.4rem 0;align-items:center";
    var inp=document.createElement("input"); inp.type="number"; inp.min="0"; inp.style.cssText="width:80px;font:1rem monospace;padding:.3rem"; row.appendChild(inp);
    var sub=document.createElement("button"); sub.textContent="Submit"; sub.style.fontWeight="600"; row.appendChild(sub);
    box.appendChild(row); inp.focus();
    var done=false;
    sub.onclick=async function(){
      if(done) return; var g=parseInt(inp.value,10); if(isNaN(g)) return; done=true; sub.disabled=true;
      var v=await (await fetch("/arena/count/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:c.id, guess:g})})).json();
      if(v.ok){ gv.textContent="PASSED"; gv.className="big pass"; gn.textContent="Counted right — a Turing test, not a coherence test. See the detector verdict."; tok.innerHTML='<p class="note">token <code>'+String(v.token||"").slice(0,24)+'…</code></p>'; say("Count PASSED."); }
      else { gv.textContent="REJECTED"; gv.className="big fail"; gn.textContent="Wrong count (or the challenge expired) — try again."; say("Count rejected."); }
      document.getElementById("ks-captcha").innerHTML=""; fetchDetectorVerdict();
    };
    say("Count the circles of the named colour and type the number.");
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
      else if(A.mode==="spatial"){ await runSpatial(gv, gn, tok); }
      else if(A.mode==="shell"){ await runShell(gv, gn, tok); }
      else if(A.mode==="timing"){ await runTiming(gv, gn, tok); }
      else if(A.mode==="keymap"){ await runKeymap(gv, gn, tok); }
      else if(A.mode==="presshold"){ await runPresshold(gv, gn, tok); }
      else if(A.mode==="sequence"){ await runSequence(gv, gn, tok); }
      else if(A.mode==="locate"){ await runLocate(gv, gn, tok); }
      else if(A.mode==="match"){ await runMatch(gv, gn, tok); }
      else if(A.mode==="slide"){ await runSlide(gv, gn, tok); }
      else if(A.mode==="pattern"){ await runPattern(gv, gn, tok); }
      else if(A.mode==="reaction"){ await runReaction(gv, gn, tok); }
      else if(A.mode==="spotdiff"){ await runSpotdiff(gv, gn, tok); }
      else if(A.mode==="pursuit"){ await runPursuit(gv, gn, tok); }
      else if(A.mode==="count"){ await runCount(gv, gn, tok); }
      else if(A.mode==="rotate"){ await runRotate(gv, gn, tok); }
      else if(A.mode==="captcha"){ await runCaptcha(gate, gv, gn, tok); }
      else if(A.mode==="audio"){ await runAudio(gv, gn, tok); }
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
