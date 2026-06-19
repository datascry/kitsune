# evasion-catalog — leverage from the red-team enumeration fleet

A subagent fleet enumerated evasion tools/techniques/research across anti-detect browsers, stealth
frameworks, TLS/HTTP impersonation, challenge bypass, behavioral humanization, fingerprint libs,
proxy/network identity, and academic research — then gap-analyzed against Kitsune's 15-evader ladder
and ruleset. For the lab's own red-team ladder (allow-list only), never third-party use.

## Headline

> The fleet already spans every OSS anti-detect *family*, and the conclusion is structural: per-session
> evasion loses to the environment floor + coordination. New evaders should buy **new test surface**, not
> another tool that hits the same floor. **The single biggest detection gap: no prevalence/likelihood
> model** — Kitsune flags hard contradictions but cannot score "improbable-but-not-impossible" joint
> field combinations (the niespodd/BrowserForge frontier). **The single biggest test gap: no live proxy
> harness** — 6 coordination + 2 IP-reputation rules are scored only synthetically.

Counts: already-have **19**, add-as-evader **6**, frontier **9**, white-box **6**, research **9**.

## Evaders worth adding (new test surface)

| tool / harness | priority | effort | what it would test that the fleet can't |
|---|---|---|---|
| **worker-spoof (stealth WORKER_SPOOF=1) — ✅ ADDED** | — | — | DONE: the context-isolation gap. A main-realm-only navigator spoof (hardwareConcurrency dropped via addInitScript) never reaches Web Worker global scope, so the collector's Blob worker reads the real value → first live catch of `br.worker_divergence` (previously 0-catch). Grounded: a real browser does not diverge. |
| **iframe-spoof (stealth IFRAME_SPOOF=1) — ✅ ADDED** | — | — | DONE: the sibling gap. A top-frame-only UA spoof (guarded on `window.top===window`) leaves a dynamically-created same-origin iframe with the real navigator → first live catch of `br.iframe_divergence` (previously 0-catch); also trips worker_divergence (the prototype patch skips Worker scope too). Grounded: a real browser does not diverge. |
| **native-spoof (stealth NATIVE_SPOOF=1) — ✅ ADDED** | — | — | DONE: the prototype-invariant gap. A GPU spoof replaces getParameter with a plain function and fakes its toString to "[native code]" — beating tostring_tampered — but a plain function has an own `prototype` and is constructable, which a real built-in never is → first live catch of `br.native_invariant_violated` (previously 0-catch). The shallow toString check is evaded; the deep invariant catches it. Grounded: a real browser trips none. |
| **linear-bot (stealth LINEAR_BOT=1) — ✅ ADDED** | — | — | DONE: the biomech floor. A straight-line constant-velocity drag → straightness 0.9999 (> path_too_straight 0.97) and velocity CV 0.041 (< uniform_velocity 0.08): first live catches of `bh.path_too_straight` AND `bh.uniform_velocity` (both previously 0-catch). The fleet's human-mouse mode (bezier, eased velocity → straightness 0.10, CV 0.90) is the negative control and trips neither — the biomech rules discriminate scripted from human motion. Note: at a 20ms inter-event interval, dispatch jitter alone keeps CV ~0.19 > 0.08; a ~75ms interval is needed to cross the uniform_velocity floor. |
| **Residential/proxy-fleet harness (Scrapoxy or socks5h chain +** | critical | hard | The single biggest test gap. rep.datacenter_asn, rep.known_proxy_exit, net.webrtc_ip_vs_observed, and ALL six proxy-topology coordination signals (residential-p |
| **curl_cffi / rnet / tls-client (bogdanfinn) as a current-temp** | high | easy | go-tls is deliberately a STALE template (uTLS 1.6.7, no PQ); primp/curl-impersonate are current. Adding rnet or tls-client gives a SECOND current high-fidelity  |
| **BrowserForge + apify fingerprint-injector JS-coherence evade** | high | medium | Tests the Bayesian-joint-distribution attack head-on: an injector setting UA->platform->codecs->GPU->screen from a real-traffic joint sample is exactly what the |
| **camoufox-geo-pinned (Camoufox with geoip + locale/timezone d** | medium | easy | net.accept_lang_vs_navigator and the IP-geo coherence story (timezone/locale/Accept-Language vs egress IP) have no live evader that deliberately MIS-pins or cor |
| **Ulixee Hero (Unblocked / DoubleAgent) — full-stack TLS+H2+DO** | medium | hard | The one OSS tool explicitly engineered to be coherent across TLS, HTTP header order, AND DOM simultaneously — it directly targets the cross-layer-incoherence th |
| **botright (real-Chromium + scraped-real fingerprints + CV CAP** | medium | medium | Uses self-scraped REAL chrome fingerprints (not generated) on ungoogled-chromium — tests whether real-device-sourced values defeat the joint-coherence rules bet |

## Frontier techniques that could beat current detection

| technique | priority | defeats | how |
|---|---|---|---|
| **Real-hardware headful deployment (non-container, passth** | high | br.webgl_software, br.webgl2_missing, br.voices_empty, br.voice_os_vs_ua, br.med | Run any anti-detect browser headful on a real machine with a real GPU, OS speech voices, a |
| **DMTG / diffusion + GAN mouse-trajectory synthesis (entr** | high | bh.path_too_straight, bh.uniform_velocity, bh.input_entropy_floor, bh.power_law_ | Generates mouse paths via diffusion (DMTG) or GAN reproducing slow initiation, 2/3 power-l |
| **Prevalence/likelihood evasion — statistically-improbabl** | high | NOTHING in the registry — every Kitsune rule is a hard not_equal/present/thresho | A generator (BrowserForge/Scrapfly) samples a field combo that violates no hard coherence  |
| **Real-OS-cursor injection (xdotool / bezmouse / pyHM dri** | medium | bh.synthetic_no_coalesced (the structural exit findings.md relied on — real hard | Drives the real OS cursor so events are OS-trusted (isTrusted=true) and flow through the r |
| **Current-template impersonator over QUIC/HTTP-3 (rnet/cu** | medium | net.quic_grease_vs_ua (stays silent on a correct QUIC hello), net.tls_pq_keyshar | A network-only client shipping a CURRENT browser template AND speaking HTTP/3 with a brows |
| **JA4H regular-header-order forgery (curl-impersonate / primp / go-tls)** | confirmed-defeated | net.h2_header_order_vs_ua (experimental), net.h2_engine_unknown | Live iter-8 fleet run: every chromium-claiming HTTP-impersonation stack already replicates Chrome's *regular* header order (sec-ch-ua before user-agent), not just the pseudo-header order — so JA4H header order alone yields zero positives. Header-order detection needs a co-signal (settings-vs-order disagreement) to bite. |
| **Profile-reuse at scale across many proxy IPs (Dolphin-A** | medium | Per-session coherence entirely (the values are real and co-occurring) and the JS | Many accounts present the SAME real-device-sourced fingerprint behind distinct residential |
| **Scroll/intent-sequence absence (DataDome 2025 intent-ba** | medium | Nothing — the collector does not capture scroll/intent (landscape.md lists this  | A bot that fills forms / clicks without the scroll, focus, hover, and intent-event streams |
| **Canvas-noise prediction / separation attack (Breaking t** | low | Evasion side: cross-session canvas tracking. For us the inverse — a detector tec | Recovers the true canvas or proves noise was applied by exploiting predictability of Brave |
| **TLS-inspection-proxy / enterprise re-origination false-** | low | Precision of net.tls_pq_keyshare_vs_ua (experimental) and net.tcp_os_vs_ua — the | Not evasion — an adversary hides behind the fact that corporate TLS-inspection proxies re- |

## White-box targets (read the tool → new detection)

| target | what to extract → detection opportunity |
|---|---|
| **BrowserForge + generative-bayesian-netwo** | The CPTs and possible-values network encode which (browser,OS,device,screen,codec,GPU) tup → Build a PREVALENCE/likelihood detector (the one thing Kitsune lacks): load apify |
| **Scrapfly fingerprint-generator (independ** | A SECOND, independently-collected Bayesian prevalence model. Diff it against Apify's: tupl → Cross-check the prevalence detector against two priors so it does not overfit Ap |
| **JShelter farbling wrappers (jshelter.org** | The exact farbling signatures: isPointInPath/isPointInStroke returns false with only ~5% p → A JShelter-specific tell beyond br.canvas_noise: probe isPointInPath many times  |
| **Brave farbling source (brave-browser, pe** | Farbled outputs derive deterministically from a per-session secret token HMAC-SHA256'd per → br.canvas_noise already catches the solid-fill case. Extend to a per-eTLD+1 STAB |
| **Camoufox webgl_data.db + fonts.json + br** | findings.md already mined the ', or similar' renderer suffix, the 49 dot-prefixed mac font → A font-COUNT coherence rule (br.font_count_vs_os): Camoufox's bundled list size  |
| **BotBrowser NAVIGATOR_PROPERTIES.md + .en** | The navigator-properties doc lists exactly which fields BotBrowser standardizes and how it → Already drove net.tcp_os_vs_ua (kernel) and the fp-collision coordination signal |

## The two strategic gaps

1. **Prevalence / likelihood model.** Kitsune is a hard-contradiction detector. The field's generators
   (BrowserForge, fingerprint-suite) are built to produce statistically-coherent joint fingerprints that
   *have no contradiction*. Scoring a fingerprint by how *improbable* its field combination is (a
   likelihood model over a real-traffic prior — the same datapoints the generators sample from) is the
   one detection class the lab lacks. This is also why the calibration matters: a prevalence model is the
   principled way to weight "unusual but real" without the FP blowup of single-layer environment tells.
2. **Live proxy/coordination harness.** The durable bots-at-scale signal (coordination + IP reputation)
   is currently exercised only by a synthetic fleet. A real residential/proxy-fleet harness (ethics-gated
   to the allow-list edge) is the only live test of `rep.*`, `net.webrtc_ip_vs_observed`, and the six
   proxy-topology coordination signals.
