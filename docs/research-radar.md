# Research radar — the detection⇄evasion loop's intake queue

This file is the durable queue of the **research-fed red⇄blue loop**: external papers/tools/techniques for
bot detection & evasion, each mapped to a Kitsune seam, tagged **groundable-in-sandbox** vs
**external-data-bound**, and tracked from `lead → grounded` (or `→ external queue`). It is fed by periodic
deep-research passes and drained by the adversarial pump. The `groundable?` column *is* the "evaluate
evasions against real-world testing" judgement: it records whether a technique can be tested with the local
lab (Docker, headless+headful browsers, synthetic traffic) or needs data the lab cannot self-generate.

## The loop cycle

Each iteration runs **locally, on demand** (the full toolchain — `uv`, `go-task`, Docker for the edge Go
tests — only exists in a local session; no cloud routine). Drive a cycle by asking Claude to "run a
research-loop cycle", or with `/loop` inside a session. The steps:

1. **Scan** — deep-research for new detection/evasion work since the last cycle; append new rows below
   (seam-tagged, cited, groundability assessed). Dedup against what Kitsune already covers.
2. **Pick** — take the highest-value **groundable** lead not yet `done`.
3. **Pump** — run one red⇄blue rung: red writes/confirms the evasion **EVADES** the current detector;
   blue builds the **grounded** detection; verify it **CONVICTS** the evader **and** passes the FP gates
   (`task calibrate` / `calibrate-intoli` / `coordination-eval`) + `task ci`.
4. **Record** — flip the row's status, update `task scoreboard`, commit (as `datascry`). Route
   external-data-bound items to the queue with the exact real data they need.

## Methodology guardrails (do not skip)

- **Grounding discipline (the standing constraint).** Never ship an ungrounded convicting rule. A rung needs
  a faithful red-team positive **and** a zero-FP sweep. External-data-bound items wait — they do not become
  speculative rules.
- **Lab-classifier deltas ≠ production-detector deltas.** Evasion papers (e.g. DMTG mouse synthesis) report
  reductions against the authors' *own* white-box classifiers. Treat such numbers as lower bounds; ground a
  red-team evasion by whether it trips Kitsune's *actual* tells, not by the paper's headline %.
- **Packet-length-sequence detections do not transfer to the wild (Rosetta, USENIX Sec 2023).** TCP
  reliability (retransmit/segmentation/MSS) makes length sequences network-path-dependent. Do NOT build a
  flow-length-sequence detection in-lab expecting it to hold in production — order/direction features are
  more robust, but flow-statistics detection is fundamentally external-data-bound here.

---

## Groundable leads (in-sandbox pump candidates)

| # | seam | technique / signal | evasion / tool | source | status |
|---|---|---|---|---|---|
| G1 | coherence (spatial) | **Cross-attribute inconsistency within one fingerprint** — e.g. a device class (UA/model) paired with a screen resolution/DPR that device never ships, an iPhone with an impossible screen geometry. FP-Inconsistent's *spatial* rules cut DataDome evasion 48% / BotD 45%. | anti-detect browsers that spoof attributes independently (browserforge/fingerprint-injector mix fields) | FP-Inconsistent, ACM **IMC 2025** (DOI 10.1145/3730567.3732919; arXiv 2406.07647) | **done** → `br.mobile_no_touch` (phone/tablet UA + maxTouchPoints 0; device-DB-free, FP-safe). Screen-geometry coherence needs a real-device resolution DB → see X5. |
| G2 | red-team / behavioral | **GAN/diffusion mouse-trajectory synthesis** as a faithful evader to pressure-test the behavioral floor + the coalesced-sample terminus. | DMTG (diffusion, arXiv 2410.18233), BeCAPTCHA-Mouse GAN, SapiAgent | DMTG; BeCAPTCHA-Mouse (Pattern Recognition 2022) | **validated** — the convicting tell (`bh.synthetic_no_coalesced` / `br.coalesced_untrusted`) is STRUCTURAL (getCoalescedEvents length + isTrusted), so trajectory SHAPE quality is orthogonal: a DMTG path injected via CDP still has `coalescedMax<=1` → caught. Already grounded (stealth `KS_BEHAVE`); escape is real XTEST/uinput (privilege-gated terminus). DMTG validates Kitsune's structural-over-shape bet. No new rule. |
| G3 | behavioral | **Keystroke-dynamics detection** (timing + key-identity); cGAN can synthesize evasions. | cGAN keystroke synthesis (arXiv 2212.08445) | IFIP SEC 2024 (DOI 10.1007/978-3-031-65175-5_30) | **not groundable** — keystroke timing is jitter-unsound across instances (no clone/structural channel, unlike mouse coalesced; memory-confirmed). `bh.keystroke_entropy_floor` stays corroborating; cGAN defeats shape/timing and there is no structural keystroke analog of coalesced sampling. |
| G6 | coherence (mobile) | **Mobile GPU-family ↔ OS coherence** — real mobile GPUs surface as enumerable WebGL renderer strings (Qualcomm **Adreno**, ARM **Mali** ⟹ Android; **"Apple GPU"** ⟹ Apple iOS/macOS). An Android UA with renderer "Apple GPU", or an iPhone UA with "Adreno"/"Mali", is a clean cross-layer incoherence — the mobile extension of `webgl_os_vs_ua` (which today only knows desktop Direct3D/Metal/Mesa). | a desktop-faking-mobile that fakes a mobile renderer to dodge `webgl_software` but mismatches the GPU family | Castle.io WebGL-renderer fingerprinting (mobile GPU enumeration), mobile-research pass 2026-06-21 | **resolved — no new rule.** Probed (confirm-EVADES-first): the **Apple-GPU** half is ALREADY caught — `_webgl_os` maps `Apple`→macOS, so an Android UA + "Apple GPU" already fires `webgl_os_vs_ua`. The **Adreno/Mali→Android** half is **FP-UNSAFE**: real **Windows-on-ARM (Snapdragon) ships Adreno** and **ChromeOS ships Mali** (both verified to currently — correctly — not fire), so mapping them to Android would FP on real devices → that direction is external (needs a device-class disambiguator, see X5). The only FP-safe sliver (Adreno/Mali under an Apple UA) is redundant — a Chromium-faking-iPhone already trips `apple_ua_nonwebkit`/`safari_ua_no_webkit_api`/`mobile_no_touch`. |
| G5 | environment (mobile) | **WebView / in-app-browser surface** — the `wv` UA token (durable through Android 16 UA reduction; standalone Chrome lacks it) + per-app IAB tokens (`FB_IAB`/`FBAN`) + the `X-Requested-With` package header (Android WebView). | host app overrides UA via `setUserAgentString` (all UA signals spoofable) | Android Devs Blog (Dec 2024); Tiwari et al. arXiv 2208.01968; mobiforge | **lead (weak/corroborating)** — WebView is ALSO the dominant *legit* mobile surface (in-app browsers), so presence is NOT convicting; only a non-UA-vs-UA mismatch (`X-Requested-With` present but UA omits `wv`) is a tell, and that's niche + needs real app traffic → mostly X7 |
| G4 | network (JA4+) | **JA4+ suite coverage audit.** | uTLS/curl-impersonate pin JA4; JA4T harder (real stack) | FoxIO JA4 (github.com/FoxIO-LLC/ja4), JA4T blog (blog.foxio.io/ja4t-tcp-fingerprinting) | **covered** — JA4 (ja4a/b/c) + JA4H (`net.h2_header_order_vs_ua`) present; JA4T's detection value = TCP-OS coherence (`tcp_kernel` SYN fp + `net.tcp_os_vs_ua`); JA4L (latency/hop-distance) marginal for bot-detection + latency-external; JA4S is server-side (N/A for a client detector). No groundable gap. |
| G7 | coherence (network ⇄ UA) | **FCrDNS declared-crawler verification** — a UA declaring a known crawler (Googlebot/Bingbot/Applebot/…) whose connecting IP fails forward-confirmed reverse DNS (no PTR, PTR under no official suffix, or no forward-confirm) is an impersonator. FCrDNS is the crawlers' OWN documented verification method, so a real crawler always confirms; transient DNS errors abstain (FP-safe). | a non-crawler IP wearing a crawler UA (fake-Googlebot scrapers — a common allow-list bypass) | GreyNoise GNQL gap analysis (`actor` + `metadata.rdns_validated` facets); Google/Bing crawler-verification docs | **done (experimental)** → edge `fingerprint.VerifyCrawler` emits `network.fake_declared_crawler` → `net.fake_declared_crawler` (coherence, convicting, w0.8). Unit-grounded (confirm / impersonator / NXDOMAIN / abstain) + a stub-resolver prepare test + a detector conviction test. EXPERIMENTAL until a live resolver grounds it in deployment (edge ships net.DefaultResolver; the FP-safe-by-construction logic mirrors the crawlers' own method). Adjacent to (not core to) the real-browser-coherence thesis — targets the declared-crawler-spoof abuse case. |
| G8 | artifact (input) | **screenX/screenY ↔ clientX/clientY pointer-coordinate coherence** — a real pointer event's `screenX/screenY` equals `clientX/clientY` plus the window's screen offset (and `screen` bounds); a CDP/`Input.dispatchMouseEvent`-injected event or a MouseEvent-Patcher shim commonly sets `screenX===clientX` or `0`, an impossible geometry. The collector today captures only `clientX/clientY` — a NET-NEW surface. | Bablosoft **MouseEvent-Patcher** (screenX/screenY spoof), CDP `Input.dispatchMouseEvent` synthetic events | TheGP/untidetect-tools (MouseEvent-Patcher); CDP Input domain | **lead (groundable)** — capture screenX/screenY+clientX/clientY+window offsets, add an artifact coherence rule, ground with a CDP-injected-event evader mode. FP-safe iff the invariant holds across multi-monitor/zoom (validate before convicting). |
| G9 | automation (CDP) | **rebrowser-bot-detector coverage audit** — its checks (Runtime.enable leak, `dummyFn`/exposeFunction binding leak, sourceURL leak, useless-main-world exec). `br.cdp_runtime_enabled` covers the Runtime.enable leak; verify the binding/sourceURL leaks are covered or add them. | rebrowser-patches / patchright (the leaks they specifically fix) | TheGP/untidetect-tools (rebrowser-bot-detector, brotector) | **partial — audited + 1 leak closed.** Mapped all 10 rebrowser tests: COVERED — runtimeEnableLeak (`cdp_runtime_enabled`), navigatorWebdriver (`webdriver_present`), bypassCsp (`csp_bypassed`), headless UA. CLOSED this tick — exposeFunction/binding leak: live-grounded that real Playwright (1.48, via addInitScript) exposes `window.__playwright__binding__` while NONE of the previously-listed automation globals were present (vanilla Playwright was EVADING the `automation_globals` surface); added it to both collectors → trips the existing `br.automation_globals` (no new rule). `__pwInitScripts` is NOT in current Playwright (ungrounded — not added). REMAINING (low value / FP-risk): sourceUrlLeak (puppeteer-specific, `__puppeteer_evaluation_script__` already listed), viewport 800x600/1280x720 (FP-risky), Chrome-for-Testing UA (niche). |
| G10 | behavioral (mobile FP fix) | **Gate the mouse-biomech floors off real touch devices** — power-law/straightness/velocity-CV/coalesced-absent are mouse-calibrated and false-positive on a real phone swipe (caps at suspicious, not bot, but still a precision hit). Emit `browser.is_mobile` (UA mobile token AND maxTouchPoints>0) and drop the mouse-motion floors in applicability when set (keep trace_replay — device-agnostic). | n/a (a precision/FP fix, not an evasion) | mobile-vs-desktop behavioral analysis 2026-06-23 | **done** → collector emits `browser.is_mobile` (mobile UA token AND maxTouchPoints>0); `applicability._MOBILE_BIOMECH_NA` drops `bh.input_entropy_floor` / `power_law_violation` / `path_too_straight` / `uniform_velocity` / `synthetic_no_coalesced` for a mobile session (trace_replay + keystroke floor stay). Tests: desktop fires the floors, mobile drops them, mobile still convicts on trace_replay. |

## External-data-bound leads (queue — need real data the lab can't self-generate)

> **Turnkey path built:** `docs/grounding.md` + `task grounding -- <captures>` runs the full grounding
> sweep (per-session FP/recall + coordination + prevalence-prior rebuild) the moment an operator supplies
> real captures. Each X-item below maps to a capture + command in that runbook.


| # | seam | technique / signal | real data needed | source | status |
|---|---|---|---|---|---|
| X1 | proxy/tunnel | **Encapsulated-TLS-handshake fingerprinting** — fully passive; detects ALL proxy/tunnel stacks (shadowsocks/vmess/trojan/vless/httpt, TPR >70%) from nested-handshake size/timing/**direction**; padding doesn't defeat it (falls back to order+direction). | real proxy egress + large-scale ISP traffic (paper: 110M flows, TCP-only deployed) | Xue et al., **USENIX Sec 2024** (ensa.fi/papers/sec24-xue.pdf) | **external** — order/direction *insight* is mineable; QUIC/MASQUE transfer is an open question |
| X2 | residential proxy | **RESIP relayed/tunnel-flow classifier** — transformer, first 5 packets, payload-free: relayed 93%/93%, tunnel 91%/96%. | real RESIP node deployment + wild egress (3TB / 116M flows) | Huang et al., arXiv 2404.10610 (USTC+IU 2024) | **external** — the IP-reputation/proxy half Kitsune already flags as blocked |
| X3 | IP reputation | **CGNAT detection** to bound the `ip_rotation_within_session` confound + RESIP collateral. | real CGNAT/residential traffic | Cloudflare (blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage) | **external** — refines the documented CGNAT FP caveat |
| X4 | prevalence | **Real-traffic prevalence/IP-reputation prior** (the recurring Tier-3 gap). | hosted-demo opt-in / real-device matrix / real traffic | Resident Evil (RESIP study); Kitsune `build_prior_from_sessions` | **partially unblocked** — the IP-reputation half is now fed by the MIT X4BNet feed (wired into `ip_reputation_refresh`, see the real-data table below); the prevalence-prior half has a **turnkey adapter built** (`berke_corpus.py`) — it just needs the operator to accept the Berke Dataverse terms + download the CSV, then one command builds the aggregate prior |
| X6 | behavioral (mobile) | **Mobile touch/swipe biometrics** — Touchalytics (30 features, ~0% median intra-session EER), BeCAPTCHA swipe+accelerometer human/bot. The mobile analog of the mouse biomech floor. | real mobile touch/swipe traffic (and GAN-defense — touch auth is adversarially synthesizable: random-vector/population attacks raise FAR 22-27%) | Touchalytics (arXiv 1207.6231), BeCAPTCHA (arXiv 2005.13655), G-TCAS (arXiv 2210.01594) | **external** — needs real mobile traffic; synthesizable, so it's corroborating-only by nature |
| X7 | environment (mobile) | **iOS WKWebView / in-app discriminator** — no durable CLIENT-side signal survived verification (the `Version/`-token-absence AND `window.webkit.messageHandlers` signals were both **refuted**); `X-Requested-With` (Android) reliability is post-2023-opt-in uncertain. | real in-app / WebView traffic across apps | research open-question 2026-06-21 | **external/open** — the largest unfilled real-mobile gap |
| X5 | coherence (spatial) | **Device-model ↔ screen-geometry coherence** — the DB-dependent half of G1 (an iPhone-15 UA with a resolution no iPhone-15 ships). Needs a real (device → screen res/DPR) mapping to be FP-safe; a hand-coded threshold FPs on foldables/edge devices. | real-device fingerprint DB (the FP-Inconsistent dataset is honey-site-derived, not released) | FP-Inconsistent, ACM IMC 2025 | **external** — split from G1 (the DB-free `mobile_no_touch` shipped) |
| X8 | IP reputation (actor) | **GreyNoise GNQL enrichment** — per-IP `classification` (malicious/suspicious/benign), `actor` (Shodan/Censys/GoogleBot), `tag`, `spoofable`, first/last-seen. Richer than the static CIDR lists Kitsune wires today: real actor/intent intel that would ground the currently-synthetic `rep.*` rules and complement the FCrDNS G7 check (confirming benign-crawler actors). | a GreyNoise API key + deploy-time egress (community tier rate-limited; GNQL is enterprise) | GreyNoise GNQL (docs.greynoise.io/docs/using-the-greynoise-query-language-gnql), gap analysis 2026-06-23 | **external** — the actor/reputation feed missing from the data-source table below; wire into `ip_reputation_refresh` at deploy when a key is available. |

## Real-data sources → grounding input (the "search for more real data" shopping list)

A vetted catalog of **actual downloadable datasets/feeds** mapped to the X-item each one unblocks, with
access + licence + the exact grounding command. Sourced via a deep-research pass (2026-06-21) and
fetchability/licence-verified in-sandbox. **Discipline:** never commit raw dataset rows — only de-identified
aggregates (a prior, a CIDR seed regenerated at deploy, counts). Licence claims are verified against the
source itself, not the aggregator's metadata (GitHub's licence detector missed X4BNet's README-embedded MIT).

| dataset / feed | unblocks | access | licence | fetchable now? | grounding input |
|---|---|---|---|---|---|
| **X4BNet/lists_vpn** `output/{vpn,datacenter}/ipv4.txt` | X4 (IP-rep) / X2,X3 corroboration | raw GitHub | **MIT** (README, covers the list data) — verified | ✅ HTTP 200 (vpn ~11k, dc ~42k) | **WIRED** → `ip_reputation_refresh` (proxy_exit += VPN, datacenter += hosting). Output uncommitted; run at deploy. |
| **Tor bulk exit list** | X4 (IP-rep) | check.torproject.org | public | ✅ (already wired) | `ip_reputation_refresh` proxy_exit (Tor slice) |
| **AWS `ip-ranges.json` + GCP `cloud.json`** | X4 (IP-rep) | publisher-authoritative | public | ✅ (already wired) | `ip_reputation_refresh` datacenter (cloud slice) |
| **FireHOL blocklist-ipsets** `firehol_proxies`/`firehol_anonymous` | X4 (broader proxy/anonymizer) | raw GitHub | **GPLv2 aggregate of mixed-licence upstreams** | ✅ HTTP 200 (~34MB) but **licence-gated** | candidate only — per-upstream vetting required before any redistribution (some components non-redistributable). Documented in `docs/ip-reputation-data.md`, NOT wired. |
| **Berke et al.** `github.com/aberke/fingerprinting-study` (PoPETs 2025) | X4 (prevalence prior) | browser-attrs file on **Harvard Dataverse** `doi.org/10.7910/DVN/0SGZFF` (repo MIT covers code only) | **research-use: no re-identification, no resharing** | ⚠ **gated** — only the no-browser-attrs survey CSV is in the repo; the 8,400-FP browser-attrs file needs accepting the Dataverse terms + download | **adapter BUILT** (`berke_corpus.py`): operator who accepted the terms runs `python -m kitsune_harness.berke_corpus <csv>` → committed **aggregate prior only** (frequency tables, never rows → satisfies no-resharing). Exact Kitsune attribute set (UA/screen/cores/unmasked-renderer). |
| **X4BNet datacenter** (above) | — | — | — | — | also a 2nd-source cross-check for the prevalence GPU/screen single-source factors |
| **Matomo `device-detector`** (regexes) | X5 (device↔geometry) partial | GitHub | **LGPL** | ✅ | device-model → class mapping; **no screen-resolution DB** (the FP-safe X5 half still needs a real device→res map) |
| **Resident Evil RESIP** (~6M IPs, rpaas.site) | X2/X3 (RESIP) | study artifact | study terms | gated | the RESIP IP set behind the residential-proxy-fleet signal |
| **GreyNoise GNQL** (per-IP actor/classification) | X8 (IP-rep actor) / G7 (benign-crawler actors) | api.greynoise.io | API key; community tier rate-limited, GNQL enterprise | ⚠ gated (needs key) | per-IP `classification`/`actor`/`tag`/`spoofable` → `ip_reputation_refresh` actor enrichment at deploy; aggregate/cache only, never commit raw |
| **Google/Bing crawler IP-range JSON** | G7 (FCrDNS — DNS-free CIDR path) | developers.google.com/static/crawling/ipranges/common-crawlers.json (+ special-crawlers); Bing equivalent | public (Google/MS authoritative) | ✅ public, daily, CIDR JSON | candidate → an authoritative CIDR feed for `net.fake_declared_crawler` (verify a declared crawler with NO DNS round-trip; resilient if DNS is slow/blocked). Edge-side consumer co-located with FCrDNS; not yet wired. |
| **Azure / Oracle / DigitalOcean / Cloudflare / Fastly ranges** | X4 (IP-rep datacenter) | Oracle `public_ip_ranges.json`, DO `digitalocean.com/geo/google.csv`, Cloudflare `/ips-v4`+`/ips-v6`, Fastly `api.fastly.com/public-ip-list`; Azure Service-Tags (rotating URL) | public | ✅ Oracle/DO/Cloudflare/Fastly stable; Azure rotates | **WIRED** (Oracle/DO/Cloudflare/Fastly → `ip_reputation_refresh` datacenter, per-source floors). Azure needs a discovery step for its rotating Service-Tags URL → candidate. |
| **Spamhaus DROP/EDROP + IPsum** | X4 (IP-rep proxy/abuse) | spamhaus.org/drop, github.com/stamparm/ipsum | DROP free-to-use; IPsum permissive (verify) | ✅ public, daily | candidate → thicken `proxy_exit` beyond Tor+X4BNet; licence-verify per source (cf. FireHOL caveat). |
| **FoxIO ja4db / peet.ws** (JA4 + Akamai H2 → client) | net.tls_vs_ua_browser / net.h2_vs_ua_browser precision | github.com/FoxIO-LLC/ja4 (ja4db), tls.peet.ws | varies (verify) | ✅ static lookup tables | candidate → expand the edge's tiny `ja4_hints.json` seed with more positively-identified clients (static table, no live traffic). |
| Hiding-in-the-Crowd (2M); Andriamilanto (4.15M) | prevalence (stats) | papers | — | ❌ stats-only (not downloadable) | reference distributions only — cannot rebuild a prior from them |

**Hardest-gap status:** mouse/touch biometrics (X6) and mobile/WebView (X7) have **no** permissively-downloadable
real dataset — they remain external/open. The one in-sandbox-actionable + permissive + fetchable asset was the
X4BNet MIT feed (now wired); the Berke corpus is the next unlock but is licence-gated (request the research-use
terms before pulling).

## Validations (research that confirms existing Kitsune work — do NOT rebuild)

- **Incoherence thesis** — FP-Inconsistent (IMC 2025) is the strongest external validation: cross-layer
  coherence is *the* convicting signal against evasive bots, not any single value. Kitsune's whole design.
- **Temporal inconsistency** = Kitsune's **within-session axis** (JA4/h2/IP/UA/fp/trace rotation) — already
  built and grounded. FP-Inconsistent's "same cookie changing an invariant" is exactly `*_within_session`.
- **Session-replay detection** = `bh.trace_replay_within_session` + coordination `trace_collision`. ReMouse
  (J. Cybersec. Privacy 2023) confirms intra-user variability makes a replayed path anomalous. NB the
  *inter*-user-similarity claim was **refuted** (0-3) — don't over-claim distinctness across users.
- **Engine-level spoof defeated by coherence, not property probes** — Camoufox's C++ patches read native;
  caught via TLS + cross-layer mismatch. Matches `privacy-browser-fp-surface` memory; keep mining coherence,
  not `[native code]` probes.

## Refuted leads — do NOT build (verification-killed)

- **Device-motion-sensor fingerprinting / coherence** — the "motion sensors fingerprint a phone 96-99%" and
  "sensors are permissionless, unlike camera/mic" claims did **not** survive 3-vote verification (1-2 / 0-3).
  Do not build a sensor-presence or motion-coherence rule on those grounds (it would be FP-prone).
- **iOS WKWebView client-side discriminators** — both "Safari has a `Version/` token a WKWebView lacks" and
  "`window.webkit.messageHandlers` is WebView-only" were **refuted** (0-3). No durable client signal → X7.
- **WebView privacy-sandbox / "259× more identifying" uniqueness** — refuted; not a basis for detection.

## Iteration log

- **2026-06-21 · iteration 1** — seeded from a deep-research pass (5 angles, 23 sources, 25 claims verified
  3-vote, 22 confirmed). Added G1–G4, X1–X4, 4 validations. Top groundable pick: **G1** (spatial
  cross-attribute coherence). Loop runs **local/manual** by design (no cloud routine — the edge pump needs
  local Docker/`go-task`); a cloud routine can be added later via `/schedule` once GitHub is connected.
- **2026-06-21 · iteration 2 (pump on G1)** — shipped `br.mobile_no_touch` (coherence, convicting): a
  phone/tablet UA (`Mobile`/iPhone/iPad token) with `maxTouchPoints == 0` is a desktop wearing a mobile UA.
  Device-DB-free + FP-safe (scoped off bare `Android`/TV). Grounded: convicts the mobile-spoof as the sole
  tell, silent on real iOS/Android (touch>0) and desktop; 0 FP on browserforge N=600; detector 260 + harness
  230 green; catalog/README/matrix regenerated. G1 spatial-screen-DB half split out to **X5** (external).
  Mirrored into the production livepage collector (`collector/src/livepage/probes.ts`, commit 3099fad) —
  emitted across demo.py (authoritative) + calibration mapper + livepage; collector CI green (Docker node).
- **2026-06-21 · iteration 3 (drain the groundable queue)** — ran G2/G3/G4: **G2 validated** (the coalesced
  terminus is structural/shape-independent, so DMTG-quality synthesis is already caught — no new rule);
  **G3 not groundable** (keystroke timing jitter-unsound, no structural channel); **G4 covered** (JA4/JA4H/
  JA4T-as-TCP-OS-coherence; JA4L marginal, JA4S N/A). **Groundable column is now DRY** — every remaining lead
  is external-data-bound (X1–X5: real proxy egress, real-device resolution DB, real-traffic prevalence). The
  loop reached the same wall as [[per-session-detection-saturated]]: the productive unlock is the GROUNDING
  HARNESS (hosted-demo opt-in / trusted-cert QUIC host / proxy egress), not more in-sandbox rules. Net result
  of the research-fed loop: 1 new grounded rule (`br.mobile_no_touch`, G1) + the rest validated/routed.
  Re-run the SCAN periodically — a genuinely new technique or tool re-opens the groundable column.
- **2026-06-21 · iteration 4 (mobile uplevel)** — Tier-1: grounded the mobile escalation ladder live (Android
  naive-spoof → `mobile_no_touch`; iOS-naive → `apple_ua_nonwebkit`+`safari_ua_no_webkit_api`+`mobile_no_touch`;
  fixed-touch → `pointer_touch_incoherent`; full-emulation → OS-leak), lighting 3 previously-unexercised rules
  via faithful evader modes (commits 350ffdb, 3ae9ac5). Tier-2: a mobile-targeted deep-research pass (6 angles,
  26 sources, 25 claims 3-vote-verified) added **G6** (mobile GPU↔OS coherence — top groundable), **G5**
  (WebView surface — weak/non-convicting), **X6** (mobile touch biometrics — external), **X7** (iOS WKWebView
  discriminator — open/external), and **killed the device-sensor lead** (refuted; saved an FP-prone build).
  Next groundable: **G6** (extend `_webgl_os` to mobile GPU families + a mismatched-renderer evader).
- **2026-06-21 · iteration 5 (G6 resolved — groundable column DRY)** — probed G6 (confirm-EVADES-first): the
  Apple-GPU half is already covered (`Apple`→macOS); the Adreno/Mali→Android half is FP-unsafe (real
  Windows-on-ARM Adreno + ChromeOS Mali) → external (X5-class); the FP-safe sliver is redundant with the
  iOS-spoof tells. **No new rule** (avoided a real-device FP), mirroring the `font_os_vs_ua`/`vendor_vs_ua`
  discipline. With G6 resolved, **every groundable lead (G1–G6) is now done/covered/validated/external and
  the whole gap queue (GAP-1–11) is cleared** — both queues exhausted. The loop's `next groundable` is empty;
  remaining radar items (X1–X7) are all external-data-bound and route to the grounding harness
  (`docs/grounding.md` / `task grounding`). External sourcing is the only way to refill the groundable column.
- **2026-06-21 · iteration 6 (real-data sourcing — X4 IP-rep half unblocked)** — ran the "search for more real
  data" pass: a deep-research sweep + in-sandbox fetchability/licence verification produced a vetted real-data
  shopping list (new **"Real-data sources → grounding input"** section), each dataset mapped to its X-item +
  access + licence + grounding command. **Grounded the one permissively-licensed, fetchable, in-sandbox asset:**
  wired **X4BNet/lists_vpn (MIT)** into `ip_reputation_refresh` — `proxy_exit` was Tor-only (a thin slice) and
  is now Tor + ~11k VPN CIDRs; `datacenter` was AWS/GCP-only and now adds ~42k hosting CIDRs. New `parse_cidr_list`
  + floor guards (`x4b_vpn`/`x4b_datacenter` ≥ 1000) + offline parser/drift tests; output stays uncommitted per
  the existing deploy-not-commit rule (detector 328 green, 99.34%). **Live-validated at scale** (in-memory, no
  committed output): a real refresh with the deploy-time floor guard active passes and grows the feeds from a
  thin seed to `proxy_exit` 1.2k → **12,231** CIDRs (~10×) and `datacenter` ~11.6k → **53,297** CIDRs (~4.6×),
  deduped; real AWS/Google IPs classify as datacenter, private LAN stays clean. **Verification catch:** GitHub's licence
  field reported X4BNet `null`, but its README carries full MIT text covering "the list itself" — confirmed at
  source before wiring (the standing don't-trust-single-source rule, applied to a licence). The other assets are
  licence-gated (Berke corpus → request research-use terms; FireHOL → per-upstream vetting) or stats-only; X6/X7
  still have no downloadable real dataset. Next external unlock: accept the Berke data terms → real prevalence prior.
- **2026-06-22 · iteration 7 (Berke prevalence-prior adapter — turnkey, awaiting operator download)** — pursued
  the X4 prevalence half. Investigation closed the loop to the session's start: the Berke browser-attributes file
  is **the same `survey-and-browser-attributes-data.csv` on Harvard Dataverse** (`doi.org/10.7910/DVN/0SGZFF`)
  behind the guestbook/WAF; the repo MIT licence covers code only, and the data carries research-use terms (no
  re-identification, **no resharing**). Only the no-attributes survey CSV is in the repo (useless for a prior).
  So I can't fetch it (the third-party-production line + I won't accept terms on the operator's behalf), but I
  **built the turnkey consumer**: `harness/berke_corpus.py` maps each Berke row into the detector's own
  `features_from_fingerprint` (zero bucketing duplication → prior stays in sync with the runtime scorer) and
  emits **only the aggregate prior** (frequency tables, never rows → honours no-resharing). Column names pinned
  from the published data dictionary + the repo's preprocessing notebook; offline-tested against synthetic rows
  in that schema (7 tests, 100% module cov, harness 240 green). The moment an operator accepts the terms and
  downloads the CSV: `uv run python -m kitsune_harness.berke_corpus <csv>` builds the real-traffic prior. This
  is the prevalence analog of iteration 6's IP-rep wiring — both halves of X4 now have turnkey consumers; only
  the operator-gated download remains.
- **2026-06-23 · GreyNoise GNQL capability-gap analysis** — mapped GreyNoise's GNQL telemetry against
  Kitsune. Verdict: **complementary, not overlapping** — GreyNoise is internet-wide IP/actor reputation,
  Kitsune is per-session cross-layer coherence; most GNQL facets map onto Kitsune's IP-reputation layer
  (already external-data-bound). Covered/equivalent: JA3/JA4/JA4H, JA4T↔`tcp_os` coherence, HTTP
  method/path/UA, the datacenter/VPN/Tor CIDR lists. Out of scope: HASSH/JA4SSH (SSH), CVE/callback_ips
  (vuln-scan/C2), internet-wide sensor generation (architectural). **Two real gaps surfaced:** (1) **G7
  FCrDNS declared-crawler verification** — a NEW *groundable* lead the iteration-3 "DRY" claim missed;
  BUILT this cycle (edge `fingerprint.VerifyCrawler` → `net.fake_declared_crawler`, experimental,
  FP-safe-by-construction, unit+detector grounded). (2) **X8 GreyNoise GNQL actor enrichment** — the
  per-IP actor/classification feed missing from the data-source table; queued (needs an API key at
  deploy). So the groundable column is no longer strictly dry — a new external telemetry source
  (GreyNoise) re-opened it, exactly as iteration 3 predicted ("a genuinely new technique re-opens it").
- **2026-06-23 · external-dataset sweep + cloud-range expansion** — catalogued four new public feeds in
  the data-source table: Google/Bing crawler IP-range JSON (G7 DNS-free path), additional cloud/CDN ranges,
  Spamhaus DROP/IPsum, and the FoxIO/peet.ws JA4 fingerprint DB. **WIRED #2**: `ip_reputation_refresh` now
  folds Oracle + DigitalOcean + Cloudflare + Fastly into the datacenter slice (stable official URLs, per-
  source floors, offline parser tests) on top of AWS+GCP+X4BNet — a ~60k-CIDR datacenter feed. Azure
  omitted (its Service-Tags JSON URL rotates weekly behind a portal redirect — needs a discovery step).
  The crawler-IP-range feed (the authoritative DNS-free consumer for `net.fake_declared_crawler`) and the
  JA4-DB hint-table expansion remain candidate (edge-side consumers).
- **2026-06-23 · arms-race loop tick 1 (gap-queue intake)** — mined TheGP/untidetect-tools,
  Everything-About-Captchas, Proxy-Providers-List + commercial anti-detect browsers (Multilogin/GoLogin/
  AdsPower/Dolphin-anty/Kameleo/Octo/BitBrowser/Linken Sphere/Bablosoft) + libraries. Cross-referenced vs
  current coverage. **Most commercial AD browsers hit the same canvas/WebGL/audio/font/WebRTC surfaces
  Kitsune already has coherence/artifact tells for** (the per-session floor), so they buy no new convict
  surface — EXCEPT specific features, now queued as **VERIFIED groundable gaps**: G8 (screenX/screenY
  coordinate coherence — a net-new surface; Bablosoft MouseEvent-Patcher), G9 (rebrowser-bot-detector
  coverage audit beyond cdp_runtime_enabled), G10 (mobile-behavioral FP gate). **New evaders for breadth**
  (caught by existing net tells, validate coverage): LightPanda (new lightweight engine class), got-scraping
  + CycleTLS (JS/Go TLS-impersonation HTTP clients) — none in the fleet. **Bablosoft PerfectCanvas**: naive
  (main-only) is already caught by `canvas_worker_vs_main`; a both-realm replay reaches the camoufox-class
  frontier (suspicious), not a new convict. **External-data-bound** (queue, not buildable): residential/
  mobile/ISP proxy detection + malware-fuelled RESIP (the Proxy-Providers-List categories → X2/X3/X8);
  CAPTCHA-solver traffic patterns (solver services are orthogonal to per-session FP detection). Loop closes
  G8→G10 + adds the breadth evaders on subsequent ticks.
- **2026-06-23 · arms-race loop tick 3 (closed G10 + missing-test audit)** — **G10 DONE** (mobile-biomech
  applicability gate, merged). **Missing-detection-test audit**: scored the full corpus vs the 100 active
  rules — 89 fire on a corpus evader, 11 do not (br.color_depth_anomaly, devicepixelratio_anomaly,
  languages_empty, mobile_no_touch, platform_empty, rfp_browser, screen_zero, voice_os_vs_ua,
  webgpu_vendor_vs_webgl, rep.datacenter_asn, rep.known_proxy_exit). **No missing-test gap**: all 11 already
  have engine-level firing tests (detector/tests/test_engine.py parametrised cases) + unit tests (rep.* in
  test_ip_reputation, rfp_browser in test_applicability). They are environment / degenerate-value / IP-rep
  tells the EVADER FLEET doesn't happen to trip (it isn't stripped/datacenter-hosted), which is expected —
  the corpus is the red-team ladder, not a coverage harness. No action; coverage is solid. **Next builds:**
  G9 (rebrowser-bot-detector leak audit — exposeFunction-binding + sourceURL leaks beyond cdp_runtime_enabled;
  groundable via a vanilla-Playwright positive vs patchright EVADES) and G8 (screen-coordinate coherence —
  net-new surface; build CORROBORATING + fullscreen-gated for FP-safety, since CDP Input.dispatchMouseEvent
  defaults screenX=clientX/screenY=clientY while a real windowed browser always has vertical chrome offset).
