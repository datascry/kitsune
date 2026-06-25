# Changelog

All notable changes to Kitsune are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut automatically from
[Conventional Commits](https://www.conventionalcommits.org/) via release-please.

## [1.7.0](https://github.com/datascry/kitsune/compare/v1.6.0...v1.7.0) (2026-06-25)


### Features

* **collector:** show swipe velocity-CV in the behavioral biometrics panel ([60cebb0](https://github.com/datascry/kitsune/commit/60cebb09c27b5acf6d0072b318a614c5637c004d))
* **deploy:** dedicated iprep-refresh service (flag-free, RW writer) ([0f06084](https://github.com/datascry/kitsune/commit/0f06084b58845461fa0898beea446133456bd957))
* **detector:** consolidate fingerprint surfaces + enumerated values into one panel ([88b29f6](https://github.com/datascry/kitsune/commit/88b29f68fce041895dd7c378b9ca54e6b7f0cc6f))
* **detector:** enumerate every profiled fingerprint surface on the live panel ([d97a379](https://github.com/datascry/kitsune/commit/d97a379998deea3b0338119f7365fb8994857c3e))
* **detector:** full mobile biomech cluster in the behavioral panel (X6) ([be21bc1](https://github.com/datascry/kitsune/commit/be21bc1a767ae78cc71a6a6c92ed7fe71418511f))
* **detector:** ground + display mobile keystroke biomech (X6) ([5efb6fc](https://github.com/datascry/kitsune/commit/5efb6fc691c7ccfd4bafe8088a7890e1ae79c9bf))
* **detector:** mobile-aware keystroke interval floor, grounded on Aalto ITE (X6) ([b52979e](https://github.com/datascry/kitsune/commit/b52979eb2d49cfc0816e65ac6fa0d6fc6df03dbd))
* **detector:** reorder behavioral panel after fingerprint surfaces + split desktop/mobile biomech ([13fc3f1](https://github.com/datascry/kitsune/commit/13fc3f17275163343cd5ffd74c448f884ee330f7))
* **detector:** ship bh.click_without_trajectory — teleport-click tell (G11) ([9aa776c](https://github.com/datascry/kitsune/commit/9aa776c09657d83e159ebc8f10556eb19571b913))
* **detector:** ship bh.keystroke_interval_floor — agent-speed typing tell (G13) ([0b338d5](https://github.com/datascry/kitsune/commit/0b338d57f412cd0b719be95cb5fb6c0495851d50))
* **detector:** ship bh.touch_uniform_velocity — mobile swipe biomech (X6) ([a16f5b4](https://github.com/datascry/kitsune/commit/a16f5b40d3563b7a7c2eedf59d9ee903cf78d745))
* **detector:** show IP geo + reputation in the wire panel ([41609c9](https://github.com/datascry/kitsune/commit/41609c921a885c929cf8da152c8a84f7788480a0))
* **edge:** N1 — JA4T TCP/IP fingerprint (MSS, window-scale, quirks) + live wire panel ([0b038c2](https://github.com/datascry/kitsune/commit/0b038c25c9cf3030f92750ebb79f13cb1357c9d6))
* **edge:** N2 — TLS extension + cipher ORDER fingerprints (+ GREASE placement) + display ([01ae43d](https://github.com/datascry/kitsune/commit/01ae43d1b6c875feed5f6cbb0c4d1deb9d3d5a79))
* **edge:** N3 — QUIC transport-parameters fingerprint + display ([fe10df4](https://github.com/datascry/kitsune/commit/fe10df46b6e45ec2312134ec36d5017238b4495f))
* **edge:** N4 — negotiated HTTP-version fingerprint + display (h1-downgrade tell) ([449394d](https://github.com/datascry/kitsune/commit/449394d648bc88cde72d69bc7bffe114fbb5345f))
* **edge:** slow-HTTP (slowloris) detection core — SlowLorisScanner (G16) ([69d6a01](https://github.com/datascry/kitsune/commit/69d6a01c731c3cdb8fc0aec016c80ced8ccd793f))
* **edge:** surface N5 ClientHello micro-tells — key_share, cert-comp, ECH/ALPS + display ([0be6e5b](https://github.com/datascry/kitsune/commit/0be6e5bc182313c56098fd4047711f7421823dbc))


### Bug Fixes

* **detector:** make ip-rep refresh resilient to a single source failing ([bdcb361](https://github.com/datascry/kitsune/commit/bdcb361cd85cf6d100fbe05a4eaf42dd9a2fff04))
* **detector:** remove Analyze button; emit trace_hash once per load (trace_replay FP) ([439f94b](https://github.com/datascry/kitsune/commit/439f94bcc50f19da15fb8c437b80634405ff3d6a))


### Performance Improvements

* **detector:** prefix-length index for IP-rep lookup (linear scan -&gt; ~50x) ([a01b8ec](https://github.com/datascry/kitsune/commit/a01b8ec46980965028a2180f21d43516399c5f14))

## [1.6.0](https://github.com/datascry/kitsune/compare/v1.5.0...v1.6.0) (2026-06-23)


### Features

* **collector:** catch Playwright's __playwright__binding__ automation global ([7fce633](https://github.com/datascry/kitsune/commit/7fce63363f9c3fd0e2f2ad6e7e22a166f1efccd5))
* **detector:** add Oracle/DigitalOcean/Cloudflare/Fastly to the datacenter feed ([485e39b](https://github.com/datascry/kitsune/commit/485e39b3ffe823588fc07643d4f1de3512fd27d3))
* **detector:** embed machine-readable verdict JSON in the live page ([66a4ccd](https://github.com/datascry/kitsune/commit/66a4ccd7b87ba9a7f6c3f2406bd15440073699e1))
* **detector:** link main-page detections + uplevel the evader drill-downs ([2a4b457](https://github.com/datascry/kitsune/commit/2a4b457bcf01be88f20a8681137c251106a96f84))
* **detector:** list all 96 evasion configs with real descriptions ([7f80f3b](https://github.com/datascry/kitsune/commit/7f80f3bf8c3f6756a2c3363a2bdf07e7157ed8ec))
* **detector:** maximal SEO on every doc + drill-down page ([f628f39](https://github.com/datascry/kitsune/commit/f628f39fcfafabd48a266c4ca62e8d6a0f2cab0e))
* **detector:** richer evader pages — real descriptions + tell titles ([0ed1ccb](https://github.com/datascry/kitsune/commit/0ed1ccb38e23759c79a4a687385242c8cffe5baa))
* **detector:** serve /llms.txt for LLM agents ([268bae1](https://github.com/datascry/kitsune/commit/268bae1ac9c75c26411bfc3631b3b0076537e5c0))
* verify declared crawlers via FCrDNS + make IP-rep data deployable ([57ddd7a](https://github.com/datascry/kitsune/commit/57ddd7a3c262eec3412ac560b08504bd52800bef))


### Bug Fixes

* clear three false positives that convicted real Safari ([d376175](https://github.com/datascry/kitsune/commit/d3761756ce13ec8522b6a2ceb079c448e9c72811))
* **detector:** define --amber in doc CSS so suspicious badges render ([f391a96](https://github.com/datascry/kitsune/commit/f391a969b812b62278cbbc277db9301277b7832a))
* **detector:** gate mouse-biomech floors off real mobile devices ([332cfcc](https://github.com/datascry/kitsune/commit/332cfcc9a82a0557b5249bb35643ff2e2193fc5f))
* **detector:** harden the drill-down routes against reflected XSS ([87e8f57](https://github.com/datascry/kitsune/commit/87e8f57d9c77ffcf5b3c418cdfd4cbe9a03559ac))
* **detector:** sanitize the evasion slug before it reaches SEO sinks ([f98fc65](https://github.com/datascry/kitsune/commit/f98fc65fd9229eec5005c87466a8eaadb6712057))
* **docs:** correct the IP-rep refresh command (uv run, not bare python) ([5af181a](https://github.com/datascry/kitsune/commit/5af181a7f8390002db6143cc986d55f04b86c248))

## [1.5.0](https://github.com/datascry/kitsune/compare/v1.4.0...v1.5.0) (2026-06-23)


### Features

* **detector:** concise customer-facing how-it-works + research pages ([5ba85da](https://github.com/datascry/kitsune/commit/5ba85dabeb905be49c310f74160e29fd96b75d46))
* **detector:** drill-down pages for every detection + evader ([ec28149](https://github.com/datascry/kitsune/commit/ec281490ee5d2c5bed3dcbf41405a2ceb8bc3553))


### Bug Fixes

* **detector:** drop the filler hero stat panel ([420c2a9](https://github.com/datascry/kitsune/commit/420c2a98a18ace136a09eb934640143cfd4b7468))
* **detector:** escape the canonical/OG url in the page shell (CodeQL) ([434cfea](https://github.com/datascry/kitsune/commit/434cfea6114fc3e6840233a0df61fc5a55521e74))
* **detector:** make the verdict legible (audit follow-up) ([485c136](https://github.com/datascry/kitsune/commit/485c1361fc1554fa8f3b6d2ec2449bb93f98d844))
* **detector:** show all behavioral metrics on mobile ([e6b293d](https://github.com/datascry/kitsune/commit/e6b293da399123f1bfdfbed11ea9f18f3514cb2d))

## [1.4.0](https://github.com/datascry/kitsune/compare/v1.3.0...v1.4.0) (2026-06-23)


### Features

* **detector:** customer-facing matrix/detections/evasions pages ([25040af](https://github.com/datascry/kitsune/commit/25040af6d54211427531607c85b21586da256e08))
* **detector:** mobile-responsive layout — fix the horizontal-overflow scroll ([71e9081](https://github.com/datascry/kitsune/commit/71e908130f22c1dee84dc6acfdd8fe66358904f5))

## [1.3.0](https://github.com/datascry/kitsune/compare/v1.2.0...v1.3.0) (2026-06-23)


### Features

* **ci:** pull-based CD — GHCR image publish + Watchtower auto-update (Option B) ([737520a](https://github.com/datascry/kitsune/commit/737520afb8b0acead7d280e3504b7cd7eec5e358))
* **collector:** interactive biometrics controls + move panel to top (GitHub Pages livepage) ([debd4cf](https://github.com/datascry/kitsune/commit/debd4cf2721ff4d8a82a5bdff3cf28e21252f42e))
* **collector:** livepage L1-L3 — mount panel early, re-evaluate, touch-aware ([4047060](https://github.com/datascry/kitsune/commit/4047060f9386451bf0ad5121c254b4166401ca65))
* **collector:** livepage L5-L7 — spoof demos, rule provenance, shareable result ([8e8049e](https://github.com/datascry/kitsune/commit/8e8049ea7125bcf7357ee7efb8afbf37c5731922))
* **detector:** doc pages — matrix/evasions/detections/how-it-works/research (Phase 5) ([1286ea8](https://github.com/datascry/kitsune/commit/1286ea8eb1a1083739663e0ae17c95772743fb57))
* **detector:** gate inspection endpoints behind KITSUNE_ADMIN_TOKEN ([6cb8f5e](https://github.com/datascry/kitsune/commit/6cb8f5ebbd308f7dc73ee8aac55a26ccd860dcae))
* **detector:** geo/ASN enrichment on the wire panel via GeoLite2 (Phase 4) ([3981733](https://github.com/datascry/kitsune/commit/3981733179325b478ff7b207f0855bf24d40bd05))
* **detector:** interactive biometrics panel on the demo page + live readout up top ([c39a206](https://github.com/datascry/kitsune/commit/c39a206c04e8345be2d00d536b77c4e02309597c))
* **detector:** landing-page SEO shell + brand assets (antidetect-first front door) ([638a172](https://github.com/datascry/kitsune/commit/638a172ccb69dc5613068e6906ac3934084882d0))
* **detector:** live-page render port + layer-grouped detections (Phase 2) ([64a94d8](https://github.com/datascry/kitsune/commit/64a94d8df9a03cc182be3b638624cb8b0c1f5f09))
* **detector:** S1 step (b) — no-JS CSS [@media](https://github.com/media) beacon collector ([d083156](https://github.com/datascry/kitsune/commit/d083156b5524a9a9a76c7970011c34147826f248))
* **detector:** S1 step (c) — detector-side CSS⇄JS touch coherence derivation ([5e6af5f](https://github.com/datascry/kitsune/commit/5e6af5f4936585dde121b4232f64f17f60ccd41a))
* **detector:** uplevel the served demo page to the forensic-inspector aesthetic ([c743d8b](https://github.com/datascry/kitsune/commit/c743d8b8c97a444842508482aefe582723540d73))
* **detector:** wire layer + cookie-scoped /inspect + full-stack ID (Phase 3) ([3090459](https://github.com/datascry/kitsune/commit/30904599e9421cc1bbe085e0ff71820316a4787c))
* **edge:** production deploy — real-cert TLS, prod compose overlay, deploy runbook ([719977e](https://github.com/datascry/kitsune/commit/719977e7c27c969bf63c7d04fa795e14a6ef9309))
* **harness:** expand the ethics allow-list with dedicated vendor/test endpoints ([a1c1e5c](https://github.com/datascry/kitsune/commit/a1c1e5c84bbbad534788f82baa09b4b4b142fb01))


### Bug Fixes

* **detector:** gate the behavioral layer on real human input ([8859752](https://github.com/datascry/kitsune/commit/885975234a16a6fa3d74740e6c8c3a1ec88f4d07))
* **docs:** certbot one-shot needs --entrypoint certbot; gitignore .env ([1065bf8](https://github.com/datascry/kitsune/commit/1065bf8c9ae22438387c7979c1ab42dc745ea554))
* **evaders:** bound PoW many-small count + annotate lab cert-skips (CodeQL) ([b6adb1b](https://github.com/datascry/kitsune/commit/b6adb1bf7f6088e228f63f95512250bb0aab67bd))


### Reverts

* **detector:** S1 pointer/touch CSS⇄JS rule — FP-unsafe (headful-grounded) ([3290747](https://github.com/datascry/kitsune/commit/3290747ead2df91fcaf9a5076b718c2bb9386801))

## [1.2.0](https://github.com/datascry/kitsune/compare/v1.1.0...v1.2.0) (2026-06-22)


### Features

* **collector:** lead the live page with a detection-capability hero banner ([8c9b77f](https://github.com/datascry/kitsune/commit/8c9b77fb3b14479fbf016a2d4d637daf6f7c0c8e))
* **collector:** live interactive behavioral panel on the demo page ([582297c](https://github.com/datascry/kitsune/commit/582297c7db5927548c019115980af417ed1405be))
* **collector:** mirror br.mobile_no_touch into the livepage collector ([1fe8885](https://github.com/datascry/kitsune/commit/1fe888575a61b453bb6c39d6215e2e679dda7e08))
* **detector:** bh.trace_replay_within_session — convict within-session pointer-trace replay (v0.74.45) ([fc39131](https://github.com/datascry/kitsune/commit/fc39131f0415c70ccaf334e2ab1173857c972eeb))
* **detector:** br.brave_spoofed catches Proxy-faked navigator.brave (v0.74.48) ([c7f629f](https://github.com/datascry/kitsune/commit/c7f629f49c4af06b6ef54747d0cf31158cf6e3f4))
* **detector:** br.coalesced_untrusted catches the Proxy-over-native coalesce fake (v0.74.37) ([087f393](https://github.com/datascry/kitsune/commit/087f393ec2c953220480e048236cc49f1e8f3464))
* **detector:** br.fingerprint_unstable_within_session — catch re-randomising anti-detect browser reusing a cookie (v0.74.44) ([cb007e8](https://github.com/datascry/kitsune/commit/cb007e863812845f47b6b0b206363c9e8c665b5a))
* **detector:** br.mobile_no_touch — phone/tablet UA with maxTouchPoints 0 (research-radar G1) ([0be9d49](https://github.com/datascry/kitsune/commit/0be9d492e4b134fa6a415dfe3e877ffb0945c340))
* **detector:** br.worker_source_rewritten — fundamental catch for worker-scope injection (v0.74.47) ([16aae95](https://github.com/datascry/kitsune/commit/16aae95c48d90a3222d12f101d8790f8e9aa9462))
* **detector:** convict within-session IP rotation (net.ip_rotation_within_session, v0.74.39) ([3145328](https://github.com/datascry/kitsune/commit/3145328d040ecb5f4e83c8dcc369ea0fc56393d8))
* **detector:** convict within-session JA4 rotation (net.ja4_unstable_within_session, v0.74.38) ([27e8bd1](https://github.com/datascry/kitsune/commit/27e8bd1dadba107573ead7fa11c0b719efdac925))
* **detector:** ground the WebRTC real-IP leak in-sandbox; demote net.webrtc_ip_vs_observed FP-safe (v0.74.40) ([3789bb5](https://github.com/datascry/kitsune/commit/3789bb5328175f54de72d0ad3b588c7ef3fac276))
* **detector:** net.datacenter_origin_proxied — convict the cloud-VM-behind-residential-proxy (v0.74.42) ([ab53bb3](https://github.com/datascry/kitsune/commit/ab53bb30f905c9786158ddc3ae8ffacae443d885))
* **detector:** net.h2_unstable_within_session — within-session h2-stack rotation (v0.74.49) ([e3d847b](https://github.com/datascry/kitsune/commit/e3d847b2f2303c3c209b6ae6c6120a209cfc40d8))
* **detector:** net.ua_rotation_within_session — catch same-engine mid-session UA rotation (v0.74.43) ([7249773](https://github.com/datascry/kitsune/commit/7249773eed392bed63ac8f9eb92feb9d01336df4))
* **detector:** rep.webrtc_origin_datacenter — classify the WebRTC-leaked origin (v0.74.41) ([f7192a6](https://github.com/datascry/kitsune/commit/f7192a6d8f1bbcbc844fabe729a6748f1cc3ee74))
* **detector:** wire MIT X4BNet VPN/datacenter feeds into IP-rep refresh ([bc60859](https://github.com/datascry/kitsune/commit/bc60859f9e1077190af7dbc2e45d6f9296d64267))
* **detector:** worker_constructor_tampered catches Proxy-wrapped Worker ctor (v0.74.46) ([762543a](https://github.com/datascry/kitsune/commit/762543ade86162b9602adeac26f00eb13e54314d))
* **docs:** deterministic auto-generation + CI freshness gate for every programmable doc metric ([9588ab3](https://github.com/datascry/kitsune/commit/9588ab396b706bb4d34f5a1d1c2a88cb2cc0ce6a))
* **edge:** DCID-keyed QUIC capture — per-connection attribution primitive (ADR-0005) ([d5f7425](https://github.com/datascry/kitsune/commit/d5f74259ba052b93023ae38e7e7e61582b60e0ca))
* **edge:** serve HTTP/3 with per-connection (DCID) QUIC attribution (ADR-0005) ([67eac3a](https://github.com/datascry/kitsune/commit/67eac3a4a87d50ada17ef7a79455cb206b556176))
* **evaders:** add apify-fp-inject — main-realm injection manufactures worker-realm incoherence ([9248870](https://github.com/datascry/kitsune/commit/92488706c509682a84e794c3b27a5ef694cf00b6))
* **evaders:** add azuretls — TLS forger caught by 4 net tells (the redundant inference was wrong) ([faa8f45](https://github.com/datascry/kitsune/commit/faa8f45e888f252c99477544bbf38c44ed65fe64))
* **evaders:** add playwright-extra — the OG stealth baseline self-inflicts cross-layer incoherence ([96eba86](https://github.com/datascry/kitsune/commit/96eba86106d9bc3ce6cf61f18b276825fc20796e))
* **evaders:** COALESCE_PROXY — Proxy-over-native coalesce patch defeats the artifact layer ([292f5e5](https://github.com/datascry/kitsune/commit/292f5e5e8ec0fe1f4d67a49817f02721bfe8d88f))
* **evaders:** COALESCE_SPOOF — defeat bh.synthetic_no_coalesced via fabricated coalesced events ([cb5800c](https://github.com/datascry/kitsune/commit/cb5800c8c413bbcb7a9d9e0181299a0eb34fc9f4))
* **evaders:** coherent-Gecko is the thinnest-caught stock engine (1 tell) — locates why Camoufox exists ([5e83d62](https://github.com/datascry/kitsune/commit/5e83d627c81e6bf95cfd90ae41cc7775629e1ed2))
* **evaders:** fix the self-defeating camoufox-hardened config (Windows-on-Linux → tcp_os) → now EVADES ([81d7cc3](https://github.com/datascry/kitsune/commit/81d7cc3e739451367f19cb26ddbcbf685f259284))
* **evaders:** Gecko maximal stack (camoufox-hardened-behave) + cross-layer combination matrix ([491ce95](https://github.com/datascry/kitsune/commit/491ce9598f4c876fcc560b0cebd803acf3ff81dd))
* **evaders:** go-tls KS_QUIC — the fleet's first QUIC client; ground-truth the retired QUIC parser FP ([824c7c7](https://github.com/datascry/kitsune/commit/824c7c7464966fa9b835974c54eb00cf751b575f))
* **evaders:** ground the coherent-WebKit engine profile (KS_COHERENT) — engine evades CDP, OS axis betrays it ([1144a74](https://github.com/datascry/kitsune/commit/1144a747af87f6a42f54773a6727815ebbcc9b5d))
* **evaders:** instrumented PoW rung — Vein D mapped to its terminus ([d98ff41](https://github.com/datascry/kitsune/commit/d98ff41f16e3003616c24bd7880b63c58e1ef634))
* **evaders:** iOS-naive + fixed-touch mobile-spoof modes — ground the mobile escalation ladder ([e62a345](https://github.com/datascry/kitsune/commit/e62a3459186ce00e3768126bb290efd07a6f507b))
* **evaders:** KEYSTROKE_HUMAN — first fleet evader to defeat the keystroke floor by timing synthesis ([6d0dd43](https://github.com/datascry/kitsune/commit/6d0dd43050bd7681e56f483ed138685c47ce9f15))
* **evaders:** KS_NOWEBRTC — block WebRTC to defeat shared_real_ip (closes the WebRTC arms race) ([7b9b3fc](https://github.com/datascry/kitsune/commit/7b9b3fc622a9cc9080089ce697a961f3959dbbb9))
* **evaders:** KS_SOCKS WebRTC counter degrades to webrtc_unavailable — the WebRTC arms race closes ([f8e851c](https://github.com/datascry/kitsune/commit/f8e851c40512550d20708d925b56c93fb1442b60))
* **evaders:** mobile-emulation — new surface, comprehensively caught (prevalence model's first live positive) ([56dd8ce](https://github.com/datascry/kitsune/commit/56dd8ce44db6adb70b8fac8fde356bc8acf3af96))
* **evaders:** naive mobile-UA-spoof mode — live positive for br.mobile_no_touch ([234aeba](https://github.com/datascry/kitsune/commit/234aeba014d35dec8eb99144477f683e9514e844))
* **evaders:** NEW EVADES — Linux-pinned headless Camoufox (lowest-bar; corrects "headful-only" framing) ([c24eb3f](https://github.com/datascry/kitsune/commit/c24eb3f86d7f5167ce4f985b0b9ebc13757bb023))
* **evaders:** PoW arms-race testbed — multi-class gate + native solver (Vein D) ([8c10745](https://github.com/datascry/kitsune/commit/8c10745a69c7d60848ac23b2eaf41bb46b7f4edd))
* **evaders:** red-team counter — headless Camoufox EVADES once the touch leak is fixed (KS_NOTOUCH) ([bf5f1ca](https://github.com/datascry/kitsune/commit/bf5f1ca31de22cf754e4addaf395e81d21151998))
* **evaders:** UACH_COHERENT — coherent cross-layer UA via CDP defeats the UA-CH headless tells ([553bf03](https://github.com/datascry/kitsune/commit/553bf0374c811dcbdd401f7490f3677c58147c13))
* **evaders:** white-box + harden playwright-extra's maskLinux self-defeat (cross-layer OS incoherence by default) ([6cb228c](https://github.com/datascry/kitsune/commit/6cb228cf4416740d2246e26a24b3529f6d9b2397))
* **evaders:** zendriver KS_UACH — coherent UA-CH makes zendriver a HEADLESS evader ([43e3f86](https://github.com/datascry/kitsune/commit/43e3f86118ac08d81c0fbcd7d0eaeb721bd19fdd))
* **evaders:** zendriver-uach-behave — stack behavioral synthesis on the clean evader; ground the saturation boundary ([0bdc64c](https://github.com/datascry/kitsune/commit/0bdc64c3815486ff4cb72f0e27b56292a6cabff6))
* **harness:** build the Berke (PoPETs 2025) prevalence-prior adapter ([9e75b4c](https://github.com/datascry/kitsune/commit/9e75b4c18973da081e6914ee9165ebbff4f0e3c0))
* **harness:** coordination — catch JA4-rotating fleets via collision clustering ([c8c80c7](https://github.com/datascry/kitsune/commit/c8c80c711b05fa8de38e10228e42e35f487adf38))
* **harness:** grounding harness — turnkey sweep + runbook for real-data grounding ([6808182](https://github.com/datascry/kitsune/commit/6808182c2d31ed0093695a9d83b6bef2a4dc5aae))
* **harness:** Tier-3 prevalence corroboration tool (real-traffic second source) ([cbc9f26](https://github.com/datascry/kitsune/commit/cbc9f26a4c3a10a98dde87ba6c7fdb1bbb15fb12))


### Bug Fixes

* **collector:** mirror high-value probes into livepage + bound the demo.py lag (GAP-10) ([27cfc3f](https://github.com/datascry/kitsune/commit/27cfc3fe0e5955e3494d7acd86ca3a39252e730f))
* **contracts:** remove duplicate source: keys + lint against them (GAP-6) ([b63679f](https://github.com/datascry/kitsune/commit/b63679f68967d8e72a01e3012b053baa035444d0))
* **detector:** catch the COALESCE_SPOOF coalesced-events override (v0.74.36) ([980d70f](https://github.com/datascry/kitsune/commit/980d70f7c77efcb8ff8fffcab976e5b3f821c8c3))
* **docs:** correct the camoufox pointer_touch mechanism — random maxTouchPoints, not ?fast under-probing ([6a6e4f4](https://github.com/datascry/kitsune/commit/6a6e4f4378d55fbd767e65190c241987d0cc0cf3))
* **edge:** cap QUIC CRYPTO reassembly to bound a forged-Initial OOM (GAP-1) ([35b9586](https://github.com/datascry/kitsune/commit/35b95862dc9b1f9f1457b597cb93b7a561fd6596))
* **edge:** evict expired tcpfp Store entries — bound memory (GAP-7) ([b049408](https://github.com/datascry/kitsune/commit/b04940870803c0594945116dd610f252731beee3))
* **edge:** expire QUIC tee Initials after a TTL — kill the stale-buffer cross-attribution + memory leak ([8c18560](https://github.com/datascry/kitsune/commit/8c1856093f5ca9070502ba7dd90bfa0d0e218d52))
* **edge:** make H2FrameScanner counters atomic — fix data race (GAP-2) ([922f6b8](https://github.com/datascry/kitsune/commit/922f6b8d8f53d1665f4323b1225cfb8031bb71d9))
* **evaders:** camoufox fixed-coords mouse self-inflicts trace_collision; jitter it + ground the coordination boundary ([3fa228c](https://github.com/datascry/kitsune/commit/3fa228c118823bd7209eaf2c224ab0dbb73d817c))
* **evaders:** REFUTE iter-24 — headless Camoufox is CAUGHT by pointer_touch_incoherent (?fast under-probed) ([36a37e6](https://github.com/datascry/kitsune/commit/36a37e69cf1e98f021e8ca1a61009f80c0f8d230))
* **harness:** calibrate br.language_vs_languages (DERIVABLE_KINDS + nav.language) (GAP-4) ([c14e7bd](https://github.com/datascry/kitsune/commit/c14e7bdf9a9c2d04141a5b9e98e11284f69b6c3c))
* **harness:** exclude internally-incoherent browserforge fingerprints from the FP corpus ([463d4c8](https://github.com/datascry/kitsune/commit/463d4c8b71069abaa266ea1c7e48f892c9a01cca))
* **harness:** harden grounding CLI arg-parsing + cover the operator path ([1a41298](https://github.com/datascry/kitsune/commit/1a41298258cad5f6882ee6f882522cbfcb55e821))
* **harness:** include pow + xtest-coalesce evaders in the evasion catalog (GAP-3) ([4dc724a](https://github.com/datascry/kitsune/commit/4dc724a6cdfd8d1825e24d14e6087019f8ec29d2))
* **repo:** re-freeze stale brave.json fleet capture — privacy-browser FP-safety re-grounded ([d97fa27](https://github.com/datascry/kitsune/commit/d97fa27cfb162baba7034a7e32dd23a4bfec3231))


### Reverts

* **evaders:** restore the deliberate playwright@1.52.0 pin ([b0a8dd8](https://github.com/datascry/kitsune/commit/b0a8dd8dfe37b8ddc889db39d208e9a330605ccb))
* **evaders:** restore the documented playwright@1.52.0 pin — my sprint bump was ineffective + contradicted it ([94fa3b9](https://github.com/datascry/kitsune/commit/94fa3b90d49ac0beab8af871ea3b33e8e292c0b6))

## [1.1.0](https://github.com/datascry/kitsune/compare/v1.0.2...v1.1.0) (2026-06-20)


### Features

* **collector:** coherence banner, per-surface tamper/hashes, forensic redesign ([7e83a0d](https://github.com/datascry/kitsune/commit/7e83a0d1270d345875681f60bcb44b487429d589))
* **collector:** live page predicts the browser + scores detections per-browser (loop iter 26) ([31a2053](https://github.com/datascry/kitsune/commit/31a2053223192026f9ccaee6088318fc4ecfe019))
* **collector:** live-page discriminates Tor/Mullvad Browser from Firefox (white-box) ([61fd6fe](https://github.com/datascry/kitsune/commit/61fd6fed198e41220110ccaac7efcc08d92cb67c))
* **contracts:** promote net.h2_header_order_vs_ua experimental→active (two-source corroboration) (v0.74.13) ([2326bc2](https://github.com/datascry/kitsune/commit/2326bc20a9faafb2dd2f3afc94d0fc6dd34c68c9))
* **detector:** audio readback-consistency noise tell (v0.59.0) ([c7562fe](https://github.com/datascry/kitsune/commit/c7562fe918c4e46b90fad8d85b645b9152496842))
* **detector:** br.apple_ua_nonwebkit — iOS/Safari engine lock + mobile browser ID (v0.73.0) ([05ed73a](https://github.com/datascry/kitsune/commit/05ed73a22b09c683f34cf5721846ce127dea5b24))
* **detector:** br.brave_spoofed + genuineness guards — close the privacy-browser-spoof evasion (v0.73.5) ([351b7f1](https://github.com/datascry/kitsune/commit/351b7f1495e094396105fc2b1092d65ea413d8b9))
* **detector:** br.canvas_geometry_noise — JShelter canvas-geometry farbling tell (v0.72.0) ([5eb1703](https://github.com/datascry/kitsune/commit/5eb1703def97ef6c5ca5afc229c8140e9d82c041))
* **detector:** br.canvas_worker_vs_main — canvas realm coherence + canvas-spoof evader (v0.67.0, loop iter 19) ([896034a](https://github.com/datascry/kitsune/commit/896034afc265099b6ebd42ce123009988fdb22a0))
* **detector:** br.firefox_ua_nongecko — a Firefox UA without navigator.buildID is not Gecko (v0.74.17) ([df27677](https://github.com/datascry/kitsune/commit/df27677b1676e0e0ede0cd699f54506310801103))
* **detector:** br.language_vs_languages — spec-invariant locale-spoof tell (v0.73.6) ([076b3b9](https://github.com/datascry/kitsune/commit/076b3b96d7357b685e3905d6374526faa6f35a99))
* **detector:** br.languages_worker_vs_main — language half of the geo-spoof realm pair (v0.69.0, loop iter 21) ([9b965b0](https://github.com/datascry/kitsune/commit/9b965b0d9a42251968e4194ef4cde5dc0b7782c5))
* **detector:** br.safari_ua_no_webkit_api — a Safari UA without window.GestureEvent is not WebKit (v0.74.18) ([77fc42a](https://github.com/datascry/kitsune/commit/77fc42a0984e7be67b17ef36441cf8226888d8d4))
* **detector:** br.timezone_offset_vs_intl — internal timezone coherence (v0.71.0, loop iter 23) ([b4373f7](https://github.com/datascry/kitsune/commit/b4373f7deb322501e2a859be2a4fbbbc7cd3c0bc))
* **detector:** br.timezone_worker_vs_main — ACTIVE geo-spoof realm coherence + tz-spoof evader (v0.68.0, loop iter 20) ([bfc1a4f](https://github.com/datascry/kitsune/commit/bfc1a4f99cc1e1d1b6849b79cb2226cd8755d6c0))
* **detector:** br.webgl_worker_vs_main — GPU renderer realm coherence (v0.66.0, loop iter 18) ([dac4528](https://github.com/datascry/kitsune/commit/dac4528ef7560f78a16a49e73a9cc20b55a86143))
* **detector:** br.worker_constructor_tampered — escalation guard for the realm-coherence family (v0.70.0, loop iter 22) ([6615c14](https://github.com/datascry/kitsune/commit/6615c1484e50cbed75a55a59b843c323920d1070))
* **detector:** build the IP-reputation seed refresh tool (live Tor + cloud ranges) ([8322446](https://github.com/datascry/kitsune/commit/8322446391a9886f35b603e87e7ec186d7fd4ac1))
* **detector:** corroborate the biomech power-law floor on a second source (SapiMouse), tighten 0.1→0.05 ([6e80319](https://github.com/datascry/kitsune/commit/6e803198996474782319348bc41fb328d5e1e0b5))
* **detector:** DOMRect invariant tell (v0.61.0, loop iter 3) ([01b1a6f](https://github.com/datascry/kitsune/commit/01b1a6fca3a400400cb3e1b2f70f4eb5d41ab50a))
* **detector:** Electron-process + native-invariant automation tells (v0.60.0) ([40b3f87](https://github.com/datascry/kitsune/commit/40b3f87e676abe7995d4327cf18e81dd84600ff9))
* **detector:** fail-loud drift guard for the IP-reputation refresh sources ([a0efd76](https://github.com/datascry/kitsune/commit/a0efd76f9ae305a07c82efde5f672a4be03af367))
* **detector:** honeypot_interaction — a bait element a human cannot reach (v0.74.11) ([2fb429c](https://github.com/datascry/kitsune/commit/2fb429cc91307eaf11919558636ce47fe22bbe2d))
* **detector:** JS-engine stale-template coherence (v0.57.0) ([d210204](https://github.com/datascry/kitsune/commit/d210204ca37b55666e218035ec7efb3f8469e21f))
* **detector:** measureText main-vs-OffscreenCanvas coherence (v0.62.0, loop iter 4) ([737b2c7](https://github.com/datascry/kitsune/commit/737b2c72829328924382cebed012dc537d7e606a))
* **detector:** per-browser N/A — real Brave users no longer convicted on Shields farbling (v0.73.3) ([3398ffd](https://github.com/datascry/kitsune/commit/3398ffd4ba9eb070e2fbd85483e89689817cde06))
* **detector:** prevalence model live as a corroborating signal (v0.63.0, loop iter 7) ([39baf02](https://github.com/datascry/kitsune/commit/39baf025a71d2811fa566aeed9d01dd593f09e44))
* **detector:** show the verdict on the live detection page ([863cd8b](https://github.com/datascry/kitsune/commit/863cd8b0b30f65756bb62415eedcb6da7ae8c90d))
* **detector:** UA-CH high-entropy headless + version coherence (v0.55.0) ([e8aa52c](https://github.com/datascry/kitsune/commit/e8aa52c9dcaed8ff30f2b015fb7a3ef740486982))
* **detector:** WebGL renderer ANGLE-wrapper coherence (v0.56.0) ([5420ade](https://github.com/datascry/kitsune/commit/5420ade7dea81c4a358dbabae713dbfe8fede641))
* **edge:** add real Safari/Firefox JA4 hints — grounded vs FoxIO, removes net.tls_vs_ua_browser blind spot ([60a2f9d](https://github.com/datascry/kitsune/commit/60a2f9db3de554d91d6219ca7704a85533c39235))
* **edge:** cover the real-Chrome 17-extension JA4 variant — completes the FoxIO browser-JA4 grounding ([79f71e7](https://github.com/datascry/kitsune/commit/79f71e723b9119ac77a63feacbf6c60d58e8cf84))
* **edge:** JA4-hint the WebKit engine — catches a WebKit-engine bot faking a non-Safari UA (v0.74.19) ([1f7fb98](https://github.com/datascry/kitsune/commit/1f7fb981b561549d94b0f410ea49de98c482ac03))
* **edge:** JA4H regular-header-order coherence (v0.58.0) ([466e063](https://github.com/datascry/kitsune/commit/466e0637405c69e6aa2512af67e93b7c8264d66f))
* **evaders:** accept-lang-spoof gives net.accept_lang_vs_navigator its first live positive (v0.74.14) ([b38945f](https://github.com/datascry/kitsune/commit/b38945f80537a3efdcbaf78dc68fea4cb6abc1f8))
* **evaders:** add iframe-spoof — first live catch of br.iframe_divergence (loop iter 15) ([abe47b2](https://github.com/datascry/kitsune/commit/abe47b232b0d6dcd1244515a0a5d1507e27a31f5))
* **evaders:** add linear-bot — first catches of path_too_straight + uniform_velocity (loop iter 17) ([37bbac0](https://github.com/datascry/kitsune/commit/37bbac022b98a83a4970d42883fa8e290fd0814f))
* **evaders:** add native-spoof — first live catch of br.native_invariant_violated (loop iter 16) ([64fc3d1](https://github.com/datascry/kitsune/commit/64fc3d1b5284c2a05145bc3208754cc5ebcac604))
* **evaders:** add worker-spoof — first live catch of br.worker_divergence (loop iter 14) ([9fbdcf0](https://github.com/datascry/kitsune/commit/9fbdcf027b66c4d668701f1c7dfb46724d145ee6))
* **evaders:** AUDIO_READBACK_SPOOF mode — live-validates br.readback_noise (v0.73.9) ([da59340](https://github.com/datascry/kitsune/commit/da59340868b83566d016829c74a7e5f7e2adddab))
* **evaders:** canvas-lie + domrect-spoof — close the no-test/no-capture liability class ([1c87792](https://github.com/datascry/kitsune/commit/1c8779222a124703d482d7f6d159850b13057d3d))
* **evaders:** electron-leak mode — first live positive for br.electron_process ([2014c71](https://github.com/datascry/kitsune/commit/2014c7132d35581ac37419c0a3c395eed0c1f76a))
* **evaders:** firefox-os-spoof gives br.oscpu_vs_ua its first live positive (v0.74.16) ([8b8e3f2](https://github.com/datascry/kitsune/commit/8b8e3f21c7f4411811a3b456ccb3d8c2cbf93f98))
* **evaders:** HEADFUL flag — test patchright browser-layer evasion; the layer HOLDS via chrome_runtime_missing ([0aedc52](https://github.com/datascry/kitsune/commit/0aedc520030327ad2283531daeddf6c86c960572))
* **evaders:** http2-naive gives net.h2_header_order_vs_ua its first live positive (v0.74.12) ([1fdbca5](https://github.com/datascry/kitsune/commit/1fdbca5eb10e80d55bafe421fd4e2c562898bb4c))
* **evaders:** KS_PROXY / PROXIES egress routing — turnkey live-proxy coordination harness ([0298370](https://github.com/datascry/kitsune/commit/02983700a13b0f646428a924c7e3341a95b5d68d))
* **evaders:** measuretext-spoof mode — first live positive for br.measuretext_offscreen_vs ([6f8de9f](https://github.com/datascry/kitsune/commit/6f8de9fb06fdd5ecebfb8b37cae7114d8f1512da))
* **evaders:** renderer-spoof gives webgl_renderer_artifact a live Blink positive; refresh matrix/scoreboard ([bfd4a67](https://github.com/datascry/kitsune/commit/bfd4a678e4579f936f145a69a3d256764d839eb7))
* **evaders:** stale-engine mode — first live positive for br.engine_feature_vs_ua ([3aead25](https://github.com/datascry/kitsune/commit/3aead252136c337100fd87457206c8e072315336))
* **harness:** build_prior_from_dir — turnkey real-traffic prevalence prior (the [#1](https://github.com/datascry/kitsune/issues/1) frontier, now data-only-blocked) ([e4fd59f](https://github.com/datascry/kitsune/commit/e4fd59fa0287c4e5ddc83bb0ee0a0444386e208b))
* **harness:** build_prior_from_sessions — prevalence prior from real-traffic SESSION captures (completes turnkey path) ([e1a2c3f](https://github.com/datascry/kitsune/commit/e1a2c3f6f3db23be7d3fd90ddb49fe7a1f3e429b))
* **harness:** coordination precision/recall gate — the calibration analog for the fleet detector (loop iter 25) ([9ceccd1](https://github.com/datascry/kitsune/commit/9ceccd105a6eba688ede4fe76f6368591ff990aa))
* **harness:** corroborate the single-source prevalence prior against fpgen (Scrapfly data) ([7d8675a](https://github.com/datascry/kitsune/commit/7d8675a73bea083a90d660e4ccb4d1608b4c2b8e))
* **harness:** generate a complete evasion-technique registry into the evasion catalog ([e2547c0](https://github.com/datascry/kitsune/commit/e2547c0c374bfb381c72a542879f45c3e0f8a06f))
* **harness:** generate a complete, auto-updating rule registry into the detection catalog ([204ddf4](https://github.com/datascry/kitsune/commit/204ddf490f72cf960fb840c08780678977ea08ec))
* **harness:** Intoli real-traffic calibration source — surfaces a 73% mobile FP (loop iter 26) ([55792fc](https://github.com/datascry/kitsune/commit/55792fc2fcc104e7e7f3fc534e71edfb45af677a))
* **harness:** keystroke-collision — catch the credential-stuffing fleet that types, not clicks ([dd981b6](https://github.com/datascry/kitsune/commit/dd981b694aa202f9a8554e179c1d245ade92e042))
* **harness:** live coordination consumer — grade the running detector's session store ([cf23fbf](https://github.com/datascry/kitsune/commit/cf23fbfd5da18723ba7510a5c67d830a4845760e))
* **harness:** prevalence-model foundation — tested scorer + committed prior (loop iter 6) ([9127c0c](https://github.com/datascry/kitsune/commit/9127c0ce6902a85d9abdb72f091f9cc380967ee9))
* **harness:** real-browser calibration harness — quantify rule false positives ([9e448c2](https://github.com/datascry/kitsune/commit/9e448c2c6d8ffdcfc1cbf02bd4e52bab8fa28779))
* **harness:** Tier-2 real-engine calibration source — refutes 2 browserforge FPs (loop iter 2) ([cc8fb52](https://github.com/datascry/kitsune/commit/cc8fb52e79073d4c9851f0f5aaabe5b0f528c09f))
* **harness:** trace-collision — the behavioural analog of the fingerprint collision (loop iter 24) ([1c36456](https://github.com/datascry/kitsune/commit/1c36456fccbe81e8ff80a3582e157784946a9fc8))
* **harness:** wire IP reputation into the coordination gate — convicts a clean clone on datacenter IPs ([a4d1ac0](https://github.com/datascry/kitsune/commit/a4d1ac0db9a0a278867bef9368758ff92ef72985))


### Bug Fixes

* **collector:** live page mislabelled real browsers as bot — apply the conviction gate ([6462d0c](https://github.com/datascry/kitsune/commit/6462d0cbcd2b967482880c8ad2943fe48c21dc84))
* **collector:** live page no longer flags real Brave users as bot (farbling N/A) ([e2a1c26](https://github.com/datascry/kitsune/commit/e2a1c268f6e15cad99ece3f84cfa8a0ac7e1c603))
* **collector:** re-read getVoices() at collection time — kill a real-browser voices_empty FP ([d4bde16](https://github.com/datascry/kitsune/commit/d4bde16a0343a5aeebe476c2737d3bd858f05299))
* **detector:** adblock_present must corroborate, not convict — ad-blocker FP (v0.74.7) ([25a6f3d](https://github.com/datascry/kitsune/commit/25a6f3d6096618223cccdf0dd56cb8d114fd7f2a))
* **detector:** apple_ua_nonwebkit dropped the captureStackTrace arm — convicted real Safari 16.4+ (v0.74.9) ([65ab2cd](https://github.com/datascry/kitsune/commit/65ab2cd2177c5e42cf856c654fb35ff3dfd52676))
* **detector:** coarsen the prevalence CORES factor into buckets — exact-count eps-gap FP (v0.74.21) ([b096921](https://github.com/datascry/kitsune/commit/b0969214a8dc573a16ca3cd6b0f91e1bbbfd2180))
* **detector:** codec_os_incoherent must corroborate, not convict — Chromium-codec FP (v0.74.3) ([f447b6c](https://github.com/datascry/kitsune/commit/f447b6c1d603f39bf47aab34f86bab4c762ded6e))
* **detector:** cross-source-calibrate the prevalence threshold — browserforge self-p1 over-flagged 5x ([aa2eef0](https://github.com/datascry/kitsune/commit/aa2eef05c7547e5aa409ad0c4eb03f29e9602d1e))
* **detector:** desktop-gate no_plugins/mimetypes_empty/no_pdfviewer — kill the mobile FP (v0.73.2) ([f582aff](https://github.com/datascry/kitsune/commit/f582aff9836c1f90d69c5deac1a0a6dc93b10f69))
* **detector:** drop the prevalence COLOUR factor — a circular single-source browserforge FP (v0.74.20) ([41336d6](https://github.com/datascry/kitsune/commit/41336d619ddccf6fb6061ff690d09c29940a6aac))
* **detector:** engine_stack_vs_ua no longer convicts modern Firefox (122+ added Error.captureStackTrace) ([047a3c1](https://github.com/datascry/kitsune/commit/047a3c1c18e67242b9938286bdf27d53f212e09c))
* **detector:** font_linux_leak must corroborate, not convict — configurable-font FP (v0.74.2) ([05bf3ee](https://github.com/datascry/kitsune/commit/05bf3ee5fb403cf0313bdbfe6fa943a74ffdff20))
* **detector:** gate bot conviction on a convicting signal (v0.64.0, loop iter 9) ([2d0e4ca](https://github.com/datascry/kitsune/commit/2d0e4ca6d61603dd8148a14943a77d7611b21be8))
* **detector:** OS-family resolution kills the Android platform-coherence FP; correct the Intoli reading (v0.71.1) ([347a1f7](https://github.com/datascry/kitsune/commit/347a1f7a7c16ff63ff1dd17902c7d4cbc9d51e63))
* **detector:** prevalence GPU 'other' bucket false-flagged real Firefox/Mullvad (v0.74.33) ([32ced84](https://github.com/datascry/kitsune/commit/32ced84b58020d3ff4fe3165b2b3371fa75cb0c6))
* **detector:** prevalence is corroborating by category, cannot convict (v0.65.0, loop iter 11) ([84d78e0](https://github.com/datascry/kitsune/commit/84d78e0339c8b252d0d90ac7ae66df2ee6856a86))
* **detector:** prevalence screen factor was a circular single-source FP — coarsen to cross-source-robust buckets (v0.73.1) ([d958c79](https://github.com/datascry/kitsune/commit/d958c7914b01c6dfc53f0b4cd85d35e4467c0aeb))
* **detector:** prevalence_low abstains on a partial fingerprint vector — absence-as-improbability FP (v0.74.8) ([84bde19](https://github.com/datascry/kitsune/commit/84bde1981e3ae739c23cc010540c25f601404719))
* **detector:** readback_noise was a missed privacy-browser FP — add it to the farbling N/A (v0.73.8) ([8971dcf](https://github.com/datascry/kitsune/commit/8971dcf7d9a2428c5e5ed9a9dbb0704cffe5226a))
* **detector:** real Tor/Mullvad/RFP-Firefox users no longer convicted (v0.73.4) ([ad0af02](https://github.com/datascry/kitsune/commit/ad0af0285a4c2df98127cb608775be1dfcd3b205))
* **detector:** retire br.notification_denied — FPs on real "block notifications" users (v0.74.35) ([a72263f](https://github.com/datascry/kitsune/commit/a72263f19db9ca2dfa5ca889247838e4e68cb9fa))
* **detector:** retire chrome_runtime_missing — it convicted every real Chrome (grounded on real Chrome 149) ([aa18a3e](https://github.com/datascry/kitsune/commit/aa18a3eb692121a74113763069cdccc1c12a4b00))
* **detector:** retire math_engine_vs_ua — it false-fires on a real Chromium (v0.74.0) ([8d25bb7](https://github.com/datascry/kitsune/commit/8d25bb77111f47c8f30177eec1cb4bf9494ab20a))
* **detector:** stop a real Mullvad Browser being convicted on its by-design RFP farbling ([f96232a](https://github.com/datascry/kitsune/commit/f96232a9c12f502ddf742cf2ded34e8f79d0c279))
* **detector:** TLS/h2-vs-UA coherence no longer convicts real Microsoft Edge (Chromium family) ([d51129d](https://github.com/datascry/kitsune/commit/d51129d01552885099d5eb107fe00ec1bd141e5a))
* **detector:** vendor_vs_ua abstains on an unclassifiable UA engine (unknown never fires) ([463f7a6](https://github.com/datascry/kitsune/commit/463f7a6fd1d15886508d7b674900be82d4d8c5d0))
* **detector:** vendor_vs_ua abstains on iOS — real Chrome-iOS was a hard bot FP ([17f477b](https://github.com/datascry/kitsune/commit/17f477bee308cfa46f74037216455a202bbe2f0d))
* **detector:** webgl_not_angle must corroborate, not convict — Linux/legacy-Chrome FP (v0.74.6) ([1466935](https://github.com/datascry/kitsune/commit/14669357e2e407e3ea12d46099fed9d692923ead))
* **detector:** webgl_os_vs_ua false-fired on software-rendering Windows/macOS (v0.74.4) ([c36bf7b](https://github.com/datascry/kitsune/commit/c36bf7bdc42fcad1cd2984b1771d1b712327c55f))
* **detector:** webgl_renderer_artifact is N/A for Firefox — its renderer generalisation is not a spoof (v0.74.10) ([a704444](https://github.com/datascry/kitsune/commit/a70444459f74d35b31803b5af904e1c7ce0491f7))
* **detector:** webgpu_webgl_vs must corroborate, not convict — old-GPU FP (v0.74.5) ([256ca52](https://github.com/datascry/kitsune/commit/256ca528417483c48f3689eae7e876f4523a07b0))
* **detector:** webrtc_unavailable must corroborate, not convict — privacy-user FP (v0.74.1) ([015fe0e](https://github.com/datascry/kitsune/commit/015fe0e234e91763fe4acdd087bcb06d38f8cec4))
* **edge:** h2 header-order tell no longer convicts real Chrome's fetch() requests ([b1ce7cb](https://github.com/datascry/kitsune/commit/b1ce7cb18a1336bded90c479027b52eb9d7fe910))
* **edge:** JA4 prefix-hint the Chromium cipher suite — real Chrome now recognised; tls_vs_ua_browser validated (v0.74.15) ([221d9f9](https://github.com/datascry/kitsune/commit/221d9f968bf4eb786d0d10c668eaff945c68806f))
* **edge:** net.tls_grease_vs_ua no longer convicts real Firefox (Gecko does not GREASE TLS) ([38beb15](https://github.com/datascry/kitsune/commit/38beb15aa77fea50597b63af257d7cd3596b73dc))
* **edge:** retire net.quic_grease_vs_ua — broken QUIC signal convicted real Chromium + Firefox ([3690e90](https://github.com/datascry/kitsune/commit/3690e906e9ffeb76d611c1b0e887588e3a7713f1))
* **edge:** retire net.quic_pq_keyshare_vs_ua — same broken QUIC capture as quic_grease (v0.74.34) ([f9cc353](https://github.com/datascry/kitsune/commit/f9cc3531baba914d293f52819f11985d65ca00be))
* **evaders:** declare stealth's real deps in package.json — rebrowser-playwright + pinned playwright ([5ec33a8](https://github.com/datascry/kitsune/commit/5ec33a88b5976416b15deb1cfa44af0e1bcc1f0b))
* **harness:** calibration mapper emitted UA-Client-Hint signals for non-Chromium browsers ([fae0d2c](https://github.com/datascry/kitsune/commit/fae0d2c48d4a485420b8f81db2a6586e70f31df0))
* **harness:** calibration mapper falsely tripped br.vendor_vs_ua on every Firefox fingerprint ([959c338](https://github.com/datascry/kitsune/commit/959c3387a5ea51447ac6b675a0c0b7407e358a5e))
* **harness:** fp-collision must not solo-convict — false-flagged a standardized corporate fleet ([47ba770](https://github.com/datascry/kitsune/commit/47ba770129424210964d96a5a386c2f78f62afe1))
* **harness:** gate fleet conviction on a non-organic signal (loop iter 10) ([0839fe2](https://github.com/datascry/kitsune/commit/0839fe2da543267cca7278eca9933b9590572c0d))
* **harness:** JA4_c-divergence must not solo-convict — false-flagged a multi-Chrome-version cohort ([743043c](https://github.com/datascry/kitsune/commit/743043cbee9732efc0f5bbf1772d16a44e8187af))
* **harness:** mapper fabricated vendor_engine for absent-vendor fps (88% false vendor_vs_ua on fpgen) ([26efe5c](https://github.com/datascry/kitsune/commit/26efe5c8372609bb86c883cb8a53d9ec8e62d77d))
* **harness:** restore ruff-clean coordination + live-re-validate the cloned-fleet conviction at 0.74.21 ([7ea44ed](https://github.com/datascry/kitsune/commit/7ea44ed227dbe39a216812143c13adf3cd0b3a5c))


### Reverts

* **harness:** drop keystroke_collision — timing-hash can't be grounded across a real fleet ([2277438](https://github.com/datascry/kitsune/commit/2277438b35e00bd8a51807d8f41ec2a274d28f3b))

## [1.0.2](https://github.com/datascry/kitsune/compare/v1.0.1...v1.0.2) (2026-06-18)


### Bug Fixes

* **security:** bump h2-rapid-reset x/net 0.38 -&gt; 0.56 — clears 9 x/net CVEs ([9eb0b94](https://github.com/datascry/kitsune/commit/9eb0b94c62df82821b86a9b02ec377bd5f52d99d))

## [1.0.1](https://github.com/datascry/kitsune/compare/v1.0.0...v1.0.1) (2026-06-18)


### Bug Fixes

* **security:** mark ks_sid cookie Secure + minimize release token scope ([212d653](https://github.com/datascry/kitsune/commit/212d6534abb8458900c6d9d6cf278446b8d82c06))
* **security:** patch collector dev-dep vulns + drop stale stealth lockfile ([e3f52be](https://github.com/datascry/kitsune/commit/e3f52be355203b663bc44b47b0e9e1b29eac6a5a))

## 1.0.0 (2026-06-18)


### Features

* canvas-farbling detection + Brave evaluated — all 5 evasion philosophies covered (v0.26.0) ([6b817a9](https://github.com/datascry/kitsune/commit/6b817a97f91a0a6cac9bdc80934c7d66110626de))
* **collector,edge:** real CDP probe + JA4 hint loader; new collector signals ([4d3c718](https://github.com/datascry/kitsune/commit/4d3c718cb14f1b55e988ef4faa2e740130f53800))
* **collector:** live in-browser bot-detection page for GitHub Pages ([fd61800](https://github.com/datascry/kitsune/commit/fd6180018646c009f41bc155236045e2a237b675))
* **contracts:** deepen coherence registry to v0.2.0 ([a04db05](https://github.com/datascry/kitsune/commit/a04db05dab7e7e6b18c1371ac73d436be9d12e97))
* cross-layer WebRTC-IP-vs-observed-IP rule — the proxied-bot detector (v0.20.0) ([d45bab0](https://github.com/datascry/kitsune/commit/d45bab0a3353b532b3a7395d0c2e8c4735ad0713))
* detection-class taxonomy + no-spoof baseline control ([9a152f7](https://github.com/datascry/kitsune/commit/9a152f72ce09ba94ec8e607b9978e432361acd78))
* **detector,collector:** deeper behavioral layer — path + velocity shape (v0.3.0) ([e5a46e8](https://github.com/datascry/kitsune/commit/e5a46e89d8975d0b762c408f97a0392c5b3dddb5))
* **detector:** activate net.quic_grease_vs_ua — QUIC layer validated live end-to-end (v0.53.0) ([63c4769](https://github.com/datascry/kitsune/commit/63c4769384dcf774f7428869d1ec6d4e7e75b4e1))
* **detector:** batch of browser lie-detection + headless tells (v0.4.0) ([2897490](https://github.com/datascry/kitsune/commit/289749076e894483968863596c1577e7cbb048b1))
* **detector:** calibrated behavioral biomechanics rules, live in the collector (behavioral 4/4, v0.49.0) ([c6a7722](https://github.com/datascry/kitsune/commit/c6a77226a5690ffd54baedf08fa5fc993e5acd0c))
* **detector:** catch faked Notification.permission via the getter override (v0.35.0) ([febf37a](https://github.com/datascry/kitsune/commit/febf37a30756ad604e35de70afc9ca4253455d5e))
* **detector:** catch JS-injection tampering — re-catch full-stealth (v0.5.0) ([a8d4cbb](https://github.com/datascry/kitsune/commit/a8d4cbb55ec9e49f92d9b1c66535e798d9f7e277))
* **detector:** coalesced-pointer-event tell — catch CDP-injected "human" motion (v0.29.0) ([d586d17](https://github.com/datascry/kitsune/commit/d586d17fbf4103c3e7916ddad94bc661cb10dcd0))
* **detector:** codec-support coherence (v0.18.0, experimental) ([7495165](https://github.com/datascry/kitsune/commit/749516552a71563a2159f7b02bf38eb1d87077fa))
* **detector:** cross-layer browser coherence — Sec-CH-UA brand vs JS UA (v0.33.0) ([0f027e4](https://github.com/datascry/kitsune/commit/0f027e4ff42683034a63c12e2f99651a42c6dc3e))
* **detector:** cross-layer locale coherence — Accept-Language vs navigator.languages (v0.31.0) ([31a8c71](https://github.com/datascry/kitsune/commit/31a8c71cbd8193430d3a8712ea3a98d6d472695e))
* **detector:** cross-layer OS coherence — Sec-CH-UA-Platform vs JS UA platform (v0.32.0) ([39bc9e9](https://github.com/datascry/kitsune/commit/39bc9e9c8480af21fa31f32549b2ad7ac4d446ce))
* **detector:** CSP-bypass detection — the one CDP vector the patches can't fix (v0.30.0) ([59537c6](https://github.com/datascry/kitsune/commit/59537c6e98ed42355b18b7899172cfbeefd87fff))
* **detector:** deep engine-API coherence (Error.captureStackTrace, v0.21.0) ([279f7ca](https://github.com/datascry/kitsune/commit/279f7ca36d008ee29cbdd604f398983eea2d83e3))
* **detector:** engine error-message coherence — the deepest engine tell (v0.24.0) ([c74af49](https://github.com/datascry/kitsune/commit/c74af49c995edee224394a25dfe69a0fd08a0068))
* **detector:** engine-agnostic OS coherence (v0.7.0) + Camoufox coherence finding ([2149e53](https://github.com/datascry/kitsune/commit/2149e53a1c74c85725f4017682d677be56c47e56))
* **detector:** font construction-artifact detection (v0.17.0) ([7748512](https://github.com/datascry/kitsune/commit/7748512532dc6a85ab2c6af72e843146c5e31a9c))
* **detector:** font-OS fingerprint (v0.11.0) + frontier findings ([e5571d1](https://github.com/datascry/kitsune/commit/e5571d16dd1f69e60916a2c2e6133c92571ec514))
* **detector:** h2-engine-unknown coherence — catch a non-browser HTTP/2 stack under a browser UA (v0.45.0) ([e4931d4](https://github.com/datascry/kitsune/commit/e4931d4b04acf146b63170ca1b74d0fecad13c92))
* **detector:** HTTP compression-fingerprint tell — Accept-Encoding vs UA (v0.36.0) ([23bcc3c](https://github.com/datascry/kitsune/commit/23bcc3c0cb18fa99b31051e1e14981739ba30cdd))
* **detector:** IP-reputation producer — close the [#1](https://github.com/datascry/kitsune/issues/1) landscape gap (v0.48.0) ([d461b29](https://github.com/datascry/kitsune/commit/d461b29265568df17cd72c4fc3ee10b2276aa4c8))
* **detector:** keystroke-dynamics capture — close the last dead rule ([7019758](https://github.com/datascry/kitsune/commit/7019758ae19e00018c3593850633b2a86a62a44b))
* **detector:** Math float-precision engine coherence — a hard-to-spoof engine tell (v0.50.0) ([95cecb6](https://github.com/datascry/kitsune/commit/95cecb634ace0851c7f6a4e81db68140ae80b3e1))
* **detector:** more white-box Camoufox tells — dPR + adblock (v0.16.0) ([ac23bbc](https://github.com/datascry/kitsune/commit/ac23bbc4275a630782ed8c3ec5ee58cd120acd7e))
* **detector:** own-property lie detection for the PDF floor (v0.34.0) ([82d39b1](https://github.com/datascry/kitsune/commit/82d39b11ec8d50650b9f40de47cffa7899e39c2b))
* **detector:** post-quantum key-share coherence — catch stale impersonation templates (v0.44.0) ([662bc0f](https://github.com/datascry/kitsune/commit/662bc0f39221cb26c9ad03657c56cdf525c3c710))
* **detector:** QUIC post-quantum key-share tell — extend the QUIC layer (v0.54.0) ([05e0bf1](https://github.com/datascry/kitsune/commit/05e0bf122c4cc9cbb2d25bc75480db9122726129))
* **detector:** resistFingerprinting (Tor/Mullvad) detection — last evasion philosophy (v0.25.0) ([50bf209](https://github.com/datascry/kitsune/commit/50bf2098c2d7883f057dc1697df20990ebdd3164))
* **detector:** scripted/non-browser client detection — close the last recall gap (v0.22.0) ([f11ec67](https://github.com/datascry/kitsune/commit/f11ec6767b04034083c89a762524d37df3faa656))
* **detector:** Sec-CH-UA GREASE-brand integrity — catch hand-assembled client hints (v0.43.0) ([9693b17](https://github.com/datascry/kitsune/commit/9693b17365b24dfc0cfc85ead4f7603884a381ed))
* **detector:** Sec-CH-UA vs UA version coherence (v0.37.0) ([d5be411](https://github.com/datascry/kitsune/commit/d5be4111829b8980eeacb36b2e47a1b8e85c0ee1))
* **detector:** Sec-CH-UA-Mobile coherence — the form-factor client hint (v0.42.0) ([fbb9168](https://github.com/datascry/kitsune/commit/fbb9168b42872c523052de93c3593b0055310c34))
* **detector:** timezone-consistency detection (CreepJS timezone lie, v0.21.0) ([265f756](https://github.com/datascry/kitsune/commit/265f75630bd6c3685b2d5ea00dcfd81ab99a183d))
* **detector:** TLS GREASE coherence — first TLS-layer tell for the scripted tier (v0.41.0) ([a07732d](https://github.com/datascry/kitsune/commit/a07732d9405ec7f0f39f4224f792acf7849fa827))
* **detector:** two survey-mined browser detections — native-fn tampering + automation globals (v0.46.0) ([581a013](https://github.com/datascry/kitsune/commit/581a013ec28d3b16108e7170252e0041ada5997c))
* **detector:** v0.13.0 speech-voice coherence — cracks single Camoufox to bot ([c3d46a7](https://github.com/datascry/kitsune/commit/c3d46a72fda812b22c6df19abd87a07087afa7ca))
* **detector:** WebGL GPU-vs-platform coherence (v0.6.0) ([fceb790](https://github.com/datascry/kitsune/commit/fceb790fdafdd97af928af2d6b4a5f2e4e36f928))
* **detector:** WebGPU coherence — the emerging GPU fingerprint vector (v0.23.0) ([e46d281](https://github.com/datascry/kitsune/commit/e46d281bcc2d96dc0e738312c37f5ce7a4072e26))
* **detector:** WebGPU vendor coherence — the headful real-hardware frontier ([622337c](https://github.com/datascry/kitsune/commit/622337c26c8e46ed9adacdb7a28bac332500a13b))
* **detector:** WebRTC ICE probe — the network-identity frontier (v0.19.0) ([01e6b80](https://github.com/datascry/kitsune/commit/01e6b8079bd54e562f96c5a5691a2004d9c8ccea))
* **detector:** white-box source-driven detection — media devices + audio (v0.15.0) ([71bb2e9](https://github.com/datascry/kitsune/commit/71bb2e9ad07f5b9d48bb46ef11dc7bb48091e352))
* **detector:** wire the Runtime.enable CDP-leak detection (chromium frontier) ([3305046](https://github.com/datascry/kitsune/commit/33050461e6b599b95c35f6650216bf400f364ca2))
* **detector:** worker-vs-main divergence indicator (v0.8.0) + Camoufox finding ([ba60e4e](https://github.com/datascry/kitsune/commit/ba60e4ef44f1096dc83027d9e8b63774ce6f1d03))
* **edge,detector:** JA4 live network scoring with a real captured hint DB ([9263f33](https://github.com/datascry/kitsune/commit/9263f33b9d13e3afe0a614c8798f19d4a3bd051b))
* **edge:** cover the HTTP/2 DoS family — CONTINUATION + control-frame floods (v0.39.0) ([3bfcec4](https://github.com/datascry/kitsune/commit/3bfcec44314b2b8425771f5de43705b71d6ac6d7))
* **edge:** H2 frame scanner — the core for Rapid Reset (CVE-2023-44487) detection ([8688e55](https://github.com/datascry/kitsune/commit/8688e55bbd621fc90485de99a184c4fb9b392856))
* **edge:** HTTP-layer Sec-Fetch coherence — catch UA-faking scripted floods (v0.24.0) ([809d75b](https://github.com/datascry/kitsune/commit/809d75b88afbf44d2c4b751271bfee124dbade0e))
* **edge:** HTTP/2 fingerprint core (Akamai format) + engine classifier ([0f8f606](https://github.com/datascry/kitsune/commit/0f8f606b2489da8dc1fa2bc97ce1d936a1362b15))
* **edge:** HTTP/2 SETTINGS-profile coherence — catch a half-spoofed h2 stack (v0.28.0) ([d196680](https://github.com/datascry/kitsune/commit/d196680f1f641af881c3b6be0ea123652979fbce))
* **edge:** JA4 prefix matching classifies the Firefox/Camoufox TLS family ([fc087c0](https://github.com/datascry/kitsune/commit/fc087c08c8b4dd19b08feb062826d3828cc688f2))
* **edge:** live HTTP/2 preface fingerprinting — close the last layer gap (v0.27.0) ([b28a372](https://github.com/datascry/kitsune/commit/b28a3728ebcb15aca43ba94d7673efee54b8b315))
* **edge:** live pipeline — transparent TLS peek-proxy + vanilla evader + compose ([6e1ff31](https://github.com/datascry/kitsune/commit/6e1ff3128c6e476a4c0d17527e2fe208cc82a2f8))
* **edge:** live TCP/IP-stack OS fingerprinting — catch an OS spoof below TLS (v0.40.0) ([3306071](https://github.com/datascry/kitsune/commit/33060715bdca685f04ea57cc1044295fe805e97a))
* **edge:** QUIC capture producer — fingerprint live client Initials (core 2/2) ([a75a39d](https://github.com/datascry/kitsune/commit/a75a39dfb92e3d0ca49bb23f17a9626f7dd36eaa))
* **edge:** QUIC v1 Initial decryptor — the core for QUIC/HTTP-3 fingerprinting (core 1/2) ([99cf288](https://github.com/datascry/kitsune/commit/99cf2881321a30ac6746aa0548f55db1d7b15bf1))
* **edge:** self-signed cert covers the "edge" service name, not just localhost ([198a5f8](https://github.com/datascry/kitsune/commit/198a5f87e9f93ee5a8de39eb030557f313f0ab45))
* **edge:** SYN parser for TCP/IP fingerprinting (CVE-free OS tell) ([1dfd134](https://github.com/datascry/kitsune/commit/1dfd134f2e81e3202e62053a27799c36345ad66a))
* **edge:** TCP/IP OS-kernel classifier — foundation for stack fingerprinting ([329c0b4](https://github.com/datascry/kitsune/commit/329c0b4a74865f8e7f8ac5503fa9975a15219bfc))
* **edge:** wire H2 rapid-reset detection — attribute CVE-2023-44487 to a session (v0.38.0) ([3003245](https://github.com/datascry/kitsune/commit/300324585a91e78a4ce98fce3b2652d49ceb99f3))
* **edge:** wire QUIC fingerprinting into the edge + quic_no_grease rule (core 3/3, v0.52.0) ([2abe33f](https://github.com/datascry/kitsune/commit/2abe33f836f20bfa4298a8757021d1877e0160a4))
* **evaders,detector:** FLOOR_SPOOF red-teams the environment floor; close the gap ([10f0133](https://github.com/datascry/kitsune/commit/10f0133c0b898f94cb6b078377d948379404a387))
* **evaders:** add primp as a reproducible evader — the high-fidelity network impersonator ([1f93be8](https://github.com/datascry/kitsune/commit/1f93be8d5fd4d57064385592203d298fe01e5d8b))
* **evaders:** Camoufox evaluation — engine-level browser evades the whole ruleset (0/27) ([6c052df](https://github.com/datascry/kitsune/commit/6c052df42905f28ecff220a8da92f9d6f9904506))
* **evaders:** evaluate curl-impersonate — the TLS-mimicry frontier ([0de5a76](https://github.com/datascry/kitsune/commit/0de5a76d83432e2d3c42bd9e8f2c5424228af5f4))
* **evaders:** evaluate nodriver (CDP anti-detect) + generalize tool runner ([14e989d](https://github.com/datascry/kitsune/commit/14e989d7f08c539a77537257c928314ff6f3e974))
* **evaders:** evaluate patchright — defeats automation tells, not the headless env ([5b52382](https://github.com/datascry/kitsune/commit/5b5238287dfc165c67f63a1a99d2b2d61889ed51))
* **evaders:** evaluate pydoll — completes the open-source anti-detect survey ([fb1662d](https://github.com/datascry/kitsune/commit/fb1662d69837a06caa8ccb108d610cbca95ad5a0))
* **evaders:** evaluate rebrowser-patches (surgical Runtime.enable fix) ([400b790](https://github.com/datascry/kitsune/commit/400b790b02b6d37b64f80234d080a47b0a8b8320))
* **evaders:** evaluate selenium-driverless — adversarial test of the Runtime.enable rule ([5263aac](https://github.com/datascry/kitsune/commit/5263aac945ac5d23e76de635f03bd7d737a3387f))
* **evaders:** evaluate undetected-chromedriver — the most popular anti-detect tool ([8ae4057](https://github.com/datascry/kitsune/commit/8ae4057bc3cc68e6cb1c203ca8808635050f5eb1))
* **evaders:** evaluate zendriver — the maintained nodriver successor ([e239697](https://github.com/datascry/kitsune/commit/e239697291f3fa39cd0b187220725d5ddd18cf99))
* **evaders:** full-stealth mode — JS-injection battery evades most of v0.4.0 ([f189ea9](https://github.com/datascry/kitsune/commit/f189ea92ffeab26b6a5e3f9ce48c5749ae2d3bbe))
* **evaders:** go-tls evader forging Chrome/Firefox TLS via uTLS ([736fdea](https://github.com/datascry/kitsune/commit/736fdea9c5d7b7f83c862d4b910e4d8203b62d40))
* **evaders:** go-tls speaks HTTP/2 with faithful Chrome headers — and uTLS lags the PQ rollout ([4ccdf22](https://github.com/datascry/kitsune/commit/4ccdf22cc7f549b0e1f5fbeb926f722cc11557d2))
* **evaders:** hardened-Camoufox red-team (KS_HARDENED) — the arms race in action ([0082b06](https://github.com/datascry/kitsune/commit/0082b0670e0810e3c26448f49f6f8bb322023b9e))
* **evaders:** human-mouse behavioral evader — the behavioral layer is weakest ([8825c3c](https://github.com/datascry/kitsune/commit/8825c3c11743c624591817903a8685a2a11032d6))
* **evaders:** live claude -p browser agent — caught by the behavioral layer ([e2d8e8f](https://github.com/datascry/kitsune/commit/e2d8e8ff053794d85c42ed474de5e904e3535789))
* **evaders:** live stealth evader — real Chromium scored through the stack ([b85fea5](https://github.com/datascry/kitsune/commit/b85fea533399c63b42ae46e68fb681794b288f0a))
* **evaders:** live-validate H2 rapid-reset detection with a raw-framer flood ([ade15eb](https://github.com/datascry/kitsune/commit/ade15eb11e003e837752d7003550806d725d0741))
* **evaders:** max-stealth chromium capstone — maximal stealth hits the environment floor ([8efce74](https://github.com/datascry/kitsune/commit/8efce746315ae9dad9c4fe023107634bd97314ec))
* **evaders:** re-evaluate nodriver vs SOTA ruleset + fix collector timing ([41a5e04](https://github.com/datascry/kitsune/commit/41a5e04dd0a0a60f76051fa8c36e1e6e44b93085))
* **evaders:** scaffold Camoufox evaluation (engine-level anti-detect Firefox) ([8538a84](https://github.com/datascry/kitsune/commit/8538a8468ed37c6643eef52c80d2100857441830))
* **evaders:** spoof-ua mode — cross-layer incoherence caught live ([c400311](https://github.com/datascry/kitsune/commit/c4003111c0ae19f14b356299e4f8e676ccdb4a79))
* **harness:** add timing-lockstep + volume to coordination scoring ([e4fa0f7](https://github.com/datascry/kitsune/commit/e4fa0f774632ecd7d34c3771beec2114fffcf365))
* **harness:** Balabit loader + real-data calibration of the human movement envelope (behavioral 2-3/4) ([f632586](https://github.com/datascry/kitsune/commit/f632586a3e81766111fa7857ad6cbf75ed1ec751))
* **harness:** biomechanics feature extractor + behavioral-data curation plan (step 1/4) ([1bb4d09](https://github.com/datascry/kitsune/commit/1bb4d09aae832015d2ac81dda18a6be9eb142513))
* **harness:** coordination / fleet detection — the durable cross-session signal ([c776e2b](https://github.com/datascry/kitsune/commit/c776e2bc1f6eac8ba89278ea355cf7a456e784cf))
* **harness:** coverage-gaps view in the aggregator ([d7d7e8c](https://github.com/datascry/kitsune/commit/d7d7e8c6048089a46f98decf89ca9364e2f15b12))
* **harness:** fast-feedback corpus loop — re-score recorded sessions in ~0.2s ([1cbfd57](https://github.com/datascry/kitsune/commit/1cbfd576230a182064c56c4a6d3d541967e3b7b1))
* **harness:** fingerprint-collision coordination signal — catch cloned-profile fleets (BotBrowser) ([ec2e46d](https://github.com/datascry/kitsune/commit/ec2e46d8f0acb1cf6458ac2b77920e8b289c2ae6))
* **harness:** fleet key = JA4 only — catches a Camoufox fleet (the capstone) ([7a85e87](https://github.com/datascry/kitsune/commit/7a85e872ac45c3e8c4af4a14ee18b9af776c3392))
* **harness:** fleet threat-severity for DDoS triage (scale + rate) ([3515805](https://github.com/datascry/kitsune/commit/351580568c760d5d7706aecf446d0d77f047bff2))
* **harness:** frontier-focused testing + graded coordination scoring ([b07c708](https://github.com/datascry/kitsune/commit/b07c708384046672be7fde69660f1ecfb67f7c2f))
* **harness:** online coordination detector (FleetTracker) ([f7cb995](https://github.com/datascry/kitsune/commit/f7cb9958e753ae706044cc52ce09a2b2ab11a9ed))
* **harness:** residential-proxy fleet detection — the bots/DDoS frontier ([404be53](https://github.com/datascry/kitsune/commit/404be531147fc9c44281ba11959b3e8c62198984))
* **harness:** sliding-window aging for the online fleet detector ([eb774e7](https://github.com/datascry/kitsune/commit/eb774e770455524a57df350fd439fc3a7ab7a26e))
* **harness:** unified live scoreboard across the evader fleet ([ade023e](https://github.com/datascry/kitsune/commit/ade023e2a2d98ad014ecf91ff281834632135fce))
* **harness:** VirusTotal-style detection aggregator + coverage matrix ([c266897](https://github.com/datascry/kitsune/commit/c266897f433fa95fcff0357902827696c226f417))
* headful Camoufox evaluation + renderer-artifact counter (v0.14.0) ([bfddc72](https://github.com/datascry/kitsune/commit/bfddc7246851250879bc95d3a7f249aab2193470))
* ramp detection engine to 45 rules (v0.9.0+v0.10.0) + fix recapture abort ([50e9079](https://github.com/datascry/kitsune/commit/50e90795f5031ec7f47f5d63040b0108f861fe47))
* scaffold Kitsune bot-detection ⇄ evasion lab (spine + standards) ([eb7e6ef](https://github.com/datascry/kitsune/commit/eb7e6efc46da981170bbd9643c4eb0841278806b))
* v0.12.0 device/media rules + JA4_c fleet detection + faster capture + CI lint enforcement ([ad01e11](https://github.com/datascry/kitsune/commit/ad01e1116dd4afa996c91485085bad9e73e2fcb7))


### Bug Fixes

* **ci:** correct the license-isolation check and enforce it in CI ([d243aa8](https://github.com/datascry/kitsune/commit/d243aa8f799b3ea85e001c732d60f9a9ad736b29))
* **ci:** pin ossf/scorecard-action to v2.4.3 ([01e5f85](https://github.com/datascry/kitsune/commit/01e5f853d1e246c0431396e9e39493687c8e6b3d))
* **ci:** resolve formatting drift breaking main CI ([da8ecfa](https://github.com/datascry/kitsune/commit/da8ecfa37286d885493d1a669c556f88c088764b))
* **collector:** implement webdriverSpoofed — TS collector typecheck was broken ([0f8e918](https://github.com/datascry/kitsune/commit/0f8e91899bd88b2ee1df9464068f36dc04b09774))
* **collector:** stop the live page flagging every real browser as bot ([55290f4](https://github.com/datascry/kitsune/commit/55290f4ac7d6dcd00fb8ea7606c6f279d9e6f257))
* **contracts:** give every rule an explicit category; correct 3 mis-bucketed ones ([6431b33](https://github.com/datascry/kitsune/commit/6431b33d91c58def948dc52e2f6ab0c9a02fb148))
* **contracts:** mark the two producer-less rules experimental, not active ([7f9ab35](https://github.com/datascry/kitsune/commit/7f9ab3551cc0689bfce3a24f55adf0c908a0f043))
* **detector,edge:** merge signals per session so browsers capture all layers ([bfa7f1f](https://github.com/datascry/kitsune/commit/bfa7f1f9915d6b4883f786a3d73d793b3c0647e6))
* **detector:** 10-user calibration removes two FP-prone biomech rules (v0.51.0) ([b7b575e](https://github.com/datascry/kitsune/commit/b7b575e7355f49b448a27548d030411a65f3d1f0))
* **detector:** consolidate redundant native-tamper rule; add screen-impossible (v0.47.0) ([a5dc850](https://github.com/datascry/kitsune/commit/a5dc85028fcb411e1c0b473ef4497b822cc840bf))
* **detector:** precision pass 2 — VM/VDI false positive (webgl_software) ([a84b48b](https://github.com/datascry/kitsune/commit/a84b48b6cbafb6173d0d931b0ccc0bbbccd424c5))
* **edge:** SettingsBrowser recognises headless Chrome; live-validate H2 rules ([4858419](https://github.com/datascry/kitsune/commit/48584197c9aef7e0983e69b995ddf1ca45e7f770))
* **edge:** SettingsBrowser robust to push-deprecation; live-validate Camoufox h2 ([b94d31f](https://github.com/datascry/kitsune/commit/b94d31f00dd03067c688273b5172a8444cc76842))
* **repo:** give the detector healthcheck a start_period for cold-start uv sync ([264e9aa](https://github.com/datascry/kitsune/commit/264e9aa069f279d098c0958ecd0697c1a99287f9))


### Performance Improvements

* **harness:** faster live runs + render the detection matrix ([3672ba0](https://github.com/datascry/kitsune/commit/3672ba0379bd798832e2a34b0b97d447dab073ab))

## [Unreleased]

### Added

- **Canvas-farbling detection + Brave evaluated** (ruleset 0.26.0) — `br.canvas_noise` covers the last
  anti-fingerprinting *philosophy* (farbling: per-session canvas/audio noise). It is **reference-free**:
  fill a canvas with a solid colour and read it back — a real browser returns the exact colour, a
  farbling browser perturbs pixels. Validated live by building a **Brave** evader (the last major
  browser): Brave trips `canvas_noise` (its canvas farbling), while stealth/camoufox read the fill back
  exactly (no false positive). `audio_noise` does not fire on Brave — its audio farbling is per-session
  *deterministic*, so the canvas invariant is what exposes it. Weight 0.5 (`suspicious`): a human on Brave
  is a privacy-tool signal (elevated risk), not a bot conviction. **All five evasion philosophies are now
  covered with validated detections** (coherent-spoof, CDP-stealth, scripted/no-JS, RFP, farbling).
- **resistFingerprinting (Tor/Mullvad) detection** (ruleset 0.25.0) — `br.rfp_browser`, covering the last
  anti-fingerprinting *philosophy* (RFP evades by making all users identical, the opposite of Camoufox's
  coherent uniqueness). From the Tor design doc: RFP forces UTC, letterboxes the window to 200×100
  multiples, and clamps `hardwareConcurrency` to 2. Each trait alone is common (a UK user, a round window,
  a 2-core VM), so the collector requires the **conjunction** — confirmed no false positive on real
  evaders (their windows aren't letterboxed). Calibrated as `suspicious` (weight 0.4), *not* a `bot`
  conviction: RFP identifies a privacy browser = elevated risk, and Tor users are often human — it
  corroborates with automation/coordination rather than convicting alone.
- **undetected-chromedriver evaluated** — the most popular anti-detect tool (only its successor nodriver
  had been tested). **Finding:** UC has evolved to defeat the SOTA `Runtime.enable` leak
  (`cdp_runtime_enabled` does not fire) and patches `navigator.webdriver` — so the *entire* popular tool
  ecosystem (UC, nodriver, patchright, rebrowser) has converged on closing the CDP-automation tells; only
  naive plain Playwright still trips `Runtime.enable` (3 corpus evaders). UC's profile mirrors nodriver
  exactly (`automation:2`, `environment:3`) and it stays `bot` 0.999 on the headless-environment floor
  (`webgl_software`, `voices_empty`, `media_devices_empty`, `headless_ua`, `chrome_runtime_missing`).
  New `undetected` evader + corpus session.
- **HTTP-layer Sec-Fetch coherence** (ruleset 0.24.0) — `net.sec_fetch_vs_ua`: every modern browser sends
  `Sec-Fetch-Site`/`Sec-Fetch-Mode` on requests, but a scripted HTTP client faking a browser UA over
  httpx/curl (the volumetric-DDoS case) omits them. The edge emits `network.sec_fetch_missing` when a
  browser-claiming UA lacks the headers — a tell on the *HTTP* layer, independent of TLS and JS. Added a
  `KS_UA` mode to the vanilla evader to validate: vanilla faking a Chrome UA now scores `bot` on *both*
  `net.no_js_execution` and `net.sec_fetch_vs_ua`; real Chromium (which sends Sec-Fetch) does not trip it.
- **Engine error-message coherence** (ruleset 0.24.0) — `br.error_engine_vs_ua`, the deepest engine tell.
  V8/SpiderMonkey/JSC produce distinct `TypeError` messages for the same fault (V8 "Cannot read
  properties of…", SpiderMonkey "can't access property…", JSC "… is not an object"). The engine's *own
  message generator* is far harder to spoof than `navigator.vendor` or `Error.captureStackTrace`.
  **Validated:** fires on `spoof-ua` (V8 engine + Firefox UA) but not on `stealth-naive` (V8 + Chrome UA)
  or `camoufox` (real SpiderMonkey + Firefox UA) — engine-spoofers caught, real browsers cleared.
- **WebGPU coherence** (ruleset 0.23.0) — `br.webgpu_webgl_vs`, the emerging GPU fingerprint vector
  (2024-25). Explored reality-first: headless Chromium has `navigator.gpu` but no adapter; Firefox/Camoufox
  lack WebGPU entirely — both too common to flag alone. The clean tell is cross-vector: a WebGL renderer
  claiming a *hardware* GPU while WebGPU exposes *no real adapter* means the renderer was spoofed (a real
  GPU drives both). **Validated:** fires on `full-stealth` (fakes its WebGL renderer to "NVIDIA RTX 3060"
  while headless) but not on `stealth-naive` (honest SwiftShader) or VM/VDI (honest software WebGL) — it
  catches the spoof below the WebGL layer with no false positive. Its headful counterpart
  `br.webgpu_vendor_vs_webgl` covers the real-hardware case: a real GPU's WebGPU adapter family must match
  the WebGL renderer, so a faked renderer on real hardware is exposed by the WebGPU vendor — the detection
  for the frontier headful-real-hardware spoofer (unit-tested; needs a GPU-equipped target to fire live).
- **Scripted / non-browser client detection** (ruleset 0.22.0) — `net.no_js_execution`: a session with a
  network/TLS fingerprint but an *empty browser layer* loaded the challenge page yet never executed the JS
  collector — a scripted HTTP client (httpx/curl), the volumetric-DDoS majority. Emitted as a score-time
  derived cross-layer signal (`network.browser_absent`, not persisted), so the registry rule and the
  incoherence amplifier handle it like any other tell. **Closes the last recall gap:** `vanilla` (httpx),
  which previously scored `human`, now scores `bot` 0.90. Humans are unaffected (they have a browser
  layer) — every evader is now `bot`, every human `human`.
- **Deep engine-API coherence** (ruleset 0.21.0) — `br.engine_stack_vs_ua`: `Error.captureStackTrace` is
  a V8 (Chromium) API absent in Firefox/Safari, so a UA claiming Chrome without it — or Firefox *with* it
  — is an engine spoof deeper than `navigator.vendor` (which JS-stealth patches, while the `Error` API it
  often misses). **Validated both ways:** fires on `spoof-ua` (Chromium engine + Firefox UA), does not
  trip real Chromium or Firefox. Near-zero false positives.
- **Timezone-consistency detection** (ruleset 0.21.0) — `br.timezone_inconsistent` (CreepJS "timezone
  lie"): a real browser derives both the IANA `timeZone` and the numeric `getTimezoneOffset()` from the
  OS, so they always agree; a spoof that sets one but not the other (or forces UTC over a real offset) is
  self-inconsistent. A coherence tell with near-zero false-positive surface — confirmed live that real
  browser engines (Camoufox, Playwright Chromium) do not trip it. Catches naive timezone spoofers.
- **Precision suite — legitimate humans must not be flagged** (`tests/test_precision.py`). A panel of
  fully-coherent human profiles (Win/Mac/Linux × Chrome/Firefox, plus a touch laptop and an
  external-monitor Mac) must all score `human`. It surfaced two real false positives that recall testing
  never would.

### Changed

- **False-positive mitigations** (from the precision suite). Retired `br.maxtouch_desktop` — it flagged
  ordinary Windows 2-in-1 touch laptops, and the sound `br.pointer_touch_incoherent` (CSS-vs-JS touch
  disagreement) supersedes it. Cut `br.macos_dpr1` 0.4 → 0.3 (desktop Mac on a 1080p external monitor) and
  `br.webgl_software` 0.6 → 0.3 (corporate VM/VDI software rendering) below the suspicious threshold, so
  neither flags a human alone — both now only corroborate inside a cluster of tells. The emergent rule:
  *environment tells must corroborate, not convict* (each has an innocent lone explanation; the combination
  is decisive). Recall unaffected — every evader still scores `bot` (Camoufox 0.99, all chromium 1.00).

### Added (continued)

- **Online coordination detector (`FleetTracker`).** Streaming fleet detection: `observe(name, session)`
  ingests sessions one at a time (arrival order), re-scores only the affected JA4-prefix cluster, and
  returns a verdict exactly when a cluster *newly* crosses the `fleet` threshold or escalates severity —
  edge-triggered, alerting once rather than on every confirming member. This is how a production bots/DDoS
  detector works (incremental clustering + threshold alerting) versus the offline `score_corpus` snapshot.
  `replay_stream` / `render_stream` (and `--stream`) replay a corpus in `first_seen` order; on the
  residential-proxy fleet it alerts on the second arrival — the instant the paradox is observable.
- **Sliding-window aging** (`FleetTracker(window_seconds=W)`) — count only cluster members within `W`
  seconds of the latest arrival, ageing out the rest: detect a *burst*, not slow accumulation of unrelated
  same-browser users into a false fleet. Two paradox nodes 10s apart alert; the same two 10 minutes apart
  never coexist and do not. State resets when a burst ages out, so a fresh burst re-alerts. 100% covered.
- **Fleet threat-severity (DDoS triage).** The coordination verdict now reports `request_volume`,
  `arrival_rate_per_min`, and a `severity` tier (`moderate`/`high`/`critical`) derived from scale and
  rate — *separate* from the confidence `score` (a confirmed fleet maxes the score whether it is 3 nodes
  or 3,000; severity distinguishes a curiosity from an active attack). Surfaced in the rendered report.
- **Residential-proxy fleet detection (coordination, the bots/DDoS frontier).** Two IP-topology signals
  in `harness/coordination.py`: (1) *residential-proxy pattern* — a confirmed spoofing fleet (JS paradox
  or JA4_c divergence) also spread across many distinct `observed_ip` values, so the IP diversity that
  defeats per-IP/ASN rules instead reveals a distributed botnet; (2) *same-origin behind proxies* —
  diverse proxy IPs but one shared `webrtc_public_ip`, cross-linking the WebRTC signal with the fleet
  view. A synthetic residential-proxy Camoufox fleet (distinct exit IPs, one real origin) scores `fleet`
  1.00 on all six coordination signals (`docs/coordination-proxy.md`). 100% covered.
- **Keystroke-dynamics capture — last dead rule closed.** A signal-emission audit found one rule whose
  signal the collector never produced: `bh.keystroke_entropy_floor` (read `behavioral.keystroke_entropy`).
  The collector now captures keydown timing and emits the normalized inter-key interval entropy, and the
  stealth evader types a phrase to exercise it. **Result:** unlike the mouse thresholds, this one bites —
  naive fixed-delay typing collapses to ~0 entropy and **fires** (`stealth-naive` `behavioral:1`), while
  variable human-like timing (0.975 vs the 0.15 floor) evades. **Every rule's signal is now emittable —
  zero dead rules.**
- **Max-stealth chromium evader (`MAX_STEALTH=1`)** — the kitchen sink (patchright + a coherent
  Linux-Chrome UA + human-mouse motion), the chromium analog of `camoufox-hardened`. Every evasion layer
  works (UA removes `headless_ua`, human-mouse zeroes behavioral, patchright closes `Runtime.enable` +
  `webdriver`), yet it is still `bot` on the environment floor (`automation:4` + `environment:6`). The
  capstone: maximal stealth on *both* engines converges on the headless environment as the irreducible
  floor, with coordination beneath it — documented in `docs/findings.md`.
- **HTTP/2 fingerprint core** (`edge/internal/fingerprint/h2.go`) — the Akamai-style h2 fingerprint
  (`SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header-order`) plus an engine classifier keyed on the
  version-stable pseudo-header order (Chromium `m,a,s,p`, Firefox `m,p,a,s`, Safari `m,s,p,a`), and a
  `signal.FromH2` emitter for `h2` + `h2_browser_hint`. Go unit-tested with documented real-browser
  fingerprints. The detector's `net.h2_vs_ua_browser` / `net.h2_vs_tls_browser` coherence rules already
  consume `h2_browser_hint`, so the detection is ready; live capture needs the edge to sniff H2 frames
  post-TLS (a multi-turn change — H2 is currently disabled on the edge so the ClientHello ConnContext
  reaches handlers). This lands the tested fingerprint core ahead of that wiring.
- **Human-mouse behavioral evader (`HUMAN_MOUSE=1`)** — synthesizes realistic motion (Bézier curve,
  ease-in-out velocity, micro-jitter, variable inter-event timing) to red-team the behavioral layer.
  Finding: the motion thresholds (`path_too_straight`, `uniform_velocity`, `input_entropy_floor`) catch
  only *degenerate* input — even the naive sine-wave path already clears them; the human generator clears
  them wider (entropy 0.87, straightness 0.29, velocity CV 1.01). Behavioral is trivially evaded and is
  the first layer to fall — the `human-mouse` evader zeroes the behavioral column yet is still `bot` on
  automation + environment. Reinforces that the durable signals are environment and coordination.
- **nodriver re-evaluated against the full ruleset** — its "minimal CDP footprint" claim **holds against
  the SOTA detection**: it trips neither `cdp_runtime_enabled` (`Runtime.enable`) nor `webdriver`
  (`automation:2`, the lowest of all CDP tools), yet is still `bot` on the environment floor plus a
  `HeadlessChrome` UA and missing `window.chrome.runtime`. Completes the CDP-tool gradient
  (plain 6 → rebrowser 5 → patchright 4 → nodriver 2 automation tells).

### Fixed

- **Collector timing regression** — the v0.19 WebRTC probe (1500ms) plus the audio/enumerate probes had
  pushed the collector's send past short fixed-wait evaders (nodriver's 3s), yielding empty captures. Cut
  the WebRTC gather window to 700ms (local candidates arrive in ~200ms; STUN does not resolve in the lab
  anyway) and gave nodriver a 4s margin. Camoufox's `webrtc_unavailable` is unaffected (it blocks WebRTC
  outright, so no candidates regardless of the window).

### Added (continued)

- **Cross-layer network-identity rule** (ruleset 0.20.0) — `net.webrtc_ip_vs_observed`: the edge now emits
  the observed connection IP (`network.observed_ip`), and the rule fires when it disagrees with the
  WebRTC STUN public IP the collector reported (`browser.webrtc_public_ip`) — the canonical proxied-bot
  tell (HTTP via a residential proxy, real IP leaked over WebRTC), central to bots/DDoS. This is the first
  rule correlating a signal the *edge* observed at the network layer with one the *browser* reported — the
  cross-layer thesis in its purest form. Needs a real proxy scenario to trigger live; unit-tested both
  ways (fires on mismatch, not on a direct connection). Edge change covered by Go tests.
- **Hardened-Camoufox evader (`KS_HARDENED=1`)** — red-teams the detector with its own findings: applies
  Camoufox config (`os="windows"` to drop the macOS-only tells, `block_webrtc=False`) to fix the
  spoof-specific tells Kitsune discovered, and measures what survives. Result: hardening cuts Camoufox's
  spoof-specific catches from three to one (Windows pin removes `macos_dpr1` + `font_mac_internal`), but
  it stays `bot` 0.93. Two tells are **not config-fixable**: `webgl_renderer_artifact` (every renderer in
  Camoufox's `webgl_data.db` carries the `", or similar"` suffix — baked into the shipped data) and
  `webrtc_unavailable` (`block_webrtc=False` did not restore it). New `camoufox-hardened` corpus session.
- **WebRTC ICE probe** (ruleset 0.19.0) — the missing network-identity vector (central to bots/DDoS).
  `br.webrtc_unavailable` (artifact): a real browser always gathers ICE candidates; **Camoufox disables
  WebRTC** to prevent the IP leak — confirmed live, it fires on Camoufox but NOT on stock headless Firefox
  (which keeps WebRTC in the same container), so it is a spoof tell, not a headless one, and it survives a
  headful deployment. A macOS-draw Camoufox now has three spoof-specific catches (`macos_dpr1` +
  `font_mac_internal` + `webrtc_unavailable`) independent of the environment floor. The STUN-reflexive
  public IP (`webrtc_public_ip`) is also collected, for future cross-layer correlation against the request
  IP (the proxied-bot tell) — leaving the evader a no-win: keep WebRTC and leak the real IP, or disable it
  and trip this rule.
- **`rebrowser-patches` evaluated** — added a `REBROWSER=1` mode to the stealth evader
  (`rebrowser-playwright@1.48.2`). Result: it closes exactly the `Runtime.enable` leak (so
  `br.cdp_runtime_enabled` correctly does not fire — validating both the rule and rebrowser's claim) but
  leaves `webdriver` / headless-UA / `window.chrome` unpatched. The three CDP tools now form a measured
  gradient of automation-tell coverage (plain 6 → rebrowser 5 → patchright 4), all still `bot` on the
  headless `environment` floor. New `rebrowser` corpus session and `docs/findings.md` comparison.
- **`Runtime.enable` CDP-leak detection wired** — the `br.cdp_runtime_enabled` rule existed but the
  collector never emitted its signal (a gap). Implemented the detection (log an `Error` with a `stack`
  getter that fires only when a CDP client serializes it — the current #1 headless-Chromium tell, 2024-25
  research). Validated: plain Playwright (`stealth-naive`) fires it; `patchright` (which patches
  `Runtime.enable`) does not — the detector now *quantifies* patchright's CDP patches (`automation:6` vs
  `4`), though both remain caught by the headless `environment` tells. Fixed the `stealth`/`patchright`
  evader image (unpinned patchright pulled a Chromium-revision mismatch; now installs the matching browser).
- **Codec-support coherence** (ruleset 0.18.0, experimental) — `br.codec_os_incoherent`: from the
  Camoufox cast map, `audioCodecs`/`videoCodecs` are unspoofed, so a non-Linux UA that cannot play
  proprietary H.264/AAC (codecs a real Windows/macOS has via the OS) would betray the real container.
  **Did not fire** on this Camoufox — the Playwright base image bundles the codecs, so its support is
  coherent. Kept as coverage of a known detection class (catches a codec-less Linux deployment).
- **Font construction-artifact detection** (ruleset 0.17.0) — from Camoufox's `fonts.json` (its fixed
  per-OS font lists). `br.font_mac_internal` (artifact): Camoufox bundles 49 dot-prefixed macOS system
  fonts (`.Aqua Kana`, …) and exposes them to `measureText`, which a real Mac never does — **confirmed
  live** on its macOS draws; works headful (no display needed). With `macos_dpr1` a macOS-draw Camoufox
  now has two spoof-specific catches independent of the headless-environment tells (`bot` 0.976).
  `br.font_linux_leak` (coherence, experimental): Arimo/Cousine/Tinos under a non-Linux UA — did not fire
  (Camoufox's font spoofing is complete) but still catches naive non-font-spoofing tools.
- **Detection-class taxonomy + no-spoof baseline control.** Added a `category` to every rule (and to each
  verdict `Contradiction`): `coherence` / `artifact` (genuine anti-detect catches) vs `environment` /
  `automation` / `behavioral` / `reputation`. Validated it against a **control group** — stock Playwright
  Firefox (`KS_BASELINE=1`, Camoufox's engine with no spoofing) through the same pipeline: it fires only
  `automation` + `environment` tells (zero coherence), proving those are headless-environment signals, not
  spoofing detection. Camoufox additionally trips `coherence`/`artifact` tells — the real catches. New
  `report.render_categories` view (in `docs/matrix.md`), `camoufox`/`baseline-firefox` corpus sessions,
  and a `docs/findings.md` section. Contracts (`coherence-rule`, `verdict`) gain the optional `category`.
- **More white-box, source-driven detection** (ruleset 0.16.0) — continuing to read the `camoufox`
  source. `br.macos_dpr1`: Camoufox pins `devicePixelRatio` to 1.0 (its cast map: "any value other than
  1.0 is suspicious") but a modern Mac is Retina (dPR 2) — **confirmed live**, fires on exactly the
  launches where Camoufox draws macOS, not Windows. `br.adblock_present` (experimental): Camoufox bundles
  uBlock Origin as a default addon (`addons.py`/`utils.py`), detected via an ad-bait element — weak alone
  (humans run adblockers) and not validated in our short sessions, but a documented default.
- **White-box, source-driven detection** (ruleset 0.15.0) — read the open-source `camoufox` package to
  drive detections precisely instead of black-box probing. From `browserforge.yml` (its spoof cast map):
  `multimediaDevices` is unsupported → `br.media_devices_empty` (enumerateDevices() empty in a container;
  a real desktop always has a default audio endpoint) — **fires on both headless and headful Camoufox**,
  raising them to `bot` 0.86 / 0.955. From the same source: Camoufox does not farble audio, so
  `br.audio_noise` (per-render AudioContext perturbation) is reserved for farbling browsers; `br.audio_missing`
  flags a stripped audio stack. Confirmed `webgl_data.db` stores every renderer with a `", or similar"`
  suffix, so `br.webgl_renderer_artifact` catches every Camoufox WebGL fingerprint by construction.
- **Headful Camoufox evaluation + renderer-artifact counter** (ruleset 0.14.0) — added a headful mode to
  the Camoufox evader (`KS_HEADFUL=1` → virtual Xvfb display) to test whether the per-session capability
  tells are real spoofing flaws or headless-container artifacts. **Finding:** headful Camoufox gains a
  software WebGL2 context (so `webgl2_missing` closes — it *was* a headless artifact) but its spoofed
  renderer string is the placeholder `"Intel(R) HD Graphics 400, or similar"`. New rule
  `br.webgl_renderer_artifact` catches that implementation flaw in Camoufox's own WebGL spoofer; headful
  Camoufox is caught at `bot` 0.90 (renderer artifact + `voices_empty`, which persists headful). New
  tracked corpus session `camoufox-headful`.
- **Speech-synthesis voice coherence** (ruleset 0.13.0) — `br.voices_empty` (no TTS voices: a headless
  container has no speech stack, a real desktop ships OS voices) and `br.voice_os_vs_ua` (voice set
  implies an OS contradicting the UA platform). **Result:** cracks a single coherent Camoufox instance —
  it returns zero voices, so combined with `webgl2_missing` the per-session verdict rises from
  `suspicious` 0.40 to **`bot` 0.70**. The engine-level spoof that once evaded every per-session rule is
  now caught per-session, via OS *capabilities* (GPU, TTS) a container cannot fake.
- **Cross-API device/media coherence** (ruleset 0.12.0) — five CreepJS/fingerprintjs rules comparing the
  CSS `matchMedia` view of the device against the JS-API view: `br.screen_avail_invalid`,
  `br.color_depth_anomaly`, `br.devicepixelratio_anomaly`, `br.hover_none_desktop`,
  `br.pointer_touch_incoherent`. Catch tools that patch one surface but not both. **Finding:** Camoufox
  keeps both views coherent, so it is not caught by these (documented in `docs/findings.md`).
- **JA4_c coordination signal** — the fleet detector now keys on the JA4 *cipher-suite prefix* (JA4_a +
  JA4_b) and grades **JA4_c (extensions/sig-alg) divergence** as a coordination tell. **Finding:**
  Camoufox randomizes JA4_c per launch, so the full JA4 is not fleet-stable — but since JA4 sorts
  extensions to defeat order-shuffling, a varying JA4_c betrays per-launch TLS manipulation. The live
  Camoufox fleet is now caught (`fleet`) via JA4_c divergence even when its JS traits collide by chance.
- **Faster single-Camoufox capture** — `KS_FAST=1` (event-driven, behavioral layer omitted so skipped
  input isn't mis-scored) and `KS_REPEAT=N` (N captures from one browser launch, amortizing the ~10s
  cold-start). The corpus fast-rescore (~0.3s, no browser) remains the path for rule-only changes.

### Fixed

- **CI lint enforcement** — the `harness` CI job was missing `ruff format --check` (the `detector` job
  had it), so harness format drift went uncaught; added it. Bumped both Python components' ruff
  `line-length` to 120 (matching the established style, incl. the mandated 2-line headers) and brought
  detector + harness fully green on `ruff check`, `ruff format`, and `mypy`. demo.py (embedded JS/HTML
  template) carries a scoped `E501` per-file-ignore.

### Added (continued)

- **Coordination scoring** (`harness/coordination.py`) — grades a JA4 cluster into a graded fleet
  verdict (`fleet`/`candidate`/`benign`) on three independent signals: the **TLS-identical-but-JS-
  divergent paradox** (a real same-build cohort shares its JS identity too, but an anti-detect fleet
  randomizes JS per instance while sharing one TLS handshake), **timing lockstep** (members arriving
  within a 2-minute window are synchronized, unlike organic same-JA4 users), and **volume**. Live
  Camoufox fleet scores `fleet` 1.00. 100% covered.
- **Frontier runner** (`scripts/frontier.sh`) — fast, frontier-only loop that exercises *only* the
  evaders that still beat per-session detection (Camoufox single + a Camoufox fleet), instead of
  re-detecting the known-caught fleet every iteration. The full sweep (`live_scoreboard.sh`) becomes
  the sparse regression tier.

- **Font-OS fingerprint** (`br.font_os_vs_ua`, ruleset 0.11.0) — the collector classifies the host OS
  from OS-signature font availability (Segoe UI/Calibri → Windows, Menlo → macOS, DejaVu → Linux) and
  flags it against the claimed UA platform. Catches chromium tools that spoof the UA but not the host
  font stack. **Finding:** Camoufox spoofs Canvas font metrics at the engine level, so it defeats this
  probe (the measured font OS coherently matches its claimed OS) — documented in `docs/findings.md`.
- **`docs/findings.md`** — empirical arms-race ladder: what each anti-detect tool leaks, why Camoufox is
  the per-session frontier, and why coordination is the durable bots/DDoS signal.

### Changed

- **Frontier crack** — `br.webgl2_missing` (v0.10.0) now flags live single-instance Camoufox
  (`suspicious` 0.40): headless Camoufox exposes no WebGL2 context where real Firefox does. The
  engine-level anti-detect browser that previously evaded all per-session rules now leaks one.
- **`liveboard`** — a crashed/empty evader output file is skipped instead of aborting the whole
  scoreboard render (was a `json.loads("")` fatal).

### Added (earlier)

- **Architecture & contracts.** Session-correlation design (`docs/architecture.md`) and the
  language-agnostic JSON-Schema contracts (`Signal`/`Session`/`Verdict`/`CoherenceRule`) plus the
  initial 10-rule coherence registry.
- **detector** (Python) — session correlation, the data-driven coherence engine, transparent
  noisy-or scoring with cross-layer amplification, SQLite store, and a FastAPI `/ingest` boundary.
  100% test coverage.
- **harness** (Python) — scenario runner + reproducible per-layer scoreboard (Markdown/JSON) with
  the ethics allow-list enforced in code. 100% test coverage.
- **edge** (Go) — raw ClientHello parser → JA3/JA4, session correlation, and signal forwarding.
- **collector** (TypeScript) — in-browser fingerprint + behavioral signal collection over an
  abstracted `BrowserEnv`. 100% test coverage of the pure logic.
- **Repo standards** — 2-line machine-scannable file headers (enforced), MADR ADRs, security
  posture (SECURITY.md, gitleaks, pinned actions, SBOM), supply-chain (Dependabot, license gate),
  community templates, and conventional-commit linting.
- **Live pipeline** — transparent TLS peek-proxy in the edge (captures the raw ClientHello, mints
  `ks_sid`, forwards JA3/JA4 signals), a real `vanilla` evader, and `docker-compose` wiring
  detector + edge + vanilla. Verified end-to-end (`session_id` threads socket → verdict).
- **`go-tls` evader** — uTLS-based Chrome/Firefox TLS fingerprint forging.
- **JA4 live network scoring** — detector `GET /session/{id}` to inspect captured signals; the edge's
  JA4 hint DB seeded with **real captured fingerprints** (go-tls Chrome, httpx), so the network layer
  recognises clients live (`ja4_browser_hint`/`ja4_os_hint` populate). (Browser-session network
  capture through the peek-proxy is a known follow-up — see `edge/README.md`.)
- **`stealth` evader (live)** — drives a real Chromium through the edge via Playwright (in the
  Playwright Docker image); the detector serves an in-page collector. Verified red-vs-blue result:
  naive automation scores `bot` (0.985, webdriver + headless tells), the stealth variant scores
  `human`.
- **`agent` evader (live)** — LLM-driven browser agent using `claude -p` as the reasoning engine
  (brain on host, Chromium in the Playwright container over CDP). Verified result: the agent beats
  the network + browser/fingerprint layers but is caught by the **behavioral** layer
  (`bot`, 0.80) — the thesis, demonstrated.
- **Coherence registry v0.2.0 → v0.3.0** — added HTTP/2-vs-TLS, headless-UA, keystroke-entropy, and
  proxy/Tor-exit rules (v0.2.0); then **deeper behavioral shape features** — mouse-path straightness
  and velocity coefficient-of-variation (collector + live demo page) with `bh.path_too_straight` and
  `bh.uniform_velocity` rules (v0.3.0), the start of the real behavioral frontier.
- **Cross-layer incoherence, demonstrated live** — a `spoof-ua` evader (real Chrome TLS + a lying
  Firefox UA) passes every single-layer check yet is caught solely by `net.tls_vs_ua_browser`
  (network 0.70 · browser 0.70 · incoherence 0.70 · bot). The thesis, proven with a real browser.
- **Unified live scoreboard** — `harness.live`/`liveboard` fold every evader's live verdict into one
  dated board; `scripts/live_scoreboard.sh` runs the whole fleet against the running stack and writes
  `docs/scoreboard.md` (vanilla → stealth → agent in one table).
- **docs/catalog.md** — opinionated catalog of ~70 relevant projects across the arms race.

[Unreleased]: https://github.com/datascry/kitsune/commits/main
