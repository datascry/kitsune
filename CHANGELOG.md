# Changelog

All notable changes to Kitsune are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut automatically from
[Conventional Commits](https://www.conventionalcommits.org/) via release-please.

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
