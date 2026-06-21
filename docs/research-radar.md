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
| G4 | network (JA4+) | **JA4+ suite coverage audit.** | uTLS/curl-impersonate pin JA4; JA4T harder (real stack) | FoxIO JA4 (github.com/FoxIO-LLC/ja4), JA4T blog (blog.foxio.io/ja4t-tcp-fingerprinting) | **covered** — JA4 (ja4a/b/c) + JA4H (`net.h2_header_order_vs_ua`) present; JA4T's detection value = TCP-OS coherence (`tcp_kernel` SYN fp + `net.tcp_os_vs_ua`); JA4L (latency/hop-distance) marginal for bot-detection + latency-external; JA4S is server-side (N/A for a client detector). No groundable gap. |

## External-data-bound leads (queue — need real data the lab can't self-generate)

> **Turnkey path built:** `docs/grounding.md` + `task grounding -- <captures>` runs the full grounding
> sweep (per-session FP/recall + coordination + prevalence-prior rebuild) the moment an operator supplies
> real captures. Each X-item below maps to a capture + command in that runbook.


| # | seam | technique / signal | real data needed | source | status |
|---|---|---|---|---|---|
| X1 | proxy/tunnel | **Encapsulated-TLS-handshake fingerprinting** — fully passive; detects ALL proxy/tunnel stacks (shadowsocks/vmess/trojan/vless/httpt, TPR >70%) from nested-handshake size/timing/**direction**; padding doesn't defeat it (falls back to order+direction). | real proxy egress + large-scale ISP traffic (paper: 110M flows, TCP-only deployed) | Xue et al., **USENIX Sec 2024** (ensa.fi/papers/sec24-xue.pdf) | **external** — order/direction *insight* is mineable; QUIC/MASQUE transfer is an open question |
| X2 | residential proxy | **RESIP relayed/tunnel-flow classifier** — transformer, first 5 packets, payload-free: relayed 93%/93%, tunnel 91%/96%. | real RESIP node deployment + wild egress (3TB / 116M flows) | Huang et al., arXiv 2404.10610 (USTC+IU 2024) | **external** — the IP-reputation/proxy half Kitsune already flags as blocked |
| X3 | IP reputation | **CGNAT detection** to bound the `ip_rotation_within_session` confound + RESIP collateral. | real CGNAT/residential traffic | Cloudflare (blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage) | **external** — refines the documented CGNAT FP caveat |
| X4 | prevalence | **Real-traffic prevalence/IP-reputation prior** (the recurring Tier-3 gap). | hosted-demo opt-in / real-device matrix / real traffic | Resident Evil (RESIP study); Kitsune `build_prior_from_sessions` | **external** — the grounding-harness unlock |
| X5 | coherence (spatial) | **Device-model ↔ screen-geometry coherence** — the DB-dependent half of G1 (an iPhone-15 UA with a resolution no iPhone-15 ships). Needs a real (device → screen res/DPR) mapping to be FP-safe; a hand-coded threshold FPs on foldables/edge devices. | real-device fingerprint DB (the FP-Inconsistent dataset is honey-site-derived, not released) | FP-Inconsistent, ACM IMC 2025 | **external** — split from G1 (the DB-free `mobile_no_touch` shipped) |

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
