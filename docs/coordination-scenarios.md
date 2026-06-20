# Coordination scenarios — precision/recall of the fleet detector

- **precision: 100%** (no legitimate cohort labelled `fleet`)
- **recall: 100%** (every fleet shape caught)

| scenario | expected | label | ✓ | why |
|---|---|---|---|---|
| `legit-corporate-fleet` | not-fleet | `candidate` | ✓ | a STANDARDIZED corporate fleet: identical laptop model + locked image hashes byte-identically, on distinct WFH residential IPs, with DISTINCT human traces and NO automation tell — fp collides but the cohort is real; must cap at candidate, not `fleet` (the fp-collision-vs-corporate FP) |
| `legit-diverse-cohort` | not-fleet | `candidate` | ✓ | distinct real users on one Chrome build: diverse hw/OS, distinct IPs+fps+traces, spread timing |
| `legit-homogeneous-pair` | not-fleet | `candidate` | ✓ | two users, identical JS (same build+config) but distinct fps/traces — a benign same-build pair |
| `legit-large-cohort` | not-fleet | `candidate` | ✓ | 8 distinct users on one build — paradox + IP spread at scale must still not convict |
| `legit-multi-version-cohort` | not-fleet | `candidate` | ✓ | real Chrome users spanning auto-update versions: ONE cipher prefix but a few distinct JA4_c (JA4_c varies across Chrome versions), distinct IPs + fps + traces, NO automation — diverges JA4_c but is a real cohort; must cap at candidate, not `fleet` (the JA4_c-randomizer-vs-multi-version FP) |
| `legit-nat-cohort` | not-fleet | `candidate` | ✓ | 5 distinct users behind ONE NAT IP — collisions need distinct IPs, so a shared IP never convicts |
| `fleet-cloned-datacenter` | fleet | `fleet` | ✓ | a CLEAN native anti-detect clone (BotBrowser-style, no automation tell, no JS divergence) but on DATACENTER IPs — the IP-reputation flag corroborates the fp-collision as a bot fleet where no automation tell does; distinguishes it from a residential corporate cohort |
| `fleet-cloned-fingerprint` | fleet | `fleet` | ✓ | BotBrowser-style: homogeneous JS but one fp_hash cloned across distinct IPs, AUTOMATED (webdriver) — the automation tell corroborates the collision as a cloned bot fleet, not standardized hardware |
| `fleet-cloned-trace` | fleet | `fleet` | ✓ | behavioural clone: distinct fps but one canned pointer trace replayed across distinct IPs |
| `fleet-ja4c-randomizer` | fleet | `fleet` | ✓ | uTLS-style fingerprint randomizer: shared cipher prefix but per-launch JA4_c randomization (NOT Camoufox — real Camoufox emits a stable JA4_c per config, grounded 2026-06-20), diverse JS, distinct IPs, AUTOMATED (webdriver) — the automation tell corroborates the JA4_c divergence as a fleet, not a benign multi-browser-version cohort (which also diverges JA4_c, hence the corroboration gate) |
| `fleet-shared-origin` | fleet | `fleet` | ✓ | proxies fronting one origin: diverse JS, distinct proxy IPs, ONE shared WebRTC-leaked real IP |
