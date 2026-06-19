# Coordination scenarios — precision/recall of the fleet detector

- **precision: 100%** (no legitimate cohort labelled `fleet`)
- **recall: 100%** (every fleet shape caught)

| scenario | expected | label | ✓ | why |
|---|---|---|---|---|
| `legit-diverse-cohort` | not-fleet | `candidate` | ✓ | distinct real users on one Chrome build: diverse hw/OS, distinct IPs+fps+traces, spread timing |
| `legit-homogeneous-pair` | not-fleet | `candidate` | ✓ | two users, identical JS (same build+config) but distinct fps/traces — a benign same-build pair |
| `legit-large-cohort` | not-fleet | `candidate` | ✓ | 8 distinct users on one build — paradox + IP spread at scale must still not convict |
| `legit-nat-cohort` | not-fleet | `candidate` | ✓ | 5 distinct users behind ONE NAT IP — collisions need distinct IPs, so a shared IP never convicts |
| `fleet-cloned-fingerprint` | fleet | `fleet` | ✓ | BotBrowser-style: homogeneous JS but one fp_hash cloned across distinct IPs |
| `fleet-cloned-trace` | fleet | `fleet` | ✓ | behavioural clone: distinct fps but one canned pointer trace replayed across distinct IPs |
| `fleet-ja4c-randomizer` | fleet | `fleet` | ✓ | Camoufox-style: shared cipher prefix but per-launch JA4_c randomization, diverse JS, distinct IPs |
| `fleet-shared-origin` | fleet | `fleet` | ✓ | proxies fronting one origin: diverse JS, distinct proxy IPs, ONE shared WebRTC-leaked real IP |
