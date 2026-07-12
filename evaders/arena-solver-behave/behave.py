# evaders/arena-solver-behave/behave — red-team evader that DEFEATS the FP-safe solve-behaviour tells of the arena
# BEHAVIOURAL gates by solving each coherently + humanizing the solve so the server-observed anomaly stays silent.

# ETHICS: allow-list-scoped — targets ONLY Kitsune's own arena gate (KS_BASE, default the owned service). NEVER a
# third-party challenge; no lifted assets. It demonstrates the arena thesis from the RED side: an FP-safe tell means
# a human-paced solver EVADES the gate's anomaly (the gate is a cost/Turing test), while a naive/superhuman solve
# TRIPS it. A passed-and-silent gate does NOT clear the session — coherence still convicts unless run in a coherent
# browser; this evader isolates the gate-behaviour layer. Env: KS_BASE (arena or detector relay), KS_SID (cookie),
# KS_GATE, KS_MODE (human|naive), KS_LEVEL. Stdlib only.

import json
import os
import random
import time
import urllib.request

BASE = os.environ.get("KS_BASE", "http://arena:8095")
SID = os.environ.get("KS_SID", "")
LEVEL = os.environ.get("KS_LEVEL", "medium")


def _req(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"content-type": "application/json"} if data is not None else {}
    if SID:
        headers["Cookie"] = f"ks_sid={SID}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    return json.loads(urllib.request.urlopen(req).read())


def get(path: str) -> dict:
    return _req("GET", path)


def post(path: str, body: dict) -> dict:
    return _req("POST", path, body)


# --- (1) PRESS-AND-HOLD — tell bh.arena_hold_robotic (static-hold tremor OR impossible claimed hold). ---
# Evasion: hold for the real duration (age >= held, no impossible claim) with a drifting held pointer (tremor std
# above the human-jitter floor). Naive: submit instantly with a pinned coordinate (tremor 0) -> anomaly.
def presshold(mode: str) -> dict:
    c = get(f"/arena/presshold?level={LEVEL}")
    hold = c["hold_ms"]
    cx, cy = 160.0, 90.0
    if mode == "human":
        # a real hand drifts continuously under the hold -> tremor std ~ 1.6px (> 0.5 floor)
        samples = [[cx + random.gauss(0, 1.6), cy + random.gauss(0, 1.6)] for _ in range(12)]
        time.sleep(hold / 1000.0 + 0.05)  # spend the real hold time (age >= held)
        held = hold - random.randint(20, 150)  # within tolerance AND < the elapsed (never impossible)
    else:  # naive/superhuman
        samples = [[cx, cy] for _ in range(8)]  # injected, pinned to one coordinate -> tremor 0
        held = hold  # claim the full hold but submit instantly -> held > age (impossible)
    return post("/arena/presshold/verify", {"id": c["id"], "held_ms": held, "samples": samples})


GATES = {
    "presshold": presshold,
}


def main() -> None:
    gate = os.environ.get("KS_GATE", "presshold")
    mode = os.environ.get("KS_MODE", "human")
    fn = GATES.get(gate)
    if fn is None:
        raise SystemExit(f"unknown gate {gate}; have {sorted(GATES)}")
    v = fn(mode)
    ok = bool(v.get("ok"))
    anomaly = v.get("anomaly")
    evaded = ok and anomaly is None
    print(json.dumps({"gate": gate, "mode": mode, "ok": ok, "anomaly": anomaly, "evaded": evaded}))


if __name__ == "__main__":
    main()
