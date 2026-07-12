# evaders/arena-solver-behave/behave — red-team evader that DEFEATS the FP-safe solve-behaviour tells of the arena
# BEHAVIOURAL gates by solving each coherently + humanizing the solve so the server-observed anomaly stays silent.

# ETHICS: allow-list-scoped — targets ONLY Kitsune's own arena gate (KS_BASE, default the owned service). NEVER a
# third-party challenge; no lifted assets. It demonstrates the arena thesis from the RED side: an FP-safe tell means
# a human-paced solver EVADES the gate's anomaly (the gate is a cost/Turing test), while a naive/superhuman solve
# TRIPS it. A passed-and-silent gate does NOT clear the session — coherence still convicts unless run in a coherent
# browser; this evader isolates the gate-behaviour layer. Env: KS_BASE (arena or detector relay), KS_SID (cookie),
# KS_GATE, KS_MODE (human|naive), KS_LEVEL. Stdlib only.

import base64
import json
import math
import os
import random
import struct
import time
import urllib.request
import zlib

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


# --- Image helpers (stdlib-only PNG decode; the CV the image gates need). Go's encoder emits RGB (3B) for opaque
# images, RGBA (4B) otherwise — read the colour type from IHDR. ---
def _decode_png(datauri: str) -> tuple[int, int, int, bytes]:
    raw = base64.b64decode(datauri.split(",", 1)[1])
    off, w, h, ct, idat = 8, 0, 0, 0, b""
    while off < len(raw):
        ln = struct.unpack(">I", raw[off : off + 4])[0]
        typ, data = raw[off + 4 : off + 8], raw[off + 8 : off + 8 + ln]
        off += 12 + ln
        if typ == b"IHDR":
            w, h, _bd, ct = struct.unpack(">IIBB", data[:10])
        elif typ == b"IDAT":
            idat += data
        elif typ == b"IEND":
            break
    buf = zlib.decompress(idat)
    bpp = 3 if ct == 2 else 4
    stride = w * bpp
    out, prev, p = bytearray(), bytearray(stride), 0

    def paeth(a: int, b: int, c: int) -> int:
        pp = a + b - c
        pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
        return a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)

    for _ in range(h):
        f = buf[p]
        p += 1
        line = bytearray(buf[p : p + stride])
        p += stride
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + b) & 255
            elif f == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 255
            elif f == 4:
                line[i] = (line[i] + paeth(a, b, c)) & 255
        out += line
        prev = line
    return w, h, bpp, bytes(out)


def _centroid_of(datauri: str, rgb: tuple[int, int, int]) -> tuple[float, float]:
    w, h, bpp, px = _decode_png(datauri)
    sx = sy = n = 0
    for y in range(h):
        for x in range(w):
            i = (y * w + x) * bpp
            if abs(px[i] - rgb[0]) < 30 and abs(px[i + 1] - rgb[1]) < 30 and abs(px[i + 2] - rgb[2]) < 30:
                sx += x
                sy += y
                n += 1
    return (sx / n, sy / n) if n else (w / 2, h / 2)


LOCATE_COLORS = {
    "red": (200, 40, 40),
    "green": (40, 160, 60),
    "blue": (50, 90, 210),
    "orange": (230, 140, 30),
    "purple": (150, 60, 190),
}


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


# --- (2) SMOOTH-PURSUIT — tell bh.arena_pursuit_superhuman (mean tracking error below the 8px human-pursuit floor).
# Evasion: follow the (public, deterministic) path but add human-like tracking ERROR (~14px std -> mean ~18px,
# above the 8px floor, below the 55px pass-max). Naive: cursor = the computed target exactly (mean error ~0).
def _pursuit_target(p: dict, t_ms: float) -> tuple[float, float]:
    s = t_ms / 1000.0
    return (p["cx"] + p["a"] * math.sin(p["w1"] * s + p["p1"]), p["cy"] + p["b"] * math.sin(p["w2"] * s + p["p2"]))


def pursuit(mode: str) -> dict:
    c = get(f"/arena/pursuit?level={LEVEL}")
    p, dur = c["path"], c["duration_ms"]
    sigma = 0.0 if mode == "naive" else 14.0  # human eye-hand pursuit trails the target by tens of px
    samples = []
    t = 0
    while t <= dur:
        x, y = _pursuit_target(p, t)
        if sigma:
            x += random.gauss(0, sigma)
            y += random.gauss(0, sigma)
        samples.append({"t": t, "x": x, "y": y})
        t += 16
    return post("/arena/pursuit/verify", {"id": c["id"], "samples": samples})


# --- (3) REACTION-TIME — tell bh.arena_reaction_superhuman (reaction = age - delay below the 120ms floor, or
# negative/anticipation). Evasion: wait for the go (the shown delay) THEN a ~250ms human reaction before clicking,
# so the server-observed reaction lands above the physiological floor. Naive: click the instant the cue fires
# (reaction ~ network, superhuman).
def reaction(mode: str) -> dict:
    c = get(f"/arena/reaction?level={LEVEL}")
    delay = c["delay_ms"]
    extra = 0.0 if mode == "naive" else 0.25  # a real hand-eye reaction (~250ms) after the box turns green
    time.sleep(delay / 1000.0 + extra)
    return post("/arena/reaction/verify", {"id": c["id"]})


# --- (4) TRACE-THE-PATTERN — tell bh.arena_pattern_superhuman (mean stroke deviation < 1.5px OR draw faster than
# N*300ms). Evasion: draw through the dots in order with a WOBBLY stroke (perpendicular offset ~5px -> mean deviation
# well above 1.5px) AND spend human drawing time (> N*300ms). Naive: a dead-straight stroke drawn instantly.
def pattern(mode: str) -> dict:
    c = get(f"/arena/pattern?level={LEVEL}")
    dots = c["dots"]
    n = len(dots)
    wob = 0.0 if mode == "naive" else 5.0
    stroke: list[list[float]] = []
    sign = 1.0
    for i in range(n - 1):
        ax, ay = dots[i]["x"], dots[i]["y"]
        bx, by = dots[i + 1]["x"], dots[i + 1]["y"]
        dx, dy = bx - ax, by - ay
        length = math.hypot(dx, dy) or 1.0
        nx, ny = -dy / length, dx / length  # unit normal
        d = 0.0
        while d < length:
            t = d / length
            w = wob * sign
            sign = -sign  # alternate the wobble so a real hand's tremor spreads off the ideal line
            stroke.append([ax + t * dx + w * nx, ay + t * dy + w * ny])
            d += 4
    stroke.append([float(dots[-1]["x"]), float(dots[-1]["y"])])
    if mode == "human":
        time.sleep(n * 0.35)  # human drawing pace (> N * 300ms)
    return post("/arena/pattern/verify", {"id": c["id"], "stroke": stroke})


# --- (5) ORDERED CLICK-IN-SEQUENCE — tell bh.arena_seqclick_superhuman (age < N*250ms OR metronomic inter-click
# cadence std < 15ms). Evasion: click the tiles in numeric order but spend human locate+click time (age > N*250ms)
# with VARIED inter-click gaps (~400-700ms -> std well above 15ms). Naive: click all instantly at a fixed cadence.
def sequence(mode: str) -> dict:
    c = get(f"/arena/sequence?level={LEVEL}")
    n = len(c["tiles"])
    clicks = list(range(1, n + 1))  # the numeric order the gate asks for
    if mode == "naive":
        times = [i * 100 for i in range(n)]  # metronomic, submitted instantly
    else:
        times, t = [], 0
        for _ in range(n):
            times.append(t)
            t += random.randint(400, 700)  # varied human inter-click gaps (std >> 15ms)
        time.sleep(n * 0.5)  # spend real locate+click time (age > N * 250ms)
    return post("/arena/sequence/verify", {"id": c["id"], "clicks": clicks, "times": times})


# --- (6) POINT LOCALIZATION — tell bh.arena_localize_superhuman (click within 2.5px of the exact centroid, OR
# age < 500ms). Evasion: CV-find the target centroid, then click NEAR it but off by ~6-14px (dist > 2.5, within the
# 34px acceptance radius) and spend > 500ms. Naive: click the exact computed centroid instantly.
def locate(mode: str) -> dict:
    c = get(f"/arena/locate?level={LEVEL}")
    color = c["prompt"].split(" circle")[0].split()[-1]
    cx, cy = _centroid_of(c["image"], LOCATE_COLORS[color])
    if mode == "naive":
        x, y = cx, cy  # pixel-perfect, instant
    else:
        ang, r = random.uniform(0, 2 * math.pi), random.uniform(6, 14)  # human aim scatter (off-centroid)
        x, y = cx + r * math.cos(ang), cy + r * math.sin(ang)
        time.sleep(0.7)  # > 500ms visual-locate + aim
    return post("/arena/locate/verify", {"id": c["id"], "x": round(x), "y": round(y)})


GATES = {
    "presshold": presshold,
    "pursuit": pursuit,
    "reaction": reaction,
    "pattern": pattern,
    "sequence": sequence,
    "locate": locate,
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
