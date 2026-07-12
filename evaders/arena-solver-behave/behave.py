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
from collections import deque

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


# --- (7) SPOT-THE-DIFFERENCE — tell bh.arena_spotdiff_superhuman (every diff click within 3px of the centroid, OR
# age < K*1200ms). Evasion: image-diff the two panels (right offset 164 = panelW 140 + gap 24), cluster the changed
# pixels into centroids, then click each OFF-centroid by ~7-14px (> 3px, within the 24px hit radius) over > K*1200ms.
def spotdiff(mode: str) -> dict:
    c = get(f"/arena/spotdiff?level={LEVEL}")
    w, h, bpp, px = _decode_png(c["image"])
    off = 164

    def rgb(x: int, y: int) -> tuple[int, int, int]:
        i = (y * w + x) * bpp
        return px[i], px[i + 1], px[i + 2]

    # cluster changed pixels by EUCLIDEAN proximity (< 20px — below the gate's ~36px min disk separation, above a
    # single disk's ~14px radius) so two nearby recoloured disks are never merged into one.
    clusters: list[list[float]] = []
    for y in range(h):
        for x in range(140):
            lft, rgt = rgb(x, y), rgb(x + off, y)
            if abs(lft[0] - rgt[0]) + abs(lft[1] - rgt[1]) + abs(lft[2] - rgt[2]) > 40:
                gx, gy = x + off, y
                for cl in clusters:
                    if math.hypot(cl[0] / cl[2] - gx, cl[1] / cl[2] - gy) < 20:
                        cl[0] += gx
                        cl[1] += gy
                        cl[2] += 1
                        break
                else:
                    clusters.append([float(gx), float(gy), 1.0])
    centres = [(cl[0] / cl[2], cl[1] / cl[2]) for cl in clusters]
    if mode == "naive":
        clicks = [[round(cx), round(cy)] for cx, cy in centres]  # pixel-perfect, instant
    else:
        clicks = []
        for cx, cy in centres:
            ang, r = random.uniform(0, 2 * math.pi), random.uniform(7, 14)  # human aim scatter off the centroid
            clicks.append([round(cx + r * math.cos(ang)), round(cy + r * math.sin(ang))])
        time.sleep(len(centres) * 1.3)  # human per-difference scan time (> K * 1200ms)
    return post("/arena/spotdiff/verify", {"id": c["id"], "clicks": clicks})


# --- (8) SLIDING-TILE (8-puzzle) — tell bh.arena_slide_superhuman (move count == the BFS minimum on a >=8-move
# scramble, OR age < nMoves*350ms). Evasion: BFS-solve for the optimal path, then PREPEND a wasted round-trip (slide
# a neighbour out and back) so the move count exceeds the minimum, and spend > nMoves*350ms. Naive: the optimal path
# submitted instantly.
_SLIDE_GOAL = (1, 2, 3, 4, 5, 6, 7, 8, 0)


def _slide_nbrs(p: int) -> list[int]:
    r, c = divmod(p, 3)
    out = []
    if r > 0:
        out.append(p - 3)
    if r < 2:
        out.append(p + 3)
    if c > 0:
        out.append(p - 1)
    if c < 2:
        out.append(p + 1)
    return out


def _slide_bfs(start: list[int]) -> list[int]:
    s = tuple(start)
    if s == _SLIDE_GOAL:
        return []
    seen: dict = {s: None}
    q = deque([s])
    while q:
        cur = q.popleft()
        bl = cur.index(0)
        for n in _slide_nbrs(bl):
            nx = list(cur)
            nx[bl], nx[n] = nx[n], nx[bl]
            t = tuple(nx)
            if t in seen:
                continue
            seen[t] = (cur, n)
            if t == _SLIDE_GOAL:
                path, node = [], t
                while seen[node] is not None:
                    prev, mv = seen[node]
                    path.append(mv)
                    node = prev
                return path[::-1]
            q.append(t)
    return []


def slide(mode: str) -> dict:
    c = get(f"/arena/slide?level={LEVEL}")
    board = c["board"]
    opt = _slide_bfs(board)
    if mode == "naive":
        moves = opt  # the exact minimum, submitted instantly
    else:
        bl = board.index(0)
        n = _slide_nbrs(bl)[0]
        moves = [n, bl] + opt  # a wasted round-trip -> move count exceeds the optimum
        time.sleep(len(moves) * 0.4)  # human sliding pace (> nMoves * 350ms)
    return post("/arena/slide/verify", {"id": c["id"], "moves": moves})


# --- (9) ORIENTATION MATCH — tell bh.arena_match_superhuman (age < (N+1)*250ms). Evasion: estimate each arrow's
# direction from its dark-pixel centroid (the filled triangle's base is wider, so centroid->centre points toward the
# apex), pick the candidate whose angle is closest to the reference, but spend > (N+1)*250ms. Naive: same solve,
# submitted instantly.
def _orient(datauri: str) -> float:
    w, h, bpp, px = _decode_png(datauri)

    def dark(x: int, y: int) -> bool:
        i = (y * w + x) * bpp
        return px[i] < 120 and px[i + 1] < 120 and px[i + 2] < 120

    # keep only pixels in the SOLID triangle (>= 3 dark 8-neighbours) — drops the scattered single noise pixels
    pts = []
    for y in range(1, h - 1):
        for x in range(1, w - 1):
            if dark(x, y) and sum(dark(x + dx, y + dy) for dx in (-1, 0, 1) for dy in (-1, 0, 1)) - 1 >= 3:
                pts.append((x, y))
    if not pts:
        return 0.0
    cx = sum(p[0] for p in pts) / len(pts)
    cy = sum(p[1] for p in pts) / len(pts)
    # the apex (triangle tip) is the farthest solid pixel from the centroid; centroid -> apex is the arrow direction
    ax, ay = max(pts, key=lambda p: (p[0] - cx) ** 2 + (p[1] - cy) ** 2)
    return math.atan2(-(ay - cy), ax - cx)


def match(mode: str) -> dict:
    c = get(f"/arena/match?level={LEVEL}")
    ra = _orient(c["reference"])
    best, bd = 0, 9.0
    for t in c["tiles"]:
        d = abs(((_orient(t["image"]) - ra) + math.pi) % (2 * math.pi) - math.pi)  # circular angle diff
        if d < bd:
            bd, best = d, t["index"]
    if mode == "human":
        time.sleep((len(c["tiles"]) + 1) * 0.28)  # human reference+candidate scan (> (N+1)*250ms)
    return post("/arena/match/verify", {"id": c["id"], "clicked": best})


# --- (10) COUNTING — tell bh.arena_count_superhuman (a correct count faster than totalShapes*220ms). Evasion:
# connected-component-count the target-colour disks, submit the correct count, but spend > totalShapes*220ms (max
# ~2.6s on the 12-shape hard level). Naive: the same correct count submitted instantly.
COUNT_COLORS = {
    "red": (200, 50, 50),
    "green": (50, 160, 70),
    "blue": (55, 95, 210),
    "orange": (225, 145, 35),
    "purple": (150, 65, 190),
}


def _count_blobs(datauri: str, rgb: tuple[int, int, int]) -> int:
    w, h, bpp, px = _decode_png(datauri)
    seen = bytearray(w * h)

    def near(x: int, y: int) -> bool:
        i = (y * w + x) * bpp
        return abs(px[i] - rgb[0]) < 30 and abs(px[i + 1] - rgb[1]) < 30 and abs(px[i + 2] - rgb[2]) < 30

    blobs = 0
    for y in range(h):
        for x in range(w):
            if near(x, y) and not seen[y * w + x]:
                blobs += 1
                seen[y * w + x] = 1
                q = deque([(x, y)])
                while q:
                    cx, cy = q.popleft()
                    for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                        nx, ny = cx + dx, cy + dy
                        if 0 <= nx < w and 0 <= ny < h and not seen[ny * w + nx] and near(nx, ny):
                            seen[ny * w + nx] = 1
                            q.append((nx, ny))
    return blobs


def count(mode: str) -> dict:
    c = get(f"/arena/count?level={LEVEL}")
    color = c["prompt"].split(" circles")[0].split()[-1]
    guess = _count_blobs(c["image"], COUNT_COLORS[color])
    if mode == "human":
        time.sleep(3.0)  # > totalShapes * 220ms (max 12*220 = 2.64s) — human sequential counting time
    return post("/arena/count/verify", {"id": c["id"], "guess": guess})


GATES = {
    "presshold": presshold,
    "pursuit": pursuit,
    "reaction": reaction,
    "pattern": pattern,
    "sequence": sequence,
    "locate": locate,
    "spotdiff": spotdiff,
    "slide": slide,
    "match": match,
    "count": count,
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
