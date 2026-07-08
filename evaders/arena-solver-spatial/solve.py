# evaders/arena-solver-spatial/solve — reference solver for the arena 3D SPATIAL (isometric cube-grid) gate.
# Samples each cube's TOP-face colour and selects the tiles matching the prompt's target colour.

# ETHICS: allow-list-scoped — targets ONLY Kitsune's own arena gate (KITSUNE_ARENA, default the owned service).
# NEVER a third-party challenge. It demonstrates the arena thesis: the gate is a Turing test, not a bot/human
# discriminator — this deterministic colour-sampler passes it every time, yet a solved gate is convicted anyway by
# the SERVER-OBSERVED speed anomaly (solved_faster_than_human -> bh.arena_captcha_superhuman), which rides the
# /verify response into the detector's coherence verdict (label=bot).

import base64
import io
import os
import re
import urllib.request

from PIL import Image

ARENA = os.environ.get("KITSUNE_ARENA", "http://arena:8095")
COLORS = {
    "red": (220, 50, 50),
    "green": (50, 170, 70),
    "blue": (60, 90, 220),
    "yellow": (225, 195, 40),
    "orange": (235, 140, 40),
    "purple": (150, 70, 200),
}


def _top_colour(img: Image.Image) -> str:
    # Average a small box inside the top diamond (the un-shaded top face) and match to the nearest cube colour.
    px = img.load()
    acc = [0, 0, 0]
    n = 0
    for y in range(22, 29):
        for x in range(29, 36):
            p = px[x, y]
            acc[0] += p[0]
            acc[1] += p[1]
            acc[2] += p[2]
            n += 1
    avg = tuple(c // n for c in acc)
    return min(COLORS, key=lambda k: sum((avg[j] - COLORS[k][j]) ** 2 for j in range(3)))


def solve(level: str) -> tuple[bool, str | None]:
    s = _get_json(f"{ARENA}/arena/spatial?level={level}")
    target = re.search(r"with the (\w+) face", s["prompt"]).group(1)
    selected = [
        i
        for i, tile in enumerate(s["tiles"])
        if _top_colour(Image.open(io.BytesIO(base64.b64decode(tile["image"].split(",", 1)[1]))).convert("RGB"))
        == target
    ]
    v = _post_json(f"{ARENA}/arena/spatial/verify", {"id": s["id"], "selected": selected})
    return bool(v.get("ok")), v.get("anomaly")


def _get_json(url: str) -> dict:
    import json

    return json.load(urllib.request.urlopen(url, timeout=15))


def _post_json(url: str, body: dict) -> dict:
    import json

    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=15))


if __name__ == "__main__":
    for lvl in ("easy", "medium", "hard"):
        ok, anomaly = solve(lvl)
        print(f"{lvl}: ok={ok} anomaly={anomaly}")
