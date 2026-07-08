# evaders/arena-solver-clock/solve — reference solver for the arena analog-clock CAPTCHA.
# Ray-casts from the clock centre to find the two hand angles, reads the time, and submits it.

# ETHICS: allow-list-scoped — targets ONLY Kitsune's own arena gate (KITSUNE_ARENA, default the owned service).
# NEVER a third-party challenge. It demonstrates the arena thesis: reading a rendered clock is a Turing test, not a
# bot/human discriminator — this deterministic hand-angle reader passes it, yet a solved gate is convicted by the
# SERVER-OBSERVED speed anomaly (solved_faster_than_human -> bh.arena_captcha_superhuman) joined into the verdict.

import base64
import io
import json
import math
import os
import urllib.request

from PIL import Image

ARENA = os.environ.get("KITSUNE_ARENA", "http://arena:8095")


def read_clock(img: Image.Image) -> str:
    g = img.convert("L")
    px = g.load()
    cx = cy = 50
    reach = [0] * 360
    for a in range(360):
        rad = math.radians(a)
        dxu, dyu = math.sin(rad), -math.cos(rad)
        run = 0
        miss = 0
        for d in range(3, 40):  # walk outward from the hub; the hands are continuous dark runs, ticks are not
            x = int(round(cx + d * dxu))
            y = int(round(cy + d * dyu))
            if 0 <= x < 100 and 0 <= y < 100 and px[x, y] < 110:
                run = d
                miss = 0
            else:
                miss += 1
                if miss > 2:  # tolerate a 2px noise gap, then the run ends
                    break
        reach[a] = run
    minute_a = max(range(360), key=lambda a: reach[a])  # the longer hand
    hour_a = max((a for a in range(360) if min(abs(a - minute_a), 360 - abs(a - minute_a)) > 18), key=lambda a: reach[a])
    minute = round(minute_a / 6) % 60
    hour = round(hour_a / 30 - minute / 60) % 12 or 12
    return f"{hour}:{minute:02d}"


def solve(level: str) -> tuple[bool, str, str | None]:
    c = json.load(urllib.request.urlopen(f"{ARENA}/arena/captcha?kind=clock&level={level}"))
    img = Image.open(io.BytesIO(base64.b64decode(c["image"].split(",", 1)[1])))
    answer = read_clock(img)
    v = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                f"{ARENA}/arena/captcha/verify",
                data=json.dumps({"kind": "clock", "id": c["id"], "answer": answer}).encode(),
                headers={"Content-Type": "application/json"},
            )
        )
    )
    return bool(v.get("ok")), answer, v.get("anomaly")


if __name__ == "__main__":
    for lvl in ("easy", "medium", "hard"):
        ok, ans, anomaly = solve(lvl)
        print(f"{lvl}: read={ans} ok={ok} anomaly={anomaly}")
