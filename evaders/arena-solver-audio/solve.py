# evaders/arena-solver-audio/solve — reference solver for the arena AUDIO (spoken-digit) gate.
# A matched-filter attack: correlates the embedded FSDD templates over the minted clip to recover the digits.

# ETHICS: allow-list-scoped — targets ONLY Kitsune's own arena gate (KITSUNE_ARENA, default the owned service).
# NEVER a third-party audio challenge. It demonstrates the arena thesis: the gate is a COST dial — this simple
# known-corpus matcher beats `easy`, but the per-level distortion (noise/tone/overlap) defeats it on medium/hard,
# which need a real ASR (Whisper); and a solved gate is convicted anyway by the SERVER-OBSERVED speed anomaly
# (solved_faster_than_audio), which rides the /verify response into the detector's coherence verdict.

import base64
import glob
import io
import json
import os
import urllib.request
import wave

import numpy as np

ARENA = os.environ.get("KITSUNE_ARENA", "http://arena:8095")
CORPUS = os.environ.get("FSDD_DIR", os.path.join(os.path.dirname(__file__), "../../arena/assets/fsdd"))


def _samples(b: bytes) -> np.ndarray:
    w = wave.open(io.BytesIO(b))
    return np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32)


def _load_templates() -> list[tuple[int, np.ndarray]]:
    out = []
    for f in sorted(glob.glob(os.path.join(CORPUS, "*.wav"))):
        digit = int(os.path.basename(f)[0])
        w = wave.open(f)
        s = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32)
        out.append((digit, s / (np.linalg.norm(s) + 1e-9)))
    return out


def solve(level: str, templates: list[tuple[int, np.ndarray]]) -> tuple[bool, str, str | None]:
    a = json.load(urllib.request.urlopen(f"{ARENA}/arena/audio?level={level}"))
    clip = _samples(base64.b64decode(a["clip"].split(",", 1)[1]))
    n = a["digits"]
    # Slide each template over the whole clip; take the N best NON-OVERLAPPING peaks, ordered by position.
    peaks = []
    for digit, tn in templates:
        if len(clip) < len(tn):
            continue
        # NORMALIZED cross-correlation (divide by local clip energy) — the best-MATCHING digit wins at each
        # position, not the loudest region. Grounded ~13% -> ~100% on easy vs the plain dot product.
        dot = np.correlate(clip, tn, mode="valid")
        energy = np.sqrt(np.convolve(clip**2, np.ones(len(tn)), mode="valid")) + 1e-9
        score = dot / energy
        p = int(np.argmax(score))
        peaks.append((float(score[p]), p, digit))
    peaks.sort(reverse=True)
    chosen: list[tuple[float, int, int]] = []
    for sc, pos, digit in peaks:
        if all(abs(pos - q) > 3000 for _, q, _ in chosen):
            chosen.append((sc, pos, digit))
        if len(chosen) == n:
            break
    chosen.sort(key=lambda x: x[1])
    answer = "".join(str(d) for _, _, d in chosen)
    body = json.dumps({"id": a["id"], "answer": answer}).encode()
    v = json.load(urllib.request.urlopen(urllib.request.Request(
        f"{ARENA}/arena/audio/verify", data=body, headers={"Content-Type": "application/json"})))
    return bool(v.get("ok")), answer, v.get("anomaly")


if __name__ == "__main__":
    tmpl = _load_templates()
    for lvl in ("easy", "medium", "hard"):
        ok, ans, anomaly = solve(lvl, tmpl)
        print(f"{lvl}: {ans} -> ok={ok} anomaly={anomaly}")
