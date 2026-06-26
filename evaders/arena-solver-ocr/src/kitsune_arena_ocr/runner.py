# evaders/arena-solver-ocr/runner — OCR evader that beats the arena's distorted-text gate (owned gates only).
# Loads a HF TrOCR captcha model, solves N text challenges, reports the pass rate; the detector convicts it.

from __future__ import annotations

import os
import time

import httpx

from .recognizer import TrOCRRecognizer
from .solver import solve_text


def main() -> None:
    base = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")
    rounds = int(os.environ.get("OCR_ROUNDS", "5"))
    print(f"loading TrOCR captcha model… (target {base})")
    recognizer = TrOCRRecognizer()
    passed = 0
    with httpx.Client(timeout=60.0) as client:
        for i in range(rounds):
            t0 = time.time()
            ok, text = solve_text(base, recognizer, client)
            ms = int((time.time() - t0) * 1000)
            passed += 1 if ok else 0
            print(f"  round {i + 1}: read {text!r} -> {'PASSED' if ok else 'FAILED'} in {ms} ms")
    print(f"text gate: {passed}/{rounds} solved by OCR — but the detector convicts this no-JS client.")
