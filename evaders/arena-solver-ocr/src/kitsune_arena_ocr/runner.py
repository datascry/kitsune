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
    # OCR_LEVEL=easy|medium|hard runs one tier; "all" sweeps every tier to find the OCR breaking point.
    sel = os.environ.get("OCR_LEVEL", "medium")
    levels = ["easy", "medium", "hard"] if sel == "all" else [sel]
    print(f"loading TrOCR captcha model… (target {base})")
    recognizer = TrOCRRecognizer()
    with httpx.Client(timeout=60.0) as client:
        for level in levels:
            passed = 0
            for i in range(rounds):
                t0 = time.time()
                ok, text = solve_text(base, recognizer, client, level)
                ms = int((time.time() - t0) * 1000)
                passed += 1 if ok else 0
                print(f"  [{level}] round {i + 1}: read {text!r} -> {'PASSED' if ok else 'FAILED'} in {ms} ms")
            print(f"text gate [{level}]: {passed}/{rounds} solved by OCR — the detector convicts the no-JS client.")
