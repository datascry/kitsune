# evaders/arena-solver-ocr — OCR solver for the arena's distorted-text gate

The Go `arena-solver` beats every arena gate except the **rasterized text** gate, which needs real OCR. This
evader closes that half by leveraging a **HuggingFace TrOCR captcha model** (default `anuashok/ocr-captcha-v3`,
CER ~0.014) — against **Kitsune's own gate only** (allow-list-checked, like `harness/allowlist.py`).

The point is the arms race, not a third-party bypass: a real OCR model reads our distorted text, and the
**detector still convicts the no-JS client** — coherence, not the challenge, is the durable layer.

```sh
# one-shot against the live spine (downloads the model on first run, ~1.3 GB)
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm --build arena-solver-ocr
```

`solver.py` is the testable flow (recognizer injected); `recognizer.py` + `__main__.py` load/run the model
(tier-2 IO, off the unit gate). `KITSUNE_OCR_MODEL` overrides the model; `KITSUNE_DETECTOR` the target.
