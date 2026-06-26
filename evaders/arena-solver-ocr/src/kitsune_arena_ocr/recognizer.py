# evaders/arena-solver-ocr/recognizer — the real OCR: a HuggingFace TrOCR captcha model (tier-2 IO).
# Leverages anuashok/ocr-captcha-v3 (TrOCR fine-tuned on captchas, CER ~0.014); excluded from the unit gate.

"""The production recognizer — a HuggingFace TrOCR captcha model.

Defaults to ``anuashok/ocr-captcha-v3`` (microsoft/trocr-base-printed fine-tuned on captchas, char error rate
~0.014). Heavy (transformers + torch + a ~1.3 GB model download), so it is imported lazily and kept out of the
unit-test path — the solve flow is tested with a stub recognizer in solver.py.
"""

from __future__ import annotations

import io
import os


class TrOCRRecognizer:
    """Reads CAPTCHA text with a HF TrOCR model. Loads weights once on construction."""

    def __init__(self, model: str | None = None) -> None:
        from PIL import Image  # noqa: F401  (ensure Pillow is present early)
        from transformers import TrOCRProcessor, VisionEncoderDecoderModel

        name = model or os.environ.get("KITSUNE_OCR_MODEL", "anuashok/ocr-captcha-v3")
        self._processor = TrOCRProcessor.from_pretrained(name)
        self._model = VisionEncoderDecoderModel.from_pretrained(name)

    def recognize(self, png: bytes) -> str:
        from PIL import Image

        image = Image.open(io.BytesIO(png)).convert("RGB")
        pixel_values = self._processor(images=image, return_tensors="pt").pixel_values
        generated = self._model.generate(pixel_values)
        return str(self._processor.batch_decode(generated, skip_special_tokens=True)[0])
