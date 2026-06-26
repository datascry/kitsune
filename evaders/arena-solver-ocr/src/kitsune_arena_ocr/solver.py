# evaders/arena-solver-ocr/solver — the OCR evasion logic: beat the arena's distorted-text gate with a model.
# Owned-gate-only; the recognizer is injected so this flow unit-tests without loading any ML weights.

"""Beat the arena's distorted-text CAPTCHA with a real OCR model — against OUR OWN gate only.

The Go heuristic solver can read the SVG-markup gates and synthesize trajectories, but the rasterized text
gate needs real OCR. This module is the missing evader half: it fetches the text challenge, hands the raster
to an injected :class:`Recognizer` (a HuggingFace TrOCR captcha model in production — see ``recognizer.py``),
and submits the read-back. The recognizer is an interface so the fetch/verify flow is testable with a mock,
and the heavy ML import stays out of the unit path. Ethics: the target is allow-list-checked to Kitsune's own
edge/detector (mirrors ``harness/allowlist.py``); this never touches a third-party challenge.
"""

from __future__ import annotations

import base64
import re
from typing import Protocol
from urllib.parse import urlparse

import httpx

#: The text gate's answer alphabet is uppercase letters + digits. TrOCR occasionally appends a spurious
#: separator (a trailing "/"), so the read-back is sanitised to this charset before submission — a known-charset
#: clean-up that recovers those misses (the solver keeping pace as difficulty rises).
_ANSWER_CHARS = re.compile(r"[^A-Z0-9]")

#: Kitsune's own surfaces — the only hosts this evader may hit (the ethics invariant, in code).
_OWN_TARGETS = frozenset({"edge", "detector", "localhost", "127.0.0.1", "::1", "arena", "arena-gate"})


class EthicsError(RuntimeError):
    """Raised when the solver is pointed at a target outside Kitsune's own surfaces."""


class Recognizer(Protocol):
    """Reads the characters out of a CAPTCHA image. Production impl is a HF TrOCR model; tests inject a stub."""

    def recognize(self, png: bytes) -> str: ...


def is_own_target(url: str) -> bool:
    host = urlparse(url).hostname
    return host is not None and host in _OWN_TARGETS


def decode_png_data_uri(data_uri: str) -> bytes:
    """Decode a ``data:image/png;base64,...`` URI to raw PNG bytes."""
    comma = data_uri.find(",")
    if comma < 0 or "base64" not in data_uri[:comma]:
        raise ValueError("not a base64 data URI")
    return base64.b64decode(data_uri[comma + 1 :])


def solve_text(
    base: str, recognizer: Recognizer, client: httpx.Client, level: str = "medium"
) -> tuple[bool, str]:
    """Fetch the text gate at the given level, OCR the image, submit the read-back. Returns (passed, read)."""
    base = base.rstrip("/")
    if not is_own_target(base):
        raise EthicsError(f"refusing {base!r} — arena-solver-ocr only hits Kitsune's own gates")
    chal = client.get(f"{base}/arena/captcha", params={"kind": "text", "level": level}).json()
    png = decode_png_data_uri(chal["image"])
    answer = _ANSWER_CHARS.sub("", recognizer.recognize(png).strip().upper())
    out = client.post(
        f"{base}/arena/captcha/verify",
        json={"kind": "text", "id": chal["id"], "answer": answer},
    ).json()
    return bool(out.get("ok")), answer
