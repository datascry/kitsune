# detector/arena_relay — config for relaying the challenge/verify protocol to the owned arena gate.
# The gate URL, the whitelisted gate/captcha/level names, and the level-clamp the /arena/* relay routes use.

"""Arena-relay configuration — the module-level state the detector's ``/arena/*`` relay routes share.

The detector relays the challenge/verify protocol to the owned ``arena/`` Go service so a visitor hits ONE
origin (through the edge); the gate verdict then joins the detector's coherence verdict client-side on
``ks_sid``. This module holds the relay's static config — the target URL, the whitelisted gate/captcha/level
names (defence-in-depth over the gate's own validation), and the level clamp — so ``app.py``'s relay routes
read one named home rather than a block of constants in the app factory.
"""

from __future__ import annotations

import os
from datetime import timedelta

#: The public arena challenge-gate (the owned ``arena/`` Go service). Empty/unset → the arena routes return
#: 503 (the live spine runs fine without it). Gate names are whitelisted; the gate itself only ever talks to
#: itself. Read from the environment at import; tests monkeypatch ``kitsune_detector.app.ARENA_URL`` (the
#: relay routes resolve it from app's globals, where it is imported).
ARENA_URL = os.environ.get("KITSUNE_ARENA_URL", "").rstrip("/")
_ARENA_GATES = frozenset({"hashcash", "many-small", "memory-hard", "cap"})
_ARENA_CAPTCHAS = frozenset({"text", "math", "clock", "honeypot", "image-select", "image-doodle", "image-shapes"})
#: Difficulty level (a cost dial — see arena/levels.go). Anything else falls back to medium, mirroring the
#: gate's own ParseLevel, so a junk ?level= never errors — it just gets the default.
_ARENA_LEVELS = frozenset({"easy", "medium", "hard"})
#: Virtual-queue position hoarding: the max concurrent tickets ONE ks_sid may hold before it looks like a scalper
#: maximising admission odds rather than a person. Threshold-CALIBRATED (even a multi-tab human does not hold this
#: many queue positions at once), so bh.arena_queue_hoarding is EXPERIMENTAL/corroborating, not FP-safe-by-
#: construction like the timing tells. Tickets older than the TTL are pruned so abandoned positions do not inflate
#: the count. The SMART hoarder spreads across ks_sids (the sybil-farmer coordination frontier, external-data-bound).
_QUEUE_HOARD_THRESHOLD = 8
_QUEUE_TICKET_TTL = timedelta(minutes=2)


def _arena_level(level: str | None) -> str:
    return level if level in _ARENA_LEVELS else "medium"
