# detector/webutil — small generic web helpers shared by the app's routes.
# The FNV-1a hash (client-comparable IDs) and the safe-slug validator (path-param XSS/traversal guard).

"""Small, generic helpers used across the detector's HTTP routes.

Kept out of ``app.py``'s route factory so the generic utilities (a hash, a validation regex) are one named
home rather than scattered constants: ``_fnv1a`` mirrors the client's FNV-1a so IDs are comparable across
layers, and ``_SAFE_SLUG`` clamps a path param to lowercase-kebab before it reaches any HTML/SEO sink.
"""

from __future__ import annotations

import re


def _fnv1a(s: str) -> str:
    """FNV-1a (32-bit) hex — the same hash the client uses, so IDs are comparable across layers."""
    h = 2166136261
    for ch in s:
        h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return format(h, "x")


#: Evader slugs are lowercase-alphanumeric-with-dashes. Validating the path param to this charset before
#: it reaches any HTML/SEO sink both 404s junk URLs and removes the reflected-XSS taint (no <, ", etc.).
_SAFE_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,80}")
