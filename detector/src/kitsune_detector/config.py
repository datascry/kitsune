# detector/config — tunable scoring constants.
# Schema version, label thresholds, and the cross-layer incoherence amplification weight.

"""Tunable constants for the detector.

Kept tiny and explicit: scoring must stay transparent, so the few magic numbers that shape a
verdict live here rather than scattered through the code.
"""

from __future__ import annotations

#: Current contract schema version this detector emits and expects (MAJOR.MINOR).
SCHEMA_VERSION = "0.1"

#: Final-score thresholds for labelling. score in [0, 1], 1 == bot.
SUSPICIOUS_THRESHOLD = 0.35
BOT_THRESHOLD = 0.65

#: How much a *cross-layer* contradiction is amplified over a single-layer one. This is the
#: mechanical expression of Kitsune's thesis: incoherence across layers counts for more than a
#: bad signal within one layer. A 0.6 cross-layer contradiction becomes 0.6 * (1 + 0.5) = 0.9.
INCOHERENCE_WEIGHT = 0.5
