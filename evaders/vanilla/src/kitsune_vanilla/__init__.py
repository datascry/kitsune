# evaders/vanilla — baseline evader package (the control / detection floor).
# Re-exports the live runner that drives the edge -> detector pipeline.

from __future__ import annotations

from .runner import NAME, VERSION, VanillaError, build_client, run_once

__all__ = ["NAME", "VERSION", "VanillaError", "build_client", "run_once"]
