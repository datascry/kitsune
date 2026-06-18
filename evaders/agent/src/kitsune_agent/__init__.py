# evaders/agent — LLM-driven browser agent package (claude -p as the brain).
# Re-exports the reasoning step (decide/Action) and the live session runner.

from __future__ import annotations

from .brain import Action, decide, parse_action
from .runner import run_session

NAME = "agent"
VERSION = "0.1.0"

__all__ = ["NAME", "VERSION", "Action", "decide", "parse_action", "run_session"]
