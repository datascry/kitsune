# evaders/agent/brain — the agent's reasoning step: ask claude -p for the next browser action.
# Pure + testable: builds the prompt, runs the model (injectable), parses a strict-JSON action.

"""The agent brain.

Each step hands claude a goal + a compact page snapshot and asks for the next *human* action as
JSON. The model runner is injected (default shells out to ``claude -p``) so parsing is testable.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

#: The small action vocabulary the agent may emit.
ACTIONS = frozenset({"move", "click", "type", "scroll", "done"})

#: A model runner takes a prompt and returns the raw model text.
ClaudeRunner = Callable[[str], str]


@dataclass(frozen=True)
class Action:
    kind: str
    x: int = 0
    y: int = 0
    text: str = ""


def default_claude(prompt: str) -> str:
    """Run a one-shot headless `claude -p` and return its stdout."""
    proc = subprocess.run(
        ["claude", "-p", prompt],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return proc.stdout


def build_prompt(goal: str, snapshot: str) -> str:
    return (
        f"You are driving a web browser like a human. Goal: {goal}\n"
        f"Visible page text:\n{snapshot[:500]}\n\n"
        "Reply with ONLY one JSON object for the next action, no prose. Schema:\n"
        '{"kind":"move|click|type|scroll|done","x":<int>,"y":<int>,"text":"<for type>"}'
    )


def parse_action(raw: str) -> Action:
    """Extract the first JSON object from the model output and build a valid Action.

    Falls back to a harmless ``done`` if the output is missing, malformed, or an unknown action.
    """
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return Action("done")
    try:
        obj = json.loads(match.group(0))
    except json.JSONDecodeError:
        return Action("done")
    kind = obj.get("kind")
    if kind not in ACTIONS:
        return Action("done")
    return Action(
        kind=kind,
        x=int(obj.get("x", 0)),
        y=int(obj.get("y", 0)),
        text=str(obj.get("text", "")),
    )


def decide(goal: str, snapshot: str, *, claude: ClaudeRunner = default_claude) -> Action:
    return parse_action(claude(build_prompt(goal, snapshot)))
