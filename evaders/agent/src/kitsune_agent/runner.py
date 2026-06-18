# evaders/agent/runner — drive a remote Chromium with claude-chosen actions, read the verdict.
# Integration glue (tier-2): connects to the Playwright server, loops decide->execute, scores.

"""Agent session runner.

Connects to a Chromium running in the Playwright container (over a Playwright server WS endpoint),
patches the obvious automation tells (so the run isolates the *behavioral* question), then loops:
snapshot -> claude action -> execute with human-ish timing. Finally reads the verdict by ``ks_sid``.
"""

from __future__ import annotations

from typing import Any

import httpx

from .brain import Action, ClaudeRunner, decide, default_claude

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


def _execute(page: Any, action: Action) -> None:  # pragma: no cover - browser IO
    if action.kind == "move":
        page.mouse.move(action.x or 200, action.y or 200, steps=12)
    elif action.kind == "click":
        page.mouse.click(action.x or 200, action.y or 200)
    elif action.kind == "type":
        page.keyboard.type(action.text, delay=80)
    elif action.kind == "scroll":
        page.mouse.wheel(0, 300)


def run_session(  # pragma: no cover - browser IO
    ws_endpoint: str,
    edge_url: str,
    detector_url: str,
    *,
    goal: str = "explore the page like a curious human",
    steps: int = 2,
    claude: ClaudeRunner = default_claude,
) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(ws_endpoint)
        context = browser.new_context(ignore_https_errors=True, user_agent=CHROME_UA)
        context.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>false})"
        )
        page = context.new_page()
        page.goto(edge_url, wait_until="load")

        for _ in range(steps):
            action = decide(goal, page.inner_text("body"), claude=claude)
            _execute(page, action)
            if action.kind == "done":
                break

        page.wait_for_timeout(3500)
        cookie = next((c for c in context.cookies() if c["name"] == "ks_sid"), None)
        if cookie is None:
            browser.close()
            raise RuntimeError("no ks_sid cookie — pipeline not wired")
        verdict = httpx.get(f"{detector_url}/verdict/{cookie['value']}").json()
        browser.close()
        return {"mode": "agent", **verdict}
