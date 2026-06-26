# harness/tools/fleet_coordination_demo — ingest a synthetic coordinated fleet into a LIVE detector.
# Proves the fleet-coordination axis end-to-end: /ingest -> store -> /scoreboard -> live grading -> conviction.

"""Drive the fleet-coordination grounding against a running detector (stdlib-only, no httpx).

The coordination scorer is graded offline (``coordination_scenarios``) and the live consumer is unit-tested
with a fake getter (``test_live_coordination``). This tool closes the remaining gap: it POSTs a coordinated
fleet through the REAL detector's ``/ingest`` contract, so the detector correlates + stores it as real
sessions, then the ``coordination-live`` task pulls them back over ``/scoreboard`` + ``/session`` and convicts
the clusters. It exercises the two CONVICTING arms of the gate (each needs >=2 distinct source IPs — the
proxy-egress topology that is the documented external input; here distinct ``observed_ip`` signals stand in
for it) plus a paradox-only control that must cap at ``candidate``:

  * fp-collision arm  — one JA4, one cloned high-entropy fp_hash across 3 distinct IPs + an automation tell
                        (the cloned-profile bot fleet) -> fleet.
  * trace-collision arm — one JA4, one replayed pointer trace_hash across 3 distinct IPs (unambiguous) -> fleet.
  * paradox control   — one JA4, divergent JS from ONE IP, no automation -> candidate (the gate's honesty).

Run: KITSUNE_DETECTOR=http://localhost:8080 python -m kitsune_harness... (see Taskfile `coordination-fleet-demo`).
"""

from __future__ import annotations

import json
import os
import urllib.request

DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://localhost:8080").rstrip("/")
WHEN = "2026-06-27T00:00:00Z"


def _sig(sid: str, layer: str, kind: str, value: object, src: str = "edge") -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "session_id": sid,
        "layer": layer,
        "kind": kind,
        "value": value,
        "source": src,
        "observed_at": WHEN,
    }


def _member(sid: str, ja4: str, ip: str, *, fp: str, trace: str | None, hw: int, automation: bool) -> list[dict]:
    sigs = [
        _sig(sid, "network", "ja4", ja4),
        _sig(sid, "network", "observed_ip", ip),
        _sig(sid, "browser", "fp_hash", fp, "collector"),
        _sig(sid, "browser", "hardware_concurrency", hw, "collector"),
    ]
    if trace is not None:
        sigs.append(_sig(sid, "behavioral", "trace_hash", trace, "collector"))
    if automation:  # an automation tell corroborates an fp-collision as a cloned BOT fleet (not a corporate cohort)
        sigs.append(_sig(sid, "browser", "webdriver", True, "collector"))
    return sigs


def _post(signals: list[dict]) -> None:
    body = json.dumps(signals).encode()
    req = urllib.request.Request(
        DETECTOR + "/ingest", data=body, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def fleet_signals() -> dict[str, list[dict]]:
    """Build the three clusters' signals, keyed by member session id."""
    # Distinct cipher-hash prefixes so the three arms form three SEPARATE clusters (the scorer groups by the
    # JA4 cipher prefix) — proving the gate convicts the two collision arms but caps the paradox-only control.
    ja4_a = "t13d1516h2_a1a1a1a1a1a1_0a0a0a0a0a0a"  # cloned-profile fleet
    ja4_b = "t13d1516h2_b2b2b2b2b2b2_0b0b0b0b0b0b"  # replayed-trace fleet
    ja4_c = "t13d1516h2_c3c3c3c3c3c3_0c0c0c0c0c0c"  # paradox-only control
    fp_clone = "9f2c7b41a0e8d35c"  # one high-entropy fingerprint cloned fleet-wide
    trace_clone = "7ab3e9f15c2d8061"  # one canned pointer trajectory replayed fleet-wide
    members: dict[str, list[dict]] = {}
    # fp-collision arm: cloned fp across 3 distinct IPs + automation tell
    for i, ip in enumerate(("10.10.0.1", "10.10.0.2", "10.10.0.3")):
        members[f"fleet-clone-{i}"] = _member(
            f"fleet-clone-{i}", ja4_a, ip, fp=fp_clone, trace=None, hw=8, automation=True
        )
    # trace-collision arm: cloned trace across 3 distinct IPs, distinct fingerprints
    for i, ip in enumerate(("10.20.0.1", "10.20.0.2", "10.20.0.3")):
        members[f"fleet-trace-{i}"] = _member(
            f"fleet-trace-{i}", ja4_b, ip, fp=f"distinct-fp-{i}", trace=trace_clone, hw=8, automation=False
        )
    # paradox control: divergent JS from ONE IP, no automation -> candidate, not fleet
    for i, hw in enumerate((4, 16)):
        members[f"paradox-ctl-{i}"] = _member(
            f"paradox-ctl-{i}", ja4_c, "10.30.0.9", fp=f"solo-fp-{i}", trace=None, hw=hw, automation=False
        )
    return members


def main() -> None:
    members = fleet_signals()
    for sigs in members.values():
        _post(sigs)
    print(f"ingested {len(members)} fleet sessions into {DETECTOR}: {', '.join(sorted(members))}")


if __name__ == "__main__":
    main()
