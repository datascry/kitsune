# fleet/skulk/model — the coordination shapes Skulk emits: a FleetMember and the wire signals it becomes.
# A FleetMember is one node's cross-session identity (JA4 / IP / fingerprint / trace); strategies build them.

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FleetMember:
    """One node of an emulated fleet — its cross-session identity. The fields are exactly the layers a
    coordination detector clusters on: the TLS engine (``ja4``), the source ``observed_ip``, the high-entropy
    browser ``fp_hash`` (canvas+audio+WebGL), the behavioural ``trace_hash`` (pointer trajectory), and the
    JS traits (``hardware_concurrency`` / ``platform``) a randomizer fleet diverges. ``trace_descriptor`` is the
    motion-feature vector of the pointer path (the SIMILARITY analog of ``trace_hash`` — a humanizer fleet's are
    near-identical even when each ``trace_hash`` differs). ``webrtc_public_ip`` is the WebRTC-leaked real origin —
    one shared value behind distinct proxy IPs is an unambiguous same-origin binding that SURVIVES JA4 rotation
    (the only thing that catches a fleet which rotates its JA4 AND fuzzes fp/trace). ``tls_ticket_id`` is the
    reused TLS-resumption ticket (the edge captures it from pre_shared_key / session_ticket) — another binding
    that survives JA4 rotation: one ticket across distinct IPs is one TLS session shared fleet-wide. ``automation``
    marks a
    per-session headless/automation tell and ``datacenter`` an IP-reputation flag — either corroborates an
    AMBIGUOUS coordination tell (an fp-collision or a template-similarity cluster) as a bot fleet, not a cohort.
    ``offset_seconds`` is the member's arrival time relative to the run base (the runner stamps each member's
    signals at base + offset): a `staggered` fleet spreads these beyond the lockstep window to shed the timing
    tell, which only costs it the lockstep corroboration — the binding still convicts.
    """

    node_id: str
    ja4: str
    observed_ip: str
    fp_hash: str | None = None
    trace_hash: str | None = None
    trace_descriptor: list[float] | None = None
    webrtc_public_ip: str | None = None
    tls_ticket_id: str | None = None
    hardware_concurrency: int | None = None
    platform: str | None = None
    automation: bool = False
    datacenter: bool = False
    offset_seconds: float = 0.0  # arrival time relative to the run base — a `staggered` fleet spreads these out

    def signals(self, session_id: str, when: str) -> list[dict[str, object]]:
        """The detector ``/ingest`` signal envelopes for this member — the stable wire contract (Skulk speaks
        the JSON contract directly and never imports a detector, so it stays standalone + portable)."""
        sigs = [
            _sig(session_id, "network", "ja4", self.ja4, when),
            _sig(session_id, "network", "observed_ip", self.observed_ip, when),
        ]
        if self.fp_hash is not None:
            sigs.append(_sig(session_id, "browser", "fp_hash", self.fp_hash, when, "collector"))
        if self.trace_hash is not None:
            sigs.append(_sig(session_id, "behavioral", "trace_hash", self.trace_hash, when, "collector"))
        if self.trace_descriptor is not None:
            sigs.append(_sig(session_id, "behavioral", "trace_descriptor", self.trace_descriptor, when, "collector"))
        if self.webrtc_public_ip is not None:
            sigs.append(_sig(session_id, "browser", "webrtc_public_ip", self.webrtc_public_ip, when, "collector"))
        if self.tls_ticket_id is not None:
            sigs.append(_sig(session_id, "network", "tls_ticket_id", self.tls_ticket_id, when, "edge"))
        if self.hardware_concurrency is not None:
            sigs.append(
                _sig(session_id, "browser", "hardware_concurrency", self.hardware_concurrency, when, "collector")
            )
        if self.platform is not None:
            sigs.append(_sig(session_id, "browser", "platform", self.platform, when, "collector"))
        if self.automation:
            sigs.append(_sig(session_id, "browser", "webdriver", True, when, "collector"))
        if self.datacenter:
            sigs.append(_sig(session_id, "reputation", "asn_is_datacenter", True, when, "detector"))
        return sigs


def _sig(sid: str, layer: str, kind: str, value: object, when: str, src: str = "edge") -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "session_id": sid,
        "layer": layer,
        "kind": kind,
        "value": value,
        "source": src,
        "observed_at": when,
    }
