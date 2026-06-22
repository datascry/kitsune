# tests/test_css_beacon — the no-JS CSS @media beacon receiver (S1, docs/detection-landscape.md).
# Cookie-correlated browser.css_* signal; allow-listed (key,value) only; merges into the session.

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from kitsune_detector.app import create_app
from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import MISSING, Layer, Signal, Source
from kitsune_detector.store import Store

_NOW = datetime(2026, 6, 22, tzinfo=UTC)


def _session_with(**browser: object):
    sigs = [
        Signal(session_id="s", layer=Layer.browser, kind=k, value=v, source=Source.collector, observed_at=_NOW)
        for k, v in browser.items()
    ]
    return group_signals(sigs)[0]


def _derived_css_incoherent(**browser: object) -> object:
    session = Detector()._with_derived(_session_with(**browser))
    return session.value(Layer.browser, "css_pointer_vs_js_incoherent")


@pytest.fixture
def app_store() -> tuple[TestClient, Store]:
    store = Store(":memory:")
    return TestClient(create_app(detector=Detector(), store=store)), store


def test_beacon_records_css_signal_correlated_by_cookie(app_store: tuple[TestClient, Store]) -> None:
    client, store = app_store
    resp = client.get("/b/any_pointer_coarse/1", cookies={"ks_sid": "sess-a"})
    assert resp.status_code == 204
    session = store.get_session("sess-a")
    assert session is not None
    # The engine-reported coarse pointer lands as a browser.css_any_pointer_coarse signal.
    assert session.value(Layer.browser, "css_any_pointer_coarse") is True


def test_beacon_value_zero_records_false(app_store: tuple[TestClient, Store]) -> None:
    client, store = app_store
    client.get("/b/any_pointer_coarse/0", cookies={"ks_sid": "sess-b"})
    session = store.get_session("sess-b")
    assert session is not None and session.value(Layer.browser, "css_any_pointer_coarse") is False


def test_beacon_without_cookie_is_dropped(app_store: tuple[TestClient, Store]) -> None:
    client, store = app_store
    resp = client.get("/b/any_pointer_coarse/1")  # no ks_sid → cannot correlate
    assert resp.status_code == 204
    assert store.list_verdicts() == []  # nothing recorded


def test_beacon_rejects_unknown_key_and_value(app_store: tuple[TestClient, Store]) -> None:
    # Allow-listed only — never an open signal sink. An unknown key or out-of-range value records nothing.
    client, store = app_store
    assert client.get("/b/evil_signal/1", cookies={"ks_sid": "s"}).status_code == 204
    assert store.get_session("s") is None
    assert client.get("/b/any_pointer_coarse/9", cookies={"ks_sid": "s"}).status_code == 204
    assert store.get_session("s") is None


def test_css_js_touch_incoherence_derivation() -> None:
    # The S1 coherence substrate: detector derives css_pointer_vs_js_incoherent only when BOTH channels are
    # present AND disagree — the contradiction a JS-side touch spoof produces but cannot avoid on the CSS beacon.
    # Disagree → fires (both directions).
    assert _derived_css_incoherent(css_any_pointer_coarse=True, js_touch=False) is True
    assert _derived_css_incoherent(css_any_pointer_coarse=False, js_touch=True) is True
    # Agree → silent (a real touch device and a real desktop both agree across channels).
    assert _derived_css_incoherent(css_any_pointer_coarse=True, js_touch=True) is MISSING
    assert _derived_css_incoherent(css_any_pointer_coarse=False, js_touch=False) is MISSING
    # Only one channel present → cannot compare, abstain (no beacon yet, or no-JS client).
    assert _derived_css_incoherent(css_any_pointer_coarse=True) is MISSING
    assert _derived_css_incoherent(js_touch=False) is MISSING


def test_beacon_merges_into_existing_session(app_store: tuple[TestClient, Store]) -> None:
    # The CSS beacon and the JS /ingest POST share the ks_sid; the beacon's css_* signal must merge with the
    # JS-collected signals into one session (order-independent — CSS typically lands first).
    client, store = app_store
    client.get("/b/any_pointer_coarse/1", cookies={"ks_sid": "sess-c"})
    payload = [
        {
            "schema_version": "0.1",
            "session_id": "sess-c",
            "layer": "browser",
            "kind": "js_touch",
            "value": False,
            "source": "collector",
            "observed_at": "2026-06-22T12:00:00+00:00",
        }
    ]
    assert client.post("/ingest", json=payload).status_code == 200
    session = store.get_session("sess-c")
    assert session is not None
    # Both channels present in one session — the substrate the S1 coherence rule will cross-check.
    assert session.value(Layer.browser, "css_any_pointer_coarse") is True
    assert session.value(Layer.browser, "js_touch") is False
