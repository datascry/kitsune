# tests/test_models — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kitsune_detector.contracts import validate
from kitsune_detector.models import (
    MISSING,
    Contradiction,
    Layer,
    Session,
    Signal,
    SignalGroups,
    Source,
)

from .conftest import FIXED, make_signal


def test_signal_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Signal(
            session_id="s",
            layer=Layer.browser,
            kind="webdriver",
            value=True,
            source=Source.collector,
            observed_at=FIXED,
            bogus="x",  # type: ignore[call-arg]
        )


def test_signal_groups_of_returns_layer_list() -> None:
    groups = SignalGroups()
    sig = make_signal("s", Layer.network, "ja4", "abc", source=Source.edge)
    groups.of(Layer.network).append(sig)
    assert groups.of(Layer.network) == [sig]
    assert groups.of(Layer.browser) == []


def test_session_value_resolves_or_missing(human_session: Session) -> None:
    assert human_session.value(Layer.browser, "ua_browser") == "chrome"
    assert human_session.value(Layer.browser, "does_not_exist") is MISSING


def test_contradiction_is_cross_layer() -> None:
    single = Contradiction(rule_id="r", layers=[Layer.browser], detail="d", weight=0.5)
    cross = Contradiction(rule_id="r", layers=[Layer.network, Layer.browser], detail="d", weight=0.5)
    assert single.is_cross_layer is False
    assert cross.is_cross_layer is True


def test_signal_round_trips_through_schema() -> None:
    sig = make_signal("s", Layer.network, "ja4", "t13d1516h2", source=Source.edge)
    validate(sig.model_dump(mode="json"), "signal.schema.json")


def test_session_round_trips_through_schema(human_session: Session) -> None:
    # The pydantic model is the detector's view; the JSON Schema is the cross-language contract the
    # edge/collector must match. A model instance must validate against its own schema, or they have drifted.
    validate(human_session.model_dump(mode="json"), "session.schema.json")


def test_verdict_round_trips_through_schema(bot_session: Session) -> None:
    from kitsune_detector.detector import Detector

    # Guards the Contradiction.category field (added with the detection-class taxonomy) against drifting
    # from verdict.schema.json — a real risk the Signal-only roundtrip did not cover.
    verdict = Detector().score(bot_session)
    validate(verdict.model_dump(mode="json"), "verdict.schema.json")
