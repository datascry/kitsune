# tests/test_scoring — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_detector import scoring
from kitsune_detector.models import Contradiction, Label, Layer


def _c(weight: float, *layers: Layer) -> Contradiction:
    return Contradiction(rule_id="r", layers=list(layers), detail="d", weight=weight)


def test_noisy_or() -> None:
    assert scoring.noisy_or([]) == 0.0
    assert scoring.noisy_or([0.5]) == 0.5
    assert scoring.noisy_or([0.5, 0.5]) == pytest.approx(0.75)


def test_effective_weight_amplifies_and_caps() -> None:
    single = _c(0.6, Layer.browser)
    cross = _c(0.6, Layer.network, Layer.browser)
    capped = _c(0.8, Layer.network, Layer.browser)
    assert scoring._effective_weight(single) == 0.6
    assert scoring._effective_weight(cross) == pytest.approx(0.9)
    assert scoring._effective_weight(capped) == 1.0  # 0.8 * 1.5 -> capped


def test_layer_scores_bucket_by_layer() -> None:
    ls = scoring.layer_scores([_c(0.9, Layer.browser), _c(0.5, Layer.network, Layer.browser)])
    assert ls.network == 0.5
    assert ls.browser == pytest.approx(0.95)
    assert ls.behavioral == 0.0


def test_incoherence_only_cross_layer() -> None:
    contradictions = [_c(0.9, Layer.browser), _c(0.6, Layer.network, Layer.browser)]
    assert scoring.incoherence_score(contradictions) == pytest.approx(0.6)


def test_final_score_uses_effective_weights() -> None:
    assert scoring.final_score([]) == 0.0
    assert scoring.final_score([_c(0.6, Layer.network, Layer.browser)]) == pytest.approx(0.9)


@pytest.mark.parametrize(
    ("score", "label"),
    [(0.0, Label.human), (0.34, Label.human), (0.35, Label.suspicious), (0.65, Label.bot)],
)
def test_label_for(score: float, label: Label) -> None:
    assert scoring.label_for(score) is label
