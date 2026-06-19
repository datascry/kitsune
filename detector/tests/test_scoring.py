# tests/test_scoring — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_detector import scoring
from kitsune_detector.models import Contradiction, Label, Layer, RuleCategory


def _c(weight: float, *layers: Layer) -> Contradiction:
    return Contradiction(rule_id="r", layers=list(layers), detail="d", weight=weight)


def _cat(weight: float, category: RuleCategory) -> Contradiction:
    return Contradiction(rule_id="r", layers=[Layer.browser], detail="d", weight=weight, category=category)


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


def test_has_convicting() -> None:
    env = [_cat(0.9, RuleCategory.environment), _cat(0.9, RuleCategory.behavioral)]
    assert scoring.has_convicting(env) is False
    assert scoring.has_convicting([*env, _cat(0.5, RuleCategory.coherence)]) is True
    for c in (RuleCategory.coherence, RuleCategory.automation, RuleCategory.artifact):
        assert scoring.has_convicting([_cat(0.4, c)]) is True
    # prevalence is corroborating-by-design: a single-source likelihood prior must not convict alone.
    for c in (RuleCategory.environment, RuleCategory.behavioral, RuleCategory.reputation, RuleCategory.prevalence):
        assert scoring.has_convicting([_cat(0.99, c)]) is False


def test_label_gate_requires_convicting_signal() -> None:
    # bot-level score from environment tells alone is capped at suspicious — a stripped-but-real browser.
    env_only = [_cat(0.55, RuleCategory.environment), _cat(0.3, RuleCategory.environment)]
    assert scoring.final_score(env_only) >= scoring.BOT_THRESHOLD  # would be bot under bare threshold
    assert scoring.label_for(scoring.final_score(env_only), env_only) is Label.suspicious
    # add one convicting tell and the same score now convicts
    convicted = [*env_only, _cat(0.4, RuleCategory.automation)]
    assert scoring.label_for(scoring.final_score(convicted), convicted) is Label.bot
    # corroborating-only below the suspicious floor stays human
    assert scoring.label_for(0.2, [_cat(0.2, RuleCategory.environment)]) is Label.human
