"""The hybrid risk engine: weighting, banding, clamping and explainability."""

from __future__ import annotations

import pytest

from app.services.risk_engine import RiskEngine, classify_score


def test_risk_engine_applies_the_configured_weights(app):
    with app.app_context():
        engine = RiskEngine(heuristic_weight=0.6, ml_weight=0.4)
        result = engine.combine(heuristic_score=80, ml_score=40, ml_confidence=0.9,
                                ml_model="test", ml_available=True)
    assert result.final_score == pytest.approx(80 * 0.6 + 40 * 0.4, abs=0.51)
    assert result.weights == {"heuristic": 0.6, "ml": 0.4}


def test_weights_can_be_rebalanced(app):
    with app.app_context():
        engine = RiskEngine(heuristic_weight=0.25, ml_weight=0.75)
        result = engine.combine(heuristic_score=0, ml_score=100, ml_confidence=0.9,
                                ml_model="test", ml_available=True)
    assert result.final_score == pytest.approx(75, abs=0.51)


def test_weights_are_normalised_when_they_do_not_sum_to_one(app):
    with app.app_context():
        engine = RiskEngine(heuristic_weight=3, ml_weight=1)
        result = engine.combine(heuristic_score=100, ml_score=0, ml_confidence=0.5,
                                ml_model="test", ml_available=True)
    assert result.weights["heuristic"] + result.weights["ml"] == pytest.approx(1.0)
    assert result.final_score == pytest.approx(75, abs=0.51)


def test_risk_engine_falls_back_to_heuristics_when_ml_is_unavailable(app):
    with app.app_context():
        engine = RiskEngine(heuristic_weight=0.6, ml_weight=0.4)
        result = engine.combine(heuristic_score=70, ml_available=False)
    assert result.final_score == pytest.approx(70, abs=0.51)
    assert result.ml_available is False
    assert any("rule" in note.lower() or "heuristic" in note.lower() for note in result.notes)


def test_engine_is_deterministic(app):
    with app.app_context():
        engine = RiskEngine()
        scores = {engine.combine(heuristic_score=55, ml_score=80, ml_confidence=0.7,
                                 ml_model="GB", ml_available=True).final_score
                  for _ in range(5)}
    assert len(scores) == 1


@pytest.mark.parametrize("heuristic,ml", [(0, 0), (100, 100), (150, 150), (-20, -20)])
def test_final_score_is_always_within_bounds(app, heuristic, ml):
    with app.app_context():
        result = RiskEngine().combine(heuristic_score=heuristic, ml_score=ml,
                                      ml_confidence=1.0, ml_model="t", ml_available=True)
    assert 0 <= result.final_score <= 100


@pytest.mark.parametrize("score,expected", [(0, "LOW"), (24, "LOW"), (25, "MEDIUM"),
                                            (49, "MEDIUM"), (50, "HIGH"), (74, "HIGH"),
                                            (75, "CRITICAL"), (100, "CRITICAL")])
def test_risk_band_boundaries(app, score, expected):
    with app.app_context():
        assert classify_score(score) == expected


def test_risk_bands_are_configurable(app):
    """Bands come from config rather than being hardcoded through the app."""
    with app.app_context():
        assert classify_score(30) == "MEDIUM"
        app.config["RISK_BANDS"] = (("LOW", 0, 10), ("MEDIUM", 11, 20),
                                    ("HIGH", 21, 40), ("CRITICAL", 41, 100))
        assert classify_score(30) == "HIGH"


def test_risk_result_is_explainable(app):
    with app.app_context():
        result = RiskEngine().combine(heuristic_score=55, ml_score=80, ml_confidence=0.7,
                                      ml_model="GradientBoosting", ml_available=True)
        payload = result.to_dict()
    assert payload["recommendation"]
    assert len(payload["explanation"]) >= 3
    for step in payload["explanation"]:
        assert set(step) >= {"step", "detail", "value"}


def test_rule_ml_and_final_scores_are_reported_separately(app):
    with app.app_context():
        result = RiskEngine().combine(heuristic_score=20, ml_score=90, ml_confidence=0.8,
                                      ml_model="GradientBoosting", ml_available=True)
    assert result.heuristic_score == 20
    assert result.ml_score == 90
    assert result.heuristic_score != result.final_score != result.ml_score
    assert result.ml_model == "GradientBoosting"


def test_confidence_is_never_presented_as_certainty(app):
    with app.app_context():
        payload = RiskEngine().combine(heuristic_score=90, ml_score=99, ml_confidence=0.99,
                                       ml_model="GB", ml_available=True).to_dict()
    assert payload["ml_confidence"] <= 1.0
    assert payload["classification"] == "CRITICAL"
    assert payload["recommendation"]
