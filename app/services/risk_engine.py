"""Hybrid risk engine: rule-based heuristics fused with the ML classifier.

    final_score = heuristic_score * HEURISTIC_WEIGHT + ml_score * ML_WEIGHT

Both weights are configurable (``HEURISTIC_WEIGHT`` / ``ML_WEIGHT`` env vars).
If the ML model is unavailable the heuristic score is used on its own and the
fallback is reported explicitly so the analyst is never misled about how the
number was produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from flask import current_app

DEFAULT_BANDS = (
    ("LOW", 0, 24),
    ("MEDIUM", 25, 49),
    ("HIGH", 50, 74),
    ("CRITICAL", 75, 100),
)

RECOMMENDATIONS = {
    "LOW": ("No strong phishing signals were detected. Continue to apply normal "
            "caution: verify unexpected requests through a known-good channel."),
    "MEDIUM": ("Several suspicious characteristics were detected. Do not interact "
               "with the link or attachment; verify the sender out-of-band and "
               "escalate to the security team if anything remains unclear."),
    "HIGH": ("Strong phishing indicators were detected. Quarantine the message, "
             "block the domain at the gateway/proxy and warn the targeted users. "
             "Do not open the link on a production endpoint."),
    "CRITICAL": ("Critical phishing indicators were detected. Treat this as an "
                 "active attack: quarantine and purge the message, block the "
                 "domain and IP, force a credential review for anyone who "
                 "interacted with it and raise an incident ticket."),
}


def classify_score(score: float, bands=None) -> str:
    """Map a 0-100 score onto a risk band label.

    When no explicit bands are supplied the configured ``RISK_BANDS`` are
    used, so retuning the thresholds in config affects every caller rather
    than only the ones that happen to go through ``RiskEngine``.
    """
    if bands is None:
        try:
            bands = current_app.config.get("RISK_BANDS", DEFAULT_BANDS)
        except RuntimeError:
            bands = DEFAULT_BANDS
    bands = bands or DEFAULT_BANDS
    value = max(0.0, min(100.0, float(score)))
    for label, low, high in bands:
        if low <= value <= high:
            return label
    return bands[-1][0]


@dataclass
class RiskResult:
    heuristic_score: float
    ml_score: float | None
    ml_confidence: float | None
    ml_model: str | None
    final_score: float
    classification: str
    weights: dict = field(default_factory=dict)
    explanation: list[dict] = field(default_factory=list)
    ml_available: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "heuristic_score": round(self.heuristic_score, 2),
            "ml_score": round(self.ml_score, 2) if self.ml_score is not None else None,
            "ml_confidence": round(self.ml_confidence, 4) if self.ml_confidence is not None else None,
            "ml_model": self.ml_model,
            "final_score": round(self.final_score, 2),
            "classification": self.classification,
            "weights": self.weights,
            "explanation": self.explanation,
            "ml_available": self.ml_available,
            "notes": self.notes,
            "recommendation": RECOMMENDATIONS.get(self.classification, ""),
        }


class RiskEngine:
    """Combines heuristic and ML scores into a single explainable verdict."""

    def __init__(self, heuristic_weight: float | None = None, ml_weight: float | None = None,
                 bands=None):
        self._heuristic_weight = heuristic_weight
        self._ml_weight = ml_weight
        self._bands = bands

    # -- configuration -------------------------------------------------
    @property
    def heuristic_weight(self) -> float:
        if self._heuristic_weight is not None:
            return self._heuristic_weight
        try:
            return float(current_app.config.get("HEURISTIC_WEIGHT", 0.6))
        except RuntimeError:
            return 0.6

    @property
    def ml_weight(self) -> float:
        if self._ml_weight is not None:
            return self._ml_weight
        try:
            return float(current_app.config.get("ML_WEIGHT", 0.4))
        except RuntimeError:
            return 0.4

    @property
    def bands(self):
        if self._bands is not None:
            return self._bands
        try:
            return current_app.config.get("RISK_BANDS", DEFAULT_BANDS)
        except RuntimeError:
            return DEFAULT_BANDS

    # -- scoring ---------------------------------------------------------
    def combine(self, heuristic_score: float, ml_score: float | None = None,
                ml_confidence: float | None = None, ml_model: str | None = None,
                ml_available: bool = True, extra_notes: list[str] | None = None) -> RiskResult:
        heuristic_score = max(0.0, min(100.0, float(heuristic_score or 0.0)))
        w_h, w_m = self.heuristic_weight, self.ml_weight
        notes = list(extra_notes or [])
        explanation: list[dict] = []

        if ml_score is None or not ml_available:
            final = heuristic_score
            used_weights = {"heuristic": 1.0, "ml": 0.0}
            notes.append(
                "ML model unavailable - the final score falls back to 100% rule-based analysis."
            )
            explanation.append({
                "step": "Rule-based score",
                "detail": f"{heuristic_score:.2f} / 100 from the heuristic indicators listed below.",
                "value": round(heuristic_score, 2),
            })
            explanation.append({
                "step": "Final score",
                "detail": "ML component unavailable, so the heuristic score is used unchanged.",
                "value": round(final, 2),
            })
        else:
            total = w_h + w_m
            if total <= 0:
                w_h, w_m, total = 0.6, 0.4, 1.0
                notes.append("Configured weights summed to zero - defaults (0.6/0.4) were applied.")
            n_h, n_m = w_h / total, w_m / total
            ml_score = max(0.0, min(100.0, float(ml_score)))
            final = heuristic_score * n_h + ml_score * n_m
            used_weights = {"heuristic": round(n_h, 3), "ml": round(n_m, 3)}
            explanation = [
                {
                    "step": "Rule-based score",
                    "detail": f"{heuristic_score:.2f} / 100 from explainable heuristics.",
                    "value": round(heuristic_score, 2),
                },
                {
                    "step": "ML score",
                    "detail": (f"{ml_score:.2f} / 100 - probability of the phishing class from the "
                               f"{ml_model or 'trained'} model."),
                    "value": round(ml_score, 2),
                },
                {
                    "step": "Weighted fusion",
                    "detail": (f"{heuristic_score:.2f} x {n_h:.2f} + {ml_score:.2f} x {n_m:.2f} "
                               f"= {final:.2f}"),
                    "value": round(final, 2),
                },
            ]

        classification = classify_score(final, self.bands)
        explanation.append({
            "step": "Classification",
            "detail": f"A final score of {final:.2f} falls in the {classification} band "
                      f"({self._band_range(classification)}).",
            "value": classification,
        })
        return RiskResult(
            heuristic_score=round(heuristic_score, 2),
            ml_score=round(ml_score, 2) if ml_score is not None and ml_available else None,
            ml_confidence=ml_confidence,
            ml_model=ml_model,
            final_score=round(final, 2),
            classification=classification,
            weights=used_weights,
            explanation=explanation,
            ml_available=bool(ml_available and ml_score is not None),
            notes=notes,
        )

    def _band_range(self, label: str) -> str:
        for name, low, high in self.bands:
            if name == label:
                return f"{low}-{high}"
        return "?"


risk_engine = RiskEngine()
