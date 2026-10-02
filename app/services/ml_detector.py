"""Application-facing wrapper around the ML URL classifier.

Adds Flask configuration awareness and graceful degradation: if the model
artefact is missing or fails to load, detection continues with rule-based
analysis only and the UI/API say so explicitly.
"""

from __future__ import annotations

import logging

from flask import current_app

from app.ml.predict import ModelNotAvailable, model_metadata, predict_url

logger = logging.getLogger(__name__)


class MLDetector:
    """Thin service object so views/tests can swap the implementation."""

    def _model_path(self) -> str | None:
        try:
            if not current_app.config.get("ML_ENABLED", True):
                return None
            return current_app.config.get("ML_MODEL_PATH")
        except RuntimeError:
            return None

    def enabled(self) -> bool:
        try:
            return bool(current_app.config.get("ML_ENABLED", True))
        except RuntimeError:
            return True

    def predict(self, url: str) -> dict:
        """Return an ML verdict, or ``{"available": False, ...}`` on failure."""
        if not self.enabled():
            return {"available": False, "reason": "ML_ENABLED is false in the current configuration."}
        try:
            result = predict_url(url, self._model_path())
            result["available"] = True
            return result
        except ModelNotAvailable as exc:
            logger.warning("ML model unavailable: %s", exc)
            return {"available": False, "reason": str(exc)}
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("ML prediction failed")
            return {"available": False, "reason": f"Prediction failed: {exc.__class__.__name__}"}

    #: Shown next to every model figure so that benchmark numbers are never
    #: presented as a guarantee about unseen traffic.
    DISCLAIMER = (
        "Model metrics were measured on a held-out split of the bundled dataset. "
        "They describe performance on data resembling that dataset only and do not "
        "guarantee accuracy on live traffic. The classifier produces false positives "
        "and false negatives; treat its score as one input to a human decision."
    )

    def metadata(self) -> dict:
        if not self.enabled():
            return {"available": False, "reason": "ML disabled by configuration.",
                    "disclaimer": self.DISCLAIMER}
        try:
            payload = model_metadata(self._model_path())
        except Exception:  # pragma: no cover - defensive
            return {"available": False, "reason": "Model bundle could not be read.",
                    "disclaimer": self.DISCLAIMER}
        payload.setdefault("disclaimer", self.DISCLAIMER)
        return payload


ml_detector = MLDetector()
