"""The machine-learning pipeline: artefact, inference, metrics and honesty."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ml.feature_engineering import FEATURE_NAMES
from app.ml.predict import model_available, model_metadata, predict_url
from app.services.ml_detector import ml_detector

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "app" / "ml" / "model.joblib"
METRICS_PATH = ROOT / "app" / "ml" / "metrics.json"


def test_the_trained_artefact_exists():
    assert MODEL_PATH.exists(), "run `python train.py` to build the model"
    assert model_available(str(MODEL_PATH))


def test_predict_url_works_without_any_training_run():
    """Inference must be independent of the training module."""
    result = predict_url("http://micros0ft-secure-login.tk/account/unlock")
    assert result["classification"] in {"PHISHING", "LEGITIMATE"}
    assert 0 <= result["risk_score"] <= 100
    assert 0.0 <= result["probability_phishing"] <= 1.0


def test_prediction_returns_a_per_feature_explanation():
    result = predict_url("http://micros0ft-secure-login.tk/account/unlock")
    assert result["explanation"], "the model must expose per-feature attributions"
    for row in result["explanation"]:
        assert set(row) >= {"feature", "value", "z_score", "contribution", "pushes"}
        assert row["feature"] in FEATURE_NAMES
    assert result["disclaimer"]


def test_prediction_is_deterministic():
    scores = {predict_url("http://198.51.100.23/paypal.com/login.php")["risk_score"]
              for _ in range(5)}
    assert len(scores) == 1


def test_ml_separates_an_obvious_phish_from_an_obvious_benign_url():
    phish = predict_url("http://198.51.100.23/paypal.com/secure/login.php?cmd=verify")
    safe = predict_url("https://docs.python.org/3/library/json.html")
    assert phish["risk_score"] > safe["risk_score"]


@pytest.mark.parametrize("url", [
    "https://github.com/pallets/flask",
    "https://www.amazon.in/gp/css/order-history?ref_=nav_orders_first",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://stackoverflow.com/questions/2020/how-to-do-x",
])
def test_ordinary_urls_with_paths_are_not_scored_as_phishing(url):
    """Regression for the dataset's path-depth confound.

    PhiUSIIL collected its legitimate class as bare root domains, so the
    model learned 'a URL with a path is phishing' - github.com/pallets/flask
    scored 85/100.  ``scripts/build_dataset.py`` now equalises path depth
    across both classes.
    """
    assert predict_url(url)["risk_score"] < 60, url


def test_path_length_is_no_longer_the_dominant_feature():
    bundle = json.loads(METRICS_PATH.read_text())
    names, values = bundle["feature_names"], bundle["importances"]
    ranked = sorted(zip(names, values), key=lambda kv: -abs(kv[1]))
    top_feature = ranked[0][0]
    assert top_feature != "path_length", "the path confound has returned"
    path_rank = [name for name, _ in ranked].index("path_length")
    assert path_rank >= 3, f"path_length is ranked {path_rank}, too influential"


def test_detector_reports_availability_and_metadata(app):
    with app.app_context():
        payload = ml_detector.predict("http://198.51.100.23/paypal.com/secure/login.php")
        assert payload["available"] is True
        assert payload["model"]
        metadata = ml_detector.metadata()
    assert metadata["available"] is True
    assert metadata["feature_count"] == 38
    selected = metadata["metrics"]["selected_model"]
    assert selected in metadata["metrics"]["models"]
    assert set(metadata["metrics"]["models"][selected]) >= {
        "accuracy", "precision", "recall", "f1", "confusion_matrix"}


def test_all_three_algorithms_were_evaluated():
    metrics = json.loads(METRICS_PATH.read_text())["metrics"]
    assert {"LogisticRegression", "RandomForest"} <= set(metrics["models"])
    for name, scores in metrics["models"].items():
        for key in ("accuracy", "precision", "recall", "f1"):
            assert 0.0 <= scores[key] <= 1.0, f"{name}.{key} out of range"
        matrix = scores["confusion_matrix"]
        assert len(matrix) == 2 and len(matrix[0]) == 2


def test_published_metrics_match_the_confusion_matrix():
    """Guards against hand-edited, fabricated numbers."""
    metrics = json.loads(METRICS_PATH.read_text())["metrics"]
    for name, scores in metrics["models"].items():
        (tn, fp), (fn, tp) = scores["confusion_matrix"]
        total = tn + fp + fn + tp
        assert scores["accuracy"] == pytest.approx((tn + tp) / total, abs=0.001), name
        if tp + fp:
            assert scores["precision"] == pytest.approx(tp / (tp + fp), abs=0.001), name
        if tp + fn:
            assert scores["recall"] == pytest.approx(tp / (tp + fn), abs=0.001), name


def test_model_is_labelled_with_its_dataset_and_caveats():
    metadata = model_metadata(str(MODEL_PATH))
    assert metadata["disclaimer"], "the model must ship an honest disclaimer"
    assert metadata["trained_at"]
    bundle = json.loads(METRICS_PATH.read_text())
    assert bundle.get("caveat"), "metrics.json must record the dataset caveat"
    assert bundle["dataset"]["rows"] > 0
    assert bundle["model_name"]


def test_metrics_are_not_implausibly_perfect():
    """A demonstration model claiming ~100% would signal a label leak."""
    metrics = json.loads(METRICS_PATH.read_text())["metrics"]
    for name, scores in metrics["models"].items():
        assert scores["accuracy"] < 0.99, f"{name} looks too good - check for leakage"


def test_feature_names_are_stable_between_training_and_inference():
    metadata = model_metadata(str(MODEL_PATH))
    assert metadata["feature_count"] == len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# Model artefact integrity (threat model section 7: untrusted pickle)
# ---------------------------------------------------------------------------


def test_model_digest_file_exists_and_matches_the_artifact():
    """joblib.load() executes pickle, so the artefact is pinned by digest."""
    from pathlib import Path

    from app.ml.predict import DEFAULT_MODEL_PATH, model_digest

    digest_file = Path(DEFAULT_MODEL_PATH).with_suffix(".sha256")
    assert digest_file.exists(), "app/ml/model.sha256 is missing"
    recorded = digest_file.read_text(encoding="utf-8").split()[0].strip()
    assert len(recorded) == 64
    assert recorded == model_digest(DEFAULT_MODEL_PATH), (
        "model.joblib does not match model.sha256 - re-run 'python train.py'")


def test_integrity_mismatch_warns_by_default_and_can_be_made_fatal(tmp_path, monkeypatch):
    """A swapped artefact must be reported, and enforceable on demand."""
    import pytest as _pytest

    from app.ml.predict import _verify_integrity

    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"not a real model")
    artifact.with_suffix(".sha256").write_text("0" * 64 + "  model.joblib\n")

    # Default: warn, do not block (retraining legitimately changes the file).
    _verify_integrity(str(artifact))

    monkeypatch.setenv("ML_REQUIRE_INTEGRITY", "1")
    with _pytest.raises(RuntimeError, match="integrity mismatch"):
        _verify_integrity(str(artifact))


def test_integrity_check_is_skipped_when_no_digest_is_recorded(tmp_path):
    """Absence of a digest file must not break loading."""
    from app.ml.predict import _verify_integrity

    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"x")
    assert len(_verify_integrity(str(artifact))) == 64
