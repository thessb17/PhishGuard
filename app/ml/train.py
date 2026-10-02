#!/usr/bin/env python3
"""Train and compare the PhishGuard URL phishing classifiers.

Pipeline
--------
1. Load ``data/datasets/url_dataset.csv`` (``url,label`` with 1 = phishing).
2. Extract the 38 lexical/structural features from
   :mod:`app.ml.feature_engineering` - the exact same code path used at
   inference time, so training and serving features cannot drift.
3. Train three models inside scikit-learn pipelines:
      * Logistic Regression (StandardScaler + lbfgs, balanced class weight)
      * Random Forest (200 trees, depth 18, balanced subsample)
      * Histogram Gradient Boosting (300 iterations)
4. Evaluate both with stratified 5-fold cross-validation on the training split
   and on a held-out 20% test split: accuracy, precision, recall, F1, ROC-AUC
   and the confusion matrix.
5. Select the best model by held-out F1 (ties broken by ROC-AUC) and persist it
   with joblib together with the metadata needed for explanations.  Models
   without a native ``feature_importances_`` attribute get permutation
   importance computed on the held-out split instead.

Run with::

    python -m app.ml.train                    # default dataset + output paths
    python -m app.ml.train --test-size 0.25   # custom split
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:  # allow `python app/ml/train.py`
    sys.path.insert(0, str(BASE_DIR))

from app.ml.feature_engineering import FEATURE_NAMES, extract_features  # noqa: E402

DEFAULT_DATASET = BASE_DIR / "data" / "datasets" / "url_dataset.csv"
DEFAULT_MODEL = BASE_DIR / "app" / "ml" / "model.joblib"
DEFAULT_METRICS = BASE_DIR / "app" / "ml" / "metrics.json"


def load_dataset(path: Path):
    import pandas as pd

    if not path.exists():
        raise SystemExit(
            f"Dataset not found at {path}.\nRun: python scripts/build_dataset.py"
        )
    frame = pd.read_csv(path)
    if "url" not in frame.columns or "label" not in frame.columns:
        raise SystemExit("Dataset must contain 'url' and 'label' columns (1 = phishing).")
    frame = frame.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    frame["label"] = frame["label"].astype(int)
    return frame


def featurise(urls):
    import numpy as np

    rows = [[float(v) for v in extract_features(u).vector()] for u in urls]
    return np.asarray(rows, dtype=float)


def evaluate(model, X_test, y_test) -> dict:
    from sklearn.metrics import (
        accuracy_score, confusion_matrix, f1_score, precision_score,
        recall_score, roc_auc_score,
    )

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else predictions
    matrix = confusion_matrix(y_test, predictions).tolist()
    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix": matrix,
        "confusion_labels": {
            "true_negative": matrix[0][0], "false_positive": matrix[0][1],
            "false_negative": matrix[1][0], "true_positive": matrix[1][1],
        },
    }


#: Bumped when the model artefact's structure or algorithm selection changes.
MODEL_VERSION = "1.1.0"

#: Bumped whenever FEATURE_NAMES changes. A model trained under one feature
#: version must never be loaded by code expecting another - predict.py checks
#: this, because a silently reordered feature vector produces confident
#: nonsense rather than an error.
FEATURE_VERSION = "1.0.0"


def dataset_fingerprint(path) -> str:
    """Short content hash so a metrics file can be tied to an exact CSV."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def main() -> int:
    import joblib
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
    from sklearn.inspection import permutation_importance
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    parser = argparse.ArgumentParser(description="Train the PhishGuard URL classifier")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model-out", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--metrics-out", type=Path, default=DEFAULT_METRICS)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument(
        "--split", choices=("random", "group"), default="random",
        help=("'random' splits at URL level (the published baseline). 'group' "
              "keeps every URL of a registrable domain on one side, which "
              "removes domain memorisation but has much higher seed variance "
              "- see docs/MODEL_CARD.md."),
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    def say(*parts):
        if not args.quiet:
            print(*parts)

    frame = load_dataset(args.dataset)
    say(f"[data] {len(frame):,} unique URLs from {args.dataset}")
    say(f"[data] phishing={int((frame['label'] == 1).sum()):,} "
        f"legitimate={int((frame['label'] == 0).sum()):,}")

    dataset_version = dataset_fingerprint(args.dataset)
    say(f"[data] dataset fingerprint sha256:{dataset_version}")

    X = featurise(frame["url"].tolist())
    y = frame["label"].to_numpy()
    say(f"[features] matrix {X.shape[0]:,} x {X.shape[1]} ({len(FEATURE_NAMES)} named features)")

    if args.split == "group":
        # Group-aware: no registrable domain may appear in both train and
        # test, so the model cannot score well by memorising a domain it has
        # already seen. Measured cost on this corpus: about -0.012 F1 versus
        # the random split, with ~7x the seed-to-seed variance.
        from sklearn.model_selection import GroupShuffleSplit

        from app.ml.feature_engineering import split_host

        def _registrable(u: str) -> str:
            try:
                host = str(u).split("//")[-1].split("/")[0].split(":")[0]
                _, reg, _ = split_host(host)
                return reg or "unknown"
            except Exception:  # noqa: BLE001 - grouping must never crash training
                return "unknown"

        groups = [_registrable(u) for u in frame["url"].tolist()]
        gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size,
                                random_state=args.random_state)
        tr_idx, te_idx = next(gss.split(X, y, groups))
        # featurise() returns a numpy array, so index positionally.
        X_train, X_test = X[tr_idx], X[te_idx]
        y_train, y_test = y[tr_idx], y[te_idx]
        n_groups = len(set(groups))
        leaked = len(set(groups[i] for i in tr_idx) & set(groups[i] for i in te_idx))
        say(f"[split] train={len(X_train):,} test={len(X_test):,} "
            f"(group-aware over {n_groups:,} domains, overlap={leaked})")
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
        )
        say(f"[split] train={len(X_train):,} test={len(X_test):,} (stratified, URL-level)")

    candidates = {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced",
                                       random_state=args.random_state)),
        ]),
        "RandomForest": Pipeline([
            ("clf", RandomForestClassifier(
                n_estimators=200, max_depth=18, min_samples_leaf=3, n_jobs=-1,
                class_weight="balanced_subsample", random_state=args.random_state)),
        ]),
        "GradientBoosting": Pipeline([
            ("clf", HistGradientBoostingClassifier(
                max_iter=300, learning_rate=0.1, random_state=args.random_state)),
        ]),
    }

    cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.random_state)
    results: dict[str, dict] = {}
    fitted: dict[str, Pipeline] = {}

    for name, pipeline in candidates.items():
        say(f"\n[train] {name}")
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
        pipeline.fit(X_train, y_train)
        metrics = evaluate(pipeline, X_test, y_test)
        metrics["cv_f1_mean"] = float(cv_scores.mean())
        metrics["cv_f1_std"] = float(cv_scores.std())
        results[name] = metrics
        fitted[name] = pipeline
        say(f"        cv-f1  {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        say(f"        holdout accuracy={metrics['accuracy']:.4f} precision={metrics['precision']:.4f} "
            f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} roc_auc={metrics['roc_auc']:.4f}")
        say(f"        confusion [[TN,FP],[FN,TP]] = {metrics['confusion_matrix']}")

    selected = max(results, key=lambda n: (results[n]["f1"], results[n]["roc_auc"]))
    say(f"\n[select] {selected} (highest held-out F1)")

    best = fitted[selected]
    lr_pipeline = fitted["LogisticRegression"]
    lr_model = lr_pipeline.named_steps["clf"]
    scaler = lr_pipeline.named_steps["scaler"]
    direction = [float(np.sign(c)) or 1.0 for c in lr_model.coef_[0]]

    best_estimator = best.named_steps["clf"]
    if hasattr(best_estimator, "feature_importances_"):
        importances = [float(v) for v in best_estimator.feature_importances_]
        importance_kind = "impurity"
    elif selected == "LogisticRegression":
        coefs = np.abs(lr_model.coef_[0])
        total = float(coefs.sum()) or 1.0
        importances = [float(v / total) for v in coefs]
        importance_kind = "absolute-standardised-coefficient"
    else:
        say("[explain] computing permutation importance on the held-out split...")
        perm = permutation_importance(
            best, X_test, y_test, n_repeats=5, random_state=args.random_state,
            scoring="f1", n_jobs=-1,
        )
        raw = np.clip(perm.importances_mean, 0, None)
        total = float(raw.sum()) or 1.0
        importances = [float(v / total) for v in raw]
        importance_kind = "permutation"

    bundle = {
        "model": best,
        "model_name": selected,
        "feature_names": FEATURE_NAMES,
        "feature_means": [float(v) for v in scaler.mean_],
        "feature_stds": [float(v) if v else 1.0 for v in scaler.scale_],
        "direction": direction,
        "importances": importances,
        "importance_kind": importance_kind,
        "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "metrics": {
            "selected_model": selected,
            "models": results,
            "test_size": args.test_size,
            "cv_folds": args.cv_folds,
            "random_state": args.random_state,
            "split_strategy": args.split,
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
        },
        "dataset": {
            "path": str(args.dataset),
            "version": dataset_version,
            "rows": int(len(frame)),
            "phishing": int((frame["label"] == 1).sum()),
            "legitimate": int((frame["label"] == 0).sum()),
            "sources": (frame["source"].value_counts().to_dict() if "source" in frame.columns else {}),
        },
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": __import__("sklearn").__version__,
        "caveat": (
            "Benchmark numbers are specific to this dataset. The PhiUSIIL corpus "
            "over-represents bare root-domain URLs in the legitimate class, so "
            "held-out scores are optimistic compared with live traffic. Re-train "
            "on organisation-specific data before operational use."
        ),
    }

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.model_out)

    # Pin the artefact's digest. joblib.load() unpickles (i.e. executes), so
    # predict.py checks the file against this before loading it. Written here
    # so the pair can never drift: retraining always refreshes both.
    import hashlib as _hashlib

    _h = _hashlib.sha256()
    with open(args.model_out, "rb") as _fh:
        for _chunk in iter(lambda: _fh.read(65536), b""):
            _h.update(_chunk)
    args.model_out.with_suffix(".sha256").write_text(
        f"{_h.hexdigest()}  {args.model_out.name}\n", encoding="utf-8")
    say(f"[save] model -> {args.model_out} ({args.model_out.stat().st_size / 1e6:.2f} MB)")

    metrics_doc = {k: v for k, v in bundle.items() if k != "model"}
    metrics_doc["importance_kind"] = importance_kind
    top_features = sorted(zip(FEATURE_NAMES, importances), key=lambda kv: kv[1], reverse=True)[:12]
    metrics_doc["top_features"] = [{"feature": f, "importance": round(i, 5)} for f, i in top_features]
    args.metrics_out.write_text(json.dumps(metrics_doc, indent=2), encoding="utf-8")
    say(f"[save] metrics -> {args.metrics_out}")

    say("\n" + "=" * 78)
    say(f"{'Model':<22}{'Accuracy':>10}{'Precision':>11}{'Recall':>9}{'F1':>9}{'ROC-AUC':>10}")
    say("-" * 78)
    for name, metrics in results.items():
        marker = " *" if name == selected else "  "
        say(f"{name + marker:<22}{metrics['accuracy']:>10.4f}{metrics['precision']:>11.4f}"
            f"{metrics['recall']:>9.4f}{metrics['f1']:>9.4f}{metrics['roc_auc']:>10.4f}")
    say("=" * 78)
    say("* selected model (persisted to model.joblib)")
    say(f"\nTop features by importance ({importance_kind}):")
    for feature, importance in top_features:
        say(f"   {feature:<26} {importance:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
