#!/usr/bin/env python
"""Project-root entry point for training the PhishGuard URL model.

Equivalent to ``python -m app.ml.train``; provided because ``python train.py``
is the conventional command for this project layout.

    python train.py                      # train on data/datasets/url_dataset.csv
    python train.py --dataset other.csv  # train on a different labelled CSV
    python train.py --help               # full option list

The script performs the complete pipeline - load, clean, feature-extract,
split, train (Logistic Regression + Random Forest + Gradient Boosting),
evaluate, select and save - and writes two artefacts:

    app/ml/model.joblib   the serialised model bundle used at inference time
    app/ml/metrics.json   the honest held-out metrics published in the UI

Training is CPU-only and takes well under a minute on the bundled dataset.
"""

from __future__ import annotations

import sys

from app.ml.train import main

if __name__ == "__main__":
    sys.exit(main())
