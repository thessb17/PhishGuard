# Model Card — PhishGuard URL Classifier

Following the Mitchell et al. (2019) model-card format. Every number here was
produced by running `python train.py` and the comparison scripts described
below. Nothing is estimated.

| | |
|---|---|
| **Model name** | PhishGuard URL Classifier |
| **Model version** | 1.1.0 |
| **Feature version** | 1.0.0 |
| **Algorithm** | `HistGradientBoostingClassifier` (scikit-learn 1.6.1) |
| **Artifact** | `app/ml/model.joblib` (349 KB) + `app/ml/metrics.json` |
| **Dataset version** | `sha256:9ae3b72046679547` (first 16 hex of the CSV digest) |
| **Random seed** | 42 (fixed; training is deterministic) |
| **Trained** | 2026-10-01 |

---

## 1. Model purpose

Score a URL string for phishing risk, as **one of two inputs** to a hybrid
risk engine (the other being 24 hand-written heuristics). The final verdict is
`0.6 × heuristic + 0.4 × ML`, so the model never decides alone.

It exists to demonstrate a complete, honest ML pipeline inside a defensive
security training platform: load → clean → feature-engineer → split → train →
evaluate → persist → predict, with the evaluation reported truthfully.

**It is a demonstration model, not a threat-intelligence product.**

---

## 2. Dataset

| | |
|---|---|
| **Source** | PhiUSIIL Phishing URL Dataset (UCI ML Repository ID 967, Prasad & Chandra 2024, CC BY 4.0) plus a generated augmentation corpus |
| **Rows** | 16,083 (8,137 phishing / 7,946 legitimate) |
| **Composition** | `phiusiil-uci-balanced` 13,937 · `augmentation-phish` 1,200 · `augmentation-benign` 946 |
| **Unique registrable domains** | 11,910 |
| **Rebuild** | `python scripts/build_dataset.py` (downloads ~15 MB once) |

### Two collection artefacts we found and corrected

Both were discovered by inspecting what the model had actually learned, and
both are corrected the same way — by neutralising a surface attribute in
**both** classes so it can no longer carry label information. `--no-balance`
reproduces the raw corpus for teaching.

**Artefact 1 — the HTTPS leak.** 100% of upstream legitimate URLs begin
`https://www.`, against 48.7% of phishing URLs. Training on the raw corpus
gave a bogus **99.7% accuracy** driven by `is_https`: the model had learned
"http ⇒ phishing", the exact misconception this platform teaches against.

**Artefact 2 — the path-depth leak.** PhiUSIIL collected legitimate sites as
bare registered domains (85% with no path) and phishing sites live with deep
paths (62% with a path). `path_length` became the single strongest feature
(permutation importance 0.276) and the model scored ordinary URLs as phishing:

| URL | ML score before | after |
|---|---:|---:|
| `github.com/pallets/flask` | 85.1 | 24.8 |
| `mail.google.com/mail/u/0/#inbox` | 99.2 | 47.8 |
| `amazon.in/gp/css/order-history` | 97.1 | 4.6 |

After `balance_path_depth()`, `path_length` importance fell to **0.028**
(rank 12).

**Honest cost of both corrections: accuracy 0.8857 → 0.8514, F1 0.8755 →
0.8364.** The earlier numbers were partly measuring collection artefacts.

---

## 3. Features

38 features, all computed from the URL **string only**. No DNS, no page fetch,
no WHOIS, no reputation feed — which also means the feature extractor cannot
be abused to make the server contact an attacker-chosen host.

| Group | Features |
|---|---|
| **Lexical** | `url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length`, `num_dots`, `num_hyphens`, `num_at`, `num_question`, `num_equals`, `num_ampersand`, `num_underscore`, `num_slash`, `num_percent`, `num_digits`, `digit_ratio`, `longest_token_length`, `double_slash_in_path`, `num_query_params`, `has_hex_encoding`, `num_non_ascii` |
| **Hostname** | `host_digit_ratio`, `num_subdomains`, `has_ip`, `has_punycode`, `host_entropy`, `tld_length`, `host_hyphens`, `has_www_in_subdomain`, `suspicious_tld`, `is_shortener` |
| **Protocol** | `is_https`, `has_port` |
| **Semantic** | `num_suspicious_keywords`, `brand_in_subdomain`, `brand_in_path`, `brand_mismatch`, `path_entropy` |

Top permutation importances in the shipped model:

| Feature | Importance |
|---|---:|
| `suspicious_tld` | 0.155 |
| `num_subdomains` | 0.115 |
| `host_digit_ratio` | 0.113 |
| `hostname_length` | 0.098 |
| `has_www_in_subdomain` | 0.094 |
| `num_suspicious_keywords` | 0.071 |

`feature_version` is recorded in the artifact. A model trained under one
feature version must not be loaded by code expecting another — a silently
reordered feature vector produces confident nonsense rather than an error.

---

## 4. Training

```bash
python train.py                  # random (URL-level) split - the published baseline
python train.py --split group    # group-aware split, grouped by registrable domain
```

Three candidates are trained and compared; the highest held-out F1 ships.

| | |
|---|---|
| Split | 80 / 20 stratified, `random_state=42` → 12,866 train / 3,217 test |
| Cross-validation | Stratified 5-fold on the training split |
| Class imbalance | `class_weight="balanced"` (LogReg, RF) |
| Determinism | Fully seeded — CI retrains and asserts the metrics reproduce to 1e-4 |

---

## 5. Evaluation

Held-out test set, n = 3,217 (1,589 legitimate / 1,628 phishing):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | 5-fold CV F1 |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.8206 | 0.8972 | 0.7291 | 0.8045 | 0.8682 | 0.806 ± 0.008 |
| Random Forest (200, d18) | 0.8415 | 0.9465 | 0.7279 | 0.8229 | 0.8978 | 0.814 ± 0.006 |
| **HistGradientBoosting — shipped** | **0.8514** | **0.9444** | **0.7506** | **0.8364** | **0.8990** | **0.830 ± 0.006** |

Confusion matrix of the shipped model:

|  | predicted legitimate | predicted phishing |
|---|---|---|
| **actually legitimate** | 1,517 (TN) | **72 (FP)** |
| **actually phishing** | **406 (FN)** | 1,222 (TP) |

### Random vs group-aware splitting

Random URL-level splitting lets the same registrable domain appear in both
train and test, so part of the test score can be memorisation rather than
generalisation. We measured it across **5 seeds** (42, 7, 13, 2024, 99):

| Split | Accuracy | F1 | ROC-AUC | Train/test domain overlap |
|---|---|---|---|---|
| Random (URL-level) | 0.8505 ± 0.0042 | 0.8372 ± 0.0053 | 0.8969 | ~219 domains |
| Group-aware (by domain) | 0.8450 ± 0.0147 | 0.8255 ± 0.0374 | 0.8907 | 0 |

**Findings, stated plainly:**

1. The random split is optimistic by **+0.0055 accuracy / +0.0117 F1**. The
   effect is real but small, because only 28.4% of rows share a registrable
   domain with another row (11,910 unique domains across 16,083 URLs).
2. The group-aware split has roughly **7× the seed-to-seed variance**
   (F1 std 0.0374 vs 0.0053), because large domain groups land entirely on
   one side of the split.
3. **A single-seed comparison would have given the wrong answer.** At seed 42
   alone, the group split scored *higher* (F1 0.8589 vs 0.8364). Only
   averaging over seeds revealed the true direction. This is recorded because
   it is the kind of mistake that is easy to make and easy to hide.

The shipped artifact uses the random split so the headline numbers stay
comparable with the earlier documented baseline; `--split group` is available
and the honest correction (−0.012 F1) is published here rather than buried.

---

## 6. Limitations

1. **It misses roughly one phishing URL in four** (406 false negatives of
   1,628 on its own held-out split).
2. **It produces false positives** — 72 of 1,589 legitimate URLs flagged.
3. **Dataset-bound.** Metrics describe this corpus. Live traffic has a
   different distribution and will score differently.
4. **String-level only.** A phishing page on a compromised high-reputation
   domain with a short clean URL is invisible to it.
5. **No temporal validation.** The corpus is a snapshot; phishing URL
   fashions drift, and no time-based holdout was performed.
6. **Not adversarially robust.** An attacker who reads this card can
   construct URLs that score low.

---

## 7. Potential bias

* **Brand coverage bias.** The brand dictionary is weighted toward large
  English-language Western brands, so impersonation of regional or
  non-English brands is less likely to be caught.
* **TLD bias.** `suspicious_tld` is the single strongest feature. Legitimate
  organisations on `.xyz`, `.top` or `.work` are penalised for their
  registrar choice, which is a structural unfairness, not a judgement about
  them.
* **Language bias.** The suspicious-keyword list is English. Non-English
  phishing is under-detected.
* **Length and structure bias.** Long URLs with many parameters score higher;
  some legitimate applications (analytics, SSO redirects) look like this
  routinely.
* **Corpus recency bias.** PhiUSIIL reflects the period it was collected in.

---

## 8. False positives and false negatives

**Measured on the held-out split:** FP 72/1,589 (4.5% of legitimate),
FN 406/1,628 (24.9% of phishing).

**Known residual false-positive pattern:** a credential-reset path on an
unfamiliar domain — `portal.cybersafe.edu/password/renew` previously scored
~41.7 (MEDIUM). Adding the organisation's own domain to
`data/intel/allowlist.txt` reduced it to **5.0**. This is the intended way to
tune the platform for a deployment.

**Known false-negative pattern:** a short, clean URL on a compromised
legitimate domain — e.g. `https://well-known-site.example/x` serving a
phishing kit. Nothing in the URL string gives it away.

---

## 9. Intended use

* Teaching how phishing detection works, and where it fails.
* Triage support: ordering which URLs a human looks at first.
* Demonstrating a reproducible ML pipeline with honest evaluation.
* A base to re-train on organisation-specific data.

---

## 10. Prohibited use

* **As an automated block/allow decision** without human review.
* **As evidence** that a URL is safe. A LOW score means "no signal found",
  not "verified benign".
* **For disciplinary action** against individuals — neither this model nor
  the awareness score may be used punitively.
* **In production security controls** without re-training, validation on
  representative traffic, and ongoing monitoring.
* **To justify a claim of "AI-powered phishing protection".** It is a
  gradient-boosting classifier over 38 lexical features with a published 85%
  accuracy on its own benchmark.

---

## 11. Reproducing these numbers

```bash
pip install -r requirements.txt
python train.py                   # rewrites model.joblib + metrics.json
python -c "import json; print(json.load(open('app/ml/metrics.json'))['metrics']['models'])"
```

Training is seeded; the CI pipeline retrains on every push and fails if any
metric drifts by more than 1e-4 from the committed values.
