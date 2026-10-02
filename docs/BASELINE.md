# PhishGuard — Baseline (pre-upgrade)

**Recorded:** 2026-10-01, before any Phase 2–30 modification.
**Purpose:** a measured snapshot to compare the upgrade against. Every number
below was produced by running the command shown. Nothing is estimated.

---

## 1. Existing features

| Area | What exists |
|---|---|
| **Auth** | Login/logout/registration, PBKDF2-SHA256 (600,000 iterations), account lockout (5 attempts / 15 min), generic error messages, disabled-account refusal, session cookie `phishguard_session` (HttpOnly, SameSite=Lax) |
| **RBAC** | 3 roles (ADMIN, ANALYST, DEMO_USER) with a capability matrix; `capability_required` decorator |
| **API keys** | SHA-256 digest storage, 8-char prefix, one-shot reveal at rotation, `X-API-Key` / `Bearer` auth |
| **Campaigns** | Create/list/detail/update/delete, 5 simulation templates, multi-target enrolment |
| **Simulation** | 4 event types only (`OPENED`, `LINK_CLICKED`, `TRAINING_PAGE_VIEWED`, `REPORTED`), per-target access tokens, educational landing page, **no credential collection** |
| **URL detection** | 24 heuristics + 38-feature ML model, hybrid scoring |
| **Email detection** | 35 heuristics across body/header/link signals, 5 scenario families |
| **Risk engine** | `final = 0.6·heuristic + 0.4·ml`, 4 bands from `config.RISK_BANDS` |
| **Dashboard** | 16 KPIs + 6 charts, all DB-derived |
| **Awareness** | Topic pages + a 10-question quiz with scoring |
| **Reports** | Campaign/analysis reports, CSV + PDF export |
| **Audit log** | 21 action constants, admin-only viewer with filtering |
| **REST API** | 53 routes total; JSON envelope `{success, data}` / `{success, error{code,message,status,title}}` |

Scale: **53 routes**, **10 blueprints**, **11 tables**, **31 templates**,
**12,108 Python LOC**, **2,854 template LOC**.

---

## 2. Current test count

```
$ pytest -q
252 passed in 14.61s
```

Zero failures, zero warnings (the 2 warnings seen under `--cov` come from the
coverage plugin, not the application).

| File | Tests |
|---|---:|
| `test_security.py` | 42 |
| `test_url_detector.py` | 37 |
| `test_api.py` | 35 |
| `test_authorization.py` | 35 |
| `test_campaigns.py` | 27 |
| `test_risk_engine.py` | 21 |
| `test_email_detector.py` | 20 |
| `test_auth.py` | 19 |
| `test_ml.py` | 16 |

---

## 3. Current coverage

```
$ pytest -q --cov=app
TOTAL    3278 statements    575 missed    82% coverage
```

Weakest modules:

| Module | Coverage |
|---|---:|
| `app/utils/decorators.py` | 53% |
| `app/utils/redaction.py` | 64% |
| `app/utils/formatting.py` | 68% |
| `app/utils/validators.py` | 70% |
| `app/routes/admin.py` | 70% |
| `app/services/ml_detector.py` | 73% |
| `app/services/report_service.py` | 73% |
| `app/routes/reports.py` | 77% |

At 100%: `services/indicators.py`, `services/awareness_content.py`,
`services/__init__.py`, `utils/__init__.py`.

---

## 4. Current ML metrics

Model: **HistGradientBoosting**, 349 KB, trained 2026-09-30T23:42:46+00:00,
38 features, `random_state=42`, `test_size=0.2`, 5-fold CV.

Dataset: 16,083 rows (8,137 phishing / 7,946 legitimate) from
`phiusiil-uci-balanced` 13,937 + `augmentation-phish` 1,200 +
`augmentation-benign` 946.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Confusion matrix |
|---|---|---|---|---|---|---|
| LogisticRegression | 0.8206 | 0.8972 | 0.7291 | 0.8045 | 0.8682 | `[[1453,136],[441,1187]]` |
| RandomForest | 0.8415 | 0.9465 | 0.7279 | 0.8229 | 0.8978 | `[[1522,67],[443,1185]]` |
| **GradientBoosting (selected)** | **0.8514** | **0.9444** | **0.7506** | **0.8364** | **0.8990** | `[[1517,72],[406,1222]]` |

Top permutation importances: `suspicious_tld` 0.155, `num_subdomains` 0.115,
`host_digit_ratio` 0.113, `hostname_length` 0.098, `has_www_in_subdomain`
0.094, `num_suspicious_keywords` 0.071.

**Gaps identified in `metrics.json`:** no `model_version`, no
`dataset_version`, and only a **two-way** train/test split (`train_test_split`
+ cross-validation on the training portion) — there is no held-out validation
set distinct from the test set, and splitting is **random at URL level**, not
grouped by registrable domain.

---

## 5. Existing security controls

```
$ flask security-check
18 checks - 17 passed, 1 warnings, 0 failures
```

The single warning is the placeholder dev `SECRET_KEY`; production refuses to
start with it (7 weak-secret classes rejected).

Verified present: CSRF on all state-changing posts · PBKDF2-SHA256 600,000 ·
account lockout · generic auth errors · CSP without `unsafe-inline` ·
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, `X-Frame-Options` · `Server: PhishGuard` (no
version disclosure) · HttpOnly/SameSite cookies · rate limiting · 1 MiB body
cap · ORM-only queries · audit redaction · SQLite `PRAGMA foreign_keys=ON` ·
hashed API keys · `.env` git-ignored and absent.

---

## 6. Known limitations at baseline

1. ML is a **demonstration model**; ~1 phishing URL in 4 is missed (406 FN of 1,628).
2. Detection is **string-level only** — no DNS, page fetch, TLS, WHOIS, reputation.
3. Known residual false positive: `portal.cybersafe.edu/password/renew` → MEDIUM.
4. Random (not group-aware) train/test split — likely optimistic.
5. No `model_version` / `dataset_version` in metadata.
6. No threat model document.
7. No request correlation IDs; logging is unstructured.
8. No detection decision trace exposed to the analyst.
9. No ML evaluation page in the UI.
10. No CI pipeline.
11. No MODEL_CARD / LIMITATIONS / DEPLOYMENT / DEMO_GUIDE documents.
12. No domain-intelligence layer (allow/deny/shortener lists are inline constants).
13. Docker Compose never booted in verification (no daemon available).
14. Coverage 82%; untested paths are mostly defensive branches.

---

## 7. Current architecture

```
Browser ──> Flask app factory (app/__init__.py)
              ├── 10 blueprints (53 routes)
              ├── Flask-Login + capability_required RBAC
              ├── CSRFProtect, Flask-Limiter, security headers
              └── error handlers 400/401/403/404/405/413/429/500 (+CSRFError)
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
     Services layer            app/ml/
     ├── url_analyzer          ├── feature_engineering (38 features)
     ├── email_analyzer        ├── train.py
     ├── risk_engine           ├── predict.py
     ├── ml_detector           └── model.joblib + metrics.json
     ├── campaign_service
     ├── report_service
     ├── indicators
     ├── awareness_content
     └── simulation_templates
                        │
                        ▼
              SQLAlchemy models (11 tables)
              users, campaigns, campaign_targets, simulation_events,
              url_analyses, email_analyses, awareness_quizzes,
              quiz_questions, quiz_attempts, reports, audit_logs
                        │
                        ▼
              SQLite (default) / PostgreSQL (Docker profile)
```

Layering rule already enforced: routes → services → models. Business logic
lives in services, not routes.

---

## 8. Baseline acceptance & frontend

```
$ python scripts/acceptance_check.py    →  21 passed, 0 failed  (exit 0)
$ python scripts/frontend_check.py      →  0 dead links, 0 orphan buttons,
                                            0 broken internal links (exit 0)
```

---

## 9. Baseline summary line

**252 tests · 82% coverage · 21/21 acceptance · 18 security checks (17 pass,
1 warn, 0 fail) · ML F1 0.8364 · 53 routes · 11 tables · 12,108 Python LOC.**
