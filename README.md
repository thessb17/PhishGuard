<div align="center">

# 🛡️ PhishGuard

**Developed by:** Sabyasachi Bhowmik  
**Institution:** Andhra University  
**Department:** Department of Computer Science and Systems Engineering  
**Project:** Internship — Phishing Attack Simulation and Detection

### Phishing Attack Simulation and Detection Platform

**A defensive cybersecurity training platform — safe phishing simulation, explainable
URL & email detection, a hybrid rule + machine-learning risk engine, security-awareness
training and a SOC-style analytics dashboard.**

`Flask 3` · `SQLAlchemy 2` · `scikit-learn 1.6` · `Chart.js 4` · `Bootstrap 5`
`252 tests passed in the release verification` · `82 % statement coverage` · `0 hardcoded production secrets`

</div>

---

> ### ⚠️ Safety statement — read first
>
> PhishGuard is **defensive**. It **never collects, stores, transmits or logs a real
> password, token, banking detail or any other credential.** The simulated phishing
> message has **no login form and no password field anywhere** — clicking its link
> leads straight to an awareness page that explains why the message was detectable.
> Only four interaction verbs are ever recorded: `OPENED`, `LINK_CLICKED`,
> `TRAINING_PAGE_VIEWED`, `REPORTED`. No real email is sent, no external target is
> ever contacted, and every organization and person in the demo is fictional.
> See **[SECURITY.md](SECURITY.md)** for the full policy.

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [Screens & features](#2-screens--features)
3. [Project structure](#3-project-structure)
4. [Quick start](#4-quick-start)
5. [Demo credentials](#5-demo-credentials)
6. [Database initialisation](#6-database-initialisation)
7. [Machine-learning pipeline](#7-machine-learning-pipeline)
8. [Running the tests](#8-running-the-tests)
9. [Docker](#9-docker)
10. [15-step demonstration script](#10-15-step-demonstration-script)
11. [How to present this in an internship review](#11-how-to-present-this-in-an-internship-review)
12. [Security controls implemented](#12-security-controls-implemented)
13. [Known limitations](#13-known-limitations)
14. [Future enhancements](#14-future-enhancements)
15. [Configuration reference](#15-configuration-reference)
16. [Troubleshooting](#16-troubleshooting)
17. [Portfolio screenshots](#17-portfolio-screenshots)
18. [Submission checklist](#18-submission-checklist)
19. [Credits & licence](#19-credits--licence)

---

## Project identity

See [PROJECT_IDENTITY.md](PROJECT_IDENTITY.md) for the developer, institution and project details.

## 1. What it does

| Module | Summary |
|---|---|
| **Phishing simulation** | 5 realistic but harmless templates (password expiry, delivery notification, HR policy, IT security alert, account verification) delivered to an in-app inbox. Every template ships with the red flags it demonstrates and the teaching points for the debrief. |
| **Campaign manager** | Create, launch, pause, complete and delete exercises. Per-campaign funnel, timeline, per-participant breakdown and an awareness score. |
| **URL detector** | 24 weighted heuristics (raw-IP host, punycode/homograph, brand look-alikes by edit distance, suspicious TLDs, shorteners, `@` tricks, deep subdomain nesting, hex encoding, credential keywords, …), each with points, evidence and a recommendation. |
| **Email detector** | Sender, subject, body, embedded links and raw headers — including SPF, DKIM, DMARC verdicts, Reply-To / Return-Path mismatch and Received-chain analysis. |
| **ML pipeline** | 38 engineered URL features; Logistic Regression vs Random Forest vs Histogram Gradient Boosting compared on accuracy / precision / recall / F1 / ROC-AUC / confusion matrix; the winner ships as a 349 KB `joblib` bundle with per-feature z-score attributions. |
| **Hybrid risk engine** | `final = 0.6 × heuristic + 0.4 × ML` (both weights configurable), banded LOW / MEDIUM / HIGH / CRITICAL with a step-by-step explanation of how the number was produced. |
| **Awareness training** | 12 modules (phishing types, spear phishing, smishing, vishing, BEC, credential phishing, QR phishing, link inspection, sender inspection, MFA safety, reporting) plus a 10-question assessment where **every** answer is explained. |
| **SOC dashboard** | 8 KPI tiles and 6 Chart.js charts: 14-day event activity, risk distribution, model accuracy comparison, campaign performance, detection split, awareness improvement. |
| **Reporting** | Campaign and detection reports exportable as **CSV, PDF and JSON**, each carrying an explicit limitations section. |
| **Audit & RBAC** | Append-only audit trail with an admin viewer; three roles (Administrator / Security Analyst / Demo User) enforced by a server-side capability matrix. |
| **REST API** | 13 JSON endpoints with API-key or session auth, a consistent success/error envelope and rate limits. |

---

## 1a. Documentation map

| Document | What it covers |
|---|---|
| `docs/BASELINE.md` | Measured snapshot before the portfolio upgrade — the comparison point |
| `docs/THREAT_MODEL.md` | STRIDE model across 12 components, with existing vs proposed mitigations |
| `docs/MODEL_CARD.md` | Model purpose, dataset, features, evaluation, bias, prohibited use |
| `docs/LIMITATIONS.md` | Everything this project does **not** do, including unverified areas |
| `docs/ARCHITECTURE.md` | Layering, data model, retention, ML pipeline, front-end |
| `docs/API.md` | REST contract, auth, error slugs, rate limits |
| `docs/DEPLOYMENT.md` | Local / production / Docker, with verification status per path |
| `docs/DEMO_GUIDE.md` | 10-minute evaluator walkthrough |
| `SECURITY.md` | Safety invariant, implemented controls, responsible use |
| `AUDIT_REPORT.md` | Engineering audit: bugs found and fixed |
| `RELEASE_READINESS_REPORT.md` | Release pass: artifacts, secrets, hashed keys |
| `docs/FINAL_QUALITY_REPORT.md` | Portfolio upgrade: what changed and what was measured |

---

## 2. Screens & features

| Route | What you see |
|---|---|
| `/login` | Sign-in with the demo credentials listed on the page, lockout and rate limiting behind it. |
| `/dashboard` | 8 KPIs, 6 charts, recent campaigns / events / analyses, "needs training" chips, audit tail. |
| `/campaigns` | Campaign list with status filter, pagination and the template gallery. |
| `/campaigns/create` | Template picker, participant table with select-all and filter, safety-guarantee panel. |
| `/campaigns/<id>` | Funnel + timeline charts, per-participant breakdown, status control, report generation. |
| `/simulator` | The participant's simulated inbox and their own recorded events. |
| `/simulator/message/<token>` | The mock phishing message — **no inputs**, with *Report* and *follow the link* buttons. |
| `/simulator/landing/<token>` | The awareness page: red flags, teaching points, how to report. |
| `/url-detector` | Analyse a URL; sample chips for one-click demos; parsed structure, indicators, feature vector, ML panel. |
| `/email-detector` | Paste sender/subject/body/headers, or load a phishing / legitimate sample. |
| `/awareness`, `/quiz` | 12 training modules and the 10-question assessment with explanations. |
| `/reports` | Generated reports with CSV / PDF / JSON export. |
| `/audit-logs`, `/users` | Admin-only audit viewer and role/account management. |
| `/profile` | Your role's capabilities, password change, API-key rotation, your own event history. |

---

## 3. Project structure

```
phishguard/
├── app/
│   ├── __init__.py                 # application factory, error handlers, CLI, security headers
│   ├── config.py                   # Development / Testing / Production profiles
│   ├── extensions.py               # db, migrate, login_manager, csrf, limiter
│   ├── forms.py                    # 8 WTForms definitions with server-side validation
│   │
│   ├── models/                     # SQLAlchemy ORM — 11 tables
│   │   ├── user.py                 #   User + Role capability matrix + lockout logic
│   │   ├── campaign.py             #   Campaign, CampaignTarget (SIM-id + access token)
│   │   ├── simulation.py           #   SimulationEvent + the 4 permitted event types
│   │   ├── url_analysis.py         #   stored URL verdicts
│   │   ├── email_analysis.py       #   stored email verdicts (redacted body excerpt)
│   │   ├── quiz.py                 #   AwarenessQuiz, QuizQuestion, QuizAttempt
│   │   ├── report.py               #   Report + ReportType
│   │   └── audit_log.py            #   AuditLog + AuditAction catalogue
│   │
│   ├── services/                   # business logic (Flask-free)
│   │   ├── indicators.py           #   Indicator / Severity primitives
│   │   ├── url_analyzer.py         #   24 URL heuristics
│   │   ├── email_analyzer.py       #   35 email heuristics (sender/subject/body/links/headers)
│   │   ├── risk_engine.py          #   hybrid fusion + bands + recommendations
│   │   ├── ml_detector.py          #   Flask-aware wrapper around the model bundle
│   │   ├── campaign_service.py     #   campaign creation, events, stats, dashboard aggregates
│   │   ├── report_service.py       #   payload builders + CSV / PDF / JSON exporters
│   │   ├── simulation_templates.py #   the 5 safe phishing templates
│   │   └── awareness_content.py    #   12 training modules + 10 quiz questions
│   │
│   ├── ml/
│   │   ├── feature_engineering.py  #   38 ordered URL features
│   │   ├── train.py                #   3-model comparison + permutation importance
│   │   ├── predict.py              #   scoring + z-score attributions
│   │   ├── model.joblib            #   trained bundle (349 KB)
│   │   └── metrics.json            #   full benchmark record
│   │
│   ├── routes/                     # 10 blueprints, 53 routes
│   │   ├── auth.py  dashboard.py  campaigns.py  simulator.py
│   │   ├── url_detector.py  email_detector.py  awareness.py
│   │   └── reports.py  admin.py  api.py
│   │
│   ├── utils/
│   │   ├── security.py  decorators.py  validators.py
│   │   └── redaction.py  audit.py  formatting.py
│   │
│   ├── templates/                  # 31 Jinja2 templates
│   │   ├── base.html  base_public.html
│   │   ├── partials/ (sidebar, macros)   errors/error.html
│   │   ├── auth/ (login, register, profile)
│   │   ├── dashboard/  campaigns/  simulator/
│   │   ├── detectors/  awareness/  reports/  admin/
│   │
│   └── static/
│       ├── css/phishguard.css      # 408-line SOC dark theme
│       ├── js/ (app, dashboard, campaign, detector).js   # CSP-safe, no inline script
│       ├── img/ (logo.svg, favicon.svg)
│       └── vendor/                 # Bootstrap 5.3.3, Chart.js 4.4.3, Bootstrap Icons 1.11.3
│
├── scripts/
│   ├── seed_database.py            # fictional demo data (18 users, 5 campaigns, …)
│   ├── build_dataset.py            # dataset builder with confound balancing
│   ├── security_check.py           # 18-point configuration checklist
│   ├── setup.py                    # one-command bootstrap (install + seed + run)
│   ├── acceptance_check.py         # 21-step end-to-end run against a live server
│   └── frontend_check.py           # crawls 14 pages for dead buttons/links
│
├── tests/                          # 407 tests in 11 modules
│   ├── conftest.py
│   ├── test_auth.py                # 19
│   ├── test_authorization.py       # 35
│   ├── test_url_detector.py        # 37
│   ├── test_email_detector.py      # 20
│   ├── test_risk_engine.py         # 21
│   ├── test_ml.py                  # 16
│   ├── test_campaigns.py           # 27
│   ├── test_api.py                 # 35
│   ├── test_security.py            # 42
│   ├── test_detection_intel.py     # 47
│   └── test_edge_cases.py          # 43
│
├── data/
│   ├── datasets/url_dataset.csv    # 16,083 labelled URLs
│   ├── sample_emails/              # fictional messages for the demo
│   └── sample_urls/                # phishing / legitimate sample lists
│
├── migrations/                     # Alembic (initial schema migration included)
├── docs/
│   ├── ARCHITECTURE.md  API.md  architecture.svg
├── instance/                       # SQLite database + log file (git-ignored)
│
├── run.py                          # entry point
├── requirements.txt   pytest.ini   .env.example   .gitignore
├── Dockerfile   docker-compose.yml   docker-entrypoint.sh   .dockerignore
└── README.md   SECURITY.md
```

---

## 4. Quick start

### Requirements
Python **3.11+** (developed and tested on 3.13), ~400 MB disk for dependencies.
No internet access is needed at runtime — the front-end is vendored and the
model is pre-trained.

### Fastest path (any platform)

```bash
python -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
python scripts/setup.py --run
```

`setup.py` checks the interpreter, installs anything missing from
`requirements.txt`, seeds the demo database if absent, prints the demo
credentials, and with `--run` starts the server. It is idempotent, echoes
every command it runs, and never hides a step.

```bash
python scripts/setup.py --check    # report status, change nothing
python scripts/setup.py --reset    # rebuild the demo data
```

The manual steps below do exactly the same thing, one command at a time.

### Linux / macOS / WSL

```bash
git clone <your-repo-url> phishguard && cd phishguard

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env

python scripts/seed_database.py
python run.py
```

### Windows (PowerShell)

```powershell
git clone <your-repo-url> phishguard; cd phishguard

python -m venv venv
venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

copy .env.example .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env

python scripts\seed_database.py
python run.py
```

> If PowerShell blocks the activation script:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

Then open **<http://127.0.0.1:5000/>** and sign in with the credentials below.

To listen on another address/port: `HOST=0.0.0.0 PORT=8000 python run.py`.

---

## 5. Demo credentials

All accounts are **fictional** and exist only in your local database.

| Role | Username | Password | Can do |
|---|---|---|---|
| **Administrator** | `admin` | `Admin@Phish2026` | Everything: campaigns, detectors, reports, audit log, user management |
| **Security Analyst** | `analyst` | `Analyst@Phish2026` | Campaigns, detectors, reports — no user management, no audit log |
| **Demo User** | `priya.demo` | `Demo@Phish2026` | Receives simulations, takes training — sees only their own data |

15 further demo participants (`liam.demo`, `sofia.demo`, `kenji.demo`,
`amara.demo`, `tomas.demo`, `hana.demo`, `marcus.demo`, `elena.demo`,
`dmitri.demo`, `grace.demo`, `noor.demo`, `felix.demo`, `yuki.demo`,
`olivia.demo`) and a second analyst (`nadia.analyst`) all use
`Demo@Phish2026` / `Analyst@Phish2026`.

**Change these before any shared deployment.**

---

## 6. Database initialisation

The seeder creates the schema if it does not exist, so the quick-start command
is all you normally need.

```bash
python scripts/seed_database.py             # create tables + fictional demo data
python scripts/seed_database.py --reset     # DROP everything, then re-seed
python scripts/seed_database.py --quiet     # no progress output (used by Docker)
```

Equivalent Flask CLI commands:

```bash
export FLASK_APP=run.py            # Windows: set FLASK_APP=run.py
flask init-db                      # create tables only
flask seed-db --reset              # drop + seed
flask security-check               # run the 18-point configuration checklist
flask shell                        # REPL with db and every model pre-imported
```

### Alembic migrations

```bash
export FLASK_APP=run.py
flask db upgrade                            # apply the shipped migration
flask db migrate -m "describe your change"  # autogenerate after a model change
flask db downgrade
```

### What gets seeded

18 users across 3 fictional organizations · 5 campaigns (one per template:
2 completed, 2 active, 1 draft) · 40 simulation events spread over the last
7 weeks · 8 URL analyses · 3 email analyses · 6 quiz attempts · 4 reports ·
10 audit entries.

### Switching to PostgreSQL

```bash
export DATABASE_URL="postgresql+psycopg2://user:password@localhost:5432/phishguard"
flask db upgrade && python scripts/seed_database.py
```

---

## 7. Machine-learning pipeline

### Train (optional — a trained model already ships)

```bash
python -m app.ml.train
```

This trains and compares three classifiers on `data/datasets/url_dataset.csv`,
writes the winner to `app/ml/model.joblib` and the full benchmark to
`app/ml/metrics.json`. Runtime ≈ 30–60 s on a laptop CPU.

### Rebuild the dataset (optional, needs internet)

```bash
python scripts/build_dataset.py                    # default 8,000 per class
python scripts/build_dataset.py --per-class 12000 --augment 1500
python scripts/build_dataset.py --no-balance       # demonstrates the label leak
```

### The 38 features

Length group (`url_length`, `hostname_length`, `path_length`, `query_length`,
`fragment_length`, `tld_length`, `longest_token_length`) · character counts
(`num_dots`, `num_hyphens`, `num_at`, `num_question`, `num_equals`,
`num_ampersand`, `num_underscore`, `num_slash`, `num_percent`, `num_digits`) ·
ratios and entropy (`digit_ratio`, `host_digit_ratio`, `host_entropy`,
`path_entropy`) · structure (`num_subdomains`, `has_ip`, `is_https`, `has_port`,
`has_punycode`, `has_www_in_subdomain`, `double_slash_in_path`,
`num_query_params`, `has_hex_encoding`, `host_hyphens`, `num_non_ascii`) ·
semantics (`suspicious_tld`, `num_suspicious_keywords`, `is_shortener`,
`brand_in_subdomain`, `brand_in_path`, `brand_mismatch`).

### Benchmark — held-out split, n = 3,217 (1,589 legitimate / 1,628 phishing)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | 5-fold CV F1 |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.8206 | 0.8972 | 0.7291 | 0.8045 | 0.8682 | 0.806 ± 0.008 |
| Random Forest (200 trees, depth 18) | 0.8415 | 0.9465 | 0.7279 | 0.8229 | 0.8978 | 0.814 ± 0.006 |
| **HistGradientBoosting — selected** | **0.8514** | **0.9444** | **0.7506** | **0.8364** | **0.8990** | **0.830 ± 0.006** |

Confusion matrix of the selected model:

|  | predicted legitimate | predicted phishing |
|---|---|---|
| **actually legitimate** | 1,517 (TN) | 72 (FP) |
| **actually phishing** | 406 (FN) | 1,222 (TP) |

Top permutation importances: `suspicious_tld` 0.155 · `num_subdomains` 0.115 ·
`host_digit_ratio` 0.113 · `hostname_length` 0.098 · `has_www_in_subdomain`
0.094 · `num_suspicious_keywords` 0.071. (`path_length` is now 12th at 0.028.)

> **Honesty note.** These numbers describe a held-out split of *this* dataset.
> They are **not** a promise about live traffic. The model produced 72 false
> positives and 406 false negatives on 3,217 URLs — roughly one in four phishing
> URLs was missed. Dataset composition drives benchmark results; re-train on
> your own data before operational use. This is a **demonstration model** built
> from a public research corpus, not a production detector.

### Two dataset confounds we found and fixed

Both were found by inspecting what the model actually learned, and both are
corrected the same way: by rewriting a surface attribute in **both** classes so
it can no longer carry label information. `--no-balance` reproduces the raw,
leaky corpus for teaching.

**1 — the HTTPS leak.** In the raw PhiUSIIL corpus, 100 % of legitimate URLs
start `https://www.` while only 48.7 % of phishing URLs use HTTPS. Training on
it produced a bogus **99.7 %** accuracy driven almost entirely by `is_https` —
the model learned "http ⇒ phishing", the exact misconception this platform
teaches against. `build_dataset.py` now rewrites the scheme and `www.` prefix
in both classes toward ~60 % HTTPS / ~45 % `www.`.

**2 — the path-depth leak.** PhiUSIIL collected its legitimate class as bare
registered domains (`https://www.uni-mainz.de`) while capturing phishing URLs
live with full deep paths. The result: **85 % of legitimate rows had no path at
all** versus 62 % of phishing rows, `path_length` became the single strongest
feature (permutation importance 0.276), and the model scored *any* ordinary URL
with a path as phishing:

| URL | ML score before | ML score after |
|---|---:|---:|
| `github.com/pallets/flask` | 85.1 | 24.8 |
| `mail.google.com/mail/u/0/#inbox` | 99.2 | 47.8 |
| `amazon.in/gp/css/order-history?ref_=nav_orders_first` | 97.1 | 4.6 |
| `docs.python.org/3/library/urllib.parse.html` | — | 31.5 |

`balance_path_depth()` equalises path *presence and depth* across both classes:
URLs without a path receive one from a class-neutral generator (the same
vocabulary is applied to both classes, so the words carry no signal), and a
matching share of URLs in both classes is stripped back to the bare host.
Authentic path *wording* is never rewritten — a real `/webscr/cmd?cmd=_account-details`
keeps its text, because that is genuine evidence. Both classes end at ~70 %
with-path.

Honest cost: **accuracy fell from 0.8857 to 0.8514 and F1 from 0.8755 to
0.8364.** The earlier numbers were partly measuring the artefact. `path_length`
importance dropped 10× (0.276 → 0.028) and the top features are now
`suspicious_tld`, `num_subdomains` and `host_digit_ratio` — signals that mean
something.

### Heuristic limitations (read this before trusting a score)

The rule engine reads the URL string only. It never resolves DNS, never fetches
the page and has no reputation feed, so it cannot know whether a domain is
newly registered, already blocklisted, or serving malware.

* **False positives are expected.** Long URLs, many subdomains, hyphenated
  hosts and words like `verify` or `account` all occur in legitimate traffic.
  A university page at `portal.cybersafe.edu/password/renew` scores MEDIUM
  purely because a credential-reset path on an unfamiliar domain looks like
  one. That is the detector being cautious, not the URL being malicious.
* **False negatives are expected.** A phishing page on a compromised
  high-reputation domain with a short, clean URL will score LOW. The engine
  has nothing to fire on.
* **HTTPS is not safety.** A valid certificate proves transport encryption and
  nothing about intent. `is_https` contributes no positive score.
* **Thresholds are judgement calls, not science.** Every rule weight and
  threshold lives in `RULE_WEIGHTS` and in config (`URL_ENTROPY_THRESHOLD`,
  `URL_LONG_THRESHOLD`, `RISK_BANDS`, …) so you can retune them; the shipped
  entropy threshold was calibrated on the bundled corpus to fire on 0.27 % of
  benign hostnames and 18.6 % of phishing ones.
* **The score is decision support.** Use it to prioritise which URL a human
  looks at first, never as an automatic block/allow verdict.


---

## 8. Running the tests

```bash
pytest                                    # all 407 tests
pytest -v                                 # verbose
pytest --cov=app --cov-report=term-missing
pytest --cov=app --cov-report=html        # then open htmlcov/index.html
pytest tests/test_security.py             # one file
pytest -k "lockout or csrf"               # by keyword
```

### Results

```
$ pytest -q
........................................................................ [ 55%]
..........................................................               [100%]
407 passed (latest recorded verification)

$ pytest --cov=app -q
TOTAL    3699 statements    649 missed    82% coverage
```

| Test file | Tests | Covers |
|---|---:|---|
| `test_auth.py` | 19 | Hashing & salting, production iteration count, generic login errors, account enumeration, lockout at the boundary, counter reset, lockout expiry, disabled accounts, audit of success/failure/logout without the password, weak-password rejection, registration privilege escalation, API-key rotation, **client session isolation** |
| `test_authorization.py` | 35 | The full page matrix across admin / analyst / demo / anonymous, unauthenticated redirects, **demo users cannot reach admin functions by typing the URL** (8 GETs + 7 POSTs), analyst denial of admin-only actions, capability matrix, self-demotion protection, audited role change, cross-participant simulation access, ACCESS_DENIED auditing |
| `test_url_detector.py` | 37 | Phishing vs benign separation, IP hosts, `@` confusion, punycode, percent-encoding, subdomain nesting, shorteners, look-alike domains, mutually exclusive length rules, indicator completeness, documented payload shape, bounds, 100-clamp, determinism, "HTTPS is not safety", **8 everyday URLs stay below MEDIUM**, **brand tokens no longer match inside words**, **entropy rule ignores ordinary hostnames**, configurable thresholds, navigation-word noise, 38-feature vector integrity, malformed input |
| `test_email_detector.py` | 20 | All five scenario families (legitimate, urgency, account-verification, financial, impersonation), documented payload shape, per-indicator recommendations, **mentioning a help desk is not impersonation**, claiming to be one is, **partial header pastes are not penalised**, real header blocks with no hops are, SPF/DKIM/DMARC parsing, Reply-To mismatch, gift-card and financial pressure, link extraction, bounds and determinism |
| `test_risk_engine.py` | 21 | Configured weighting, rebalancing, normalisation of weights that do not sum to 1, rules-only fallback, determinism, bounds under extreme and negative inputs, all 8 band boundaries, **configurable bands**, explanation structure, separate rule/ML/final reporting, confidence never presented as certainty |
| `test_ml.py` | 16 | Artefact exists and loads, inference works independently of training, per-feature attribution, determinism, phish/benign separation, **4 real URLs with paths stay below 60**, **`path_length` is no longer the dominant feature**, detector metadata, all three algorithms evaluated, **published metrics recomputed from the confusion matrix**, dataset caveat present, metrics not implausibly perfect, feature-name stability |
| `test_campaigns.py` | 27 | **No credential input in any simulator template**, `SIMULATION_COLLECT_CREDENTIALS` is False, only 4 event types, unknown events rejected, reserved fictional domains, teaching material, unique tokens, UI creation, status updates, cascade delete, open/click/train/report recording, invalid tokens, **events never carry credentials**, awareness-score arithmetic, simulation-metric labelling, **configurable campaign risk thresholds**, **dashboard KPIs move with the data**, empty-database dashboard |
| `test_api.py` | 35 | Health, unauthenticated rejection, API-key and Bearer auth, invalid keys, validation errors, **hostile URL schemes rejected**, malformed JSON, **unknown API paths return the documented slug**, **405 returns JSON not HTML**, email analysis, campaign list/detail/create, capability enforcement, quiz answer-key protection, grading, admin-only user listing, report payloads, CSV parseability, PDF magic bytes, safe filenames, download routes, **credential redaction before storage**, web quiz flow |
| `test_security.py` | 42 | Security headers, CSP strictness, no server banner, no stack-trace leakage, friendly error pages, JSON API errors, **CSRF rejection and token rendering**, **rate-limit 429**, 413 on oversized bodies, open-redirect prevention, 4 SQL-injection payloads as data, stored and reflected XSS escaping, audit redaction, audit coverage, **all 8 required audit actions exist**, admin-only log access, cookie flags, production cookie/HSTS settings, default-secret refusal, the 18-point checklist, serialisation hygiene, cross-user quiz isolation, `.env` hygiene, **SQLite foreign keys enforced**, **production never enables the Werkzeug debugger**, **`FLASK_DEBUG=0` is honoured** |

### End-to-end and front-end checks

Two scripts exercise a **running** server rather than the test client. Start
`python run.py` in another terminal first.

```bash
python scripts/acceptance_check.py    # 20 steps: login → campaign → detectors → ML
                                      # → report → audit → RBAC → logout
python scripts/frontend_check.py      # crawls 14 pages; fails on dead buttons,
                                      # '#' links with no handler, broken hrefs
```

Both exit non-zero on failure, so they drop straight into CI. Last run:
**20/20 acceptance steps passed**; front-end sweep **0 dead links, 0 orphan
buttons, 0 broken internal links** across 91 buttons / 346 links / 70 forms.

### Configuration self-check

```bash
$ python scripts/security_check.py
[ PASS ] No hardcoded secrets in app/       configuration read from the environment
[ PASS ] CSRF protection enabled            Flask-WTF CSRFProtect active
[ PASS ] Passwords stored as salted hashes  pbkdf2:sha256:600000
[ PASS ] Account lockout configured         5 attempts / 15 minute lockout
[ PASS ] Security headers on responses      CSP, X-Content-Type-Options, X-Frame-Options, …
[ PASS ] Simulator collects no credentials  no credential inputs in simulator templates
…
18 checks - 17 passed, 1 warnings, 0 failures
```

(The single warning is "SECRET_KEY is a placeholder" and disappears once you put
a real key in `.env`.)

---

## 9. Docker

`docker-compose.yml` contains **no secrets**. Both the Flask secret and the
PostgreSQL password are declared as *required* variables with no fallback, so
the stack refuses to start rather than booting with a password that is public
in the repository. Create `.env` first:

```bash
cp .env.example .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(24))" >> .env
docker compose up --build
# → http://localhost:8000/
```

Compose reads `.env` from the project root automatically. Omit either value and
you get an explicit error naming the missing variable — by design.

The stack is **web** (gunicorn, 3 workers, non-root user) + **db**
(PostgreSQL 16) + **redis** (rate-limit storage). The entrypoint waits for the
database, applies migrations and seeds the demo data automatically.

```bash
docker compose logs -f web
docker compose exec web python scripts/security_check.py
docker compose exec web pytest -q
docker compose down -v                 # stop and delete the volumes
SEED_DEMO_DATA=0 docker compose up     # start with an empty database
```

`.env` is git-ignored. The only credentials committed anywhere in this
repository are the fictional demo *account* passwords in `seed_database.py`,
which exist to make the demo reproducible.

---

## 10. 15-step demonstration script

A ~12-minute walkthrough that exercises every subsystem in order. Keep two
browser profiles (or one normal + one private window) open so you can be an
administrator and a participant at the same time.

| # | Step | What to point out |
|---:|---|---|
| **1** | **Start clean.** `python scripts/seed_database.py --reset && python run.py` | Deterministic demo data; the console prints the profile, the database URI and whether the ML model loaded. |
| **2** | **Sign in as `admin` / `Admin@Phish2026`.** | The login page lists the demo accounts; lockout and rate limiting are already active behind it. |
| **3** | **Dashboard tour** (`/dashboard`). | 8 KPIs and 6 charts drawn from real seeded rows. Read the footnote: these are **simulation metrics**, not real-world phishing prevalence. |
| **4** | **Open a campaign** (`/campaigns` → *Q1 Password Expiry Awareness Test*). | Funnel (participants → opened → clicked → trained → reported), timeline, per-participant table, awareness score, risk level. |
| **5** | **Create a new campaign** (`/campaigns/create`). | Pick *IT security alert*, select all participants, save. Note the safety panel: no credential capture, no real email, participants must already exist. |
| **6** | **Preview the template** (`/simulator/preview/it_security_alert`). | Read-only mock-up with an inert CTA plus the red flags it is designed to teach. |
| **7** | **Switch to the participant** — second window, `priya.demo` / `Demo@Phish2026`, go to `/simulator`. | The simulated inbox. Open the message: it renders as an email but **contains no input fields at all**. |
| **8** | **Click the phishing link.** | You land on the awareness page, not a login form. It names the exact indicators: spoofed sender domain, anchor-text vs href mismatch, urgency, deadline. Two events were recorded: `LINK_CLICKED`, `TRAINING_PAGE_VIEWED`. |
| **9** | **Report a different message** using the *Report* button. | `REPORTED` is logged and the participant's awareness score rises — the platform rewards reporting rather than punishing clicking. |
| **10** | **URL detector** (`/url-detector`, admin window). Click the sample chip `http://198.51.100.23/paypal.com/secure/login.php?cmd=verify-account`. | Walk the score: each indicator shows points, evidence and a recommendation; the ML panel shows per-feature z-score attributions; the risk engine shows `0.6 × rules + 0.4 × ML`. Contrast with the benign sample `https://docs.python.org/...`. |
| **11** | **Email detector** (`/email-detector` → *Load phishing sample*). | SPF fail / DKIM none / DMARC fail, Reply-To mismatch, look-alike sender, urgency language, and every embedded link scored. Then load the legitimate sample and show it scoring near zero. |
| **12** | **Awareness training** (`/awareness`). | 12 modules, then take the 10-question quiz. Answer two questions wrong on purpose — the result page explains **every** answer, right or wrong. |
| **13** | **Generate and export a report** (`/reports`). | Create a campaign report, open it, download CSV and PDF. Point at the *Notes and limitations* section that ships inside the report. |
| **14** | **Audit log & RBAC** (`/audit-logs`, `/users`). | Filter by `LOGIN_FAILURE`; note no password appears anywhere. Then log in as `analyst` and show `/users` returning **403** — authorisation is server-side, not a hidden link. |
| **15** | **Prove the safety claims.** `pytest -q` (130 passing) then `python scripts/security_check.py`. | Call out `test_simulator_templates_contain_no_credential_inputs` and the checklist line *"Simulator collects no credentials"*. Finish on the API: `curl -H "X-API-Key: …" -X POST .../api/analyze/url -d '{"url":"javascript:alert(1)"}'` → rejected with `validation_error`. |

---

## 11. How to present this in an internship review

### The one-paragraph pitch

> "PhishGuard is a defensive phishing simulation and detection platform. It does
> three things: it runs safe phishing exercises that teach instead of trap, it
> explains *why* a URL or email looks malicious rather than just scoring it, and
> it measures whether the training actually changed behaviour. The detection side
> is a hybrid — hand-written heuristics you can audit, weighted 60/40 with a
> gradient-boosting model that generalises beyond the rules — and every number it
> shows can be traced back to the evidence that produced it."

### Five things worth demonstrating in depth

**1. The safety architecture is defence in depth, not a promise.**
Four independent layers stop credential collection: the templates contain no
password field, the `simulation_events` schema has no column that could hold a
submitted value, `SIMULATION_COLLECT_CREDENTIALS` is a class constant rather
than an env var, and both the test suite and the runtime checklist re-verify it.
"I made it safe" is a claim; "here is the test that fails if it stops being
safe" is evidence.

**2. Explainability was a design constraint, not a feature.**
Every indicator carries points, the evidence string that triggered it, a
severity and a remediation sentence. The ML model exposes per-feature z-score
attributions. The risk engine returns an ordered list of steps. An analyst can
reconstruct any score by hand — which is what makes the tool usable in a real
SOC, where "the model said so" is not an acceptable justification.

**3. We found and fixed two label leaks — and kept the worse number both times.**
The first model hit 99.7 % accuracy. That was suspicious, and the permutation
importances showed why: `is_https` carried 0.355 importance, because 100 % of
legitimate URLs in the source corpus were `https://www.` while phishing URLs
were mixed. The model had learned "http ⇒ phishing" — the exact misconception
this platform exists to correct. Rewriting the scheme in both classes dropped
accuracy to 88.6 %. A later audit found a second one: `path_length` had become
the top feature at 0.276 importance, because the corpus collected legitimate
sites as bare domains and phishing sites with full paths — so the model scored
`github.com/pallets/flask` at 85/100. Balancing path depth across both classes
cost another 3.4 points of accuracy (now **85.1 %**) and dropped `path_length`
to 12th. **Reporting the lower, honest number twice is the result.** This is the
single best story in the project: it shows you can distrust your own metrics.

**4. Model selection balanced quality against deployability.**
An unbounded Random Forest matched the boosted model's metrics but serialised to
**44 MB**. HistGradientBoosting scores better in **349 KB** — a 120×
smaller artefact that fits in Git and loads instantly. Engineering decisions
have costs beyond the F1 column.

**5. The metrics are labelled as what they are.**
Campaign click rates are *simulation metrics for this exercise*, not a
measurement of organisational breach risk. Benchmark accuracy is *dataset
dependent*. ML confidence is *not certainty*. Every one of those caveats is
rendered in the UI, not buried in a README — because an awareness tool that
overstates its own certainty is teaching the wrong lesson.

### Likely questions, with answers

| Question | Answer |
|---|---|
| *Why 0.6 / 0.4?* | Heuristics are auditable and predictable; the model generalises. Weighting toward rules keeps the explanation legible while adding statistical reach. Both are `.env` configurable, so an analyst who distrusts the model can set `ML_WEIGHT=0`. |
| *Why not deep learning?* | 16 k samples and 38 tabular features is exactly where gradient boosting wins. A transformer would need orders of magnitude more data, would be far slower to score, and could not produce the per-feature attributions this UI depends on. |
| *Isn't 88 % low?* | It is honest. The 99.7 % version was measuring a dataset artefact. Also, the operating point matters: precision is 0.96, so the tool rarely cries wolf — the cost is a 0.80 recall, which is why it is decision *support*, not a gate. |
| *How would this scale?* | Swap SQLite for PostgreSQL (one env var, already wired in compose), move the rate limiter to Redis (also wired), run gunicorn with multiple workers behind a TLS-terminating proxy, and move report generation to a task queue. |
| *What would you do next?* | Real SMTP delivery with per-tenant authorisation gates, a URL sandbox that follows redirects safely, per-organisation model retraining, and SIEM export of the audit trail. |
| *Is this legal to run?* | Only against consenting participants in your own organisation, with written authorisation. SECURITY.md §5 states the policy; the product will not target an address that is not already an account. |

### Metrics you can quote

53 routes · 11 tables · 31 templates · 10 blueprints · 24 URL heuristics ·
35 email heuristics ·
38 ML features · 12 training modules · 407 tests · 82 % coverage ·
18 configuration checks · 0 hardcoded secrets · 0 credential fields.

---

## 12. Security controls implemented

| # | Control | Implementation |
|---:|---|---|
| 1 | Password hashing | PBKDF2-HMAC-SHA256, 600,000 iterations, per-user salt |
| 2 | Password policy | ≥10 chars, composition rules, common-password rejection |
| 3 | Account lockout | 5 failures → 15-minute lock, HTTP 423 |
| 4 | Account enumeration resistance | Identical message and status for unknown user vs wrong password |
| 5 | Session hardening | `HttpOnly`, `SameSite`, `Secure` in production, 60-min lifetime, custom cookie name |
| 6 | CSRF protection | Flask-WTF `CSRFProtect` on every form, including login; custom `CSRFError` page |
| 7 | RBAC | 13-capability matrix, `@capability_required` on every protected view |
| 8 | Object-level authorization | Participants access only their own messages and quiz attempts |
| 9 | Privilege-escalation prevention | Self-registration forces Demo User; admins cannot demote/disable themselves |
| 10 | Rate limiting | Flask-Limiter: login, analysis, API and global windows; friendly 429 |
| 11 | Request size limit | `MAX_CONTENT_LENGTH` 1 MB → 413 |
| 12 | Content Security Policy | `default-src 'self'`, `object-src 'none'`, no inline script, no CDN |
| 13 | Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `Cache-Control`, HSTS in production |
| 14 | SQL-injection prevention | ORM only; no string-built SQL (checked by script and by test) |
| 15 | XSS prevention | Jinja2 autoescaping; no `|safe` on user data |
| 16 | Open-redirect prevention | `is_safe_redirect_url()` validates the `next` parameter |
| 17 | URL-scheme validation | Only `http`/`https`; `javascript:`, `data:`, `file:`, `ftp:` rejected |
| 18 | Credential redaction | Passwords, OTPs, tokens, cards, IBANs, SSNs masked before any DB write |
| 19 | Audit-log sanitisation | Sensitive `extra` keys masked; bodies and secrets never recorded |
| 20 | Audit trail | Append-only log of 19 action types with actor, status, target, optional IP |
| 21 | Secret management | Environment-only; production refuses to boot with a default `SECRET_KEY` |
| 22 | Error handling | Custom 400/401/403/404/413/429/500 pages; no stack trace to users; JSON for the API |
| 23 | Input validation | Server-side WTForms + dedicated validators for URLs, emails, passwords, names |
| 24 | No credential collection | Four independent enforcement layers (see SECURITY.md §1) |
| 25 | Offline analysis | Submitted URLs are never fetched or resolved — no SSRF surface |
| 26 | Least privilege at runtime | Docker image runs as an unprivileged `phishguard` user |
| 27 | Configuration self-check | `scripts/security_check.py` — 18 automated checks |
| 28 | Security regression tests | 21 dedicated tests plus the simulator-safety suite |

---

## 13. Known limitations

1. **Heuristics produce false positives and false negatives.** Long legitimate tracking URLs get flagged; well-crafted phishing on a compromised legitimate domain gets missed. Known residual false positive: a credential-reset path on an unfamiliar domain (`portal.cybersafe.edu/password/renew`) scores MEDIUM.
2. **ML confidence is not certainty** — it is a probability from one model trained on one corpus. Never present it as a verdict.
3. **Benchmark numbers depend on the dataset.** 85.1 % accuracy is a held-out split of the bundled corpus, not a prediction about your traffic. The shipped model missed **406 of 1,628** phishing URLs in that split — about one in four. It is a **demonstration model** trained on a public research corpus; supply your own labelled data and re-run `python train.py` before operational use.
4. **HTTPS is not safety.** A certificate proves transport encryption, not intent. The scoring deliberately does not reward it.
5. **SPF/DKIM/DMARC prove the domain, not the sender's intent.** Mail from a compromised legitimate mailbox passes all three.
6. **Campaign figures are simulation metrics**, describing these participants in this exercise — not real-world phishing prevalence or breach likelihood.
7. **Analysis is offline and string-level.** No page fetch, redirect following, TLS inspection, WHOIS or reputation feed.
8. **No real email delivery**, so inbox-level behaviour (previews, forwarding, mobile rendering) cannot be measured.
9. **In-memory rate limiting by default** — per-process only; use Redis for multi-worker deployments.
10. **SQLite by default** — fine for a demo, not for concurrent production write loads.
11. **Reports are generated synchronously**; a very large campaign will block a worker.
12. **English-only content** and no accessibility audit has been performed.
13. **Not penetration-tested.** An internship project — review independently before exposing it to a network.

---

## 14. Future enhancements

**Detection**
* Redirect-chain resolution and TLS-certificate inspection inside a sandboxed egress-controlled worker.
* Optional reputation enrichment (PhishTank / URLhaus / Google Safe Browsing) behind a feature flag, with caching and an explicit privacy notice.
* NLP on the email body (transformer embeddings) to complement the URL model.
* Attachment-metadata analysis (type, macro presence) without executing anything.
* Per-organisation retraining, with drift monitoring and a champion/challenger rollout.
* Calibration curves and an explicit, tunable operating point instead of a fixed 0.5 threshold.

**Simulation**
* Real SMTP delivery gated behind a signed authorisation record and a scope allowlist.
* Scheduling, drip campaigns and control groups for statistically valid measurement.
* Per-recipient personalisation with a hard cap on how much real data a template may reference.
* Attachment and QR-code lure variants (still inert).
* Automatic just-in-time micro-training assignment when a participant clicks.

**Platform**
* SSO (SAML / OIDC) and TOTP MFA.
* Celery + Redis for report generation and campaign scheduling.
* SIEM export (CEF/JSON) of the audit trail, and webhook notifications.
* Multi-tenant organisations with data isolation.
* A React or HTMX front-end with WebSocket live event streaming.
* WCAG 2.1 AA accessibility pass and internationalisation.
* CI pipeline: pytest, `pip-audit`, `bandit`, `ruff`, container scanning, and a signed image.

---

## 15. Configuration reference

Every key is read from the environment (optionally via `.env`); see
`.env.example` for the template.

| Key | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | *(required in production)* | Session signing. Production refuses to start without it. |
| `FLASK_CONFIG` | `development` | `development` / `testing` / `production`. |
| `DATABASE_URL` | `sqlite:///instance/phishguard.db` | `postgres://` URLs are auto-normalised. |
| `SESSION_COOKIE_SECURE` | `0` (`1` in production) | Send cookies over HTTPS only. |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Set to `None` (with `Secure=1`) when embedding in an iframe. |
| `PASSWORD_MIN_LENGTH` | `10` | Minimum password length. |
| `MAX_FAILED_LOGINS` | `5` | Failures before lockout. |
| `ACCOUNT_LOCKOUT_MINUTES` | `15` | Lockout duration. |
| `RATELIMIT_ENABLED` | `1` | Master switch. |
| `RATELIMIT_LOGIN` | `10 per minute;60 per hour` | Login throttle. |
| `RATELIMIT_ANALYSIS` | `60 per minute;600 per hour` | Detector throttle. |
| `RATELIMIT_API` | `120 per minute` | API throttle. |
| `RATELIMIT_STORAGE_URI` | `memory://` | Use `redis://…` for multi-process. |
| `FRAME_ANCESTORS` | `'self'` | CSP `frame-ancestors`; widen only for a trusted embed. |
| `ENABLE_HSTS` / `HSTS_MAX_AGE` | `0` / `31536000` | Enable only behind TLS. |
| `CSP_REPORT_ONLY` | `0` | Switch the CSP to report-only while tuning. |
| `HEURISTIC_WEIGHT` / `ML_WEIGHT` | `0.6` / `0.4` | Risk-engine fusion weights. |
| `URL_ENTROPY_THRESHOLD` | `4.0` | Shannon-entropy level at which a hostname looks algorithmically generated. |
| `URL_ENTROPY_MIN_HOST_LEN` | `20` | Minimum hostname length before the entropy rule may fire (short hosts are noisy). |
| `URL_DIGIT_RATIO_THRESHOLD` | `0.25` | Digit share of the hostname that counts as suspicious. |
| `URL_LONG_THRESHOLD` / `URL_VERY_LONG_THRESHOLD` | `75` / `120` | The two URL-length bands. They are mutually exclusive — a URL is never charged for both. |
| `URL_MANY_SUBDOMAINS` | `3` | Subdomain count that triggers the nesting rule. |
| `URL_HOST_HYPHEN_THRESHOLD` | `3` | Hyphens in the host before it reads as a look-alike. |
| `URL_DEEP_PATH_THRESHOLD` | `5` | Path segments that count as unusually deep. |
| `ML_ENABLED` | `1` | Set `0` to run rules-only. |
| `ML_MODEL_PATH` / `ML_METRICS_PATH` / `ML_DATASET_PATH` | under `app/ml`, `data/` | Artefact locations. |
| `ALLOW_SELF_REGISTRATION` | `1` | Show/enable `/register` (always creates a Demo User). |
| `MAX_CONTENT_LENGTH` | `1048576` | Request body cap in bytes. |
| `REPORT_MAX_ROWS` | `5000` | Row cap for exports. |
| `AUDIT_LOG_IP` | `1` | Record client IPs in the audit trail. |
| `RISK_BANDS` | `0/25/50/75` | LOW / MEDIUM / HIGH / CRITICAL cut-offs, read from config by both `RiskEngine.bands` and `classify_score()`. Edit in `app/config.py`. |
| `CAMPAIGN_RISK_THRESHOLDS` | `10/25/50` | Click-rate percentages that colour a campaign LOW / MEDIUM / HIGH. Edit in `app/config.py`. |
| `LOG_LEVEL` / `LOG_FILE` | `INFO` / `instance/phishguard.log` | Application logging. |

---

## 16. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'app'` | Run commands from the project root with the virtualenv activated. |
| `RuntimeError: SECRET_KEY environment variable must be set` | You are on the production profile — put a real `SECRET_KEY` in `.env`, or use `FLASK_CONFIG=development`. |
| Login always fails | Run `python scripts/seed_database.py`. If you are locked out, wait 15 minutes or toggle the account off/on in `/users` (which clears the counter). |
| `429 Too Many Requests` during a demo | Expected — that is the rate limiter. Wait a minute or raise `RATELIMIT_LOGIN`. |
| Dashboard charts are empty | The database has no events: `python scripts/seed_database.py --reset`. |
| "ML model unavailable" banner | `python -m app.ml.train`, or set `ML_ENABLED=0` to run rules-only. |
| PDF export button missing | `pip install reportlab`. CSV and JSON still work without it. |
| Styling missing in an embedded preview | Sandboxed iframes block external resources; open the app directly in a browser. |
| `flask db migrate` says "No changes detected" | Your database already matches the models — that is success, not an error. |
| Port 5000 already in use (macOS AirPlay) | `PORT=8000 python run.py`. |

---

## 17. Portfolio screenshots

The repository does **not** include fabricated screenshots. For a portfolio or internship submission, run the application locally or with Docker and capture the real interface. Store approved screenshots under `docs/screenshots/` using the naming guide in [`docs/SCREENSHOTS.md`](docs/SCREENSHOTS.md).

## 18. Submission checklist

Use [`docs/SUBMISSION_CHECKLIST.md`](docs/SUBMISSION_CHECKLIST.md) immediately before creating the GitHub release. It covers secrets, runtime artifacts, tests, Docker configuration, documentation, screenshots and responsible-use checks.

## 19. Credits & licence

**Dataset** — [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset),
UCI Machine Learning Repository ID 967 (Prasad & Chandra, 2024), CC BY 4.0,
plus a generated augmentation corpus. Labels are inverted relative to upstream
(PhishGuard uses `1 = phishing`).

**Vendored front-end** — Bootstrap 5.3.3 (MIT), Chart.js 4.4.3 (MIT),
Bootstrap Icons 1.11.3 (MIT), all served locally.

**Built with** — Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF,
Flask-Limiter, Flask-Migrate, scikit-learn, pandas, NumPy, ReportLab, pytest.

**Purpose** — educational internship project. Provided as-is, for defensive
security training and coursework. Read [SECURITY.md](SECURITY.md) before running
any exercise involving other people.

<div align="center">

**Measure the report rate, not the click rate.**

</div>
