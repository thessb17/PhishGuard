# PhishGuard — Final Quality Report

**Date:** 2026-10-01
**Scope:** upgrade of the existing, already-audited PhishGuard platform toward
portfolio quality, without rebuilding working components.

> **Every number in this report came from executing the command shown.** Where
> something was not verified, it is listed as not verified rather than
> omitted. Section 12 and 13 are deliberately long.

> **Historical report note:** This document records the portfolio-upgrade phase. Subsequent CSRF/session regression work added additional tests. The latest recorded suite size is 407 tests; run `pytest -q` on the current checkout to obtain the current result.

---

## 1. Baseline

Recorded in `docs/BASELINE.md` before any change was made.

| Metric | Baseline | Final | Δ |
|---|---|---|---|
| Tests | 252 | **342** | +90 |
| Statement coverage | 82% (3,278 stmts) | **82%** (3,699 stmts) | +421 statements covered at the same rate |
| Acceptance steps | 21/21 | **21/21** | — |
| Security checklist | 17 pass / 1 warn / 0 fail | **17 / 1 / 0** | — |
| Routes | 53 | 53 | — |
| Tables | 11 | 11 | — |
| Python LOC | 12,108 | ~13,400 | +~1,300 |
| Documentation | 3,422 lines | **~6,000 lines** | +6 new documents |
| pyflakes findings | 1 (intentional `noqa`) | **0** after filter | — |

---

## 2. Improvements

### 2.1 Detection quality — a real bug, found by measurement

The look-alike check compared **whole domains**, so the TLD dominated the edit
distance:

```
paypa1.example  vs paypal.com     raw=7  deskeletoned=6   -> rule needs <=2, never fired
arnazon.example vs amazon.com     raw=8  deskeletoned=6   -> never fired
```

Five of the six characters of difference were just `.example` vs `.com`.
Comparing the **domain label** instead gives distance 1, 2 and 0 respectively.

Measured effect on heuristic score:

| URL | Before | After |
|---|---:|---:|
| `arnazon.example/orders` | **0.0** | 28.0 |
| `paypa1.example/login` | 5.0 | 33.0 |
| `micros0ft.example/account/verify` | 10.0 | 38.0 |
| `paypal.com.account-verify.example/signin` | 35.0 | 61.0 |

`arnazon.example` — a textbook `rn`→`m` homoglyph squat — previously scored
**zero**.

### 2.2 Phase 4 — domain intelligence layer

New `app/services/domain_intel.py`: a `DomainIntelProvider` ABC with an
offline `LocalDomainIntelProvider` backed by editable files in `data/intel/`
(allowlist, denylist, suspicious TLDs, shorteners, brands).

Three verdicts, and the central rule is enforced in code and tests:

```
KNOWN_SAFE        -> suppresses brand-impersonation findings
KNOWN_SUSPICIOUS  -> +40 points
UNKNOWN           -> +0 points      <- "not on my list" is NOT evidence of badness
```

No paid API, no live feed, works fully offline. A real deployment can add a
feed-backed provider without touching the analyzers.

### 2.3 Phase 5 — explainable brand impersonation

New `app/services/brand_intel.py` names the **technique** rather than emitting
an opaque score:

| Technique | Example | Points |
|---|---|---:|
| `HOMOGLYPH` | `paypa1`, `arnazon`, `micros0ft` | 28 |
| `BRAND_IN_SUBDOMAIN` | `paypal.com.account-verify.example` | 26 |
| `EXACT_LABEL_FOREIGN_DOMAIN` | `paypal-support.example` | 24 |
| `TYPOSQUAT` | `payppal.example` | 20 |
| `PUNYCODE_LOOKALIKE` | `xn--pypal-4ve.example` | 18 |

False-positive controls, each tested: domains the brand owns are skipped;
allowlisted domains are exempt; labels under 5 characters are not
edit-distance matched; the edit budget **scales with label length** so `ups`
cannot match on the same terms as `microsoft`.

Measured: 5/5 impersonation cases detected, **0/8 legitimate domains flagged**
(`paypal.com`, `github.com`, `mail.google.com`, `flask.palletsprojects.com`,
`uni-mainz.de`, `stackoverflow.com`, `en.wikipedia.org`, `www.paypal.com`).

### 2.4 Phase 11 — detection decision trace (flagship)

New `app/services/detection_trace.py` + `partials/detection_trace.html`.
Renders the pipeline as six expandable stages:

```
INPUT -> FEATURE EXTRACTION -> RULE ENGINE -> ML MODEL -> RISK FUSION -> VERDICT
```

Built on `<details>`/`<summary>`, so it needs **no JavaScript** — it works
under the strict CSP (`script-src 'self'`, no inline script) and is
keyboard-navigable for free. The UI answers *"How was this score
calculated?"* instead of asserting "Phishing detected".

It is a presentation layer over data the analysers already return — it
recomputes nothing. A test asserts the trace's verdict equals the actual
`RiskAssessment`, because a trace that could disagree with the verdict would
be worthless.

### 2.5 Phases 8 + 9 — ML credibility

`metrics.json` now carries `model_version` (1.1.0), `feature_version` (1.0.0),
`dataset.version` (a SHA-256 fingerprint of the CSV), `split_strategy`, and
explicit `train_rows` / `test_rows`.

`python train.py --split group` added: group-aware splitting by registrable
domain.

**Measured across 5 seeds (42, 7, 13, 2024, 99):**

| Split | Accuracy | F1 | Domain overlap |
|---|---|---|---|
| Random (URL-level) | 0.8505 ± 0.0042 | 0.8372 ± 0.0053 | ~219 domains |
| Group-aware | 0.8450 ± 0.0147 | 0.8255 ± 0.0374 | 0 |

Three honest findings:

1. Random splitting **is** optimistic: +0.0055 accuracy, +0.0117 F1.
2. The effect is **small** because only 28.4% of rows share a domain with
   another row (11,910 unique domains across 16,083 URLs).
3. **A single-seed comparison gives the wrong answer.** At seed 42 the group
   split scored *higher* (F1 0.8589). Only averaging revealed the true
   direction. This is recorded because it is an easy mistake to hide.

### 2.6 Phases 17 + 18 — observability

New `app/utils/observability.py`:

* Every request gets an ID, returned in `X-Request-ID` and included in every
  API response body.
* A client may supply its own ID — but only if it is ≤64 chars and
  alphanumeric. A hostile value heading for the log file is replaced:
  `X-Request-ID: <script>alert(1)</script>` → a fresh generated ID (tested).
* Security events are emitted as **JSON lines** on a dedicated
  `phishguard.security` logger with a stable field set.

Observed live:

```json
{"timestamp":"2026-10-01T00:10:34.744+00:00","level":"INFO",
 "logger":"phishguard.security","request_id":"329e48de30954963",
 "message":"http.401","action":"http_401","resource":"/api/campaigns",
 "outcome":"REJECTED","ip":"127.0.0.1","method":"GET","status":401,
 "duration_ms":0.85,"event":"http"}
```

Redaction is enforced in the emitter, not trusted to callers.

### 2.7 Phase 17 — API envelope

```json
{"success": true,  "data": {...}, "error": null,     "request_id": "..."}
{"success": false, "data": null,  "error": {"code": "...", "message": "..."}, "request_id": "..."}
```

`data` and `error` are both always present, so a client destructures one shape
instead of branching on which keys exist.

### 2.8 Phase 21 — an edge case found a real 500

The new edge-case suite found that `http://[::1` (unterminated IPv6 bracket)
raised an unhandled `ValueError` from `urllib.parse`:

```
http://[::1   -> HTTP 500      (before)
http://[::1   -> HTTP 400      (after)
```

Fixed in `validate_url`, with defence-in-depth in `extract_features` because
it is also reachable from `predict_url()`. No traceback ever leaked, but a
500 on ordinary bad input is a defect.

### 2.9 Phase 26 — CI caught my own sloppiness

`.github/workflows/ci.yml` runs on Python 3.11/3.12/3.13: compile → pyflakes
→ import check → tests → coverage floor (80%) → seed → security-check → app
startup probe → acceptance → frontend crawl. A second job **retrains the model
and fails if any metric drifts >1e-4** from the committed values.

Reproducing the lint gate locally immediately flagged **6 unused imports in
the code I had just written**. All removed; pyflakes is now clean.

---

## 3. New architecture

See `docs/architecture.svg` (rewritten) and `docs/ARCHITECTURE.md`.

```
USERS (untrusted)
   ↓
FRONTEND            31 templates · no inline script · detection trace
   ↓
FLASK APP           10 blueprints · 53 routes · request-ID middleware
   ↓
AUTHN / RBAC        Flask-Login · capabilities · hashed API keys
   ↓
DETECTION SERVICES  Email Analyzer │ URL Analyzer │ Simulation Engine
   ↓
FEATURES + INTEL    38 features │ DomainIntelProvider │ Brand impersonation
   ↓
RULE ENGINE  +  ML ENGINE
   ↓
RISK FUSION         final = 0.6·heuristic + 0.4·ML, clamped 0–100
   ↓
DATABASE            11 tables, SQLite / PostgreSQL
   ↓
ANALYTICS · REPORTS · AUDIT
```

A security-control envelope (CSP, CSRF, rate limiting, headers, body cap,
request IDs, audit logging) wraps the whole stack. **No outbound fetch of
user-supplied URLs** — SSRF is designed out, and the diagram says so.

New modules, all additive:

| Module | Purpose |
|---|---|
| `app/services/domain_intel.py` | Provider interface + offline local implementation |
| `app/services/brand_intel.py` | Explainable impersonation detection |
| `app/services/detection_trace.py` | Pipeline trace assembly |
| `app/utils/observability.py` | Request IDs + JSON security events |
| `data/intel/*` | Editable allowlist, denylist, TLDs, shorteners, brands |

---

## 4. Security controls

Verified in this pass:

| Control | Evidence |
|---|---|
| **No SSRF** | Zero outbound HTTP clients in `app/`; zero DNS resolution; grep-verified |
| **No `|safe` in templates** | 0 occurrences; Jinja autoescape on |
| **No f-string SQL** | 0 occurrences; ORM throughout |
| **Only one pickle load** | `joblib.load` of the locally-built artifact |
| **RBAC** | Live 12-route × 3-role matrix, **0 violations** |
| **Hashed API keys** | SHA-256 digest; raw key in no column |
| **Weak secret rejection** | 7 classes refused in production |
| **CSRF** | 4 endpoints return 400 without a token |
| **Security headers** | CSP, nosniff, Referrer-Policy, Permissions-Policy, COOP, `Server: PhishGuard` |
| **No credential capture** | 6 sentinels injected, 11 tables scanned, 0 retained |
| **No secrets in logs** | Password, old key, new key, digest — 0 matches in audit table and log file |
| **No tracebacks** | 6 error probes, 0 leaks |
| **Checklist** | 18 checks, 17 pass, 1 warn (dev placeholder secret), 0 fail |

New: `docs/THREAT_MODEL.md` — STRIDE across 12 components with asset, threat,
attack surface, impact, likelihood, existing and proposed mitigation, plus an
explicit out-of-scope list and a ranked residual-risk section.

---

## 5. Detection capabilities

Measured live on the running server, final fused scores:

**Malicious / impersonation**

| URL | Heuristic | Final | Band |
|---|---:|---:|---|
| `198.51.100.23/secure/paypal-login/verify.php` | 68.0 | 80.8 | CRITICAL |
| `paypal.com.account-verify.example/signin` | 61.0 | 76.5 | CRITICAL |
| `micros0ft.example/account/verify` | 38.0 | 62.7 | HIGH |
| `phish-demo-known-bad.example/x` (denylisted) | 56.0 | 58.5 | HIGH |
| `paypa1.example/login` | 33.0 | 56.9 | HIGH |
| `arnazon.example/orders` | 28.0 | 33.9 | MEDIUM |

**Benign**

| URL | Final | Band |
|---|---:|---|
| `stackoverflow.com/questions/12345/parse-url` | 5.7 | LOW |
| `amazon.in/gp/css/order-history` | 5.8 | LOW |
| `github.com/pallets/flask` | 9.9 | LOW |
| `docs.python.org/3/library/urllib.parse.html` | 12.6 | LOW |
| `uni-mainz.de` | 13.8 | LOW |
| `mail.google.com/mail/u/0/#inbox` | 19.1 | LOW |
| `en.wikipedia.org/wiki/Phishing` | 20.9 | LOW |
| `portal.cybersafe.edu/password/renew` | 41.8 | MEDIUM |

**0/6 malicious scored LOW. 0/8 benign scored HIGH or CRITICAL.** Mean benign
final score 16.2.

**Partial fix, stated honestly:** the known `portal.cybersafe.edu` false
positive dropped from **41.7 → 5.0 on the heuristic** once the organisation's
domain was allowlisted, but its **final score is still 41.8 (MEDIUM)** because
the allowlist does not influence the ML component. Reducing it further would
require re-training on organisation-specific data. It is no longer a rules
problem; it is now a model problem, and that distinction is the point.

---

## 6. ML methodology

Full detail in `docs/MODEL_CARD.md`.

Pipeline: load → deduplicate → 38-feature extraction → stratified split →
train 3 candidates → 5-fold CV → permutation importance → select by held-out
F1 → persist bundle + metrics.

Reproducibility: `random_state=42` throughout; CI retrains and asserts every
metric reproduces to 1e-4. Confirmed locally — a full retrain produced
identical accuracy/precision/recall/F1 for all three models.

Two corrected dataset artefacts (HTTPS leak, path-depth leak) cost
0.8857 → 0.8514 accuracy. Reporting the lower number is the result.

---

## 7. ML evaluation

Held-out test set, n = 3,217 (1,589 legitimate / 1,628 phishing):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | CV F1 |
|---|---|---|---|---|---|---|
| LogisticRegression | 0.8206 | 0.8972 | 0.7291 | 0.8045 | 0.8682 | 0.806 ± 0.008 |
| RandomForest | 0.8415 | 0.9465 | 0.7279 | 0.8229 | 0.8978 | 0.814 ± 0.006 |
| **HistGradientBoosting** | **0.8514** | **0.9444** | **0.7506** | **0.8364** | **0.8990** | **0.830 ± 0.006** |

Confusion matrix: `[[1517, 72], [406, 1222]]` — **72 false positives, 406
false negatives**. It misses about one phishing URL in four.

Top features: `suspicious_tld` 0.155, `num_subdomains` 0.115,
`host_digit_ratio` 0.113, `hostname_length` 0.098.

---

## 8. Test count

**342 tests** (baseline 252, +90).

| File | Tests | |
|---|---:|---|
| `test_detection_intel.py` | 47 | **new** — domain intel, brand impersonation, trace, observability |
| `test_edge_cases.py` | 43 | **new** — malformed/empty/huge/unicode input, invalid roles, IDOR, traversal |
| `test_security.py` | 42 | |
| `test_url_detector.py` | 37 | |
| `test_api.py` | 35 | |
| `test_authorization.py` | 35 | |
| `test_campaigns.py` | 27 | |
| `test_risk_engine.py` | 21 | |
| `test_email_detector.py` | 20 | |
| `test_auth.py` | 19 | |
| `test_ml.py` | 16 | |

---

## 9. Coverage

```
$ pytest -q --cov=app
TOTAL    3699 statements    649 missed    82% coverage
342 passed
```

Coverage held at 82% while the codebase grew by 421 statements — the new
modules arrived with their own tests rather than diluting the rate. The CI
pipeline enforces an 80% floor.

---

## 10. Acceptance test result

```
$ python scripts/acceptance_check.py
21 passed, 0 failed out of 21 acceptance steps      (exit 0)

$ python scripts/frontend_check.py
0 dead links, 0 orphan buttons, 0 broken internal links
PASS - every button, link and form resolves         (exit 0)

$ flask security-check
18 checks - 17 passed, 1 warnings, 0 failures
```

Full fresh-setup sequence re-executed end to end: delete database → seed →
342 tests → start server → acceptance → frontend crawl → RBAC matrix →
compile → 48 module imports → pyflakes. All green.

---

## 11. Performance observations

Measured, not assumed:

| Observation | Detail |
|---|---|
| **Model loads once per process** | `@lru_cache` on the loader. Verified: inference works with the training module blocked from import. |
| **Domain intel loads once** | `@lru_cache` on `get_provider()`; five files read at first use, not per request. Re-reading per request would have been pure waste. |
| **Brand matching is bounded** | Edit distance runs over ~27 brand labels against one domain label — short strings, linear in dictionary size. |
| **Indexed API-key lookup** | Hashing the presented key preserves the single indexed query; no table scan was introduced. |
| **Test suite** | 342 tests in 16.8s (~49 ms/test). |
| **Full retrain** | ~20s on 16,083 rows. |
| **Analysis latency** | Acceptance run of 21 HTTP steps including 4 analyses completes in ~1s total. |

No N+1 query was introduced; the new modules perform **no database queries at
all**. Deeper query profiling was not performed.

---

## 12. Known limitations

Full list in `docs/LIMITATIONS.md`. The ones that matter most:

1. **The model misses ~1 phishing URL in 4** and flags ~4.5% of legitimate URLs.
2. **Demonstration model**, trained on a public research corpus. Not a claim about live traffic.
3. **String-level analysis only** — no DNS, fetch, TLS, WHOIS or reputation. Deliberate, to avoid SSRF.
4. **Brand dictionary is Western/English-weighted**; regional brand impersonation is under-detected.
5. **`suspicious_tld` is the strongest feature**, which structurally penalises legitimate sites on cheap TLDs.
6. **No temporal validation and no calibration study.** "Confidence" is a transformed probability, not a calibrated one.
7. **Single-tenant.** Report access is capability-checked, not per-object owner-checked.
8. **No automated retention job**; cascades are wired, scheduling is the deployer's.
9. **Not penetration-tested.** The checklist verifies configuration, not the absence of vulnerabilities.

### Not verified in this pass

| Area | Status |
|---|---|
| **Docker Compose** | **Never booted** — no Docker daemon available. Compose file statically validated only. |
| **GitHub Actions** | YAML-validated and every step reproduced locally; never run on GitHub runners. |
| **PostgreSQL profile** | Migration applies on SQLite; the Postgres path was not executed. |
| **Gunicorn `Server` header** | Dev-server banner suppressed; gunicorn's own is not. |

### Phases implemented partially or not at all

Stated plainly rather than claimed:

| Phase | Status |
|---|---|
| 3 — advanced URL features | **Already satisfied** by the existing 38-feature pipeline; verified against the requested list rather than rewritten (rewriting would have invalidated the trained model for no gain) |
| 6 — email analysis 2.0 | **Partial.** The six analysis layers already exist and are surfaced in the trace. **Raw RFC822/EML parsing, Authentication-Results extraction and attachment-metadata analysis were NOT implemented.** |
| 10 — ML evaluation dashboard | **Not implemented as a page.** The data exists in `metrics.json` and `/api/ml/metadata`; no dedicated UI was built. |
| 12 — SOC event timeline | **Not implemented.** The audit log provides filtering by action/category/status/text, but no severity-ranked timeline view was added. |
| 13 — SOC dashboard upgrade | **Pre-existing** 16 KPIs + 6 charts verified DB-derived; not redesigned. |
| 14 — simulation funnel | **Pre-existing** campaign funnel retained; not rebuilt. |
| 15 — awareness score | **Pre-existing** transparent formula retained and documented; not changed. |
| 16 — incident report generator | **Pre-existing** PDF/CSV/JSON reporting retained; the richer executive-summary structure was not added. |
| 19 — database quality | **Reviewed, no changes needed.** FK enforcement, cascades, indexes and constraints were already verified in the earlier audit. |
| 22 — performance | Reviewed; see §11. No meaningful issues found, so nothing was changed. |
| 23 — UX | **Partial.** The detection trace is a substantial UX addition with keyboard support and `prefers-reduced-motion`; a broader empty/loading/validation-state pass was not done. |
| 24 — demo mode | **Partial.** Seeded demo data and documented accounts exist (`docs/DEMO_GUIDE.md`); no separate toggleable "demo mode" was built. |
| 25 — one-command setup | **Done.** `scripts/setup.py` added and verified end to end in a clean venv: detects missing dependencies, installs them, seeds the database, prints credentials, optionally starts the server. `--check` exits 1 when dependencies are missing. `docs/DEPLOYMENT.md` covers Windows/Linux/WSL/Docker. |

---

## 13. Future improvements

Ranked by value for effort:

1. **Model integrity hash.** Record a SHA-256 of `model.joblib` and verify on
   load. The threat model ranks untrusted pickle as the top residual ML risk.
2. **Raw EML parsing** (Phase 6 completion) using Python's `email` library —
   headers, Authentication-Results, attachment metadata only.
3. **ML evaluation page** rendering `metrics.json`, clearly separating
   *benchmark metrics* from *live detection results*.
4. **Per-object ownership checks** on reports, closing the multi-tenant IDOR gap.
5. **Calibration study** so "confidence" means something, plus a
   precision/recall trade-off curve for threshold selection.
6. **Temporal validation split** to measure drift honestly.
7. **Boot the Docker stack** and close the largest verification gap.
8. **Dependency CVE scanning** (`pip-audit`) in CI.
9. **Broader UX pass** on empty and loading states.
10. **Non-English keyword and brand coverage.**

---

## 14. Summary

**What was improved:** a genuine detection bug (whole-domain edit distance
defeating all typosquat detection) found and fixed; a pluggable offline
domain-intelligence layer; explainable brand-impersonation detection naming
five techniques; a six-stage detection decision trace; ML versioning and a
measured random-vs-group-split comparison across 5 seeds; request-ID
correlation and JSON security logging; a uniform API envelope; a 500-causing
input bug fixed; a CI pipeline including ML reproducibility; and six new
documents including a STRIDE threat model and a model card.

**What was tested:** 342 automated tests, 21 live acceptance steps, a 14-page
front-end crawl, an 18-point configuration checklist, a 12×3 RBAC matrix, a
6-sentinel credential-leak scan across 11 tables, a secrets-in-logs scan, 6
traceback probes, compile and import checks over 48 modules, and a full
retrain asserting metric reproducibility.

**What passed:** all of it — 342/342 tests, 21/21 acceptance steps, 0 dead
front-end controls, 0 RBAC violations, 0 credential leaks, 0 secret leaks, 0
tracebacks, 0 pyflakes findings, 0 security-check failures.

**What remains limited:** the model still misses one phishing URL in four;
detection is string-level only by design; Docker and CI were never actually
executed; raw EML parsing, the ML evaluation page and the SOC timeline were
not built; and the project is not penetration-tested. It is an internship
portfolio project, and it should be presented as one.

**Exact commands to run the final system:**

```bash
# setup
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
python scripts/seed_database.py                      # prints the admin API key once

# run
python run.py                                        # http://127.0.0.1:5000
# sign in: admin / Admin@Phish2026

# verify everything in this report
pytest -q                                            # 342 tests
pytest -q --cov=app                                  # 82% coverage
python scripts/acceptance_check.py                   # 21 live steps  (server must be running)
python scripts/frontend_check.py                     # dead-control crawl
flask security-check                                 # 18-point checklist
python train.py                                      # retrain; metrics reproduce exactly
python train.py --split group                        # group-aware comparison
```
