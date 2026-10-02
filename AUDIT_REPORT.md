# PhishGuard — Engineering Audit Report

**Project owner:** Sabyasachi Bhowmik · **Institution:** Andhra University

**Scope:** full correctness audit of the delivered platform, then repair.
**Method:** inspect first, change second.
**Status of this document:** rewritten on 2026-10-01 during the release-readiness
pass. **Every result below was re-executed in that pass** — nothing is carried
over on trust from an earlier session. Results specific to the release pass
(artifact removal, Docker secrets, API-key hashing) are in
`RELEASE_READINESS_REPORT.md`.

---

## A. Files changed

**Application code**

| File | Change |
|---|---|
| `app/config.py` | 8 `URL_*` heuristic thresholds + `CAMPAIGN_RISK_THRESHOLDS`; `DevelopmentConfig.DEBUG` honours `FLASK_DEBUG`; `DEV_SECRET_PLACEHOLDER` constant; hardened production secret guard. |
| `app/__init__.py` | 401/405 error handlers, `ERROR_SLUGS` map, `_wants_json()` so every `/api/` error is JSON. |
| `app/extensions.py` | `PRAGMA foreign_keys=ON` connect listener for SQLite. |
| `app/ml/feature_engineering.py` | Boundary-aware `find_brands()`; trimmed keyword list; entropy rule gated on host length. |
| `app/ml/predict.py` | Module-level `DISCLAIMER`; `disclaimer`/`caveat`/`sklearn_version` added to `model_metadata()`. |
| `app/models/audit_log.py` | `CAMPAIGN_MODIFIED` → `CAMPAIGN_UPDATED`, old name kept as an equal-valued alias. |
| `app/models/user.py` | **API keys stored as SHA-256 digests** (`api_key_hash`, `api_key_prefix`, `api_key_issued_at`); plaintext `api_key` column removed. |
| `app/models/{user,campaign,quiz,simulation}.py` | `passive_deletes=True` so DB-level `ON DELETE CASCADE` is used. |
| `app/routes/api.py` | Key lookup hashes the presented value; still one indexed query. |
| `app/routes/auth.py` | Rotation returns the raw key and reveals it once via `session`. |
| `app/routes/campaigns.py` | Uses `AuditAction.CAMPAIGN_UPDATED`. |
| `app/services/risk_engine.py` | `classify_score()` reads `RISK_BANDS` from config. |
| `app/services/url_analyzer.py` | Entropy/length/subdomain/hyphen/path rules read config. |
| `app/services/email_analyzer.py` | `IMPERSONATION_RE` rewritten; `RECEIVED_CHAIN` gated; `BODY_GIFT_CARD` 18 → 25. |
| `app/utils/security.py` | Strips `X-Powered-By`. |
| `run.py` | Custom `WSGIRequestHandler` suppressing the Werkzeug version banner. |

**Templates** — `detectors/url_result.html` (button `type`), `partials/macros.html` (disabled pagination → labelled `<span>`), `auth/profile.html` (one-shot key reveal).

**Tests** — `conftest.py` rewritten; the 9 required files written; 5 stale files deleted.

**Scripts** — `train.py` (new, root); `scripts/build_dataset.py` (path-depth balancing); `scripts/acceptance_check.py` (new); `scripts/frontend_check.py` (new); `scripts/seed_database.py` (captures issued keys).

**Data** — `data/datasets/url_dataset.csv` rebuilt (16,083 rows); `app/ml/model.joblib` + `metrics.json` retrained.

**Docs** — `README.md`, `SECURITY.md`, `docs/API.md`, `docs/ARCHITECTURE.md`, `.env.example`, `.gitignore`, `docker-compose.yml`.

---

## B. Bugs discovered

1. **`classify_score()` silently ignored configured risk bands** — it used `DEFAULT_BANDS` while only `RiskEngine.bands` read config, so retuning thresholds did nothing for direct callers.
2. **`FLASK_DEBUG=0` was ignored.** `DevelopmentConfig.DEBUG = True` was hardcoded. Observed in a real server log: `Debugger is active! Debugger PIN: 736-778-747` while bound to `0.0.0.0`.
3. **The ML model had learned a collection artefact.** `path_length` was the top feature (importance 0.276); `github.com/pallets/flask` scored **85.1/100**.
4. **Brand tokens matched inside unrelated words** (substring matching).
5. **Entropy rule fired on ordinary short hostnames.**
6. **Impersonation regex over-matched** — mentioning a help desk counted as impersonation.
7. **`RECEIVED_CHAIN` penalised partial header pastes.**
8. **Gift-card BEC under-scored** after fixing (7).
9. **`model_metadata()` published metrics with no disclaimer.**
10. **API returned HTML for 405**; unmatched `/api/` paths had no documented slug.
11. **`AuditAction.CAMPAIGN_MODIFIED`** did not match the required name.
12. **SQLite foreign keys were off**, so `ON DELETE CASCADE` never ran.
13. **`python train.py` did not exist.**
14. **Dead pagination controls** (`<a href="#">`).
15. **Six unused imports**; one button missing `type`.
16. **Test suite misorganised** — 5 files, none with the required names.

Found during the release pass (detailed in `RELEASE_READINESS_REPORT.md`):

17. **API keys were stored in plaintext.**
18. **Hardcoded PostgreSQL password and fallback `SECRET_KEY` in `docker-compose.yml`.**
19. **`Server: Werkzeug/3.1.9 Python/3.13.14`** disclosed exact framework and interpreter versions; the test that claimed to cover this only checked `X-Powered-By`.
20. **Production secret guard was narrow** — rejected one exact string, accepting `changeme`, 8-character keys, and `"a"*64`.
21. **Generated artifacts were present in the tree** (`instance/phishguard.db`, `instance/phishguard.log`, `.coverage`).

---

## C. Bugs fixed

All 21. Verification re-run in this pass:

| # | Fix | Verified by |
|---|---|---|
| 1 | `classify_score()` reads `RISK_BANDS` | `test_risk_bands_are_configurable` |
| 2 | `DEBUG = _bool("FLASK_DEBUG", True)`; production hard-off | 2 tests + live log now `Debug mode: off` |
| 3 | `balance_path_depth()`; retrained | importance 0.276 → **0.0275**; github URL 85.1 → **24.77** (re-measured) |
| 4 | Boundary-aware `find_brands()` | `test_url_detector.py` |
| 5 | Entropy needs `>4.0` **and** host ≥ 20 chars | `test_url_detector.py` |
| 6 | `IMPERSONATION_RE` requires self-identification | `test_email_detector.py` |
| 7 | `RECEIVED_CHAIN` requires a real transport block | `test_email_detector.py` |
| 8 | `BODY_GIFT_CARD` 18 → 25 | `test_email_detector.py` |
| 9 | Module `DISCLAIMER` in `model_metadata()` | `test_ml.py` |
| 10 | 405 handler + `ERROR_SLUGS` | live `DELETE /api/health` → 405 JSON |
| 11 | Renamed, alias retained | `test_security.py` |
| 12 | `PRAGMA foreign_keys=ON` + `passive_deletes` | `test_sqlite_foreign_keys_are_enforced` |
| 13 | `train.py` created | **re-run in this pass**, reproduced identical metrics |
| 14 | Disabled pagination → `<span>` | `frontend_check.py`: 0 dead links |
| 15 | Removed | pyflakes: 1 intentional `# noqa` probe only |
| 16 | 9 files, 5 deleted | `pytest -q` → 252 passed |
| 17 | SHA-256 digest + one-shot reveal | 3 new tests + acceptance step 13b |
| 18 | Required compose variables, no fallback | syntax validated; no literal secrets remain |
| 19 | Custom `WSGIRequestHandler` | live: exactly one `Server: PhishGuard` |
| 20 | Rejects empty/placeholder/short/low-variety | 7 cases, 6 rejected + 1 accepted |
| 21 | Deleted; `.gitignore` rewritten | tree re-scanned: clean |

---

## D. Security improvements

1. **API keys are no longer recoverable from the database** — SHA-256 digest, 8-character prefix for identification, one-shot reveal, constant-time verification.
2. **Interactive debugger can be switched off** and production cannot switch it on.
3. **No secrets in `docker-compose.yml`** — required variables with no fallback.
4. **Production refuses seven classes of weak `SECRET_KEY`.**
5. **Framework and interpreter versions no longer advertised.**
6. **Foreign keys enforced in SQLite**; audit trail survives actor deletion (`ON DELETE SET NULL` + denormalised `actor_username`).
7. **Uniform JSON error contract** across 400/401/403/404/405/413/429/500.
8. **All 8 required audit actions present and emitted** by the routes that perform them.
9. **Risk thresholds in config**, documented in `.env.example`.

Re-verified unchanged: PBKDF2-SHA256 600,000 iterations, CSRF on all state-changing posts, CSP without `unsafe-inline`, HttpOnly/SameSite cookies, rate limiting, `.env` git-ignored and absent, HSTS on in production.

---

## E. Test count

**252 tests** across the 9 required files.

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

## F. Actual test results

```
$ pytest -q
252 passed in 13.42s

$ pytest -q --cov=app
TOTAL    3278 statements    575 missed    82% coverage
```

Baseline at the start of the audit: **130 passed**. Now **252 passed, 0 failed**.

Failures were not papered over. The first real run of the regrouped suite was
**8 failed / 232 passed**, and three of those were genuine product bugs (B1,
B8, B9). During the release pass two further tests failed for real — the
configuration checklist (my own refactor tripped the hardcoded-secret scanner)
and the `Server` banner assertion — and both were fixed rather than relaxed.

Other checks executed in this pass:

```
$ python scripts/acceptance_check.py    →  21 passed, 0 failed   (exit 0)
$ python scripts/frontend_check.py      →  0 dead links, 0 orphan buttons,
                                           0 broken internal links (exit 0)
$ flask security-check                  →  18 checks: 17 pass, 1 warn, 0 fail
$ python -m pyflakes app/ scripts/ tests/  →  1 intentional noqa probe
$ python -m compileall app scripts tests   →  OK
$ 44 app modules imported                  →  0 failures
```

The one warning is the placeholder `SECRET_KEY` in the dev profile — correct
behaviour; production refuses to start with it.

---

## G. How to run

```bash
cd phishguard
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python scripts/seed_database.py                      # --reset to wipe first
python run.py                                        # http://127.0.0.1:5000
```

`pytest -q` runs the suite. `flask security-check` runs the configuration
checklist. For Docker, create `.env` with `SECRET_KEY` and `POSTGRES_PASSWORD`
first — see README §9.

---

## H. Demo credentials

All identities are fictional.

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@Phish2026` |
| Security analyst | `analyst` | `Analyst@Phish2026` |
| Security analyst | `nadia.analyst` | `Analyst@Phish2026` |
| Demo participant | `priya.demo` (15 `*.demo` accounts) | `Demo@Phish2026` |

The seeder prints the `admin` API key once. It is not recoverable afterwards —
rotate from `/profile` to get a new one.

---

## I. Known limitations

1. **The ML model is a demonstration model.** 0.8514 accuracy / 0.8364 F1 on a held-out split of a public research corpus — not a claim about live traffic. It misses roughly one phishing URL in four (406 FN of 1,628).
2. **Removing the two dataset confounds cost real accuracy** (0.8857 → 0.8514). The higher number was partly measuring artefacts.
3. **Heuristics produce false positives and negatives.** Known residual: `portal.cybersafe.edu/password/renew` scores MEDIUM.
4. **String-level analysis only** — no DNS, page fetch, TLS inspection, WHOIS or reputation feed.
5. **HTTPS is never treated as safety**; SPF/DKIM/DMARC prove the domain, not intent.
6. **Campaign figures are simulation metrics**, not phishing prevalence.
7. **No automated retention or purge job** — documented in `docs/ARCHITECTURE.md` with a manual procedure.
8. SQLite and in-memory rate limiting by default; synchronous report generation; English-only; no accessibility audit; not penetration-tested.

---

## J. Remaining issues

Nothing known is broken. Deliberately not done:

1. **Coverage is 82 %.** Thinnest modules: `utils/decorators.py`, `utils/redaction.py`, `utils/formatting.py`, `utils/validators.py`, `services/ml_detector.py`, `services/report_service.py` — mostly defensive branches.
2. **`CAMPAIGN_MODIFIED` alias retained** for backwards compatibility.
3. **`data/datasets/.cache/` is not committed**, so `build_dataset.py` re-downloads a 15.4 MB archive. The built CSV is committed, so training works offline.
4. **`acceptance_check.py` mutates the demo database.** Re-run `python scripts/seed_database.py --reset` afterwards.
5. **The dev-profile `SECRET_KEY` warning is intentional.**
6. **`flask db migrate` reports no changes against a seeded DB** — autogenerate needs a blank database.
7. **Docker Compose was not booted** — no Docker daemon in the verification sandbox. Syntax and variable wiring were validated statically; the stack itself is unverified.
