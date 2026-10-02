# PhishGuard — Final Debug Report

**Date:** 2026-10-01
**Rule followed:** every number below was produced by executing the command
shown, in a **freshly created virtual environment**, during this session.
No figure is carried over from any earlier report.

---

## 1. Original failure

I was told the current build contained an error. I did **not** assume where it
was. I reproduced the whole project from zero in a clean environment and
exercised every subsystem.

**The dependency install, imports, compilation, database creation, migrations,
test suite, ML pipeline and HTTP surface all passed unmodified.** There was no
crash, no import error, no dependency conflict, and no failing test.

Two genuine defects were found by targeted probing. The first is the
substantive one.

### Defect 1 — the email Detection Trace was dead code (functional regression)

The Detection Trace is the project's flagship explainability feature. It was
present on the URL result page and **entirely absent from the email result
page**, even though the function to build it existed and worked.

Measured before the fix:

```
URL result:
   'Detection trace' panel : True
   pipeline stages rendered: 6
EMAIL result:
   'Detection trace' panel : False
   pipeline stages rendered: 0
```

### Defect 2 — the project's own verification scripts crashed with a traceback

Running either script without the server up produced a raw Python stack
trace — the exact behaviour the application itself is held to avoid.

---

## 2. Exact error messages

**Defect 1** produced no exception. That is precisely why it survived: a
silently missing UI panel raises nothing. The evidence was a grep:

```
$ grep -rn "build_email_trace" app/ tests/
app/services/detection_trace.py:210:def build_email_trace(rule_result, ml_result, risk) -> list[dict]:
```

One hit — the definition. No caller anywhere.

**Defect 2:**

```
$ python scripts/frontend_check.py        # server not running
Traceback (most recent call last):
  File "/usr/local/lib/python3.13/urllib/request.py", line 1348, in http_open
    return self.do_open(http.client.HTTPConnection, req)
  File "/usr/local/lib/python3.13/urllib/request.py", line 1322, in do_open
    raise URLError(err)
urllib.error.URLError: <urlopen error [Errno 111] Connection refused>
EXIT: 1
```

---

## 3. Root cause

**Defect 1.** In the Phase 11 (detection trace) work, `detection_trace.py` was
written with **two** builders — `build_url_trace` and `build_email_trace`.
Only the URL path was then wired end to end: the route was updated, the
template macro imported, the panel rendered. The email path was left at the
service layer and never connected to its route or template.

Two things let it through:

1. **No test referenced `build_email_trace`.** Coverage counted the module as
   exercised because the URL builder beside it was heavily tested.
2. **No integration test asserted the email result page contains a trace**,
   so the absent panel was invisible to the suite.

It was recorded as "implemented" because the function existed and worked when
called directly — which it never was.

**Defect 2.** Both scripts call `urllib.request.urlopen` at module level with
no connectivity check. Any connection error propagates as an unhandled
exception.

---

## 4. Files responsible

| File | Role in the defect |
|---|---|
| `app/services/detection_trace.py` | Defined `build_email_trace`; never imported by any caller |
| `app/routes/email_detector.py` | Rendered `email_result.html` without a `trace` argument |
| `app/templates/detectors/email_result.html` | Never imported or invoked the `detection_trace` macro |
| `tests/test_detection_intel.py` | Covered only the URL trace |
| `scripts/acceptance_check.py` | No connectivity preflight |
| `scripts/frontend_check.py` | No connectivity preflight |

---

## 5. Fix applied

**Defect 1 — wire the existing builder through, change no logic:**

* `app/routes/email_detector.py`: added
  `from app.services.detection_trace import build_email_trace` and passed
  `trace=build_email_trace(rule_result, ml_result, risk)` to the template.
* `app/templates/detectors/email_result.html`: imported the shared
  `detection_trace` macro and rendered it after the explanation panel, opening
  on the `layer_body` stage (the most informative one for an email).

**Defect 2 — a shared preflight in both scripts:**

```python
def _preflight(base: str) -> None:
    try:
        urllib.request.urlopen(base + "/api/health", timeout=5).read()
    except urllib.error.HTTPError:
        return                       # reachable; a non-200 is the test's business
    except Exception as exc:
        print(f"ERROR: cannot reach PhishGuard at {base}", file=sys.stderr)
        print(f"       {type(exc).__name__}: {exc}", file=sys.stderr)
        print("       Start the server in another terminal first:", file=sys.stderr)
        print("           python run.py", file=sys.stderr)
        sys.exit(2)
```

Observed after the fix:

```
ERROR: cannot reach PhishGuard at http://127.0.0.1:5000
       URLError: <urlopen error [Errno 111] Connection refused>

       Start the server in another terminal first:
           python run.py
       then re-run this script.
exit: 2
```

**Six regression tests added** to `tests/test_detection_intel.py`:

| Test | Guards |
|---|---|
| `test_email_trace_builds_and_is_serialisable` | the builder runs and is JSON-safe |
| `test_email_trace_has_input_fusion_and_verdict_stages` | expected stage structure |
| `test_email_trace_verdict_matches_the_risk_engine` | trace cannot disagree with the verdict |
| `test_email_detector_page_renders_the_detection_trace` | **the actual regression** — page contains the panel |
| `test_url_detector_page_still_renders_the_detection_trace` | the URL path did not regress |
| `test_verification_scripts_fail_cleanly_without_a_server` | exit 2, no traceback, helpful message |

### Defect 3 — found in my own regression test, during final verification

The last of those six tests initially used a literal string replace to repoint
`BASE` at a closed port. The two scripts spell the assignment differently —
`BASE = "..."` in `acceptance_check.py`, `BASE="..."` in `frontend_check.py` —
so the substitution **silently matched only one of them**. With the server
down (the state during the first run) both scripts exited 2 regardless, so the
test passed for the wrong reason. Re-running the suite with the server **up**
exposed it immediately:

```
FAILED tests/test_detection_intel.py::test_verification_scripts_fail_cleanly_without_a_server
1 failed, 347 passed
```

Fixed by switching to a regex and **asserting the substitution happened**:

```python
patched, n = re.subn(r'^BASE\s*=\s*["\'][^"\']+["\']',
                     'BASE = "http://127.0.0.1:1"', source, count=1, flags=re.M)
assert n == 1, f"could not repoint BASE in {script} - test would be vacuous"
```

The test now passes **with the server running**, which proves it exercises the
preflight rather than ambient conditions. This is the same class of fault as
Defect 1 — something reported as verified that was not actually being
exercised.

No existing test was weakened, deleted or relaxed. No feature was disabled,
no exception suppressed, no security control touched.

---

## 6. Why the fix works

The trace builders are **pure presentation over data the analysers already
return** — they recompute nothing. Wiring the email builder therefore cannot
change any score; it only surfaces what was already computed. This is proved
rather than asserted: `test_email_trace_verdict_matches_the_risk_engine`
compares the trace's verdict against the live `RiskAssessment`.

Verified on the running application after the fix:

```
URL  : trace=True  stages=6
EMAIL: trace=True  stages=8
```

The preflight fix is a guard clause, not a swallowed exception — the failure
is still fatal (exit 2), just legible.

---

## 7. Dependency changes

**None.** `requirements.txt` was audited and left unmodified, because the
clean install succeeded with no conflicts:

```
$ python -m venv /tmp/.venv_final
$ pip install -r requirements.txt
install exit: 0
```

Installed and verified:

| Package | Version |
|---|---|
| Flask | 3.1.3 |
| SQLAlchemy | 2.1.1 |
| scikit-learn | 1.6.1 |
| pandas | 2.2.3 |
| numpy | 2.3.5 |

Python 3.13.14. No deprecation errors, no resolver backtracking, no build
failures (`psycopg2-binary` and `reportlab` both installed from wheels).
Changing pins without a demonstrated problem would have been churn.

---

## 8. Database changes

**None to the schema.** Verified instead:

```
$ rm -f instance/phishguard.db && python scripts/seed_database.py
SEED EXIT: 0                     18 users, 5 campaigns, 40 events, 4 reports

$ python scripts/seed_database.py --quiet        # duplicate seeding
RESEED EXIT: 0                   no corruption

$ flask db upgrade               # on a fresh database
Running upgrade  -> 20d5746fcc32, Initial PhishGuard schema
Running upgrade 20d5746fcc32 -> 3a1c7f0b52e4, Store API keys as SHA-256 digests
EXIT: 0

Schema parity (migrations vs models):
  model tables: 11 | migration tables: 11
  only in models   : none
  only in migration: none
  VERDICT: SCHEMAS MATCH

$ flask init-db / flask seed-db   both exit 0
```

---

## 9. Security changes

**None were required, and none were weakened.** Re-verified in this session:

| Check | Result |
|---|---|
| Cookie-less API auth | no credential → 401, bad key → 401, short key → 401, bad bearer → 401 |
| Session-vs-key confusion | an earlier probe appeared to bypass auth; re-tested **without a cookie jar** it was the admin session, not a bypass |
| Account lockout | 12 bad logins → `401×5, 423×4, 429×3` — lockout **and** rate limit both fire |
| Hostile `X-Request-ID` | `<script>alert(1)</script>` not echoed; replaced with a generated ID |
| Overlong `X-Request-ID` | 200-char value rejected, generated ID used |
| Clean `X-Request-ID` | `test123` echoed; body `request_id` matches the header |
| Hostile URL schemes | `javascript:` → 400 `validation_error` |
| Malformed JSON | 400 `validation_error` |
| API responses | all JSON, no HTML, no exceptions leaked |
| `security_check.py` | 18 checks, 17 pass, **1 warn, 0 fail** |

The single WARN is the development placeholder `SECRET_KEY`. Investigated:
it is intentional — `ProductionConfig.init_app` refuses to start on it, and
that refusal is covered by tests. Not a defect.

---

## 10. Tests run

In the final clean environment (`/tmp/.venv_final`), in this order:

```
python -m compileall -q app scripts tests      exit 0
python scripts/setup.py                        Setup complete
python scripts/seed_database.py                exit 0
pytest -q                                      exit 0
pytest --cov=app --cov-report=term-missing     exit 0
python scripts/security_check.py               exit 0
python scripts/frontend_check.py               exit 0
python scripts/acceptance_check.py             exit 0
```

Plus targeted probing: a 17-case URL input matrix, an 8-case email matrix, an
API endpoint sweep, cookie-less auth tests, request-ID handling, report
download in 3 formats, quiz submission, rate limit/lockout, migration parity,
ML consistency across 10 URLs, and `train.py` reproducibility.

---

## 11–14. Actual results

| Metric | Value |
|---|---|
| **Test count** | **348** |
| **Passed** | **348** |
| **Failed** | **0** |
| **Coverage** | **83%** (3,700 statements, 628 missed) |

```
$ pytest -q
348 passed in 17.73s

$ pytest --cov=app --cov-report=term-missing
TOTAL    3700    628    83%
348 passed, 2 warnings in 29.43s
```

The 2 warnings appear only under `--cov` and originate from the coverage
plugin, not the application; a plain `pytest -q` run reports none.

Test count rose 342 → 348 because six regression tests were added. No test
was removed.

---

## 15. Acceptance result

```
$ python scripts/acceptance_check.py
21 passed, 0 failed out of 21 acceptance steps
EXIT: 0
```

---

## 16. Security-check result

```
$ python scripts/security_check.py
18 checks - 17 passed, 1 warnings, 0 failures
EXIT: 0
```

---

## 17. Frontend-check result

```
$ python scripts/frontend_check.py
scanned 14 pages: 90 buttons, 349 links, 70 forms
dead links (href='#' with no JS hook): 0
buttons with no type and no JS hook   : 0
forms posting off-site                : 0
internal links probed: 26; broken (>=400, excluding 403): 0
PASS - every button, link and form resolves
EXIT: 0
```

---

## 18. Docker result

**NOT TESTED — no Docker daemon in this environment.**

```
$ which docker docker-compose
  docker: NOT AVAILABLE in this environment
```

`docker compose build` and `docker compose up` could not be executed. The
compose file was re-checked statically: `SECRET_KEY`, `POSTGRES_USER`,
`POSTGRES_PASSWORD` and `POSTGRES_DB` are all `${VAR:?error}` (required, no
fallback) and no literal secret remains. **The running stack remains
unverified.**

---

## 19. Remaining limitations

**Fixed in this session:** the email Detection Trace; the traceback-on-startup
in both verification scripts.

**NOT FIXED — out of scope or not possible here:**

| Item | Status and reason |
|---|---|
| **Docker** | **NOT TESTED.** No daemon available. |
| **Browser automation smoke test** | **NOT RUN.** No browser automation tool available; an HTTP smoke test was performed instead (documented in §10). |
| **Gunicorn `Server` header** | **NOT FIXED.** The Werkzeug dev-server banner is suppressed in `run.py`; gunicorn sets its own, which needs a reverse proxy. Not reachable from application code. |
| **GitHub Actions** | **NOT EXECUTED.** YAML validated and every step reproduced locally; never run on GitHub runners. |
| **PostgreSQL profile** | **NOT EXECUTED.** Migrations verified on SQLite only. |
| **Coverage 83%** | Untested remainder is mostly defensive branches: `utils/decorators.py`, `utils/redaction.py` (64%), `utils/formatting.py` (68%), `utils/observability.py` (73%). |

**Unchanged project limitations** (detection quality, demonstration-grade ML,
single-tenancy, no retention job, not penetration-tested) are catalogued in
`docs/LIMITATIONS.md` and were not affected by this work.

---

## 20. Quality gate

Verified in the final clean environment:

| Gate | Result |
|---|---|
| Clean dependency installation | PASS — exit 0, no conflicts |
| Application imports | PASS — `APPLICATION IMPORT OK` |
| Database initializes from zero | PASS — 18 users seeded |
| Migrations work | PASS — schema parity with models |
| Application starts | PASS — `Debug mode: off`, ML model loaded |
| Admin / Analyst / Demo login | PASS |
| RBAC | PASS — 12 routes × 3 roles, 0 violations |
| URL detector | PASS — 17 inputs, 0 HTTP 500, 0 tracebacks |
| Email detector | PASS — 8 inputs, 0 HTTP 500, 0 tracebacks |
| ML training | PASS — metrics reproduce to 1e-4 |
| ML inference | PASS — works with training module import-blocked |
| Hybrid risk engine | PASS |
| **Detection trace matches risk engine** | **PASS — 10 URLs, 0 inconsistencies** |
| Safe simulation | PASS — 4 event types only |
| No credential collection | PASS — `SIMULATION_COLLECT_CREDENTIALS=False`, schema has no field |
| Dashboard uses real data | PASS |
| API | PASS — envelope correct on every endpoint, no HTML |
| Reports | PASS — PDF (`%PDF-`), CSV, JSON all download |
| Audit logging | PASS |
| Security checks | PASS — 0 failures |
| Frontend checks | PASS — 0 dead controls |
| Tests pass | PASS — 348/348 |
| Coverage measured | PASS — 83% |
| Docker | **NOT TESTED** |
| No secrets/runtime artifacts distributed | PASS — see below |
| Clean-room reproduction | PASS |

Distributable cleanliness, re-checked after the final run:

```
instance/phishguard.db   removed
instance/phishguard.log  removed
.coverage                removed
coverage.xml             removed
.pytest_cache            removed
__pycache__              removed
.env                     absent (and git-ignored)
.env.example             present
```

All of these are git-ignored and regenerate on first run.

---

## 21. Honest summary

The build was **not broken in the sense of crashing**. A full clean-room
reproduction — new venv, fresh install, zero database — completed without a
single error before I changed anything.

What was actually wrong was a **silent functional regression**: the email
Detection Trace existed as working code that nothing ever called, so the
flagship explainability feature was missing from half the places it was
documented to appear. It raised no exception, failed no test, and reduced no
coverage number, which is exactly why it survived three previous audit passes
that all reported success.

That is the more useful lesson than a stack trace would have been: *a green
test suite proves the code you tested works, not that the feature is wired
up.* The fix is six lines of wiring plus six tests that would now catch it.
