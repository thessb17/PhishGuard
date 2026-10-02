# PhishGuard — Startup / Localhost Reachability Fix

**Date:** 2026-10-01
**Reported:** the application is not reachable at `http://localhost:5000/`.
**Status:** Reproduced, two root causes found, both fixed and verified.

Every figure below came from running the command shown against this build.
No detection logic, ML model, or CSRF protection was changed.

---

## 1. Original startup problem

`http://localhost:5000/` did not respond. Two independent causes were found —
one operational, one a genuine defect in `run.py`.

---

## 2. Exact error

**Cause 1 — nothing was listening.**

```
$ ss -ltnp | grep ':5000'
  NOTHING listening on 5000

$ curl -i http://127.0.0.1:5000/
  (connection failed)
```

The server process was not running. There was no traceback because there was
no process.

**Cause 2 — IPv4/IPv6 mismatch, reproduced after starting it.**

```
$ python3 -c "import socket; print(socket.getaddrinfo('localhost', 5000, ...))"
  localhost    -> ('::1', 5000, 0, 0)      <- IPv6 FIRST
  127.0.0.1    -> ('127.0.0.1', 5000)

$ HOST=0.0.0.0 python run.py
$ ss -ltn | grep 5000
  LISTEN 0 128  0.0.0.0:5000  0.0.0.0:*    <- IPv4 ONLY

$ curl http://127.0.0.1:5000/   -> 302
$ curl http://localhost:5000/   -> 302     (curl retries over IPv4)
$ curl http://[::1]:5000/       -> CONNECTION REFUSED
```

---

## 3. Root cause

**Two defects, both in `run.py`:**

**(a) The default bind was loopback-only.** `run.py` defaulted to
`HOST=127.0.0.1`. Anything outside that interface — a container port mapping,
a preview proxy, another machine — could not reach it. Every previous start
in this project had to pass `HOST=0.0.0.0` explicitly, which is a trap for
anyone running `python run.py` as documented.

**(b) `0.0.0.0` is IPv4-only, but `localhost` resolves to `::1` first.** On
this host — and most modern Linux — `getaddrinfo("localhost")` returns the
IPv6 loopback ahead of the IPv4 one. A socket bound to `0.0.0.0` does not
accept IPv6 connections, so the first connection attempt to
`http://localhost:5000` is **refused**. `curl` silently retries over IPv4 and
appears to work; a client that does not retry simply fails. That is precisely
the reported symptom: `127.0.0.1:5000` works, `localhost:5000` does not.

Binding `::` with `IPV6_V6ONLY=0` serves both families from one socket:

```
$ HOST=:: python run.py
  bound: LISTEN 0 128  *:5000  *:*
  127.0.0.1    -> 302
  localhost    -> 302
  [::1]        -> 302
```

---

## 4. Files changed

| File | Change |
|---|---|
| `run.py` | `_pick_host()` — defaults to dual-stack `::`, falls back to `0.0.0.0` where IPv6 is unavailable, honours an explicit `HOST`. `_port_available()` — detects a busy port and names the owning PID. `_preflight()` — 9 startup checks. New startup banner. Debugger forced off on any non-loopback bind. Password removed from first-run output. |
| `app/routes/dashboard.py` | Added unauthenticated `GET /health`. |
| `scripts/smoke_test.py` | **New** — 9-step live end-to-end check, exits non-zero on failure. |
| `tests/test_startup.py` | **New** — 39 tests, no running server required. |

**Unchanged:** detection services, ML model and pipeline, `CSRFProtect`,
`WTF_CSRF_ENABLED`, cookie defaults, all blueprints and routes.

---

## 5. Dependency changes

**None.** A clean `.venv_test` installed `requirements.txt` with exit code 0
and no conflicts. Nothing was repinned.

---

## 6. Host / port configuration

| Setting | Before | After |
|---|---|---|
| Default host | `127.0.0.1` (loopback only) | `::` dual-stack, `0.0.0.0` fallback |
| Default port | `5000` | `5000` (unchanged) |
| `HOST` / `PORT` env | supported | supported |
| Debugger on public bind | possible | **forced off**, with a printed notice |
| Port already in use | opaque `OSError` | named PID + `PORT=5001` suggestion, exit 1 |

Observed:

```
Port 5000 is already in use.
  LISTEN 0 128 *:5000 *:* users:(("python3",pid=1482,fd=6))
  Start on another port:  PORT=5001 python run.py
exit: 1
```

`PORT=5001 python run.py` then served `/health` → 200 alongside the first
instance.

The debugger guard fires on every non-loopback bind:

```
NOTE: debugger disabled because the server is bound to :: (not loopback).
Debug       : OFF
```

---

## 7. Database initialisation result

`instance/phishguard.db` deleted, then in the clean venv:

```
$ python scripts/seed_database.py     exit 0
Database    : PASS 11 tables
```

`run.py` also self-initialises on first run if the database is absent.

---

## 8. ML startup result

The existing artifact is loaded; **no retraining happens at startup**.

```
ML model    : PASS loaded from app/ml/model.joblib
```

Missing or unloadable artifacts degrade to `WARN` with the rebuild command
(`python train.py`) rather than blocking startup. A live detector request
returned HTTP 200 with a full 6-stage detection trace.

---

## 9. CSRF result

Unchanged and still enabled:

```
CSRF        : ENABLED
```

`app.extensions['csrf'] is app.extensions.csrf` → one instance, asserted by
test. Development cookie policy verified as `Secure=False`,
`HttpOnly=True`, `SameSite=Lax`. All CSRF regression tests from the previous
pass still pass.

---

## 10. `localhost` result

```
http://localhost:5000/        -> 302
http://localhost:5000/health  -> 200

$ curl -I http://localhost:5000/
HTTP/1.1 302 FOUND
Server: PhishGuard
```

---

## 11. `127.0.0.1` result

```
http://127.0.0.1:5000/        -> 302
http://127.0.0.1:5000/health  -> 200
http://[::1]:5000/            -> 302

$ curl -I http://127.0.0.1:5000/
HTTP/1.1 302 FOUND
Server: PhishGuard
```

All three hostnames now behave identically.

---

## 12. `/health` result

```
$ curl http://127.0.0.1:5000/health
{"database":"ok","ml":"ok","service":"PhishGuard","status":"ok","version":"1.0.0"}
```

Unauthenticated, `Cache-Control: no-store`, returns **503** with
`"status":"degraded"` when a component fails. Verified by test that it leaks
no secret, connection string, or filesystem path, and that a simulated
database failure produces 503 without surfacing the exception text.

---

## 13. Test results

Clean `.venv_test`, database deleted and rebuilt from zero:

```
$ python -m compileall -q app scripts tests        OK
$ python -c "from app import create_app; ..."      APP IMPORT OK
$ python -c "from run import app; ..."             run import OK: 56 routes
$ python scripts/seed_database.py                  exit 0

$ pytest -q                                        446 passed in 25.67s
$ pytest --cov=app --cov-report=term-missing       TOTAL 3824 639 83%
$ python scripts/security_check.py                 18 checks - 17 passed, 1 warnings, 0 failures
$ python scripts/frontend_check.py                 PASS - every button, link and form resolves
$ python scripts/acceptance_check.py               21 passed, 0 failed out of 21
$ python scripts/smoke_test.py                     9/9 checks passed
```

Test count 407 → **446** (+39 startup tests). No test was weakened.

Static assets, all 200: `phishguard.css`, `app.js`, `detector.js`,
`bootstrap.min.css`, `chart.umd.min.js`, `bootstrap-icons.css`,
`favicon.svg`.

### Two faults found in my own work while writing the tests

1. **A password was printed at startup.** The first-run auto-initialiser
   printed `Sign in with admin / Admin@Phish2026`, which the brief explicitly
   forbids. Caught by `test_startup_banner_does_not_print_passwords`. Now
   prints account *names* and points at the seeder for credentials.
2. **The smoke test's logout check passed vacuously.** It asserted
   `status in (302, 401)` while the client follows redirects, so a logged-out
   `/dashboard` returned 200 from the login page it landed on. Rewritten to
   assert on page content. Logout itself was always correct
   (`302 → /login?next=/dashboard`, verified with a non-redirecting client).

---

## 14. Remaining issues

1. **The sandbox is not your machine.** If `localhost:5000` is typed into a
   browser on your own computer, it reaches *your* computer. This application
   runs in a remote sandbox and is reachable only through the preview URL the
   platform provides. Everything in §10–11 was measured from inside the
   sandbox, where `localhost` is correct.
2. **Cross-origin iframe form submissions still fail** with `SameSite=Lax`.
   This is a browser cookie rule, unchanged by this work, and documented in
   `docs/CSRF_ROOT_CAUSE_REPORT.md` §12. Opening the preview in a normal tab
   avoids it.
3. **Docker and GitHub Actions remain unexecuted** — no daemon, no runners.
4. Coverage is 83%; the untested remainder is mostly defensive branches.
