# PhishGuard — CSRF Root Cause Report

**Date:** 2026-10-01
**Status:** Reproduced, root cause proven, fixed, and structurally prevented.
**CSRF protection was strengthened. Nothing was disabled, exempted, or relaxed.**

Every figure below came from running the command shown against this build.

---

## 1. Exact failing request

```
POST /login
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded
Cookie: (none sent)
Body: csrf_token=<91 chars, valid>&username=admin&password=...

-> HTTP 400  "CSRF validation failed"
   "Your session token expired or was missing."
```

The same failure occurred on **every** state-changing POST — `/url-detector`,
`/email-detector`, `/campaigns/create`, `/quiz`, `/profile/api-key`. `GET /`
was never involved.

---

## 2. Exact root cause

**Cause G: `SESSION_COOKIE_SECURE=1` while serving plain HTTP.**

I started the server with `SESSION_COOKIE_SECURE=1` and
`SESSION_COOKIE_SAMESITE=None`. The browser accepted and stored the cookie,
then — correctly — **refused to send it back over `http://`**, because
`Secure` means "never transmit this cookie over cleartext".

Flask therefore received no session on every subsequent request. Flask-WTF
stores the CSRF secret *inside the session*, so it had nothing to validate
the submitted token against and raised `CSRFError`. The error message blamed
CSRF for what was purely a cookie-transport failure.

**The CSRF token was never the problem.** It was rendered correctly and
submitted correctly on every request.

Reproduction, using a standards-compliant cookie jar (no overrides):

```
GET /login -> 200
  cookie stored by jar : 1 cookie(s)
    phishguard_session  secure=True  samesite=None
  csrf token in HTML   : PRESENT (len 91)

POST /login -> HTTP 400
  'CSRF validation failed' on page : True
  reached dashboard                : False
```

`SameSite=None` compounded it (**cause H**): browsers *require* `Secure` with
`SameSite=None`, so the two settings were locked together — I could not drop
`Secure` without also abandoning `None`.

### Causes positively excluded, with evidence

| Candidate | Evidence it was not the cause |
|---|---|
| **A** token not rendered | `csrf token in HTML : PRESENT (len 91)` |
| **B** token not submitted | log: `csrf_form=PRESENT` |
| **D** token from another session | reproduced with a single clean session |
| **E** `SECRET_KEY` changes | `SECRET_KEY identical across 3 create_app(): True` |
| **F** CSRF secret changes | `WTF_CSRF_SECRET_KEY` unset → signs with the stable `SECRET_KEY` |
| **I/J** multiple CSRFProtect instances | one instance at `app/extensions.py:39`; `app.extensions['csrf'] is shared → True` |
| **K** JS missing `X-CSRFToken` | no JS makes unsafe requests; failure reproduced with no JS at all |
| **L** stale cache | reproduced on a first-ever request in a brand-new jar |
| **M** form posts to wrong route | `POST /login` reached `endpoint=auth.login` |
| **C** session cookie missing | **This is the symptom. G is why.** |

The in-application diagnostic now prints the signature directly:

```json
{"action":"csrf_rejected","endpoint":"auth.login",
 "session_cookie":"MISSING","csrf_session":"MISSING",
 "csrf_form":"PRESENT","csrf_header":"MISSING",
 "scheme":"http","secure_cookie":false,"samesite":"Lax",
 "reason":"The CSRF session token is missing."}
```

`csrf_form=PRESENT` with `session_cookie=MISSING` is the fingerprint of this
bug: the client did everything right; the cookie never arrived.

---

## 3. Why the previous implementation failed

The previous pass identified this mechanism correctly and even measured it
(`SESSION_COOKIE_SECURE=1` over HTTP → login 400). It then documented
`SameSite=None; Secure` as the configuration for an embedded HTTPS preview,
and I **started the server that way** — reasoning that the preview proxy
serves HTTPS, so `Secure` would be satisfied.

That reasoning was wrong for anyone reaching the app at
`http://localhost:5000`. The previous fix also only added *detection*
(a startup warning) and *recovery* (a better error page, a session-reset
link). A warning in a log nobody reads does not stop the server from booting
into a state where every form is broken.

**The gap was that nothing prevented the misconfiguration.** That is what
changed.

---

## 4. Files changed

| File | Change |
|---|---|
| `run.py` | **Hard guard**: refuses to start when `SESSION_COOKIE_SECURE` is set outside production, because this entry point serves plain HTTP. Escape hatch `ALLOW_SECURE_COOKIE_OVER_HTTP=1` for a TLS-terminating proxy. |
| `app/__init__.py` | CSRF rejections now logged with presence-only diagnostics (method, path, endpoint, cookie/session/form/header presence, scheme, host, origin, referer, cookie policy, reason, request id). |
| `app/routes/auth.py` | Added `/__debug__/session` (development only, 404 in production). |
| `tests/test_csrf_session.py` | **New** — 27 tests pinning cause and fix. |

**Not changed:** `CSRFProtect` registration, `WTF_CSRF_ENABLED`,
`WTF_CSRF_TIME_LIMIT` (still 3600s), exemption lists (still none for browser
routes), any form, any template token.

---

## 5. Configuration changed

The committed defaults were already correct and are unchanged:

| Profile | SameSite | Secure | Status |
|---|---|---|---|
| development | `Lax` | `False` | correct for `http://localhost` **and** same-origin HTTPS |
| production | `Lax` | `True` | unchanged, enforced by test |

What changed is that the broken combination is now **impossible to run by
accident**:

```
$ SESSION_COOKIE_SECURE=1 python run.py
  PhishGuard cannot start: SESSION_COOKIE_SECURE=1 with the plain-HTTP development server.
  A browser will NOT return a Secure cookie over http://, so the
  session is lost on every request and all form submissions fail
  with 'CSRF validation failed'.
  For local development (http://localhost:5000) use:
      SESSION_COOKIE_SECURE=0
      SESSION_COOKIE_SAMESITE=Lax
exit code: 1            (stdout lines: 0 — the banner never prints)
```

Production is untouched: it is served by gunicorn behind TLS, not by this
entry point, and `ProductionConfig.SESSION_COOKIE_SECURE` remains `True`.

---

## 6. How session persistence was verified

`/__debug__/session`, exercised in the Phase-2 sequence over plain HTTP with
a standard cookie jar:

```
1st GET            cookie=False csrf_session=False auth=False secure=False samesite=Lax
reload             cookie=True  csrf_session=False auth=False
3rd GET            cookie=True  csrf_session=False auth=False
after /login page  cookie=True  csrf_session=True  auth=False
after login POST   cookie=True  csrf_session=True  auth=True  user=admin
```

The session is issued on the first response, returned on every subsequent
request, gains its CSRF token when a form is rendered, and carries the
authenticated identity after login. Under the broken configuration
`cookie` stayed `False` forever.

---

## 7. How CSRF token persistence was verified

* `test_csrf_token_stays_valid_within_the_same_session` — a token minted on
  one page still validates after unrelated navigation.
* `test_fresh_token_works_after_a_failure` — after a rejected POST, reloading
  issues a token that works.
* `test_expired_token_fails_safely` — with a 1-second limit and a frozen
  clock, an aged token is rejected (400). Expiry was **not** extended.
* `test_secret_key_is_stable_across_application_restarts` — the dev secret is
  identical across three `create_app()` builds, so tokens survive a restart.

Live restart check:

```
login after restart        -> HTTP 200, dashboard=True
state-changing op after it -> HTTP 200, csrf_error=False
```

---

## 8. How browser behaviour was verified

Full workflow over plain HTTP with a **standard, browser-correct** cookie jar
(no `Secure` override, no custom policy):

```
[PASS]  1. GET /                  HTTP 200
[PASS]  2. Dashboard              HTTP 200
[PASS]  3. Analyze URL            HTTP 200, trace=6
[PASS]  4. Analyze email          HTTP 200, trace=8
[PASS]  5. Create campaign        HTTP 200
[PASS]  6. Simulator              HTTP 200
[PASS]  7. Submit quiz            HTTP 200
[PASS]  8. Generate report        HTTP 200
[PASS]  9. Rotate API key         HTTP 200
[PASS] 10. Logout                 HTTP 200
[PASS] 11. Login again            HTTP 200

WORKFLOW FAILURES: 0
```

Cookie now issued as:

```
phishguard_session=<redacted>; Expires=...; HttpOnly; Path=/; SameSite=Lax
```

---

## 9. Tests added

`tests/test_csrf_session.py` — **27 tests**, covering all 18 required cases:

GET `/` does not trigger CSRF · GET `/login` works · login page contains a
token · valid token succeeds · missing token fails · invalid token fails ·
session persists between GETs · token valid within a session · SECRET_KEY
stable across restarts · one CSRFProtect bound to the app · CSRF secret not
regenerated · development HTTP cookie config · production HTTPS cookie
config · **dev entry point refuses Secure-over-HTTP** · TLS override exists ·
every state-changing form has a token · no form posts to an implicit URL ·
JS token mechanism available · no unsafe JS without a header · session API
write requires CSRF · API-key write does not · logout invalidates the
session · expired token fails safely · fresh token works after failure ·
`/__debug__/session` is dev-only · it leaks no secrets · CSRF failures are
logged with presence-only fields.

### Three faults found in my own work while writing them

1. The diagnostics endpoint listed `csrf_token` in `session_keys`. Only the
   key *name*, not a value — but redundant with `csrf_session_present` and
   sloppy. Removed.
2. `caplog` could not see the rejection log because `phishguard.security`
   sets `propagate=False`. The test captured nothing and would have passed
   vacuously had I asserted less. Fixed by attaching a handler directly.
3. My "no token in the log" assertion searched for the word `token`, which
   appears in Flask-WTF's own reason text (*"The CSRF token is missing."*).
   Rewritten to assert on token *shape* and to check the real secret is
   absent.

---

## 10. Actual test results

```
$ pytest -q                                   (clean venv, /tmp/.venv_final)
407 passed in 30.82s

$ pytest --cov=app --cov-report=term-missing
TOTAL   3803   636   83%
407 passed in 48.12s

$ python -m compileall -q app scripts tests   exit 0
$ python scripts/seed_database.py             exit 0
$ python scripts/security_check.py            18 checks - 17 passed, 1 warnings, 0 failures
$ python scripts/frontend_check.py            PASS - every button, link and form resolves
$ python scripts/acceptance_check.py          21 passed, 0 failed out of 21
```

Test count 380 → **407** (+27). No test was weakened or removed. The single
checklist warning is the dev placeholder `SECRET_KEY`; production refuses to
start with it.

---

## 11. Security regression results

Every negative case still fails closed, verified live:

```
missing token        -> 400
invalid token        -> 400
other session token  -> 400
token, no cookie     -> 400
```

Plus, from the suite: expired token → 400; session-authenticated API write
without a header → 403 `csrf_required`; API-key write → 200 (correct — an API
key is an explicit credential, not an ambient cookie); production refuses
`/__debug__/session` and `/auth/session-reset` with 404.

---

## 12. Remaining limitation (not a defect)

With `FRAME_ANCESTORS` widened so the app can be shown in a cross-origin
preview iframe, `SameSite=Lax` means browsers withhold the session cookie
**inside that frame**, so form POSTs cannot complete there. The app logs this
at startup:

```
WARNING [session-policy] embedded_with_lax_cookie: ... the embedded app can
render pages but every form POST will fail CSRF validation.
```

This is a browser rule, not something application code can override. The two
valid resolutions are both documented in `docs/DEPLOYMENT.md` §3a:

* **open the app in a normal top-level tab** — works completely; or
* serve it over **HTTPS** with `SameSite=None` + `Secure`.

What is *not* acceptable, and is now blocked by the `run.py` guard, is
setting `Secure` while serving plain HTTP — which is exactly the bug this
report is about.

---

## 13. Summary

The application's CSRF implementation was correct throughout. The session
cookie was being withheld by the browser because I launched the server with
`SESSION_COOKIE_SECURE=1` over plain HTTP, and Flask-WTF cannot validate a
token when the session carrying its counterpart never arrives.

The fix is one line of configuration and one guard that makes the mistake
unrepeatable: the development entry point now refuses to start in that state
and prints the remedy, instead of booting an application whose every form is
quietly broken.
