# PhishGuard — CSRF Failure: Root Cause and Fix

**Date:** 2026-10-01
**Reported:** HTTP 400 "CSRF validation failed" in the browser at `/`.
**Status:** **Reproduced and fixed.** CSRF protection was strengthened, not
weakened. Nothing was exempted, disabled, or relaxed.

Every result below was produced by running the command shown against the
current build.

---

## 1. Exact original error

```
HTTP 400
CSRF validation failed

Your session token expired or was missing. Reload the page and retry.
```

Served at `http://localhost:5000/`.

---

## 2. Root cause

**The session cookie was not reaching the server. CSRF was blamed for a
cookie-delivery failure.**

Flask-WTF stores the CSRF secret *in the session*. When the session cookie is
absent, Flask creates a brand-new empty session, so a perfectly valid token
arrives with nothing to validate it against — and the only thing the user
sees is "CSRF validation failed".

Two distinct conditions produce it, and **both were reproduced**:

### Cause A — cross-origin iframe with a `SameSite=Lax` cookie (the operational one)

Browsers withhold `SameSite=Lax` cookies inside a **third-party iframe**. The
app is rendered in a frame on another origin, so:

1. the frame loads `/login` and Flask issues a session;
2. the browser refuses to store/return that cookie in a third-party context;
3. the form posts with a valid token but **no session**;
4. CSRF validation fails → HTTP 400.

**This was my own regression.** When I enabled the live preview I widened
`FRAME_ANCESTORS` to permit cross-origin framing **but left the cookie at
`SameSite=Lax`**. Allowing a page to be framed cross-origin while keeping a
Lax cookie is self-defeating: it renders and can never complete a POST.

### Cause B — a stale session cookie the server cannot verify

A cookie signed with a different `SECRET_KEY` (server restarted under another
configuration, or a different app instance) fails signature verification.
Flask discards it silently and proceeds with an empty session — identical
symptom, no way out from inside the browser.

### What was NOT the cause

* `GET /` is a plain redirect and **never** reaches the CSRF handler — measured
  `302 → /login`.
* `POST /` correctly returns **405**, not a CSRF error.
* No form posts to `/`.
* `SECRET_KEY` is stable across restarts in development (the named placeholder).
* CSRF itself was working correctly the entire time.

---

## 3. How it was reproduced

```
=== 1. GET / and POST / ===
  GET  /  -> HTTP 302  Location='/login'  CSRF_ERROR=False
  POST /  -> HTTP 405  Location=''        CSRF_ERROR=False      <- root route innocent

=== 2. login WITH a valid CSRF token ===
  valid token -> HTTP 200  logged_in=True                        <- works

=== 3. login WITHOUT a token ===
  no token -> HTTP 400  CSRF_ERROR=True                          <- correct rejection

=== 4. valid form token but NO session cookie ===
  -> HTTP 400
     'CSRF validation failed'  : True
     'session token expired'   : True                            <- EXACT REPORTED ERROR

=== Cause B: stale cookie signed with another key ===
  stale cookie -> HTTP 400  'CSRF validation failed'=True
                            'session token expired'=True         <- same symptom
```

Confirmed the live cookie carried the breaking attribute:

```
Set-Cookie: phishguard_session=<redacted>; HttpOnly; Path=/; SameSite=Lax
```

---

## 4. Files changed

| File | Change |
|---|---|
| **`app/utils/session_policy.py`** | **New.** Startup validator for cookie/CSRF coherence + a non-sensitive diagnostics snapshot. |
| `app/__init__.py` | Runs the validator at startup; richer `CSRFError` handler (HTML page / JSON `csrf_required`); opt-in dev diagnostics hook. |
| `app/config.py` | Added `CSRF_DEBUG` (dev-only, off by default). |
| `app/routes/auth.py` | Added `/auth/session-reset`, **404 in production**. |
| **`app/templates/errors/csrf.html`** | **New.** Explains the real causes, offers recovery, leaks nothing. |
| `app/templates/base.html`, `base_public.html` | Added `<meta name="csrf-token">` for JavaScript. |
| `app/static/js/app.js` | Added `pgFetch()` which attaches `X-CSRFToken` to unsafe requests. |
| `app/templates/auth/login.html`, `auth/register.html`, `campaigns/create.html`, `detectors/url.html`, `detectors/email.html` | Gave 5 action-less POST forms **explicit actions**. |
| **`tests/test_csrf.py`** | **New.** 29 regression tests. |
| `.env.example`, `docs/DEPLOYMENT.md` | Documented the SameSite/Secure decision. |

**Not changed:** `CSRFProtect` registration, `WTF_CSRF_ENABLED`, token
lifetime, any exemption list. No route was exempted.

---

## 5. Configuration changes

The default is unchanged and remains correct for the documented primary mode:

| Context | SameSite | Secure | Status |
|---|---|---|---|
| Local HTTP (`http://localhost:5000`) | `Lax` | `False` | **default** |
| Production HTTPS | `Lax` | `True` | unchanged |
| Embedded cross-origin iframe (HTTPS only) | `None` | `True` | documented opt-in |

**I deliberately did *not* make `SameSite=None; Secure` the default.** It was
tested and it **breaks plain-HTTP localhost completely** — `Secure` cookies are
never sent over HTTP, so every POST fails:

```
with SESSION_COOKIE_SECURE=1 over http://127.0.0.1:5000
  [FAIL]  3. Login            HTTP 400
  [FAIL]  6. Analyze URL      HTTP 400
  [FAIL] 10. Create campaign  HTTP 400
```

Breaking the documented way of running the project to suit one hosting
artifact would be the wrong trade.

### Startup validation (new)

Four incoherent combinations are now detected and explained at boot:

| Configuration | Verdict |
|---|---|
| `Lax` + insecure, same-origin (local HTTP) | clean |
| **embedded + `Lax`** | **warn `embedded_with_lax_cookie`** |
| embedded + `None` + `Secure` | clean |
| `None` without `Secure` | **error `samesite_none_without_secure`** |
| `Secure` on plain-HTTP dev | warn `secure_cookie_on_http_dev` |
| production HTTPS | clean |

Live output when the broken combination is used:

```
WARNING [session-policy] embedded_with_lax_cookie: FRAME_ANCESTORS allows
cross-origin embedding but SESSION_COOKIE_SAMESITE=Lax. Browsers withhold
Lax/Strict cookies inside a third-party iframe, so the embedded app can
render pages but every form POST will fail CSRF validation.
-> For an embedded HTTPS deployment set SESSION_COOKIE_SAMESITE=None and
   SESSION_COOKIE_SECURE=1.
```

The failure is now diagnosed in one line at startup instead of appearing as a
mystery CSRF error later.

---

## 6. CSRF architecture (unchanged, re-verified)

| Surface | Requirement |
|---|---|
| HTML forms | `CSRFProtect` validates every POST/PUT/PATCH/DELETE. All **21** POST forms carry a token. |
| Session-authenticated API writes | Must send `X-CSRFToken` → otherwise `403 csrf_required`. |
| API-key authenticated writes | No CSRF — an API key is not an ambient browser credential. |
| JavaScript | `<meta name="csrf-token">` + `X-CSRFToken` (the supported Flask-WTF path). |
| Secret | CSRF signs with `SECRET_KEY`; `WTF_CSRF_SECRET_KEY` honoured if set. No hardcoded secret. |
| Lifetime | `WTF_CSRF_TIME_LIMIT=3600`, finite and configurable. Not raised to hide the bug. |

---

## 7. Session-cookie configuration

```
Set-Cookie: phishguard_session=<redacted>; Expires=...; HttpOnly; Path=/; SameSite=Lax
```

`HttpOnly` always; `Secure` in production; `SameSite` configurable with
startup validation. Production still asserts `SESSION_COOKIE_SECURE is True`
(test-enforced).

---

## 8. Browser behaviour

| Scenario | Before | After |
|---|---|---|
| `GET /` | 302 (never broken) | 302 |
| `POST /` | 405 | 405 |
| Login on localhost | worked | works |
| Form POST inside a cross-origin iframe | **400 CSRF, no explanation** | still 400 (browser withholds the cookie) — but the operator is warned at startup, and the page now explains it with recovery actions |
| Stale/unverifiable cookie | 400, stuck | 400 with explanation + `/auth/session-reset` to recover |

**Honest limitation:** nothing in application code can force a browser to send
a Lax cookie into a third-party frame. The fix is to make the condition
*diagnosable and recoverable*, and to document the one configuration that
genuinely works there (`None` + `Secure`, HTTPS only). Opening the preview in
a new top-level tab also avoids it entirely.

---

## 9. Tests added

`tests/test_csrf.py` — **29 tests**, covering every case the brief named:

Reported symptom: `test_root_get_never_requires_csrf`,
`test_root_post_is_method_not_allowed_not_a_csrf_error`,
`test_valid_token_without_the_session_cookie_is_rejected`.

Positive/negative: `test_login_with_valid_csrf_succeeds`,
`test_login_without_csrf_fails`, `test_login_with_invalid_csrf_fails`,
`test_token_from_another_session_is_rejected`,
`test_expired_token_is_rejected_and_reload_recovers`,
`test_fresh_page_issues_a_usable_token_after_a_failure`.

Templates: `test_every_post_form_template_carries_a_csrf_token`,
`test_no_post_form_relies_on_an_implicit_action`,
`test_csrf_meta_tag_is_published_for_javascript`,
`test_csrf_token_present_on_login_page`.

Configuration: `test_development_http_cookie_configuration`,
`test_production_keeps_secure_cookies`,
`test_session_cookie_flags_on_a_real_response`,
`test_policy_validator_detects_broken_cookie_configurations` (4 cases),
`test_policy_validator_is_quiet_on_a_correct_local_configuration`,
`test_policy_validator_accepts_a_correct_embedded_configuration`.

Recovery: `test_session_reset_is_development_only`,
`test_session_reset_clears_the_login_session`.

API: `test_session_authenticated_api_write_requires_csrf`,
`test_api_key_authenticated_write_does_not_require_csrf`,
`test_api_csrf_failure_returns_json_not_html`.

Safety: `test_csrf_error_has_safe_message`,
`test_csrf_time_limit_is_finite_and_configurable`.

### Two bugs found in my own work while writing these

1. **The new CSRF error page crashed for anonymous users.** It extended
   `base.html`, whose sidebar calls `current_user.can()` — undefined on
   `AnonymousUserMixin`, so the error page itself 500'd. That is the exact
   path a logged-out user hits. Fixed by extending `base_public.html`.
2. **The expiry test was flaky** (failed 2 runs in 3): itsdangerous timestamps
   have one-second resolution, so `sleep(1.5)` against a 1-second limit sits
   on the boundary. Replaced with a frozen clock; stable over 4 consecutive
   runs.

---

## 10. Actual test results

```
$ pytest -q
377 passed in 17.19s          (348 before, +29 CSRF tests)

$ pytest -q tests/test_csrf.py   (x4 consecutive runs)
29 passed / 29 passed / 29 passed / 29 passed
```

---

## 11. Security regression results

Every negative case still fails closed:

```
no token                 -> 400
invalid token            -> 400
another session's token  -> 400
token without cookie     -> 400     <- the reported bug; still rejected
```

```
$ python scripts/security_check.py
18 checks - 17 passed, 1 warnings, 0 failures
$ python scripts/acceptance_check.py
21 passed, 0 failed out of 21 acceptance steps
$ python scripts/frontend_check.py
PASS - every button, link and form resolves
```

*Note on the cross-origin Referer probe:* it returned 200 because the test
client held both a valid token **and** the matching cookie — that is not a
cross-origin attack, it is a same-client request with a forged header. The
real control is that a genuine cross-origin page cannot read the token
(same-origin policy) and Lax withholds the cookie. Reported here rather than
presented as a pass.

---

## 12. Browser workflow result

All 19 steps over plain HTTP, the configuration a local user runs:

```
[PASS]  1. Open /            [PASS]  8. Analyze email      [PASS] 15. Profile
[PASS]  2. Sign-in page      [PASS]  9. Campaigns          [PASS] 16. Rotate API key
[PASS]  3. Login             [PASS] 10. Create campaign    [PASS] 17. Audit logs
[PASS]  4. Dashboard         [PASS] 11. Simulator          [PASS] 18. Logout
[PASS]  5. URL detector      [PASS] 12. Submit quiz        [PASS] 19. Login again
[PASS]  6. Analyze URL       [PASS] 13. Reports
[PASS]  7. Email detector    [PASS] 14. Generate report

WORKFLOW FAILURES: 0
```

No legitimate submission produced a CSRF error.

---

## 13. Acceptance criteria

| Criterion | Result |
|---|---|
| `GET /` works | PASS (302 → /login) |
| `GET /login` works | PASS |
| Login with valid CSRF works | PASS |
| Login without CSRF fails | PASS (400) |
| Invalid CSRF fails | PASS (400) |
| Expired CSRF fails safely | PASS (400, reload recovers) |
| Fresh page generates a valid token | PASS |
| HTTP localhost session cookie works | PASS (19/19 workflow) |
| HTTPS production cookie stays secure | PASS (`SESSION_COOKIE_SECURE is True`) |
| All HTML POST forms have CSRF | PASS (21/21) |
| JS unsafe requests use `X-CSRFToken` | PASS (meta tag + `pgFetch`; no JS POSTs exist today) |
| Session-authenticated API writes require CSRF | PASS (403 `csrf_required`) |
| API-key requests work without CSRF | PASS (200) |
| No page produces unexpected CSRF errors | PASS |
| Existing security tests still pass | PASS |
| Full pytest suite passes | PASS (377) |
| Acceptance test passes | PASS (21/21) |
| Fresh-session test passes | PASS |
| **No CSRF protection disabled** | **PASS — nothing exempted or relaxed** |

---

## 13a. Configuration this preview runs with

The Arena preview proxy terminates TLS and serves the app at
`https://<port>-<sandbox>.e2b.app` inside a cross-origin iframe — the exact
case that needs the embedded profile. It is therefore started with:

```bash
FRAME_ANCESTORS="'self' https://*.e2b.app https://*.arena.ai" \
SESSION_COOKIE_SAMESITE=None SESSION_COOKIE_SECURE=1 python run.py
```

Startup reports no policy warning (that combination is coherent), and the
cookie is issued as:

```
Set-Cookie: phishguard_session=<redacted>; Secure; HttpOnly; Path=/; SameSite=None
```

Verified against the running server with a cookie jar permitted to return
Secure cookies (what a browser does over TLS): login, dashboard, URL analysis
(6 trace stages), email analysis (8 trace stages), campaigns, quiz, reports,
API-key rotation, audit logs, logout — **11/11, 0 failures**.

> A measurement correction worth recording: an earlier pass of this check
> appeared to succeed while actually serving the login page, because the
> assertion only looked for HTTP 200 and the absence of a CSRF string. The
> hand-rolled cookie jar behind it was dropping the session across redirects.
> Re-run with a real `http.cookiejar` the numbers above are genuine — the
> giveaway was `trace stages=0` where 6 and 8 were expected.

For plain `http://localhost:5000` use the default instead
(`SESSION_COOKIE_SAMESITE=Lax`, `SESSION_COOKIE_SECURE=0`), because a browser
will not send a Secure cookie over HTTP.

---

## 14. Honest summary

The application's CSRF implementation was never broken. What was broken was
the **session cookie reaching it**, caused by a cookie policy that contradicted
the framing policy — a mismatch I introduced when I widened `FRAME_ANCESTORS`
for the preview and left `SameSite=Lax`.

The fix does three things and weakens nothing:

1. **Diagnoses the condition at startup** instead of letting it surface as a
   misleading CSRF error later.
2. **Explains it in the browser** with a page that names the real causes and
   offers recovery, including a development-only session reset.
3. **Documents the one configuration that works for cross-origin embedding**
   (`SameSite=None` + `Secure`, HTTPS only), while keeping the default correct
   for `http://localhost`.

The residual limitation is a browser rule, not a bug: a `Lax` cookie will never
be sent into a third-party frame, and a `Secure` cookie will never be sent over
plain HTTP. Those two facts cannot both be satisfied by one static
configuration, so the project defaults to the documented local-HTTP case and
makes the alternative explicit.
