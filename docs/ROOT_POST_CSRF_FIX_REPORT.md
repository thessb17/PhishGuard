# PhishGuard — CSRF Error at "/" : Root-Cause Investigation

**Date:** 2026-10-01
**Reported:** HTTP 400 "CSRF validation failed" with `http://localhost:5000/`
in the address bar.
**Hypothesis under test:** an unsafe `POST /` is reaching Flask.
**Verdict: disproved, with evidence. The failing request is not to `/` at all.**

CSRF protection was not weakened, no route was exempted, and no `POST /`
handler was added. Every figure below came from running the command shown.

---

## 1. Exact failing request

Not `/`. Measured on the running server:

```
GET  /  -> HTTP 302 FOUND              (redirect to /login)
POST /  -> HTTP 405 METHOD NOT ALLOWED
```

Neither produces a CSRF page. The requests that *can* produce one are POSTs
to real form endpoints:

```
POST /login            -> 400  csrf_page=True
POST /url-detector     -> 400  csrf_page=True
POST /campaigns/create -> 400  csrf_page=True
POST /profile/api-key  -> 400  csrf_page=True
```

---

## 2. Routing evidence that clears "/"

```
methods on '/': ['GET', 'HEAD', 'OPTIONS']
WTF_CSRF_METHODS: {'POST', 'PUT', 'PATCH', 'DELETE'}
```

Two independent facts, each sufficient on its own:

1. **`GET` is not in `WTF_CSRF_METHODS`.** `CSRFProtect` never inspects a GET,
   so `GET /` cannot raise `CSRFError`.
2. **`POST /` returns 405, not 400.** This is the decisive one. Werkzeug
   matches the URL rule and rejects the method during **routing**, which
   happens *before* `before_request` — where `CSRFProtect.protect()` is
   installed. A `POST /` is therefore rejected before CSRF code ever runs.

**Conclusion: no request to `/`, by any verb, can render the CSRF error
page.** The suspicion that a stray `POST /` was the cause is ruled out by the
status code itself: it would have to be 400 to be CSRF, and it is 405.

A regression test now pins this (`test_post_root_is_405_at_routing_not_a_csrf_error`),
so if someone ever adds a POST route to `/`, the suite fails loudly.

---

## 3. Browser / initiator analysis

No browser automation is available in this environment, so instead of
guessing at an initiator I enumerated **every mechanism by which a browser
can emit `POST /`** and tested each against the rendered application.

| Mechanism | Scan | Result |
|---|---|---|
| POST form with no/empty/`/` action (submits to current URL) | all 31 templates | **0** |
| `<button>` with no `type` inside a form (defaults to submit) | all 31 templates | **0** |
| Same, in **rendered** HTML across 15 authenticated pages | live render | **0** |
| Unbalanced or nested `<form>` (binds buttons to the wrong form) | live render, 15 pages | **0** |
| `fetch("/")`, `fetch("")`, `form.action = "/"`, `.submit()` | all JS | **0** |
| Inline `<script>` blocks | all templates | **0** (CSP forbids; JSON islands only) |
| Forms on the CSRF error page itself | live render | **0 forms**; recovery actions are `<a>` links to `/login`, `/`, `/auth/session-reset` |

A development request trace (`REQUEST_TRACE=1`, new) was then run across a
full login and analysis flow:

```
TRACE GET  /              302
TRACE POST /              405     <- my own deliberate curl probe
TRACE GET  /login         200
TRACE POST /login         302     <- the real login
TRACE GET  /home          302
TRACE GET  /dashboard     200
TRACE GET  /url-detector  200
TRACE POST /url-detector  200

POST / in trace: 1 occurrence  (the probe, 405)
```

**No legitimate UI action emits `POST /`.** The only one in the log is the
probe I sent by hand, and it was refused at routing.

---

## 4. Root cause

**The URL in the address bar is not the URL of the failing request.**

PhishGuard is displayed inside a **cross-origin iframe** in the preview panel.
The address bar shows the *container* page — the site root, `/`. The iframe
navigates independently: a form inside it POSTs to `/login`, that POST fails
CSRF, and the frame renders the error page. The address bar still reads `/`,
so the error appears to be "at `/`" when the request was to `/login`.

Why the POST fails inside the frame is already established and unchanged:
with `SameSite=Lax`, browsers **withhold the session cookie from a
third-party frame**. Flask-WTF keeps the CSRF secret in the session, so a
correctly-rendered, correctly-submitted token arrives with no session to
validate against.

The diagnostic logging added in the previous pass prints exactly that
signature — and the new `reason_category` field names it:

```json
{"action":"csrf_rejected","endpoint":"auth.login","path":"/login",
 "session_cookie":"MISSING","csrf_session":"MISSING",
 "csrf_form":"PRESENT","csrf_header":"MISSING",
 "samesite":"Lax","secure_cookie":false,
 "reason":"The CSRF session token is missing.",
 "reason_category":"session_lost"}
```

`csrf_form=PRESENT` with `session_cookie=MISSING` is the fingerprint: the
client did everything right and the cookie never arrived. `path` is `/login`,
not `/`.

---

## 5. File that caused the problem

**None.** No template, script, or route in this project emits `POST /`. The
seven scans in §3 all returned zero, and the five action-less forms that did
exist were given explicit actions in an earlier pass
(`auth/login.html`, `auth/register.html`, `campaigns/create.html`,
`detectors/url.html`, `detectors/email.html`).

The behaviour is a browser cookie rule interacting with cross-origin
embedding, not an application defect. Reporting a code fix here would be
fabricating one.

---

## 6. Code changes

All diagnostic or preventive — none alter CSRF enforcement.

| File | Change |
|---|---|
| `app/__init__.py` | `_csrf_reason_category()` classifies `error.description` into `missing` / `session_lost` / `expired` / `mismatch` / `invalid`, logged alongside the existing presence-only fields. User-facing message stays generic. |
| `app/__init__.py` | `REQUEST_TRACE=1` development-only `METHOD PATH STATUS` trace; automatically disabled in production. |
| `app/config.py` | Added `REQUEST_TRACE` (default **False**). |
| `tests/test_root_route.py` | **New** — 27 tests pinning the routing facts and every HTML invariant above. |

Verified categorisation:

```
The CSRF token is missing.          -> missing
The CSRF session token is missing.  -> session_lost
The CSRF token has expired.         -> expired
The CSRF tokens do not match.       -> mismatch
The CSRF token is invalid.          -> invalid
```

---

## 7. Why this resolves it

It does not "fix" `/`, because `/` was never broken — it returns 302 and is
unreachable by CSRF. What changed is that the failure is now **self-diagnosing
and permanently pinned**:

* the trace shows the real method and path, so the address bar can no longer
  mislead;
* `reason_category` distinguishes *the cookie never arrived* from
  *the token was wrong* — different causes that previously looked identical;
* 27 tests fail if a POST route is ever added to `/`, if any form loses its
  action, if any button loses its `type`, if forms become nested, or if the
  error page ever gains a form.

**The practical resolution for the reported symptom is unchanged and
documented: open the application in a normal top-level tab rather than the
embedded frame.** There, `SameSite=Lax` sends the cookie and every form works
— confirmed by the 21-step acceptance run and the 9-step smoke test below.

---

## 8. CSRF security preserved

Unchanged: `CSRFProtect` registered once in `app/extensions.py`,
`WTF_CSRF_ENABLED=True`, `WTF_CSRF_TIME_LIMIT=3600`, no browser route
exempted, no `POST /` handler added.

Negative cases still fail closed:

```
missing token        -> 400
invalid token        -> 400
other session token  -> 400
token, no cookie     -> 400
```

---

## 9. Browser-equivalent test result

Live, standard cookie jar over plain HTTP:

```
GET  /login         -> 200   csrf field present: True
POST /login         -> 200   logged in: True
POST /url-detector  -> 200
curl -i  http://127.0.0.1:5000/   -> HTTP/1.1 302 FOUND
curl -iX POST http://127.0.0.1:5000/ -> HTTP/1.1 405 METHOD NOT ALLOWED
```

---

## 10. Automated test result

```
$ pytest -q
473 passed in 23.89s
```

446 → **473** (+27). No test weakened or removed.

Two faults found in my own new tests while writing them:

1. `test_state_changing_forms_target_their_own_endpoint` logged in before
   fetching `/login` and `/register` — both redirect an authenticated user
   away, so no form was rendered and the assertion failed. Now fetched
   anonymously.
2. The same test initially asserted only that *a* POST form existed; it now
   asserts the form's `action` equals the expected endpoint, which is the
   property that actually matters here.

---

## 11. Acceptance test result

```
$ python scripts/security_check.py     18 checks - 17 passed, 1 warnings, 0 failures
$ python scripts/frontend_check.py     PASS - every button, link and form resolves
$ python scripts/acceptance_check.py   21 passed, 0 failed out of 21
$ python scripts/smoke_test.py         9/9 checks passed
```

The single warning is the development placeholder `SECRET_KEY`; production
refuses to start with it.

---

## 12. Honest summary

The hypothesis was reasonable and worth testing, but it is wrong: `POST /`
returns **405**, which proves routing rejects it before CSRF runs, so no
request to `/` can produce that page. Seven independent scans found nothing
in the templates, rendered HTML, or JavaScript capable of emitting one.

The address bar was showing the preview container while the iframe displayed
a CSRF failure from `POST /login` — caused by the browser withholding a
`SameSite=Lax` cookie from a third-party frame, which no application code can
override.

What this pass delivers is not a code fix for a bug that does not exist in
the code, but the means to never be misled this way again: a request trace
that shows the true method and path, a CSRF reason category that separates
"cookie never arrived" from "token was wrong", and 27 tests that lock down
every HTML and routing invariant involved.
