"""Session-cookie / CSRF coherence validation.

Why this module exists
----------------------
A mismatched cookie policy does not fail loudly. The browser simply stops
sending the session cookie, Flask sees an empty session, the CSRF token in
the submitted form has nothing to validate against, and the user is shown

    HTTP 400 - CSRF validation failed
    Your session token expired or was missing.

which blames CSRF for what is actually a cookie-delivery problem. That error
is very hard to diagnose from the browser, so the combinations that cause it
are detected here, at startup, and reported in plain language.

The three failure modes
-----------------------
1. ``SameSite=None`` with ``Secure=False`` - browsers **reject the cookie
   outright**. Nothing works at all.
2. ``Secure=True`` while serving plain HTTP - the browser accepts the cookie
   but never sends it back. Every POST looks like a CSRF failure.
3. ``SameSite=Lax`` while the app is embedded in a **cross-origin iframe** -
   Lax cookies are withheld inside a third-party frame, so the embedded app
   can render but can never complete a form POST.

Case 3 is the one that bit this project: ``FRAME_ANCESTORS`` was widened to
permit embedding without moving the cookie to ``SameSite=None; Secure``.
Allowing a page to be framed cross-origin while keeping a Lax cookie is
self-defeating.

Nothing here weakens CSRF. It only validates that the session cookie can
physically reach the server, which CSRF depends on.
"""

from __future__ import annotations


def _frame_ancestors_allow_cross_origin(value: str) -> bool:
    """True when FRAME_ANCESTORS permits an origin other than our own."""
    tokens = [t.strip().strip("'\"") for t in (value or "").split() if t.strip()]
    if not tokens:
        return False
    # 'self' and 'none' are same-origin / no-embedding; anything else is a
    # third-party origin (https://*.example, a scheme, or a wildcard).
    return any(t.lower() not in ("self", "none") for t in tokens)


def evaluate_session_policy(config) -> list[dict]:
    """Return a list of problems found in the cookie/CSRF configuration.

    Each entry is ``{"level": "error"|"warning", "code": str, "message": str,
    "remedy": str}``. Pure function - no logging, no side effects - so it can
    be unit-tested directly.
    """
    problems: list[dict] = []

    samesite = str(config.get("SESSION_COOKIE_SAMESITE") or "").strip() or "Lax"
    secure = bool(config.get("SESSION_COOKIE_SECURE"))
    env_name = str(config.get("ENV_NAME") or "development").lower()
    frame_ancestors = str(config.get("FRAME_ANCESTORS") or "'self'")
    csrf_enabled = bool(config.get("WTF_CSRF_ENABLED", True))
    embedded = _frame_ancestors_allow_cross_origin(frame_ancestors)

    # 1. SameSite=None without Secure - the cookie is rejected by the browser.
    if samesite.lower() == "none" and not secure:
        problems.append({
            "level": "error",
            "code": "samesite_none_without_secure",
            "message": ("SESSION_COOKIE_SAMESITE=None requires "
                        "SESSION_COOKIE_SECURE=1. Browsers reject a "
                        "SameSite=None cookie that is not Secure, so no "
                        "session will be stored at all and every form POST "
                        "will fail CSRF validation."),
            "remedy": "Set SESSION_COOKIE_SECURE=1 (requires HTTPS), or use SameSite=Lax.",
        })

    # 2. Secure cookies in development - usually means plain HTTP.
    #    Exception: SameSite=None REQUIRES Secure, and that combination only
    #    makes sense behind HTTPS (e.g. a TLS-terminating preview proxy), so
    #    it is a deliberate, coherent choice rather than a mistake. Warning
    #    about it would make the validator cry wolf on a correct setup.
    coherent_embedded = samesite.lower() == "none" and secure
    if secure and env_name == "development" and not coherent_embedded:
        problems.append({
            "level": "warning",
            "code": "secure_cookie_on_http_dev",
            "message": ("SESSION_COOKIE_SECURE=True while running development "
                        "over HTTP. The browser will not send the session "
                        "cookie, which surfaces as a confusing "
                        "'CSRF validation failed' error on every form."),
            "remedy": "Set SESSION_COOKIE_SECURE=0 for local HTTP development.",
        })

    # 3. Cross-origin embedding with a Lax cookie - the case that broke the
    #    preview. The page frames fine and then no POST ever works.
    if embedded and samesite.lower() != "none":
        problems.append({
            "level": "warning",
            "code": "embedded_with_lax_cookie",
            "message": (f"FRAME_ANCESTORS allows cross-origin embedding "
                        f"({frame_ancestors}) but SESSION_COOKIE_SAMESITE="
                        f"{samesite}. Browsers withhold Lax/Strict cookies "
                        f"inside a third-party iframe, so the embedded app "
                        f"can render pages but every form POST will fail "
                        f"CSRF validation."),
            "remedy": ("For an embedded HTTPS deployment set "
                       "SESSION_COOKIE_SAMESITE=None and SESSION_COOKIE_SECURE=1. "
                       "For normal same-origin use, keep FRAME_ANCESTORS='self'."),
        })

    # 4. CSRF switched off outside the test profile.
    if not csrf_enabled and env_name != "testing":
        problems.append({
            "level": "error",
            "code": "csrf_disabled",
            "message": ("WTF_CSRF_ENABLED is False outside the testing "
                        "profile. State-changing requests are unprotected."),
            "remedy": "Remove WTF_CSRF_ENABLED=0 from the environment.",
        })

    return problems


def log_session_policy(app) -> list[dict]:
    """Evaluate the policy and write any problems to the application log."""
    problems = evaluate_session_policy(app.config)
    for p in problems:
        line = f"[session-policy] {p['code']}: {p['message']} -> {p['remedy']}"
        if p["level"] == "error":
            app.logger.error(line)
        else:
            app.logger.warning(line)
    return problems


def session_diagnostics(request, session, config) -> dict:
    """Non-sensitive snapshot used by the development diagnostics hook.

    Deliberately reports only presence/absence booleans. It never records a
    CSRF token, a session value, the secret key, or any credential.
    """
    return {
        "method": request.method,
        "path": request.path,
        "session_cookie_present": config.get("SESSION_COOKIE_NAME") in request.cookies,
        "csrf_session_present": "csrf_token" in session,
        "csrf_form_present": "csrf_token" in (request.form or {}),
        "csrf_header_present": any(
            h in request.headers for h in ("X-CSRFToken", "X-CSRF-Token")
        ),
        "session_cookie_secure": bool(config.get("SESSION_COOKIE_SECURE")),
        "session_cookie_samesite": config.get("SESSION_COOKIE_SAMESITE"),
        "csrf_time_limit": config.get("WTF_CSRF_TIME_LIMIT"),
        "flask_config": config.get("ENV_NAME"),
    }
