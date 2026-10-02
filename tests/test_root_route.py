"""Root-route and HTML-structure regression tests.

Context: a CSRF error was reported with ``http://localhost:5000/`` in the
address bar, suggesting an unsafe ``POST /``. These tests pin the routing
facts that disprove that, and the HTML invariants that would be the only way
a browser could produce such a request:

* ``/`` accepts GET/HEAD/OPTIONS only, so ``POST /`` is rejected at **routing**
  (405) before ``before_request`` — meaning neither verb can reach CSRF;
* no POST form anywhere submits to the current URL;
* no ``<button>`` inside a form can submit by accident;
* the CSRF error page contains no form at all.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from app import create_app
from tests.conftest import ADMIN_PASSWORD, make_app

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"


@pytest.fixture()
def csrf_app(tmp_path):
    app = make_app(tmp_path, WTF_CSRF_ENABLED=True)
    from app.extensions import db as _db
    from app.models.user import Role, User

    with app.app_context():
        _db.create_all()
        user = User(username="admin", email="a@cybersafe.edu",
                    full_name="Avery Sinclair", role=Role.ADMIN)
        user.set_password(ADMIN_PASSWORD)
        user.ensure_api_key()
        _db.session.add(user)
        _db.session.commit()
    return app


def _token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, f"no csrf_token on {path}"
    return match.group(1)


# ---------------------------------------------------------------------------
# Root route
# ---------------------------------------------------------------------------


def test_root_get_redirects_to_login_when_unauthenticated(csrf_app):
    response = csrf_app.test_client().get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_root_get_redirects_onward_when_authenticated(csrf_app):
    client = csrf_app.test_client()
    client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" not in response.headers["Location"]


def test_root_does_not_have_post_route(csrf_app):
    rule = next(r for r in csrf_app.url_map.iter_rules() if str(r) == "/")
    assert "POST" not in rule.methods
    assert rule.methods >= {"GET", "HEAD", "OPTIONS"}


def test_post_root_is_405_at_routing_not_a_csrf_error(csrf_app):
    """405 proves routing rejects the verb before CSRF ever runs.

    If this ever became 400, it would mean a POST route had been added to '/'
    and CSRF was being reached — the situation originally suspected.
    """
    response = csrf_app.test_client().post("/", data={"x": "1"})
    assert response.status_code == 405
    assert b"CSRF validation failed" not in response.data


def test_get_requests_are_never_csrf_validated(csrf_app):
    methods = csrf_app.config.get("WTF_CSRF_METHODS", {"POST", "PUT", "PATCH", "DELETE"})
    assert "GET" not in methods
    for path in ("/", "/login", "/health"):
        assert b"CSRF validation failed" not in csrf_app.test_client().get(path).data


# ---------------------------------------------------------------------------
# Form targets
# ---------------------------------------------------------------------------


def test_login_posts_to_the_login_endpoint(csrf_app):
    html = csrf_app.test_client().get("/login").get_data(as_text=True)
    match = re.search(r'<form[^>]*method="post"[^>]*>', html, re.I)
    assert match, "no POST form on the login page"
    assert 'action="/login"' in match.group(0), match.group(0)


@pytest.mark.parametrize("path,expected_action", [
    ("/login", "/login"),
    ("/register", "/register"),
    ("/url-detector", "/url-detector"),
    ("/email-detector", "/email-detector"),
    ("/campaigns/create", "/campaigns/create"),
])
def test_state_changing_forms_target_their_own_endpoint(csrf_app, path, expected_action):
    # /login and /register redirect an authenticated user away, so those two
    # must be fetched anonymously or no form is rendered at all.
    client = csrf_app.test_client()
    if path not in ("/login", "/register"):
        client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                    "password": ADMIN_PASSWORD}, follow_redirects=True)
    html = client.get(path).get_data(as_text=True)
    forms = re.findall(r'<form[^>]*method="post"[^>]*>', html, re.I)
    assert forms, f"no POST form rendered on {path}"
    assert any(f'action="{expected_action}"' in f for f in forms), forms[:3]


def test_no_rendered_post_form_submits_to_the_current_url(csrf_app):
    """A POST form with no action submits to the page's own URL - the only
    HTML-level way a browser could be made to emit POST /."""
    client = csrf_app.test_client()
    client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    offenders = []
    for path in ("/", "/login", "/register", "/dashboard", "/campaigns",
                 "/campaigns/create", "/simulator", "/url-detector",
                 "/email-detector", "/awareness", "/quiz", "/reports",
                 "/audit-logs", "/profile", "/users"):
        html = client.get(path, follow_redirects=True).get_data(as_text=True)
        for form in re.findall(r'<form\b([^>]*)>', html, re.I):
            method = (re.search(r'method\s*=\s*["\']?(\w+)', form, re.I) or [None, "get"])[1]
            action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form, re.I)
            if method.lower() == "post" and (action is None or action.group(1).strip() in ("", "/")):
                offenders.append(f"{path}: {form.strip()[:60]}")
    assert not offenders, f"forms that would POST to the current URL: {offenders}"


# ---------------------------------------------------------------------------
# Buttons
# ---------------------------------------------------------------------------


class _FormAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.max_depth = 0
        self.typeless_buttons: list[str] = []
        self.post_forms: list[str | None] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.depth += 1
            self.max_depth = max(self.max_depth, self.depth)
            if a.get("method", "get").lower() == "post":
                self.post_forms.append(a.get("action"))
        elif tag == "button" and self.depth > 0 and "type" not in a:
            self.typeless_buttons.append(str(a)[:70])

    def handle_endtag(self, tag):
        if tag == "form":
            self.depth -= 1


def test_non_submit_buttons_are_type_button(csrf_app):
    """A <button> with no type defaults to submit and will fire its form."""
    client = csrf_app.test_client()
    client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    offenders = []
    for path in ("/login", "/dashboard", "/campaigns", "/campaigns/create",
                 "/url-detector", "/email-detector", "/reports", "/profile",
                 "/audit-logs", "/quiz", "/simulator"):
        audit = _FormAudit()
        audit.feed(client.get(path, follow_redirects=True).get_data(as_text=True))
        for button in audit.typeless_buttons:
            offenders.append(f"{path}: {button}")
    assert not offenders, f"typeless buttons inside forms: {offenders}"


def test_templates_declare_a_type_on_every_button():
    offenders = []
    for path in TEMPLATES.rglob("*.html"):
        for match in re.finditer(r'<button\b([^>]*)>', path.read_text(encoding="utf-8"), re.I):
            if not re.search(r'\btype\s*=', match.group(1), re.I):
                offenders.append(f"{path.name}: <button{match.group(1).strip()[:50]}>")
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# HTML structure (item 20)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [
    "/login", "/dashboard", "/campaigns", "/url-detector",
    "/email-detector", "/reports", "/profile",
])
def test_rendered_pages_have_balanced_unnested_forms(csrf_app, path):
    """Unbalanced or nested forms let a browser bind a button to the wrong
    form, which is a classic source of an unintended submission target."""
    client = csrf_app.test_client()
    client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    audit = _FormAudit()
    audit.feed(client.get(path, follow_redirects=True).get_data(as_text=True))
    assert audit.depth == 0, f"{path}: unbalanced <form> tags ({audit.depth})"
    assert audit.max_depth <= 1, f"{path}: nested forms (depth {audit.max_depth})"


# ---------------------------------------------------------------------------
# The CSRF error page must not itself be able to submit anything
# ---------------------------------------------------------------------------


def test_error_page_links_do_not_submit_forms(csrf_app):
    client = csrf_app.test_client()
    client.get("/login")
    response = client.post("/login", data={"username": "admin"})
    assert response.status_code == 400
    html = response.get_data(as_text=True)

    audit = _FormAudit()
    audit.feed(html)
    assert audit.post_forms == [], f"CSRF page contains POST forms: {audit.post_forms}"
    assert audit.typeless_buttons == []

    # Recovery actions must be plain GET links.
    hrefs = re.findall(r'<a\b[^>]*href="([^"]*)"', html)
    assert "/login" in hrefs
    assert all(h.startswith(("/", "http")) or h == "" for h in hrefs)


def test_csrf_error_page_renders_for_anonymous_users(csrf_app):
    """It extends base_public: base.html's sidebar calls current_user.can(),
    which is undefined for AnonymousUserMixin and would 500 the error page."""
    client = csrf_app.test_client()
    client.get("/login")
    response = client.post("/login", data={"username": "admin"})
    assert response.status_code == 400
    assert b"Why this usually happens" in response.data


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


def test_no_javascript_targets_the_site_root_with_an_unsafe_request():
    offenders = []
    for js in (ROOT / "app" / "static" / "js").rglob("*.js"):
        text = js.read_text(encoding="utf-8")
        for pattern in (r'fetch\(\s*["\']/["\']', r'fetch\(\s*["\']\s*["\']',
                        r'\.action\s*=\s*["\']/["\']', r'\.submit\(\)'):
            if re.search(pattern, text):
                offenders.append(f"{js.name}: {pattern}")
    assert not offenders, f"JS that could POST to the root: {offenders}"


def test_no_inline_script_blocks_in_templates():
    """CSP forbids inline script; JSON data islands are the sanctioned form."""
    offenders = []
    for path in TEMPLATES.rglob("*.html"):
        for match in re.finditer(r'<script\b([^>]*)>', path.read_text(encoding="utf-8"), re.I):
            attrs = match.group(1)
            if "src=" not in attrs and 'type="application/json"' not in attrs:
                offenders.append(f"{path.name}: <script{attrs.strip()[:40]}>")
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def test_csrf_reason_is_categorised_for_logs():
    from app import _csrf_reason_category

    assert _csrf_reason_category("The CSRF token is missing.") == "missing"
    assert _csrf_reason_category("The CSRF session token is missing.") == "session_lost"
    assert _csrf_reason_category("The CSRF token has expired.") == "expired"
    assert _csrf_reason_category("The CSRF tokens do not match.") == "mismatch"
    assert _csrf_reason_category("The CSRF token is invalid.") == "invalid"


def test_request_trace_is_disabled_by_default_and_never_in_production():
    assert create_app("development").config["REQUEST_TRACE"] is False
    source = (ROOT / "app" / "__init__.py").read_text(encoding="utf-8")
    assert 'app.config.get("REQUEST_TRACE") and app.config.get("ENV_NAME") != "production"' in source
