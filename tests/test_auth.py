"""Authentication: hashing, sign-in, lockout, sessions and self-registration."""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta

from app.extensions import db as _db
from app.models.audit_log import AuditAction, AuditLog
from app.models.user import Role, User, utcnow
from tests.conftest import ADMIN_PASSWORD, ANALYST_PASSWORD, DEMO_PASSWORD, _make_user, login


def test_password_is_never_stored_in_plaintext(app, users):
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        assert user.password_hash != ADMIN_PASSWORD
        assert ADMIN_PASSWORD not in user.password_hash
        assert user.password_hash.startswith("pbkdf2:sha256:")
        assert user.check_password(ADMIN_PASSWORD) is True
        assert user.check_password("wrong-password") is False


def test_two_users_with_same_password_get_different_hashes(app):
    with app.app_context():
        from app.extensions import db as _db

        first = _make_user("dup.one", "dup.one@cybersafe.edu", Role.DEMO_USER,
                           DEMO_PASSWORD, "Dup One")
        second = _make_user("dup.two", "dup.two@cybersafe.edu", Role.DEMO_USER,
                            DEMO_PASSWORD, "Dup Two")
        _db.session.commit()
        assert first.password_hash != second.password_hash, "hashes must be individually salted"


def test_production_password_hashing_uses_a_strong_iteration_count():
    """The fast test hash must never be what production ships with."""
    from app.config import BaseConfig

    method = BaseConfig.PASSWORD_HASH_METHOD
    assert method.startswith("pbkdf2:sha256:")
    assert int(method.rsplit(":", 1)[1]) >= 600_000


def test_login_success_redirects_to_dashboard(client, users):
    response = login(client, "admin", ADMIN_PASSWORD)
    assert response.status_code == 200
    assert b"dashboard" in response.data.lower()


def test_login_failure_returns_401_and_generic_message(client, users):
    response = client.post("/login", data={"username": "admin", "password": "not-the-password"})
    assert response.status_code == 401
    body = response.get_data(as_text=True)
    assert "Invalid credentials" in body
    assert "no such user" not in body.lower()
    assert "unknown user" not in body.lower()


def test_unknown_user_and_wrong_password_give_the_same_message(client, users):
    unknown = client.post("/login", data={"username": "ghost", "password": "whatever-1234"})
    wrong = client.post("/login", data={"username": "admin", "password": "whatever-1234"})
    assert unknown.status_code == wrong.status_code == 401
    assert "Invalid credentials" in unknown.get_data(as_text=True)
    assert "Invalid credentials" in wrong.get_data(as_text=True)


def test_account_locks_after_max_failed_logins(app, client, users):
    limit = app.config["MAX_FAILED_LOGINS"]
    for attempt in range(limit - 1):
        client.post("/login", data={"username": "analyst", "password": "bad-password"})
        with app.app_context():
            user = User.query.filter_by(username="analyst").one()
            assert user.failed_login_count == attempt + 1
            assert user.is_locked is False

    client.post("/login", data={"username": "analyst", "password": "bad-password"})
    with app.app_context():
        user = User.query.filter_by(username="analyst").one()
        # On lockout the counter resets and a deadline is stored instead.
        assert user.is_locked is True
        assert user.locked_until is not None
        assert user.failed_login_count == 0

    blocked = client.post("/login", data={"username": "analyst", "password": ANALYST_PASSWORD})
    assert blocked.status_code == 423
    assert "temporarily locked" in blocked.get_data(as_text=True).lower()


def test_successful_login_resets_failure_counter(app, client, users):
    client.post("/login", data={"username": "analyst", "password": "bad"})
    client.post("/login", data={"username": "analyst", "password": "bad"})
    login(client, "analyst", ANALYST_PASSWORD)
    with app.app_context():
        user = User.query.filter_by(username="analyst").one()
        assert user.failed_login_count == 0
        assert user.last_login_at is not None


def test_lockout_expires_after_the_configured_window(app, users):
    with app.app_context():
        from app.extensions import db as _db

        user = User.query.filter_by(username="analyst").one()
        user.locked_until = utcnow() - timedelta(minutes=1)
        _db.session.commit()
        assert user.is_locked is False


def test_failed_login_is_audited_without_the_password(app, client, users):
    client.post("/login", data={"username": "admin", "password": "SuperSecret123!"})
    with app.app_context():
        entry = AuditLog.query.filter_by(action=AuditAction.LOGIN_FAILURE).first()
        assert entry is not None
        assert entry.status == "FAILURE"
        assert "SuperSecret123!" not in f"{entry.description} {entry.extra}"


def test_successful_login_and_logout_are_audited(app, users, client):
    login(client, "admin", ADMIN_PASSWORD)
    client.get("/logout", follow_redirects=True)
    with app.app_context():
        actions = {entry.action for entry in AuditLog.query.all()}
    assert AuditAction.LOGIN_SUCCESS in actions
    assert AuditAction.LOGOUT in actions


def test_disabled_account_cannot_sign_in(app, client, users):
    with app.app_context():
        from app.extensions import db as _db

        user = User.query.filter_by(username="priya.demo").one()
        user.is_active_account = False
        _db.session.commit()
    response = client.post("/login", data={"username": "priya.demo", "password": DEMO_PASSWORD})
    assert response.status_code == 403
    assert "disabled" in response.get_data(as_text=True).lower()


def test_logout_clears_the_session(admin_client):
    admin_client.get("/logout", follow_redirects=True)
    response = admin_client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_registration_rejects_weak_passwords(app, client):
    response = client.post("/register", data={
        "username": "weakling", "email": "weakling@cybersafe.edu",
        "full_name": "Weak Ling", "department": "Testing",
        "organization": "Andhra University",
        "password": "short", "confirm": "short",
    })
    assert response.status_code in (200, 400)
    with app.app_context():
        assert User.query.filter_by(username="weakling").first() is None


def test_registration_creates_a_demo_user_only(app, client):
    response = client.post("/register", data={
        "username": "newjoiner", "email": "newjoiner@cybersafe.edu",
        "full_name": "New Joiner", "department": "Testing",
        "organization": "Andhra University",
        "password": "Str0ng-Passw0rd!", "confirm": "Str0ng-Passw0rd!",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        created = User.query.filter_by(username="newjoiner").first()
        assert created is not None
        assert created.role == Role.DEMO_USER, "self-registration must never grant a role"


def test_api_key_rotation_changes_the_key(app, admin_client, users):
    original = users.admin.api_key
    with app.app_context():
        before = User.query.filter_by(username="admin").one()
        original_hash, original_prefix = before.api_key_hash, before.api_key_prefix

    response = admin_client.post("/profile/api-key", follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        after = User.query.filter_by(username="admin").one()
        assert after.api_key_hash != original_hash, "rotation must change the stored digest"
        assert after.api_key_prefix != original_prefix
        assert not after.verify_api_key(original), "the old key must stop working"


def test_api_keys_are_stored_hashed_never_in_plaintext(app, users):
    """The database must not contain anything that can be replayed as a key."""
    import sqlalchemy as sa

    from app.models.user import User as U

    with app.app_context():
        admin = U.query.filter_by(username="admin").one()
        raw = users.admin.api_key

        # The stored value is a SHA-256 digest of the raw key, not the key.
        assert admin.api_key_hash == hashlib.sha256(raw.encode()).hexdigest()
        assert admin.api_key_hash != raw
        assert len(admin.api_key_hash) == 64

        # The raw key must appear in no column of the users table.
        columns = [c.name for c in sa.inspect(U).columns]
        assert "api_key" not in columns, "the plaintext column must be gone"
        row = _db.session.execute(
            sa.text(f"SELECT {', '.join(columns)} FROM users WHERE id = :i"),
            {"i": admin.id},
        ).mappings().one()
        for name, value in row.items():
            assert raw not in str(value), f"raw API key leaked into users.{name}"

        # Only the first 8 characters are retained, for identification.
        assert admin.api_key_prefix == raw[:8]
        assert admin.api_key_display.startswith(raw[:8])
        assert raw not in admin.api_key_display


def test_rotated_api_key_is_revealed_exactly_once(app, admin_client, users):
    """A key we cannot recover must be shown once, then never again."""
    reveal = admin_client.post("/profile/api-key", follow_redirects=True)
    body = reveal.get_data(as_text=True)

    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        prefix = admin.api_key_prefix

    # The freshly issued key is on the page and authenticates.
    match = re.search(rf"\b({re.escape(prefix)}[0-9a-f]{{40}})\b", body)
    assert match, "the new key must be displayed once, immediately after rotation"
    new_key = match.group(1)
    with app.app_context():
        assert User.query.filter_by(username="admin").one().verify_api_key(new_key)

    # Revisiting the profile must not show it again.
    again = admin_client.get("/profile").get_data(as_text=True)
    assert new_key not in again, "the key must never be rendered a second time"
    assert prefix in again, "the non-secret prefix should still identify the key"


def test_session_is_not_shared_between_clients(app, users):
    """Regression guard for the fixture bug this suite used to have.

    Two independent clients must not see each other's identity, and a fresh
    client must be anonymous even after another client has signed in.
    """
    signed_in = app.test_client()
    login(signed_in, "admin", ADMIN_PASSWORD)
    assert signed_in.get("/users").status_code == 200

    anonymous = app.test_client()
    response = anonymous.get("/users")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
