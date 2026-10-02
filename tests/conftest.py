"""Shared pytest fixtures.

Isolation notes (important, and the reason this file looks the way it does)
--------------------------------------------------------------------------
An earlier version of this file kept a single application context pushed for
the whole test, like this::

    with application.app_context():
        _db.create_all()
        yield application          # <-- context still active

That is a trap.  ``RequestContext.push()`` only creates a *new* application
context when one is not already active for the same app, so every test-client
request reused the outer context - and Flask-Login caches the signed-in user
on ``g._login_user``.  Once any client logged in, that identity leaked into
every subsequent request, **including requests made by a brand-new client
with no cookies**.  Authorization tests could therefore pass while asserting
nothing at all; a probe run showed an anonymous client receiving HTTP 200
from ``/users`` and ``/audit-logs``.

The fixtures below never hold a context open across a request.  Database
setup happens inside short-lived contexts, fixtures hand back plain data
(ids, names, keys) instead of live ORM objects, and any test that needs the
ORM opens its own context explicitly::

    with app.app_context():
        assert db.session.get(User, user_id).is_active

Each test also gets its own file-backed SQLite database, so no state can
travel between tests.
"""

from __future__ import annotations

import os
import sys
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("FLASK_CONFIG", "testing")

from app import create_app  # noqa: E402
from app.config import TestingConfig  # noqa: E402
from app.extensions import db as _db  # noqa: E402
from app.models.campaign import CampaignStatus, Difficulty  # noqa: E402
from app.models.quiz import AwarenessQuiz, QuizQuestion  # noqa: E402
from app.models.user import Role, User  # noqa: E402
from app.services.awareness_content import ensure_default_quiz  # noqa: E402
from app.services.campaign_service import create_campaign  # noqa: E402

ADMIN_PASSWORD = "AdminTest@2026"
ANALYST_PASSWORD = "AnalystTest@2026"
DEMO_PASSWORD = "DemoTest@2026"


def make_app(tmp_path, **overrides):
    """Build an app bound to a private SQLite file, with tables created."""
    uri = f"sqlite:///{tmp_path}/phishguard-test.db"
    previous = TestingConfig.SQLALCHEMY_DATABASE_URI
    TestingConfig.SQLALCHEMY_DATABASE_URI = uri
    applied = {}
    for key, value in overrides.items():
        applied[key] = getattr(TestingConfig, key, None)
        setattr(TestingConfig, key, value)
    try:
        application = create_app("testing")
    finally:
        TestingConfig.SQLALCHEMY_DATABASE_URI = previous
        for key, value in applied.items():
            if value is None:
                delattr(TestingConfig, key)
            else:
                setattr(TestingConfig, key, value)
    with application.app_context():
        _db.create_all()
    return application


@pytest.fixture()
def app(tmp_path):
    application = make_app(tmp_path)
    yield application
    with application.app_context():
        _db.session.remove()
        _db.drop_all()
        _db.engine.dispose()


@pytest.fixture()
def db(app):
    """The SQLAlchemy extension.  Use inside an explicit ``app.app_context()``."""
    return _db


def _make_user(username, email, role, password, full_name, department="General",
               organization="Andhra University"):
    """Create a user and stash the raw API key on the instance for tests.

    Only a digest is persisted, so the plaintext is available exactly once -
    at issue time. Tests need it to exercise header authentication, so we
    hang it off a transient attribute rather than re-reading the column
    (which no longer holds anything usable).
    """
    user = User(username=username, email=email, role=role, full_name=full_name,
                department=department, organization=organization)
    user.set_password(password)
    user.raw_api_key = user.ensure_api_key()
    _db.session.add(user)
    return user


@pytest.fixture()
def users(app):
    """Create the four standard accounts; return ids/keys, not ORM objects."""
    with app.app_context():
        admin = _make_user("admin", "admin@cybersafe.edu", Role.ADMIN, ADMIN_PASSWORD,
                           "Avery Sinclair", "Information Security Office")
        analyst = _make_user("analyst", "analyst@cybersafe.edu", Role.ANALYST, ANALYST_PASSWORD,
                             "Rohan Varma", "Security Operations Centre")
        demo = _make_user("priya.demo", "priya.nandakumar@cybersafe.edu", Role.DEMO_USER,
                          DEMO_PASSWORD, "Priya Nandakumar", "Student Services")
        demo2 = _make_user("liam.demo", "liam.whitfield@cybersafe.edu", Role.DEMO_USER,
                           DEMO_PASSWORD, "Liam Whitfield", "Faculty of Engineering")
        _db.session.commit()
        return SimpleNamespace(
            admin=SimpleNamespace(id=admin.id, username="admin", password=ADMIN_PASSWORD,
                                  api_key=admin.raw_api_key, email=admin.email),
            analyst=SimpleNamespace(id=analyst.id, username="analyst", password=ANALYST_PASSWORD,
                                    api_key=analyst.raw_api_key, email=analyst.email),
            demo=SimpleNamespace(id=demo.id, username="priya.demo", password=DEMO_PASSWORD,
                                 api_key=demo.raw_api_key, email=demo.email),
            demo2=SimpleNamespace(id=demo2.id, username="liam.demo", password=DEMO_PASSWORD,
                                  api_key=demo2.raw_api_key, email=demo2.email),
        )


@pytest.fixture()
def campaign(app, users):
    """Create a campaign; return its id plus its participants' access tokens."""
    with app.app_context():
        created = create_campaign(
            name="Unit Test Password Expiry Drill",
            description="Fixture campaign used by the automated test-suite.",
            template_key="password_expiry",
            difficulty=Difficulty.MEDIUM,
            start_date=date.today() - timedelta(days=2),
            end_date=date.today() + timedelta(days=5),
            target_ids=[users.demo.id, users.demo2.id],
            creator=_db.session.get(User, users.admin.id),
            status=CampaignStatus.ACTIVE,
            organization="Andhra University",
        )
        targets = created.targets.all()
        return SimpleNamespace(
            id=created.id,
            name=created.name,
            tokens={t.user.username: t.access_token for t in targets},
            target_ids=[t.id for t in targets],
        )


@pytest.fixture()
def quiz(app):
    with app.app_context():
        created = ensure_default_quiz(_db.session, AwarenessQuiz, QuizQuestion)
        return SimpleNamespace(
            id=created.id,
            slug=created.slug,
            question_ids=[q.id for q in created.questions],
            correct={q.id: q.correct_index for q in created.questions},
            option_counts={q.id: len(q.options) for q in created.questions},
        )


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username: str, password: str):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=True)


def logged_in(app, username: str, password: str):
    test_client = app.test_client()
    login(test_client, username, password)
    return test_client


@pytest.fixture()
def admin_client(app, users):
    return logged_in(app, users.admin.username, users.admin.password)


@pytest.fixture()
def analyst_client(app, users):
    return logged_in(app, users.analyst.username, users.analyst.password)


@pytest.fixture()
def demo_client(app, users):
    return logged_in(app, users.demo.username, users.demo.password)
