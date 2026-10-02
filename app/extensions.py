"""Flask extension singletons.

Kept in a dedicated module so that models, blueprints and services can import
them without triggering circular imports with the application factory.
"""

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _enforce_sqlite_foreign_keys(dbapi_connection, connection_record):
    """Turn on foreign-key enforcement for SQLite connections.

    SQLite ships with ``PRAGMA foreign_keys=OFF``, so ON DELETE CASCADE and
    ON DELETE SET NULL are silently ignored.  Development and the test suite
    run on SQLite while production runs on PostgreSQL, which *does* enforce
    them - without this listener a referential-integrity bug can pass every
    local test and only surface in production.
    """
    if type(dbapi_connection).__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id: str):
    from app.models.user import User

    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
