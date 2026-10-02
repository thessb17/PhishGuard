"""User account model, roles and RBAC helpers."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp (stored naive-UTC for SQLite portability)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role:
    """Role constants + capability matrix used by the RBAC decorators."""

    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    DEMO_USER = "DEMO_USER"

    ALL = (ADMIN, ANALYST, DEMO_USER)
    LABELS = {
        ADMIN: "Administrator",
        ANALYST: "Security Analyst",
        DEMO_USER: "Demo User",
    }

    #: capability -> roles allowed to use it
    CAPABILITIES = {
        "dashboard.view": {ADMIN, ANALYST},
        "campaign.view": {ADMIN, ANALYST},
        "campaign.create": {ADMIN, ANALYST},
        "campaign.edit": {ADMIN, ANALYST},
        "campaign.delete": {ADMIN},
        "analysis.run": {ADMIN, ANALYST},
        "analysis.view": {ADMIN, ANALYST},
        "report.view": {ADMIN, ANALYST},
        "report.create": {ADMIN, ANALYST},
        "audit.view": {ADMIN},
        "user.manage": {ADMIN},
        "simulation.participate": {ADMIN, ANALYST, DEMO_USER},
        "awareness.view": {ADMIN, ANALYST, DEMO_USER},
    }

    @classmethod
    def capabilities_for(cls, role: str) -> list[str]:
        return sorted(cap for cap, roles in cls.CAPABILITIES.items() if role in roles)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default=Role.DEMO_USER, index=True)
    department = db.Column(db.String(120), nullable=False, default="General")
    organization = db.Column(db.String(120), nullable=False, default="Andhra University")
    is_active_account = db.Column("is_active", db.Boolean, nullable=False, default=True)

    # API keys are stored as a SHA-256 digest, never in plaintext.  ``prefix``
    # keeps the first 8 characters so the UI can identify *which* key is active
    # without being able to reproduce it.  See ``hash_api_key`` for why a fast
    # digest (rather than PBKDF2) is the correct choice here.
    api_key_hash = db.Column(db.String(64), unique=True, nullable=True, index=True)
    api_key_prefix = db.Column(db.String(12), nullable=True)
    api_key_issued_at = db.Column(db.DateTime, nullable=True)

    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships -----------------------------------------------------
    # ``passive_deletes`` makes the ORM defer to the database's ON DELETE rule
    # instead of issuing its own UPDATE/DELETE pass.  Previously the ORM said
    # ``delete-orphan`` while the column said ``ON DELETE CASCADE``; the two
    # agreed by accident, and SQLite silently ignored the constraint anyway.
    # PhishGuard deliberately exposes **no user-deletion route** - accounts are
    # disabled, never deleted - precisely so campaign and audit history is
    # never destroyed.  See docs/ARCHITECTURE.md ("Retention").
    campaigns_created = db.relationship(
        "Campaign", back_populates="created_by", lazy="dynamic", passive_deletes=True
    )
    targets = db.relationship(
        "CampaignTarget", back_populates="user", cascade="all, delete-orphan", lazy="dynamic"
    )
    simulation_events = db.relationship(
        "SimulationEvent", back_populates="user", cascade="all, delete-orphan", lazy="dynamic"
    )
    email_analyses = db.relationship("EmailAnalysis", back_populates="analyst", lazy="dynamic")
    url_analyses = db.relationship("URLAnalysis", back_populates="analyst", lazy="dynamic")
    quiz_attempts = db.relationship(
        "QuizAttempt", back_populates="user", cascade="all, delete-orphan", lazy="dynamic"
    )

    # Password handling --------------------------------------------------
    def set_password(self, password: str) -> None:
        """Hash and store a password.  Plaintext is never persisted."""
        if not password:
            raise ValueError("Password must not be empty")
        method = "pbkdf2:sha256:600000"
        try:
            method = current_app.config.get("PASSWORD_HASH_METHOD", method)
        except RuntimeError:  # outside an application context
            pass
        self.password_hash = generate_password_hash(password, method=method)

    def check_password(self, password: str) -> bool:
        if not password or not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    # Lockout handling ----------------------------------------------------
    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())

    def register_failed_login(self) -> bool:
        """Increment the failure counter, locking the account when exceeded.

        Returns ``True`` when the account has just been locked.
        """
        max_failed = current_app.config.get("MAX_FAILED_LOGINS", 5)
        minutes = current_app.config.get("ACCOUNT_LOCKOUT_MINUTES", 15)
        self.failed_login_count = (self.failed_login_count or 0) + 1
        if self.failed_login_count >= max_failed:
            self.locked_until = utcnow() + timedelta(minutes=minutes)
            self.failed_login_count = 0
            return True
        return False

    def register_successful_login(self) -> None:
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login_at = utcnow()

    # API keys ---------------------------------------------------------------
    # The raw key is shown to the user exactly once, at issue time, and only a
    # digest is persisted.  A database leak therefore yields no usable key.
    #
    # Why SHA-256 and not PBKDF2/bcrypt like the password column?  Those are
    # deliberately slow to survive *guessing* of low-entropy human passwords.
    # An API key here is 24 random bytes from ``secrets`` - 192 bits of
    # entropy - so dictionary and rainbow-table attacks do not apply, and the
    # digest must stay fast because it is computed on every single API
    # request; a 600,000-iteration KDF in that path would be a self-inflicted
    # denial of service.  This is the same construction GitHub and Stripe use
    # for personal access tokens.

    API_KEY_BYTES = 24
    API_KEY_PREFIX_LEN = 8

    @staticmethod
    def hash_api_key(raw_key: str) -> str:
        """Deterministic digest used for the indexed lookup."""
        return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()

    def issue_api_key(self) -> str:
        """Generate a new key, store only its digest, return the raw value.

        The return value is the *only* time the plaintext key exists; callers
        must surface it to the user immediately or discard it.
        """
        raw_key = secrets.token_hex(self.API_KEY_BYTES)
        self.api_key_hash = self.hash_api_key(raw_key)
        self.api_key_prefix = raw_key[: self.API_KEY_PREFIX_LEN]
        self.api_key_issued_at = utcnow()
        return raw_key

    def ensure_api_key(self) -> str | None:
        """Issue a key only if the account has none. Returns raw key or None."""
        if not self.api_key_hash:
            return self.issue_api_key()
        return None

    def rotate_api_key(self) -> str:
        """Replace any existing key. The previous key stops working at once."""
        return self.issue_api_key()

    def verify_api_key(self, raw_key: str) -> bool:
        """Constant-time comparison against the stored digest."""
        if not self.api_key_hash or not raw_key:
            return False
        return secrets.compare_digest(self.api_key_hash, self.hash_api_key(raw_key))

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key_hash)

    @property
    def api_key_display(self) -> str | None:
        """Identifying fragment, e.g. ``a1b2c3d4...`` - never the whole key."""
        if not self.api_key_prefix:
            return None
        return f"{self.api_key_prefix}{'.' * 8}"

    # RBAC -----------------------------------------------------------------
    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def is_analyst(self) -> bool:
        return self.role == Role.ANALYST

    @property
    def is_demo_user(self) -> bool:
        return self.role == Role.DEMO_USER

    @property
    def role_label(self) -> str:
        return Role.LABELS.get(self.role, self.role)

    def has_role(self, *roles: str) -> bool:
        return self.role in roles

    def can(self, capability: str) -> bool:
        return self.role in Role.CAPABILITIES.get(capability, set())

    # Flask-Login override (column is named is_active in the DB)
    @property
    def is_active(self) -> bool:  # type: ignore[override]
        return bool(self.is_active_account)

    def initials(self) -> str:
        parts = [p for p in (self.full_name or self.username).split() if p]
        return "".join(p[0].upper() for p in parts[:2]) or self.username[:2].upper()

    def to_dict(self, include_sensitive: bool = False) -> dict:
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "role_label": self.role_label,
            "department": self.department,
            "organization": self.organization,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
        if include_sensitive:
            # Never the key itself - only enough to identify which key is
            # active. The plaintext exists solely at issue time.
            data["api_key_prefix"] = self.api_key_display
            data["api_key_issued_at"] = (
                self.api_key_issued_at.isoformat() if self.api_key_issued_at else None
            )
        return data

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<User {self.username} ({self.role})>"
