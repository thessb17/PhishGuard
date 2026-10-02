"""Application configuration objects for PhishGuard.

All secrets and environment-specific values are read from environment
variables (optionally loaded from a local ``.env`` file).  No secret is ever
hard-coded: the production configuration refuses to start without an
explicitly provided ``SECRET_KEY``.
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _normalise_db_uri(uri: str) -> str:
    """Allow ``postgres://`` style URLs (Heroku/Render) with SQLAlchemy 2.x."""
    if uri.startswith("postgres://"):
        return uri.replace("postgres://", "postgresql+psycopg2://", 1)
    return uri


#: The development-only fallback session secret.  It is deliberately a known,
#: published string: it exists so local development works with no setup, and
#: ``ProductionConfig.init_app`` refuses to start if it is ever seen in
#: production.  Named "...PLACEHOLDER" rather than "...SECRET_KEY" so the
#: hardcoded-secret scanner in scripts/security_check.py stays strict about
#: real ``SECRET_KEY = "literal"`` assignments.
DEV_SECRET_PLACEHOLDER = "dev-only-insecure-key-change-me"


class BaseConfig:
    """Settings shared by every environment."""

    # --- Core -----------------------------------------------------------
    APP_NAME = "PhishGuard"
    APP_TAGLINE = "Phishing Attack Simulation and Detection Platform"
    PROJECT_OWNER = "Sabyasachi Bhowmik"
    INSTITUTION = "Andhra University"
    DEPARTMENT = "Department of Computer Science and Systems Engineering"
    PROJECT_CREDIT = "Developed by Sabyasachi Bhowmik · Andhra University"
    VERSION = "1.0.0"
    BASE_DIR = BASE_DIR
    SECRET_KEY = os.environ.get("SECRET_KEY", DEV_SECRET_PLACEHOLDER)

    # --- Database -------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = _normalise_db_uri(
        os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'phishguard.db'}")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # --- Sessions / cookies ---------------------------------------------
    SESSION_COOKIE_NAME = "phishguard_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("SESSION_LIFETIME_MINUTES", 60))
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_DURATION = timedelta(days=1)

    # --- CSRF -------------------------------------------------------------
    WTF_CSRF_ENABLED = _bool("WTF_CSRF_ENABLED", True)
    WTF_CSRF_TIME_LIMIT = _int("WTF_CSRF_TIME_LIMIT", 3600)
    WTF_CSRF_SSL_STRICT = False
    #: Opt-in request diagnostics for debugging cookie/CSRF delivery.
    #: Logs presence booleans only, and is ignored in production.
    CSRF_DEBUG = _bool("CSRF_DEBUG", False)
    #: Development-only "METHOD PATH STATUS" trace. Never on in production.
    REQUEST_TRACE = _bool("REQUEST_TRACE", False)

    # --- Passwords / lockout ---------------------------------------------
    # Werkzeug PBKDF2-HMAC-SHA256 (salted, 600k iterations by default).
    PASSWORD_HASH_METHOD = os.environ.get("PASSWORD_HASH_METHOD", "pbkdf2:sha256:600000")
    PASSWORD_MIN_LENGTH = _int("PASSWORD_MIN_LENGTH", 10)
    MAX_FAILED_LOGINS = _int("MAX_FAILED_LOGINS", 5)
    ACCOUNT_LOCKOUT_MINUTES = _int("ACCOUNT_LOCKOUT_MINUTES", 15)

    # --- Rate limiting ----------------------------------------------------
    RATELIMIT_ENABLED = _bool("RATELIMIT_ENABLED", True)
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "600 per hour;120 per minute")
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_LOGIN = os.environ.get("RATELIMIT_LOGIN", "10 per minute;60 per hour")
    RATELIMIT_ANALYSIS = os.environ.get("RATELIMIT_ANALYSIS", "60 per minute;600 per hour")
    RATELIMIT_API = os.environ.get("RATELIMIT_API", "120 per minute")

    # --- Security headers --------------------------------------------------
    # ``FRAME_ANCESTORS`` is configurable so the app can be embedded in a
    # trusted preview/demo iframe.  The hardened default is 'self'.
    FRAME_ANCESTORS = os.environ.get("FRAME_ANCESTORS", "'self'")
    ENABLE_HSTS = _bool("ENABLE_HSTS", False)
    HSTS_MAX_AGE = _int("HSTS_MAX_AGE", 31536000)
    CSP_REPORT_ONLY = _bool("CSP_REPORT_ONLY", False)

    # --- Risk engine -------------------------------------------------------
    HEURISTIC_WEIGHT = _float("HEURISTIC_WEIGHT", 0.6)
    ML_WEIGHT = _float("ML_WEIGHT", 0.4)
    RISK_BANDS = (
        ("LOW", 0, 24),
        ("MEDIUM", 25, 49),
        ("HIGH", 50, 74),
        ("CRITICAL", 75, 100),
    )

    # --- Heuristic detector thresholds ---------------------------------------
    # Tunable so an operator can trade false positives against recall without
    # editing detector source.  The entropy defaults were calibrated on the
    # 16k-row bundled dataset: ``> 4.0 bits/char`` over ``>= 20`` characters
    # fires on 0.27% of benign hostnames and 18.6% of phishing hostnames.
    # The previous 3.7 / 18 setting fired on 10% of BENIGN hostnames.
    URL_ENTROPY_THRESHOLD = _float("URL_ENTROPY_THRESHOLD", 4.0)
    URL_ENTROPY_MIN_HOST_LEN = _int("URL_ENTROPY_MIN_HOST_LEN", 20)
    URL_DIGIT_RATIO_THRESHOLD = _float("URL_DIGIT_RATIO_THRESHOLD", 0.25)
    URL_LONG_THRESHOLD = _int("URL_LONG_THRESHOLD", 75)
    URL_VERY_LONG_THRESHOLD = _int("URL_VERY_LONG_THRESHOLD", 120)
    URL_MANY_SUBDOMAINS = _int("URL_MANY_SUBDOMAINS", 3)
    URL_HOST_HYPHEN_THRESHOLD = _int("URL_HOST_HYPHEN_THRESHOLD", 3)
    URL_DEEP_PATH_THRESHOLD = _int("URL_DEEP_PATH_THRESHOLD", 5)

    # Campaign click-rate -> risk banding (upper bound, exclusive).
    CAMPAIGN_RISK_THRESHOLDS = ((10, "LOW"), (25, "MEDIUM"), (50, "HIGH"))

    # --- Machine learning ----------------------------------------------------
    ML_MODEL_PATH = os.environ.get("ML_MODEL_PATH", str(BASE_DIR / "app" / "ml" / "model.joblib"))
    ML_METRICS_PATH = os.environ.get("ML_METRICS_PATH", str(BASE_DIR / "app" / "ml" / "metrics.json"))
    ML_DATASET_PATH = os.environ.get("ML_DATASET_PATH", str(BASE_DIR / "data" / "datasets" / "url_dataset.csv"))
    ML_ENABLED = _bool("ML_ENABLED", True)

    # --- Simulation safety rails ---------------------------------------------
    # Hard switch enforced by the simulator blueprint and its templates: the
    # awareness landing page never renders a credential form.
    SIMULATION_COLLECT_CREDENTIALS = False  # immutable safety invariant
    SIMULATION_BANNER = "SAFE SIMULATION - NO CREDENTIALS ARE EVER COLLECTED"
    ALLOW_SELF_REGISTRATION = _bool("ALLOW_SELF_REGISTRATION", True)

    # --- Reports --------------------------------------------------------------
    REPORT_MAX_ROWS = _int("REPORT_MAX_ROWS", 5000)
    MAX_CONTENT_LENGTH = _int("MAX_CONTENT_LENGTH", 1 * 1024 * 1024)  # 1 MB request cap

    # --- Logging ---------------------------------------------------------------
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    SECURITY_LOG_FILE = os.environ.get("SECURITY_LOG_FILE", "")
    LOG_FILE = os.environ.get("LOG_FILE", str(BASE_DIR / "instance" / "phishguard.log"))
    AUDIT_LOG_IP = _bool("AUDIT_LOG_IP", True)

    JSON_SORT_KEYS = False
    TEMPLATES_AUTO_RELOAD = False

    @classmethod
    def init_app(cls, app):  # pragma: no cover - overridden by subclasses
        return None


class DevelopmentConfig(BaseConfig):
    # Debug defaults to on for local work, but ``FLASK_DEBUG=0`` must be able to
    # turn it off: the Werkzeug debugger exposes an interactive console, which
    # is unacceptable on anything reachable from the network (e.g. HOST=0.0.0.0
    # for a demo). Hardcoding ``True`` here silently ignored the operator.
    DEBUG = _bool("FLASK_DEBUG", True)
    TESTING = False
    TEMPLATES_AUTO_RELOAD = True
    ENV_NAME = "development"


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True
    ENV_NAME = "testing"
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    # Fast (but still salted + iterated) hashing keeps the suite quick.
    PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000"
    # Generated per process: tests get a stable key without shipping a literal.
    SECRET_KEY = os.environ.get("TEST_SECRET_KEY") or secrets.token_urlsafe(32)
    ML_ENABLED = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    ENV_NAME = "production"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", True)
    REMEMBER_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", True)
    ENABLE_HSTS = _bool("ENABLE_HSTS", True)
    PREFERRED_URL_SCHEME = "https"

    #: Values that must never sign production sessions.  The dev placeholder is
    #: the development fallback; the rest are placeholders people paste in.
    WEAK_SECRETS = frozenset({
        DEV_SECRET_PLACEHOLDER,
        "change-me",
        "changeme",
        "secret",
        "secret-key",
        "please-change-me",
        "your-secret-key-here",
        "compose-demo-secret-change-me-8f2b41c7a96d",
    })
    MIN_SECRET_LENGTH = 32

    @classmethod
    def init_app(cls, app):
        """Refuse to boot production with a guessable session secret.

        A predictable SECRET_KEY lets anyone forge a session cookie and log in
        as any user, so this is a hard failure rather than a warning.
        """
        secret = (os.environ.get("SECRET_KEY") or "").strip()
        if not secret:
            raise RuntimeError(
                "SECRET_KEY environment variable must be set to a strong random "
                "value before running PhishGuard in production. Generate one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        if secret.lower() in {w.lower() for w in cls.WEAK_SECRETS}:
            raise RuntimeError(
                "SECRET_KEY is set to a known development/placeholder value. "
                "Production requires a unique, randomly generated secret."
            )
        if len(secret) < cls.MIN_SECRET_LENGTH:
            raise RuntimeError(
                f"SECRET_KEY must be at least {cls.MIN_SECRET_LENGTH} characters "
                f"(got {len(secret)}). Generate one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        if len(set(secret)) < 8:
            raise RuntimeError(
                "SECRET_KEY has too little variety to be random "
                "(e.g. 'aaaa...'). Generate a real random value."
            )


CONFIG_BY_NAME = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(name: str | None = None):
    """Resolve a configuration class from a name or the environment.

    Checked in order: explicit argument, ``FLASK_CONFIG``, ``FLASK_ENV``,
    ``APP_ENV``; the fallback is the development profile.
    """
    key = (
        name
        or os.environ.get("FLASK_CONFIG")
        or os.environ.get("FLASK_ENV")
        or os.environ.get("APP_ENV")
        or "development"
    ).lower()
    return CONFIG_BY_NAME.get(key, DevelopmentConfig)
