"""Input validation helpers shared by forms, views and the REST API."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{3,64}$")
ALLOWED_URL_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048


class ValidationError(ValueError):
    """Raised when user supplied input fails validation."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.message = message
        self.field = field


def validate_text(value: str | None, field: str, *, required: bool = True,
                  min_length: int = 0, max_length: int = 5000) -> str:
    text = (value or "").strip()
    if required and not text:
        raise ValidationError(f"{field} is required.", field)
    if text and len(text) < min_length:
        raise ValidationError(f"{field} must be at least {min_length} characters.", field)
    if len(text) > max_length:
        raise ValidationError(f"{field} must be at most {max_length} characters.", field)
    return text


def validate_username(value: str | None) -> str:
    username = validate_text(value, "Username", min_length=3, max_length=64)
    if not USERNAME_RE.match(username):
        raise ValidationError(
            "Username may only contain letters, numbers, dots, dashes and underscores.", "username"
        )
    return username.lower()


def validate_email_address(value: str | None, field: str = "Email") -> str:
    email = validate_text(value, field, max_length=320).lower()
    if not EMAIL_RE.match(email):
        raise ValidationError(f"{field} must be a valid email address.", field.lower())
    return email


def validate_password(value: str | None, min_length: int = 10) -> str:
    password = value or ""
    if len(password) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters long.", "password")
    checks = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(checks) < 3:
        raise ValidationError(
            "Password must combine at least three of: lowercase, uppercase, digits, symbols.",
            "password",
        )
    return password


#: ``scheme:`` prefix at the start of a string (RFC 3986 section 3.1).
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def normalize_url(value: str | None) -> str:
    """Trim and add a scheme when the user pasted a bare hostname.

    A scheme that is already present is preserved verbatim - including unsafe
    ones such as ``javascript:`` or ``data:`` - so that :func:`validate_url`
    can reject them instead of silently rewriting them into an ``http://``
    URL that looks legitimate.
    """
    url = (value or "").strip().strip("<>\"'")
    if not url:
        return ""
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    return url


def validate_url(value: str | None, field: str = "URL") -> str:
    """Validate a URL for *offline, string-level* analysis.

    PhishGuard never fetches the URL, so the validation only ensures the value
    is a parseable http(s) URL of sane length.
    """
    url = normalize_url(value)
    if not url:
        raise ValidationError(f"{field} is required.", "url")
    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(f"{field} must be at most {MAX_URL_LENGTH} characters.", "url")
    # urlparse raises ValueError on some malformed inputs - notably an
    # unterminated IPv6 bracket such as 'http://[::1'. Left unhandled that
    # surfaced as an HTTP 500 for ordinary bad user input, so every parse of
    # untrusted text is converted into a clean validation error.
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except ValueError as exc:
        raise ValidationError(f"{field} is not a parseable URL.", "url") from exc
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ValidationError("Only http:// and https:// URLs can be analysed.", "url")
    if not parsed.netloc:
        raise ValidationError(f"{field} must include a hostname.", "url")
    if not host:
        raise ValidationError(f"{field} must include a hostname.", "url")
    if any(ch in url for ch in ("\n", "\r", "\t", " ")):
        raise ValidationError("URL must not contain whitespace or control characters.", "url")
    return url


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def validate_choice(value: str | None, choices, field: str) -> str:
    val = (value or "").strip().upper()
    allowed = {str(c).upper() for c in choices}
    if val not in allowed:
        raise ValidationError(f"{field} must be one of: {', '.join(sorted(allowed))}.", field.lower())
    return val


def validate_int(value, field: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be an integer.", field.lower()) from None
    if minimum is not None and number < minimum:
        raise ValidationError(f"{field} must be >= {minimum}.", field.lower())
    if maximum is not None and number > maximum:
        raise ValidationError(f"{field} must be <= {maximum}.", field.lower())
    return number


def extract_urls(text: str | None, limit: int = 40) -> list[str]:
    """Pull http(s) URLs out of free text (used by the email analyser)."""
    if not text:
        return []
    found = re.findall(r"(?:https?://|www\.)[^\s<>\"')\]]+", text, flags=re.IGNORECASE)
    urls: list[str] = []
    for raw in found:
        cleaned = raw.rstrip(".,;:!?")
        if cleaned.lower().startswith("www."):
            cleaned = "http://" + cleaned
        if cleaned not in urls:
            urls.append(cleaned)
        if len(urls) >= limit:
            break
    return urls
