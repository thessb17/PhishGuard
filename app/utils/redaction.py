"""Redaction helpers.

PhishGuard analyses *submitted* email content, so anything that looks like a
secret (password, API key, OTP, card number, bearer token) is masked before
the text is persisted or logged.  This keeps the detection features useful
while ensuring the database never becomes a credential store.
"""

from __future__ import annotations

import re

MASK = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # password: hunter2 / password = hunter2 / pwd - hunter2
    (re.compile(r"(?i)\b(pass(?:word|phrase|wd)?|pwd|senha|contrase[nñ]a)\b\s*(?:[:=\-]|\bis\b|\bwas\b|\bequals\b)\s*\S+"), r"\1: " + MASK),
    # one time codes / OTP / PIN
    (re.compile(r"(?i)\b(otp|one[- ]time (?:code|password)|pin|verification code|security code)\b\s*(?:[:=\-]|\bis\b|\bwas\b)?\s*\d{4,10}"), r"\1: " + MASK),
    # Authorization headers / bearer tokens
    (re.compile(r"(?i)\b(authorization|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)\b\s*[:=]?\s*[A-Za-z0-9._\-]{8,}"), r"\1: " + MASK),
    # Long opaque tokens (JWT-like)
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"), MASK),
    # Payment card numbers (13-19 digits, optional separators)
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), MASK),
    # CVV
    (re.compile(r"(?i)\b(cvv|cvc|security digits)\b\s*[:=\-]?\s*\d{3,4}"), r"\1: " + MASK),
    # IBAN-ish / long account numbers
    (re.compile(r"(?i)\b(iban|account\s*(?:no|number)|acct)\b\s*[:=\-]?\s*[A-Z0-9]{8,34}"), r"\1: " + MASK),
    # SSN / national id style
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), MASK),
]


def redact_sensitive(text: str | None) -> str:
    """Mask credential-like substrings in ``text``.

    The function is intentionally conservative: it prefers over-masking to
    leaking a secret into persistent storage.
    """
    if not text:
        return ""
    cleaned = str(text)
    for pattern, replacement in _PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def truncate(text: str | None, limit: int = 4000) -> str:
    """Trim ``text`` to ``limit`` characters with an explicit marker."""
    if not text:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} characters]"


def safe_excerpt(text: str | None, limit: int = 4000) -> str:
    """Redact then truncate - the combination used before DB writes."""
    return truncate(redact_sensitive(text), limit)


def mask_email(address: str | None) -> str:
    """Partially mask an email address for display in shared reports."""
    if not address or "@" not in address:
        return address or ""
    local, _, domain = address.partition("@")
    if len(local) <= 2:
        masked = local[0] + "*"
    else:
        masked = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked}@{domain}"
