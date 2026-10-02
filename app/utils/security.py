"""HTTP security headers and related hardening helpers."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from flask import request


def build_csp(frame_ancestors: str = "'self'") -> str:
    """A strict, self-hosted Content-Security-Policy.

    Every asset (Bootstrap, Chart.js, icons, fonts) is vendored locally, so no
    external origin needs to be allowed and no inline script is required -
    page data is passed to JavaScript through ``<script type="application/json">``
    data blocks, which are inert and therefore CSP-safe.
    """
    directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        f"frame-ancestors {frame_ancestors}",
    ]
    return "; ".join(directives)


def apply_security_headers(response, config):
    """Attach the standard security header set to every response."""
    frame_ancestors = config.get("FRAME_ANCESTORS", "'self'")
    csp_header = "Content-Security-Policy-Report-Only" if config.get("CSP_REPORT_ONLY") else "Content-Security-Policy"
    response.headers.setdefault(csp_header, build_csp(frame_ancestors))
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()",
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("X-XSS-Protection", "0")  # rely on CSP, not the legacy auditor
    # The ``Server`` banner is written by the WSGI server, not by Flask, so it
    # cannot be replaced from here - setting it would simply emit a second
    # header.  It is suppressed at the server layer instead (see run.py).
    response.headers.pop("X-Powered-By", None)
    # X-Frame-Options only makes sense for the same-origin policy; when the
    # deployment explicitly allows embedding we rely on CSP frame-ancestors.
    if frame_ancestors.strip() == "'self'":
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    elif frame_ancestors.strip() == "'none'":
        response.headers.setdefault("X-Frame-Options", "DENY")
    if config.get("ENABLE_HSTS") and request.is_secure:
        max_age = config.get("HSTS_MAX_AGE", 31536000)
        response.headers.setdefault(
            "Strict-Transport-Security", f"max-age={max_age}; includeSubDomains"
        )
    response.headers.setdefault("Cache-Control", "no-store" if _is_sensitive(request.path) else "no-cache")
    return response


def _is_sensitive(path: str) -> bool:
    sensitive_prefixes = ("/login", "/profile", "/audit-logs", "/api/", "/reports")
    return any(path.startswith(prefix) for prefix in sensitive_prefixes)


def is_safe_redirect_url(target: str | None) -> bool:
    """Prevent open-redirects on the post-login ``next`` parameter."""
    if not target:
        return False
    if target.startswith("//") or "\\" in target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc
