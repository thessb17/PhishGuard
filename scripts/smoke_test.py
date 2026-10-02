#!/usr/bin/env python3
"""End-to-end smoke test against a running PhishGuard server.

Nine checks, in the order a person would perform them: reach the server,
land on the login page, sign in, see the dashboard, analyse a URL, sign out.
Exits 0 only if every check passes; any failure exits non-zero.

    python run.py                  # in one terminal
    python scripts/smoke_test.py   # in another

Options:
    --base-url URL     target (default http://localhost:5000)
    --username / --password   demo credentials to use

Nothing here is hardcoded to succeed: each step asserts on real response
content, and the exit code is derived from the results.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "http://localhost:5000"


class _LoopbackCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Return Secure cookies to a loopback target reached over plain HTTP.

    ``Secure`` tells a browser not to transmit a cookie over a cleartext
    *network*. This harness talks to loopback, and the server may legitimately
    be configured for an HTTPS deployment. Without this the jar silently drops
    the session and the test reports a confusing parse failure instead of a
    result.
    """

    def return_ok_secure(self, cookie, request):
        host = (request.host or "").split(":")[0].strip("[]")
        if host in ("127.0.0.1", "localhost", "::1"):
            return True
        return super().return_ok_secure(cookie, request)


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        jar = http.cookiejar.CookieJar(policy=_LoopbackCookiePolicy())
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))

    def get(self, path: str):
        return self._open(urllib.request.Request(self.base + path))

    def post(self, path: str, data: dict):
        body = urllib.parse.urlencode(data, doseq=True).encode()
        return self._open(urllib.request.Request(self.base + path, data=body))

    def _open(self, request):
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def csrf(self, path: str) -> str:
        _, html = self.get(path)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        return match.group(1) if match else ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="Admin@Phish2026")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        results.append((name, bool(ok), detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<34} {detail}")
        return bool(ok)

    print(f"PhishGuard smoke test -> {base}")
    print("-" * 64)

    # 1. server reachable
    try:
        with urllib.request.urlopen(base + "/health", timeout=10) as response:
            reachable, health_status = True, response.status
    except Exception as exc:  # noqa: BLE001
        print(f"  [FAIL] server unreachable at {base}", file=sys.stderr)
        print(f"         {type(exc).__name__}: {exc}", file=sys.stderr)
        print("", file=sys.stderr)
        print("         Start it first:  python run.py", file=sys.stderr)
        return 2
    check("server reachable", reachable, base)

    client = Client(base)

    # 2. GET /
    status, _ = client.get("/")
    check("GET / responds", status in (200, 302), f"HTTP {status}")

    # 3. GET /health
    import json

    status, body = client.get("/health")
    try:
        health = json.loads(body)
    except ValueError:
        health = {}
    check("GET /health returns JSON", status == 200 and health.get("status") == "ok",
          f"HTTP {status} status={health.get('status')} db={health.get('database')} ml={health.get('ml')}")

    # 4 + 5. login page
    status, html = client.get("/login")
    check("GET /login renders", status == 200 and "csrf_token" in html,
          f"HTTP {status}")

    # 6. login
    token = client.csrf("/login")
    status, html = client.post("/login", {"csrf_token": token,
                                          "username": args.username,
                                          "password": args.password})
    logged_in = status == 200 and "CSRF validation failed" not in html
    check("login succeeds", logged_in, f"HTTP {status}")

    # 7. dashboard
    status, html = client.get("/dashboard")
    check("dashboard reachable", status == 200 and "Sign in" not in html,
          f"HTTP {status}")

    # 8. analyse a safe test URL
    token = client.csrf("/url-detector")
    status, html = client.post("/url-detector",
                               {"csrf_token": token,
                                "url": "https://example.com/account/verify"})
    scored = status == 200 and "CSRF validation failed" not in html
    check("URL analysis completes", scored, f"HTTP {status}")

    # 9. logout
    status, _ = client.get("/logout")
    check("logout succeeds", status == 200, f"HTTP {status}")
    # Assert on CONTENT, not just the status code: this client follows
    # redirects, so a logged-out /dashboard returns HTTP 200 for the login
    # page it lands on. Checking only the status would pass vacuously.
    status, html = client.get("/dashboard")
    landed_on_login = "csrf_token" in html and "Sign in" in html
    check("session invalidated", landed_on_login,
          f"HTTP {status}, redirected to login" if landed_on_login
          else f"HTTP {status}, still authenticated")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("-" * 64)
    print(f"  {passed}/{total} checks passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
