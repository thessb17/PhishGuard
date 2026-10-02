"""Phase 21: edge-case and property tests.

The application must fail *safely* on malformed, empty, enormous and
unexpected input - returning a handled error, never a stack trace, a 500, or
a corrupted score.
"""

from __future__ import annotations

import pytest

from app.extensions import db as _db
from app.models.campaign import Campaign
from app.models.user import User
from app.services.risk_engine import classify_score
from app.services.url_analyzer import url_analyzer
from app.utils.validators import ValidationError, validate_url


# --------------------------------------------------------------------------
# URL edge cases
# --------------------------------------------------------------------------

MALFORMED_URLS = [
    "", "   ", "http://", "https://", "://missing-scheme", "http:///nohost",
    "not a url at all", "http://[::1", "ht!tp://bad.example", "//protocol-relative",
    "http://.", "http://..", "http://-leading-hyphen.example",
]


@pytest.mark.parametrize("raw", MALFORMED_URLS)
def test_malformed_urls_are_rejected_or_scored_without_crashing(app, raw):
    with app.app_context():
        try:
            cleaned = validate_url(raw)
        except ValidationError:
            return  # rejected cleanly - the preferred outcome
        result = url_analyzer.analyze(cleaned)
        assert 0.0 <= result["heuristic_score"] <= 100.0


def test_extremely_long_url_is_bounded(app):
    url = "https://example.com/" + ("a" * 50_000)
    with app.app_context():
        result = url_analyzer.analyze(url)
        assert 0.0 <= result["heuristic_score"] <= 100.0


def test_unicode_url_is_handled(app):
    with app.app_context():
        result = url_analyzer.analyze("https://пример.example/вход")
        assert 0.0 <= result["heuristic_score"] <= 100.0


def test_url_with_unusual_port_is_handled(app):
    with app.app_context():
        for port in (8080, 65535, 1):
            result = url_analyzer.analyze(f"https://example.com:{port}/x")
            assert 0.0 <= result["heuristic_score"] <= 100.0


def test_url_with_many_subdomains_does_not_overflow(app):
    host = ".".join(["sub"] * 60) + ".example.com"
    with app.app_context():
        result = url_analyzer.analyze(f"https://{host}/path")
        assert result["heuristic_score"] <= 100.0


@pytest.mark.parametrize("scheme", ["javascript:", "data:", "file:", "ftp:", "vbscript:"])
def test_hostile_schemes_are_refused(app, scheme):
    with app.app_context():
        with pytest.raises(ValidationError):
            validate_url(f"{scheme}//evil.example/x")


def test_url_analysis_is_deterministic(app):
    with app.app_context():
        a = url_analyzer.analyze("https://paypa1.example/verify")
        b = url_analyzer.analyze("https://paypa1.example/verify")
        assert a["heuristic_score"] == b["heuristic_score"]
        assert [i["code"] for i in a["indicators"]] == [i["code"] for i in b["indicators"]]


# --------------------------------------------------------------------------
# Email edge cases
# --------------------------------------------------------------------------

def test_empty_email_is_handled(app):
    from app.services.email_analyzer import email_analyzer
    with app.app_context():
        result = email_analyzer.analyze(sender="", subject="", body="")
        assert 0.0 <= result["heuristic_score"] <= 100.0


def test_email_with_missing_headers_is_handled(app):
    from app.services.email_analyzer import email_analyzer
    with app.app_context():
        result = email_analyzer.analyze(sender="only@example.com", subject="", body="hi")
        assert 0.0 <= result["heuristic_score"] <= 100.0


def test_very_large_email_body_is_bounded(app):
    from app.services.email_analyzer import email_analyzer
    with app.app_context():
        result = email_analyzer.analyze(
            sender="a@example.com", subject="x", body="word " * 100_000)
        assert 0.0 <= result["heuristic_score"] <= 100.0


def test_malformed_email_headers_do_not_crash(app):
    from app.services.email_analyzer import email_analyzer
    with app.app_context():
        result = email_analyzer.analyze(
            sender="<<<not an address>>>", subject="\x00\x01binary",
            body="Received: nonsense\nFrom without colon\n")
        assert 0.0 <= result["heuristic_score"] <= 100.0


# --------------------------------------------------------------------------
# Scores and roles
# --------------------------------------------------------------------------

@pytest.mark.parametrize("score", [-500.0, -1.0, 0.0, 50.0, 100.0, 101.0, 1e9])
def test_classify_score_never_escapes_the_band_set(app, score):
    with app.app_context():
        band = classify_score(score)
        assert band in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_invalid_role_is_not_granted_capabilities(app):
    with app.app_context():
        user = User(username="weird", email="w@cybersafe.edu",
                    full_name="W", role="NOT_A_REAL_ROLE")
        assert user.can("audit.view") is False
        assert user.can("campaign.create") is False


def test_nonexistent_campaign_returns_404_not_500(admin_client):
    assert admin_client.get("/campaigns/99999999").status_code == 404


def test_nonexistent_report_returns_404(admin_client):
    assert admin_client.get("/reports/99999999").status_code == 404


def test_deleted_user_does_not_break_the_audit_trail(app, users):
    """Audit rows must survive their actor (ON DELETE SET NULL)."""
    from app.models.audit_log import AuditLog
    with app.app_context():
        before = AuditLog.query.count()
        user = _db.session.get(User, users.demo.id)
        _db.session.delete(user)
        _db.session.commit()
        assert AuditLog.query.count() >= before


def test_duplicate_campaign_name_is_allowed_but_ids_differ(app, users):
    """Names are not unique; the system must not silently merge campaigns."""
    from datetime import datetime, timedelta, timezone

    from app.services.campaign_service import create_campaign
    with app.app_context():
        admin = _db.session.get(User, users.admin.id)
        kwargs = dict(description="d", template_key="password_expiry", difficulty="EASY",
                      start_date=datetime.now(timezone.utc).replace(tzinfo=None),
                      end_date=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=5),
                      target_ids=[users.demo.id], creator=admin, status="DRAFT",
                      organization="Andhra University")
        a = create_campaign(name="Same Name", **kwargs)
        b = create_campaign(name="Same Name", **kwargs)
        _db.session.commit()
        assert a.id != b.id
        assert Campaign.query.filter_by(name="Same Name").count() == 2


# --------------------------------------------------------------------------
# Input hostility at the HTTP layer
# --------------------------------------------------------------------------

def test_malicious_looking_filename_cannot_traverse(admin_client):
    for probe in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "report\x00.pdf"):
        response = admin_client.get(f"/reports/download/{probe}")
        assert response.status_code in (400, 404, 403, 301, 308)
        assert b"root:" not in response.data


def test_invalid_json_body_returns_400(client, users):
    response = client.post("/api/analyze/url", data="{not json",
                           content_type="application/json",
                           headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "validation_error"


def test_oversized_json_body_is_refused(client, users):
    huge = '{"url": "https://example.com/' + "a" * 2_000_000 + '"}'
    response = client.post("/api/analyze/url", data=huge,
                           content_type="application/json",
                           headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code in (400, 413)


def test_null_bytes_in_input_are_handled(client, users):
    response = client.post("/api/analyze/url",
                           json={"url": "https://exa\x00mple.com/"},
                           headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code in (200, 400)
    assert b"Traceback" not in response.data
