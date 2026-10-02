"""REST API contract: auth, validation, status codes, JSON shape and reports."""

from __future__ import annotations

import csv
import io
import json

import pytest

from app.extensions import db as _db
from app.models.email_analysis import EmailAnalysis
from app.models.quiz import QuizAttempt
from app.models.report import Report
from app.models.url_analysis import URLAnalysis
from app.models.user import User
from app.services.report_service import (create_campaign_report, pdf_available, report_filename,
                                         report_to_csv, report_to_pdf)


# ------------------------------------------------------------------- basics
def test_health_endpoint_is_public_and_json(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["status"] == "ok"


def test_api_requires_authentication(client):
    response = client.post("/api/analyze/url", json={"url": "http://example.invalid"})
    assert response.status_code == 401
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["error"]["code"] == "unauthorized"


def test_api_key_authentication_works(client, users):
    response = client.post("/api/analyze/url",
                           json={"url": "http://198.51.100.23/paypal.com/login.php"},
                           headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["classification"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0 <= data["risk_score"] <= 100
    assert 0 <= data["heuristic_score"] <= 100
    assert data["weights"] == {"heuristic": 0.6, "ml": 0.4}
    assert data["indicators"]
    assert "disclaimer" in data


def test_bearer_token_authentication_works(client, users):
    response = client.get("/api/campaigns",
                          headers={"Authorization": f"Bearer {users.analyst.api_key}"})
    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_invalid_api_key_is_rejected(client, users):
    assert client.get("/api/campaigns",
                      headers={"X-API-Key": "not-a-real-key"}).status_code == 401


# --------------------------------------------------------------- validation
def test_api_rejects_a_missing_url_field(client, users):
    response = client.post("/api/analyze/url", json={},
                           headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize("hostile", ["javascript:alert(1)", "data:text/html,<script>x</script>",
                                     "file:///etc/passwd", "ftp://files.example/x"])
def test_api_rejects_unsupported_schemes(client, users, hostile):
    response = client.post("/api/analyze/url", json={"url": hostile},
                           headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 400, hostile
    assert response.get_json()["success"] is False


def test_api_rejects_a_malformed_json_body(client, users):
    response = client.post("/api/analyze/url", data="not json",
                           headers={"X-API-Key": users.analyst.api_key,
                                    "Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.mimetype == "application/json"


def test_unknown_api_path_returns_the_documented_error_envelope(client, users):
    response = client.get("/api/does-not-exist", headers={"X-API-Key": users.admin.api_key})
    assert response.status_code == 404
    assert response.mimetype == "application/json"
    error = response.get_json()["error"]
    assert error["code"] == "not_found", "error codes must be the documented slugs"


def test_wrong_http_method_returns_json_not_html(client, users):
    """Regression: a 405 on an API route used to return Werkzeug's HTML page."""
    response = client.delete("/api/campaigns", headers={"X-API-Key": users.admin.api_key})
    assert response.status_code == 405
    assert response.mimetype == "application/json"
    assert response.get_json()["error"]["code"] == "method_not_allowed"


def test_api_email_analysis_returns_indicators(client, users):
    response = client.post("/api/analyze/email", json={
        "sender": '"IT" <it@cybersafe-notices.example>',
        "subject": "URGENT: verify your password now",
        "body": "Confirm your password at http://cybersafe-notices.example/verify",
        "headers": "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail",
    }, headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["indicators"]
    assert data["header_findings"]["spf"] == "fail"


# ------------------------------------------------------------- authorization
def test_api_campaign_listing_and_detail(client, users, campaign):
    listing = client.get("/api/campaigns", headers={"X-API-Key": users.analyst.api_key})
    assert listing.status_code == 200
    items = listing.get_json()["data"]["campaigns"]
    assert len(items) == 1
    assert items[0]["statistics"]["participants"] == 2

    detail = client.get(f"/api/campaigns/{campaign.id}",
                        headers={"X-API-Key": users.analyst.api_key})
    assert detail.status_code == 200
    assert detail.get_json()["data"]["campaign"]["name"] == campaign.name


def test_api_campaign_creation_requires_the_capability(client, users):
    response = client.post("/api/campaigns", json={
        "name": "API created drill", "template_key": "hr_policy",
        "target_ids": [users.demo.id],
    }, headers={"X-API-Key": users.demo.api_key})
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "forbidden"


def test_api_campaign_creation_succeeds_for_an_analyst(client, users):
    response = client.post("/api/campaigns", json={
        "name": "API created drill", "template_key": "hr_policy",
        "description": "Created through the REST API by the test-suite.",
        "target_ids": [users.demo.id, users.demo2.id],
    }, headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 201
    data = response.get_json()["data"]
    assert data["campaign"]["name"] == "API created drill"
    assert data["campaign"]["template_key"] == "hr_policy"


def test_api_campaign_creation_validates_the_template(client, users):
    response = client.post("/api/campaigns", json={
        "name": "Bad", "template_key": "nope", "target_ids": [users.demo.id],
    }, headers={"X-API-Key": users.analyst.api_key})
    assert response.status_code == 400


def test_api_analysis_is_denied_to_demo_users(client, users):
    response = client.post("/api/analyze/url", json={"url": "http://example.invalid"},
                           headers={"X-API-Key": users.demo.api_key})
    assert response.status_code == 403


def test_api_user_listing_is_admin_only(client, users):
    assert client.get("/api/users",
                      headers={"X-API-Key": users.analyst.api_key}).status_code == 403
    response = client.get("/api/users", headers={"X-API-Key": users.admin.api_key})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "password_hash" not in body
    assert "api_key" not in body


def test_api_404_for_an_unknown_report(client, users):
    response = client.get("/api/reports/9999", headers={"X-API-Key": users.admin.api_key})
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "not_found"


def test_api_ml_metadata_is_honest_about_limitations(client, users):
    response = client.get("/api/ml/metadata", headers={"X-API-Key": users.analyst.api_key})
    payload = response.get_json()["data"]
    assert payload["available"] is True
    assert payload["feature_count"] == 38
    assert payload["disclaimer"]


# -------------------------------------------------------------------- quiz
def test_api_quiz_never_leaks_the_answer_key(client, users, quiz):
    response = client.get("/api/quiz", headers={"X-API-Key": users.demo.api_key})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    payload = response.get_json()["data"]
    assert len(payload["questions"]) == 10
    for question in payload["questions"]:
        assert "correct_index" not in question
        assert "explanation" not in question
    assert "correct_index" not in body


def test_api_quiz_submission_is_graded_and_explained(app, client, users, quiz):
    answers = {str(qid): index for qid, index in quiz.correct.items()}
    response = client.post("/api/quiz/submit", json={"answers": answers},
                           headers={"X-API-Key": users.demo.api_key})
    assert response.status_code == 201
    data = response.get_json()["data"]
    assert data["attempt"]["score"] == 100
    assert data["attempt"]["passed"] is True
    assert len(data["results"]) == 10
    assert all(row["explanation"] for row in data["results"])
    with app.app_context():
        assert QuizAttempt.query.filter_by(user_id=users.demo.id).count() == 1


def test_api_quiz_submission_with_wrong_answers_fails_the_pass_mark(client, users, quiz):
    answers = {str(qid): (index + 1) % quiz.option_counts[qid]
               for qid, index in quiz.correct.items()}
    response = client.post("/api/quiz/submit", json={"answers": answers},
                           headers={"X-API-Key": users.demo.api_key})
    data = response.get_json()["data"]
    assert data["attempt"]["score"] == 0
    assert data["attempt"]["passed"] is False


def test_api_quiz_submission_rejects_an_empty_body(client, users, quiz):
    response = client.post("/api/quiz/submit", json={"answers": {}},
                           headers={"X-API-Key": users.demo.api_key})
    assert response.status_code == 400


# ----------------------------------------------------------------- reports
def test_campaign_report_payload_contains_statistics(app, campaign, users):
    with app.app_context():
        from app.models.campaign import Campaign

        report = create_campaign_report(_db.session.get(Campaign, campaign.id),
                                        _db.session.get(User, users.admin.id))
        assert report.id is not None
        assert report.payload["statistics"]["participants"] == 2
        assert report.payload["notes"], "reports must state their limitations"


def test_report_csv_export_is_parseable(app, campaign, users):
    with app.app_context():
        from app.models.campaign import Campaign

        report = create_campaign_report(_db.session.get(Campaign, campaign.id),
                                        _db.session.get(User, users.admin.id))
        text = report_to_csv(report)
    rows = list(csv.reader(io.StringIO(text)))
    assert len(rows) > 5
    assert any("PhishGuard" in ",".join(row) for row in rows[:3])


@pytest.mark.skipif(not pdf_available(), reason="reportlab is not installed")
def test_report_pdf_export_produces_a_pdf(app, campaign, users):
    with app.app_context():
        from app.models.campaign import Campaign

        report = create_campaign_report(_db.session.get(Campaign, campaign.id),
                                        _db.session.get(User, users.admin.id))
        blob = report_to_pdf(report)
    assert blob.startswith(b"%PDF-")
    assert len(blob) > 1000


def test_report_filename_is_safe(app, campaign, users):
    with app.app_context():
        from app.models.campaign import Campaign

        report = create_campaign_report(_db.session.get(Campaign, campaign.id),
                                        _db.session.get(User, users.admin.id))
        name = report_filename(report, "csv")
    assert name.endswith(".csv")
    assert "/" not in name and " " not in name


def test_report_download_routes(app, admin_client, campaign, users):
    with app.app_context():
        from app.models.campaign import Campaign

        report = create_campaign_report(_db.session.get(Campaign, campaign.id),
                                        _db.session.get(User, users.admin.id))
        report_id = report.id

    csv_response = admin_client.get(f"/reports/{report_id}/download/csv")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"

    json_response = admin_client.get(f"/reports/{report_id}/download/json")
    assert json_response.status_code == 200
    exported = json.loads(json_response.get_data(as_text=True))
    assert exported["payload"]["statistics"]["participants"] == 2
    assert "attachment" in json_response.headers["Content-Disposition"]

    assert admin_client.get(f"/reports/{report_id}/download/exe").status_code in (400, 404)


def test_detection_report_can_be_generated_from_the_ui(app, analyst_client):
    analyst_client.post("/url-detector",
                        data={"url": "http://198.51.100.23/paypal.com/secure/login.php"})
    with app.app_context():
        analysis = URLAnalysis.query.first()
        assert analysis is not None
        analysis_id = analysis.id
    response = analyst_client.post(f"/reports/detection/url/{analysis_id}", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert Report.query.filter_by(subject_type="url_analysis").count() == 1


def test_email_analysis_through_the_ui_is_persisted_redacted(app, analyst_client):
    analyst_client.post("/email-detector", data={
        "sender": "it@cybersafe-notices.example", "subject": "Verify now",
        "body": "My password is Sup3rSecret! and my OTP is 123456. "
                "Visit http://cybersafe-notices.example/verify",
        "urls": "", "headers": "",
    })
    with app.app_context():
        record = EmailAnalysis.query.first()
        assert record is not None
        assert "Sup3rSecret!" not in record.body_excerpt
        assert "123456" not in record.body_excerpt
        assert "[REDACTED" in record.body_excerpt or "***" in record.body_excerpt


def test_quiz_submission_through_the_web_ui(app, demo_client, quiz):
    data = {f"question-{qid}": str(index) for qid, index in quiz.correct.items()}
    response = demo_client.post("/quiz", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert "100" in response.get_data(as_text=True)
    with app.app_context():
        attempt = QuizAttempt.query.first()
        assert attempt.score == 100 and attempt.passed is True


def test_unanswered_quiz_questions_count_as_incorrect(app, demo_client, quiz):
    first_id = quiz.question_ids[0]
    response = demo_client.post("/quiz",
                                data={f"question-{first_id}": str(quiz.correct[first_id])},
                                follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        attempt = QuizAttempt.query.first()
        assert attempt.answered_count == 1
        assert attempt.correct_count == 1
        assert attempt.score == 10
        assert attempt.passed is False
