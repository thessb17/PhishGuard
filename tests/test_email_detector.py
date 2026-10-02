"""Email heuristics across the five scenario families the brief requires."""

from __future__ import annotations

import pytest

from app.services.email_analyzer import email_analyzer

LEGITIMATE = dict(
    sender="library-notices@cybersafe.edu",
    subject="Your interlibrary loan is ready for collection",
    body=("Hello Priya,\n\nThe book you requested has arrived at the Central Library "
          "help desk until 14 March.\nYou can review your current loans at "
          "https://library.cybersafe.edu/account/loans\n\nKind regards,\nCentral Library"),
    headers=("Reply-To: library-notices@cybersafe.edu\n"
             "Return-Path: <library-notices@cybersafe.edu>\n"
             "Received: from mx1.cybersafe.edu (mx1.cybersafe.edu [198.51.100.10]) "
             "by mail.cybersafe.edu\n"
             "Received: from lib-app01.cybersafe.edu by mx1.cybersafe.edu\n"
             "Authentication-Results: mx.cybersafe.edu; spf=pass; dkim=pass; dmarc=pass"),
)
URGENCY = dict(
    sender='"IT Service Desk" <it-servicedesk@cybersafe-notices.example>',
    subject="ACTION REQUIRED: your password expires in 12 hours",
    body=("Dear User,\n\nYour password expires in 12 hours. Renew immediately or your "
          "account will be locked automatically.\n"
          "http://cybersafe-notices.example/password/renew?uid=8823ab"),
    headers=("Reply-To: helpdesk-recovery@mail-support.example\n"
             "Return-Path: <bounce@bulk-sender.example>\n"
             "X-Mailer: PHPMailer 6.1.7\n"
             "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail"),
)
ACCOUNT_VERIFICATION = dict(
    sender="no-reply@account-verification-center.example",
    subject="Verify your account to avoid suspension",
    body=("We could not verify your account. Confirm your identity within 24 hours: "
          "https://account-verification-center.example/verify?id=91823\n"
          "Failure to verify will result in permanent suspension."),
    headers="Authentication-Results: mx; spf=softfail; dkim=none; dmarc=fail",
)
FINANCIAL = dict(
    sender='"Accounts Payable" <ap-invoices@examplecorp-billing.example>',
    subject="Re: Outstanding invoice 88213 - immediate payment required today",
    body=("Our records show invoice 88213 is overdue. Please process the wire transfer "
          "to our updated bank details today and keep this confidential until the audit "
          "closes. Do not discuss with other departments.\n"
          "http://examplecorp-billing.example/pay/88213"),
    headers=("Reply-To: finance-recovery@mail-drop.example\n"
             "Authentication-Results: mx; spf=softfail; dkim=none; dmarc=fail"),
)
IMPERSONATION = dict(
    sender='"Avery Sinclair (CEO)" <avery.sinclair.ceo@gmail.invalid>',
    subject="Quick favour - are you at your desk?",
    body=("I am in a meeting and cannot talk. I need you to purchase five gift cards "
          "for a client and send me the codes. Keep this between us, I will reimburse "
          "you later."),
    headers="Reply-To: a.sinclair.office@mail-drop.example",
)

SCENARIOS = {
    "urgency": URGENCY,
    "account_verification": ACCOUNT_VERIFICATION,
    "financial": FINANCIAL,
    "impersonation": IMPERSONATION,
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_each_phishing_scenario_outscores_the_legitimate_message(name):
    suspicious = email_analyzer.analyze(**SCENARIOS[name])["heuristic_score"]
    legitimate = email_analyzer.analyze(**LEGITIMATE)["heuristic_score"]
    assert suspicious > legitimate
    assert suspicious >= 50, f"{name} should reach at least the HIGH band"


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_each_scenario_returns_the_full_documented_payload(name):
    result = email_analyzer.analyze(**SCENARIOS[name])
    assert set(result) >= {"sender", "subject", "heuristic_score", "indicators",
                           "urls", "header_findings", "disclaimer"}
    assert result["indicators"], "a phishing email must produce detected indicators"
    for indicator in result["indicators"]:
        assert set(indicator) >= {"code", "title", "category", "points",
                                  "evidence", "recommendation", "severity"}
        assert indicator["recommendation"], "every indicator must advise an action"


def test_legitimate_message_scores_low_and_is_not_over_flagged():
    result = email_analyzer.analyze(**LEGITIMATE)
    assert result["heuristic_score"] < 25
    codes = {i["code"] for i in result["indicators"]}
    assert "AUTH_PASS" in codes


def test_mentioning_a_help_desk_is_not_impersonation():
    """Regression: bare 'help desk' matched ordinary prose for 12 points."""
    codes = {i["code"] for i in email_analyzer.analyze(**LEGITIMATE)["indicators"]}
    assert "BODY_IMPERSONATION" not in codes


def test_claiming_to_be_the_help_desk_is_impersonation():
    result = email_analyzer.analyze(
        sender="a@b.invalid", subject="Notice",
        body="This is the IT help desk. We need you to confirm your login now.")
    codes = {i["code"] for i in result["indicators"]}
    assert "BODY_IMPERSONATION" in codes


def test_partial_header_paste_is_not_penalised_as_a_broken_chain():
    """Regression: supplying only a Reply-To line cost the analyst 8 points."""
    codes = {i["code"] for i in email_analyzer.analyze(
        sender="a@b.invalid", subject="Hi", body="Hello",
        headers="Reply-To: a@b.invalid")["indicators"]}
    assert "RECEIVED_CHAIN" not in codes


def test_a_real_header_block_with_no_received_hops_is_flagged():
    codes = {i["code"] for i in email_analyzer.analyze(
        sender="a@b.invalid", subject="Hi", body="Hello",
        headers=("Return-Path: <bounce@bulk.example>\n"
                 "Message-ID: <1@bulk.example>\n"
                 "Authentication-Results: mx; spf=fail"))["indicators"]}
    assert "RECEIVED_CHAIN" in codes


def test_email_authentication_failures_are_parsed():
    findings = email_analyzer.analyze(
        sender="alerts@example.invalid", subject="Notice", body="Hello",
        headers=("Reply-To: attacker@mail-drop.example\n"
                 "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\n"),
    )["header_findings"]
    assert findings["spf"] == "fail"
    assert findings["dkim"] == "none"
    assert findings["dmarc"] == "fail"
    assert findings["reply_to"] == "attacker@mail-drop.example"


def test_reply_to_mismatch_is_reported():
    codes = {i["code"] for i in email_analyzer.analyze(
        sender="payroll@example-corp.com", subject="Payslip", body="See attached.",
        headers="Reply-To: payroll-team@free-mail.example\n")["indicators"]}
    assert "REPLY_TO_MISMATCH" in codes


def test_gift_card_request_is_detected():
    codes = {i["code"] for i in email_analyzer.analyze(**IMPERSONATION)["indicators"]}
    assert "BODY_GIFT_CARD" in codes
    assert "BODY_SECRECY" in codes


def test_financial_pressure_is_detected():
    codes = {i["code"] for i in email_analyzer.analyze(**FINANCIAL)["indicators"]}
    assert "BODY_FINANCIAL" in codes


def test_embedded_urls_are_extracted_and_scored():
    result = email_analyzer.analyze(
        sender="noreply@example.invalid", subject="Invoice",
        body=("Pay here http://198.51.100.23/pay/invoice and read "
              "https://library.cybersafe.edu/account/loans"),
    )
    assert len({entry["url"] for entry in result["urls"]}) == 2
    assert result["worst_url"]["hostname"] == "198.51.100.23"


def test_email_body_with_no_links_is_handled():
    result = email_analyzer.analyze(sender="a@b.invalid", subject="Hi", body="No links here.")
    assert result["urls"] == []
    assert result["worst_url"] is None


def test_email_score_is_bounded_and_deterministic():
    extreme = email_analyzer.analyze(
        sender="a@" + "x" * 60 + ".tk",
        subject="URGENT VERIFY PASSWORD ACCOUNT SUSPENDED NOW!!!" * 4,
        body=("click http://198.51.100.1/login " * 30) + "send your password and gift cards",
        headers="Reply-To: z@evil.example\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail",
    )
    assert extreme["heuristic_score"] == 100
    assert extreme["raw_score"] > 100
    repeated = {email_analyzer.analyze(**URGENCY)["heuristic_score"] for _ in range(4)}
    assert len(repeated) == 1
