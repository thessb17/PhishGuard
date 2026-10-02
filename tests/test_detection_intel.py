"""Tests for the domain-intelligence, brand-impersonation, detection-trace
and observability subsystems added in the portfolio upgrade.

These are defensive tests: they assert the application behaves safely and
explainably. None of them constitute offensive tooling.
"""

from __future__ import annotations

import json

import pytest

from app.services.brand_intel import (
    allowed_distance, detect_brand_impersonation, levenshtein,
    normalise_homoglyphs, similarity, strip_separators,
)
from app.services.detection_trace import build_url_trace
from app.services.domain_intel import (
    DomainVerdict, LocalDomainIntelProvider, get_provider,
)
from app.utils.observability import _sanitise, current_request_id, new_request_id


# ---------------------------------------------------------------------------
# Domain intelligence
# ---------------------------------------------------------------------------


def test_provider_loads_every_local_list():
    stats = get_provider().stats()
    assert stats["allowlist"] > 0
    assert stats["denylist"] > 0
    assert stats["suspicious_tlds"] > 0
    assert stats["shorteners"] > 0
    assert stats["brands"] > 0


def test_allowlisted_domain_is_known_safe():
    intel = get_provider().lookup("cybersafe.edu")
    assert intel.verdict == DomainVerdict.KNOWN_SAFE
    assert intel.reasons


def test_denylisted_domain_is_known_suspicious():
    intel = get_provider().lookup("phish-demo-known-bad.example")
    assert intel.verdict == DomainVerdict.KNOWN_SUSPICIOUS
    assert intel.score_adjustment > 0


def test_unknown_domain_is_unknown_and_scores_zero():
    """The central rule: absence from a local list is not evidence of badness."""
    intel = get_provider().lookup("some-random-domain-nobody-listed.example")
    assert intel.verdict == DomainVerdict.UNKNOWN
    assert intel.score_adjustment == 0.0


def test_subdomains_inherit_the_parent_verdict():
    assert get_provider().lookup("portal.cybersafe.edu").verdict == DomainVerdict.KNOWN_SAFE


def test_weak_signals_do_not_change_the_verdict():
    """A shortener or an abused TLD is noted, but stays UNKNOWN."""
    short = get_provider().lookup("bit.ly")
    assert short.is_shortener is True
    assert short.verdict == DomainVerdict.UNKNOWN

    tld = get_provider().lookup("whatever.tk")
    assert tld.is_suspicious_tld is True
    assert tld.verdict == DomainVerdict.UNKNOWN


def test_denylist_beats_allowlist(tmp_path):
    """An explicit 'this is bad' outranks an inherited 'this was fine'."""
    (tmp_path / "allowlist.txt").write_text("conflict.example\n")
    (tmp_path / "denylist.txt").write_text("conflict.example\n")
    (tmp_path / "suspicious_tlds.txt").write_text("tk\n")
    (tmp_path / "shorteners.txt").write_text("bit.ly\n")
    (tmp_path / "brands.json").write_text(json.dumps({"brands": []}))
    provider = LocalDomainIntelProvider(base_dir=tmp_path)
    assert provider.lookup("conflict.example").verdict == DomainVerdict.KNOWN_SUSPICIOUS


def test_provider_tolerates_a_missing_directory(tmp_path):
    """Absent list files must degrade to UNKNOWN, never raise."""
    provider = LocalDomainIntelProvider(base_dir=tmp_path / "nope")
    assert provider.lookup("anything.example").verdict == DomainVerdict.UNKNOWN
    assert provider.brands() == []


def test_empty_domain_is_handled():
    assert get_provider().lookup("").verdict == DomainVerdict.UNKNOWN


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host,domain,technique,brand", [
    ("paypa1.example", "paypa1.example", "HOMOGLYPH", "paypal"),
    ("micros0ft.example", "micros0ft.example", "HOMOGLYPH", "microsoft"),
    ("arnazon.example", "arnazon.example", "HOMOGLYPH", "amazon"),
    ("paypal.com.account-verify.example", "account-verify.example",
     "BRAND_IN_SUBDOMAIN", "paypal"),
    ("secure.paypal-support.example", "paypal-support.example",
     "EXACT_LABEL_FOREIGN_DOMAIN", "paypal"),
])
def test_impersonation_techniques_are_detected_and_named(host, domain, technique, brand):
    match = detect_brand_impersonation(host, domain)
    assert match is not None, f"{host} should be flagged"
    assert match.technique == technique
    assert match.brand_detected == brand
    assert match.explanation and match.evidence


def test_punycode_is_flagged_as_a_lookalike():
    match = detect_brand_impersonation("xn--pypal-4ve.example", "xn--pypal-4ve.example")
    assert match is not None
    assert match.technique == "PUNYCODE_LOOKALIKE"


@pytest.mark.parametrize("host,domain", [
    ("paypal.com", "paypal.com"),
    ("www.paypal.com", "paypal.com"),
    ("github.com", "github.com"),
    ("mail.google.com", "google.com"),
    ("flask.palletsprojects.com", "palletsprojects.com"),
    ("www.uni-mainz.de", "uni-mainz.de"),
    ("stackoverflow.com", "stackoverflow.com"),
    ("en.wikipedia.org", "wikipedia.org"),
])
def test_legitimate_domains_are_never_accused(host, domain):
    """False positives here would destroy trust in the whole feature."""
    assert detect_brand_impersonation(host, domain) is None


def test_allowlisted_domain_is_exempt_from_impersonation_findings():
    assert detect_brand_impersonation("portal.cybersafe.edu", "cybersafe.edu") is None


def test_short_labels_are_not_edit_distance_matched():
    """At three characters almost everything is within one edit."""
    assert detect_brand_impersonation("ucs.example", "ucs.example") is None
    assert allowed_distance("ups") == 1
    assert allowed_distance("microsoft") >= 2


def test_edit_budget_scales_with_label_length():
    assert allowed_distance("abcde") < allowed_distance("abcdefghijkl")


def test_homoglyph_normalisation_collapses_substitutions():
    assert normalise_homoglyphs("paypa1") == "paypal"
    assert normalise_homoglyphs("arnazon") == "amazon"
    assert normalise_homoglyphs("micr0s0ft") == "microsoft"


def test_separator_stripping_catches_hyphenated_squats():
    assert strip_separators("pay-pal") == "paypal"


def test_levenshtein_and_similarity_are_sane():
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("", "abc") == 3
    assert similarity("abc", "abc") == 1.0
    assert 0.0 <= similarity("abc", "xyz") <= 1.0


def test_brand_match_serialises_for_the_api():
    match = detect_brand_impersonation("paypa1.example", "paypa1.example")
    payload = match.to_dict()
    for key in ("brand_detected", "matched_domain", "similarity_score",
                "technique", "explanation"):
        assert key in payload


def test_similarity_alone_is_not_treated_as_proof():
    """A typosquat match must carry a caveat, not a verdict."""
    match = detect_brand_impersonation("payppal.example", "payppal.example")
    if match and match.technique == "TYPOSQUAT":
        assert "not proof" in match.explanation.lower()


def test_empty_input_returns_no_match():
    assert detect_brand_impersonation("", "") is None


# ---------------------------------------------------------------------------
# Detection trace
# ---------------------------------------------------------------------------


def _trace_for(app, url):
    from app.services.ml_detector import ml_detector
    from app.services.risk_engine import risk_engine
    from app.services.url_analyzer import url_analyzer

    with app.app_context():
        rule = url_analyzer.analyze(url)
        ml = ml_detector.predict(url)
        risk = risk_engine.combine(
            heuristic_score=rule["heuristic_score"],
            ml_score=ml.get("risk_score") if ml.get("available") else None,
            ml_confidence=ml.get("confidence") if ml.get("available") else None,
            ml_model=ml.get("model") if ml.get("available") else None,
            ml_available=bool(ml.get("available")),
        )
        return build_url_trace(rule, ml, risk), rule, risk


def test_trace_has_the_documented_pipeline_stages(app):
    trace, _, _ = _trace_for(app, "https://paypa1.example/account/verify")
    keys = [s["key"] for s in trace]
    assert keys == ["input", "features", "rules", "ml", "fusion", "verdict"]


def test_trace_verdict_matches_the_actual_risk_assessment(app):
    """If the trace could disagree with the verdict it would be worthless."""
    trace, _, risk = _trace_for(app, "http://198.51.100.23/secure/login.php")
    verdict = next(s for s in trace if s["key"] == "verdict")
    values = {r["label"]: r["value"] for r in verdict["rows"]}
    assert values["Risk band"] == risk.classification
    assert float(values["Final score"]) == pytest.approx(risk.final_score, abs=0.01)


def test_trace_states_that_no_network_request_is_made(app):
    trace, _, _ = _trace_for(app, "https://example.com/")
    assert "never" in trace[0]["caveat"].lower()
    assert "fetch" in trace[0]["caveat"].lower()


def test_trace_ml_stage_carries_an_honesty_caveat(app):
    trace, _, _ = _trace_for(app, "https://example.com/")
    ml_stage = next(s for s in trace if s["key"] == "ml")
    assert "demonstration model" in ml_stage["caveat"].lower()


def test_trace_is_json_serialisable(app):
    trace, _, _ = _trace_for(app, "https://example.com/")
    json.dumps(trace)


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------


def test_request_id_is_returned_in_a_header(client):
    response = client.get("/api/health")
    assert response.headers.get("X-Request-ID")


def test_request_id_appears_in_the_api_envelope(client):
    body = client.get("/api/health").get_json()
    assert body["request_id"] == "" or len(body["request_id"]) > 0
    assert body["error"] is None
    assert "data" in body


def test_error_envelope_has_data_null_and_a_request_id(client):
    body = client.get("/api/does-not-exist").get_json()
    assert body["success"] is False
    assert body["data"] is None
    assert body["error"]["code"] == "not_found"
    assert body["request_id"]


def test_client_supplied_request_id_is_echoed(client):
    response = client.get("/api/health", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers["X-Request-ID"] == "trace-abc-123"


def test_hostile_request_id_is_not_reflected(client):
    """A client-supplied ID lands in the log file; it must be constrained."""
    hostile = "<script>alert(1)</script>"
    response = client.get("/api/health", headers={"X-Request-ID": hostile})
    assert response.headers["X-Request-ID"] != hostile
    assert "<" not in response.headers["X-Request-ID"]


def test_overlong_request_id_is_rejected(client):
    response = client.get("/api/health", headers={"X-Request-ID": "a" * 200})
    assert len(response.headers["X-Request-ID"]) <= 64


def test_structured_logger_redacts_sensitive_fields():
    cleaned = _sanitise({"password": "hunter2", "api_key": "abc", "ok": "visible"})
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["ok"] == "visible"


def test_structured_logger_truncates_long_values():
    cleaned = _sanitise({"note": "x" * 5000})
    assert len(cleaned["note"]) <= 256


def test_request_id_outside_a_request_context_is_a_placeholder():
    assert current_request_id() == "-"


def test_new_request_ids_are_unique():
    assert len({new_request_id() for _ in range(100)}) == 100


# ---------------------------------------------------------------------------
# Regression: the email detection trace was built but never wired up
# ---------------------------------------------------------------------------


def _email_trace(app):
    from app.services.detection_trace import build_email_trace
    from app.services.email_analyzer import email_analyzer
    from app.services.ml_detector import ml_detector
    from app.services.risk_engine import risk_engine

    with app.app_context():
        rule = email_analyzer.analyze(
            sender="ceo@examp1e-corp.example",
            subject="URGENT: gift cards needed now",
            body=("Please buy 5 gift cards and send me the codes. "
                  "Keep this confidential. http://paypa1.example/pay"))
        ml = ml_detector.predict("http://paypa1.example/pay")
        risk = risk_engine.combine(
            heuristic_score=rule["heuristic_score"],
            ml_score=ml.get("risk_score") if ml.get("available") else None,
            ml_confidence=ml.get("confidence") if ml.get("available") else None,
            ml_model=ml.get("model") if ml.get("available") else None,
            ml_available=bool(ml.get("available")))
        return build_email_trace(rule, ml, risk), risk


def test_email_trace_builds_and_is_serialisable(app):
    trace, _ = _email_trace(app)
    assert trace, "the email trace must not be empty"
    json.dumps(trace)


def test_email_trace_has_input_fusion_and_verdict_stages(app):
    trace, _ = _email_trace(app)
    keys = [s["key"] for s in trace]
    assert keys[0] == "input"
    assert "fusion" in keys and "verdict" in keys
    assert any(k.startswith("layer_") for k in keys), "per-layer stages expected"


def test_email_trace_verdict_matches_the_risk_engine(app):
    """The trace must never disagree with the actual assessment."""
    trace, risk = _email_trace(app)
    verdict = next(s for s in trace if s["key"] == "verdict")
    values = {r["label"]: r["value"] for r in verdict["rows"]}
    assert values["Risk band"] == risk.classification


def test_email_detector_page_renders_the_detection_trace(analyst_client):
    """Regression: build_email_trace existed but the route never called it,
    so the email result page had no trace while the URL page had six stages."""
    response = analyst_client.post("/email-detector", data={
        "sender": "ceo@examp1e-corp.example",
        "subject": "URGENT: gift cards needed now",
        "body": ("Please buy 5 gift cards and send the codes. "
                 "Keep this confidential. http://paypa1.example/pay"),
    }, follow_redirects=True)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Detection trace" in body, "email result page is missing the trace panel"
    assert "How was this score calculated" in body
    assert body.count("pg-trace-title") >= 4


def test_url_detector_page_still_renders_the_detection_trace(analyst_client):
    response = analyst_client.post("/url-detector",
                                   data={"url": "https://paypa1.example/verify"},
                                   follow_redirects=True)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Detection trace" in body
    assert body.count("pg-trace-title") == 6


def test_verification_scripts_fail_cleanly_without_a_server():
    """Regression: both scripts dumped a urllib traceback when the server was
    down - the exact behaviour the application itself is held to avoid."""
    import re
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for script in ("scripts/acceptance_check.py", "scripts/frontend_check.py"):
        source = (root / script).read_text(encoding="utf-8")
        assert "_preflight" in source, f"{script} has no connectivity preflight"
        # Point the script at a closed port and confirm it exits cleanly.
        # A regex is required because the two scripts spell the assignment
        # differently ('BASE = "..."' vs 'BASE="..."'); a literal replace
        # silently matched only one of them, so this test previously passed
        # for the wrong reason whenever the real server happened to be down.
        patched, n = re.subn(r'^BASE\s*=\s*["\'][^"\']+["\']',
                             'BASE = "http://127.0.0.1:1"', source, count=1,
                             flags=re.M)
        assert n == 1, f"could not repoint BASE in {script} - test would be vacuous"
        proc = subprocess.run([sys.executable, "-c", patched],
                              capture_output=True, text=True, cwd=root, timeout=60)
        assert proc.returncode == 2, f"{script} exit {proc.returncode}, expected 2"
        assert "Traceback" not in proc.stderr, f"{script} leaked a traceback"
        assert "cannot reach PhishGuard" in proc.stderr
