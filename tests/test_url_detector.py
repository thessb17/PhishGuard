"""URL heuristics: coverage, bounds, explainability and false-positive control."""

from __future__ import annotations

import pytest

from app.ml.feature_engineering import (FEATURE_NAMES, extract_features, features_to_vector,
                                        find_brands, shannon_entropy)
from app.services.url_analyzer import url_analyzer

PHISHING_URLS = [
    "http://198.51.100.23/paypal.com/secure/login.php?cmd=verify-account",
    "https://cybersafe.edu.verify-student.example/finance/confirm?id=8812",
    "http://micros0ft-secure-login.tk/account/unlock",
]
BENIGN_URLS = [
    "https://library.cybersafe.edu/account/loans",
    "https://docs.python.org/3/library/json.html?highlight=dumps",
]

#: Ordinary URLs that a phishing detector must leave alone.
EVERYDAY_BENIGN = [
    "https://www.google.com",
    "https://github.com/pallets/flask",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.amazon.in/gp/css/order-history?ref_=nav_orders_first",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://stackoverflow.com/questions/2020/how-to-do-x",
    "https://www.nhs.uk/conditions/",
]


@pytest.mark.parametrize("url", PHISHING_URLS)
def test_suspicious_urls_score_above_benign_ones(url):
    suspicious = url_analyzer.analyze(url)["heuristic_score"]
    benign = max(url_analyzer.analyze(u)["heuristic_score"] for u in BENIGN_URLS)
    assert suspicious > benign


def test_ip_literal_host_is_flagged():
    result = url_analyzer.analyze("http://198.51.100.23/login")
    codes = {indicator["code"] for indicator in result["indicators"]}
    assert "IP_HOST" in codes
    assert result["heuristic_score"] > 0


def test_at_symbol_authority_confusion_is_flagged():
    codes = {i["code"] for i in url_analyzer.analyze(
        "http://paypal.com@evil.example/secure")["indicators"]}
    assert "AT_SYMBOL" in codes


def test_punycode_host_is_flagged():
    codes = {i["code"] for i in url_analyzer.analyze(
        "https://xn--pypal-4ve.com/signin")["indicators"]}
    assert "PUNYCODE" in codes


def test_percent_encoding_is_flagged():
    codes = {i["code"] for i in url_analyzer.analyze(
        "http://192.0.2.44:8080/login/%68%74%74%70")["indicators"]}
    assert "HEX_ENCODING" in codes
    assert "NON_STANDARD_PORT" in codes


def test_deeply_nested_subdomains_are_flagged():
    codes = {i["code"] for i in url_analyzer.analyze(
        "https://appleid.apple.com.verify-account.ru/signin")["indicators"]}
    assert "MANY_SUBDOMAINS" in codes


def test_url_shortener_is_flagged():
    codes = {i["code"] for i in url_analyzer.analyze("http://bit.ly/3xR4pQz")["indicators"]}
    assert "SHORTENER" in codes


def test_brand_lookalike_domain_is_detected():
    codes = {i["code"] for i in url_analyzer.analyze(
        "http://paypa1-security.example/login")["indicators"]}
    assert codes & {"BRAND_LOOKALIKE", "LOOKALIKE_TYPO", "SUSPICIOUS_KEYWORDS", "HOST_HYPHENS"}


def test_long_url_is_flagged_but_only_once():
    result = url_analyzer.analyze("https://example.invalid/" + "a" * 200)
    codes = [i["code"] for i in result["indicators"]]
    assert "VERY_LONG_URL" in codes
    assert "LONG_URL" not in codes, "the two length rules must be mutually exclusive"


def test_every_indicator_explains_its_own_contribution():
    result = url_analyzer.analyze(PHISHING_URLS[0])
    assert result["indicators"], "a malicious URL must produce indicators"
    for indicator in result["indicators"]:
        assert set(indicator) >= {"code", "title", "category", "points", "evidence",
                                  "recommendation", "severity"}
        assert isinstance(indicator["points"], (int, float))
        assert indicator["evidence"], "an indicator must show the evidence behind it"


def test_analysis_result_exposes_the_documented_shape():
    result = url_analyzer.analyze(PHISHING_URLS[0])
    assert set(result) >= {"url", "hostname", "scheme", "registrable_domain", "tld",
                           "heuristic_score", "raw_score", "indicators", "features",
                           "feature_vector", "disclaimer"}
    assert result["disclaimer"]


def test_heuristic_score_is_bounded():
    for url in PHISHING_URLS + BENIGN_URLS:
        assert 0 <= url_analyzer.analyze(url)["heuristic_score"] <= 100


def test_extreme_url_is_clamped_to_one_hundred():
    hostile = ("http://paypal.verify.secure.login.account-update.confirm."
               "198.51.100.5:8080/webscr/login.php%2e%2e//signin?password=x&"
               + "pad=" + "a" * 300)
    result = url_analyzer.analyze(hostile)
    assert result["raw_score"] > 100
    assert result["heuristic_score"] == 100


def test_analysis_is_deterministic():
    scores = {url_analyzer.analyze(PHISHING_URLS[0])["heuristic_score"] for _ in range(5)}
    assert len(scores) == 1


def test_https_alone_does_not_make_a_url_safe():
    result = url_analyzer.analyze("https://cybersafe.edu.verify-student.example/login")
    assert result["scheme"] == "https"
    assert result["heuristic_score"] > 0, "HTTPS must not zero out the risk score"


@pytest.mark.parametrize("url", EVERYDAY_BENIGN)
def test_ordinary_urls_are_not_labelled_suspicious(url):
    """Regression: the detector must not cry wolf on everyday browsing."""
    assert url_analyzer.analyze(url)["heuristic_score"] < 25, url


def test_brand_tokens_do_not_match_inside_unrelated_words():
    """Regression for a substring bug: 'irs' matched inside 'first'.

    ``amazon.in/gp/css/order-history?ref_=nav_orders_first`` was scored HIGH
    because the brand token ``irs`` was 'found' in the word *first*, which
    then tripped BRAND_MISMATCH for 20 points.
    """
    assert find_brands("nav_orders_first") == []
    assert find_brands("a lawsuit about groups") == []
    assert find_brands("/gp/css/order-history?ref_=nav_orders_first") == []
    # Genuine appearances still match.
    assert "paypal" in find_brands("paypal-secure.example")
    assert "paypal" in find_brands("paypalsecure.example", allow_substring=True)

    result = url_analyzer.analyze(
        "https://www.amazon.in/gp/css/order-history?ref_=nav_orders_first")
    codes = {i["code"] for i in result["indicators"]}
    assert "BRAND_MISMATCH" not in codes
    assert result["heuristic_score"] < 25


def test_brand_mismatch_still_fires_on_real_impersonation():
    result = url_analyzer.analyze("https://paypal.secure-login.tk/webscr")
    codes = {i["code"] for i in result["indicators"]}
    assert "BRAND_MISMATCH" in codes


def test_high_entropy_rule_ignores_ordinary_hostnames():
    """Regression: the old 3.7/18 threshold fired on 10% of benign hostnames."""
    for host in ("portal.cybersafe.edu", "library.cybersafe.edu",
                 "docs.python.org", "www.wikipedia.org"):
        codes = {i["code"] for i in url_analyzer.analyze(f"https://{host}/")["indicators"]}
        assert "HIGH_ENTROPY_HOST" not in codes, host


def test_high_entropy_rule_still_catches_generated_hostnames():
    codes = {i["code"] for i in url_analyzer.analyze(
        "https://a8f3kd92mxqz7vbn.top/confirm")["indicators"]}
    assert "HIGH_ENTROPY_HOST" in codes
    assert shannon_entropy("a8f3kd92mxqz7vbn.top") > 4.0


def test_detector_thresholds_are_configurable(app):
    """Thresholds come from config, so an operator can retune without a patch."""
    url = "https://portal.cybersafe.edu/password/renew"
    with app.app_context():
        baseline = {i["code"] for i in url_analyzer.analyze(url)["indicators"]}
        assert "HIGH_ENTROPY_HOST" not in baseline
        app.config["URL_ENTROPY_THRESHOLD"] = 3.7
        app.config["URL_ENTROPY_MIN_HOST_LEN"] = 18
        retuned = {i["code"] for i in url_analyzer.analyze(url)["indicators"]}
        assert "HIGH_ENTROPY_HOST" in retuned


def test_generic_navigation_words_are_not_treated_as_bait():
    """'mail', 'id', 'user' and friends occur in ordinary URLs."""
    result = url_analyzer.analyze("https://mail.google.com/mail/u/0/")
    codes = {i["code"] for i in result["indicators"]}
    assert "SUSPICIOUS_KEYWORDS" not in codes


def test_credential_bait_keywords_are_still_detected():
    result = url_analyzer.analyze(
        "http://example.invalid/secure/verify/account?confirm=1&password=x")
    codes = {i["code"] for i in result["indicators"]}
    assert "SUSPICIOUS_KEYWORDS" in codes


def test_feature_vector_matches_declared_feature_names():
    url = "https://cybersafe.edu.verify-student.example/finance?id=1"
    features = extract_features(url)
    vector = features_to_vector(url)
    assert len(FEATURE_NAMES) == 38
    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(value, (int, float)) for value in vector)
    assert set(features.as_dict()["numeric"]) == set(FEATURE_NAMES)
    assert features.vector() == vector


@pytest.mark.parametrize("bad", ["", "   ", "not a url", "http://"])
def test_malformed_input_does_not_raise(bad):
    result = url_analyzer.analyze(bad)
    assert 0 <= result["heuristic_score"] <= 100
