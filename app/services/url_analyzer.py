"""Explainable, offline URL phishing heuristics.

The analyser never resolves DNS and never fetches the URL - all signals are
derived from the URL string, which makes analysis safe, fast and repeatable.

Every rule contributes a documented number of points; the sum is capped at
100.  Heuristics are *indicative*, not proof: false positives and false
negatives are possible and are surfaced explicitly in the UI and API output.
"""

from __future__ import annotations

import re

from flask import current_app, has_app_context

from app.ml.feature_engineering import (
    FREEMAIL_DOMAINS,
    SHORTENER_DOMAINS,
    URLFeatures,
    extract_features,
)
from app.services.brand_intel import detect_brand_impersonation
from app.services.domain_intel import DomainVerdict, get_provider
from app.services.indicators import AnalysisOutcome, Indicator

#: Documented rule weights (points added to the heuristic score).
RULE_WEIGHTS = {
    "IP_HOST": 25.0,
    "PUNYCODE": 20.0,
    "NON_ASCII": 18.0,
    "AT_SYMBOL": 18.0,
    "BRAND_MISMATCH": 20.0,
    "SUSPICIOUS_KEYWORDS": 15.0,      # scaled by number of hits (max value)
    "MANY_SUBDOMAINS": 10.0,
    "LONG_URL": 10.0,
    "VERY_LONG_URL": 15.0,
    "SUSPICIOUS_TLD": 12.0,
    "SHORTENER": 12.0,
    "NO_HTTPS": 8.0,
    "NON_STANDARD_PORT": 10.0,
    "HEX_ENCODING": 8.0,
    "HOST_HYPHENS": 8.0,
    "HIGH_ENTROPY_HOST": 8.0,
    "DOUBLE_SLASH_PATH": 6.0,
    "DIGIT_HEAVY_HOST": 6.0,
    "DANGEROUS_EXTENSION": 15.0,
    "OPEN_REDIRECT_PARAM": 12.0,
    "CREDENTIAL_PARAM": 12.0,
    "DEEP_PATH": 5.0,
    "LOOKALIKE_TYPO": 16.0,
}

DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jar", ".vbs", ".ps1", ".msi",
    ".apk", ".dll", ".iso", ".hta", ".lnk", ".zip", ".rar", ".7z",
)

REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "continue", "return",
                   "returnurl", "goto", "dest", "destination", "r", "u", "link"}

CREDENTIAL_PARAMS = {"password", "passwd", "pwd", "pass", "token", "otp", "pin",
                     "card", "cvv", "ssn", "account", "secret"}

#: Frequently spoofed domains, used for cheap typo-squat detection.
LOOKALIKE_TARGETS = {
    "paypal.com", "microsoft.com", "office.com", "outlook.com", "google.com",
    "apple.com", "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "docusign.com", "adobe.com", "github.com",
    "binance.com", "coinbase.com", "whatsapp.com", "zoom.us", "dhl.com",
    "fedex.com", "ups.com", "icloud.com", "cybersafe.edu", "example-corp.com",
}

_SUFFIX_DIGIT_RE = re.compile(r"\d")


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (small strings only - hostnames)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


#: Homoglyph / leet substitutions used by typo-squatters.
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s"}


def deskeleton(text: str) -> str:
    """Normalise common homoglyph substitutions before comparing domains."""
    lowered = (text or "").lower()
    for src, dst in HOMOGLYPHS.items():
        lowered = lowered.replace(src, dst)
    return lowered.replace("rn", "m").replace("vv", "w")


def closest_lookalike(domain: str) -> tuple[str | None, int]:
    """Return the nearest well-known domain and its edit distance.

    The comparison is run both on the raw domain and on a homoglyph-normalised
    version, so 'micr0s0ft.com' and 'rnicrosoft.com' are both caught.
    """
    if not domain:
        return None, 99
    normalised = deskeleton(domain)
    best, best_distance = None, 99
    for target in LOOKALIKE_TARGETS:
        distance = min(levenshtein(domain, target), levenshtein(normalised, deskeleton(target)))
        if distance < best_distance:
            best, best_distance = target, distance
    return best, best_distance


class URLAnalyzer:
    """Rule-based URL risk analysis with per-indicator explanations."""

    DISCLAIMER = (
        "Heuristic analysis inspects the URL string only - it does not visit the "
        "site. HTTPS does not make a URL safe, and legitimate sites can trigger "
        "rules. Treat the score as decision support, not proof."
    )

    # Fallback values used when no Flask application context is active
    # (unit tests, ``python -c`` probes).  The live values come from config so
    # an operator can retune the detector without editing this module.
    DEFAULT_THRESHOLDS = {
        "URL_ENTROPY_THRESHOLD": 4.0,
        "URL_ENTROPY_MIN_HOST_LEN": 20,
        "URL_DIGIT_RATIO_THRESHOLD": 0.25,
        "URL_LONG_THRESHOLD": 75,
        "URL_VERY_LONG_THRESHOLD": 120,
        "URL_MANY_SUBDOMAINS": 3,
        "URL_HOST_HYPHEN_THRESHOLD": 3,
        "URL_DEEP_PATH_THRESHOLD": 5,
    }

    def thresholds(self) -> dict:
        """Read tunable thresholds from config, falling back to the defaults."""
        values = dict(self.DEFAULT_THRESHOLDS)
        if has_app_context():
            for key in values:
                values[key] = current_app.config.get(key, values[key])
        return values

    def analyze(self, url: str) -> dict:
        features: URLFeatures = extract_features(url)
        n = features.numeric
        t = self.thresholds()
        outcome = AnalysisOutcome()

        # --- Host-based rules ------------------------------------------
        if n["has_ip"]:
            outcome.add(Indicator(
                "IP_HOST", "Raw IP address used instead of a domain name", "structure",
                RULE_WEIGHTS["IP_HOST"],
                evidence=f"Host is the literal address '{features.hostname}'.",
                recommendation="Legitimate brands publish named domains; treat bare IP links as hostile.",
            ))
        if n["has_punycode"]:
            outcome.add(Indicator(
                "PUNYCODE", "Punycode (xn--) host - possible homograph attack", "structure",
                RULE_WEIGHTS["PUNYCODE"],
                evidence=f"Host '{features.hostname}' contains an internationalised label.",
                recommendation="Decode the label and compare it with the brand's real domain.",
            ))
        if n["num_non_ascii"]:
            outcome.add(Indicator(
                "NON_ASCII", "Non-ASCII characters in the URL", "structure",
                RULE_WEIGHTS["NON_ASCII"],
                evidence=f"{int(n['num_non_ascii'])} non-ASCII character(s) detected.",
                recommendation="Cyrillic/Greek look-alikes are used to imitate brand domains.",
            ))
        if n["num_at"]:
            outcome.add(Indicator(
                "AT_SYMBOL", "'@' in the URL hides the true destination", "structure",
                RULE_WEIGHTS["AT_SYMBOL"],
                evidence="Everything before '@' is treated as userinfo and ignored by browsers.",
                recommendation="Read the host that appears immediately after the '@'.",
            ))
        if n["num_subdomains"] >= t["URL_MANY_SUBDOMAINS"]:
            outcome.add(Indicator(
                "MANY_SUBDOMAINS", "Excessive subdomain nesting", "structure",
                RULE_WEIGHTS["MANY_SUBDOMAINS"],
                evidence=f"{int(n['num_subdomains'])} subdomain labels: '{features.subdomain}'.",
                recommendation="Attackers bury brand names in subdomains they control.",
            ))
        if n["host_hyphens"] >= t["URL_HOST_HYPHEN_THRESHOLD"]:
            outcome.add(Indicator(
                "HOST_HYPHENS", "Unusually hyphenated hostname", "structure",
                RULE_WEIGHTS["HOST_HYPHENS"],
                evidence=f"{int(n['host_hyphens'])} hyphens in '{features.hostname}'.",
                recommendation="Strings like 'secure-login-update' are typical of phishing kits.",
            ))
        if (n["host_entropy"] > t["URL_ENTROPY_THRESHOLD"]
                and n["hostname_length"] >= t["URL_ENTROPY_MIN_HOST_LEN"]):
            outcome.add(Indicator(
                "HIGH_ENTROPY_HOST", "Random-looking hostname", "structure",
                RULE_WEIGHTS["HIGH_ENTROPY_HOST"],
                evidence=f"Shannon entropy {n['host_entropy']:.2f} bits/char over {int(n['hostname_length'])} chars.",
                recommendation="Algorithmically generated hosts are common in throwaway infrastructure.",
            ))
        if n["host_digit_ratio"] > t["URL_DIGIT_RATIO_THRESHOLD"] and not n["has_ip"]:
            outcome.add(Indicator(
                "DIGIT_HEAVY_HOST", "Digit-heavy hostname", "structure",
                RULE_WEIGHTS["DIGIT_HEAVY_HOST"],
                evidence=f"{n['host_digit_ratio'] * 100:.0f}% of the hostname characters are digits.",
                recommendation="Compare with the brand's documented domain.",
            ))
        if n["suspicious_tld"]:
            outcome.add(Indicator(
                "SUSPICIOUS_TLD", f"Frequently abused TLD '.{features.tld}'", "reputation",
                RULE_WEIGHTS["SUSPICIOUS_TLD"],
                evidence=f"Top-level domain '.{features.tld}' has an elevated abuse ratio.",
                recommendation="Not proof of malice - weigh it together with the other signals.",
            ))
        if n["is_shortener"]:
            outcome.add(Indicator(
                "SHORTENER", "URL-shortening / redirect service", "reputation",
                RULE_WEIGHTS["SHORTENER"],
                evidence=f"'{features.registrable_domain}' is a known shortener.",
                recommendation="Expand the link in a sandbox or preview service before trusting it.",
            ))

        # --- Look-alike / brand impersonation ---------------------------
        if n["brand_mismatch"]:
            outcome.add(Indicator(
                "BRAND_MISMATCH", "Brand name outside the registrable domain", "reputation",
                RULE_WEIGHTS["BRAND_MISMATCH"],
                evidence=(f"Brand token(s) {', '.join(features.brands)} appear in the subdomain/path "
                          f"while the real domain is '{features.registrable_domain}'."),
                recommendation="Only the registrable domain proves ownership - read it right-to-left.",
            ))
        target, distance = closest_lookalike(features.registrable_domain)
        if target and distance == 0 and features.registrable_domain not in LOOKALIKE_TARGETS:
            distance = 1  # homoglyph-normalised exact match => deliberate squat
        if target and 0 < distance <= 2 and features.registrable_domain not in LOOKALIKE_TARGETS:
            outcome.add(Indicator(
                "LOOKALIKE_TYPO", "Typo-squatted look-alike domain", "reputation",
                RULE_WEIGHTS["LOOKALIKE_TYPO"],
                evidence=f"'{features.registrable_domain}' is {distance} edit(s) away from '{target}'.",
                recommendation="Character swaps (rn/m, 0/o, 1/l) are classic impersonation tricks.",
            ))

        # --- Brand impersonation (label-level, explainable) --------------
        # The legacy LOOKALIKE_TYPO check above compares whole domains, so the
        # TLD dominates the edit distance ('paypa1.example' vs 'paypal.com' is
        # 6 edits, 5 of them just '.example' vs '.com') and real typosquats
        # score as unrelated. brand_intel compares the *label* and names the
        # technique, so the analyst sees why.
        brand_match = detect_brand_impersonation(
            features.hostname, features.registrable_domain
        )
        if brand_match and not outcome.has("LOOKALIKE_TYPO"):
            outcome.add(Indicator(
                brand_match.technique if brand_match.technique.startswith("BRAND_")
                else f"BRAND_{brand_match.technique}",
                f"Brand impersonation: {brand_match.technique.replace('_', ' ').lower()}",
                "reputation",
                brand_match.points,
                evidence=brand_match.evidence,
                recommendation=brand_match.explanation,
                severity=brand_match.severity,
            ))
            outcome.brand_match = brand_match

        # --- Local domain intelligence -----------------------------------
        # UNKNOWN contributes nothing: almost every domain is unknown to a
        # local list, and treating that as evidence of badness is the fastest
        # route to a detector nobody trusts.
        intel = get_provider().lookup(features.registrable_domain)
        outcome.domain_intel = intel
        if intel.verdict == DomainVerdict.KNOWN_SUSPICIOUS:
            outcome.add(Indicator(
                "DOMAIN_DENYLISTED", "Domain is on the local denylist", "reputation",
                abs(intel.score_adjustment),
                evidence=f"'{intel.domain}': {'; '.join(intel.reasons)}.",
                recommendation="This domain was previously recorded as malicious by this organisation.",
                severity="CRITICAL",
            ))
        elif intel.verdict == DomainVerdict.KNOWN_SAFE:
            # Recorded as a reassuring observation worth 0 points rather than a
            # negative score. Its real effect is upstream: brand_intel refuses
            # to raise impersonation findings against an allowlisted domain.
            # Structural indicators (IP host, punycode, credential keywords)
            # still fire - an allowlist entry is not a blank cheque.
            outcome.add(Indicator(
                "DOMAIN_ALLOWLISTED", "Domain is on the local allowlist", "reputation",
                0.0,
                evidence=f"'{intel.domain}': {'; '.join(intel.reasons)}.",
                recommendation=("Allowlisting suppresses brand-impersonation findings only. "
                                "Structural indicators are still evaluated."),
                positive=True,
            ))


        # --- Transport ---------------------------------------------------
        if not n["is_https"]:
            outcome.add(Indicator(
                "NO_HTTPS", "Connection is not encrypted (http://)", "structure",
                RULE_WEIGHTS["NO_HTTPS"],
                evidence=f"Scheme is '{features.scheme or 'http'}'.",
                recommendation="Credentials submitted over HTTP are exposed in transit.",
            ))
        else:
            outcome.add(Indicator(
                "HTTPS_PRESENT", "HTTPS in use (adds no safety guarantee)", "structure", 0.0,
                evidence="Most phishing sites now use free TLS certificates.",
                recommendation="Never treat the padlock as evidence of legitimacy.",
                positive=True,
            ))
        if n["has_port"]:
            outcome.add(Indicator(
                "NON_STANDARD_PORT", "Non-standard network port", "structure",
                RULE_WEIGHTS["NON_STANDARD_PORT"],
                evidence=f"Explicit port {features.port} in the URL.",
                recommendation="Brand portals rarely expose custom ports to end users.",
            ))

        # --- Path / query --------------------------------------------------
        if n["url_length"] > t["URL_VERY_LONG_THRESHOLD"]:
            outcome.add(Indicator(
                "VERY_LONG_URL", "Very long URL", "structure",
                RULE_WEIGHTS["VERY_LONG_URL"],
                evidence=f"{int(n['url_length'])} characters.",
                recommendation="Length is used to push the real host out of view on mobile clients.",
            ))
        elif n["url_length"] > t["URL_LONG_THRESHOLD"]:
            outcome.add(Indicator(
                "LONG_URL", "Longer-than-average URL", "structure",
                RULE_WEIGHTS["LONG_URL"],
                evidence=f"{int(n['url_length'])} characters.",
                recommendation="Compare the visible text with the actual link target.",
            ))
        if features.keywords:
            hits = features.keywords[:8]
            points = min(RULE_WEIGHTS["SUSPICIOUS_KEYWORDS"], 5.0 * len(hits))
            outcome.add(Indicator(
                "SUSPICIOUS_KEYWORDS", "Credential/urgency keywords in the URL", "reputation",
                points,
                evidence="Keywords: " + ", ".join(hits),
                recommendation="Words such as 'verify', 'secure' and 'update' are bait, not proof of identity.",
            ))
        if n["has_hex_encoding"]:
            outcome.add(Indicator(
                "HEX_ENCODING", "Percent-encoded characters obscure the URL", "structure",
                RULE_WEIGHTS["HEX_ENCODING"],
                evidence=f"{int(n['num_percent'])} '%' escape sequence(s).",
                recommendation="Decode the URL before judging it.",
            ))
        if n["double_slash_in_path"]:
            outcome.add(Indicator(
                "DOUBLE_SLASH_PATH", "Double slash inside the path", "structure",
                RULE_WEIGHTS["DOUBLE_SLASH_PATH"],
                evidence=f"Path '{features.path}' contains '//'.",
                recommendation="Often a sign of a chained redirect.",
            ))
        lowered_path = (features.path or "").lower()
        bad_ext = next((e for e in DANGEROUS_EXTENSIONS if lowered_path.endswith(e)), None)
        if bad_ext:
            outcome.add(Indicator(
                "DANGEROUS_EXTENSION", f"Link points directly at a '{bad_ext}' file", "structure",
                RULE_WEIGHTS["DANGEROUS_EXTENSION"],
                evidence=f"Path ends with '{bad_ext}'.",
                recommendation="Never execute downloads delivered by unsolicited links.",
            ))
        query_keys = {k.lower() for k, _ in _parse_query(features.query)}
        redirect_hits = sorted(query_keys & REDIRECT_PARAMS)
        if redirect_hits and any("http" in v.lower() for _, v in _parse_query(features.query)):
            outcome.add(Indicator(
                "OPEN_REDIRECT_PARAM", "Embedded redirect target in the query string", "structure",
                RULE_WEIGHTS["OPEN_REDIRECT_PARAM"],
                evidence="Parameter(s): " + ", ".join(redirect_hits),
                recommendation="Open-redirect abuse lets attackers borrow a trusted domain's reputation.",
            ))
        credential_hits = sorted(query_keys & CREDENTIAL_PARAMS)
        if credential_hits:
            outcome.add(Indicator(
                "CREDENTIAL_PARAM", "Credential-style parameters in the query string", "structure",
                RULE_WEIGHTS["CREDENTIAL_PARAM"],
                evidence="Parameter(s): " + ", ".join(credential_hits),
                recommendation="Secrets must never travel in a URL - they leak via logs and referrers.",
            ))
        if n["num_slash"] >= 7:
            outcome.add(Indicator(
                "DEEP_PATH", "Deeply nested path", "structure",
                RULE_WEIGHTS["DEEP_PATH"],
                evidence=f"{int(n['num_slash'])} path separators.",
                recommendation="Deep paths are used to mimic legitimate directory structures.",
            ))

        outcome.finalise()
        outcome.details = {
            "features": features.as_dict(),
            "disclaimer": self.DISCLAIMER,
            "rule_weights": RULE_WEIGHTS,
        }
        return {
            "url": features.url,
            "hostname": features.hostname,
            "scheme": features.scheme,
            "registrable_domain": features.registrable_domain,
            "tld": features.tld,
            "heuristic_score": outcome.score,
            "raw_score": outcome.raw_score,
            "indicators": outcome.to_dicts(),
            "features": features.as_dict(),
            "feature_vector": features.vector(),
            "brand_match": (outcome.brand_match.to_dict()
                            if getattr(outcome, "brand_match", None) else None),
            "domain_intel": (outcome.domain_intel.to_dict()
                             if getattr(outcome, "domain_intel", None) else None),
            "disclaimer": self.DISCLAIMER,
        }


def _parse_query(query: str) -> list[tuple[str, str]]:
    from urllib.parse import parse_qsl

    return parse_qsl(query or "", keep_blank_values=True)


def is_freemail(domain: str) -> bool:
    return (domain or "").lower() in FREEMAIL_DOMAINS


def is_shortener(domain: str) -> bool:
    return (domain or "").lower() in SHORTENER_DOMAINS


url_analyzer = URLAnalyzer()
