"""URL feature engineering.

This module is the single source of truth for URL features.  It is used by:

* :mod:`app.services.url_analyzer` - explainable rule-based scoring,
* :mod:`app.ml.train`             - model training,
* :mod:`app.ml.predict`           - inference at request time.

Keeping one implementation guarantees that training-time and serving-time
features cannot drift apart.  No network access is performed: every feature is
derived from the URL string itself, which keeps analysis safe and offline.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlparse

# --------------------------------------------------------------------------
# Lexicons
# --------------------------------------------------------------------------

#: TLDs frequently abused by phishing kits (indicative, not proof of malice).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "cf", "ml", "tk", "ga",
    "work", "fit", "rest", "country", "kim", "loan", "men", "date", "racing",
    "stream", "download", "review", "party", "science", "trade", "bid", "win",
    "webcam", "cam", "buzz", "monster", "quest", "sbs", "cyou", "icu", "lol",
    "su", "cc", "pw", "info", "online", "site", "shop", "store", "live", "life",
}

#: URL-shortening and redirect-as-a-service hosts.
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bl.ink", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly",
    "s.id", "t.ly", "soo.gd", "qr.ae", "clck.ru", "lnkd.in", "db.tt", "trib.al",
    "shorte.st", "urlz.fr", "v.gd", "x.co", "short.io", "1url.com",
}

#: Credential/urgency keywords commonly embedded in phishing URLs.
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "logon", "verify", "verification", "validate",
    "secure", "security", "account", "update", "confirm", "confirmation",
    "password", "passwd", "credential", "authenticate", "auth", "wallet",
    "unlock", "recovery", "recover", "reset", "billing", "invoice", "payment",
    "refund", "bank", "suspend", "suspended", "limited", "alert",
    "webscr", "session", "token", "otp", "mfa", "2fa", "helpdesk",
    "ebayisapi",
}
# Deliberately NOT in the list above: 'id', 'user', 'mail', 'pay', 'auth',
# 'portal', 'service', 'support', 'customer'.  They occur in a large share of
# perfectly ordinary URLs (mail.google.com, /support/, ?id=), so they added
# score without adding evidence.  Keeping them made benign navigation URLs
# look suspicious, which is exactly the failure mode this detector must avoid.

#: Brand tokens used to detect impersonation in subdomains / paths.
BRAND_TOKENS = {
    "paypal", "microsoft", "office365", "outlook", "onedrive", "google", "gmail",
    "apple", "icloud", "amazon", "aws", "netflix", "facebook", "instagram",
    "whatsapp", "linkedin", "dropbox", "docusign", "adobe", "chase", "hsbc",
    "barclays", "wellsfargo", "citibank", "sbi", "hdfc", "icici", "paytm",
    "dhl", "fedex", "ups", "usps", "irs", "hmrc", "binance", "coinbase",
    "metamask", "steam", "zoom", "slack", "github", "bankofamerica",
}

#: Free webmail providers (legitimate, but unusual for corporate senders).
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "protonmail.com", "proton.me", "mail.com", "gmx.com",
    "zoho.com", "yandex.com", "icloud.com", "rediffmail.com", "inbox.com",
}

#: Multi-label public suffixes needed to find the registrable domain without
#: pulling in a full public-suffix-list dependency.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "res.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "com.br", "com.mx", "com.ar", "com.sg", "com.my", "com.tr",
    "co.za", "co.jp", "ne.jp", "or.jp", "co.kr", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.tw", "com.ua", "com.pl", "com.ph", "com.vn", "com.pk",
    "com.eg", "com.sa", "com.ng", "com.gh", "com.co", "com.pe", "com.ec",
}

HEX_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

#: Canonical, ordered feature vector used by the ML models.
FEATURE_NAMES: list[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question",
    "num_equals",
    "num_ampersand",
    "num_underscore",
    "num_slash",
    "num_percent",
    "num_digits",
    "digit_ratio",
    "host_digit_ratio",
    "num_subdomains",
    "has_ip",
    "is_https",
    "has_port",
    "has_punycode",
    "is_shortener",
    "suspicious_tld",
    "num_suspicious_keywords",
    "brand_in_subdomain",
    "brand_in_path",
    "brand_mismatch",
    "host_entropy",
    "path_entropy",
    "longest_token_length",
    "double_slash_in_path",
    "tld_length",
    "num_query_params",
    "has_hex_encoding",
    "host_hyphens",
    "num_non_ascii",
    "has_www_in_subdomain",
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char) - high values hint at random-looking hosts."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_ip_host(host: str) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    # Dotted-decimal written with padding or hex/octal notation
    if re.fullmatch(r"0x[0-9a-fA-F]+", candidate):
        return True
    if re.fullmatch(r"\d{8,12}", candidate):
        return True
    return False


def split_host(host: str) -> tuple[str, str, str]:
    """Return ``(subdomain, registrable_domain, tld)`` for a hostname."""
    host = (host or "").lower().strip(".")
    if not host or is_ip_host(host):
        return "", host, ""
    parts = host.split(".")
    if len(parts) == 1:
        return "", host, ""
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(parts) >= 3:
        tld = last_two
        registrable = ".".join(parts[-3:])
        subdomain = ".".join(parts[:-3])
    else:
        tld = parts[-1]
        registrable = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])
    return subdomain, registrable, tld


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_SPLIT_RE.split((text or "").lower()) if t]


def count_keywords(text: str) -> list[str]:
    tokens = set(tokenize(text))
    lowered = (text or "").lower()
    hits = {kw for kw in SUSPICIOUS_KEYWORDS if kw in tokens}
    # catch concatenated forms such as "paypal-secure-login"
    for kw in ("login", "verify", "secure", "account", "update", "confirm",
               "password", "billing", "suspended", "webscr", "recovery"):
        if kw in lowered:
            hits.add(kw)
    return sorted(hits)


def find_brands(text: str, *, allow_substring: bool = False) -> list[str]:
    """Locate brand tokens in ``text``.

    Matching is **boundary aware**.  A naive ``brand in text`` test produces
    absurd false positives because short brand tokens hide inside ordinary
    words - ``irs`` inside "f*irs*t", ``aws`` inside "l*aws*uit", ``ups``
    inside "gro*ups*".  That single bug was enough to push a legitimate
    ``amazon.in/gp/css/order-history?ref_=nav_orders_first`` URL into the HIGH
    band, so brands must be delimited by a non-letter on both sides.

    ``allow_substring`` relaxes the rule for hostnames only, where attackers
    deliberately glue the brand to other words (``paypalsecure.example``).
    It is restricted to tokens of five characters or more so that short
    brands cannot re-introduce the original bug.
    """
    lowered = (text or "").lower()
    if not lowered:
        return []
    found = set()
    for brand in BRAND_TOKENS:
        if re.search(rf"(?<![a-z]){re.escape(brand)}(?![a-z])", lowered):
            found.add(brand)
        elif allow_substring and len(brand) >= 5 and brand in lowered:
            found.add(brand)
    return sorted(found)


# --------------------------------------------------------------------------
# Feature container
# --------------------------------------------------------------------------

@dataclass
class URLFeatures:
    """Structured result of URL parsing + numeric feature extraction."""

    url: str
    scheme: str = ""
    hostname: str = ""
    subdomain: str = ""
    registrable_domain: str = ""
    tld: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""
    port: int | None = None
    keywords: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    numeric: dict[str, float] = field(default_factory=dict)

    def vector(self) -> list[float]:
        return [float(self.numeric.get(name, 0.0)) for name in FEATURE_NAMES]

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "subdomain": self.subdomain,
            "registrable_domain": self.registrable_domain,
            "tld": self.tld,
            "path": self.path,
            "query": self.query,
            "port": self.port,
            "keywords": self.keywords,
            "brands": self.brands,
            "numeric": {k: round(float(v), 4) for k, v in self.numeric.items()},
        }


def extract_features(url: str) -> URLFeatures:
    """Parse ``url`` and compute the canonical numeric feature set."""
    raw = (url or "").strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    # urlparse raises ValueError on malformed input (e.g. an unterminated
    # IPv6 bracket). Feature extraction is called from predict_url() as well
    # as the web layer, so it degrades to an empty parse rather than letting
    # a ValueError escape into an unrelated caller.
    try:
        parsed = urlparse(raw)
        _ = parsed.hostname
    except ValueError:
        parsed = urlparse("")
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    subdomain, registrable, tld = split_host(hostname)
    decoded = unquote(raw)

    host_digits = sum(ch.isdigit() for ch in hostname)
    url_digits = sum(ch.isdigit() for ch in raw)
    tokens = tokenize(raw)
    longest_token = max((len(t) for t in tokens), default=0)

    keywords = count_keywords(decoded)
    path_and_query = f"{path}?{query}"
    brands_in_host = find_brands(hostname, allow_substring=True)
    brands_in_path = find_brands(path_and_query)

    # Brand mismatch: a brand token appears in the subdomain or path while the
    # registrable domain does not belong to that brand.
    brand_mismatch = 0
    for brand in set(brands_in_host + brands_in_path):
        if brand not in registrable:
            brand_mismatch = 1
            break

    numeric: dict[str, float] = {
        "url_length": len(raw),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "num_dots": raw.count("."),
        "num_hyphens": raw.count("-"),
        "num_at": raw.count("@"),
        "num_question": raw.count("?"),
        "num_equals": raw.count("="),
        "num_ampersand": raw.count("&"),
        "num_underscore": raw.count("_"),
        "num_slash": raw.count("/"),
        "num_percent": raw.count("%"),
        "num_digits": url_digits,
        "digit_ratio": url_digits / len(raw) if raw else 0.0,
        "host_digit_ratio": host_digits / len(hostname) if hostname else 0.0,
        "num_subdomains": len([p for p in subdomain.split(".") if p]),
        "has_ip": 1 if is_ip_host(hostname) else 0,
        "is_https": 1 if scheme == "https" else 0,
        "has_port": 1 if port not in (None, 80, 443) else 0,
        "has_punycode": 1 if "xn--" in hostname else 0,
        "is_shortener": 1 if registrable in SHORTENER_DOMAINS or hostname in SHORTENER_DOMAINS else 0,
        "suspicious_tld": 1 if tld.split(".")[-1] in SUSPICIOUS_TLDS else 0,
        "num_suspicious_keywords": len(keywords),
        "brand_in_subdomain": 1 if brands_in_host else 0,
        "brand_in_path": 1 if brands_in_path else 0,
        "brand_mismatch": brand_mismatch,
        "host_entropy": shannon_entropy(hostname),
        "path_entropy": shannon_entropy(path),
        "longest_token_length": longest_token,
        "double_slash_in_path": 1 if "//" in path else 0,
        "tld_length": len(tld),
        "num_query_params": len(parse_qsl(query, keep_blank_values=True)),
        "has_hex_encoding": 1 if HEX_ENCODING_RE.search(raw) else 0,
        "host_hyphens": hostname.count("-"),
        "num_non_ascii": sum(1 for ch in raw if ord(ch) > 127),
        "has_www_in_subdomain": 1 if subdomain.startswith("www.") or subdomain == "www" else 0,
    }

    return URLFeatures(
        url=raw,
        scheme=scheme,
        hostname=hostname,
        subdomain=subdomain,
        registrable_domain=registrable,
        tld=tld,
        path=path,
        query=query,
        fragment=fragment,
        port=port,
        keywords=keywords,
        brands=sorted(set(brands_in_host + brands_in_path)),
        numeric=numeric,
    )


def features_to_vector(url: str) -> list[float]:
    """Convenience wrapper returning only the ordered numeric vector."""
    return extract_features(url).vector()


def build_feature_frame(urls):
    """Build a :class:`pandas.DataFrame` of features for an iterable of URLs."""
    import pandas as pd  # imported lazily - keeps web requests light

    rows = [extract_features(u).numeric for u in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES).fillna(0.0)
