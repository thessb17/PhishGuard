"""Explainable brand-impersonation detection.

A phishing domain usually imitates a brand in one of a small number of
mechanical ways. This module names the mechanism rather than emitting an
opaque similarity number, because an analyst needs to know *why* a domain was
flagged in order to overrule it.

Techniques detected
-------------------
``EXACT_LABEL_FOREIGN_DOMAIN``
    The brand's own name is the domain label, but the domain is not one the
    brand owns - ``paypal-security.example``.
``HOMOGLYPH``
    The label becomes the brand after undoing visually confusable
    substitutions - ``paypa1`` (one → l), ``arnazon`` (rn → m).
``TYPOSQUAT``
    The label is within a small edit distance of the brand - ``payppal``.
``BRAND_IN_SUBDOMAIN``
    The brand appears in a subdomain while the registrable domain belongs to
    someone else - ``paypal.com.account-verify.example``. This is the pattern
    that most reliably fools people, because the brand is the first thing
    they read.
``PUNYCODE_LOOKALIKE``
    The hostname is IDNA-encoded (``xn--``), which can render as a visually
    identical string.

Deliberate non-goals
--------------------
Similarity is **evidence, not proof**. ``flask.palletsprojects.com`` is not
impersonating anything, and a short brand label like ``ups`` will collide
with ordinary words. So:

* A domain the brand genuinely owns is never reported.
* A domain on the local allowlist is never reported.
* Labels shorter than ``MIN_LABEL_LENGTH`` are not edit-distance matched,
  because at three characters almost everything is within distance one.
* The edit-distance budget scales with label length rather than being a flat
  number, so ``ups`` cannot match ``ucs`` on the same terms as
  ``microsoft`` matching ``micr0soft``.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.domain_intel import DomainIntelProvider, get_provider

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

#: Below this length, edit-distance matching is too noisy to be useful.
MIN_LABEL_LENGTH = 5

#: Visually confusable substitutions used by typo-squatters. Applied to both
#: sides of the comparison so 'paypa1' and 'paypal' normalise identically.
HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "$": "s", "@": "a",
}

#: Multi-character sequences that imitate a single glyph.
DIGRAPH_MAP = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

SEVERITY_BY_TECHNIQUE = {
    "EXACT_LABEL_FOREIGN_DOMAIN": "HIGH",
    "BRAND_IN_SUBDOMAIN": "HIGH",
    "HOMOGLYPH": "HIGH",
    "PUNYCODE_LOOKALIKE": "MEDIUM",
    "TYPOSQUAT": "MEDIUM",
}

POINTS_BY_TECHNIQUE = {
    "EXACT_LABEL_FOREIGN_DOMAIN": 24.0,
    "BRAND_IN_SUBDOMAIN": 26.0,
    "HOMOGLYPH": 28.0,
    "PUNYCODE_LOOKALIKE": 18.0,
    "TYPOSQUAT": 20.0,
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BrandMatch:
    """One brand-impersonation finding."""

    brand_detected: str
    matched_domain: str
    similarity_score: float          # 0.0-1.0
    technique: str
    severity: str
    points: float
    evidence: str
    explanation: str
    observed_label: str = ""
    edit_distance: int | None = None

    def to_dict(self) -> dict:
        return {
            "brand_detected": self.brand_detected,
            "matched_domain": self.matched_domain,
            "similarity_score": round(self.similarity_score, 4),
            "technique": self.technique,
            "severity": self.severity,
            "points": self.points,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "observed_label": self.observed_label,
            "edit_distance": self.edit_distance,
        }


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------


def levenshtein(a: str, b: str) -> int:
    """Edit distance. Hostname labels only - inputs are short by construction."""
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
            current.append(min(previous[j] + 1,
                               current[j - 1] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def normalise_homoglyphs(text: str) -> str:
    """Undo common visual substitutions so look-alikes collapse onto the brand."""
    out = (text or "").lower()
    for src, dst in HOMOGLYPH_MAP.items():
        out = out.replace(src, dst)
    for src, dst in DIGRAPH_MAP:
        out = out.replace(src, dst)
    return out


def strip_separators(text: str) -> str:
    """``pay-pal`` and ``pay_pal`` are the same attack as ``paypal``."""
    return "".join(ch for ch in (text or "").lower() if ch.isalnum())


def allowed_distance(label: str) -> int:
    """Edit budget scaled to label length.

    A flat threshold of 2 means a 5-character brand matches almost anything.
    Scaling keeps short labels strict and still catches realistic typos in
    longer ones.
    """
    n = len(label)
    if n <= 6:
        return 1
    if n <= 10:
        return 2
    return 3


def similarity(a: str, b: str) -> float:
    """1.0 for identical strings, decreasing with edit distance."""
    if not a and not b:
        return 1.0
    longest = max(len(a), len(b)) or 1
    return max(0.0, 1.0 - (levenshtein(a, b) / longest))


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _domain_label(registrable_domain: str) -> str:
    """``paypa1.example`` -> ``paypa1``.

    The whole point: comparing the full domain lets the TLD dominate the edit
    distance. ``paypa1.example`` vs ``paypal.com`` is 6 edits, of which 5 are
    just ``.example`` vs ``.com`` - so a real typosquat scores as unrelated.
    Comparing labels gives 1.
    """
    return (registrable_domain or "").split(".")[0].lower()


def detect_brand_impersonation(
    hostname: str,
    registrable_domain: str,
    *,
    provider: DomainIntelProvider | None = None,
) -> BrandMatch | None:
    """Return the strongest brand-impersonation finding, or ``None``.

    ``hostname`` is the full host (``paypal.com.login.evil.example``);
    ``registrable_domain`` is the part the attacker had to register
    (``evil.example``). The distinction is what makes subdomain abuse
    detectable.
    """
    provider = provider or get_provider()
    host = (hostname or "").lower().strip(".")
    domain = (registrable_domain or "").lower().strip(".")
    if not host or not domain:
        return None

    # Never accuse a domain the operator has vouched for.
    if provider.lookup(domain).verdict == "KNOWN_SAFE":
        return None

    label = _domain_label(domain)
    label_flat = strip_separators(label)
    label_norm = normalise_homoglyphs(label_flat)

    # Subdomain labels, excluding the registrable domain's own parts.
    domain_parts = set(domain.split("."))
    sub_labels = [p for p in host.split(".") if p and p not in domain_parts]
    sub_flat = strip_separators("".join(sub_labels))

    candidates: list[BrandMatch] = []

    for brand in provider.brands():
        b = brand.label
        b_norm = normalise_homoglyphs(b)

        # A domain the brand genuinely owns is not impersonation.
        if brand.owns(domain):
            continue

        # --- 1. exact brand label on a foreign domain ---------------------
        if b in label_flat:
            candidates.append(BrandMatch(
                brand_detected=b,
                matched_domain=brand.domains[0],
                similarity_score=1.0,
                technique="EXACT_LABEL_FOREIGN_DOMAIN",
                severity=SEVERITY_BY_TECHNIQUE["EXACT_LABEL_FOREIGN_DOMAIN"],
                points=POINTS_BY_TECHNIQUE["EXACT_LABEL_FOREIGN_DOMAIN"],
                evidence=f"domain '{domain}' contains the brand name '{b}'",
                explanation=(
                    f"The registrable domain carries the '{b}' brand name but is not "
                    f"operated by that brand (their domain is '{brand.domains[0]}'). "
                    f"Anyone can register a domain containing a brand name."
                ),
                observed_label=label,
                edit_distance=0,
            ))
            continue

        # --- 2. brand in a subdomain, foreign registrable domain ----------
        if b in sub_flat:
            candidates.append(BrandMatch(
                brand_detected=b,
                matched_domain=brand.domains[0],
                similarity_score=1.0,
                technique="BRAND_IN_SUBDOMAIN",
                severity=SEVERITY_BY_TECHNIQUE["BRAND_IN_SUBDOMAIN"],
                points=POINTS_BY_TECHNIQUE["BRAND_IN_SUBDOMAIN"],
                evidence=f"'{b}' appears left of the real domain '{domain}'",
                explanation=(
                    f"The brand name appears in the subdomain while the domain actually "
                    f"registered is '{domain}'. Browsers show the full host, so readers "
                    f"see '{b}' first and often stop reading there. Only the rightmost "
                    f"labels identify the owner."
                ),
                observed_label=".".join(sub_labels),
                edit_distance=0,
            ))
            continue

        if len(b) < MIN_LABEL_LENGTH or len(label_flat) < MIN_LABEL_LENGTH:
            continue

        # --- 3. homoglyph: identical once visual tricks are undone --------
        if label_norm == b_norm and label_flat != b:
            candidates.append(BrandMatch(
                brand_detected=b,
                matched_domain=brand.domains[0],
                similarity_score=1.0,
                technique="HOMOGLYPH",
                severity=SEVERITY_BY_TECHNIQUE["HOMOGLYPH"],
                points=POINTS_BY_TECHNIQUE["HOMOGLYPH"],
                evidence=f"'{label}' normalises to '{b_norm}'",
                explanation=(
                    f"'{label}' is '{b}' with visually confusable characters substituted "
                    f"(for example 0/o, 1/l, rn/m). At a glance it is indistinguishable "
                    f"from the real brand."
                ),
                observed_label=label,
                edit_distance=0,
            ))
            continue

        # --- 4. typosquat within a length-scaled edit budget --------------
        distance = min(levenshtein(label_flat, b), levenshtein(label_norm, b_norm))
        if 0 < distance <= allowed_distance(b):
            candidates.append(BrandMatch(
                brand_detected=b,
                matched_domain=brand.domains[0],
                similarity_score=similarity(label_flat, b),
                technique="TYPOSQUAT",
                severity=SEVERITY_BY_TECHNIQUE["TYPOSQUAT"],
                points=POINTS_BY_TECHNIQUE["TYPOSQUAT"],
                evidence=f"'{label}' is {distance} edit(s) from '{b}'",
                explanation=(
                    f"The domain label differs from '{b}' by {distance} character(s). "
                    f"Registering near-misses of a brand is a standard phishing tactic. "
                    f"Similarity alone is not proof - verify the real domain is "
                    f"'{brand.domains[0]}'."
                ),
                observed_label=label,
                edit_distance=distance,
            ))

    # --- 5. punycode, independent of any particular brand -----------------
    if host.startswith("xn--") or ".xn--" in host:
        candidates.append(BrandMatch(
            brand_detected="(unspecified)",
            matched_domain="",
            similarity_score=0.0,
            technique="PUNYCODE_LOOKALIKE",
            severity=SEVERITY_BY_TECHNIQUE["PUNYCODE_LOOKALIKE"],
            points=POINTS_BY_TECHNIQUE["PUNYCODE_LOOKALIKE"],
            evidence=f"hostname '{host}' is IDNA/punycode encoded",
            explanation=(
                "The hostname uses punycode (xn--), which lets non-Latin characters "
                "render as something visually identical to a Latin brand name. "
                "Legitimate internationalised domains exist, so this is a reason to "
                "look closely rather than a verdict."
            ),
            observed_label=host,
        ))

    if not candidates:
        return None

    # Strongest finding wins: points first, then similarity.
    return sorted(candidates, key=lambda m: (m.points, m.similarity_score), reverse=True)[0]


def detect_all(hostname: str, registrable_domain: str,
               *, provider: DomainIntelProvider | None = None) -> list[BrandMatch]:
    """All findings, strongest first - used by the detection trace view."""
    provider = provider or get_provider()
    best = detect_brand_impersonation(hostname, registrable_domain, provider=provider)
    return [best] if best else []
