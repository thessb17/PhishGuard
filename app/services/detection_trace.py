"""Detection decision trace — show the analyst *how* a verdict was reached.

A risk score on its own is an assertion. An analyst who cannot see the
reasoning has two options: believe it or ignore it, and both are bad. This
module reconstructs the pipeline as an ordered list of stages

    INPUT → FEATURE EXTRACTION → RULE ENGINE → ML MODEL → RISK FUSION → VERDICT

each carrying the data it actually produced, so the chain from raw input to
final classification can be inspected end to end.

It is a **presentation layer over data the analysers already return** — it
re-derives nothing and re-scores nothing. If the trace and the verdict could
disagree, the trace would be worthless.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TraceStage:
    """One step of the detection pipeline."""

    key: str
    title: str
    summary: str
    #: Ordered label/value rows rendered in the expandable panel.
    rows: list[tuple[str, str]] = field(default_factory=list)
    #: Indicator dicts, when the stage produced any.
    indicators: list[dict] = field(default_factory=list)
    #: Short note on what this stage can and cannot establish.
    caveat: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "summary": self.summary,
            "rows": [{"label": k, "value": v} for k, v in self.rows],
            "indicators": self.indicators,
            "caveat": self.caveat,
        }


def _fmt(value, digits: int = 2) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def build_url_trace(rule_result: dict, ml_result: dict, risk) -> list[dict]:
    """Assemble the trace for a URL analysis.

    ``rule_result`` comes from ``URLAnalyzer.analyze``, ``ml_result`` from
    ``MLDetector.predict``, ``risk`` is the ``RiskAssessment`` from the risk
    engine. All three are passed in rather than recomputed.
    """
    features = rule_result.get("features", {}) or {}
    indicators = rule_result.get("indicators", []) or []
    negative = [i for i in indicators if not i.get("positive")]
    positive = [i for i in indicators if i.get("positive")]
    ml_available = bool(ml_result.get("available"))

    stages: list[TraceStage] = []

    # -- 1. input -----------------------------------------------------------
    stages.append(TraceStage(
        key="input",
        title="Input",
        summary="The URL exactly as submitted — parsed, never fetched.",
        rows=[
            ("Submitted URL", rule_result.get("url", "")),
            ("Scheme", rule_result.get("scheme", "") or "—"),
            ("Hostname", rule_result.get("hostname", "") or "—"),
            ("Registrable domain", rule_result.get("registrable_domain", "") or "—"),
            ("TLD", rule_result.get("tld", "") or "—"),
        ],
        caveat=("PhishGuard never issues a network request to a submitted URL. "
                "No DNS lookup, no page fetch, no redirect following — so the "
                "analysis cannot be used to reach an internal host, and cannot "
                "see content."),
    ))

    # -- 2. feature extraction ---------------------------------------------
    notable = [
        ("URL length", features.get("url_length")),
        ("Hostname length", features.get("hostname_length")),
        ("Path length", features.get("path_length")),
        ("Subdomain depth", features.get("num_subdomains")),
        ("Digits in hostname (ratio)", features.get("host_digit_ratio")),
        ("Hostname entropy", features.get("host_entropy")),
        ("Raw IP host", features.get("has_ip")),
        ("HTTPS", features.get("is_https")),
        ("Punycode", features.get("has_punycode")),
        ("Suspicious TLD", features.get("suspicious_tld")),
        ("Suspicious keywords", features.get("num_suspicious_keywords")),
        ("Percent-encoding present", features.get("has_hex_encoding")),
    ]
    stages.append(TraceStage(
        key="features",
        title="Feature extraction",
        summary=f"{len(features)} lexical, structural and semantic features computed from the string.",
        rows=[(label, _fmt(value)) for label, value in notable if value is not None],
        caveat=("Features are descriptive, not incriminating. A long URL with "
                "many subdomains is unusual, not malicious — it is the "
                "combination that matters."),
    ))

    # -- 3. rule engine -----------------------------------------------------
    rule_rows = [
        ("Indicators fired", str(len(negative))),
        ("Reassuring observations", str(len(positive))),
        ("Raw rule total", _fmt(rule_result.get("raw_score"))),
        ("Heuristic score (clamped 0–100)", _fmt(rule_result.get("heuristic_score"))),
    ]
    intel = rule_result.get("domain_intel")
    if intel:
        rule_rows.append(("Local domain intelligence",
                          f"{intel.get('verdict')} — {'; '.join(intel.get('reasons', []))}"))
    brand = rule_result.get("brand_match")
    if brand:
        rule_rows.append(("Brand impersonation",
                          f"{brand.get('technique')} → {brand.get('brand_detected')} "
                          f"(similarity {brand.get('similarity_score')})"))
    stages.append(TraceStage(
        key="rules",
        title="Rule engine",
        summary=(f"{len(negative)} indicator(s) contributed "
                 f"{_fmt(rule_result.get('raw_score'))} points before clamping."),
        rows=rule_rows,
        indicators=indicators,
        caveat=("Every weight is a human judgement recorded in RULE_WEIGHTS and "
                "app/config.py, not a learned value. Thresholds are tunable "
                "without touching code."),
    ))

    # -- 4. ML model --------------------------------------------------------
    if ml_available:
        ml_rows = [
            ("Model", ml_result.get("model", "—")),
            ("Model version", ml_result.get("model_version", "—")),
            ("Feature version", ml_result.get("feature_version", "—")),
            ("Trained at", ml_result.get("trained_at", "—")),
            ("P(phishing)", _fmt(ml_result.get("probability_phishing"), 4)),
            ("ML risk score", _fmt(ml_result.get("risk_score"))),
            ("Confidence", _fmt(ml_result.get("confidence"), 4)),
        ]
        top = (ml_result.get("explanation") or [])[:6]
        ml_summary = f"{ml_result.get('model', 'model')} scored this {_fmt(ml_result.get('risk_score'))}/100."
    else:
        ml_rows = [("Status", "unavailable — scoring fell back to rules only")]
        top = []
        ml_summary = "No model available; the final score is the heuristic score."
    stages.append(TraceStage(
        key="ml",
        title="ML model",
        summary=ml_summary,
        rows=ml_rows,
        indicators=[{"code": "ML_FEATURE", "title": str(e), "category": "ml",
                     "points": 0, "evidence": "", "severity": "INFO", "positive": False}
                    for e in top],
        caveat=("A probability is not a verdict. This is a demonstration model "
                "trained on a public research corpus; it misses roughly one "
                "phishing URL in four on its own held-out split."),
    ))

    # -- 5. risk fusion -----------------------------------------------------
    rd = risk.to_dict() if hasattr(risk, "to_dict") else dict(risk)
    stages.append(TraceStage(
        key="fusion",
        title="Risk fusion",
        summary=rd.get("formula", "Weighted combination of the rule and ML scores."),
        rows=[
            ("Heuristic score", _fmt(rd.get("heuristic_score"))),
            ("Heuristic weight", _fmt(rd.get("heuristic_weight"))),
            ("ML score", _fmt(rd.get("ml_score"))),
            ("ML weight", _fmt(rd.get("ml_weight"))),
            ("Formula", rd.get("formula", "—")),
            ("Final score", _fmt(rd.get("final_score"))),
        ],
        caveat=("Deterministic: the same input always produces the same score. "
                "Weights come from HEURISTIC_WEIGHT / ML_WEIGHT in config."),
    ))

    # -- 6. verdict ---------------------------------------------------------
    stages.append(TraceStage(
        key="verdict",
        title="Final classification",
        summary=f"{_fmt(rd.get('final_score'))}/100 → {rd.get('classification', '—')}",
        rows=[
            ("Final score", _fmt(rd.get("final_score"))),
            ("Risk band", rd.get("classification", "—")),
            ("Band boundaries", rd.get("band_description", "—")),
            ("Recommendation", rd.get("recommendation", "—")),
        ],
        caveat=("Bands are configurable (RISK_BANDS). The score is decision "
                "support for a human analyst, not an automated block/allow "
                "verdict."),
    ))

    return [s.to_dict() for s in stages]


def build_email_trace(rule_result: dict, ml_result: dict, risk) -> list[dict]:
    """Assemble the trace for an email analysis.

    Mirrors the URL trace but groups indicators by the analysis layer that
    produced them, which is how an analyst reads a suspicious message.
    """
    indicators = rule_result.get("indicators", []) or []
    by_category: dict[str, list[dict]] = {}
    for ind in indicators:
        by_category.setdefault(ind.get("category", "other"), []).append(ind)

    order = ["header", "sender", "subject", "body", "link", "reputation", "structure"]
    label = {
        "header": "Header analysis", "sender": "Sender analysis",
        "subject": "Subject analysis", "body": "Body analysis",
        "link": "Link analysis", "reputation": "Reputation",
        "structure": "Structure",
    }

    stages: list[TraceStage] = [TraceStage(
        key="input",
        title="Input",
        summary="Submitted message — parsed as text. Links are never opened.",
        rows=[
            ("From", rule_result.get("sender", "") or "—"),
            ("Subject", rule_result.get("subject", "") or "—"),
            ("Links found", str(len(rule_result.get("urls", []) or []))),
        ],
        caveat=("Credential-like strings are redacted before the message is "
                "stored. Attachments, when present, are examined by metadata "
                "only and never opened."),
    )]

    for cat in order + [c for c in by_category if c not in order]:
        items = by_category.get(cat)
        if not items:
            continue
        total = sum(i.get("points", 0) for i in items if not i.get("positive"))
        stages.append(TraceStage(
            key=f"layer_{cat}",
            title=label.get(cat, cat.title()),
            summary=f"{len(items)} finding(s), {total:+.1f} points.",
            indicators=items,
        ))

    worst = rule_result.get("worst_url")
    if worst:
        stages.append(TraceStage(
            key="worst_link",
            title="Highest-risk link",
            summary=f"{worst.get('url', '')} → {_fmt(worst.get('heuristic_score'))}/100",
            rows=[("URL", worst.get("url", "")),
                  ("Host", worst.get("hostname", "")),
                  ("Score", _fmt(worst.get("heuristic_score")))],
            caveat="Each link is scored by the same URL engine, lexically only.",
        ))

    rd = risk.to_dict() if hasattr(risk, "to_dict") else dict(risk)
    stages.append(TraceStage(
        key="fusion", title="Risk fusion",
        summary=rd.get("formula", ""),
        rows=[("Heuristic score", _fmt(rd.get("heuristic_score"))),
              ("ML score", _fmt(rd.get("ml_score"))),
              ("Final score", _fmt(rd.get("final_score")))],
    ))
    stages.append(TraceStage(
        key="verdict", title="Final classification",
        summary=f"{_fmt(rd.get('final_score'))}/100 → {rd.get('classification', '—')}",
        rows=[("Risk band", rd.get("classification", "—")),
              ("Recommendation", rd.get("recommendation", "—"))],
    ))
    return [s.to_dict() for s in stages]
