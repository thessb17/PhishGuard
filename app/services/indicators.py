"""Shared indicator primitives used by every analyser.

An *indicator* is a single, human-readable observation with a numeric
contribution to the heuristic score.  Storing indicators (rather than only a
score) is what makes PhishGuard explainable: every point of the final score
can be traced back to a named rule and the evidence that triggered it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

    @classmethod
    def from_points(cls, points: float) -> str:
        if points >= 22:
            return cls.CRITICAL
        if points >= 15:
            return cls.HIGH
        if points >= 8:
            return cls.MEDIUM
        if points > 0:
            return cls.LOW
        return cls.INFO


@dataclass
class Indicator:
    """A single explainable detection signal."""

    code: str
    title: str
    category: str            # sender | subject | body | link | header | structure | reputation
    points: float            # contribution to the heuristic score (0 = informational)
    evidence: str = ""
    recommendation: str = ""
    severity: str = ""
    positive: bool = False   # True => reassuring observation, not a risk signal

    def __post_init__(self) -> None:
        if not self.severity:
            self.severity = Severity.INFO if self.positive else Severity.from_points(self.points)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["points"] = round(float(self.points), 2)
        return data


@dataclass
class AnalysisOutcome:
    """Container returned by the rule-based analysers."""

    indicators: list[Indicator] = field(default_factory=list)
    raw_score: float = 0.0
    score: float = 0.0
    details: dict = field(default_factory=dict)
    #: Optional enrichment attached by the URL analyzer. Kept as plain
    #: attributes (not required constructor args) so every existing caller
    #: that builds an AnalysisOutcome() keeps working unchanged.
    brand_match: object | None = None
    domain_intel: object | None = None

    def add(self, indicator: Indicator) -> None:
        self.indicators.append(indicator)

    def has(self, code: str) -> bool:
        """True if an indicator with ``code`` has already fired."""
        return any(i.code == code for i in self.indicators)

    def finalise(self, cap: float = 100.0) -> "AnalysisOutcome":
        self.raw_score = round(sum(i.points for i in self.indicators if not i.positive), 2)
        self.score = round(min(cap, max(0.0, self.raw_score)), 2)
        return self

    def sorted_indicators(self) -> list[Indicator]:
        return sorted(
            self.indicators,
            key=lambda i: (i.positive, -i.points, Severity.ORDER.get(i.severity, 0) * -1),
        )

    def to_dicts(self) -> list[dict]:
        return [i.to_dict() for i in self.sorted_indicators()]
