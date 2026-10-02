"""Jinja filters and small presentation helpers."""

from __future__ import annotations

from datetime import datetime

RISK_COLORS = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

SEVERITY_HEX = {
    "critical": "#ff4d4f",
    "high": "#ff7a45",
    "medium": "#f0b429",
    "low": "#2ecc71",
    "info": "#4dabf7",
}

SEVERITY_COLORS = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def risk_class(classification: str | None) -> str:
    return RISK_COLORS.get((classification or "").upper(), "low")


def severity_class(severity: str | None) -> str:
    return SEVERITY_COLORS.get((severity or "").lower(), "info")


def severity_color(severity: str | None) -> str:
    return SEVERITY_HEX.get((severity or "").lower(), "#4dabf7")


def fmt_datetime(value: datetime | None, fmt: str = "%d %b %Y, %H:%M") -> str:
    if not value:
        return "-"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(fmt)


def fmt_date(value, fmt: str = "%d %b %Y") -> str:
    if not value:
        return "-"
    return value.strftime(fmt)


def percent(value: float | int | None, digits: int = 1) -> str:
    if value is None:
        return "-"
    return f"{float(value):.{digits}f}%"


def score_bar_width(score: float | int | None) -> int:
    try:
        return max(0, min(100, int(round(float(score)))))
    except (TypeError, ValueError):
        return 0


def register_filters(app):
    app.jinja_env.filters["risk_class"] = risk_class
    app.jinja_env.filters["severity_class"] = severity_class
    app.jinja_env.filters["severity_color"] = severity_color
    app.jinja_env.filters["fmt_datetime"] = fmt_datetime
    app.jinja_env.filters["fmt_date"] = fmt_date
    app.jinja_env.filters["percent"] = percent
    app.jinja_env.filters["score_width"] = score_bar_width
