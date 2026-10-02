"""Report generation: JSON payloads, CSV export and PDF export.

Reports are snapshots: the payload is stored with the report row so that a
downloaded artefact always matches what the analyst saw when it was created.
"""

from __future__ import annotations

import csv
import io

from app.extensions import db
from app.models.campaign import Campaign
from app.models.email_analysis import EmailAnalysis
from app.models.report import Report, ReportType
from app.models.url_analysis import URLAnalysis
from app.models.user import User, utcnow
from app.services.campaign_service import campaign_stats
from app.services.risk_engine import RECOMMENDATIONS

GENERATOR = "PhishGuard - Phishing Attack Simulation and Detection Platform | Sabyasachi Bhowmik | Andhra University"
SAFETY_NOTE = (
    "Simulation data in this report was produced by controlled awareness "
    "exercises. No passwords, tokens, payment data or other sensitive "
    "information are collected, stored or reported by PhishGuard."
)


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def build_campaign_payload(campaign: Campaign) -> dict:
    stats = campaign_stats(campaign)
    return {
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "generator": GENERATOR,
        "report_type": ReportType.CAMPAIGN,
        "campaign": stats["campaign"],
        "template": {
            "key": (stats["template"] or {}).get("key"),
            "name": (stats["template"] or {}).get("name"),
            "category": (stats["template"] or {}).get("category"),
            "difficulty": (stats["template"] or {}).get("difficulty"),
        } if stats["template"] else {},
        "statistics": {
            "participants": stats["participants"],
            "messages_simulated": stats["messages_simulated"],
            "events_total": stats["events_total"],
            "open_rate": stats["open_rate"],
            "interaction_rate": stats["interaction_rate"],
            "report_rate": stats["report_rate"],
            "training_rate": stats["training_rate"],
            "awareness_score": stats["awareness_score"],
            "risk_level": stats["risk_level"],
        },
        "event_counts": stats["event_counts"],
        "unique_counts": stats["unique_counts"],
        "participants": [
            {
                "demo_user_ref": row["demo_user_ref"],
                "username": row["username"],
                "full_name": row["full_name"],
                "department": row["department"],
                "simulated_message_id": row["simulated_message_id"],
                "opened": row["opened"],
                "clicked": row["clicked"],
                "training_viewed": row["trained"],
                "reported": row["reported"],
                "awareness_score": row["awareness_score"],
            }
            for row in stats["participant_rows"]
        ],
        "timeline": stats["timeline"],
        "notes": [stats["metric_note"], SAFETY_NOTE],
    }


def build_url_detection_payload(analysis: URLAnalysis) -> dict:
    data = analysis.to_dict()
    return {
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "generator": GENERATOR,
        "report_type": ReportType.DETECTION_URL,
        "subject": {
            "url": data["url"],
            "hostname": data["hostname"],
            "scheme": data["scheme"],
            "analysed_at": data["created_at"],
            "analyst": data["analyst"],
            "source": data["source"],
        },
        "scores": {
            "heuristic_score": data["heuristic_score"],
            "ml_score": data["ml_score"],
            "ml_confidence": data["ml_confidence"],
            "ml_model": data["ml_model"],
            "final_score": data["final_score"],
            "classification": data["classification"],
        },
        "indicators": data["indicators"],
        "explanation": data["explanation"],
        "features": data["features"].get("numeric", {}),
        "recommendation": data["recommendation"] or RECOMMENDATIONS.get(data["classification"], ""),
        "notes": [
            "Heuristic analysis is string-based and offline; the URL is never fetched.",
            "ML output is a probability estimate and can be wrong in both directions.",
            SAFETY_NOTE,
        ],
    }


def build_email_detection_payload(analysis: EmailAnalysis) -> dict:
    data = analysis.to_dict()
    return {
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "generator": GENERATOR,
        "report_type": ReportType.DETECTION_EMAIL,
        "subject": {
            "sender": data["sender"],
            "reply_to": data["reply_to"],
            "subject": data["subject"],
            "urls": data["urls"],
            "analysed_at": data["created_at"],
            "analyst": data["analyst"],
        },
        "scores": {
            "heuristic_score": data["heuristic_score"],
            "ml_score": data["ml_score"],
            "ml_confidence": data["ml_confidence"],
            "final_score": data["final_score"],
            "classification": data["classification"],
        },
        "header_findings": data["header_findings"],
        "indicators": data["indicators"],
        "explanation": data["explanation"],
        "recommendation": data["recommendation"] or RECOMMENDATIONS.get(data["classification"], ""),
        "notes": [
            "Submitted content is redacted before storage; credential-like strings are masked.",
            SAFETY_NOTE,
        ],
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def create_campaign_report(campaign: Campaign, user: User | None = None) -> Report:
    payload = build_campaign_payload(campaign)
    stats = payload["statistics"]
    report = Report(
        report_type=ReportType.CAMPAIGN,
        title=f"Campaign report - {campaign.name}",
        summary=(
            f"{stats['participants']} participants, "
            f"{stats['interaction_rate']}% simulation interaction rate, "
            f"{stats['report_rate']}% report rate, "
            f"awareness score {stats['awareness_score']}/100 "
            f"(residual risk {stats['risk_level']})."
        ),
        campaign_id=campaign.id,
        subject_type="campaign",
        subject_id=campaign.id,
        payload=payload,
        generated_by_id=getattr(user, "id", None),
    )
    db.session.add(report)
    db.session.commit()
    return report


def create_detection_report(analysis, user: User | None = None) -> Report:
    if isinstance(analysis, URLAnalysis):
        payload = build_url_detection_payload(analysis)
        title = f"URL detection report - {analysis.hostname or analysis.url[:40]}"
        subject_type, report_type = "url_analysis", ReportType.DETECTION_URL
        summary = (
            f"{analysis.classification} ({analysis.final_score}/100) for "
            f"{analysis.url[:80]} - {len([i for i in (analysis.indicators or []) if i.get('points', 0) > 0])} "
            f"risk indicators."
        )
    elif isinstance(analysis, EmailAnalysis):
        payload = build_email_detection_payload(analysis)
        title = f"Email detection report - {(analysis.subject or 'no subject')[:50]}"
        subject_type, report_type = "email_analysis", ReportType.DETECTION_EMAIL
        summary = (
            f"{analysis.classification} ({analysis.final_score}/100) for message from "
            f"{analysis.sender or 'unknown sender'} - "
            f"{len([i for i in (analysis.indicators or []) if i.get('points', 0) > 0])} risk indicators."
        )
    else:  # pragma: no cover - guarded by the caller
        raise TypeError("analysis must be a URLAnalysis or EmailAnalysis instance")

    report = Report(
        report_type=report_type,
        title=title,
        summary=summary,
        subject_type=subject_type,
        subject_id=analysis.id,
        payload=payload,
        generated_by_id=getattr(user, "id", None),
    )
    db.session.add(report)
    db.session.commit()
    return report


# ---------------------------------------------------------------------------
# Exporters
# ---------------------------------------------------------------------------

def _write_kv(writer, title: str, mapping: dict) -> None:
    writer.writerow([])
    writer.writerow([title])
    for key, value in (mapping or {}).items():
        writer.writerow([str(key).replace("_", " ").title(), _flatten(value)])


def _flatten(value) -> str:
    if isinstance(value, (list, tuple)):
        return "; ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}={_flatten(v)}" for k, v in value.items())
    if value is None:
        return ""
    return str(value)


def report_to_csv(report: Report) -> str:
    """Render a report payload as a flat, spreadsheet-friendly CSV."""
    payload = report.payload or {}
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    writer.writerow(["PhishGuard report"])
    writer.writerow(["Title", report.title])
    writer.writerow(["Type", report.type_label])
    writer.writerow(["Generated at", payload.get("generated_at", "")])
    writer.writerow(["Generated by", report.generated_by.username if report.generated_by else "system"])
    writer.writerow(["Summary", report.summary])

    if report.report_type == ReportType.CAMPAIGN:
        _write_kv(writer, "CAMPAIGN", payload.get("campaign", {}))
        _write_kv(writer, "TEMPLATE", payload.get("template", {}))
        _write_kv(writer, "STATISTICS", payload.get("statistics", {}))
        _write_kv(writer, "EVENT COUNTS", payload.get("event_counts", {}))
        writer.writerow([])
        writer.writerow(["PARTICIPANTS"])
        writer.writerow([
            "Demo user ref", "Username", "Full name", "Department", "Simulated message id",
            "Opened", "Clicked", "Training viewed", "Reported", "Awareness score",
        ])
        for row in payload.get("participants", []):
            writer.writerow([
                row.get("demo_user_ref"), row.get("username"), row.get("full_name"),
                row.get("department"), row.get("simulated_message_id"),
                row.get("opened"), row.get("clicked"), row.get("training_viewed"),
                row.get("reported"), row.get("awareness_score"),
            ])
        writer.writerow([])
        writer.writerow(["TIMELINE"])
        writer.writerow(["Date", "Opened", "Link clicked", "Training viewed", "Reported", "Total"])
        for row in payload.get("timeline", []):
            writer.writerow([
                row.get("date"), row.get("OPENED", 0), row.get("LINK_CLICKED", 0),
                row.get("TRAINING_PAGE_VIEWED", 0), row.get("REPORTED", 0), row.get("total", 0),
            ])
    else:
        _write_kv(writer, "SUBJECT", payload.get("subject", {}))
        _write_kv(writer, "SCORES", payload.get("scores", {}))
        if payload.get("header_findings"):
            _write_kv(writer, "HEADER FINDINGS", payload["header_findings"])
        writer.writerow([])
        writer.writerow(["INDICATORS"])
        writer.writerow(["Code", "Title", "Category", "Severity", "Points", "Evidence", "Recommendation"])
        for indicator in payload.get("indicators", []):
            writer.writerow([
                indicator.get("code"), indicator.get("title"), indicator.get("category"),
                indicator.get("severity"), indicator.get("points"),
                indicator.get("evidence"), indicator.get("recommendation"),
            ])
        writer.writerow([])
        writer.writerow(["SCORE EXPLANATION"])
        writer.writerow(["Step", "Detail", "Value"])
        for step in payload.get("explanation", []):
            writer.writerow([step.get("step"), step.get("detail"), step.get("value")])
        writer.writerow([])
        writer.writerow(["RECOMMENDATION", payload.get("recommendation", "")])

    writer.writerow([])
    writer.writerow(["NOTES"])
    for note in payload.get("notes", []):
        writer.writerow([note])
    return buffer.getvalue()


def pdf_available() -> bool:
    try:
        import reportlab  # noqa: F401

        return True
    except ImportError:  # pragma: no cover - reportlab is a hard requirement
        return False


def report_to_pdf(report: Report) -> bytes:
    """Render the report as a styled PDF using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    payload = report.payload or {}
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, title=report.title, author="Sabyasachi Bhowmik - Andhra University",
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#0b1f3a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12.5, textColor=colors.HexColor("#144d8c"),
                        spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12.5, alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=7.8, textColor=colors.HexColor("#44506b"))

    def table(data, widths=None, header=True):
        tbl = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
        style = [
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6fc")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        if header:
            style += [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f3a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        tbl.setStyle(TableStyle(style))
        return tbl

    story = [
        Paragraph("PhishGuard", h1),
        Paragraph("Phishing Attack Simulation and Detection Platform", small),
        Paragraph("Developed by Sabyasachi Bhowmik · Andhra University", small),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#144d8c"), spaceBefore=6, spaceAfter=10),
        Paragraph(report.title, h2),
        Paragraph(report.summary or "", body),
        Spacer(1, 6),
        table([
            ["Report type", report.type_label],
            ["Report id", str(report.id)],
            ["Generated at", payload.get("generated_at", utcnow().isoformat(timespec="seconds"))],
            ["Generated by", report.generated_by.username if report.generated_by else "system"],
        ], widths=[38 * mm, 130 * mm], header=False),
    ]

    if report.report_type == ReportType.CAMPAIGN:
        campaign = payload.get("campaign", {})
        stats = payload.get("statistics", {})
        story += [Paragraph("Campaign details", h2),
                  table([[k.replace("_", " ").title(), _flatten(v)] for k, v in campaign.items()],
                        widths=[38 * mm, 130 * mm], header=False)]
        story += [Paragraph("Simulation statistics", h2),
                  table([["Metric", "Value"]] + [[k.replace("_", " ").title(), _flatten(v)] for k, v in stats.items()],
                        widths=[60 * mm, 108 * mm])]
        participants = payload.get("participants", [])
        if participants:
            rows = [["Demo ref", "Department", "Opened", "Clicked", "Trained", "Reported", "Awareness"]]
            for row in participants[:60]:
                rows.append([
                    row.get("demo_user_ref", ""), (row.get("department") or "")[:22],
                    "Y" if row.get("opened") else "-", "Y" if row.get("clicked") else "-",
                    "Y" if row.get("training_viewed") else "-", "Y" if row.get("reported") else "-",
                    str(row.get("awareness_score", "")),
                ])
            story += [Paragraph("Participant breakdown", h2),
                      table(rows, widths=[32 * mm, 38 * mm, 17 * mm, 17 * mm, 17 * mm, 19 * mm, 22 * mm])]
    else:
        subject = payload.get("subject", {})
        scores = payload.get("scores", {})
        story += [Paragraph("Analysed artefact", h2),
                  table([[k.replace("_", " ").title(), Paragraph(_flatten(v)[:400], body)] for k, v in subject.items()],
                        widths=[38 * mm, 130 * mm], header=False)]
        story += [Paragraph("Risk scoring", h2),
                  table([["Metric", "Value"]] + [[k.replace("_", " ").title(), _flatten(v)] for k, v in scores.items()],
                        widths=[60 * mm, 108 * mm])]
        if payload.get("header_findings"):
            story += [Paragraph("Email authentication", h2),
                      table([["Check", "Result"]] +
                            [[k.replace("_", " ").title(), _flatten(v)[:120]]
                             for k, v in payload["header_findings"].items()],
                            widths=[60 * mm, 108 * mm])]
        indicators = payload.get("indicators", [])
        if indicators:
            rows = [["Points", "Indicator", "Severity", "Evidence"]]
            for indicator in indicators[:40]:
                rows.append([
                    str(indicator.get("points", 0)),
                    Paragraph(str(indicator.get("title", ""))[:120], body),
                    str(indicator.get("severity", "")).upper(),
                    Paragraph(str(indicator.get("evidence", ""))[:220], body),
                ])
            story += [Paragraph("Detection indicators", h2),
                      table(rows, widths=[16 * mm, 52 * mm, 20 * mm, 80 * mm])]
        explanation = payload.get("explanation", [])
        if explanation:
            rows = [["Step", "How the score was produced", "Value"]]
            for step in explanation:
                rows.append([
                    str(step.get("step", "")),
                    Paragraph(str(step.get("detail", ""))[:260], body),
                    str(step.get("value", "")),
                ])
            story += [Paragraph("Score explanation", h2),
                      table(rows, widths=[34 * mm, 110 * mm, 24 * mm])]
        if payload.get("recommendation"):
            story += [Paragraph("Recommended action", h2), Paragraph(payload["recommendation"], body)]

    notes = payload.get("notes", [])
    if notes:
        story += [Spacer(1, 8), Paragraph("Notes and limitations", h2)]
        story += [Paragraph(f"- {note}", small) for note in notes]

    story += [
        Spacer(1, 10),
        HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#c9d4e6")),
        Paragraph(
            "Generated by PhishGuard · Sabyasachi Bhowmik · Andhra University. Heuristic and machine-learning findings are decision "
            "support, not proof. This document contains no credentials or sensitive data.",
            small,
        ),
    ]
    doc.build(story)
    return buffer.getvalue()


def report_filename(report: Report, extension: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (report.title or "report"))[:60]
    return f"phishguard-{report.id}-{safe.strip('-').lower()}.{extension}"
