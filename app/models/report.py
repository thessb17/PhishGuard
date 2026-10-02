"""Generated report artefacts (campaign + detection)."""

from __future__ import annotations

from app.extensions import db
from app.models.user import utcnow


class ReportType:
    CAMPAIGN = "CAMPAIGN"
    DETECTION_URL = "DETECTION_URL"
    DETECTION_EMAIL = "DETECTION_EMAIL"
    EXECUTIVE = "EXECUTIVE"

    ALL = (CAMPAIGN, DETECTION_URL, DETECTION_EMAIL, EXECUTIVE)
    LABELS = {
        CAMPAIGN: "Campaign report",
        DETECTION_URL: "URL detection report",
        DETECTION_EMAIL: "Email detection report",
        EXECUTIVE: "Executive summary",
    }


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(32), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.Text, nullable=False, default="")
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    subject_type = db.Column(db.String(32), nullable=True)   # campaign | url_analysis | email_analysis
    subject_id = db.Column(db.Integer, nullable=True)
    payload = db.Column(db.JSON, nullable=False, default=dict)
    generated_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    campaign = db.relationship("Campaign", back_populates="reports")
    generated_by = db.relationship("User", foreign_keys=[generated_by_id])

    @property
    def type_label(self) -> str:
        return ReportType.LABELS.get(self.report_type, self.report_type)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_type": self.report_type,
            "type_label": self.type_label,
            "title": self.title,
            "summary": self.summary,
            "campaign_id": self.campaign_id,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "generated_by": self.generated_by.username if self.generated_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "payload": self.payload or {},
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Report {self.id} {self.report_type}>"
