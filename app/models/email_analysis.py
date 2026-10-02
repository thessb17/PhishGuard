"""Persisted results of email phishing analysis."""

from __future__ import annotations

from app.extensions import db
from app.models.user import utcnow


class EmailAnalysis(db.Model):
    __tablename__ = "email_analyses"

    id = db.Column(db.Integer, primary_key=True)
    analyst_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    sender = db.Column(db.String(320), nullable=False, default="")
    reply_to = db.Column(db.String(320), nullable=False, default="")
    subject = db.Column(db.String(512), nullable=False, default="")
    #: Redacted + truncated copy of the analysed body (secrets are masked by
    #: :func:`app.utils.redaction.redact_sensitive` before it reaches the DB).
    body_excerpt = db.Column(db.Text, nullable=False, default="")
    body_length = db.Column(db.Integer, nullable=False, default=0)
    urls = db.Column(db.JSON, nullable=False, default=list)

    heuristic_score = db.Column(db.Float, nullable=False, default=0.0)
    ml_score = db.Column(db.Float, nullable=True)
    ml_confidence = db.Column(db.Float, nullable=True)
    final_score = db.Column(db.Float, nullable=False, default=0.0)
    classification = db.Column(db.String(16), nullable=False, default="LOW", index=True)
    indicators = db.Column(db.JSON, nullable=False, default=list)
    explanation = db.Column(db.JSON, nullable=False, default=list)
    recommendation = db.Column(db.Text, nullable=False, default="")
    header_findings = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    analyst = db.relationship("User", back_populates="email_analyses")

    __table_args__ = (db.Index("ix_email_class_created", "classification", "created_at"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": "email",
            "sender": self.sender,
            "reply_to": self.reply_to,
            "subject": self.subject,
            "urls": self.urls or [],
            "heuristic_score": round(self.heuristic_score, 2),
            "ml_score": round(self.ml_score, 2) if self.ml_score is not None else None,
            "ml_confidence": round(self.ml_confidence, 4) if self.ml_confidence is not None else None,
            "final_score": round(self.final_score, 2),
            "classification": self.classification,
            "indicators": self.indicators or [],
            "explanation": self.explanation or [],
            "header_findings": self.header_findings or {},
            "recommendation": self.recommendation,
            "analyst": self.analyst.username if self.analyst else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<EmailAnalysis {self.id} {self.classification}>"
