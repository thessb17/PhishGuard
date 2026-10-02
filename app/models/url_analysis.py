"""Persisted results of URL phishing analysis."""

from __future__ import annotations

from app.extensions import db
from app.models.user import utcnow


class URLAnalysis(db.Model):
    __tablename__ = "url_analyses"

    id = db.Column(db.Integer, primary_key=True)
    analyst_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    url = db.Column(db.String(2048), nullable=False)
    normalized_url = db.Column(db.String(2048), nullable=False, default="")
    hostname = db.Column(db.String(255), nullable=False, default="", index=True)
    scheme = db.Column(db.String(16), nullable=False, default="")

    heuristic_score = db.Column(db.Float, nullable=False, default=0.0)
    ml_score = db.Column(db.Float, nullable=True)
    ml_confidence = db.Column(db.Float, nullable=True)
    ml_model = db.Column(db.String(64), nullable=True)
    final_score = db.Column(db.Float, nullable=False, default=0.0)
    classification = db.Column(db.String(16), nullable=False, default="LOW", index=True)

    indicators = db.Column(db.JSON, nullable=False, default=list)
    features = db.Column(db.JSON, nullable=False, default=dict)
    explanation = db.Column(db.JSON, nullable=False, default=list)
    recommendation = db.Column(db.Text, nullable=False, default="")
    source = db.Column(db.String(32), nullable=False, default="web")  # web | api | email
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    analyst = db.relationship("User", back_populates="url_analyses")

    __table_args__ = (db.Index("ix_url_class_created", "classification", "created_at"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": "url",
            "url": self.url,
            "hostname": self.hostname,
            "scheme": self.scheme,
            "heuristic_score": round(self.heuristic_score, 2),
            "ml_score": round(self.ml_score, 2) if self.ml_score is not None else None,
            "ml_confidence": round(self.ml_confidence, 4) if self.ml_confidence is not None else None,
            "ml_model": self.ml_model,
            "final_score": round(self.final_score, 2),
            "classification": self.classification,
            "indicators": self.indicators or [],
            "features": self.features or {},
            "explanation": self.explanation or [],
            "recommendation": self.recommendation,
            "source": self.source,
            "analyst": self.analyst.username if self.analyst else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<URLAnalysis {self.id} {self.classification}>"
