"""Safe simulation interaction events.

SAFETY INVARIANT
----------------
Only non-sensitive interaction metadata is persisted: campaign id, demo user
reference, event type, simulated message id and a timestamp.  Passwords,
tokens, payment data and submitted form values are never accepted, never
transmitted and never stored by the simulation subsystem.
"""

from __future__ import annotations

from app.extensions import db
from app.models.user import utcnow


class EventType:
    OPENED = "OPENED"
    LINK_CLICKED = "LINK_CLICKED"
    TRAINING_PAGE_VIEWED = "TRAINING_PAGE_VIEWED"
    REPORTED = "REPORTED"

    ALL = (OPENED, LINK_CLICKED, TRAINING_PAGE_VIEWED, REPORTED)
    LABELS = {
        OPENED: "Message opened",
        LINK_CLICKED: "Simulation link clicked",
        TRAINING_PAGE_VIEWED: "Awareness training viewed",
        REPORTED: "Reported as phishing",
    }
    BADGES = {
        OPENED: "info",
        LINK_CLICKED: "danger",
        TRAINING_PAGE_VIEWED: "warning",
        REPORTED: "success",
    }
    #: Contribution of each event type to the per-user awareness score.
    AWARENESS_WEIGHT = {
        OPENED: -5,
        LINK_CLICKED: -25,
        TRAINING_PAGE_VIEWED: +10,
        REPORTED: +30,
    }


class SimulationEvent(db.Model):
    __tablename__ = "simulation_events"

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    demo_user_ref = db.Column(db.String(64), nullable=False, default="anonymous", index=True)
    simulated_message_id = db.Column(db.String(32), nullable=False, index=True)
    event_type = db.Column(db.String(32), nullable=False, index=True)
    occurred_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    #: Free-text, non-sensitive context (e.g. "clicked from awareness inbox").
    note = db.Column(db.String(255), nullable=False, default="")

    campaign = db.relationship("Campaign", back_populates="events")
    user = db.relationship("User", back_populates="simulation_events")

    __table_args__ = (
        db.Index("ix_event_campaign_type", "campaign_id", "event_type"),
        db.Index("ix_event_user_time", "user_id", "occurred_at"),
    )

    @property
    def label(self) -> str:
        return EventType.LABELS.get(self.event_type, self.event_type)

    @property
    def badge(self) -> str:
        return EventType.BADGES.get(self.event_type, "secondary")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "demo_user_ref": self.demo_user_ref,
            "simulated_message_id": self.simulated_message_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "note": self.note,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SimulationEvent {self.event_type} {self.simulated_message_id}>"
