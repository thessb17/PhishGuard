"""Phishing *simulation* campaign models (awareness exercises only)."""

from __future__ import annotations

import secrets

from app.extensions import db
from app.models.user import utcnow


class CampaignStatus:
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"

    ALL = (DRAFT, ACTIVE, COMPLETED, ARCHIVED)
    BADGES = {
        DRAFT: "secondary",
        ACTIVE: "success",
        COMPLETED: "info",
        ARCHIVED: "dark",
    }


class Difficulty:
    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"

    ALL = (EASY, MEDIUM, HARD)


class Campaign(db.Model):
    __tablename__ = "campaigns"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False, default="")
    template_key = db.Column(db.String(64), nullable=False, index=True)
    difficulty = db.Column(db.String(16), nullable=False, default=Difficulty.MEDIUM)
    status = db.Column(db.String(16), nullable=False, default=CampaignStatus.DRAFT, index=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    organization = db.Column(db.String(120), nullable=False, default="Andhra University")

    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    created_by = db.relationship("User", back_populates="campaigns_created")
    targets = db.relationship(
        "CampaignTarget", back_populates="campaign", cascade="all, delete-orphan", lazy="dynamic"
    )
    events = db.relationship(
        "SimulationEvent", back_populates="campaign", cascade="all, delete-orphan", lazy="dynamic"
    )
    reports = db.relationship("Report", back_populates="campaign", lazy="dynamic")

    __table_args__ = (db.Index("ix_campaign_status_created", "status", "created_at"),)

    @property
    def status_badge(self) -> str:
        return CampaignStatus.BADGES.get(self.status, "secondary")

    @property
    def participant_count(self) -> int:
        return self.targets.count()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "template_key": self.template_key,
            "difficulty": self.difficulty,
            "status": self.status,
            "organization": self.organization,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "created_by": self.created_by.username if self.created_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "participants": self.participant_count,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Campaign {self.id} {self.name!r} {self.status}>"


class CampaignTarget(db.Model):
    """A demo participant enrolled in a simulation campaign.

    ``access_token`` identifies a *simulated* message.  It is a random,
    unguessable value used purely to attribute safe interaction events; it
    carries no authentication power and grants no privileges.
    """

    __tablename__ = "campaign_targets"

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    simulated_message_id = db.Column(db.String(32), nullable=False, unique=True, index=True)
    access_token = db.Column(db.String(64), nullable=False, unique=True, index=True)
    delivered_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    campaign = db.relationship("Campaign", back_populates="targets")
    user = db.relationship("User", back_populates="targets")

    __table_args__ = (
        db.UniqueConstraint("campaign_id", "user_id", name="uq_campaign_target"),
    )

    @staticmethod
    def new_message_id() -> str:
        return f"SIM-{secrets.token_hex(4).upper()}"

    @staticmethod
    def new_token() -> str:
        return secrets.token_urlsafe(24)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "user_id": self.user_id,
            "simulated_message_id": self.simulated_message_id,
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CampaignTarget {self.simulated_message_id}>"
