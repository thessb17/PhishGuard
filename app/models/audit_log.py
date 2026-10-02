"""Tamper-evident-ish application audit trail.

Only security-relevant *metadata* is recorded.  Passwords, session tokens,
API keys and submitted analysis payloads are never written to this table.
"""

from __future__ import annotations

from app.extensions import db
from app.models.user import utcnow


class AuditAction:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGIN_BLOCKED = "LOGIN_BLOCKED"
    LOGOUT = "LOGOUT"
    REGISTER = "REGISTER"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    CAMPAIGN_CREATED = "CAMPAIGN_CREATED"
    CAMPAIGN_UPDATED = "CAMPAIGN_UPDATED"
    #: Backwards-compatible alias for rows written before the rename.
    CAMPAIGN_MODIFIED = "CAMPAIGN_UPDATED"
    CAMPAIGN_DELETED = "CAMPAIGN_DELETED"
    ANALYSIS_PERFORMED = "ANALYSIS_PERFORMED"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
    ROLE_CHANGED = "ROLE_CHANGED"
    USER_STATUS_CHANGED = "USER_STATUS_CHANGED"
    SIMULATION_EVENT = "SIMULATION_EVENT"
    QUIZ_SUBMITTED = "QUIZ_SUBMITTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    API_KEY_ROTATED = "API_KEY_ROTATED"

    CATEGORIES = {
        LOGIN_SUCCESS: "authentication",
        LOGIN_FAILURE: "authentication",
        LOGIN_BLOCKED: "authentication",
        LOGOUT: "authentication",
        REGISTER: "authentication",
        PASSWORD_CHANGED: "authentication",
        CAMPAIGN_CREATED: "campaign",
        CAMPAIGN_UPDATED: "campaign",
        CAMPAIGN_DELETED: "campaign",
        ANALYSIS_PERFORMED: "detection",
        REPORT_GENERATED: "reporting",
        REPORT_DOWNLOADED: "reporting",
        ROLE_CHANGED: "administration",
        USER_STATUS_CHANGED: "administration",
        SIMULATION_EVENT: "simulation",
        QUIZ_SUBMITTED: "awareness",
        ACCESS_DENIED: "authorization",
        RATE_LIMITED: "authorization",
        API_KEY_ROTATED: "administration",
    }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_username = db.Column(db.String(64), nullable=False, default="anonymous", index=True)
    actor_role = db.Column(db.String(32), nullable=False, default="anonymous")
    action = db.Column(db.String(64), nullable=False, index=True)
    category = db.Column(db.String(32), nullable=False, default="general", index=True)
    status = db.Column(db.String(16), nullable=False, default="SUCCESS", index=True)
    target_type = db.Column(db.String(64), nullable=True)
    target_id = db.Column(db.String(64), nullable=True)
    description = db.Column(db.String(512), nullable=False, default="")
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    extra = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    actor = db.relationship("User", foreign_keys=[actor_id])

    __table_args__ = (db.Index("ix_audit_action_created", "action", "created_at"),)

    @property
    def status_badge(self) -> str:
        return {"SUCCESS": "success", "FAILURE": "danger", "BLOCKED": "warning"}.get(self.status, "secondary")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "actor": self.actor_username,
            "actor_role": self.actor_role,
            "action": self.action,
            "category": self.category,
            "status": self.status,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "description": self.description,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "extra": self.extra or {},
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} by {self.actor_username}>"
