"""SQLAlchemy models for PhishGuard.

Importing this package registers every model with the shared metadata so that
``db.create_all()`` and Flask-Migrate autogeneration see the full schema.
"""

from app.models.audit_log import AuditAction, AuditLog
from app.models.campaign import Campaign, CampaignStatus, CampaignTarget, Difficulty
from app.models.email_analysis import EmailAnalysis
from app.models.quiz import AwarenessQuiz, QuizAttempt, QuizQuestion
from app.models.report import Report, ReportType
from app.models.simulation import EventType, SimulationEvent
from app.models.url_analysis import URLAnalysis
from app.models.user import Role, User, utcnow

__all__ = [
    "AuditAction",
    "AuditLog",
    "AwarenessQuiz",
    "Campaign",
    "CampaignStatus",
    "CampaignTarget",
    "Difficulty",
    "EmailAnalysis",
    "EventType",
    "QuizAttempt",
    "QuizQuestion",
    "Report",
    "ReportType",
    "Role",
    "SimulationEvent",
    "URLAnalysis",
    "User",
    "utcnow",
]
