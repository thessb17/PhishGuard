"""Security-awareness quiz models."""

from __future__ import annotations

from app.extensions import db
from app.models.user import utcnow


class AwarenessQuiz(db.Model):
    __tablename__ = "awareness_quizzes"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    pass_mark = db.Column(db.Integer, nullable=False, default=70)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    questions = db.relationship(
        "QuizQuestion",
        back_populates="quiz",
        cascade="all, delete-orphan",
        order_by="QuizQuestion.position",
    )
    attempts = db.relationship(
        "QuizAttempt", back_populates="quiz", cascade="all, delete-orphan", lazy="dynamic"
    )

    @property
    def question_count(self) -> int:
        return len(self.questions)

    def to_dict(self, include_answers: bool = False) -> dict:
        return {
            "id": self.id,
            "slug": self.slug,
            "title": self.title,
            "description": self.description,
            "pass_mark": self.pass_mark,
            "questions": [q.to_dict(include_answers) for q in self.questions],
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AwarenessQuiz {self.slug}>"


class QuizQuestion(db.Model):
    __tablename__ = "quiz_questions"

    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("awareness_quizzes.id", ondelete="CASCADE"), nullable=False, index=True)
    position = db.Column(db.Integer, nullable=False, default=0)
    prompt = db.Column(db.Text, nullable=False)
    options = db.Column(db.JSON, nullable=False, default=list)
    correct_index = db.Column(db.Integer, nullable=False, default=0)
    explanation = db.Column(db.Text, nullable=False, default="")
    category = db.Column(db.String(64), nullable=False, default="general")

    quiz = db.relationship("AwarenessQuiz", back_populates="questions")

    def to_dict(self, include_answers: bool = False) -> dict:
        data = {
            "id": self.id,
            "position": self.position,
            "prompt": self.prompt,
            "options": self.options or [],
            "category": self.category,
        }
        if include_answers:
            data["correct_index"] = self.correct_index
            data["explanation"] = self.explanation
        return data

    def __repr__(self) -> str:  # pragma: no cover
        return f"<QuizQuestion {self.id} pos={self.position}>"


class QuizAttempt(db.Model):
    __tablename__ = "quiz_attempts"

    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("awareness_quizzes.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False, default=0)            # percentage 0-100
    correct_count = db.Column(db.Integer, nullable=False, default=0)
    total_questions = db.Column(db.Integer, nullable=False, default=0)
    answered_count = db.Column(db.Integer, nullable=False, default=0)
    passed = db.Column(db.Boolean, nullable=False, default=False, index=True)
    #: [{question_id, selected_index, correct_index, correct: bool}]
    answers = db.Column(db.JSON, nullable=False, default=list)
    started_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    completed_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    quiz = db.relationship("AwarenessQuiz", back_populates="attempts")
    user = db.relationship("User", back_populates="quiz_attempts")

    __table_args__ = (db.Index("ix_attempt_user_completed", "user_id", "completed_at"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "quiz": self.quiz.slug if self.quiz else None,
            "user": self.user.username if self.user else None,
            "score": self.score,
            "correct_count": self.correct_count,
            "total_questions": self.total_questions,
            "answered_count": self.answered_count,
            "passed": self.passed,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<QuizAttempt user={self.user_id} score={self.score}>"
