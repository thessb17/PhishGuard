"""Security-awareness training and quiz."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db, limiter
from app.forms import SimpleActionForm
from app.models.audit_log import AuditAction
from app.models.quiz import AwarenessQuiz, QuizAttempt, QuizQuestion
from app.models.user import utcnow
from app.services.awareness_content import TOPIC_INDEX, TOPICS, ensure_default_quiz
from app.utils.audit import log_audit

awareness_bp = Blueprint("awareness", __name__)


def _quiz() -> AwarenessQuiz:
    return ensure_default_quiz(db.session, AwarenessQuiz, QuizQuestion)


@awareness_bp.route("/awareness")
@login_required
def index():
    quiz = _quiz()
    attempts = (
        QuizAttempt.query.filter_by(user_id=current_user.id, quiz_id=quiz.id)
        .order_by(QuizAttempt.completed_at.desc()).all()
    )
    best = max((attempt.score for attempt in attempts), default=None)
    return render_template("awareness/index.html", topics=TOPICS, quiz=quiz,
                           attempts=attempts[:5], best=best)


@awareness_bp.route("/awareness/topic/<slug>")
@login_required
def topic(slug: str):
    item = TOPIC_INDEX.get(slug)
    if not item:
        abort(404)
    slugs = [t["slug"] for t in TOPICS]
    position = slugs.index(slug)
    previous_topic = TOPICS[position - 1] if position > 0 else None
    next_topic = TOPICS[position + 1] if position < len(TOPICS) - 1 else None
    return render_template("awareness/topic.html", topic=item, topics=TOPICS,
                           previous_topic=previous_topic, next_topic=next_topic)


@awareness_bp.route("/quiz", methods=["GET"])
@login_required
def quiz():
    quiz_obj = _quiz()
    form = SimpleActionForm()
    attempts = (
        QuizAttempt.query.filter_by(user_id=current_user.id, quiz_id=quiz_obj.id)
        .order_by(QuizAttempt.completed_at.desc()).limit(5).all()
    )
    return render_template("awareness/quiz.html", quiz=quiz_obj, form=form, attempts=attempts)


def grade_quiz(quiz_obj: AwarenessQuiz, submitted: dict[int, int], user) -> QuizAttempt:
    """Grade a submission and persist the attempt."""
    results = []
    correct = 0
    for question in quiz_obj.questions:
        selected = submitted.get(question.id)
        is_correct = selected is not None and int(selected) == question.correct_index
        correct += 1 if is_correct else 0
        results.append({
            "question_id": question.id,
            "prompt": question.prompt,
            "selected_index": selected,
            "correct_index": question.correct_index,
            "correct": is_correct,
            "explanation": question.explanation,
            "options": question.options,
        })
    total = len(quiz_obj.questions) or 1
    score = round(correct / total * 100)
    attempt = QuizAttempt(
        quiz_id=quiz_obj.id,
        user_id=user.id,
        score=score,
        correct_count=correct,
        total_questions=total,
        answered_count=len([r for r in results if r["selected_index"] is not None]),
        passed=score >= quiz_obj.pass_mark,
        answers=results,
        started_at=utcnow(),
        completed_at=utcnow(),
    )
    db.session.add(attempt)
    db.session.commit()
    return attempt


@awareness_bp.route("/quiz", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def submit_quiz():
    quiz_obj = _quiz()
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)

    submitted: dict[int, int] = {}
    for question in quiz_obj.questions:
        raw = request.form.get(f"question-{question.id}")
        if raw is None or raw == "":
            continue
        try:
            value = int(raw)
        except ValueError:
            continue
        if 0 <= value < len(question.options or []):
            submitted[question.id] = value

    if not submitted:
        flash("Answer at least one question before submitting.", "warning")
        return redirect(url_for("awareness.quiz"))

    attempt = grade_quiz(quiz_obj, submitted, current_user)
    log_audit(AuditAction.QUIZ_SUBMITTED,
              description=f"Quiz '{quiz_obj.slug}' submitted: {attempt.score}% "
                          f"({'pass' if attempt.passed else 'fail'})",
              target_type="quiz_attempt", target_id=attempt.id,
              extra={"score": attempt.score, "answered": attempt.answered_count})
    return redirect(url_for("awareness.quiz_result", attempt_id=attempt.id))


@awareness_bp.route("/quiz/result/<int:attempt_id>")
@login_required
def quiz_result(attempt_id: int):
    attempt = db.session.get(QuizAttempt, attempt_id)
    if not attempt:
        abort(404)
    if attempt.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return render_template("awareness/quiz_result.html", attempt=attempt, quiz=attempt.quiz,
                           topics=TOPICS)
