"""Campaign lifecycle, safe event recording and analytics.

All metrics produced here describe the *simulation* only.  They measure how
demo participants reacted to a controlled awareness exercise - they are not a
measurement of real-world phishing prevalence or of real attacker success.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta

from flask import current_app, has_app_context
from sqlalchemy import func

from app.extensions import db
from app.models.campaign import Campaign, CampaignStatus, CampaignTarget, Difficulty
from app.models.email_analysis import EmailAnalysis
from app.models.quiz import QuizAttempt
from app.models.simulation import EventType, SimulationEvent
from app.models.url_analysis import URLAnalysis
from app.models.user import Role, User, utcnow
from app.services.simulation_templates import get_template

#: Baseline awareness score before any interaction is recorded.
AWARENESS_BASELINE = 60

#: Fallback click-rate thresholds (%) used to label a campaign's residual
#: risk when no application context is active.  The live values come from
#: ``CAMPAIGN_RISK_THRESHOLDS`` in config so they can be retuned per install.
RISK_THRESHOLDS = ((10, "LOW"), (25, "MEDIUM"), (50, "HIGH"))


def _risk_thresholds():
    if has_app_context():
        return current_app.config.get("CAMPAIGN_RISK_THRESHOLDS", RISK_THRESHOLDS)
    return RISK_THRESHOLDS


class CampaignError(Exception):
    """Raised for invalid campaign operations."""


def create_campaign(*, name: str, description: str, template_key: str, difficulty: str,
                    start_date: date | None, end_date: date | None, target_ids: list[int],
                    creator: User, status: str = CampaignStatus.ACTIVE,
                    organization: str | None = None) -> Campaign:
    """Create a campaign and enrol its demo participants."""
    if not get_template(template_key):
        raise CampaignError(f"Unknown simulation template '{template_key}'.")
    if difficulty not in Difficulty.ALL:
        raise CampaignError(f"Unknown difficulty '{difficulty}'.")
    if status not in CampaignStatus.ALL:
        raise CampaignError(f"Unknown status '{status}'.")
    if start_date and end_date and end_date < start_date:
        raise CampaignError("End date cannot be earlier than the start date.")

    targets = (
        db.session.query(User)
        .filter(User.id.in_(target_ids or []), User.is_active_account.is_(True))
        .all()
    )
    if not targets:
        raise CampaignError("Select at least one active participant for the simulation.")

    campaign = Campaign(
        name=name,
        description=description,
        template_key=template_key,
        difficulty=difficulty,
        status=status,
        start_date=start_date,
        end_date=end_date,
        organization=organization or creator.organization,
        created_by=creator,
    )
    db.session.add(campaign)
    db.session.flush()

    for user in targets:
        db.session.add(
            CampaignTarget(
                campaign_id=campaign.id,
                user_id=user.id,
                simulated_message_id=CampaignTarget.new_message_id(),
                access_token=CampaignTarget.new_token(),
                delivered_at=utcnow() if status == CampaignStatus.ACTIVE else None,
            )
        )
    db.session.commit()
    return campaign


def record_event(target: CampaignTarget, event_type: str, note: str = "",
                 commit: bool = True) -> SimulationEvent:
    """Persist a safe interaction event.

    Only the campaign id, the demo participant reference, the simulated
    message id, the event type and a timestamp are stored.
    """
    if event_type not in EventType.ALL:
        raise CampaignError(f"Unsupported event type '{event_type}'.")
    event = SimulationEvent(
        campaign_id=target.campaign_id,
        user_id=target.user_id,
        demo_user_ref=f"demo-user-{target.user_id}",
        simulated_message_id=target.simulated_message_id,
        event_type=event_type,
        note=(note or "")[:255],
    )
    db.session.add(event)
    if commit:
        db.session.commit()
    return event


def awareness_score_for(events: list[SimulationEvent]) -> int:
    """Awareness score for one participant.

    ``score = 60 + sum(event weights)``, clamped to 0-100 where
    OPENED = -5, LINK_CLICKED = -25, TRAINING_PAGE_VIEWED = +10, REPORTED = +30.
    A participant who reports the simulation instead of clicking scores highest.
    """
    score = AWARENESS_BASELINE
    for event in events:
        score += EventType.AWARENESS_WEIGHT.get(event.event_type, 0)
    return max(0, min(100, score))


def _risk_level(click_rate: float) -> str:
    for threshold, label in _risk_thresholds():
        if click_rate < threshold:
            return label
    return "CRITICAL"


def campaign_stats(campaign: Campaign) -> dict:
    """Aggregate metrics + per-participant breakdown for one campaign."""
    targets = campaign.targets.all()
    events = campaign.events.order_by(SimulationEvent.occurred_at.asc()).all()

    by_user: dict[int, list[SimulationEvent]] = defaultdict(list)
    for event in events:
        by_user[event.user_id].append(event)

    counts = Counter(event.event_type for event in events)
    participants = len(targets)
    unique = {etype: len({e.user_id for e in events if e.event_type == etype}) for etype in EventType.ALL}

    click_rate = (unique[EventType.LINK_CLICKED] / participants * 100) if participants else 0.0
    open_rate = (unique[EventType.OPENED] / participants * 100) if participants else 0.0
    report_rate = (unique[EventType.REPORTED] / participants * 100) if participants else 0.0
    training_rate = (unique[EventType.TRAINING_PAGE_VIEWED] / participants * 100) if participants else 0.0

    participant_rows = []
    for target in targets:
        user_events = by_user.get(target.user_id, [])
        etypes = {e.event_type for e in user_events}
        participant_rows.append({
            "user_id": target.user_id,
            "demo_user_ref": f"demo-user-{target.user_id}",
            "username": target.user.username if target.user else "unknown",
            "full_name": target.user.full_name if target.user else "",
            "department": target.user.department if target.user else "",
            "simulated_message_id": target.simulated_message_id,
            "opened": EventType.OPENED in etypes,
            "clicked": EventType.LINK_CLICKED in etypes,
            "trained": EventType.TRAINING_PAGE_VIEWED in etypes,
            "reported": EventType.REPORTED in etypes,
            "awareness_score": awareness_score_for(user_events),
            "last_activity": max((e.occurred_at for e in user_events), default=None),
        })

    awareness = (
        round(sum(row["awareness_score"] for row in participant_rows) / len(participant_rows), 1)
        if participant_rows else float(AWARENESS_BASELINE)
    )

    timeline_map: dict[str, Counter] = defaultdict(Counter)
    for event in events:
        timeline_map[event.occurred_at.strftime("%Y-%m-%d")][event.event_type] += 1
    timeline = [
        {
            "date": day,
            **{etype: timeline_map[day].get(etype, 0) for etype in EventType.ALL},
            "total": sum(timeline_map[day].values()),
        }
        for day in sorted(timeline_map)
    ]

    template = get_template(campaign.template_key)
    return {
        "campaign": campaign.to_dict(),
        "template": template.to_dict() if template else None,
        "participants": participants,
        "messages_simulated": participants,
        "events_total": len(events),
        "event_counts": {etype: counts.get(etype, 0) for etype in EventType.ALL},
        "unique_counts": unique,
        "open_rate": round(open_rate, 1),
        "interaction_rate": round(click_rate, 1),      # simulation interaction rate
        "report_rate": round(report_rate, 1),
        "training_rate": round(training_rate, 1),
        "awareness_score": awareness,
        "risk_level": _risk_level(click_rate),
        "participant_rows": sorted(participant_rows, key=lambda r: (-r["clicked"], r["username"])),
        "timeline": timeline,
        "metric_note": (
            "Simulation metrics only: they describe participant behaviour during a "
            "controlled awareness exercise, not real-world phishing prevalence."
        ),
    }


def dashboard_stats() -> dict:
    """Organisation-wide KPIs + chart series for the SOC dashboard."""
    total_campaigns = db.session.query(func.count(Campaign.id)).scalar() or 0
    active_campaigns = (
        db.session.query(func.count(Campaign.id))
        .filter(Campaign.status == CampaignStatus.ACTIVE).scalar() or 0
    )
    total_targets = db.session.query(func.count(CampaignTarget.id)).scalar() or 0
    total_events = db.session.query(func.count(SimulationEvent.id)).scalar() or 0

    event_counts = {
        etype: db.session.query(func.count(SimulationEvent.id))
        .filter(SimulationEvent.event_type == etype).scalar() or 0
        for etype in EventType.ALL
    }
    clicked_users = {
        row[0] for row in db.session.query(SimulationEvent.user_id)
        .filter(SimulationEvent.event_type == EventType.LINK_CLICKED).distinct().all()
        if row[0]
    }
    reported_users = {
        row[0] for row in db.session.query(SimulationEvent.user_id)
        .filter(SimulationEvent.event_type == EventType.REPORTED).distinct().all()
        if row[0]
    }
    trained_users = {
        row[0] for row in db.session.query(SimulationEvent.user_id)
        .filter(SimulationEvent.event_type == EventType.TRAINING_PAGE_VIEWED).distinct().all()
        if row[0]
    }
    engaged_users = {
        row[0] for row in db.session.query(SimulationEvent.user_id).distinct().all() if row[0]
    }

    # Detection subsystem -------------------------------------------------
    url_rows = db.session.query(URLAnalysis.classification, func.count(URLAnalysis.id)) \
        .group_by(URLAnalysis.classification).all()
    email_rows = db.session.query(EmailAnalysis.classification, func.count(EmailAnalysis.id)) \
        .group_by(EmailAnalysis.classification).all()
    risk_distribution = Counter()
    for label, count in url_rows:
        risk_distribution[label] += count
    for label, count in email_rows:
        risk_distribution[label] += count

    total_url = sum(c for _, c in url_rows)
    total_email = sum(c for _, c in email_rows)
    total_analyses = total_url + total_email
    high_risk = risk_distribution.get("HIGH", 0) + risk_distribution.get("CRITICAL", 0)
    detection_rate = round(high_risk / total_analyses * 100, 1) if total_analyses else 0.0

    avg_url = db.session.query(func.avg(URLAnalysis.final_score)).scalar() or 0.0
    avg_email = db.session.query(func.avg(EmailAnalysis.final_score)).scalar() or 0.0
    if total_analyses:
        avg_risk = round(((avg_url * total_url) + (avg_email * total_email)) / total_analyses, 1)
    else:
        avg_risk = 0.0

    # Users requiring training: clicked the simulation and never completed
    # the awareness training or a passing quiz attempt.
    passed_quiz_users = {
        row[0] for row in db.session.query(QuizAttempt.user_id)
        .filter(QuizAttempt.passed.is_(True)).distinct().all()
    }
    needs_training = sorted(clicked_users - trained_users - passed_quiz_users)

    # Activity over the last 14 days -------------------------------------
    today = utcnow().date()
    days = [(today - timedelta(days=offset)) for offset in range(13, -1, -1)]
    labels = [day.strftime("%d %b") for day in days]
    activity = {etype: [0] * len(days) for etype in EventType.ALL}
    index = {day.strftime("%Y-%m-%d"): position for position, day in enumerate(days)}
    day_expr = (
        func.strftime("%Y-%m-%d", SimulationEvent.occurred_at)
        if db.engine.dialect.name == "sqlite"
        else func.to_char(SimulationEvent.occurred_at, "YYYY-MM-DD")
    )
    window_start = datetime.combine(days[0], datetime.min.time())
    rows = (
        db.session.query(day_expr, SimulationEvent.event_type,
                         func.count(SimulationEvent.id))
        .filter(SimulationEvent.occurred_at >= window_start)
        .group_by(day_expr, SimulationEvent.event_type)
        .all()
    )
    for day_str, etype, count in rows:
        if day_str in index and etype in activity:
            activity[etype][index[day_str]] = count

    # Campaign performance (top 6 by participants) -------------------------
    campaign_perf = []
    for campaign in Campaign.query.order_by(Campaign.created_at.desc()).limit(6).all():
        stats = campaign_stats(campaign)
        campaign_perf.append({
            "id": campaign.id,
            "name": campaign.name,
            "interaction_rate": stats["interaction_rate"],
            "report_rate": stats["report_rate"],
            "awareness_score": stats["awareness_score"],
            "participants": stats["participants"],
            "risk_level": stats["risk_level"],
        })
    campaign_perf.reverse()

    # Awareness improvement: mean quiz score per week (last 6 weeks) --------
    quiz_attempts = QuizAttempt.query.order_by(QuizAttempt.completed_at.asc()).all()
    weekly: dict[str, list[int]] = defaultdict(list)
    for attempt in quiz_attempts:
        key = attempt.completed_at.strftime("%Y-W%V")
        weekly[key].append(attempt.score)
    awareness_labels = sorted(weekly)[-6:]
    awareness_series = [round(sum(weekly[k]) / len(weekly[k]), 1) for k in awareness_labels]

    ml_ready = None
    try:
        from app.services.ml_detector import ml_detector

        ml_ready = ml_detector.metadata()
    except Exception:  # pragma: no cover - defensive
        ml_ready = {"available": False}

    return {
        "kpis": {
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "total_simulations": total_targets,
            "emails_simulated": total_targets,
            "simulation_interactions": total_events,
            "link_clicks": event_counts[EventType.LINK_CLICKED],
            "reports_submitted": event_counts[EventType.REPORTED],
            "detection_rate": detection_rate,
            "high_risk_events": high_risk,
            "avg_risk_score": avg_risk,
            "users_requiring_training": len(needs_training),
            "total_analyses": total_analyses,
            "url_analyses": total_url,
            "email_analyses": total_email,
            "engaged_users": len(engaged_users),
            "reported_users": len(reported_users),
        },
        "charts": {
            "activity": {"labels": labels, "series": activity},
            "risk_distribution": {
                "labels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "values": [risk_distribution.get(k, 0) for k in ("LOW", "MEDIUM", "HIGH", "CRITICAL")],
            },
            "detection_split": {
                "labels": ["Email analyses", "URL analyses"],
                "values": [total_email, total_url],
            },
            "campaign_performance": {
                "labels": [c["name"][:22] for c in campaign_perf],
                "interaction": [c["interaction_rate"] for c in campaign_perf],
                "reporting": [c["report_rate"] for c in campaign_perf],
                "awareness": [c["awareness_score"] for c in campaign_perf],
            },
            "awareness_improvement": {
                "labels": awareness_labels,
                "values": awareness_series,
            },
            "event_mix": {
                "labels": [EventType.LABELS[e] for e in EventType.ALL],
                "values": [event_counts[e] for e in EventType.ALL],
            },
        },
        "ml": ml_ready,
        "needs_training_ids": needs_training,
        "metric_note": (
            "Detection rate = share of analyses classified HIGH or CRITICAL. "
            "Simulation metrics reflect controlled exercises, not real attacks."
        ),
    }


def detection_accuracy_series() -> dict:
    """Confusion-matrix style summary from the stored ML validation metrics."""
    from app.services.ml_detector import ml_detector

    meta = ml_detector.metadata()
    if not meta.get("available"):
        return {"available": False}
    metrics = meta.get("metrics", {})
    selected = metrics.get("selected_model") or meta.get("model_name")
    models = metrics.get("models", {})
    return {
        "available": True,
        "selected": selected,
        "labels": list(models.keys()),
        "accuracy": [round(m.get("accuracy", 0) * 100, 2) for m in models.values()],
        "precision": [round(m.get("precision", 0) * 100, 2) for m in models.values()],
        "recall": [round(m.get("recall", 0) * 100, 2) for m in models.values()],
        "f1": [round(m.get("f1", 0) * 100, 2) for m in models.values()],
        "confusion": {name: m.get("confusion_matrix") for name, m in models.items()},
    }


def users_requiring_training() -> list[User]:
    stats = dashboard_stats()
    ids = stats["needs_training_ids"]
    if not ids:
        return []
    return User.query.filter(User.id.in_(ids)).all()


def demo_participants() -> list[User]:
    return (
        User.query.filter(User.role == Role.DEMO_USER, User.is_active_account.is_(True))
        .order_by(User.full_name.asc())
        .all()
    )
