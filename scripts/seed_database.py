#!/usr/bin/env python3
"""Populate PhishGuard with fictional demonstration data.

Everything created here is invented for the demo:

* three fictional organizations - Andhra University, Example Corporation and
  Demo IT Department;
* eighteen fictional staff/student identities that do not correspond to real
  people, using RFC 2606 reserved or clearly fictitious mail domains;
* five simulated phishing campaigns, one per built-in template;
* interaction events limited to OPENED / LINK_CLICKED / TRAINING_PAGE_VIEWED /
  REPORTED - no credentials, no form submissions, no message content;
* a handful of URL/email analyses, quiz attempts, reports and audit entries so
  that every dashboard chart has real data behind it.

Usage::

    python scripts/seed_database.py            # create tables, add demo data
    python scripts/seed_database.py --reset    # drop everything first
    flask --app run:app seed-db --reset        # same thing through the CLI
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import has_app_context  # noqa: E402

from app.extensions import db  # noqa: E402
from app.models.audit_log import AuditAction, AuditLog  # noqa: E402
from app.models.campaign import Campaign, CampaignStatus, Difficulty  # noqa: E402
from app.models.email_analysis import EmailAnalysis  # noqa: E402
from app.models.quiz import AwarenessQuiz, QuizAttempt, QuizQuestion  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.models.simulation import EventType, SimulationEvent  # noqa: E402
from app.models.url_analysis import URLAnalysis  # noqa: E402
from app.models.user import Role, User, utcnow  # noqa: E402

RNG = random.Random(20260301)

CYBERSAFE = "Andhra University"
EXAMPLE_CORP = "Example Corporation"
DEMO_IT = "Demo IT Department"

DEMO_PASSWORD = "Demo@Phish2026"

#: (username, full name, email, role, department, organization, password)
ACCOUNTS: list[tuple[str, str, str, str, str, str, str]] = [
    ("admin", "Sabyasachi Bhowmik", "admin@andhra-university.example", Role.ADMIN,
     "Department of Computer Science and Systems Engineering", CYBERSAFE, "Admin@Phish2026"),
    ("analyst", "Rohan Varma", "analyst@cybersafe.edu", Role.ANALYST,
     "Security Operations Centre", CYBERSAFE, "Analyst@Phish2026"),
    ("nadia.analyst", "Nadia Okonkwo", "nadia.okonkwo@example-corp.com", Role.ANALYST,
     "Corporate Security", EXAMPLE_CORP, "Analyst@Phish2026"),
    ("priya.demo", "Priya Nandakumar", "priya.nandakumar@cybersafe.edu", Role.DEMO_USER,
     "Student Services", CYBERSAFE, DEMO_PASSWORD),
    ("liam.demo", "Liam Whitfield", "liam.whitfield@cybersafe.edu", Role.DEMO_USER,
     "Faculty of Engineering", CYBERSAFE, DEMO_PASSWORD),
    ("sofia.demo", "Sofia Marchetti", "sofia.marchetti@cybersafe.edu", Role.DEMO_USER,
     "Library Services", CYBERSAFE, DEMO_PASSWORD),
    ("kenji.demo", "Kenji Arakawa", "kenji.arakawa@cybersafe.edu", Role.DEMO_USER,
     "Research Computing", CYBERSAFE, DEMO_PASSWORD),
    ("amara.demo", "Amara Diallo", "amara.diallo@cybersafe.edu", Role.DEMO_USER,
     "Admissions", CYBERSAFE, DEMO_PASSWORD),
    ("tomas.demo", "Tomas Ebersohn", "tomas.ebersohn@cybersafe.edu", Role.DEMO_USER,
     "Facilities", CYBERSAFE, DEMO_PASSWORD),
    ("hana.demo", "Hana Lindqvist", "hana.lindqvist@example-corp.com", Role.DEMO_USER,
     "Finance", EXAMPLE_CORP, DEMO_PASSWORD),
    ("marcus.demo", "Marcus Oyelaran", "marcus.oyelaran@example-corp.com", Role.DEMO_USER,
     "Human Resources", EXAMPLE_CORP, DEMO_PASSWORD),
    ("elena.demo", "Elena Vasquez", "elena.vasquez@example-corp.com", Role.DEMO_USER,
     "Sales", EXAMPLE_CORP, DEMO_PASSWORD),
    ("dmitri.demo", "Dmitri Ilyushin", "dmitri.ilyushin@example-corp.com", Role.DEMO_USER,
     "Logistics", EXAMPLE_CORP, DEMO_PASSWORD),
    ("grace.demo", "Grace Abioye", "grace.abioye@example-corp.com", Role.DEMO_USER,
     "Legal", EXAMPLE_CORP, DEMO_PASSWORD),
    ("noor.demo", "Noor Al-Rashid", "noor.alrashid@example-corp.com", Role.DEMO_USER,
     "Customer Support", EXAMPLE_CORP, DEMO_PASSWORD),
    ("felix.demo", "Felix Brunner", "felix.brunner@demo-it.example", Role.DEMO_USER,
     "Service Desk", DEMO_IT, DEMO_PASSWORD),
    ("yuki.demo", "Yuki Tanabe", "yuki.tanabe@demo-it.example", Role.DEMO_USER,
     "Infrastructure", DEMO_IT, DEMO_PASSWORD),
    ("olivia.demo", "Olivia Ferreira", "olivia.ferreira@demo-it.example", Role.DEMO_USER,
     "Application Support", DEMO_IT, DEMO_PASSWORD),
]

#: name, template, organization, status, days ago started, duration, behaviour profile
CAMPAIGNS: list[dict] = [
    {
        "name": "Q1 Password Expiry Awareness Test",
        "description": ("Baseline exercise for Andhra University staff and students. Measures how "
                        "many recipients act on an urgent password-expiry notice before checking the "
                        "sender domain."),
        "template_key": "password_expiry",
        "difficulty": Difficulty.MEDIUM,
        "organization": CYBERSAFE,
        "status": CampaignStatus.COMPLETED,
        "starts_days_ago": 52,
        "duration_days": 10,
        "org_filter": CYBERSAFE,
        "profile": {"open": 0.85, "click": 0.42, "training": 0.86, "report": 0.22},
    },
    {
        "name": "Courier Delivery Notification Drill",
        "description": ("Consumer-style lure sent to Example Corporation. Tests whether a small "
                        "'redelivery fee' and a tracking number are enough to bypass suspicion."),
        "template_key": "delivery_notification",
        "difficulty": Difficulty.EASY,
        "organization": EXAMPLE_CORP,
        "status": CampaignStatus.COMPLETED,
        "starts_days_ago": 34,
        "duration_days": 7,
        "org_filter": EXAMPLE_CORP,
        "profile": {"open": 0.78, "click": 0.30, "training": 0.9, "report": 0.35},
    },
    {
        "name": "Annual HR Policy Acknowledgement Test",
        "description": ("Authority-based lure referencing a mandatory policy sign-off with a deadline. "
                        "Run after the first round of awareness training to measure improvement."),
        "template_key": "hr_policy",
        "difficulty": Difficulty.HARD,
        "organization": EXAMPLE_CORP,
        "status": CampaignStatus.ACTIVE,
        "starts_days_ago": 13,
        "duration_days": 21,
        "org_filter": EXAMPLE_CORP,
        "profile": {"open": 0.82, "click": 0.22, "training": 0.92, "report": 0.5},
    },
    {
        "name": "SOC Security Alert Simulation",
        "description": ("Impersonates the university SOC with a fake 'unusual sign-in' alert. Designed "
                        "to test whether recipients verify alerts through the official portal."),
        "template_key": "it_security_alert",
        "difficulty": Difficulty.HARD,
        "organization": CYBERSAFE,
        "status": CampaignStatus.ACTIVE,
        "starts_days_ago": 6,
        "duration_days": 12,
        "org_filter": None,
        "profile": {"open": 0.7, "click": 0.18, "training": 0.9, "report": 0.55},
    },
    {
        "name": "Student Account Verification Exercise",
        "description": ("Scheduled exercise using a deceptive subdomain (cybersafe.edu.verify-student"
                        ".example). Prepared but not yet released, so no events exist."),
        "template_key": "account_verification",
        "difficulty": Difficulty.MEDIUM,
        "organization": CYBERSAFE,
        "status": CampaignStatus.DRAFT,
        "starts_days_ago": -7,
        "duration_days": 10,
        "org_filter": CYBERSAFE,
        "profile": None,
    },
]

DEMO_URLS: list[tuple[str, str]] = [
    ("http://198.51.100.23/paypal.com/secure/login.php?cmd=verify-account", "web"),
    ("https://cybersafe.edu.verify-student.example/finance/confirm?id=8812", "web"),
    ("https://xn--pypal-4ve.com/signin", "api"),
    ("http://bit.ly/3xR4pQz", "web"),
    ("http://micros0ft-secure-login.tk/account/unlock", "web"),
    ("https://library.cybersafe.edu/account/loans", "web"),
    ("https://docs.python.org/3/library/json.html?highlight=dumps", "api"),
    ("https://www.wikipedia.org/wiki/Phishing", "web"),
]


def _log(message: str, verbose: bool) -> None:
    if verbose:
        print(message, flush=True)


#: Raw API keys issued during this seeding run.  They exist only in memory,
#: are never written to the database (only a SHA-256 digest is), and are
#: printed once so the README's curl examples work immediately after seeding.
ISSUED_API_KEYS: dict[str, str] = {}


def _make_users(verbose: bool) -> dict[str, User]:
    users: dict[str, User] = {}
    created = 0
    for username, full_name, email, role, department, organization, password in ACCOUNTS:
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(username=username, email=email, full_name=full_name, role=role,
                        department=department, organization=organization)
            user.set_password(password)
            raw_key = user.ensure_api_key()
            if raw_key:
                ISSUED_API_KEYS[username] = raw_key
            db.session.add(user)
            created += 1
        users[username] = user
    db.session.commit()
    _log(f"  users: {created} created, {len(ACCOUNTS) - created} already present", verbose)
    return users


def _event_timestamp(base: datetime, offset_hours: float) -> datetime:
    """Offset a timestamp, never allowing a demo event to land in the future."""
    moment = base + timedelta(hours=offset_hours)
    ceiling = utcnow() - timedelta(minutes=5)
    return min(moment, ceiling)


def _seed_campaign(spec: dict, creator: User, participants: list[User],
                   verbose: bool) -> Campaign | None:
    from app.services.campaign_service import create_campaign, record_event

    if Campaign.query.filter_by(name=spec["name"]).first():
        _log(f"  campaign '{spec['name']}' already present - skipped", verbose)
        return None

    pool = [u for u in participants
            if spec["org_filter"] is None or u.organization == spec["org_filter"]]
    if not pool:
        pool = participants

    start = date.today() - timedelta(days=spec["starts_days_ago"])
    campaign = create_campaign(
        name=spec["name"],
        description=spec["description"],
        template_key=spec["template_key"],
        difficulty=spec["difficulty"],
        start_date=start,
        end_date=start + timedelta(days=spec["duration_days"]),
        target_ids=[u.id for u in pool],
        creator=creator,
        status=spec["status"],
        organization=spec["organization"],
    )

    started_at = utcnow() - timedelta(days=max(spec["starts_days_ago"], 0))
    campaign.created_at = started_at
    campaign.updated_at = started_at

    profile = spec["profile"]
    if not profile:
        db.session.commit()
        _log(f"  campaign '{spec['name']}': {len(pool)} participants, no events (draft)", verbose)
        return campaign

    events = 0
    for target in campaign.targets:
        target.created_at = started_at
        target.delivered_at = started_at + timedelta(hours=RNG.uniform(0.2, 6))
        if RNG.random() > profile["open"]:
            continue  # participant never opened the simulated message
        opened_at = _event_timestamp(started_at, RNG.uniform(0.5, 110))
        event = record_event(target, EventType.OPENED, note="seeded demo event", commit=False)
        event.occurred_at = opened_at
        events += 1

        clicked = RNG.random() < profile["click"]
        if clicked:
            clicked_at = _event_timestamp(opened_at, RNG.uniform(0.01, 2))
            event = record_event(target, EventType.LINK_CLICKED, note="seeded demo event",
                                 commit=False)
            event.occurred_at = clicked_at
            events += 1
            if RNG.random() < profile["training"]:
                event = record_event(target, EventType.TRAINING_PAGE_VIEWED,
                                     note="seeded demo event", commit=False)
                event.occurred_at = _event_timestamp(clicked_at, RNG.uniform(0.001, 0.2))
                events += 1

        if RNG.random() < (profile["report"] * (0.4 if clicked else 1.0)):
            event = record_event(target, EventType.REPORTED, note="seeded demo event",
                                 commit=False)
            event.occurred_at = _event_timestamp(opened_at, RNG.uniform(0.02, 20))
            events += 1

    db.session.commit()
    _log(f"  campaign '{spec['name']}': {len(pool)} participants, {events} events", verbose)
    return campaign


def _seed_url_analyses(analyst: User, verbose: bool) -> list[URLAnalysis]:
    from app.routes.url_detector import analyse_url_payload

    records = []
    for index, (url, source) in enumerate(DEMO_URLS):
        if URLAnalysis.query.filter_by(url=url).first():
            continue
        _, _, _, record = analyse_url_payload(url, analyst=analyst, source=source)
        record.created_at = utcnow() - timedelta(days=RNG.uniform(0, 21),
                                                          hours=index)
        records.append(record)
    db.session.commit()
    _log(f"  URL analyses: {len(records)} created", verbose)
    return records


def _seed_email_analyses(analyst: User, verbose: bool) -> list[EmailAnalysis]:
    from app.routes.email_detector import (SAMPLE_LEGITIMATE, SAMPLE_PHISHING,
                                           analyse_email_payload)

    extra = {
        "sender": '"Accounts Payable" <ap-invoices@examplecorp-billing.example>',
        "subject": "Re: Outstanding invoice 88213 - immediate payment required today",
        "body": ("Hello,\n\nOur records show invoice 88213 is overdue. Please process the wire "
                 "transfer to our updated bank details today and keep this confidential until the "
                 "audit closes.\n\nUpdated remittance portal: "
                 "http://examplecorp-billing.example/pay/88213\n\nRegards,\nAccounts Payable"),
        "headers": ("From: \"Accounts Payable\" <ap-invoices@examplecorp-billing.example>\n"
                    "Reply-To: finance-recovery@mail-drop.example\n"
                    "Authentication-Results: mx.example-corp.com; spf=softfail; dkim=none; "
                    "dmarc=fail\n"),
    }

    created = []
    for sample in (SAMPLE_PHISHING, extra, SAMPLE_LEGITIMATE):
        if EmailAnalysis.query.filter_by(subject=sample["subject"][:512]).first():
            continue
        _, _, _, record = analyse_email_payload(
            sender=sample["sender"], subject=sample["subject"], body=sample["body"],
            urls=[], headers=sample["headers"], analyst=analyst,
        )
        record.created_at = utcnow() - timedelta(days=RNG.uniform(0, 14))
        created.append(record)
    db.session.commit()
    _log(f"  email analyses: {len(created)} created", verbose)
    return created


def _seed_quiz_attempts(users: dict[str, User], verbose: bool) -> int:
    from app.routes.awareness import grade_quiz
    from app.services.awareness_content import ensure_default_quiz

    quiz = ensure_default_quiz(db.session, AwarenessQuiz, QuizQuestion)
    questions = list(quiz.questions)
    if not questions:
        return 0

    plan = [("priya.demo", 0.9, 24), ("liam.demo", 0.6, 18), ("sofia.demo", 1.0, 11),
            ("hana.demo", 0.5, 9), ("marcus.demo", 0.8, 6), ("felix.demo", 0.7, 3)]
    created = 0
    for username, accuracy, days_ago in plan:
        user = users.get(username)
        if user is None or QuizAttempt.query.filter_by(user_id=user.id).first():
            continue
        submitted = {}
        for question in questions:
            if RNG.random() < accuracy:
                submitted[question.id] = question.correct_index
            else:
                wrong = [i for i in range(len(question.options)) if i != question.correct_index]
                submitted[question.id] = RNG.choice(wrong) if wrong else question.correct_index
        attempt = grade_quiz(quiz, submitted, user)
        moment = utcnow() - timedelta(days=days_ago)
        attempt.started_at = moment
        attempt.completed_at = moment
        created += 1
    db.session.commit()
    _log(f"  quiz attempts: {created} created (quiz '{quiz.slug}', "
         f"{len(questions)} questions)", verbose)
    return created


def _seed_reports(admin: User, analyst: User, verbose: bool) -> int:
    from app.services.report_service import create_campaign_report, create_detection_report

    created = 0
    for campaign in Campaign.query.filter(
        Campaign.status.in_([CampaignStatus.COMPLETED, CampaignStatus.ACTIVE])
    ).order_by(Campaign.id.asc()).limit(2).all():
        if Report.query.filter_by(subject_type="campaign", subject_id=campaign.id).first():
            continue
        create_campaign_report(campaign, admin)
        created += 1

    worst_url = URLAnalysis.query.order_by(URLAnalysis.final_score.desc()).first()
    if worst_url and not Report.query.filter_by(subject_type="url_analysis",
                                                subject_id=worst_url.id).first():
        create_detection_report(worst_url, analyst)
        created += 1

    worst_email = EmailAnalysis.query.order_by(EmailAnalysis.final_score.desc()).first()
    if worst_email and not Report.query.filter_by(subject_type="email_analysis",
                                                  subject_id=worst_email.id).first():
        create_detection_report(worst_email, analyst)
        created += 1

    db.session.commit()
    _log(f"  reports: {created} created", verbose)
    return created


def _seed_audit_trail(users: dict[str, User], verbose: bool) -> int:
    from app.utils.audit import log_audit

    if AuditLog.query.count():
        _log("  audit trail: entries already present - skipped", verbose)
        return 0

    entries = [
        (users["admin"], AuditAction.LOGIN_SUCCESS, "SUCCESS",
         "Administrator signed in", None, None, 14),
        (users["analyst"], AuditAction.LOGIN_SUCCESS, "SUCCESS",
         "Analyst signed in", None, None, 13),
        (None, AuditAction.LOGIN_FAILURE, "FAILURE",
         "Failed sign-in attempt for username 'analyst' (invalid password)", None, None, 12),
        (None, AuditAction.LOGIN_FAILURE, "FAILURE",
         "Failed sign-in attempt for username 'root' (unknown account)", None, None, 12),
        (users["admin"], AuditAction.CAMPAIGN_CREATED, "SUCCESS",
         "Campaign 'Q1 Password Expiry Awareness Test' created", "campaign", 1, 11),
        (users["analyst"], AuditAction.ANALYSIS_PERFORMED, "SUCCESS",
         "URL analysis completed: CRITICAL", "url_analysis", 1, 8),
        (users["admin"], AuditAction.ROLE_CHANGED, "SUCCESS",
         "Role for nadia.analyst changed DEMO_USER -> ANALYST", "user", 3, 6),
        (users["analyst"], AuditAction.REPORT_GENERATED, "SUCCESS",
         "Campaign report generated", "report", 1, 4),
        (users["priya.demo"], AuditAction.QUIZ_SUBMITTED, "SUCCESS",
         "Awareness quiz completed", "quiz_attempt", 1, 3),
        (None, AuditAction.RATE_LIMITED, "WARNING",
         "Rate limit reached on /url-detector", None, None, 2),
    ]
    for actor, action, status, description, target_type, target_id, days_ago in entries:
        entry = log_audit(action, status=status, description=description,
                          target_type=target_type, target_id=target_id, actor=actor,
                          commit=False)
        entry.created_at = utcnow() - timedelta(days=days_ago,
                                                         hours=RNG.uniform(0, 12))
    db.session.commit()
    _log(f"  audit trail: {len(entries)} entries created", verbose)
    return len(entries)


def _summary(verbose: bool) -> dict:
    counts = {
        "users": User.query.count(),
        "campaigns": Campaign.query.count(),
        "simulation_events": SimulationEvent.query.count(),
        "url_analyses": URLAnalysis.query.count(),
        "email_analyses": EmailAnalysis.query.count(),
        "quiz_attempts": QuizAttempt.query.count(),
        "reports": Report.query.count(),
    }
    if verbose:
        print("\nSeeded database contents")
        print("-" * 52)
        for key, value in counts.items():
            print(f"  {key.replace('_', ' '):<22} {value}")
        print("-" * 52)
        print("Demo credentials (fictional accounts, demo use only)")
        print("  Administrator     admin       / Admin@Phish2026")
        print("  Security analyst  analyst     / Analyst@Phish2026")
        print(f"  Demo participant  priya.demo  / {DEMO_PASSWORD}")
        print(f"  (all other *.demo accounts also use {DEMO_PASSWORD})")
        admin_key = ISSUED_API_KEYS.get("admin")
        if admin_key:
            print("-" * 52)
            print("API key for 'admin' (shown once - only a digest is stored):")
            print(f"  {admin_key}")
            print("  Lost it? Sign in, open /profile and rotate the key.")
        print("-" * 52)
    return counts


def _seed(reset: bool, verbose: bool) -> dict:
    if reset:
        _log("Dropping existing tables...", verbose)
        db.drop_all()
    db.create_all()
    _log("Seeding demo data...", verbose)

    users = _make_users(verbose)
    admin = users["admin"]
    analyst = users["analyst"]
    participants = [u for u in users.values() if u.role == Role.DEMO_USER]

    for spec in CAMPAIGNS:
        _seed_campaign(spec, admin if spec["organization"] == CYBERSAFE else users["nadia.analyst"],
                       participants, verbose)

    _seed_url_analyses(analyst, verbose)
    _seed_email_analyses(analyst, verbose)
    _seed_quiz_attempts(users, verbose)
    _seed_reports(admin, analyst, verbose)
    _seed_audit_trail(users, verbose)
    return _summary(verbose)


def seed(reset: bool = False, verbose: bool = True) -> dict:
    """Seed the database, creating an application context when needed."""
    if has_app_context():
        return _seed(reset, verbose)
    from app import create_app

    app = create_app()
    with app.app_context():
        return _seed(reset, verbose)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed PhishGuard with fictional demo data.")
    parser.add_argument("--reset", action="store_true",
                        help="Drop all tables before seeding (destroys existing data).")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    args = parser.parse_args()
    seed(reset=args.reset, verbose=not args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
