"""Campaign lifecycle, dashboard analytics and the simulator's safety rails."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest

from app.extensions import db as _db
from app.models.campaign import Campaign, CampaignStatus, CampaignTarget
from app.models.simulation import EventType, SimulationEvent
from app.models.user import User
from app.services.campaign_service import (CampaignError, awareness_score_for, campaign_stats,
                                           create_campaign, dashboard_stats, record_event)
from app.services.simulation_templates import TEMPLATES, get_template

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "app" / "templates" / "simulator"


# ------------------------------------------------------------------ safety
def test_five_simulation_templates_are_available():
    assert len(TEMPLATES) == 5
    assert set(TEMPLATES) == {"password_expiry", "delivery_notification", "hr_policy",
                              "it_security_alert", "account_verification"}


def test_every_template_uses_reserved_fictional_domains():
    for key, template in TEMPLATES.items():
        domain = template.from_address.split("@")[-1]
        assert domain.endswith((".example", ".invalid", ".test")), f"{key} uses {domain}"


def test_every_template_carries_teaching_material():
    for key, template in TEMPLATES.items():
        assert template.indicators, f"{key} must list the red flags it demonstrates"
        assert template.teaching_points, f"{key} must provide teaching points"
        for indicator in template.indicators:
            assert indicator["title"] and indicator["detail"]


def test_simulator_templates_contain_no_credential_inputs():
    """The single most important safety property of this project."""
    password_input = re.compile(r"""type\s*=\s*["']password["']""", re.IGNORECASE)
    credential_name = re.compile(
        r"""<input[^>]*name\s*=\s*["'](?:username|user|email|password|pass|otp|pin|card)""",
        re.IGNORECASE,
    )
    for path in TEMPLATE_DIR.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert not password_input.search(text), f"{path.name} contains a password field"
        assert not credential_name.search(text), f"{path.name} contains a credential field"


def test_credential_collection_is_disabled_by_configuration(app):
    assert app.config["SIMULATION_COLLECT_CREDENTIALS"] is False


def test_only_four_event_types_can_ever_be_recorded():
    assert set(EventType.ALL) == {"OPENED", "LINK_CLICKED", "TRAINING_PAGE_VIEWED", "REPORTED"}


def test_unknown_event_types_are_rejected(app, campaign):
    with app.app_context():
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        with pytest.raises(CampaignError):
            record_event(target, "PASSWORD_SUBMITTED")


# ------------------------------------------------------------ campaign CRUD
def test_campaign_creation_enrols_targets_with_unique_tokens(app, campaign):
    with app.app_context():
        created = _db.session.get(Campaign, campaign.id)
        assert created.status == CampaignStatus.ACTIVE
        assert created.targets.count() == 2
        targets = created.targets.all()
        assert len({t.access_token for t in targets}) == 2
        assert len({t.simulated_message_id for t in targets}) == 2
        for target in targets:
            assert target.simulated_message_id.startswith("SIM-")
            assert len(target.access_token) >= 24


def test_campaign_requires_a_known_template(app, users):
    with app.app_context():
        with pytest.raises(CampaignError):
            create_campaign(name="Bad", description="", template_key="not_a_template",
                            difficulty="MEDIUM", start_date=date.today(), end_date=None,
                            target_ids=[users.demo.id],
                            creator=_db.session.get(User, users.admin.id))


def test_campaign_requires_at_least_one_participant(app, users):
    with app.app_context():
        with pytest.raises(CampaignError):
            create_campaign(name="Empty", description="", template_key="password_expiry",
                            difficulty="MEDIUM", start_date=date.today(), end_date=None,
                            target_ids=[], creator=_db.session.get(User, users.admin.id))


def test_campaign_can_be_created_through_the_ui(app, admin_client, users):
    response = admin_client.post("/campaigns/create", data={
        "name": "UI created drill", "description": "Created by the test-suite.",
        "template_key": "hr_policy", "difficulty": "EASY",
        "start_date": date.today().isoformat(),
        "targets": [users.demo.id, users.demo2.id],
        "status": CampaignStatus.ACTIVE,
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        created = Campaign.query.filter_by(name="UI created drill").first()
        assert created is not None
        assert created.targets.count() == 2


def test_campaign_status_can_be_updated(app, admin_client, campaign):
    admin_client.post(f"/campaigns/{campaign.id}/status",
                      data={"status": CampaignStatus.COMPLETED}, follow_redirects=True)
    with app.app_context():
        assert _db.session.get(Campaign, campaign.id).status == CampaignStatus.COMPLETED


def test_deleting_a_campaign_removes_its_targets_and_events(app, admin_client, campaign):
    with app.app_context():
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        record_event(target, EventType.OPENED)
    response = admin_client.post(f"/campaigns/{campaign.id}/delete", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert _db.session.get(Campaign, campaign.id) is None
        assert CampaignTarget.query.filter_by(campaign_id=campaign.id).count() == 0
        assert SimulationEvent.query.filter_by(campaign_id=campaign.id).count() == 0


def test_template_lookup_rejects_unknown_keys():
    assert get_template("password_expiry").key == "password_expiry"
    assert get_template("nope") is None


# ------------------------------------------------------------- participation
def test_simulated_message_page_records_an_open_event(app, demo_client, campaign):
    token = campaign.tokens["priya.demo"]
    assert demo_client.get(f"/simulator/message/{token}").status_code == 200
    with app.app_context():
        target = CampaignTarget.query.filter_by(access_token=token).one()
        events = SimulationEvent.query.filter_by(
            simulated_message_id=target.simulated_message_id).all()
        assert [event.event_type for event in events] == [EventType.OPENED]


def test_message_page_shows_the_simulation_banner_and_no_form_inputs(demo_client, campaign):
    body = demo_client.get(
        f"/simulator/message/{campaign.tokens['priya.demo']}").get_data(as_text=True)
    assert "SAFE SIMULATION" in body.upper()
    assert 'type="password"' not in body


def test_clicking_the_link_records_a_click_then_shows_the_training_page(app, demo_client,
                                                                       campaign, users):
    response = demo_client.get(f"/simulator/click/{campaign.tokens['priya.demo']}",
                               follow_redirects=True)
    assert response.status_code == 200
    assert "simulation" in response.get_data(as_text=True).lower()
    with app.app_context():
        recorded = {event.event_type for event
                    in SimulationEvent.query.filter_by(user_id=users.demo.id).all()}
    assert EventType.LINK_CLICKED in recorded
    assert EventType.TRAINING_PAGE_VIEWED in recorded


def test_landing_page_teaches_instead_of_harvesting(demo_client, campaign):
    body = demo_client.get(
        f"/simulator/landing/{campaign.tokens['priya.demo']}").get_data(as_text=True)
    assert 'type="password"' not in body
    assert "red flag" in body.lower() or "indicator" in body.lower()


def test_reporting_a_message_is_recorded(app, demo_client, campaign, users):
    response = demo_client.post(f"/simulator/report/{campaign.tokens['priya.demo']}",
                                follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        events = SimulationEvent.query.filter_by(user_id=users.demo.id,
                                                 event_type=EventType.REPORTED).all()
    assert len(events) == 1


def test_invalid_token_returns_404(demo_client):
    assert demo_client.get("/simulator/message/not-a-real-token").status_code == 404


def test_recorded_events_never_carry_submitted_credentials(app, demo_client, campaign):
    demo_client.get(f"/simulator/click/{campaign.tokens['priya.demo']}", follow_redirects=True)
    with app.app_context():
        for event in SimulationEvent.query.all():
            serialised = f"{event.event_type} {event.note or ''}"
            assert "password" not in serialised.lower()
            columns = {c.name for c in SimulationEvent.__table__.columns}
            assert not columns & {"password", "credential", "card_number", "otp"}


# ----------------------------------------------------------------- analytics
def test_awareness_score_rewards_reporting_and_penalises_clicking(app, campaign):
    with app.app_context():
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        opened = record_event(target, EventType.OPENED)
        clicked = record_event(target, EventType.LINK_CLICKED)
        trained = record_event(target, EventType.TRAINING_PAGE_VIEWED)
        reported = record_event(target, EventType.REPORTED)

        assert awareness_score_for([opened]) == 55           # 60 - 5
        assert awareness_score_for([opened, clicked]) == 30   # 60 - 5 - 25
        assert awareness_score_for([opened, clicked, trained]) == 40
        assert awareness_score_for([opened, reported]) == 85
        assert 0 <= awareness_score_for([clicked] * 20) <= 100


def test_campaign_stats_are_labelled_as_simulation_metrics(app, campaign):
    with app.app_context():
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        record_event(target, EventType.OPENED)
        record_event(target, EventType.LINK_CLICKED)
        stats = campaign_stats(_db.session.get(Campaign, campaign.id))
    assert stats["participants"] == 2
    assert stats["event_counts"][EventType.OPENED] == 1
    assert stats["interaction_rate"] == 50.0
    assert "simulation" in stats["metric_note"].lower()
    assert stats["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert len(stats["participant_rows"]) == 2


def test_campaign_risk_thresholds_are_configurable(app, campaign):
    with app.app_context():
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        record_event(target, EventType.LINK_CLICKED)   # 1 of 2 clicked -> 50%
        assert campaign_stats(_db.session.get(Campaign, campaign.id))["risk_level"] == "CRITICAL"
        app.config["CAMPAIGN_RISK_THRESHOLDS"] = ((60, "LOW"), (80, "MEDIUM"), (95, "HIGH"))
        assert campaign_stats(_db.session.get(Campaign, campaign.id))["risk_level"] == "LOW"


def test_dashboard_stats_shape(app, campaign):
    with app.app_context():
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        record_event(target, EventType.OPENED)
        stats = dashboard_stats()
    assert set(stats["charts"]) >= {"activity", "risk_distribution", "detection_split",
                                    "campaign_performance", "awareness_improvement"}
    assert len(stats["charts"]["activity"]["labels"]) == 14
    assert "simulation" in stats["metric_note"].lower()


def test_dashboard_numbers_come_from_the_database(app, campaign):
    """No hardcoded statistics: the KPIs must move when the data moves."""
    with app.app_context():
        before = dashboard_stats()["kpis"]
        target = CampaignTarget.query.filter_by(campaign_id=campaign.id).first()
        record_event(target, EventType.OPENED)
        record_event(target, EventType.LINK_CLICKED)
        after = dashboard_stats()["kpis"]
    assert after["simulation_interactions"] == before["simulation_interactions"] + 2
    assert after["link_clicks"] == before["link_clicks"] + 1
    assert after["engaged_users"] >= before["engaged_users"]


def test_dashboard_starts_empty_on_a_fresh_database(app, users):
    with app.app_context():
        kpis = dashboard_stats()["kpis"]
    assert kpis["total_campaigns"] == 0
    assert kpis["total_analyses"] == 0
    assert kpis["simulation_interactions"] == 0
