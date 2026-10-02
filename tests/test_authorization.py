"""Role-based access control.

Every assertion here runs against a client whose identity is established
purely by its session cookie.  See ``tests/conftest`` for why that matters:
a previous version of the fixtures leaked one client's identity into every
other request, which would have made this entire module vacuous.
"""

from __future__ import annotations

import pytest

from app.models.audit_log import AuditAction, AuditLog
from app.models.user import Role, User

#: (path, admin, analyst, demo, anonymous)
PAGE_MATRIX = [
    ("/dashboard",        200, 200, 403, 302),
    ("/dashboard/data",   200, 200, 403, 302),
    ("/campaigns",        200, 200, 403, 302),
    ("/campaigns/create", 200, 200, 403, 302),
    ("/url-detector",     200, 200, 403, 302),
    ("/email-detector",   200, 200, 403, 302),
    ("/reports",          200, 200, 403, 302),
    ("/audit-logs",       200, 403, 403, 302),
    ("/users",            200, 403, 403, 302),
    ("/awareness",        200, 200, 200, 302),
    ("/quiz",             200, 200, 200, 302),
    ("/profile",          200, 200, 200, 302),
    ("/simulator",        200, 200, 200, 302),
]


@pytest.mark.parametrize("path,admin,analyst,demo,anon", PAGE_MATRIX)
def test_page_access_matrix(admin_client, analyst_client, demo_client, client,
                            path, admin, analyst, demo, anon):
    assert admin_client.get(path).status_code == admin, f"admin {path}"
    assert analyst_client.get(path).status_code == analyst, f"analyst {path}"
    assert demo_client.get(path).status_code == demo, f"demo {path}"
    assert client.get(path).status_code == anon, f"anonymous {path}"


@pytest.mark.parametrize("path", [p[0] for p in PAGE_MATRIX])
def test_unauthenticated_requests_are_redirected_to_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_demo_user_cannot_reach_admin_functions_by_typing_the_url(demo_client, users, campaign):
    """The headline requirement: URL-guessing must not escalate privilege."""
    forbidden_gets = ["/audit-logs", "/users", "/campaigns/create", "/dashboard",
                      "/reports", "/url-detector", "/email-detector",
                      f"/campaigns/{campaign.id}"]
    for path in forbidden_gets:
        assert demo_client.get(path).status_code == 403, f"GET {path}"

    forbidden_posts = [
        ("/campaigns/create", {"name": "x", "template_key": "hr_policy", "target_ids": [1]}),
        (f"/campaigns/{campaign.id}/status", {"status": "COMPLETED"}),
        (f"/campaigns/{campaign.id}/delete", {}),
        (f"/users/{users.admin.id}/role", {"role": Role.DEMO_USER}),
        (f"/users/{users.admin.id}/status", {"active": "0"}),
        ("/url-detector", {"url": "http://example.invalid"}),
        ("/email-detector", {"sender": "a@b.invalid", "subject": "s", "body": "b"}),
    ]
    for path, payload in forbidden_posts:
        assert demo_client.post(path, data=payload).status_code == 403, f"POST {path}"


def test_analyst_cannot_perform_admin_only_actions(analyst_client, users, campaign):
    assert analyst_client.get("/users").status_code == 403
    assert analyst_client.get("/audit-logs").status_code == 403
    assert analyst_client.post(f"/campaigns/{campaign.id}/delete").status_code == 403
    assert analyst_client.post(f"/users/{users.demo.id}/role",
                               data={"role": Role.ADMIN}).status_code == 403


def test_analyst_can_use_the_analysis_workspace(analyst_client):
    assert analyst_client.get("/url-detector").status_code == 200
    assert analyst_client.get("/email-detector").status_code == 200
    assert analyst_client.get("/campaigns/create").status_code == 200


def test_admin_can_reach_every_area(admin_client):
    for path in ("/dashboard", "/campaigns", "/url-detector", "/email-detector",
                 "/reports", "/audit-logs", "/users", "/awareness", "/quiz", "/profile"):
        assert admin_client.get(path).status_code == 200, path


def test_role_capabilities_are_distinct():
    admin = set(Role.capabilities_for(Role.ADMIN))
    analyst = set(Role.capabilities_for(Role.ANALYST))
    demo = set(Role.capabilities_for(Role.DEMO_USER))
    assert "user.manage" in admin and "user.manage" not in analyst
    assert "audit.view" in admin and "audit.view" not in analyst
    assert "campaign.create" in analyst and "campaign.create" not in demo
    assert "campaign.delete" in admin and "campaign.delete" not in analyst
    assert demo.issubset(admin)


def test_admin_cannot_demote_self(app, admin_client, users):
    admin_client.post(f"/users/{users.admin.id}/role",
                      data={"role": Role.DEMO_USER}, follow_redirects=True)
    with app.app_context():
        assert User.query.filter_by(username="admin").one().role == Role.ADMIN


def test_admin_can_change_another_users_role_and_it_is_audited(app, admin_client, users):
    response = admin_client.post(f"/users/{users.demo2.id}/role",
                                 data={"role": Role.ANALYST}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert User.query.filter_by(username="liam.demo").one().role == Role.ANALYST
        assert AuditLog.query.filter_by(action=AuditAction.ROLE_CHANGED).count() == 1


def test_a_participant_cannot_open_another_participants_simulated_message(demo_client, campaign):
    other_token = campaign.tokens["liam.demo"]
    assert demo_client.get(f"/simulator/message/{other_token}").status_code == 403


def test_denied_access_is_recorded_in_the_audit_trail(app, demo_client):
    demo_client.get("/audit-logs")
    with app.app_context():
        actions = {entry.action for entry in AuditLog.query.all()}
    assert AuditAction.ACCESS_DENIED in actions
