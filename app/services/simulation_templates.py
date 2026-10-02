"""Catalogue of SAFE phishing-awareness simulation templates.

Every template is a *teaching artefact*: it renders a realistic-looking
message inside PhishGuard's own interface, and the only link it contains
points back to PhishGuard's awareness landing page.

SAFETY INVARIANTS
-----------------
* No template contains a credential form, attachment or external endpoint.
* Bodies are stored as plain-text paragraphs and escaped by Jinja on render,
  so templates cannot inject HTML/JS into the application.
* Sender addresses use RFC 2606 reserved names (``.example``/``.invalid``)
  and fictional organisations only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SimulationTemplate:
    key: str
    name: str
    category: str
    difficulty: str
    from_name: str
    from_address: str
    subject: str
    preheader: str
    paragraphs: list[str]
    cta_text: str
    displayed_link: str          # what the victim *thinks* the link is
    indicators: list[dict]       # red flags taught on the landing page
    teaching_points: list[str]
    legitimate_equivalent: str

    def to_dict(self) -> dict:
        return asdict(self)


TEMPLATES: dict[str, SimulationTemplate] = {
    "password_expiry": SimulationTemplate(
        key="password_expiry",
        name="Password expiry notice",
        category="Credential phishing",
        difficulty="EASY",
        from_name="CyberSafe IT Service Desk",
        from_address="it-servicedesk@cybersafe-notices.example",
        subject="Action required: your password expires in 24 hours",
        preheader="Re-validate your directory account to avoid losing access.",
        paragraphs=[
            "Dear User,",
            "Our records show that the password for your Andhra University "
            "directory account is scheduled to expire in less than 24 hours. "
            "Accounts that are not re-validated before the deadline are "
            "automatically suspended by the identity platform.",
            "To keep your access, re-validate your account using the secure "
            "portal link below. This process takes less than one minute.",
            "If you do not complete this step, you will lose access to email, "
            "shared drives and the virtual learning environment.",
            "Regards,\nIT Service Desk\nAndhra University",
        ],
        cta_text="Re-validate my account",
        displayed_link="https://portal.cybersafe.edu/password/renew",
        indicators=[
            {"title": "Mismatched link destination",
             "detail": "The button text showed portal.cybersafe.edu, but the real destination was a different host. Hover over links before clicking."},
            {"title": "Manufactured deadline",
             "detail": "'Expires in 24 hours' exists to stop you from verifying. Real password policies warn you repeatedly, well in advance."},
            {"title": "Look-alike sender domain",
             "detail": "cybersafe-notices.example is not the university's domain (cybersafe.edu). Attackers register similar-looking domains."},
            {"title": "Generic greeting",
             "detail": "'Dear User' - the IT department already knows your name."},
            {"title": "Threat of losing access",
             "detail": "Fear of suspension is the lever. Genuine notices do not threaten immediate account closure."},
        ],
        teaching_points=[
            "Change passwords only from a bookmarked portal URL you typed yourself.",
            "Check the sender's full address, not just the display name.",
            "If a message creates time pressure, that is itself a reason to slow down.",
        ],
        legitimate_equivalent="Real expiry notices come from your organisation's own domain, address you by name and never require a link to act.",
    ),
    "delivery_notification": SimulationTemplate(
        key="delivery_notification",
        name="Parcel delivery failure",
        category="Consumer lure / smishing crossover",
        difficulty="EASY",
        from_name="Global Parcel Express",
        from_address="tracking@gpx-delivery-alerts.example",
        subject="Delivery attempt failed - reschedule your parcel (GPX-4471902)",
        preheader="Your package is held at the depot pending a small redelivery fee.",
        paragraphs=[
            "Hello,",
            "We attempted to deliver your parcel today but nobody was available "
            "to accept it. The package is currently held at our regional depot.",
            "A redelivery fee of 1.99 is outstanding. Confirm your delivery "
            "preferences within 48 hours or the parcel will be returned to the "
            "sender and the shipping fee forfeited.",
            "Tracking reference: GPX-4471902",
            "Global Parcel Express Customer Care",
        ],
        cta_text="Reschedule my delivery",
        displayed_link="https://gpx-delivery.example/track/GPX-4471902",
        indicators=[
            {"title": "Unexpected parcel",
             "detail": "You were not expecting this delivery. Unsolicited parcel notices are one of the highest-volume phishing lures."},
            {"title": "Small payment request",
             "detail": "A tiny fee lowers suspicion while harvesting card details on the landing page."},
            {"title": "Unknown courier domain",
             "detail": "gpx-delivery-alerts.example is not a courier you have a contract with."},
            {"title": "Deadline pressure",
             "detail": "'Within 48 hours or returned' forces a fast, careless decision."},
        ],
        teaching_points=[
            "Track parcels only through the retailer's order page or the courier app.",
            "Couriers never ask for card details over email links for domestic redelivery.",
            "Check whether you actually ordered anything before reacting.",
        ],
        legitimate_equivalent="Genuine couriers reference a real order number you can confirm in your retailer account and do not demand instant payment.",
    ),
    "hr_policy": SimulationTemplate(
        key="hr_policy",
        name="HR policy acknowledgement",
        category="Internal-process spear phishing",
        difficulty="MEDIUM",
        from_name="Human Resources - Example Corporation",
        from_address="hr-policy@examplecorp-hr.example",
        subject="Mandatory: acknowledge the revised remote working policy today",
        preheader="Unacknowledged staff will be reported to their line manager.",
        paragraphs=[
            "Dear Colleague,",
            "The revised Remote Working and Acceptable Use Policy takes effect "
            "from Monday. All staff are required to review and acknowledge the "
            "document through the HR portal before the end of the working day.",
            "Acknowledgement is tracked. Employees who have not signed by the "
            "deadline will be listed in the compliance report circulated to "
            "department heads.",
            "Please use your network credentials to sign in to the portal.",
            "Human Resources\nExample Corporation",
        ],
        cta_text="Review and acknowledge the policy",
        displayed_link="https://hr.example-corp.com/policies/remote-working",
        indicators=[
            {"title": "Authority + social pressure",
             "detail": "Naming a compliance report that goes to managers pressures you to act without checking."},
            {"title": "Credential prompt",
             "detail": "'Use your network credentials' is the pay-off - the attacker wants a single-sign-on password."},
            {"title": "Near-miss domain",
             "detail": "examplecorp-hr.example is not example-corp.com. One hyphen changes the owner of a domain."},
            {"title": "Same-day deadline",
             "detail": "Policy roll-outs normally allow weeks, not hours."},
        ],
        teaching_points=[
            "Reach internal portals from the intranet homepage or a bookmark.",
            "HR announcements can be confirmed with a quick message to a colleague.",
            "Single-sign-on prompts arriving from email links deserve extra scrutiny.",
        ],
        legitimate_equivalent="Real HR communications come from the corporate domain and are usually mirrored on the intranet, where you can verify them independently.",
    ),
    "it_security_alert": SimulationTemplate(
        key="it_security_alert",
        name="IT security alert - suspicious sign-in",
        category="Credential phishing",
        difficulty="MEDIUM",
        from_name="Security Operations Centre",
        from_address="soc-alerts@cybersafe-security.example",
        subject="Security alert: unrecognised sign-in from Kyiv, UA",
        preheader="Review this activity now or your account will be locked.",
        paragraphs=[
            "Security notification",
            "A sign-in to your account was detected from an unrecognised device:",
            "Location: Kyiv, UA\nDevice: Windows 10 - Chrome 118\nTime: today, 03:14 local time",
            "If this was not you, review the activity immediately and confirm "
            "your identity. Failure to respond within 12 hours will result in a "
            "precautionary account lock.",
            "Security Operations Centre",
        ],
        cta_text="Review this sign-in activity",
        displayed_link="https://security.cybersafe.edu/activity/review",
        indicators=[
            {"title": "Alarming but unverifiable detail",
             "detail": "Precise-looking device and location data feels authentic yet cannot be checked from the email itself."},
            {"title": "Fear trigger",
             "detail": "'Unrecognised sign-in' pushes you to click before thinking - the single most effective phishing pattern."},
            {"title": "Sender is not the real SOC domain",
             "detail": "cybersafe-security.example is not cybersafe.edu."},
            {"title": "Threatened lock-out",
             "detail": "A deadline plus a consequence is the standard phishing structure."},
        ],
        teaching_points=[
            "Check sign-in activity from your account's security page, not an email link.",
            "Real security teams tell you how to reach them through official channels.",
            "Enable phishing-resistant MFA so a stolen password alone is not enough.",
        ],
        legitimate_equivalent="Genuine providers show the same alert inside the account security dashboard, so you never need to trust the email.",
    ),
    "account_verification": SimulationTemplate(
        key="account_verification",
        name="Account verification required",
        category="Credential phishing",
        difficulty="HARD",
        from_name="CyberSafe Student Finance",
        from_address="no-reply@cybersafe.edu.verify-student.example",
        subject="Re: Scholarship disbursement - identity verification pending",
        preheader="Your disbursement is on hold until verification completes.",
        paragraphs=[
            "Hello,",
            "Thank you for your recent scholarship application. Before the "
            "disbursement can be released, the finance system requires a "
            "one-time identity verification against your student record.",
            "This is a standard control introduced this term. The verification "
            "page will ask you to confirm your student ID and sign in with your "
            "university account.",
            "Applications that remain unverified after 72 hours are returned to "
            "the review queue and the disbursement is delayed by one cycle.",
            "Student Finance Office",
        ],
        cta_text="Complete identity verification",
        displayed_link="https://finance.cybersafe.edu/verification",
        indicators=[
            {"title": "Subdomain trick",
             "detail": "cybersafe.edu.verify-student.example LOOKS like cybersafe.edu, but the owning domain is verify-student.example. Always read a domain from right to left."},
            {"title": "Fake reply prefix",
             "detail": "'Re:' implies an existing conversation you never started."},
            {"title": "Money as motivation",
             "detail": "A pending payment makes the target cooperative and compliant."},
            {"title": "Plausible bureaucracy",
             "detail": "Invented but believable processes ('standard control introduced this term') defeat casual scepticism."},
            {"title": "Soft deadline",
             "detail": "72 hours is long enough to sound reasonable and short enough to discourage checking."},
        ],
        teaching_points=[
            "Read domains right to left: the part before the final slash is what matters.",
            "Payment-related requests deserve a phone call to a number you already have.",
            "When a process is new to you, confirm it exists before following it.",
        ],
        legitimate_equivalent="Finance offices publish verification steps on the official portal and never chain identity checks to an emailed deadline.",
    ),
}


def list_templates() -> list[SimulationTemplate]:
    return list(TEMPLATES.values())


def get_template(key: str) -> SimulationTemplate | None:
    return TEMPLATES.get(key)


def template_choices() -> list[tuple[str, str]]:
    return [(t.key, f"{t.name} ({t.category})") for t in TEMPLATES.values()]
