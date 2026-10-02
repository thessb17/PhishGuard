"""Security-awareness training content and the default quiz bank.

Content is stored as structured data (not HTML) so Jinja escapes it on render
and the same material can be served through the UI, the API and reports.
"""

from __future__ import annotations

TOPICS: list[dict] = [
    {
        "slug": "what-is-phishing",
        "title": "What is phishing?",
        "icon": "bi-envelope-exclamation",
        "summary": "Social engineering delivered by message: an attacker impersonates a trusted party to make you act against your own interest.",
        "sections": [
            {
                "heading": "The mechanics",
                "body": "Phishing works on people, not software. The attacker borrows the identity of "
                        "something you already trust - your IT department, a courier, a bank, a "
                        "colleague - and attaches a request to it: click a link, open an attachment, "
                        "approve a payment, read a QR code. The message is engineered so that "
                        "complying feels faster and safer than checking.",
            },
            {
                "heading": "Why it still works",
                "body": "Modern phishing is cheap to send, easy to personalise with public data and "
                        "increasingly well written. Defences that depend only on spotting bad spelling "
                        "are obsolete. What still works is process: verify requests through a channel "
                        "you chose yourself, and treat urgency as a warning sign rather than a reason "
                        "to hurry.",
            },
            {
                "heading": "The anatomy of a phishing message",
                "body": "Almost every phishing message has four parts: a trusted-looking sender, a "
                        "pretext (a story that explains the request), a lever (urgency, fear, authority, "
                        "reward or curiosity) and a payload (the link, attachment, QR code or reply "
                        "the attacker actually wants). Learn to name those four parts and the message "
                        "stops being persuasive.",
            },
        ],
        "tips": [
            "Treat unexpected requests for credentials, payments or data as hostile until verified.",
            "Verify through a channel you already trust - a bookmark, a saved phone number, a walk to a desk.",
            "Reporting a real message that turns out to be legitimate costs nothing; the reverse is expensive.",
        ],
    },
    {
        "slug": "types-of-phishing",
        "title": "Types of phishing",
        "icon": "bi-diagram-3",
        "summary": "Bulk phishing, spear phishing, whaling, clone phishing and pharming differ mainly in targeting and effort.",
        "sections": [
            {
                "heading": "Bulk phishing",
                "body": "Millions of identical messages sent indiscriminately. Generic greetings, "
                        "well-known brands, low personalisation. Filters catch most of it, so anything "
                        "that reaches your inbox has already survived several layers of defence.",
            },
            {
                "heading": "Spear phishing and whaling",
                "body": "Targeted at one person or a small group, using real names, real projects and "
                        "real reporting lines gathered from LinkedIn, GitHub, conference programmes and "
                        "previous breaches. Whaling is spear phishing aimed at executives, where a "
                        "single success authorises a large transfer.",
            },
            {
                "heading": "Clone phishing and thread hijacking",
                "body": "The attacker copies a genuine message you already received - or replies inside "
                        "a stolen mail thread - and swaps the link or attachment. Because the context is "
                        "real, scepticism drops. Check whether the reply actually advances the "
                        "conversation and whether the sending address changed.",
            },
        ],
        "tips": [
            "Personalised detail proves research, not identity.",
            "A reply inside a known thread can still come from a compromised mailbox.",
            "The more a message flatters or pressures you, the more verification it deserves.",
        ],
    },
    {
        "slug": "spear-phishing",
        "title": "Spear phishing",
        "icon": "bi-bullseye",
        "summary": "Research-driven, one-to-one attacks that quote real projects, real colleagues and real deadlines.",
        "sections": [
            {
                "heading": "How targets are chosen",
                "body": "Attackers map an organisation from public sources: the website's team page, "
                        "job adverts (which reveal the technology stack), conference talks, code "
                        "repositories and social media. Finance, HR, IT support and executive assistants "
                        "are prioritised because they can move money, data or access.",
            },
            {
                "heading": "What a good one looks like",
                "body": "Correct signature block, correct internal jargon, correct project name, plausible "
                        "timing (right after a real all-hands or a public funding announcement) and a "
                        "small, reasonable ask. The first message often contains no link at all - it just "
                        "establishes a conversation.",
            },
        ],
        "tips": [
            "Out-of-band verification matters most when the request is plausible.",
            "Be suspicious of first contact that moves quickly to a private channel.",
            "Limit what your public profiles reveal about internal processes and tooling.",
        ],
    },
    {
        "slug": "smishing",
        "title": "Smishing (SMS phishing)",
        "icon": "bi-phone",
        "summary": "SMS and messaging-app phishing: short, urgent, link-heavy and hard to inspect on a phone.",
        "sections": [
            {
                "heading": "Why SMS is effective",
                "body": "Phone screens truncate URLs, mobile browsers hide the address bar while "
                        "scrolling, and texts feel personal. Delivery failures, bank alerts, toll fines "
                        "and 'is this you?' one-time-code messages dominate the category.",
            },
            {
                "heading": "The OTP relay trick",
                "body": "A common pattern: the attacker already has your password and triggers a real "
                        "login. You receive a genuine one-time code, then a text or call claiming to be "
                        "the provider's fraud team asking you to read it out. The code is real; the "
                        "caller is not. No legitimate organisation ever asks for a one-time code.",
            },
        ],
        "tips": [
            "Never read a one-time code to anyone, on any channel, for any reason.",
            "Open your banking or courier app directly instead of tapping the text's link.",
            "Report smishing to your provider and to your security team.",
        ],
    },
    {
        "slug": "vishing",
        "title": "Vishing (voice phishing)",
        "icon": "bi-telephone",
        "summary": "Phone-based social engineering, now frequently combined with spoofed caller ID and synthetic voices.",
        "sections": [
            {
                "heading": "The pretext call",
                "body": "'This is the IT service desk, we're seeing malware on your machine.' The caller "
                        "sounds calm, competent and busy. They may quote real internal details harvested "
                        "from a previous phishing email or a public breach, then ask you to install a "
                        "remote-support tool or approve an MFA prompt.",
            },
            {
                "heading": "Voice cloning",
                "body": "A few seconds of recorded speech is enough to clone a voice convincingly. Treat "
                        "voice as identification only when it arrives on a channel you initiated - a "
                        "callback to a number from the internal directory, never a number the caller "
                        "supplies.",
            },
        ],
        "tips": [
            "Hang up and call back on a number you looked up yourself.",
            "Never approve an MFA prompt you did not personally trigger.",
            "Agree a verbal challenge phrase for high-value finance approvals.",
        ],
    },
    {
        "slug": "business-email-compromise",
        "title": "Business Email Compromise (BEC)",
        "icon": "bi-briefcase",
        "summary": "Low-tech, high-value fraud: invoice redirection, payroll diversion, gift-card scams and CEO impersonation.",
        "sections": [
            {
                "heading": "Invoice and payroll redirection",
                "body": "The attacker monitors a compromised mailbox, waits for a genuine invoice, then "
                        "sends 'updated bank details' at exactly the right moment. Payroll variants ask "
                        "HR to change an employee's salary account before the monthly run.",
            },
            {
                "heading": "Why BEC beats filters",
                "body": "There is often no link, no attachment and no malware - just text. Many BEC "
                        "messages are sent from genuine but compromised accounts, so SPF, DKIM and DMARC "
                        "all pass. Only process controls stop it.",
            },
        ],
        "tips": [
            "Any change of bank details requires callback verification to a pre-existing number.",
            "Enforce dual authorisation above a defined payment threshold.",
            "Gift-card requests from executives are fraud, without exception.",
        ],
    },
    {
        "slug": "credential-phishing",
        "title": "Credential phishing",
        "icon": "bi-key",
        "summary": "Fake sign-in pages that capture usernames, passwords and - with a proxy - live session cookies.",
        "sections": [
            {
                "heading": "The fake portal",
                "body": "A pixel-perfect copy of a login page, hosted on a look-alike domain or a "
                        "compromised legitimate site. Some kits pre-fill your email address so the page "
                        "feels personalised, and forward you to the real site after capture so nothing "
                        "seems wrong.",
            },
            {
                "heading": "Adversary-in-the-middle and MFA fatigue",
                "body": "Reverse-proxy kits relay your credentials AND your MFA response to the real "
                        "service in real time, stealing the resulting session cookie. Push-notification "
                        "MFA is also attacked by simple repetition until the victim approves. Phishing-"
                        "resistant methods - passkeys, FIDO2 security keys, certificate-based auth - "
                        "are bound to the real domain and defeat both.",
            },
        ],
        "tips": [
            "Reach login pages from bookmarks or the app, never from an email link.",
            "A password manager that refuses to autofill is telling you the domain is wrong.",
            "Prefer passkeys or hardware security keys over SMS and push approvals.",
        ],
    },
    {
        "slug": "qr-phishing",
        "title": "QR phishing (quishing)",
        "icon": "bi-qr-code",
        "summary": "A QR code moves the victim from a monitored corporate laptop to an unmanaged personal phone.",
        "sections": [
            {
                "heading": "Why attackers love QR codes",
                "body": "The destination is unreadable to a human, image-based codes slip past text "
                        "scanners, and scanning usually happens on a personal phone that has no "
                        "corporate web filtering, no EDR and no managed browser.",
            },
            {
                "heading": "Where they appear",
                "body": "Inside PDF attachments ('scan to view the secure document'), in printed posters "
                        "and parking meters where a sticker is placed over the genuine code, and in MFA "
                        "enrolment emails that ask you to 're-register your authenticator'.",
            },
        ],
        "tips": [
            "Preview the decoded URL before opening it - most phone cameras show it first.",
            "Type known URLs manually instead of scanning codes that arrive by email.",
            "Inspect physical QR codes for stickers placed over the original.",
        ],
    },
    {
        "slug": "inspect-links",
        "title": "How to inspect links",
        "icon": "bi-link-45deg",
        "summary": "Read a URL right to left: the registrable domain immediately before the first single slash decides who owns the page.",
        "sections": [
            {
                "heading": "Read right to left",
                "body": "In https://login.microsoft.com.secure-verify.tk/account the owner is "
                        "secure-verify.tk - everything to the left is a subdomain the attacker "
                        "controls. Find the first single slash after the scheme, then read backwards "
                        "from it to the second dot.",
            },
            {
                "heading": "Common obfuscation tricks",
                "body": "'@' hides everything before it; punycode (xn--) renders as look-alike letters; "
                        "percent-encoding hides keywords; open redirects borrow a trusted domain; URL "
                        "shorteners hide the destination completely; and a padlock only means the "
                        "transport is encrypted, never that the site is honest.",
            },
        ],
        "tips": [
            "Hover on desktop, long-press on mobile, and compare what you see with what was written.",
            "Paste suspicious URLs into the PhishGuard URL detector instead of opening them.",
            "HTTPS is table stakes for attackers too - the padlock proves encryption, not identity.",
        ],
    },
    {
        "slug": "inspect-senders",
        "title": "How to inspect email senders",
        "icon": "bi-person-badge",
        "summary": "Display names are free text. Expand the address, check the domain, then check what the headers claim.",
        "sections": [
            {
                "heading": "Display name vs real address",
                "body": "Mail clients show 'IT Service Desk' and hide "
                        "it-desk@random-domain.example. Always expand the sender. On mobile, tap the "
                        "name; on desktop, hover or open the message details.",
            },
            {
                "heading": "SPF, DKIM and DMARC in one minute",
                "body": "SPF checks whether the sending server is authorised for the domain. DKIM checks "
                        "a cryptographic signature over the message. DMARC ties the two to the visible "
                        "From address and tells receivers what to do on failure. All three can pass for "
                        "a message sent from a compromised-but-legitimate account, so authentication "
                        "proves the domain, not the intent.",
            },
        ],
        "tips": [
            "Compare the From domain with the Reply-To and Return-Path domains.",
            "A first-time sender writing about money or access deserves a callback.",
            "Authentication passes are necessary, not sufficient.",
        ],
    },
    {
        "slug": "mfa-safety",
        "title": "MFA safety",
        "icon": "bi-shield-lock",
        "summary": "Multi-factor authentication is essential but not equal: some factors are phishable, others are not.",
        "sections": [
            {
                "heading": "Factor strength",
                "body": "SMS codes can be intercepted, SIM-swapped or relayed. App-generated codes are "
                        "better but can still be typed into a fake page. Push approvals are vulnerable "
                        "to fatigue attacks. Passkeys and FIDO2 security keys are cryptographically "
                        "bound to the real domain, so a look-alike site simply cannot use them.",
            },
            {
                "heading": "Handling unexpected prompts",
                "body": "An MFA prompt you did not trigger means someone already has your password. "
                        "Deny it, change the password immediately from a known-good device and tell the "
                        "security team - they need to look for a session that survived.",
            },
        ],
        "tips": [
            "Never approve a prompt you did not personally initiate.",
            "Never share a one-time code, even with someone claiming to be support.",
            "Register a backup factor so losing a device does not force you onto a weaker method.",
        ],
    },
    {
        "slug": "reporting",
        "title": "Reporting suspicious emails",
        "icon": "bi-flag",
        "summary": "Fast reporting shortens the attacker's window and protects everyone who received the same message.",
        "sections": [
            {
                "heading": "What to do",
                "body": "Do not forward the message as normal text - that strips the headers the "
                        "security team needs. Use the report-phishing button in your mail client, or "
                        "attach the original message (.eml/.msg) to a new mail to the security mailbox. "
                        "Then delete it, and do not warn colleagues by forwarding the original.",
            },
            {
                "heading": "If you already clicked",
                "body": "Report it immediately - speed matters far more than embarrassment. Disconnect "
                        "the device from the network if you ran anything, change the password from a "
                        "different trusted device, and let the team revoke active sessions and tokens. "
                        "Blame-free reporting is a security control, not a courtesy.",
            },
        ],
        "tips": [
            "Report first, investigate later - the security team would rather see ten false alarms.",
            "Include the time you received it and whether you interacted with it.",
            "If you entered credentials anywhere, say so explicitly so sessions can be revoked.",
        ],
    },
]

TOPIC_INDEX = {topic["slug"]: topic for topic in TOPICS}

DEFAULT_QUIZ = {
    "slug": "phishing-awareness-core",
    "title": "Phishing Awareness Assessment",
    "description": "Ten questions covering link inspection, sender verification, MFA safety, "
                   "BEC and incident reporting. A score of 70% or higher is a pass.",
    "pass_mark": 70,
    "questions": [
        {
            "prompt": "In the URL https://login.microsoft.com.secure-verify.tk/session, which domain actually owns the page?",
            "options": ["login.microsoft.com", "microsoft.com", "secure-verify.tk", "com.secure-verify"],
            "correct_index": 2,
            "explanation": "Read a URL right to left from the first single slash. The registrable domain "
                           "is secure-verify.tk; everything to its left is a subdomain the attacker controls.",
            "category": "link-inspection",
        },
        {
            "prompt": "An email is protected by HTTPS and shows a padlock on its landing page. What does that prove?",
            "options": [
                "The site is operated by the brand it imitates",
                "Only that traffic to the site is encrypted in transit",
                "That the site has been security-audited",
                "That the message passed SPF, DKIM and DMARC",
            ],
            "correct_index": 1,
            "explanation": "TLS encrypts the connection. Certificates are free and automated, so the "
                           "majority of phishing sites now use HTTPS. The padlock says nothing about honesty.",
            "category": "link-inspection",
        },
        {
            "prompt": "You receive an MFA push notification you did not trigger. What is the correct response?",
            "options": [
                "Approve it - it is probably a delayed prompt from an earlier login",
                "Ignore it and carry on working",
                "Deny it, change your password from a trusted device and report it",
                "Approve it once to stop the notifications repeating",
            ],
            "correct_index": 2,
            "explanation": "An unexpected prompt means someone already holds your password. Deny, rotate "
                           "the password from a known-good device and report so sessions can be revoked.",
            "category": "mfa",
        },
        {
            "prompt": "Your CEO emails from a personal address asking you to urgently buy gift cards for client thank-yous, promising reimbursement. What is this?",
            "options": [
                "A normal request that should be actioned quickly",
                "Business Email Compromise - a well-known fraud pattern",
                "A legitimate request as long as you keep the receipts",
                "Spam that can simply be deleted without reporting",
            ],
            "correct_index": 1,
            "explanation": "Gift-card requests are a classic BEC pattern: fast, irreversible and untraceable. "
                           "No legitimate executive process works this way. Verify by phone and report it.",
            "category": "bec",
        },
        {
            "prompt": "Which sender check is the most reliable first step when a message looks suspicious?",
            "options": [
                "Check whether the display name matches someone you know",
                "Expand the full email address and read the registrable domain",
                "Check whether the message has a company logo",
                "Check whether the signature block lists a phone number",
            ],
            "correct_index": 1,
            "explanation": "Display names, logos and signatures are free text that anyone can copy. The "
                           "address domain is the first piece of evidence that is hard to fake.",
            "category": "sender-inspection",
        },
        {
            "prompt": "A text message says a parcel is held pending a small fee and links to a shortened URL. What is the safest action?",
            "options": [
                "Tap the link and pay the fee if it looks like the real courier site",
                "Reply STOP to unsubscribe",
                "Open the courier's official app or website directly and check any real deliveries",
                "Forward the text to colleagues so they are warned",
            ],
            "correct_index": 2,
            "explanation": "Never follow the link in the message. Go to the courier app or type the known "
                           "URL yourself; a genuine delivery will be visible there.",
            "category": "smishing",
        },
        {
            "prompt": "A caller claiming to be the IT service desk asks you to read out the one-time code you just received. What should you do?",
            "options": [
                "Read the code out - the service desk needs it to verify you",
                "Refuse, end the call and report it through official channels",
                "Read out only the first three digits as a compromise",
                "Ask them to email the request instead, then comply",
            ],
            "correct_index": 1,
            "explanation": "No legitimate organisation ever asks for a one-time code. Receiving the code "
                           "means a login attempt is in progress right now - this is an active attack.",
            "category": "vishing",
        },
        {
            "prompt": "Which of these is a phishing-resistant authentication factor?",
            "options": ["SMS one-time codes", "Push approval notifications",
                        "FIDO2 security keys or passkeys", "Email one-time links"],
            "correct_index": 2,
            "explanation": "FIDO2/passkey credentials are cryptographically bound to the real origin, so a "
                           "look-alike domain cannot use them - even with a real-time proxy.",
            "category": "mfa",
        },
        {
            "prompt": "You clicked a phishing link and entered your password before realising. What should you do first?",
            "options": [
                "Say nothing and hope nothing happens",
                "Delete the email so no one finds out",
                "Report it immediately and change the password from a different trusted device",
                "Run an antivirus scan and wait to see if anything is detected",
            ],
            "correct_index": 2,
            "explanation": "Speed limits the damage. Reporting lets the team revoke sessions and tokens - "
                           "changing the password alone does not kill a stolen session cookie.",
            "category": "incident-response",
        },
        {
            "prompt": "An email passes SPF, DKIM and DMARC. What can you safely conclude?",
            "options": [
                "The message is definitely safe to act on",
                "The message genuinely came from that domain, but its intent is still unproven",
                "The sender's account cannot be compromised",
                "The links in the message have been scanned and cleared",
            ],
            "correct_index": 1,
            "explanation": "Authentication proves the domain, not the intent. Mail from a compromised but "
                           "legitimate mailbox passes all three checks - which is exactly why BEC works.",
            "category": "sender-inspection",
        },
    ],
}


def ensure_default_quiz(db_session, quiz_model, question_model):
    """Create the default quiz if it does not already exist."""
    quiz = quiz_model.query.filter_by(slug=DEFAULT_QUIZ["slug"]).first()
    if quiz:
        return quiz
    quiz = quiz_model(
        slug=DEFAULT_QUIZ["slug"],
        title=DEFAULT_QUIZ["title"],
        description=DEFAULT_QUIZ["description"],
        pass_mark=DEFAULT_QUIZ["pass_mark"],
        is_active=True,
    )
    db_session.add(quiz)
    db_session.flush()
    for position, question in enumerate(DEFAULT_QUIZ["questions"], start=1):
        db_session.add(question_model(
            quiz_id=quiz.id,
            position=position,
            prompt=question["prompt"],
            options=question["options"],
            correct_index=question["correct_index"],
            explanation=question["explanation"],
            category=question["category"],
        ))
    db_session.commit()
    return quiz
