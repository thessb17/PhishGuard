"""Explainable email phishing heuristics.

Analyses five surfaces - sender, subject, body, embedded links and (optional)
headers - and returns a capped 0-100 heuristic score together with the exact
indicators that produced it.

The analyser is purely offline: nothing is fetched, resolved or sent anywhere.
Submitted content is redacted before persistence by the calling route.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.utils import getaddresses, parseaddr

from app.ml.feature_engineering import FREEMAIL_DOMAINS, SUSPICIOUS_TLDS, split_host
from app.services.indicators import AnalysisOutcome, Indicator
from app.services.url_analyzer import closest_lookalike, is_shortener, url_analyzer
from app.utils.validators import extract_urls

# --------------------------------------------------------------------------
# Lexicons (kept explicit so the rules can be reviewed and unit tested)
# --------------------------------------------------------------------------

URGENCY_TERMS = [
    "urgent", "immediately", "right away", "asap", "as soon as possible",
    "within 24 hours", "within 24hrs", "expires today", "expiring", "expires",
    "final notice", "last warning", "act now", "time sensitive", "deadline",
    "do not delay", "quick action", "prompt action",
]

THREAT_TERMS = [
    "suspend", "suspended", "suspension", "terminated", "termination",
    "deactivate", "deactivated", "disabled", "locked", "lockout", "blocked",
    "legal action", "penalty", "fine", "unauthorized access", "unauthorised access",
    "security breach", "compromised", "will be deleted", "permanently removed",
    "account closure", "restricted",
]

REWARD_TERMS = [
    "congratulations", "you have won", "winner", "prize", "lottery", "reward",
    "gift card", "voucher", "cash bonus", "free gift", "claim your", "refund due",
    "tax refund", "bonus payment", "compensation",
]

VERIFICATION_TERMS = [
    "verify your account", "verify your identity", "confirm your account",
    "confirm your identity", "validate your account", "re-activate", "reactivate",
    "update your details", "update your information", "confirm your details",
    "account verification", "identity verification", "re-verify",
]

CREDENTIAL_REQUEST_RE = re.compile(
    r"(?i)\b(confirm|verify|update|validate|re-?enter|provide|submit|send|share|enter)\b"
    r"[^.\n]{0,40}\b(password|passcode|pass phrase|credentials?|login details|"
    r"sign-?in details|account details|pin|otp|one[- ]time code|mfa code|2fa code|"
    r"security question|security code)\b"
)

FINANCIAL_RE = re.compile(
    r"(?i)\b(wire transfer|bank transfer|payment details|invoice attached|"
    r"outstanding invoice|remittance|swift code|iban|routing number|"
    r"credit card|debit card|cvv|billing information|purchase order|"
    r"process (?:this )?payment|release funds|transfer funds)\b"
)

GIFT_CARD_RE = re.compile(
    r"(?i)\b(gift cards?|itunes cards?|google play cards?|steam cards?|"
    r"amazon cards?|prepaid cards?|scratch (?:off|the) card)\b"
)

SECRECY_RE = re.compile(
    r"(?i)\b(keep this (?:confidential|between us|discreet)|don'?t tell|"
    r"do not discuss|strictly confidential|handle (?:this )?discreetly|"
    r"i'?m (?:in a meeting|travelling|traveling|unavailable)|"
    r"can'?t talk (?:right )?now|only communicate by email)\b"
)

# An authority *claim*, not a mere mention.  Requiring the surrounding framing
# ("this is the help desk", "the IT department requires...") stops the rule
# firing on ordinary prose such as "collect it at the library help desk",
# which previously added 12 points to a perfectly legitimate notice.
_AUTHORITY = (
    r"(?:it (?:help ?desk|support|department|team)|help ?desk|service desk|"
    r"system administrator|sysadmin|hr department|human resources|payroll team|"
    r"security team|account team|billing department|ceo|cfo|managing director|"
    r"microsoft (?:365|support|team)|google support|apple support)"
)
IMPERSONATION_RE = re.compile(
    r"(?i)(?:"
    # "this is the IT help desk", "on behalf of the CEO", "from the security team"
    rf"\b(?:this is|i am|i'm|we are|we're|on behalf of|message from|contacting you from|"
    rf"from)\s+(?:the\s+|your\s+|our\s+)?{_AUTHORITY}\b"
    r"|"
    # "the IT department requires you to...", "security team has detected..."
    rf"\b(?:the\s+|your\s+|our\s+){_AUTHORITY}\s+(?:requires?|requests?|needs?|asks?|"
    rf"has (?:detected|flagged|identified)|is requesting|instructed|mandates?)\b"
    r")"
)

GENERIC_GREETING_RE = re.compile(
    r"(?i)^\s*(dear (?:customer|user|client|member|account holder|sir/madam|sir or madam|employee)|"
    r"hello (?:user|customer|there)|attention (?:user|customer)|valued (?:customer|member))",
    re.MULTILINE,
)

ATTACHMENT_LURE_RE = re.compile(
    r"(?i)\b(open the attach(?:ed|ment)|see attach(?:ed|ment)|"
    r"review the attached|enable (?:macros|editing|content)|"
    r"download the (?:attached|document|invoice|file)|"
    r"\.(?:exe|scr|js|jar|vbs|iso|hta|zip|rar|7z|docm|xlsm)\b)"
)

QR_RE = re.compile(r"(?i)\b(scan (?:the )?(?:qr|barcode)|qr code|quick response code)\b")

ANCHOR_RE = re.compile(r"(?is)<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>")
HTML_TAG_RE = re.compile(r"(?s)<[^>]+>")

#: Documented email rule weights.
RULE_WEIGHTS = {
    "SENDER_FREEMAIL": 10.0,
    "SENDER_LOOKALIKE": 20.0,
    "SENDER_DISPLAY_MISMATCH": 16.0,
    "SENDER_SUSPICIOUS_TLD": 10.0,
    "SENDER_RANDOM_LOCAL": 8.0,
    "SENDER_MALFORMED": 12.0,
    "SENDER_SUBDOMAIN_BRAND": 14.0,
    "REPLY_TO_MISMATCH": 15.0,
    "RETURN_PATH_MISMATCH": 12.0,
    "SUBJECT_URGENCY": 10.0,
    "SUBJECT_THREAT": 12.0,
    "SUBJECT_REWARD": 8.0,
    "SUBJECT_VERIFICATION": 10.0,
    "SUBJECT_SHOUTING": 5.0,
    "SUBJECT_FAKE_REPLY": 5.0,
    "BODY_CREDENTIAL_REQUEST": 22.0,
    "BODY_URGENCY": 10.0,
    "BODY_THREAT": 10.0,
    "BODY_FINANCIAL": 15.0,
    # Gift-card solicitation is one of the highest-precision BEC signals
    # there is; almost no legitimate business process asks for codes.
    "BODY_GIFT_CARD": 25.0,
    "BODY_SECRECY": 12.0,
    "BODY_IMPERSONATION": 12.0,
    "BODY_GENERIC_GREETING": 6.0,
    "BODY_ATTACHMENT_LURE": 10.0,
    "BODY_QR_REQUEST": 8.0,
    "LINK_RISK": 25.0,          # scaled from the worst embedded URL score
    "LINK_TEXT_MISMATCH": 18.0,
    "LINK_SHORTENER": 10.0,
    "SPF_FAIL": 15.0,
    "DKIM_FAIL": 15.0,
    "DMARC_FAIL": 18.0,
    "AUTH_MISSING": 6.0,
    "RECEIVED_CHAIN": 8.0,
    "SUSPICIOUS_MAILER": 6.0,
}

TRUSTED_INTERNAL_DOMAINS = {"cybersafe.edu", "example-corp.com", "demo-it.local"}


def _matches(text: str, terms: list[str]) -> list[str]:
    lowered = (text or "").lower()
    return [t for t in terms if t in lowered]


def strip_html(text: str) -> str:
    return HTML_TAG_RE.sub(" ", text or "")


class EmailAnalyzer:
    """Rule-based email risk analysis with per-indicator explanations."""

    DISCLAIMER = (
        "Heuristic email analysis is based on the supplied text only. Without the "
        "original message source, authentication results cannot be verified "
        "independently. False positives and false negatives are possible."
    )

    def analyze(self, sender: str = "", subject: str = "", body: str = "",
                urls: list[str] | None = None, headers: str = "") -> dict:
        outcome = AnalysisOutcome()
        display_name, address = parseaddr(sender or "")
        address = (address or "").strip().lower()
        sender_domain = address.split("@")[-1] if "@" in address else ""
        _, sender_registrable, sender_tld = split_host(sender_domain)

        header_findings = self._analyze_headers(headers, address, outcome)
        self._analyze_sender(display_name, address, sender_domain, sender_registrable,
                             sender_tld, header_findings, outcome)
        self._analyze_subject(subject, outcome)
        text_body = strip_html(body)
        self._analyze_body(body, text_body, outcome)
        url_results = self._analyze_links(body, urls, sender_registrable, outcome)

        outcome.finalise()
        worst = max(url_results, key=lambda r: r["heuristic_score"], default=None)
        return {
            "sender": address,
            "display_name": display_name,
            "sender_domain": sender_domain,
            "sender_registrable_domain": sender_registrable,
            "subject": subject or "",
            "heuristic_score": outcome.score,
            "raw_score": outcome.raw_score,
            "indicators": outcome.to_dicts(),
            "urls": url_results,
            "worst_url": worst,
            "header_findings": header_findings,
            "body_length": len(body or ""),
            "disclaimer": self.DISCLAIMER,
        }

    # -- sender ------------------------------------------------------------
    def _analyze_sender(self, display_name, address, domain, registrable, tld,
                        header_findings, outcome: AnalysisOutcome) -> None:
        if not address or "@" not in address:
            outcome.add(Indicator(
                "SENDER_MALFORMED", "Sender address missing or malformed", "sender",
                RULE_WEIGHTS["SENDER_MALFORMED"],
                evidence=f"Parsed address: '{address or '(none)'}'.",
                recommendation="A well-formed From address is the bare minimum for a legitimate sender.",
            ))
            return

        if domain in FREEMAIL_DOMAINS:
            outcome.add(Indicator(
                "SENDER_FREEMAIL", "Corporate-style message sent from free webmail", "sender",
                RULE_WEIGHTS["SENDER_FREEMAIL"],
                evidence=f"Sender domain '{domain}' is a free webmail provider.",
                recommendation="Official notices come from the organisation's own domain.",
            ))

        if tld.split(".")[-1] in SUSPICIOUS_TLDS:
            outcome.add(Indicator(
                "SENDER_SUSPICIOUS_TLD", f"Sender uses frequently abused TLD '.{tld}'", "sender",
                RULE_WEIGHTS["SENDER_SUSPICIOUS_TLD"],
                evidence=f"Sender domain '{domain}'.",
                recommendation="Check whether the brand actually operates on this TLD.",
            ))

        target, distance = closest_lookalike(registrable)
        if target and distance == 0 and registrable not in TRUSTED_INTERNAL_DOMAINS:
            distance = 1
        if target and 0 < distance <= 2:
            outcome.add(Indicator(
                "SENDER_LOOKALIKE", "Sender domain imitates a well-known domain", "sender",
                RULE_WEIGHTS["SENDER_LOOKALIKE"],
                evidence=f"'{registrable}' is {distance} edit(s) from '{target}'.",
                recommendation="Read the domain character by character; confirm via a known contact.",
            ))

        local_part = address.split("@")[0]
        if len(local_part) >= 12 and sum(c.isdigit() for c in local_part) >= 4:
            outcome.add(Indicator(
                "SENDER_RANDOM_LOCAL", "Machine-generated looking mailbox name", "sender",
                RULE_WEIGHTS["SENDER_RANDOM_LOCAL"],
                evidence=f"Local part '{local_part}'.",
                recommendation="Bulk phishing often uses disposable, randomised mailboxes.",
            ))

        # Display-name spoofing: brand in the display name, different domain.
        from app.ml.feature_engineering import BRAND_TOKENS

        display_lower = (display_name or "").lower()
        brand_hits = [b for b in BRAND_TOKENS if b in display_lower]
        if brand_hits and not any(b in registrable for b in brand_hits):
            outcome.add(Indicator(
                "SENDER_DISPLAY_MISMATCH", "Display name impersonates a brand", "sender",
                RULE_WEIGHTS["SENDER_DISPLAY_MISMATCH"],
                evidence=(f"Display name '{display_name}' references {', '.join(brand_hits)}, "
                          f"but the address domain is '{registrable}'."),
                recommendation="Mail clients hide the real address - always expand the sender.",
            ))

        subdomain, _, _ = split_host(domain)
        sub_brand = [b for b in BRAND_TOKENS if b in subdomain]
        if sub_brand and not any(b in registrable for b in sub_brand):
            outcome.add(Indicator(
                "SENDER_SUBDOMAIN_BRAND", "Brand name hidden in the sender subdomain", "sender",
                RULE_WEIGHTS["SENDER_SUBDOMAIN_BRAND"],
                evidence=f"Subdomain '{subdomain}' vs registrable domain '{registrable}'.",
                recommendation="Ownership is proven by the registrable domain, not the subdomain.",
            ))

        reply_to = header_findings.get("reply_to")
        if reply_to and "@" in reply_to:
            reply_domain = reply_to.split("@")[-1]
            _, reply_registrable, _ = split_host(reply_domain)
            if reply_registrable and reply_registrable != registrable:
                outcome.add(Indicator(
                    "REPLY_TO_MISMATCH", "Reply-To points to a different domain", "header",
                    RULE_WEIGHTS["REPLY_TO_MISMATCH"],
                    evidence=f"From '{registrable}' but Reply-To '{reply_registrable}'.",
                    recommendation="Replies would leave the organisation - classic BEC redirection.",
                ))

        return_path = header_findings.get("return_path")
        if return_path and "@" in return_path:
            rp_domain = return_path.split("@")[-1].strip(">")
            _, rp_registrable, _ = split_host(rp_domain)
            if rp_registrable and rp_registrable != registrable:
                outcome.add(Indicator(
                    "RETURN_PATH_MISMATCH", "Return-Path does not match the From domain", "header",
                    RULE_WEIGHTS["RETURN_PATH_MISMATCH"],
                    evidence=f"From '{registrable}' vs Return-Path '{rp_registrable}'.",
                    recommendation="Bounce address mismatches often indicate spoofed envelopes.",
                ))

    # -- subject -------------------------------------------------------------
    def _analyze_subject(self, subject: str, outcome: AnalysisOutcome) -> None:
        subject = subject or ""
        if not subject.strip():
            return
        hits = _matches(subject, URGENCY_TERMS)
        if hits:
            outcome.add(Indicator(
                "SUBJECT_URGENCY", "Urgency pressure in the subject", "subject",
                RULE_WEIGHTS["SUBJECT_URGENCY"],
                evidence="Terms: " + ", ".join(hits[:5]),
                recommendation="Manufactured time pressure is the most common phishing lever.",
            ))
        hits = _matches(subject, THREAT_TERMS)
        if hits:
            outcome.add(Indicator(
                "SUBJECT_THREAT", "Threat or account-suspension language in the subject", "subject",
                RULE_WEIGHTS["SUBJECT_THREAT"],
                evidence="Terms: " + ", ".join(hits[:5]),
                recommendation="Verify account status by logging in through a bookmarked URL.",
            ))
        hits = _matches(subject, REWARD_TERMS)
        if hits:
            outcome.add(Indicator(
                "SUBJECT_REWARD", "Reward / prize bait in the subject", "subject",
                RULE_WEIGHTS["SUBJECT_REWARD"],
                evidence="Terms: " + ", ".join(hits[:5]),
                recommendation="Unsolicited winnings are a long-running fraud pattern.",
            ))
        hits = _matches(subject, VERIFICATION_TERMS)
        if hits:
            outcome.add(Indicator(
                "SUBJECT_VERIFICATION", "Account-verification demand in the subject", "subject",
                RULE_WEIGHTS["SUBJECT_VERIFICATION"],
                evidence="Terms: " + ", ".join(hits[:5]),
                recommendation="Providers do not ask you to re-verify via emailed links.",
            ))
        letters = [c for c in subject if c.isalpha()]
        caps_ratio = sum(c.isupper() for c in letters) / len(letters) if letters else 0
        if (caps_ratio > 0.6 and len(letters) > 8) or subject.count("!") >= 2:
            outcome.add(Indicator(
                "SUBJECT_SHOUTING", "Shouting / excessive punctuation in the subject", "subject",
                RULE_WEIGHTS["SUBJECT_SHOUTING"],
                evidence=f"Uppercase ratio {caps_ratio:.0%}, '!' count {subject.count('!')}.",
                recommendation="Professional senders rarely shout in subject lines.",
            ))
        if re.match(r"(?i)^\s*(re|fwd?)\s*:", subject) and "re:" not in subject.lower()[3:]:
            outcome.add(Indicator(
                "SUBJECT_FAKE_REPLY", "Fake reply/forward prefix", "subject",
                RULE_WEIGHTS["SUBJECT_FAKE_REPLY"],
                evidence=f"Subject starts with '{subject.split(':')[0]}:' with no prior thread.",
                recommendation="Attackers fake threads to borrow trust from a conversation.",
            ))

    # -- body ---------------------------------------------------------------
    def _analyze_body(self, raw_body: str, text_body: str, outcome: AnalysisOutcome) -> None:
        body = text_body or ""
        if not body.strip():
            return
        match = CREDENTIAL_REQUEST_RE.search(body)
        if match:
            outcome.add(Indicator(
                "BODY_CREDENTIAL_REQUEST", "Request for credentials or one-time codes", "body",
                RULE_WEIGHTS["BODY_CREDENTIAL_REQUEST"],
                evidence=f"Matched phrase: '{match.group(0).strip()[:120]}'.",
                recommendation="No legitimate service asks for your password, PIN or OTP by email.",
            ))
        hits = _matches(body, URGENCY_TERMS)
        if hits:
            outcome.add(Indicator(
                "BODY_URGENCY", "Artificial urgency in the message body", "body",
                RULE_WEIGHTS["BODY_URGENCY"],
                evidence="Terms: " + ", ".join(hits[:5]),
                recommendation="Slow down: urgency exists to stop you thinking.",
            ))
        hits = _matches(body, THREAT_TERMS)
        if hits:
            outcome.add(Indicator(
                "BODY_THREAT", "Threatening consequences in the message body", "body",
                RULE_WEIGHTS["BODY_THREAT"],
                evidence="Terms: " + ", ".join(hits[:5]),
                recommendation="Confirm account state directly with the provider.",
            ))
        match = FINANCIAL_RE.search(body)
        if match:
            outcome.add(Indicator(
                "BODY_FINANCIAL", "Financial / payment instruction", "body",
                RULE_WEIGHTS["BODY_FINANCIAL"],
                evidence=f"Matched phrase: '{match.group(0).strip()[:120]}'.",
                recommendation="Verify payment changes by phone using a previously known number.",
            ))
        match = GIFT_CARD_RE.search(body)
        if match:
            outcome.add(Indicator(
                "BODY_GIFT_CARD", "Gift-card request (classic BEC fraud)", "body",
                RULE_WEIGHTS["BODY_GIFT_CARD"],
                evidence=f"Matched phrase: '{match.group(0).strip()[:120]}'.",
                recommendation="No executive legitimately asks staff to buy gift cards by email.",
            ))
        match = SECRECY_RE.search(body)
        if match:
            outcome.add(Indicator(
                "BODY_SECRECY", "Secrecy / isolation pressure", "body",
                RULE_WEIGHTS["BODY_SECRECY"],
                evidence=f"Matched phrase: '{match.group(0).strip()[:120]}'.",
                recommendation="Isolating the target prevents verification - always verify anyway.",
            ))
        match = IMPERSONATION_RE.search(body)
        if match:
            outcome.add(Indicator(
                "BODY_IMPERSONATION", "Claims authority (IT/HR/executive/provider)", "body",
                RULE_WEIGHTS["BODY_IMPERSONATION"],
                evidence=f"Matched phrase: '{match.group(0).strip()[:120]}'.",
                recommendation="Authority claims are trivially faked; confirm through the directory.",
            ))
        if GENERIC_GREETING_RE.search(body):
            outcome.add(Indicator(
                "BODY_GENERIC_GREETING", "Generic, non-personalised greeting", "body",
                RULE_WEIGHTS["BODY_GENERIC_GREETING"],
                evidence="Greeting does not address the recipient by name.",
                recommendation="Bulk phishing cannot personalise; note that spear phishing can.",
            ))
        match = ATTACHMENT_LURE_RE.search(body)
        if match:
            outcome.add(Indicator(
                "BODY_ATTACHMENT_LURE", "Pressure to open an attachment or enable macros", "body",
                RULE_WEIGHTS["BODY_ATTACHMENT_LURE"],
                evidence=f"Matched phrase: '{match.group(0).strip()[:120]}'.",
                recommendation="Never enable macros; open unexpected documents in a viewer/sandbox.",
            ))
        if QR_RE.search(body):
            outcome.add(Indicator(
                "BODY_QR_REQUEST", "Asks the reader to scan a QR code (quishing)", "body",
                RULE_WEIGHTS["BODY_QR_REQUEST"],
                evidence="QR-code instruction detected.",
                recommendation="QR codes move the victim to an unmanaged personal device.",
            ))

    # -- links -----------------------------------------------------------------
    def _analyze_links(self, raw_body: str, urls: list[str] | None,
                       sender_registrable: str, outcome: AnalysisOutcome) -> list[dict]:
        collected: list[str] = []
        for url in (urls or []):
            if url and url.strip():
                collected.append(url.strip())
        collected.extend(u for u in extract_urls(raw_body) if u not in collected)

        # Anchor text vs href mismatch (HTML bodies)
        for href, label in ANCHOR_RE.findall(raw_body or ""):
            label_text = strip_html(label).strip()
            label_urls = extract_urls(label_text)
            if not label_urls:
                continue
            _, href_domain, _ = split_host((href.split("//")[-1].split("/")[0]))
            _, label_domain, _ = split_host((label_urls[0].split("//")[-1].split("/")[0]))
            if href_domain and label_domain and href_domain != label_domain:
                outcome.add(Indicator(
                    "LINK_TEXT_MISMATCH", "Link text does not match the real destination", "link",
                    RULE_WEIGHTS["LINK_TEXT_MISMATCH"],
                    evidence=f"Displayed '{label_domain}' but the href points to '{href_domain}'.",
                    recommendation="Hover (or long-press) every link and read the real host.",
                ))
                break

        results: list[dict] = []
        for url in collected[:15]:
            try:
                analysis = url_analyzer.analyze(url)
            except Exception:  # pragma: no cover - defensive
                continue
            results.append({
                "url": analysis["url"],
                "hostname": analysis["hostname"],
                "heuristic_score": analysis["heuristic_score"],
                "top_indicators": [i for i in analysis["indicators"] if i["points"] > 0][:4],
            })

        if results:
            worst = max(results, key=lambda r: r["heuristic_score"])
            if worst["heuristic_score"] > 0:
                points = round(RULE_WEIGHTS["LINK_RISK"] * (worst["heuristic_score"] / 100.0), 2)
                outcome.add(Indicator(
                    "LINK_RISK", "Embedded link carries its own phishing indicators", "link",
                    points,
                    evidence=(f"Highest-risk link '{worst['url'][:110]}' scored "
                              f"{worst['heuristic_score']}/100 in the URL analyser."),
                    recommendation="Run the link through the URL detector for the full breakdown.",
                ))
            for result in results:
                _, registrable, _ = split_host(result["hostname"])
                if is_shortener(registrable):
                    outcome.add(Indicator(
                        "LINK_SHORTENER", "Shortened link hides the destination", "link",
                        RULE_WEIGHTS["LINK_SHORTENER"],
                        evidence=f"'{result['hostname']}' is a URL-shortening service.",
                        recommendation="Expand shortened links before clicking.",
                    ))
                    break
        return results

    # -- headers ------------------------------------------------------------------
    def _analyze_headers(self, headers: str, from_address: str,
                         outcome: AnalysisOutcome) -> dict:
        findings: dict = {
            "provided": bool((headers or "").strip()),
            "spf": "not provided",
            "dkim": "not provided",
            "dmarc": "not provided",
            "reply_to": "",
            "return_path": "",
            "received_count": 0,
            "x_mailer": "",
            "from_header": "",
        }
        if not (headers or "").strip():
            outcome.add(Indicator(
                "AUTH_MISSING", "No message headers supplied", "header", 0.0,
                evidence="SPF/DKIM/DMARC results could not be evaluated.",
                recommendation="Paste the full internet headers for authentication analysis.",
                positive=False,
            ))
            return findings

        message = message_from_string(headers)
        auth_results = " ".join(message.get_all("Authentication-Results", []) or []).lower()
        received_spf = " ".join(message.get_all("Received-SPF", []) or []).lower()
        combined = f"{auth_results} {received_spf}"

        def _verdict(mechanism: str) -> str:
            match = re.search(rf"{mechanism}\s*=\s*([a-z]+)", combined)
            if match:
                return match.group(1)
            if mechanism == "spf" and received_spf:
                first = received_spf.strip().split()
                return first[0] if first else "not provided"
            return "not provided"

        findings["spf"] = _verdict("spf")
        findings["dkim"] = _verdict("dkim")
        findings["dmarc"] = _verdict("dmarc")
        findings["received_count"] = len(message.get_all("Received", []) or [])
        findings["x_mailer"] = (message.get("X-Mailer") or "")[:120]
        findings["from_header"] = (message.get("From") or "")[:200]
        reply_to_pairs = getaddresses(message.get_all("Reply-To", []) or [])
        findings["reply_to"] = (reply_to_pairs[0][1].lower() if reply_to_pairs else "")
        findings["return_path"] = (message.get("Return-Path") or "").strip("<> ").lower()

        failure_states = {"fail", "softfail", "permerror", "temperror", "none", "neutral"}
        if findings["spf"] in failure_states:
            outcome.add(Indicator(
                "SPF_FAIL", f"SPF did not pass (spf={findings['spf']})", "header",
                RULE_WEIGHTS["SPF_FAIL"],
                evidence=f"Authentication-Results reported spf={findings['spf']}.",
                recommendation="The sending IP is not authorised by the domain's SPF record.",
            ))
        if findings["dkim"] in failure_states:
            outcome.add(Indicator(
                "DKIM_FAIL", f"DKIM did not pass (dkim={findings['dkim']})", "header",
                RULE_WEIGHTS["DKIM_FAIL"],
                evidence=f"Authentication-Results reported dkim={findings['dkim']}.",
                recommendation="The message signature is missing or does not validate.",
            ))
        if findings["dmarc"] in failure_states:
            outcome.add(Indicator(
                "DMARC_FAIL", f"DMARC did not pass (dmarc={findings['dmarc']})", "header",
                RULE_WEIGHTS["DMARC_FAIL"],
                evidence=f"Authentication-Results reported dmarc={findings['dmarc']}.",
                recommendation="Alignment failed - the From domain does not vouch for this message.",
            ))
        if all(findings[k] == "pass" for k in ("spf", "dkim", "dmarc")):
            outcome.add(Indicator(
                "AUTH_PASS", "SPF, DKIM and DMARC all reported pass", "header", 0.0,
                evidence="Authentication-Results header reports pass for all three mechanisms.",
                recommendation="Authentication proves the domain, not the intent - keep reading the content.",
                positive=True,
            ))
        # Only meaningful when the analyst actually pasted a transport header
        # block.  Someone who supplies just a Reply-To line has not shown us a
        # truncated chain - they have shown us a partial paste, and charging
        # 8 points for that penalised the *user*, not the email.
        transport_present = any(
            message.get(h) for h in
            ("Return-Path", "Message-ID", "Delivered-To", "DKIM-Signature",
             "Authentication-Results", "Received-SPF", "Received")
        )
        if findings["received_count"] == 0 and transport_present:
            outcome.add(Indicator(
                "RECEIVED_CHAIN", "No Received headers in the supplied chain", "header",
                RULE_WEIGHTS["RECEIVED_CHAIN"],
                evidence="A genuine delivered message always accumulates Received hops.",
                recommendation="Headers may be truncated or fabricated - request the original .eml.",
            ))
        elif findings["received_count"] == 1:
            outcome.add(Indicator(
                "RECEIVED_CHAIN", "Unusually short Received chain", "header",
                RULE_WEIGHTS["RECEIVED_CHAIN"] / 2,
                evidence=f"{findings['received_count']} Received hop recorded.",
                recommendation="Compare with the hop count of known-good mail from this sender.",
            ))
        mailer = findings["x_mailer"].lower()
        if any(tool in mailer for tool in ("phpmailer", "swiftmailer", "sendblaster", "mass mailer", "python-requests")):
            outcome.add(Indicator(
                "SUSPICIOUS_MAILER", "Bulk-mailer software in X-Mailer", "header",
                RULE_WEIGHTS["SUSPICIOUS_MAILER"],
                evidence=f"X-Mailer: {findings['x_mailer']}",
                recommendation="Corporate mail normally originates from the organisation's gateway.",
            ))
        return findings


email_analyzer = EmailAnalyzer()
