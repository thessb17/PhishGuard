# Security Policy & Ethics — PhishGuard

**Project owner:** Sabyasachi Bhowmik · **Institution:** Andhra University

PhishGuard is a **defensive security-awareness training platform** built as an
internship project. It simulates phishing in order to teach people to recognise
it. This document states what the platform does, what it deliberately refuses to
do, and how it protects itself.

---

## 1. The non-negotiable safety invariant

> **PhishGuard never collects, stores, transmits or logs a real password, token,
> banking detail, payment detail or any other sensitive credential.**

This is enforced in four independent places, so no single mistake can break it:

| # | Layer | Enforcement |
|---|---|---|
| 1 | **Templates** | No `<input type="password">` and no credential-named input exists anywhere under `app/templates/simulator/`. The "phishing" message is a rendered mock-up; its call-to-action leads straight to the awareness page. |
| 2 | **Schema** | `simulation_events` has no column capable of holding a submitted value — only `event_type`, `campaign_id`, `demo_user_ref`, `simulated_message_id`, `occurred_at`, `note`. |
| 3 | **Configuration** | `SIMULATION_COLLECT_CREDENTIALS = False` is a class-level constant in `BaseConfig`, not an environment variable, so it cannot be flipped by a misconfigured `.env`. |
| 4 | **Tests + checklist** | `test_simulator_templates_contain_no_credential_inputs` fails the build if a credential field appears; `scripts/security_check.py` re-scans the templates at runtime. |

### The landing page is a lesson, not a lure

When a participant clicks the simulated link they land on
`/simulator/landing/<token>`, which immediately says the message was a
simulation and then explains **why it was detectable** — the spoofed sender
domain, the mismatch between anchor text and destination, the urgency framing,
the deadline. It never renders a login form, never asks for information, and
never scores the person.

### Other things PhishGuard refuses to do

* **No real email is sent.** Campaign "delivery" is an in-app inbox at `/simulator`. There is no SMTP client, no mail queue, no outbound connector.
* **No real-world targeting.** Participants must be existing accounts in the local database. There is no import-from-CSV of external addresses.
* **No live fetching of analysed URLs.** Analysis is offline and string-level; the app never resolves DNS or issues a request to a submitted URL, so it cannot be used as an SSRF pivot or to notify an attacker that a link was inspected.
* **No malware, payloads, persistence or exploitation code.** There is no attachment handling, no macro generation, no C2 of any kind.
* **No real people.** Every identity is fictional (see §6).

---

## 2. Implemented security controls

### Authentication & session management
* Passwords hashed with **PBKDF2-HMAC-SHA256, 600,000 iterations**, per-user salt (Werkzeug). The plaintext never leaves the request scope and is never logged — two users with the same password get different hashes (test enforced).
* Minimum length 10 with a composition and common-password check (`validate_password`).
* **Account lockout**: 5 consecutive failures → 15-minute lock. On lockout the counter resets and a `locked_until` deadline is stored; the login view returns **423 Locked**.
* **Generic error messages**: unknown username and wrong password produce the identical response and status, so the form cannot be used to enumerate accounts.
* Session cookie: `HttpOnly`, `SameSite=Lax` (configurable), `Secure` in production, 60-minute lifetime, custom name `phishguard_session`.
* Disabled accounts (`is_active = false`) are refused at login with **403**.
* Self-registration always creates a **Demo User**; a role can never be self-assigned.
* **API keys are stored hashed, never in plaintext.** A key is 24 random bytes from `secrets` (192 bits), and only its **SHA-256 digest** is persisted (`users.api_key_hash`, unique + indexed); the first 8 characters are kept separately (`api_key_prefix`) purely so the UI can say *which* key is active. The raw value is returned exactly once, at issue time, and shown on a single render of `/profile`. A database disclosure therefore yields no usable key.
  * *Why SHA-256 rather than PBKDF2 like the password column?* Slow KDFs exist to survive guessing of low-entropy human passwords. An API key here is high-entropy random data, so dictionary and rainbow-table attacks do not apply — and the digest is computed on **every** API request, where a 600,000-iteration KDF would be a self-inflicted denial of service. Lookup stays a single indexed query. This is the construction GitHub and Stripe use for personal access tokens.
  * Verification uses `secrets.compare_digest`, so comparison is constant-time.
  * Rotation is audited (`API_KEY_ROTATED`) and the audit record carries only the non-secret prefix — never the key.

### Authorization (RBAC)
Three roles and a capability matrix in `app/models/user.py`:

| Capability | Admin | Analyst | Demo User |
|---|:--:|:--:|:--:|
| `dashboard.view` | ✔ | ✔ | |
| `campaign.view` | ✔ | ✔ | |
| `campaign.create` / `campaign.edit` | ✔ | ✔ | |
| `campaign.delete` | ✔ | | |
| `analysis.run` / `analysis.view` | ✔ | ✔ | |
| `report.view` / `report.create` | ✔ | ✔ | |
| `audit.view` | ✔ | | |
| `user.manage` | ✔ | | |
| `simulation.participate` | ✔ | ✔ | ✔ |
| `awareness.view` | ✔ | ✔ | ✔ |

Enforced server-side by `@capability_required(...)` on **every** protected view
— hiding a link in the sidebar is a convenience, never the control. Object-level
checks exist too: a participant may only open their own simulated message
(403 otherwise) and only read their own quiz attempts.

Self-protection: an administrator cannot demote or disable their own account.

### Injection & output safety
* **SQL injection**: the SQLAlchemy ORM is used exclusively; no string-built SQL exists. `scripts/security_check.py` greps for f-string SQL and fails if it finds any. Test: `test_sql_injection_attempt_is_treated_as_data`.
* **XSS**: Jinja2 autoescaping is on everywhere; no `|safe` on user-controlled data. Test: `test_stored_xss_payload_is_escaped_in_the_ui`.
* **CSRF**: Flask-WTF `CSRFProtect` on all form posts, including login. The JSON API is exempt from form CSRF but requires either an API key or a session **plus** `X-CSRFToken`.
* **Open redirect**: the post-login `next` parameter is validated by `is_safe_redirect_url()` (same host, no `//`, no backslash).
* **Unsafe URL schemes**: `validate_url()` preserves any scheme the user typed and rejects everything that is not `http`/`https`, so `javascript:`, `data:`, `file:` and `ftp:` cannot slip through the "add a missing scheme" normaliser.

### Transport & browser hardening
Applied to every response by `apply_security_headers()`:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
                         img-src 'self' data:; font-src 'self'; connect-src 'self';
                         form-action 'self'; base-uri 'self'; object-src 'none';
                         frame-ancestors 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN            (omitted when frame-ancestors is widened)
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store                (on /login, /profile, /audit-logs, /api/, /reports)
Strict-Transport-Security: max-age=31536000; includeSubDomains   (production + HTTPS)
```

There is **no inline JavaScript and no CDN**: Bootstrap, Chart.js and the icon
font are vendored locally, so `script-src 'self'` holds without `unsafe-inline`
and the app runs fully offline.

### Rate limiting & resource limits
Flask-Limiter with configurable windows: login `10/min; 60/hour`, analysis
`60/min; 600/hour`, API `120/min`, global `600/hour; 120/min`. Exceeding a limit
returns a friendly **429**. Request bodies are capped at **1 MB**
(`MAX_CONTENT_LENGTH`) → **413**.

### Secrets management
* No secret is hardcoded. `SECRET_KEY` comes from the environment; the **production profile refuses to start** without one (`RuntimeError`).
* The testing profile generates a random per-process key rather than shipping a literal.
* `.env` is git-ignored; `.env.example` documents every key with no values.
* `scripts/security_check.py` greps `app/` for hardcoded `SECRET_KEY`/`PASSWORD`/`API_KEY` literals.

### Data minimisation & redaction
* Submitted email bodies are passed through `redact_sensitive()` **before** they touch the database: passwords ("password is …", "pwd: …"), OTP/PIN codes, bearer tokens and API keys, JWT-like strings, 13–19 digit card numbers, CVVs, IBAN/account numbers and SSN-format strings are replaced with `[REDACTED]`, then truncated to 4,000 characters.
* The audit trail stores *what happened*, never *what was typed*. `log_audit()` masks any `extra` key matching a sensitive name list.
* Simulation events record a `demo_user_ref` and an event type — nothing about content or behaviour beyond the four permitted verbs.
* IP capture in the audit log is switchable (`AUDIT_LOG_IP`).

### Error handling & logging
Custom pages for **400, 401, 403, 404, 413, 429, 500** plus `CSRFError`. Normal
users never see a stack trace; the JSON API returns the error envelope instead
of HTML. Debug mode is off outside development and the checklist fails a
production app with `DEBUG=True`.

### Audit logging
Append-only `audit_logs`, viewable only with `audit.view` (Admin) and
filterable by action, category, status and free text. Twenty action constants
are defined on `AuditAction`; these eight are the required security-relevant
set and each is written by the route that performs the action:

| Action | Written when |
|---|---|
| `LOGIN_SUCCESS` | A session is established. |
| `LOGIN_FAILURE` | Credentials rejected (the submitted password is never recorded). |
| `LOGOUT` | A session ends. |
| `CAMPAIGN_CREATED` | A simulation campaign is created. |
| `CAMPAIGN_UPDATED` | A campaign's fields or status change. |
| `ANALYSIS_PERFORMED` | A URL or email is scored, via the UI or the API. |
| `REPORT_GENERATED` | A report is produced. |
| `ROLE_CHANGED` | A user's role is changed by an administrator. |

The remaining constants cover `LOGIN_BLOCKED` (lockout), `REGISTER`,
`PASSWORD_CHANGED`, `API_KEY_ROTATED`, `CAMPAIGN_DELETED`,
`REPORT_DOWNLOADED`, `USER_STATUS_CHANGED`, `SIMULATION_EVENT`,
`QUIZ_SUBMITTED`, `ACCESS_DENIED` and `RATE_LIMITED`.

> `CAMPAIGN_MODIFIED` is retained as a deprecated alias of `CAMPAIGN_UPDATED`
> with the identical stored value, so historical rows and any external query
> written against the old name keep working. New code should use
> `CAMPAIGN_UPDATED`.

---

## 3. Self-assessment tooling

```bash
python scripts/security_check.py          # or: flask --app run:app security-check
```

18 configuration checks (secret strength, hardcoded secrets, CSRF, hashing,
password policy, lockout, rate limits, cookie flags, security headers, CSP
strictness, debug mode, error pages, credential-free simulator, the simulation
flag, HSTS, SQL construction, audit redaction, body size). Exit code is the
number of failures.

**This is a configuration checklist, not a penetration test.** It proves the
controls this project claims are switched on. It cannot prove the absence of
vulnerabilities.

---

## 4. Known limitations (read before trusting a verdict)

1. **Heuristics produce false positives and false negatives.** Hand-written rules flag unusual-but-legitimate URLs (long tracking links, legitimate shorteners, new gTLDs) and miss well-crafted phishing on a compromised legitimate domain. In the shipped benchmark the selected model alone produced **72 false positives and 406 false negatives** on 3,217 held-out URLs — roughly one phishing URL in four was missed. A known residual false positive: a credential-reset path on an unfamiliar domain (`portal.cybersafe.edu/password/renew`) scores MEDIUM.
2. **ML confidence is not certainty.** The number is a calibrated-ish probability from one model trained on one corpus. Treat it as one input to a human decision, never as a verdict.
3. **Benchmark figures are dataset-dependent.** ~85.1 % accuracy was measured on a held-out split of the bundled dataset, which is derived from PhiUSIIL plus a generated augmentation corpus. Real-world traffic differs in distribution and will score differently. Re-train on organisation-specific data before operational use.
4. **HTTPS does not mean safe.** A valid certificate proves transport encryption and (at most) domain control. Most phishing sites today use HTTPS. PhishGuard deliberately does not reward HTTPS with a lower score.
5. **Authentication results prove the domain, not the intent.** SPF, DKIM and DMARC all pass for mail sent from a compromised but legitimate mailbox.
6. **Campaign figures are simulation metrics.** A 33 % click rate means a third of *these* participants clicked *this* mock message in *this* exercise. It is not a measurement of real-world phishing prevalence or of actual breach likelihood.
7. **Analysis is offline and string-level.** No page content, redirect chain, TLS certificate, WHOIS record or reputation feed is consulted. A URL that only becomes malicious after a redirect will not be caught.
8. **No email is actually delivered**, so the simulator cannot measure real inbox behaviour (previewing, forwarding, mobile-client rendering).
9. **The rate limiter defaults to in-memory storage**, which is per-process. Use Redis for any multi-worker deployment (the compose stack does).
10. **Not a penetration-tested product.** This is an internship project. Do not expose it to the public internet without an independent review, TLS, a hardened database and a reverse proxy.

---

## 5. Responsible-use policy

**Permitted**: running simulations against consenting participants inside your
own organisation or lab; analysing suspicious URLs and messages you have a
legitimate reason to inspect; teaching.

**Not permitted**: targeting anyone who has not consented, or any external
organisation; adapting the simulator to capture credentials; using the templates
as the basis of a real phishing campaign; presenting the output as a compliance
certification.

Before any real exercise: obtain **written authorisation**, notify HR/legal and
your service desk, define a blackout window, and publish the debrief. A
simulation that punishes participants destroys the reporting culture it is meant
to build — measure the **report rate**, not the click rate.

---

## 6. Fictional data statement

Every organization, person, mailbox, domain and message in this project is
invented for the demonstration:

* **Organizations**: Andhra University, Example Corporation, Demo IT Department.
* **People**: 18 seeded accounts with invented names (Avery Sinclair, Rohan Varma, Priya Nandakumar, …). They do not refer to real individuals.
* **Domains**: attacker infrastructure uses RFC 2606 reserved names (`.example`, `.invalid`, `.test`); the fictional org domains `cybersafe.edu` and `example-corp.com` appear only as demo strings. The application never contacts any of them.
* **Demo passwords** are published in this repository *because* the accounts are fictional and local. Change them before any shared deployment.

---

## 7. Reporting a vulnerability

This is a student project, not a maintained product. If you find a flaw, open an
issue describing the impact and the reproduction steps — please do not include a
working exploit against a third party. Do not report vulnerabilities in the
fictional domains above; they are not real services.
