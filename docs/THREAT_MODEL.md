# PhishGuard — Threat Model

**Method:** STRIDE per component, against the implementation as it actually
exists (53 routes, 11 tables, 3 roles). Mitigations marked *Implemented* were
verified by test or by direct observation; mitigations marked *Proposed* are
not built.

**Scope note.** PhishGuard is a defensive training platform that runs locally
or on an internal network. It is **not** internet-exposed infrastructure, and
this model does not pretend otherwise. Likelihood ratings assume the realistic
deployment: a demo or internal lab, with authenticated users who are students
or staff.

**Rating scale.** Impact and Likelihood are Low / Medium / High. They are
deliberately conservative — inflating risk in a student project is its own
kind of dishonesty.

---

## 0. System overview and trust boundaries

```
  ┌─ UNTRUSTED ──────────────────────────────────────────────┐
  │  Browser (any user)        API client (X-API-Key)        │
  └───────────────┬──────────────────────┬───────────────────┘
                  │  HTTP                │  HTTP
  ┌───────────────▼──────────────────────▼───────────────────┐
  │  TRUST BOUNDARY 1 — Flask application                    │
  │  CSRF · rate limit · security headers · body-size cap    │
  │  ┌─ TRUST BOUNDARY 2 — Authentication (Flask-Login) ───┐ │
  │  │  ┌─ TRUST BOUNDARY 3 — Authorization (capability) ┐ │ │
  │  │  │  Routes → Services → Models                    │ │ │
  │  │  └────────────────────────────────────────────────┘ │ │
  │  └──────────────────────────────────────────────────────┘│
  └───────────────┬──────────────────────────────────────────┘
                  │  SQLAlchemy (parameterised)
  ┌───────────────▼──────────────────────────────────────────┐
  │  DATA — SQLite / PostgreSQL · model.joblib · audit_logs   │
  └───────────────────────────────────────────────────────────┘
```

**Analyst-supplied content is untrusted data, never code.** A submitted URL or
email body is parsed and scored; it is never fetched, rendered as HTML, or
executed.

---

## 1. Authentication

| | |
|---|---|
| **Asset** | User credentials, password hashes, session establishment |
| **Attack surface** | `POST /login`, `POST /register`, `POST /profile/password` |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **S** | Credential stuffing / brute force | High | Medium | Account lockout after 5 failures for 15 min; rate limit `10/min;60/hour` on login; `LOGIN_FAILURE` + `LOGIN_BLOCKED` audited | *Proposed:* exponential backoff; breached-password check |
| **I** | Username enumeration via differing responses | Low | Medium | Identical status and message for unknown user vs wrong password (test-enforced) | — |
| **I** | Password disclosure at rest | High | Low | PBKDF2-HMAC-SHA256, 600,000 iterations, per-user salt; plaintext never logged or stored (verified by sentinel scan) | *Proposed:* migrate to Argon2id |
| **E** | Privilege escalation via registration | High | Low | Registration hardcodes `Role.DEMO_USER`; role is not a form field (test-enforced) | — |
| **T** | Session forgery via predictable `SECRET_KEY` | High | Low | Production refuses to start on empty / placeholder / <32-char / low-variety secrets (7 cases verified) | *Proposed:* key rotation procedure |
| **D** | Lockout used to deny service to a real user | Low | Low | Lockout is time-boxed (15 min) and self-clearing | *Proposed:* admin unlock action |

---

## 2. User sessions

| | |
|---|---|
| **Asset** | Authenticated session cookie `phishguard_session` |
| **Attack surface** | Cookie handling, every authenticated route |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **S** | Session theft via XSS | High | Low | `HttpOnly`; CSP `script-src 'self'` with no `unsafe-inline`; Jinja autoescaping | — |
| **T** | Session tampering | High | Low | Itsdangerous-signed cookie; strong-secret guard | — |
| **S** | CSRF riding an authenticated session | Medium | Medium | Flask-WTF `CSRFProtect` on all form posts; session-authenticated API writes additionally require `X-CSRFToken`; `SameSite=Lax` | — |
| **I** | Session sent over cleartext | High | Low (local) | `SESSION_COOKIE_SECURE=True` in production; HSTS in production | Operator must terminate TLS |
| **S** | Session fixation | Medium | Low | Flask-Login issues a fresh session on login; `/logout` clears it (acceptance step 20) | *Proposed:* explicit session-id regeneration |

---

## 3. Campaign management

| | |
|---|---|
| **Asset** | Campaign definitions, target enrolment, access tokens |
| **Attack surface** | `/campaigns*`, `POST /api/campaigns` |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **E** | Demo user creates or edits campaigns | Medium | Medium | `campaign.create` / `campaign.edit` = ADMIN+ANALYST; demo gets 403 on 8 GETs and 7 POSTs (test-enforced) | — |
| **E** | Analyst deletes a campaign | Low | Low | `campaign.delete` is ADMIN-only | — |
| **T** | Unaudited modification | Medium | Low | `CAMPAIGN_CREATED` / `CAMPAIGN_UPDATED` / `CAMPAIGN_DELETED` audited with actor | — |
| **T** | Malicious template injection into simulated mail | Medium | Low | `template_key` must match a key in the fixed `TEMPLATES` dict; unknown keys raise `CampaignError` | — |
| **I** | Enumerating other campaigns by ID | Low | Medium | Auth + capability required; IDs are not secrets in a single-tenant lab | *Proposed:* per-organisation scoping for multi-tenant use |

---

## 4. Simulation tracking

| | |
|---|---|
| **Asset** | Participant interaction events, per-target access tokens |
| **Attack surface** | `/simulator/message/<token>`, `/click/<token>`, `/report/<token>` |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **S** | Guessing another participant's token | Medium | Low | `secrets.token_urlsafe(24)` (192-bit); invalid token → 404 | — |
| **I** | Reading another participant's simulated message (IDOR) | Medium | Medium | Ownership check — a different user's token returns **403** (test-enforced) | — |
| **T** | Forging interaction events to fake an awareness score | Low | Medium | Events are server-generated with fixed notes; only 4 enumerated types accepted; unknown types rejected | *Proposed:* signed, single-use event tokens |
| **I** | **Credential harvesting through the simulation** | **Critical** | **Designed out** | `simulation_events` has **no column** able to hold a submitted value; `SIMULATION_COLLECT_CREDENTIALS=False` in all profiles; no `type="password"` in any simulator template; verified by injecting 6 credential-shaped sentinels and scanning all 11 tables — zero retained | This is the project's hard safety invariant |
| **R** | Participant denies clicking | Low | Low | Timestamped events with campaign and user IDs | — |

---

## 5. Email analysis

| | |
|---|---|
| **Asset** | Submitted email content (potentially sensitive), analysis verdicts |
| **Attack surface** | `POST /email-detector`, `POST /api/analyze/email` |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **I** | Submitted body containing real credentials persisted | High | Medium | `redact_sensitive()` masks passwords, OTP/PIN, bearer tokens, API keys, JWTs, 13–19-digit card numbers, CVV, IBAN, SSN **before** the DB write; excerpt capped at 4,000 chars | — |
| **X** (XSS) | Stored XSS via email body rendered back to the analyst | Medium | Medium | Jinja autoescaping; CSP; payload round-trip test asserts escaping | — |
| **D** | Very large body exhausting memory | Medium | Low | `MAX_CONTENT_LENGTH` 1 MiB → 413 | *Proposed:* per-field length caps |
| **S (SSRF)** | Links in the email fetched server-side | High | **Designed out** | The analyzer **never** performs network I/O — links are parsed lexically only. See §7 and Phase 29. | Must remain true |
| **T** | Crafted headers causing a parser crash | Low | Medium | Header parsing is defensive; malformed input returns a scored result, not a 500 | Covered by edge-case tests |

---

## 6. URL analysis

| | |
|---|---|
| **Asset** | Submitted URLs, risk verdicts |
| **Attack surface** | `POST /url-detector`, `POST /api/analyze/url` |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **S (SSRF)** | Attacker submits `http://169.254.169.254/...` to make the server fetch cloud metadata | High | **Designed out** | **No server-side fetching of submitted URLs anywhere.** Analysis is purely lexical/static | Must remain true |
| **T** | Hostile scheme (`javascript:`, `data:`, `file:`, `ftp:`) accepted | Medium | Medium | Scheme allowlist; rejected with 400 `validation_error` (test-enforced) | — |
| **D** | Pathological URL (very long, deep nesting) causing CPU blow-up | Low | Low | Length caps; regexes avoid catastrophic backtracking | Covered by edge-case tests |
| **X** | URL reflected into the result page | Medium | Medium | Autoescaping + CSP | — |
| **R** | Analyst disputes a verdict | Low | Medium | Deterministic scoring; every indicator carries evidence; analysis rows are persisted | Detection Trace (Phase 11) |

---

## 7. ML inference

| | |
|---|---|
| **Asset** | `model.joblib`, inference integrity, published metrics |
| **Attack surface** | Model file on disk; every analysis request |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **T** | **Malicious pickle in `model.joblib` → RCE on load** | **High** | Low | The artifact is generated locally by `train.py` from a committed CSV and is never downloaded at runtime | *Proposed:* record a SHA-256 of the artifact and verify on load; never load a model from an untrusted path |
| **T** | Model swapped for a degraded one | Medium | Low | Artifact lives in the repo; metrics published in `metrics.json` | Model version + integrity hash (Phase 8) |
| **I** | Metrics overstating capability | Medium | **High** (honesty risk) | Disclaimer embedded in `model_metadata()` and shown in the UI; documented as a demonstration model | MODEL_CARD.md (Phase 27) |
| **D** | Model reloaded on every request | Low | Low | `lru_cache` on the loader — loaded once per process | — |
| **T** | Adversarial URL evading the model | Medium | High | Hybrid scoring: rules still fire when ML is confident-but-wrong; ML is 40% of the final score | Documented limitation |

---

## 8. Reports

| | |
|---|---|
| **Asset** | Generated reports (PDF/CSV/JSON), possibly containing participant names |
| **Attack surface** | `/reports*`, download routes |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **I** | Downloading another user's report (IDOR) | Medium | Medium | `report.view` capability; demo users get 403 | *Proposed:* per-report ownership check for multi-tenant use |
| **T** | Path traversal via report filename | High | Low | Filenames are generated server-side and sanitised; user input never reaches the path (test-enforced) | — |
| **I** | CSV injection (`=cmd()` opening in Excel) | Low | Medium | Values are quoted by `csv.writer` | *Proposed:* prefix leading `=+-@` with `'` |
| **D** | Huge report blocking a worker | Low | Medium | `REPORT_MAX_ROWS` 5,000 | Documented limitation (synchronous generation) |

---

## 9. Audit logs

| | |
|---|---|
| **Asset** | The security trail itself |
| **Attack surface** | `/audit-logs`, `log_audit()` callers |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **I** | Non-admin reads the trail | Medium | Medium | `audit.view` is ADMIN-only; analyst gets 403 (test-enforced) | — |
| **R** | Attacker deletes their own trail by deleting the account | High | Low | `audit_logs.actor_id` is `ON DELETE SET NULL`; `actor_username`/`actor_role` are denormalised so the record survives the account (verified: 44 rows retained after user deletion) | — |
| **I** | Secrets leaking into the trail | High | Medium | `_sanitise_extra()` masks known-sensitive keys and truncates values; API-key rotation logs only the 8-char prefix; verified by sentinel scan of audit table + log file | — |
| **T** | Log injection via newline in a field | Low | Medium | Values coerced to scalars and truncated; stored as DB columns, not concatenated text | — |
| **R** | No tamper-evidence | Medium | Low | Append-only by convention; no UI deletes | *Proposed:* hash-chained entries |

---

## 10. Database

| | |
|---|---|
| **Asset** | All persisted data |
| **Attack surface** | Every query path; the SQLite file |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **T** | SQL injection | High | Low | SQLAlchemy ORM throughout; no f-string SQL (checklist-enforced); 4 injection payloads stored as inert data (test-enforced) | — |
| **I** | Reading the SQLite file directly | High | Medium (shared host) | Passwords hashed; API keys hashed; no plaintext credentials anywhere | Filesystem permissions are the operator's responsibility |
| **T** | Orphaned rows after deletion | Low | Low | `PRAGMA foreign_keys=ON` + `ON DELETE CASCADE` + `passive_deletes` (verified: children 3,1,1 → 0,0,0) | — |
| **D** | SQLite write contention | Low | Medium | Documented limitation; PostgreSQL profile provided | — |

---

## 11. Admin functions

| | |
|---|---|
| **Asset** | User management, role assignment |
| **Attack surface** | `/users`, role-change POSTs |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **E** | Non-admin reaching admin URLs by typing them | High | **High** (the classic mistake) | `user.manage` is ADMIN-only; analyst and demo both get **403** on `/users` (verified in the live RBAC matrix) | — |
| **E** | Admin demoting themselves, orphaning the system | Low | Low | Self-demotion protection (test-enforced) | — |
| **R** | Silent role change | Medium | Low | `ROLE_CHANGED` audited with actor and target | — |

---

## 12. API endpoints

| | |
|---|---|
| **Asset** | Programmatic access to analysis, campaigns, users |
| **Attack surface** | `/api/*` |

| STRIDE | Threat | Impact | Likelihood | Existing mitigation | Additional mitigation |
|---|---|---|---|---|---|
| **S** | Stolen API key replay | Medium | Medium | Keys are 192-bit random; stored as SHA-256 digests; rotation invalidates immediately | *Proposed:* key expiry; per-key scopes |
| **I** | Key recovered from a database dump | High | Low | Only digests stored — a dump yields nothing replayable (verified: raw key in no column) | — |
| **E** | Analyst calling admin-only endpoints | Medium | Medium | `api_auth(capability)`; `/api/users` → analyst 403, admin 200 | — |
| **I** | Stack trace in an error response | Medium | Low | Uniform JSON error envelope for 400/401/403/404/405/413/429/500; zero tracebacks across 6 probes | — |
| **D** | API flooding | Low | Medium | `RATELIMIT_API` 120/min → 429 with `Retry-After` | *Proposed:* Redis storage for multi-worker |
| **T** | Malformed JSON crashing a handler | Low | Medium | Returns 400 `validation_error` (test-enforced) | — |

---

## 13. Threats explicitly out of scope

Stating these plainly is part of the model:

* **Physical access** to the host running the demo.
* **Supply-chain compromise** of pinned PyPI packages. Versions are pinned; no
  automated CVE scanning is performed.
* **TLS termination** — the app sets `Secure`/HSTS in production but does not
  provide certificates.
* **Multi-tenant isolation.** The capability model is role-based, not
  organisation-scoped. Adequate for one lab; not for hosting several
  independent customers.
* **Denial of service at network level.**
* **Insider abuse by an administrator.** An admin can legitimately read all
  data; the audit trail records that they did.

---

## 14. Highest-value residual risks

Ranked by (impact × likelihood), after existing mitigations:

1. **Over-trusting the ML verdict.** The likeliest real harm is a human acting
   on a confident-looking score. Mitigated by disclaimers, hybrid scoring and
   explainability; never fully eliminated.
2. **Simulation event forgery** by a participant wanting a better awareness
   score. Low impact, but the score should never be used punitively — stated
   in SECURITY.md and the awareness UI.
3. **Report IDOR in a multi-user deployment.** Capability checks exist;
   per-object ownership does not.
4. **Pickle-based model loading.** Safe as built (locally generated artifact),
   but a downloaded model would be arbitrary code execution. An integrity hash
   is the proposed mitigation.
