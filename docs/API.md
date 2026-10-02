# PhishGuard REST API

Base path: `/api` · Content type: `application/json` · Version: 1.0.0

Every endpoint returns one of two envelopes.

```jsonc
// success
{ "success": true,  "data": { /* endpoint payload */ } }

// failure
{ "success": false, "error": { "code": "validation_error", "message": "URL is required.", "field": "url" } }
```

| `error.code` | HTTP | Meaning |
|---|---|---|
| `validation_error` | 400 | Malformed or missing input. `field` names the offender. |
| `unauthorized` | 401 | No credential, or the credential is unknown/disabled. |
| `forbidden` | 403 | Authenticated, but the role lacks the capability. |
| `not_found` | 404 | No such resource — including any unmatched path under `/api/`. |
| `method_not_allowed` | 405 | Wrong HTTP verb for this endpoint. Returned as JSON, never as an HTML page. |
| `payload_too_large` | 413 | Body exceeded `MAX_CONTENT_LENGTH` (1 MB). |
| `rate_limited` | 429 | Rate limit exceeded; see the `Retry-After` header. |
| `campaign_error` | 400 | The request was well-formed but the campaign rules rejected it. |
| `server_error` | 500 | Unexpected failure. No stack trace is ever returned. |

Errors raised by a view carry `code` and `message` (plus `field` for
validation failures). Errors produced by the global HTTP error handlers —
400, 401, 403, 404, 405, 413, 429, 500 — additionally carry `status` (the
integer HTTP code) and `title` (a short human label), so a client can render
them without a lookup table:

```json
{ "success": false,
  "error": { "code": "method_not_allowed",
             "message": "That HTTP method is not supported on this endpoint.",
             "status": 405,
             "title": "Method not allowed" } }
```

Any request whose path starts with `/api/`, or that sends
`Accept: application/json`, receives JSON for **every** error status. Browser
requests to non-API routes get the styled error page instead. Neither surface
ever includes a stack trace, exception class or file path.

---

## Authentication

Two mechanisms; pick one per request.

**1. API key (recommended for scripts).** Generate or rotate yours on
`/profile`.

> **The key is shown exactly once**, on the page you land on immediately after
> rotating. PhishGuard stores only a SHA-256 digest of it, so it cannot be
> displayed again — the profile page shows only the first 8 characters
> afterwards, to identify which key is active. Lost it? Rotate to get a new
> one; the previous key stops working the moment you do.
>
> `python scripts/seed_database.py` also prints the `admin` account's key once,
> so the examples below work straight after seeding.

```bash
curl -H "X-API-Key: $PHISHGUARD_KEY" http://localhost:5000/api/dashboard/stats
# or
curl -H "Authorization: Bearer $PHISHGUARD_KEY" http://localhost:5000/api/dashboard/stats
```

**2. Session cookie (for the browser).** Sign in normally, then send
`X-CSRFToken` on every write — the API blueprint is exempt from form CSRF but
session-authenticated writes still require the header.

The key inherits exactly the capabilities of its owner's role. `GET /api/health`
is the only unauthenticated endpoint and the only one exempt from rate limits.

---

## Endpoints

### `GET /api/health`
Liveness plus model status. No auth.

```json
{ "success": true, "data": {
  "app": "PhishGuard", "version": "1.0.0", "status": "ok",
  "environment": "development",
  "ml_model": { "available": true, "model_name": "GradientBoosting", "feature_count": 38,
                "dataset": { "rows": 16083, "phishing": 8137, "legitimate": 7946 } } } }
```

---

### `POST /api/analyze/url`
Capability: `analysis.run`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `url` | string | yes | `http`/`https` only; max 2048 chars. Other schemes are rejected. |
| `persist` | bool | no | Default `true`. `false` analyses without writing a row. |

```bash
curl -X POST http://localhost:5000/api/analyze/url \
  -H "X-API-Key: $PHISHGUARD_KEY" -H "Content-Type: application/json" \
  -d '{"url":"http://198.51.100.23/paypal.com/secure/login.php?cmd=verify-account"}'
```

```jsonc
{ "success": true, "data": {
  "analysis_id": 12,
  "url": "http://198.51.100.23/paypal.com/secure/login.php?cmd=verify-account",
  "hostname": "198.51.100.23",
  "classification": "CRITICAL",
  "risk_score": 92.4,          // fused final score 0-100
  "heuristic_score": 88.0,
  "ml": { "available": true, "model": "GradientBoosting", "classification": "PHISHING",
          "risk_score": 99.0, "confidence": 0.99,
          "explanation": [ { "feature": "path_length", "value": 31, "z_score": 1.32,
                             "contribution": 0.36, "pushes": "phishing" } ] },
  "weights": { "heuristic": 0.6, "ml": 0.4 },
  "indicators": [ { "code": "IP_HOST", "title": "Host is a raw IP address",
                    "category": "infrastructure", "points": 20.0,
                    "evidence": "198.51.100.23", "severity": "critical",
                    "recommendation": "Legitimate services publish a domain name." } ],
  "features": { "url_length": 68, "num_dots": 5, "has_ip": 1 },
  "explanation": [ { "step": "Rule engine", "detail": "7 indicators fired", "value": 88.0 } ],
  "recommendation": "Block and report. Do not open on a work device.",
  "disclaimer": "Heuristic scoring is indicative, not definitive..." } }
```

---

### `POST /api/analyze/email`
Capability: `analysis.run`.

| Field | Type | Required |
|---|---|---|
| `sender` | string | no (one of sender/subject/body required) |
| `subject` | string | no |
| `body` | string | no |
| `urls` | string[] | no — links found in the body are added automatically |
| `headers` | string | no — raw RFC 822 block; enables SPF/DKIM/DMARC checks |

Response mirrors the URL endpoint and adds `header_findings`
(`spf`, `dkim`, `dmarc`, `reply_to`, `return_path`, `received_count`,
`x_mailer`) and `urls[]` with a per-link rule score.

> The stored copy of the body is redacted and truncated. The API response echoes
> only derived fields, never the raw message.

---

### `GET /api/campaigns`
Capability: `campaign.view`. Optional `?status=ACTIVE`.

```jsonc
{ "success": true, "data": { "campaigns": [
  { "campaign": { "id": 1, "name": "Q1 Password Expiry Awareness Test",
                  "template_key": "password_expiry", "status": "COMPLETED" },
    "statistics": { "participants": 6, "open_rate": 83.3, "interaction_rate": 33.3,
                    "report_rate": 33.3, "awareness_score": 64, "risk_level": "HIGH",
                    "metric_note": "Simulation metrics describe this exercise only..." } } ] } }
```

### `POST /api/campaigns`
Capability: `campaign.create` (Admin or Analyst). Returns **201**.

```jsonc
{ "name": "API created drill", "template_key": "hr_policy",
  "description": "Optional", "difficulty": "MEDIUM",
  "status": "ACTIVE", "target_ids": [4, 5, 6] }
```

`template_key` ∈ `password_expiry`, `delivery_notification`, `hr_policy`,
`it_security_alert`, `account_verification`. At least one valid `target_ids`
entry is required.

### `GET /api/campaigns/<id>`
Capability: `campaign.view`. Full statistics, per-participant breakdown and
timeline.

---

### `GET /api/reports/<id>`
Capability: `report.view`. Returns the stored report document, including its
`payload` and the `notes` array that states the report's limitations.

---

### `GET /api/dashboard/stats`
Capability: `dashboard.view`. The same aggregate the SOC dashboard renders:
`kpis`, `charts` (activity, risk_distribution, detection_split,
campaign_performance, awareness_improvement, event_mix), `ml` and `metric_note`.

### `GET /api/ml/metadata`
Capability: `analysis.view`. Model name, training timestamp, dataset make-up,
per-model metrics, feature count and the mandatory `disclaimer`.

---

### `GET /api/quiz`
Capability: `awareness.view`. Questions **without** `correct_index` or
`explanation` — the answer key never leaves the server before grading.

### `POST /api/quiz/submit`
Capability: `awareness.view`. Returns **201**.

```jsonc
{ "answers": { "1": 2, "2": 0, "3": 3 } }      // question id -> option index
```

```jsonc
{ "success": true, "data": {
  "attempt": { "id": 7, "score": 90, "correct_count": 9, "total_questions": 10,
               "answered_count": 10, "passed": true },
  "results": [ { "question_id": 1, "correct": true, "correct_index": 2,
                 "selected_index": 2, "explanation": "..." } ] } }
```

Unanswered questions count as incorrect. Out-of-range option indices are a
`validation_error`.

### `GET /api/quiz/attempts`
Your own attempt history.

---

### `GET /api/users`
Capability: `user.manage` (**Admin only**). Never includes `password_hash`,
`api_key_hash`, or any API key material.

---

## Rate limits

| Scope | Default | Config key |
|---|---|---|
| Global default | `600/hour; 120/minute` | `RATELIMIT_DEFAULT` |
| API blueprint | `120/minute` | `RATELIMIT_API` |
| Analysis endpoints | `60/minute; 600/hour` | `RATELIMIT_ANALYSIS` |
| Login | `10/minute; 60/hour` | `RATELIMIT_LOGIN` |

Exceeding a limit returns **429** with `Retry-After`. In-memory storage is the
default; set `RATELIMIT_STORAGE_URI=redis://…` for multi-process deployments
(the compose stack does this).

---

## Worked example

```bash
KEY="paste-your-key-from-/profile"
BASE="http://localhost:5000"

curl -s "$BASE/api/health" | python -m json.tool

curl -s -X POST "$BASE/api/analyze/url" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://cybersafe.edu.verify-student.example/finance/confirm?id=8812"}' \
  | python -c "import json,sys; d=json.load(sys.stdin)['data']; \
print(d['classification'], d['risk_score']); \
[print(' -', i['title'], i['points']) for i in d['indicators']]"

curl -s -X POST "$BASE/api/analyze/email" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"sender":"it@cybersafe-notices.example",
       "subject":"URGENT: verify your password now",
       "body":"Confirm at http://cybersafe-notices.example/verify",
       "headers":"Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail"}' \
  | python -m json.tool
```

## What the API will not do

* It will not fetch, resolve or sandbox a URL — analysis is offline and string-level.
* It will not accept or return a password, OTP, card number or session token.
* It will not send email. Campaign "delivery" is an in-app inbox.
* It will not expose another user's quiz attempts, or any user's API key.
