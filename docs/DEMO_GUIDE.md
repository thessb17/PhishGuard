# PhishGuard — Demo Guide

A 10-minute walkthrough for an evaluator. Every step below was executed
against the running application while writing this guide.

## 0. Start (90 seconds)

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python scripts/seed_database.py
python run.py                                      # http://127.0.0.1:5000
```

The seeder prints the `admin` API key **once** — copy it if you want to try
the REST API. Lost it? Sign in, open `/profile`, click *Rotate key*.

## 1. Demo accounts

All identities are fictional. Everything in the database is labelled demo data.

| Role | Username | Password | What it demonstrates |
|---|---|---|---|
| Administrator | `admin` | `Admin@Phish2026` | Full platform, audit log, user management |
| Security analyst | `analyst` | `Analyst@Phish2026` | Detection and campaigns, **no** audit log |
| Demo participant | `priya.demo` | `Demo@Phish2026` | Receives simulations, takes the quiz, sees nothing else |

## 2. The five-minute path

**a. Sign in as `admin` → Dashboard.** 16 KPIs and 6 charts, every value read
from the database. Prove it: insert rows directly with `flask shell` and
refresh — the numbers move.

**b. URL detector → paste `https://paypa1.example/account/verify`.**
Scores CRITICAL. Scroll to **Detection trace** and expand the stages:

```
Input → Feature extraction → Rule engine → ML model → Risk fusion → Verdict
```

This is the single best thing to look at. The rule stage names the technique
(`HOMOGLYPH`: `paypa1` normalises to `paypal`), the ML stage shows the model
version and its honesty caveat, and the fusion stage shows the arithmetic
`0.6 × heuristic + 0.4 × ML`.

**c. Now paste `https://github.com/pallets/flask`.** Scores 0. The point of a
detector is not flagging everything — this URL is long, has a path and
subdomain-free host, and is correctly left alone.

**d. Email detector → load the "CEO gift card" sample.** Shows layered
findings: sender/reply-to mismatch, urgency, financial request, secrecy.

**e. Campaigns → create one.** Pick targets, choose a template, save. Open the
campaign to see the funnel. Then sign in as `priya.demo` in a private window
and open the simulated message — **notice there is nowhere to type a
password.** That is the project's hard safety invariant, enforced by the
database schema itself.

**f. Audit logs (admin only).** Every action above is recorded. Sign in as
`analyst` and try `/audit-logs` → **403**.

## 3. Things worth asking about

* *"Why is the accuracy only 85%?"* — Because two dataset collection
  artefacts were found and removed. Before that it was 99.7% and meaningless.
  See `docs/MODEL_CARD.md` §2.
* *"Does it fetch the URL to check it?"* — No, deliberately. That would be an
  SSRF vector. Analysis is lexical only; the trade-off is documented.
* *"Can a demo user reach admin pages by typing the URL?"* — No. Try it: 403.
* *"Are API keys recoverable from the database?"* — No, only SHA-256 digests
  are stored. The key is shown once at rotation.

## 4. Verifying the claims yourself

```bash
pytest -q                              # 407 tests
python scripts/acceptance_check.py     # 21 end-to-end steps against the live server
python scripts/frontend_check.py       # crawls 14 pages for dead controls
flask security-check                   # 18-point configuration checklist
python train.py                        # retrains; metrics reproduce exactly
```

## 5. Demo data labelling

All seeded content is fictional: `cybersafe.edu` is an invented organisation,
every participant is an invented person, and simulated phishing messages use
reserved example domains. No real brand is targeted and no real person's data
appears anywhere.
