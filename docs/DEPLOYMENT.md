# PhishGuard — Deployment

Three supported ways to run it. The first two are verified; the third is
documented but was not booted in the verification environment (no Docker
daemon available) — stated here rather than implied.

---

## 1. Local development (verified)

### Fastest path — any platform

```bash
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
python scripts/setup.py --run
```

Idempotent and safe to re-run. `--check` reports status without changing
anything (exit 1 if dependencies are missing); `--reset` rebuilds the demo
data. Every command it runs is echoed, so nothing is hidden.

### Linux / macOS / WSL

```bash
git clone <repo> && cd phishguard
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python scripts/seed_database.py
python run.py                       # http://127.0.0.1:5000
```

### Windows (PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\seed_database.py
python run.py
```

No `.env` is required for local development: the dev profile falls back to a
clearly-labelled placeholder secret, and `flask security-check` warns about
it every time.

### Exposing it on a LAN for a demo

```bash
HOST=0.0.0.0 FLASK_DEBUG=0 python run.py
```

**Always pass `FLASK_DEBUG=0`** when binding `0.0.0.0`. The Werkzeug debugger
exposes an interactive Python console; `DevelopmentConfig.DEBUG` honours this
variable precisely so it can be turned off.

---

## 2. Production profile (configuration verified; not deployed)

```bash
export FLASK_CONFIG=production
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/phishguard"
export RATELIMIT_STORAGE_URI="redis://localhost:6379/0"
export SESSION_COOKIE_SECURE=1
export ENABLE_HSTS=1

flask db upgrade
gunicorn --bind 0.0.0.0:8000 --workers 3 "run:app"
```

`ProductionConfig.init_app` refuses to start if `SECRET_KEY` is missing, is a
known placeholder, is shorter than 32 characters, or has too little character
variety. Seven rejection cases are covered by tests.

**You must provide TLS.** The app sets `Secure` cookies and HSTS but does not
terminate TLS; put it behind nginx, Caddy or a load balancer.

**Gunicorn sends its own `Server` header.** The dev-server banner is
suppressed in `run.py`; for gunicorn, strip it at the reverse proxy.

---

## 3. Docker Compose (not booted in verification)

```bash
cp .env.example .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(24))" >> .env
docker compose up --build            # http://localhost:8000
```

`docker-compose.yml` contains **no secrets**. `SECRET_KEY`, `POSTGRES_USER`,
`POSTGRES_PASSWORD` and `POSTGRES_DB` are declared `${VAR:?error}` — required
with no fallback — so the stack fails loudly rather than booting with a
password that is public in the repository.

Stack: **web** (gunicorn, 3 workers, non-root) + **db** (PostgreSQL 16) +
**redis** (rate-limit storage). The entrypoint waits for the database,
applies migrations, then seeds demo data unless `SEED_DEMO_DATA=0`.

> **Verification status:** the compose file is syntax-checked and its variable
> wiring is validated, but the stack has not been started. Treat first boot as
> untested.

---

## 3a. Embedding the app in an iframe (and the CSRF error it causes)

If PhishGuard is framed by a **different origin** (a preview proxy, a portal,
an LMS), the browser applies third-party-cookie rules. With the default
`SameSite=Lax` the session cookie is **withheld inside that frame**, so pages
render but every form POST fails with:

```
HTTP 400 - CSRF validation failed
Your session token expired or was missing.
```

That is a cookie-delivery problem wearing a CSRF costume. Two valid fixes:

| Situation | Setting |
|---|---|
| Normal use, `http://localhost` or same-origin | `SESSION_COOKIE_SAMESITE=Lax`, `SESSION_COOKIE_SECURE=0` (**default**) |
| Embedded cross-origin, served over **HTTPS** | `SESSION_COOKIE_SAMESITE=None`, `SESSION_COOKIE_SECURE=1` |

`SameSite=None` **requires** `Secure`, and `Secure` cookies are never sent over
plain HTTP — so the embedded configuration only works behind TLS. Do not set
`SESSION_COOKIE_SECURE=1` for plain-HTTP localhost; the cookie will be stored
and never sent back.

The application checks this at startup and logs a specific warning for each
incoherent combination, rather than leaving you to deduce it from a CSRF
error. Simply opening the preview in a **new top-level tab** also avoids the
problem entirely.

---

## 4. Configuration reference

Full table in `README.md` §15. The variables that matter most:

| Variable | Default | Why it matters |
|---|---|---|
| `SECRET_KEY` | placeholder in dev | Signs sessions. Production refuses weak values. |
| `FLASK_CONFIG` | `development` | Selects the profile. |
| `FLASK_DEBUG` | `1` in dev | **Set to `0` on any network-reachable bind.** |
| `DATABASE_URL` | SQLite in `instance/` | `postgres://` is auto-normalised. |
| `SESSION_COOKIE_SECURE` | `0` (dev) / `1` (prod) | HTTPS-only cookies. |
| `RATELIMIT_STORAGE_URI` | `memory://` | Use Redis for multi-worker. |
| `FRAME_ANCESTORS` | `'self'` | Widen only for a trusted embed. |
| `SECURITY_LOG_FILE` | unset | Path for the JSON security event stream. |

---

## 5. Post-deployment checklist

```bash
flask security-check                   # 18 checks; expect 0 failures
python scripts/acceptance_check.py     # 21 end-to-end steps
python scripts/frontend_check.py       # dead-control crawl
```

Then tune detection for your environment:

1. Add your own domains to `data/intel/allowlist.txt` — this is the single
   highest-value change, and it is what removed the known
   `portal.cybersafe.edu` false positive.
2. Add any domains from your own incident history to
   `data/intel/denylist.txt`.
3. Review `data/intel/brands.json` for brands your users actually see.
4. Re-train on your own labelled data if you have any: `python train.py`.

---

## 6. Backup and retention

There is **no automated retention or purge job**. Deletion cascades are wired
and verified (deleting a user removes their targets, events and attempts;
audit rows survive via `ON DELETE SET NULL`). Scheduling is yours:

```bash
# SQLite
cp instance/phishguard.db backups/phishguard-$(date +%F).db
# PostgreSQL
pg_dump "$DATABASE_URL" > backups/phishguard-$(date +%F).sql
```

A manual audit-log purge procedure is documented in `ARCHITECTURE.md`.
