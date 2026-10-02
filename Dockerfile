# ---------------------------------------------------------------------------
# PhishGuard - production-ish container image.
# Runs as a non-root user, ships the pre-trained model, serves with gunicorn.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_CONFIG=production

WORKDIR /app

# Build dependencies for psycopg2 / scientific wheels, removed afterwards.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt \
 && apt-get purge -y --auto-remove build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# Unprivileged runtime user; the instance directory holds the SQLite DB + logs.
RUN useradd --create-home --shell /usr/sbin/nologin phishguard \
 && mkdir -p /app/instance \
 && chown -R phishguard:phishguard /app
USER phishguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

# entrypoint.sh waits for the database, applies migrations and seeds demo data.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60", \
     "--access-logfile", "-", "run:app"]
