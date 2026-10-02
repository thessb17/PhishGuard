#!/usr/bin/env sh
# Container entrypoint: wait for the database, migrate, optionally seed.
set -e

echo "[phishguard] starting entrypoint"

if [ -n "$DATABASE_URL" ]; then
  echo "[phishguard] waiting for the database to accept connections..."
  python - <<'PY'
import os, sys, time
from sqlalchemy import create_engine, text

uri = os.environ["DATABASE_URL"].replace("postgres://", "postgresql+psycopg2://", 1)
for attempt in range(1, 31):
    try:
        create_engine(uri).connect().execute(text("SELECT 1"))
        print("[phishguard] database is ready")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"[phishguard] attempt {attempt}/30: {type(exc).__name__}")
        time.sleep(2)
print("[phishguard] database never became reachable", file=sys.stderr)
sys.exit(1)
PY
fi

echo "[phishguard] applying database migrations"
FLASK_APP=run.py python -m flask db upgrade || {
  echo "[phishguard] migration failed, falling back to create_all"
  FLASK_APP=run.py python -m flask init-db
}

if [ "${SEED_DEMO_DATA:-1}" = "1" ]; then
  echo "[phishguard] seeding fictional demo data (set SEED_DEMO_DATA=0 to skip)"
  python scripts/seed_database.py --quiet || echo "[phishguard] seeding skipped"
fi

echo "[phishguard] launching: $*"
exec "$@"
