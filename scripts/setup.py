#!/usr/bin/env python3
"""One-command setup for PhishGuard.

Takes a fresh clone to a running application, and is safe to re-run at any
time: every step is idempotent and skipped when already satisfied.

    python scripts/setup.py              # check, install, seed, print next steps
    python scripts/setup.py --run        # ... and start the server
    python scripts/setup.py --reset      # drop and re-seed the demo data
    python scripts/setup.py --check      # report status only, change nothing

Why this exists: dependencies live outside the repository, so a cloned or
restored workspace can have the code, the database and the trained model all
present while `import flask` still fails. This script diagnoses that in one
place instead of leaving you to work it out from an ImportError.

Deliberately NOT hidden by this script: it prints every command it runs, so
nothing about the setup is a mystery.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
DB_PATH = ROOT / "instance" / "phishguard.db"
MODEL_PATH = ROOT / "app" / "ml" / "model.joblib"
DATASET_PATH = ROOT / "data" / "datasets" / "url_dataset.csv"

OK, WARN, BAD = "  [ok]  ", "  [warn]", "  [fail]"


def say(*parts):
    print(*parts, flush=True)


def run(cmd: list[str], *, label: str) -> bool:
    """Run a command, echoing it first. Returns True on success."""
    say(f"\n$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        say(f"{BAD} {label} failed (exit {result.returncode})")
        return False
    return True


def in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def deps_installed() -> tuple[bool, list[str]]:
    """Check the imports that actually matter, not the full pin list."""
    required = {
        "flask": "Flask", "flask_sqlalchemy": "Flask-SQLAlchemy",
        "flask_login": "Flask-Login", "flask_wtf": "Flask-WTF",
        "flask_limiter": "Flask-Limiter", "flask_migrate": "Flask-Migrate",
        "sqlalchemy": "SQLAlchemy", "sklearn": "scikit-learn",
        "pandas": "pandas", "numpy": "numpy", "joblib": "joblib",
        "reportlab": "reportlab", "dotenv": "python-dotenv",
    }
    missing = []
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    return (not missing), missing


def report_status() -> dict:
    say("Environment")
    say(f"  python          {sys.version.split()[0]}  ({sys.executable})")
    say(f"  virtualenv      {'yes' if in_virtualenv() else 'NO - installing into the system interpreter'}")

    ok_deps, missing = deps_installed()
    say("\nDependencies")
    if ok_deps:
        say(f"{OK} all required packages importable")
    else:
        say(f"{BAD} missing: {', '.join(missing)}")

    say("\nArtifacts")
    for label, path, note in (
        ("database", DB_PATH, "created by the seeder"),
        ("ML model", MODEL_PATH, "committed; rebuild with python train.py"),
        ("dataset", DATASET_PATH, "committed; rebuild with scripts/build_dataset.py"),
    ):
        if path.exists():
            size = path.stat().st_size
            unit = f"{size/1_048_576:.1f} MB" if size > 1_048_576 else f"{size/1024:.0f} KB"
            say(f"{OK} {label:<10} {path.relative_to(ROOT)}  ({unit})")
        else:
            say(f"{WARN} {label:<10} missing - {note}")

    return {"deps": ok_deps, "missing": missing, "db": DB_PATH.exists()}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Set up PhishGuard: install dependencies, seed the demo database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--run", action="store_true",
                        help="start the development server when setup finishes")
    parser.add_argument("--reset", action="store_true",
                        help="drop and re-seed the demo data")
    parser.add_argument("--check", action="store_true",
                        help="report status only; install and change nothing")
    parser.add_argument("--host", default="127.0.0.1",
                        help="host for --run (use 0.0.0.0 to expose on a LAN)")
    parser.add_argument("--port", default="5000", help="port for --run")
    args = parser.parse_args()

    say("=" * 70)
    say("  PhishGuard setup")
    say("=" * 70)

    status = report_status()

    if args.check:
        say("\n--check: nothing was modified.")
        return 0 if status["deps"] else 1

    # ---- dependencies -------------------------------------------------
    if not status["deps"]:
        if not in_virtualenv():
            say("\n" + WARN + " not running inside a virtual environment.")
            say("         Recommended first:")
            say("           python -m venv venv && source venv/bin/activate")
            say("           (Windows: venv\\Scripts\\activate)")
        if not REQUIREMENTS.exists():
            say(f"{BAD} {REQUIREMENTS} not found")
            return 1
        if not run([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)],
                   label="dependency install"):
            return 1
        ok_deps, missing = deps_installed()
        if not ok_deps:
            say(f"{BAD} still missing after install: {', '.join(missing)}")
            return 1
        say(f"{OK} dependencies installed")

    # ---- database -----------------------------------------------------
    seed_cmd = [sys.executable, "scripts/seed_database.py"]
    if args.reset:
        seed_cmd.append("--reset")
        say("\nRe-seeding demo data (--reset)")
    elif not DB_PATH.exists():
        say("\nNo database found - seeding demo data")
    else:
        say(f"\n{OK} database already present - leaving it alone "
            f"(use --reset to rebuild)")
        seed_cmd = []

    if seed_cmd and not run(seed_cmd, label="database seeding"):
        return 1

    # ---- done ---------------------------------------------------------
    say("\n" + "=" * 70)
    say("  Setup complete")
    say("=" * 70)
    say("""
  Start the server
      python run.py                       http://127.0.0.1:5000

  Sign in (fictional demo accounts)
      admin        / Admin@Phish2026      full platform + audit log
      analyst      / Analyst@Phish2026    detection + campaigns
      priya.demo   / Demo@Phish2026       simulation participant

  Verify the project yourself
      pytest -q                           407 tests
      python scripts/acceptance_check.py  21 live steps (server must be running)
      python scripts/frontend_check.py    dead-control crawl
      flask security-check                18-point configuration checklist

  Worth seeing first
      URL detector -> paste  https://paypa1.example/account/verify
      then expand the Detection trace panel.
""")

    if args.run:
        env = dict(os.environ, HOST=args.host, PORT=str(args.port))
        env.setdefault("FLASK_DEBUG", "0" if args.host == "0.0.0.0" else "1")
        if args.host == "0.0.0.0":
            say(f"{WARN} binding 0.0.0.0 - forcing FLASK_DEBUG=0 so the "
                f"Werkzeug debugger stays off.\n")
            env["FLASK_DEBUG"] = "0"
        say(f"$ HOST={args.host} PORT={args.port} python run.py\n")
        return subprocess.run([sys.executable, "run.py"], cwd=ROOT, env=env).returncode

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say("\ninterrupted")
        sys.exit(130)
