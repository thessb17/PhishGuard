#!/usr/bin/env python3
"""Final submission hygiene check for PhishGuard.

This script intentionally uses only Python's standard library, so it can run
before Flask dependencies are installed. It checks that the distributable tree
contains no runtime databases/logs/secrets and that the Python source compiles.
It does NOT claim that the live application has passed its runtime test suite;
use pytest, acceptance_check.py and smoke_test.py for that.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".log"}
FORBIDDEN_NAMES = {".env", ".coverage"}
FORBIDDEN_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", "htmlcov"}


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def main() -> int:
    failures: list[str] = []
    print("PhishGuard submission hygiene check")
    print("=" * 50)

    # Runtime artifacts / secrets.
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in FORBIDDEN_DIRS for part in rel.parts):
            continue
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"runtime artifact present: {rel}")
        if path.name == ".env.example":
            continue
        if path.name == ".env" or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            failures.append(f"secret/config artifact present: {rel}")

    # Compile every Python source without importing third-party packages.
    compile_count = 0
    for path in ROOT.rglob("*.py"):
        if any(part in FORBIDDEN_DIRS for part in path.relative_to(ROOT).parts):
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
            compile_count += 1
        except Exception as exc:
            failures.append(f"Python syntax/compile failure: {path.relative_to(ROOT)}: {exc}")

    # Basic repository hygiene.
    for required in [
        "README.md", "SECURITY.md", "requirements.txt", ".env.example",
        "run.py", "train.py", "app", "tests", "scripts",
        "docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md", "docs/MODEL_CARD.md",
    ]:
        if not (ROOT / required).exists():
            failures.append(f"required submission item missing: {required}")

    # Detect obvious raw API-key column names in current Python source. This is
    # deliberately conservative: comments/docs are not scanned here.
    for path in (ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"Column\([^\n]*(?:api[_ ]?key|secret[_ ]?key)[^\n]*String", text, re.I):
            # The legitimate hash/prefix fields are allowed; only plaintext
            # api_key columns are rejected.
            if re.search(r"\bapi_key\b\s*=\s*Column", text):
                failures.append(f"possible plaintext API-key column: {path.relative_to(ROOT)}")

    if failures:
        for item in failures:
            fail(item)
        print(f"\n{len(failures)} failure(s).")
        return 1

    print(f"[PASS] Python syntax/compile: {compile_count} files")
    print("[PASS] No runtime database/log/secret artifacts")
    print("[PASS] Required submission files present")
    print("\nSubmission hygiene: PASS")
    print("NOTE: install dependencies and run pytest/acceptance/smoke tests separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
