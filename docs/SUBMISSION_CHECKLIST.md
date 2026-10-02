# PhishGuard GitHub submission checklist

## Repository hygiene
- [ ] No `.env` or production secrets are committed.
- [ ] No private keys, API keys, credentials, runtime databases or logs are committed.
- [ ] No virtual environment, cache, coverage, build or generated export artifacts are committed.
- [ ] The committed ML model and dataset are intentional and documented.
- [ ] Demo data is fictional and contains no real credentials or targets.

## Verification
- [ ] Run the full pytest suite and record the actual result.
- [ ] Run coverage and record the actual result.
- [ ] Run the 21-step acceptance check against a live server.
- [ ] Run the frontend/dead-link check.
- [ ] Run the security configuration check.
- [ ] Run `compileall`/static checks before release.
- [ ] Verify Docker startup with fresh environment values.

## Presentation
- [ ] Add only real, sanitized screenshots under `docs/screenshots/`.
- [ ] Confirm README test numbers describe the release verification, not an older run.
- [ ] Confirm documentation links work.
- [ ] Confirm `LICENSE` is present.
- [ ] Confirm the defensive/safe-simulation policy is visible before any demo instructions.

## Final Git check
Run `git status`, inspect `git ls-files`, and search the staged tree for secrets before pushing.
