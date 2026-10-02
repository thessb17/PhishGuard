# PhishGuard — Limitations

A single place that states plainly what this project does **not** do. Written
because a security tool that overstates itself is worse than one that admits
its boundaries: an analyst who trusts a wrong verdict acts on it.

Everything here is a measured or structural fact, not a disclaimer template.

---

## 1. Detection

| Limitation | Detail |
|---|---|
| **Misses ~1 phishing URL in 4** | 406 false negatives of 1,628 on the model's own held-out split. |
| **Flags ~4.5% of legitimate URLs** | 72 false positives of 1,589. |
| **String-level analysis only** | No DNS resolution, no page fetch, no redirect following, no TLS inspection, no WHOIS, no reputation feed. This is a deliberate SSRF-avoidance decision (see §5), not an oversight. |
| **Cannot see content** | A phishing page on a compromised high-reputation domain with a short, clean URL produces no lexical signal and scores LOW. |
| **Shorteners hide the destination** | `bit.ly/xyz` is noted as a shortener; what it points at is unknowable without fetching it, which the platform refuses to do. |
| **HTTPS is not safety** | A certificate proves transport encryption, not intent. `is_https` contributes no positive risk score, and the UI says so. |
| **Email authentication proves the domain, not the intent** | SPF/DKIM/DMARC all pass for mail sent from a compromised legitimate mailbox. |
| **Not adversarially robust** | An attacker who reads `RULE_WEIGHTS` and this documentation can construct URLs that score low. |
| **English-only semantics** | The suspicious-keyword list and brand dictionary are English/Western-weighted; non-English phishing is under-detected. |

### Known residual false positive

A credential-reset path on an unfamiliar domain looks exactly like phishing.
`portal.cybersafe.edu/password/renew` scored ~41.7 (MEDIUM) before the
organisation's domain was added to `data/intel/allowlist.txt`, which brought
it to 5.0. Tuning the allowlist is the intended remedy, and it is the first
thing to do in a new deployment.

---

## 2. Machine learning

| Limitation | Detail |
|---|---|
| **Demonstration model** | 0.8514 accuracy / 0.8364 F1 on a held-out split of a public research corpus. Not a claim about live traffic. |
| **Two collection artefacts were found and corrected** | Removing them cost 0.8857 → 0.8514 accuracy. The earlier number was partly measuring the artefact. |
| **Random split is mildly optimistic** | Measured at +0.0117 F1 versus a group-aware split across 5 seeds. Published rather than hidden. |
| **No temporal validation** | The corpus is a snapshot. Phishing URL fashions drift and no time-based holdout was performed. |
| **No calibration study** | The reported "confidence" is a transformed probability, not a calibrated one. A 0.9 does not mean 90% of such URLs are phishing. |
| **Pickle-based artifact** | `joblib.load` executes pickle. Safe as shipped (the artifact is built locally from a committed CSV) but loading a downloaded model would be arbitrary code execution. |
| **Brand/TLD/length bias** | Documented in `MODEL_CARD.md` §7. |

---

## 3. Simulation metrics

Campaign numbers — open rate, click rate, report rate, awareness score —
describe **these fictional participants in this controlled exercise**. They
are *simulation metrics*.

They are **not**:

* real-world phishing prevalence,
* a prediction of breach likelihood,
* a measure of an individual's competence,
* grounds for disciplinary or employment decisions.

The awareness score uses a transparent published formula and exists to show a
participant their own trend over time.

---

## 4. Scope and architecture

| Limitation | Detail |
|---|---|
| **Single-tenant** | The capability model is role-based, not organisation-scoped. Fine for one lab; not for hosting independent customers. Report access is capability-checked, not per-object owner-checked. |
| **SQLite by default** | Adequate for a demo; concurrent write loads need the PostgreSQL profile. |
| **In-memory rate limiting by default** | Per-process only. Multi-worker deployments need the Redis storage URI. |
| **Synchronous report generation** | A very large campaign report blocks a worker. `REPORT_MAX_ROWS` (5,000) bounds it. |
| **No automated retention/purge job** | Deletion cascades are wired and verified; scheduling is left to the deployer. Manual procedure in `ARCHITECTURE.md`. |
| **No email delivery** | Simulated messages are rendered in-app. Inbox behaviour (previews, mobile rendering, forwarding) cannot be measured. |
| **No accessibility audit** | Keyboard navigation and semantic markup were considered; no formal WCAG audit was performed. |

---

## 5. Security boundaries

**Deliberately absent, and must stay absent:**

* **Server-side fetching of submitted URLs.** The platform never issues a
  request to a URL a user supplies. This removes an entire SSRF class — no
  cloud metadata endpoint, no internal host scanning, no blind SSRF. The
  cost is that content-based detection is impossible. We consider that trade
  correct for this application.
* **Attachment execution.** Attachment handling is metadata-only (filename,
  extension, MIME type, size). Nothing is opened, parsed as a document, or
  executed.
* **Credential collection in simulations.** `simulation_events` has no column
  capable of storing a submitted value, and `SIMULATION_COLLECT_CREDENTIALS`
  is `False` in every profile. Verified by injecting six credential-shaped
  sentinels and scanning all 11 tables: zero retained.

**Not performed:**

* Penetration testing. The 18-point checklist verifies *configuration*, not
  the absence of vulnerabilities.
* Dependency CVE scanning. Versions are pinned; no automated advisory check runs.
* Fuzzing beyond the edge-case suite.
* Formal threat-model review by a second party.
* Load or stress testing.

---

## 6. Verification gaps

Stated so nobody assumes otherwise:

| Area | Status |
|---|---|
| **Docker Compose stack** | **Never booted.** No Docker daemon in the verification environment. The compose file is statically validated (required variables, no literal secrets) but the running stack, gunicorn path and entrypoint migrate-and-seed sequence are unverified. |
| **Gunicorn `Server` header** | The Werkzeug dev-server banner is suppressed; gunicorn's own banner is not. A reverse proxy would handle this in a real deployment. |
| **PostgreSQL profile** | Models use portable SQLAlchemy constructs and the migration applies cleanly on SQLite; the Postgres path has not been executed. |
| **GitHub Actions workflow** | Validated as YAML and every step reproduced locally, but never executed on GitHub's runners. |
| **Statement coverage** | 82.5%. The untested remainder is mostly defensive branches in `utils/decorators.py`, `utils/redaction.py`, `utils/formatting.py` and `services/report_service.py`. |

---

## 7. What this project is

An **internship-level defensive security portfolio project**: a complete,
runnable, documented, honestly-evaluated phishing simulation and detection
platform.

It is not a product, not production-ready, and not a replacement for a
commercial secure email gateway. Presenting it as any of those would
undermine the thing it is actually good at — showing that the author
understands both how detection works and where it breaks.
