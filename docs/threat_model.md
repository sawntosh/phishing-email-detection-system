# Threat Model — Explainable Phishing Email Detector

ICT932 Assessment 3, Project 3. STRIDE analysis across the three trust
boundaries: **browser ↔ application**, **application ↔ database**, and
**application ↔ submitted email content** (the last is the boundary
specific to this project — every uploaded email is, by definition,
attacker-controlled input).

## Assets

- User credentials and TOTP secrets
- Submitted email content and derived analysis (may contain PII from the
  original message)
- The trained ML model and its feature-extraction logic (an attacker who
  can reverse-engineer scoring can craft evasive phishing emails)
- The audit log (integrity of the historical record itself is an asset)
- Analyst/admin session state

## Trust boundaries & STRIDE

| # | Boundary | STRIDE category | Threat | Mitigation | Where implemented |
|---|---|---|---|---|---|
| 1 | Browser ↔ App | Spoofing | Credential theft / session hijack | TOTP 2FA, HttpOnly+SameSite cookies, rate-limited login, account lockout after 5 failures | `auth/routes.py`, `config.py` |
| 2 | Browser ↔ App | Tampering | CSRF-forged state-changing requests | Flask-WTF CSRF token on every POST form | `app.py` (`CSRFProtect`), all templates |
| 3 | Browser ↔ App | Elevation of Privilege | Analyst accessing admin-only pages (audit log, model performance) | `@admin_required` / `@roles_required` decorators returning HTTP 403 | `security_utils.py` |
| 4 | Browser ↔ App | Elevation of Privilege | User A viewing User B's analysis results (IDOR) | Ownership check in `_get_owned_submission()`; admin override only for `is_admin` | `detector/routes.py` |
| 5 | **Email ↔ App** | **Tampering / Spoofing** | **Attacker submits a crafted, malicious, or malformed email to compromise the parser or exfiltrate data** | **Zero-Trust ingestion pipeline (G1–G7): deny-by-default MIME/size allow-list, safe stdlib parsing only, HTML sanitisation before any downstream code sees the body, no live requests ever made to URLs found in the email** | `analysis/zero_trust.py` |
| 6 | Email ↔ App | Information Disclosure | Attachment content exfiltrated or executed via the analysis pipeline | Attachments are **never opened, rendered, executed, or persisted** — only filename, declared MIME type, and SHA-256 hash are retained | `analysis/zero_trust.py::gate_sanitise_and_contain` |
| 7 | Email ↔ App | Denial of Service | Oversized or deeply-nested MIME payload exhausts memory/CPU | Hard 5 MB cap enforced before parsing (`MAX_CONTENT_LENGTH`), extension/MIME allow-list rejects non-email content immediately | `config.py`, `analysis/zero_trust.py` |
| 8 | App ↔ DB | Tampering | SQL injection via crafted email fields (subject/sender reflected into queries) | SQLAlchemy ORM parameterised queries throughout; no raw SQL string interpolation anywhere in the codebase | `models.py` |
| 9 | App ↔ DB | Repudiation | Analyst denies having released a quarantined phishing email, or denies a scoring decision | Every ingest/score/quarantine/release/feedback action is written to the **hash-chained** `AuditLog`; `verify_chain()` detects any retroactive edit | `models.py::AuditLog` |
| 10 | App ↔ DB | Information Disclosure | Secrets (SECRET_KEY, DB credentials) checked into source control | All secrets loaded from `.env` (git-ignored); `.env.example` documents required keys with empty defaults | `.env.example`, `.gitignore`, `config.py` |
| 11 | Model | Tampering / Evasion | Attacker studies the linear model to craft a feature-vector that evades detection (adversarial evasion) | Documented residual risk (see below) — mitigated by combining ML with independent rule-based indicators (hybrid scoring), so evading one signal alone does not zero the combined score | `analysis/risk_engine.py` |
| 12 | Model | Repudiation of model integrity | Swapped/poisoned `model.json` loaded silently | Model file is plain JSON (not pickle — avoids arbitrary deserialisation/RCE) and is schema-checked against `FEATURE_NAMES` on load; mismatch raises rather than silently loading | `analysis/ml_classifier.py::load` |

## Advanced feature evaluation: Zero-Trust email ingestion

**Design summary.** Every submission is treated as hostile until it has
passed all seven gates (see `analysis/zero_trust.py` module docstring):
authorization → size/MIME allow-list → structural parse → content
sanitisation → attachment containment → capability-scoped analysis →
quarantine-by-default. There is no default-allow path; any exception
anywhere in the chain results in outright rejection, never silent
pass-through.

**Measurable evaluation (see `tests/test_zero_trust.py`):**

| Property tested | Result |
|---|---|
| Unauthenticated submission rejected at G1 | Pass |
| Disallowed file extension (.exe) rejected at G2 | Pass |
| Oversized upload rejected at G2 | Pass |
| Empty upload rejected at G2 | Pass |
| Unparseable/binary content rejected at G3 | Pass |
| `<script>`/`onclick=` stripped from HTML body before any downstream module sees it | Pass |
| Attachment bytes never appear in the returned result — only filename/type/SHA-256 | Pass |
| Valid, well-formed email passes all 5 applicable gates and is fully sanitised | Pass |

**Residual risk / limitations to state honestly in the report:**
- The sanitiser is a targeted denylist (script/style/on\* handlers/meta-refresh/iframe), not a full HTML sanitisation library (e.g. `bleach`); for a production deployment, swap in a maintained allow-list-based sanitiser.
- No live SPF/DKIM/DMARC re-verification is performed (by design — the module never makes outbound network calls driven by attacker-controlled input); it only parses `Authentication-Results` already recorded by the receiving mail server, so a submission with no such header degrades gracefully to "not evaluated" rather than a false pass.
- Quarantine release is analyst/admin-gated but does not currently require a second approver (four-eyes) — a reasonable future-work item for a real deployment (see report Section 9).

## Ethics / authorised-testing statement

All sample phishing emails in `sample_emails/` are synthetic, contain no
real credentials or live malicious payloads, and reference only fictitious
or clearly-marked demonstration domains (`paypa1-secure.com`, etc. — none
of which resolve or are contacted by the application, per the no-live-request
design above). No real individual's data is used or targeted anywhere in
this project.
