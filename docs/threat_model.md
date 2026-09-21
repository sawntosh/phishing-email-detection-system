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

<<<<<<< HEAD
Risk rating = **Likelihood × Impact** (each Low/Medium/High), giving an
overall priority used to order remediation effort. Ratings reflect
residual risk *after* the listed mitigation is applied, except where
noted as a pre-mitigation / inherent rating.

| # | Boundary | STRIDE category | Threat | Likelihood | Impact | Risk rating (residual) | Mitigation | Where implemented |
|---|---|---|---|---|---|---|---|---|
| 1 | Browser ↔ App | Spoofing | Credential theft / session hijack | Medium | High | **Medium** | TOTP 2FA, HttpOnly+SameSite cookies, rate-limited login, account lockout after 5 failures | `auth/routes.py`, `config.py` |
| 2 | Browser ↔ App | Tampering | CSRF-forged state-changing requests | Low | High | **Low** | Flask-WTF CSRF token on every POST form | `app.py` (`CSRFProtect`), all templates |
| 3 | Browser ↔ App | Elevation of Privilege | Analyst accessing admin-only pages (audit log, model performance, user management) | Low | High | **Low** | `@admin_required` / `@roles_required` decorators returning HTTP 403 | `security_utils.py` |
| 4 | Browser ↔ App | Elevation of Privilege | User A viewing User B's analysis results (IDOR) | Medium | Medium | **Medium** | Ownership check in `_get_owned_submission()`; admin override only for `is_admin` | `detector/routes.py` |
| 5 | Browser ↔ App | Elevation of Privilege | An admin account is demoted/removed leaving zero admins able to manage roles or view the audit log | Low | High | **Low** | `change_user_role` refuses to demote the last remaining `admin` account, regardless of who requests it | `admin/routes.py::change_user_role` |
| 6 | **Email ↔ App** | **Tampering / Spoofing** | **Attacker submits a crafted, malicious, or malformed email to compromise the parser or exfiltrate data** | High (attacker-controlled input by definition) | High | **Medium** | **Zero-Trust ingestion pipeline (G1–G7): deny-by-default MIME/size allow-list, safe stdlib parsing only, HTML sanitisation before any downstream code sees the body, no live requests ever made to URLs found in the email** | `analysis/zero_trust.py` |
| 7 | Email ↔ App | Information Disclosure | Attachment content exfiltrated or executed via the analysis pipeline | Medium | High | **Medium** | Attachments are **never opened, rendered, executed, or persisted** — only filename, declared MIME type, and SHA-256 hash are retained | `analysis/zero_trust.py::gate_sanitise_and_contain` |
| 8 | Email ↔ App | Denial of Service | Oversized or deeply-nested MIME payload exhausts memory/CPU | Medium | Medium | **Medium** | Hard 5 MB cap enforced before parsing (`MAX_CONTENT_LENGTH`), extension/MIME allow-list rejects non-email content immediately | `config.py`, `analysis/zero_trust.py` |
| 9 | App ↔ DB | Tampering | SQL injection via crafted email fields (subject/sender reflected into queries) | Low | High | **Low** | SQLAlchemy ORM parameterised queries throughout; no raw SQL string interpolation anywhere in the codebase | `models.py` |
| 10 | App ↔ DB | Repudiation | Analyst denies having released a quarantined phishing email, or denies a scoring decision | Low | Medium | **Low** | Every ingest/score/quarantine/release/feedback action is written to the **hash-chained** `AuditLog`; `verify_chain()` detects any retroactive edit | `models.py::AuditLog` |
| 11 | App ↔ DB | Information Disclosure | Secrets (SECRET_KEY, DB credentials) checked into source control | Low | High | **Low** | All secrets loaded from `.env` (git-ignored); `.env.example` documents required keys with empty defaults | `.env.example`, `.gitignore`, `config.py` |
| 12 | Model | Tampering / Evasion | Attacker studies the linear model to craft a feature-vector that evades detection (adversarial evasion) | High | Medium | **Medium-High** | Documented residual risk (see below) — mitigated by combining ML with independent rule-based indicators (hybrid scoring), so evading one signal alone does not zero the combined score | `analysis/risk_engine.py` |
| 13 | Model | Repudiation of model integrity | Swapped/poisoned `model.json` loaded silently | Low | High | **Low** | Model file is plain JSON (not pickle — avoids arbitrary deserialisation/RCE) and is schema-checked against `FEATURE_NAMES` on load; mismatch raises rather than silently loading | `analysis/ml_classifier.py::load` |

**Priority order for remediation effort (highest residual risk first):**
Row 12 (adversarial ML evasion) > Rows 1, 6, 7, 8 (Medium) > all remaining
Low-rated rows. This ordering is why the hybrid rules+ML design and the
Zero-Trust pipeline received the most implementation and testing effort
in this project — they mitigate the two highest-rated residual risks.
=======
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
| 12 | Model | Repudiation of model integrity | Swapped/poisoned `model.json` / `model_text.json` loaded silently | Both model files are plain JSON (not pickle — avoids arbitrary deserialisation/RCE); the structured model is schema-checked against `FEATURE_NAMES`, the text model against its format version and array lengths; mismatch raises rather than silently loading | `analysis/ml_classifier.py::load`, `analysis/text_model.py::load` |
| 13 | Email ↔ App ↔ Internet | Spoofing / SSRF | An email carries a link crafted to make the server call an internal address (cloud metadata, localhost, LAN) when a lookup is performed | Ingestion makes **no** network calls. Redirect resolution is analyst-triggered, off by default, and refuses any hop whose DNS answers are not globally routable (private, loopback, link-local, CGNAT, IPv4-mapped IPv6), connects to the *validated* IP (no DNS-rebinding gap), allows only http/https on ports 80/443, HEAD only, 5 hops / 5 s, no body read | `analysis/threat_intel.py::resolve_redirect_chain` |
| 14 | Email ↔ App ↔ Internet | Tampering | Attacker-controlled text steers the VirusTotal request (path/host injection, API-key exfiltration) | Host is a constant; only a strictly validated domain (`DOMAIN_RE`) or SHA-256 hex digest is placed in the path; the HTTP helper refuses any URL not under the VirusTotal API base; key comes from `.env`, never the UI or logs | `analysis/threat_intel.py::lookup_domain`, `::lookup_file_hash` |
| 15 | Browser ↔ App | Repudiation / DoS | Abuse of external lookups to burn API quota or use the app as a scanning proxy | Analyst/admin only, per-user limit of 20 lookups/hour, hard cap of `THREAT_INTEL_MAX_LOOKUPS` per click, every lookup written to the hash-chained audit log | `detector/routes.py::run_threat_intel` |
| 16 | Email ↔ Analyst | Tampering (client side) | Spreadsheet formula injection: a subject/sender such as `=HYPERLINK(...)` executes when an analyst opens a CSV export | Every CSV cell starting with `= + - @ TAB CR` is prefixed with `'` | `detector/routes.py::_csv_safe` |
| 17 | Email ↔ Analyst | Tampering / DoS | Markup in the subject/body breaks or hijacks the PDF renderer (reportlab parses XML-like tags) | All attacker-controlled text is XML-escaped before it reaches a `Paragraph` | `detector/pdf_report.py::_e` |
| 18 | Email ↔ Analyst | Spoofing (social engineering) | An analyst clicks a live phishing link shown in a result page | Domains and URLs are displayed defanged (`hxxp`, `[.]`), auto-escaped, and never rendered as links | `analysis/explanations.py::defang`, `templates/detector/result.html` |
| 19 | Model | Denial of Service | An enormous body makes the text tokenizer consume unbounded CPU | Input is truncated to 20 000 characters before tokenisation | `analysis/text_model.py::MAX_INPUT_CHARS` |
>>>>>>> f678d98 (Add real-corpus text model, threat intel, redirect checks, review queue)

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
- **Dataset bias.** The text model is trained on 2015–2021 Nazario phishing mail versus 2000s Enron corporate mail. Part of the measured separation is era/style, not intent, so the held-out F1 (~0.97) overstates real-world accuracy, especially on modern legitimate marketing mail. Mitigations: corpus-identifying tokens (`enron`, names, `energy`…) are excluded, exact duplicates are removed before the split, and the ML signal is blended 50/50 with independent rule-based checks. Analyst false-positive feedback (exportable CSV) is the intended route to retraining on in-domain mail.
- **Evasion.** Because the text model is a transparent linear model, an attacker who reads its explanation can pad an email with "legitimate" words. The rule-based URL/header checks are unaffected by padding, which is the main reason the score is hybrid.
- **Redirect resolver residual risk.** It is disabled by default. When enabled the server does contact attacker-chosen hosts (only public IPs on 80/443, HEAD only), which reveals the analyst's server IP to that host. Run it from an isolated egress network in any real deployment.
- **Blocklist freshness.** The offline blocklist is only as current as the feeds an operator imports; it is a fast first filter, not a replacement for the analyst-triggered VirusTotal lookup.

## Ethics / authorised-testing statement

The ML training corpora (`data/`, git-ignored and not redistributed) are the
public research datasets used by the reference project: Jose Nazario's phishing
corpus and the Enron e-mail dataset. They contain historical, real messages
(including real names in the Enron set), so they are used for offline model
training only, never displayed in the application, and must not be republished.

All sample phishing emails in `sample_emails/` are synthetic, contain no
real credentials or live malicious payloads, and reference only fictitious
or clearly-marked demonstration domains (`paypa1-secure.com`, etc. — none
of which resolve or are contacted by the application, per the no-live-request
design above). No real individual's data is used or targeted anywhere in
this project.
