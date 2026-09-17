# Explainable Phishing Email Detector

ICT932 – Cybersecurity Testing and Assurance, Assessment 3, Project 3.

A web-based tool that analyses `.eml`/`.txt` email submissions for phishing
indicators using a **hybrid rules + ML engine**, explains every verdict at
the feature level, and ingests every submission through a **Zero-Trust
pipeline** (the mandatory advanced security feature) that treats every
message as hostile until proven otherwise.

See `docs/architecture.md` for diagrams and `docs/threat_model.md` for the
full STRIDE analysis and advanced-feature evaluation.

## Feature checklist (maps to the assessment brief)

- [x] Secure login with RBAC (analyst/admin) and TOTP 2FA
- [x] Safe `.eml`/text parsing; attachments handled by metadata/hash only
- [x] URL/domain analysis, look-alike domain detection, IP-literal/punycode/shortener checks
- [x] Header/sender analysis: SPF/DKIM/DMARC parsing, display-name spoofing, reply-to mismatch
- [x] Content/keyword/structure analysis with a human-readable risk score
- [x] Hybrid detection: rules + Logistic Regression ML classifier
- [x] Explainability view (top contributing features per prediction)
- [x] Quarantine simulation, analyst feedback workflow, false-positive review
- [x] Exportable PDF / CSV / JSON reports
- [x] Dashboard: detection rates, common indicators, false positives
- [x] **Advanced feature: Zero-Trust email-ingestion pipeline**
- [x] DevSecOps: GitHub Actions 5-stage pipeline (Build/Lint → SAST → Dependency check → Test+coverage gate → Deploy)
- [x] Tamper-evident, hash-chained audit log with chain-verification UI
- [x] Precision/recall/F1/confusion matrix/false-positive rate reporting (`admin/model-performance`)

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit .env: set SECRET_KEY, optionally DEFAULT_ADMIN_*

python train_model.py              # trains the ML classifier -> instance/model.json

cd src
python app.py                      # http://127.0.0.1:5000
```

First run: either set `DEFAULT_ADMIN_USERNAME/EMAIL/PASSWORD` in `.env`
before first start to auto-create an admin, **or** just register the first
account at `/auth/register` and select role `admin`. Either way you'll be
sent through TOTP 2FA setup (scan the QR code with Google Authenticator/Authy)
before you can log in.

Try it immediately with the two sample emails in `sample_emails/`
(`phishing_paypal.eml` scores ~98/100 and is auto-quarantined;
`legitimate_meeting.eml` scores <5/100 and is not).

## Running tests

```bash
cd src
pytest ../tests -v --cov=. --cov-report=term-missing
```

37 tests, ~79% coverage. Covers: RBAC/2FA/lockout, every Zero-Trust gate
individually (including attachment-containment and HTML-sanitisation
properties), rule-based analysis modules, the hybrid risk engine, the
tamper-evident audit log (including a test that verifies **tampering is
actually detected**, not just that appends work), and end-to-end upload →
score → quarantine → export flows with cross-user access-control checks.

## Running the security tools locally (mirrors `ci-cd/pipeline.yml`)

```bash
flake8 src --select=E9,F63,F7,F82          # hard syntax/undefined-name gate
bandit -r src -ll                          # SAST (0 issues; 1 justified #nosec — see analysis/synthetic_data.py)
safety check -r requirements.txt           # dependency CVE scan
```

## Project structure

```
/src
  app.py                  - Flask application factory, security headers, error handlers
  config.py                - all configuration from environment (.env); no hard-coded secrets
  models.py                 - SQLAlchemy models incl. hash-chained AuditLog
  security_utils.py         - RBAC decorators, rate limiter
  /auth                     - register / login / TOTP 2FA / lockout
  /detector                 - upload, scoring, results, PDF/CSV/JSON export
  /admin                    - audit log viewer (+ chain verification), model performance dashboard
  /analysis
    zero_trust.py            - the mandatory advanced feature: Zero-Trust ingestion pipeline
    url_analysis.py          - URL/domain/look-alike/IP-literal checks
    header_analysis.py       - SPF/DKIM/DMARC, sender-spoofing checks
    content_analysis.py      - urgency/credential-request keyword scoring
    features.py               - single source of truth for the ML feature vector
    ml_classifier.py          - explainable Logistic Regression (JSON-serialised, no pickle)
    synthetic_data.py         - documented synthetic training-data generator (see limitation below)
    risk_engine.py            - fuses rules + ML into one explainable verdict
  /templates, /static       - server-rendered UI
/tests                      - pytest suite (see above)
/ci-cd/pipeline.yml         - GitHub Actions DevSecOps pipeline (mirror to .github/workflows/)
/docs
  architecture.md            - component diagram, data-flow, ER diagram (Mermaid)
  threat_model.md            - STRIDE analysis + advanced-feature evaluation
/sample_emails               - synthetic demo .eml files (safe, no live payloads)
train_model.py                - trains + evaluates the ML classifier, prints precision/recall/F1/FPR
```

## Important limitation to disclose in the report

**The ML classifier is trained on a synthetic, template-generated corpus**
(`analysis/synthetic_data.py`), because this environment has no network
access to real phishing corpora (Nazario, PhishTank, Enron-Spam, etc.) at
build time. `train_model.py` reports a genuine held-out evaluation
(precision/recall/F1/confusion matrix/FPR) — but treat that as a
**proof-of-pipeline result**, not a real-world accuracy claim, in Section 5/6
of the report. Before any real deployment, retrain on an authorised,
ethically-sourced phishing corpus using the exact same `train_model.py`
entry point — the feature extraction and model code do not need to change,
only the data source (swap out `generate_dataset()` in
`analysis/synthetic_data.py` for a real-corpus loader that yields the same
`{subject, body_text, sender_raw, raw_headers, attachment_count, label}`
dict shape).

## Extending reputation lookups

`analysis/url_analysis.py` intentionally never makes a live network request
against a URL found in a submitted email (that would be an SSRF /
self-inflicted-click risk — see `docs/threat_model.md`). To add a real
threat-intel lookup (VirusTotal, PhishTank, Google Safe Browsing), add a new
function that is called explicitly by an analyst action (never automatically
on ingestion) and clearly logged to the audit trail.

## Security notes

- Passwords: PBKDF2-SHA256 via Werkzeug, never plaintext.
- 2FA: RFC 6238 TOTP via PyOTP, Google-Authenticator compatible.
- CSRF: Flask-WTF `CSRFProtect` on every state-changing form.
- Rate limiting: 20/hour on auth endpoints, 30/hour on uploads.
- Session cookies: `HttpOnly`, `SameSite=Lax`, `Secure` in production.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, CSP, `Referrer-Policy`, HSTS in production.
- Model file is plain JSON, never pickle (avoids deserialisation/RCE risk).
- All secrets read from `.env` (git-ignored); `.env.example` documents required keys.
