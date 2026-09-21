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
- [x] Safe `.eml`/text parsing; attachments handled by metadata/hash only. **Two input modes on the Analyse page: paste a message (optionally with subject/sender, or a full raw email with headers) or upload a `.eml`/`.txt` file** -- both go through the same Zero-Trust pipeline
- [x] URL/domain analysis, look-alike domain detection, IP-literal/punycode/shortener checks
- [x] **Suspicious-redirect checks**: open-redirect parameters (incl. double-encoded), `user@host` tricks, URLs embedded in paths, redirects into look-alike domains, non-standard ports
- [x] **Reputation / threat intelligence**: offline domain blocklist on every upload + analyst-triggered VirusTotal domain/attachment-hash lookups + hardened redirect-chain resolver (both off until configured, audit-logged)
- [x] Header/sender analysis: SPF/DKIM/DMARC parsing, display-name spoofing, reply-to mismatch
- [x] Content/keyword/structure analysis with a human-readable risk score and a plain-English reason for every indicator
- [x] **Hybrid detection: rules + a text model trained on real phishing (Nazario) and legitimate (Enron) mail + a structured-feature model**
- [x] Explainability view: exact per-word contributions from the text model, per-feature contributions from the structured model, and a score-breakdown table
- [x] Quarantine simulation, analyst feedback workflow, **false-positive review queue** with labelled-feedback CSV export
- [x] Exportable PDF / CSV / JSON reports (per submission and export-all), CSV formula-injection safe
- [x] Dashboard: detection rate, false-positive rate, analyst-confirmed precision, verdict distribution, 14-day trend, common indicators, tool activity
- [x] Admin model-performance page: held-out metrics on the real corpus, side-by-side classifier benchmark, globally strongest phishing/legitimate terms
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

python train_model.py              # trains on data/ (real corpus) -> instance/model_text.json + model.json (~1 min)

cd src
python app.py                      # http://127.0.0.1:5000
```

### Training data

`train_model.py` expects the two public research corpora under `data/` (git-ignored, not redistributed):

```
data/phishing/*.csv    Jose Nazario phishing corpus, 2015-2021   (label 1)
data/enron/*.csv       Enron e-mail dataset                       (label 0)
```

Each CSV needs `subject` and `content` columns. They are the same files as `Notebook/Dataset/` in
<https://github.com/mohammedtouheedpatelgithubcom/Phishing-Email-Detection>. Without `data/` the script
falls back to a small synthetic corpus (`--source synthetic`) so the app and tests still run.

```bash
python train_model.py                       # auto: real corpus if data/ exists
python train_model.py --max-legit 15000     # cap on Enron messages used (default 15000)
python train_model.py --source synthetic    # offline / fast
```

### Optional: threat intelligence

Add to `.env` (all optional, see `.env.example`):

```
VIRUSTOTAL_API_KEY=...          # enables VirusTotal domain + attachment-hash reputation
ENABLE_REDIRECT_RESOLVER=true   # enables the safe redirect-chain resolver
```

Then open any result and click **Run threat-intel lookup** (analyst/admin only). To use the offline blocklist,
copy `threat_intel/blocklist.sample.txt` to `instance/threat_intel/blocklist.txt` and add domains.

First run: set `DEFAULT_ADMIN_USERNAME/EMAIL/PASSWORD` in `.env` before
first start to auto-create an admin account (see `_ensure_default_admin`
in `app.py`). Self-registration at `/auth/register` always creates an
`analyst` account by design — registrants cannot choose their own role,
since that would be a privilege-escalation hole in the RBAC feature.
Either way you'll be sent through TOTP 2FA setup (scan the QR code with
Google Authenticator/Authy) before you can log in.

Try it immediately with the two sample emails in `sample_emails/`
(`phishing_paypal.eml` scores ~98/100 and is auto-quarantined;
`legitimate_meeting.eml` scores <5/100 and is not).

## Running tests

```bash
cd src
pytest ../tests -v --cov=. --cov-report=term-missing
```

187 tests. Covers: RBAC/2FA/lockout, every Zero-Trust gate
individually (including attachment-containment and HTML-sanitisation
properties), rule-based analysis modules, the hybrid risk engine, the
tamper-evident audit log (including a test that verifies **tampering is
actually detected**, not just that appends work), and end-to-end upload →
score → quarantine → export flows with cross-user access-control checks, plus: redirect/userinfo/embedded-URL detection,
blocklist matching, VirusTotal response handling and input validation (no request is ever sent for a malformed
domain/hash), SSRF guards of the redirect resolver (private/loopback/metadata addresses, DNS rebinding, ports, schemes,
hop cap), pure-Python text-model inference matching scikit-learn exactly, the false-positive review workflow, CSV
formula-injection and PDF-markup safety, pasted-message analysis (header-injection safe, same Zero-Trust gates as uploads), and automatic database column migration.

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
    features.py               - single source of truth for the structured feature vector
    text_model.py             - TF-IDF + Logistic Regression on real mail (JSON-serialised, exact per-word explanations)
    dataset_loader.py         - loads/dedupes the Nazario + Enron corpora from data/
    ml_classifier.py          - structured-feature Logistic Regression (JSON-serialised, no pickle)
    synthetic_data.py         - synthetic generator for the structured model (only source of header signal) + offline fallback
    threat_intel.py           - offline blocklist, VirusTotal client, SSRF-hardened redirect resolver
    explanations.py           - plain-English text for every indicator; URL defanging
    risk_engine.py            - fuses rules + both ML models into one explainable verdict
  /templates, /static       - server-rendered UI
/data                       - training corpora (git-ignored; see "Training data")
/threat_intel               - sample blocklist
/tests                      - pytest suite (see above)
/ci-cd/pipeline.yml         - GitHub Actions DevSecOps pipeline (mirror to .github/workflows/)
/docs
  architecture.md            - component diagram, data-flow, ER diagram (Mermaid)
  threat_model.md            - STRIDE analysis + advanced-feature evaluation
/sample_emails               - synthetic demo .eml files (safe, no live payloads)
train_model.py                - trains + evaluates the ML classifier, prints precision/recall/F1/FPR
```

## Important limitations to disclose in the report

**The text model is trained on real but dated, era-skewed data.** Phishing = Nazario 2015-2021, legitimate = Enron
(2000s corporate mail). Held-out F1 is ~0.97 with a ~0.4% false-positive rate, but part of that separation is
style/era rather than intent, so treat it as an upper bound and expect more false positives on modern legitimate
marketing mail. Mitigations already in place: corpus-identifying tokens (`enron`, first names, `energy`...) are
excluded, exact duplicates are removed before the split, and the ML signal is only half of the final score (the other
half is independent rule-based URL/header/content checks). The **Review queue** exports analyst-labelled feedback
so the model can be retrained on in-domain mail. See `docs/threat_model.md` for the full residual-risk list.

**The structured-feature model is trained on the synthetic generator** (`analysis/synthetic_data.py`) because none of
the public corpora contain raw headers, so SPF/DKIM/DMARC/Reply-To signal exists nowhere else. Its 1.0 metrics are a
proof-of-pipeline result only and are labelled as such on the Model-performance page.

The admin page also benchmarks Linear SVM, Naive Bayes, Random Forest and Decision Tree on the same split (the
reference project compared ten classifiers). Logistic Regression is deployed on purpose: its predictions decompose
exactly into per-word contributions, which the black-box alternatives cannot do without approximations like SHAP/LIME.

## Threat-intelligence design

`analysis/url_analysis.py` never makes a request for a URL found in an email during ingestion (that would be an SSRF
/ self-inflicted-click risk). Everything network-facing lives in `analysis/threat_intel.py` and is analyst-triggered,
rate-limited (20/hour), capped per click, and written to the tamper-evident audit log:

- **Offline blocklist** - checked on every upload with no network access; hot-reloads when the file changes.
- **VirusTotal** - fixed https host; only a validated domain or SHA-256 digest is ever placed in the request path.
- **Redirect resolver** - refuses non-public DNS answers, connects to the validated IP, HEAD only, ports 80/443, 5 hops.

## Security notes

- Passwords: Argon2id via passlib, never plaintext.
- 2FA: RFC 6238 TOTP via PyOTP, Google-Authenticator compatible.
- CSRF: Flask-WTF `CSRFProtect` on every state-changing form.
- Rate limiting: 20/hour on auth endpoints, 30/hour on uploads.
- Session cookies: `HttpOnly`, `SameSite=Lax`, `Secure` in production.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, CSP, `Referrer-Policy`, HSTS in production.
- Errors: users see a friendly page with an error reference only; stack traces, SQL and paths go to the server log. The Werkzeug debugger is off by default (`FLASK_DEBUG=true` to opt in; never in production).
- Logging: structured JSON lines with INFO / WARNING / ERROR / SECURITY levels, a request id on every line and on the `X-Request-ID` response header, secrets and email content redacted, log-forging via newlines impossible. Audit-log events are mirrored to `instance/logs/security.log`.
- Passwords: Argon2id; accounts created with the older PBKDF2 hashes still log in and are upgraded transparently on first successful login.
- Model files are plain JSON, never pickle (avoids deserialisation/RCE risk).
- Result pages show domains defanged (`hxxp`, `[.]`) and never as clickable links; CSV exports are formula-injection safe; PDF text is XML-escaped.
- All secrets read from `.env` (git-ignored); `.env.example` documents required keys.
