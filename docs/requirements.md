# Requirements (Section 3.1 draft)

Drafted in Phase 1 by Member 2 (auth/RBAC/2FA/audit owner) so role checks
are locked in before other modules depend on them. FR/NFR numbering
matches the references already in code comments (`FR1` in `models.py`,
`SR6` in `config.py`) — extend this table, don't renumber, if new
requirements are added later.

## Functional requirements

| ID | Requirement | Owner | Implemented in |
|----|-------------|-------|-----------------|
| FR1 | RBAC with a minimum of two roles (`analyst`, `admin`); role-gated routes return HTTP 403 on violation | Member 2 | `security_utils.py` (`roles_required`, `admin_required`), `models.py::User.role` |
| FR2 | Secure registration & login: strong password policy, hashed storage, no plaintext anywhere | Member 2 | `auth/forms.py`, `auth/routes.py`, `models.py::User.set_password/check_password` |
| FR3 | Mandatory TOTP two-factor authentication before a session is established | Member 2 | `auth/routes.py` (`setup_2fa`, `confirm_2fa_setup`, `verify_2fa`) |
| FR4 | Tamper-evident audit logging of every security-relevant event (login, 2FA, RBAC denial, logout) | Member 2 | `models.py::AuditLog` (hash-chained), called throughout `auth/routes.py` |
| FR5 | Safe parsing of `.eml`/text uploads; attachments handled by hash + metadata only, never executed | Member 3 / Santosh (Zero-Trust) | `analysis/zero_trust.py` |
| FR6 | URL/domain analysis: look-alike domains, redirects, reputation signals | Member 3 | `analysis/url_analysis.py` |
| FR7 | Header/sender analysis: SPF/DKIM/DMARC, spoofing indicators | Member 3 | `analysis/header_analysis.py` |
| FR8 | Content/keyword/structural analysis producing a numeric risk contribution | Member 3 | `analysis/content_analysis.py` |
| FR9 | Hybrid detection: rules engine + ML classifier fused into one score | Santosh | `analysis/risk_engine.py`, `analysis/ml_classifier.py` |
| FR10 | Explainability view showing which features/rules drove a verdict | Santosh | `analysis/ml_classifier.py`, `templates/detector/result.html` |
| FR11 | Quarantine simulation + analyst feedback / false-positive review workflow | Member 3 | `detector/routes.py`, `models.py::EmailSubmission` |
| FR12 | Exportable PDF/CSV/JSON reports per analysed email | Member 3 | `detector/pdf_report.py`, `detector/routes.py` |
| FR13 | Admin dashboard: detection rate, common indicators, false positives, model performance | Member 2 (routes) + Santosh (data) | `admin/routes.py::model_performance` |
| FR14 | Zero-Trust ingestion pipeline (mandatory advanced feature): deny-by-default, multi-gate validation | Santosh | `analysis/zero_trust.py` |

## Non-functional / security requirements

| ID | Requirement | Implemented in |
|----|-------------|-----------------|
| NFR1 | Passwords never stored in plaintext (Argon2id via passlib) | `models.py::User` |
| NFR2 | Session cookies `HttpOnly`, `SameSite=Lax`, `Secure` in production; 30-minute idle timeout, session cleared on logout | `config.py`, `auth/routes.py` (`session.permanent`, `session.clear()`) |
| NFR3 | CSRF protection on every state-changing form | `app.py` (`CSRFProtect`), all templates |
| NFR4 | Brute-force resistance: rate-limited auth endpoints + account lockout after 5 failed logins for 15 minutes | `auth/routes.py`, `security_utils.py::limiter` |
| NFR5 | No hard-coded secrets; all configuration/secrets from environment (`.env`, git-ignored) | `config.py`, `.env.example` |
| SR6 | Security response headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`, HSTS in production) | `app.py::set_security_headers` |
| NFR7 | Audit trail integrity: hash-chained, tamper-evident, independently verifiable | `models.py::AuditLog.verify_chain` |
| NFR8 | ML model artefact stored as JSON, never pickle (avoids deserialisation/RCE risk) | `analysis/ml_classifier.py` |
| NFR9 | Uploaded content is size-capped (5 MB) and MIME/extension-restricted before parsing | `config.py`, `analysis/zero_trust.py` |
| NFR10 | Automated test coverage with a CI-enforced pass gate | `tests/`, `ci-cd/pipeline.yml` |

## Roles & permissions (locks in FR1)

| Role | Can | Cannot |
|------|-----|--------|
| `analyst` | Register (self-service, always this role), upload/view **own** submissions, give feedback, export own reports | View audit log, view model-performance dashboard, manage/promote users |
| `admin` | Everything an analyst can, plus view the hash-chained audit log and model-performance dashboard | — |

Design decision locked 2026-09-17: self-registration **always** creates an
`analyst` account — the registration form has no role selector. The only
way to get an `admin` account today is the `.env`-seeded default admin
(`app.py::_ensure_default_admin`). An admin-only user-management/promotion
route is still to be built (Phase 3) rather than exposed at registration,
because letting a registrant choose `admin` for themselves is a
privilege-escalation hole in the RBAC feature this section is graded on.

## Traceability for Section 4.1 / 4.4 (Member 2)

| Report section | Requirement IDs | Evidence |
|---|---|---|
| 4.1 Secure Coding / Authentication | FR1, FR2, FR3, NFR1, NFR2, NFR4, NFR5 | register → 2FA setup → login screenshots; `tests/test_auth.py` |
| 4.4 Logging / Incident Response | FR4, NFR7 | audit log page screenshot, `tests/test_audit_log.py`, incident-simulation screenshots (Phase 4, not yet captured) |
