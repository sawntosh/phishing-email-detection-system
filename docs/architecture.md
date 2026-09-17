# Architecture — Explainable Phishing Email Detector

## Component architecture

```mermaid
flowchart TB
    subgraph Browser
        UI[Analyst / Admin browser]
    end

    subgraph FlaskApp["Flask application (app.py factory)"]
        AUTH["auth blueprint<br/>register / login / 2FA (PyOTP TOTP)"]
        DET["detector blueprint<br/>upload / result / export"]
        ADM["admin blueprint<br/>audit log / model performance"]
        SEC["security_utils<br/>RBAC decorators + rate limiter"]
    end

    subgraph ZT["Zero-Trust Ingestion Pipeline (advanced feature)"]
        G1[G1 Authorization]
        G2[G2 Size / MIME allow-list]
        G3[G3 Structural parse]
        G4[G4 Content sanitisation]
        G5[G5 Attachment containment]
        G1-->G2-->G3-->G4-->G5
    end

    subgraph Analysis["Analysis modules (capability-scoped, G6)"]
        URLM[url_analysis.py]
        HDR[header_analysis.py]
        CONT[content_analysis.py]
        ML["ml_classifier.py<br/>Logistic Regression + explainability"]
        RISK["risk_engine.py<br/>hybrid rule+ML scoring"]
    end

    DB[("SQLite<br/>users / email_submissions / audit_log")]

    UI -->|HTTPS, CSRF-protected forms| AUTH
    UI --> DET
    UI --> ADM
    AUTH --> SEC
    DET --> SEC
    ADM --> SEC
    DET -->|raw upload| ZT
    ZT -->|sanitised subject/body/headers| Analysis
    URLM --> RISK
    HDR --> RISK
    CONT --> RISK
    ML --> RISK
    RISK -->|risk_score, verdict, explanation| DET
    AUTH --> DB
    DET --> DB
    ADM --> DB
    ZT -.->|every gate transition logged| DB
```

## Data-flow: one email submission, end to end

```mermaid
sequenceDiagram
    participant A as Analyst (browser)
    participant R as detector/routes.py
    participant ZT as zero_trust.ingest()
    participant AN as analysis modules
    participant ML as ml_classifier
    participant DB as SQLite

    A->>R: POST /upload (multipart .eml, CSRF token)
    R->>ZT: ingest(raw_bytes, filename, mimetype, current_user, limits)
    ZT->>ZT: G1 authz check
    ZT->>ZT: G2 size + MIME allow-list
    ZT->>ZT: G3 stdlib RFC5322 parse
    ZT->>ZT: G4 strip <script>/onX=/iframe/meta-refresh
    ZT->>ZT: G5 hash attachments, discard raw bytes
    ZT-->>R: IngestionResult (sanitised) OR raises ZeroTrustRejection
    R->>DB: AuditLog.append("ingest_accepted"/"ingest_rejected")
    R->>AN: analyse_urls / analyse_headers / analyse_content
    R->>ML: classify(feature_dict)
    ML-->>R: probability, top-6 feature contributions
    AN-->>R: rule indicators + risk points
    R->>R: risk_engine.score_email() combines rule_score*0.55 + ml_prob*0.45
    R->>DB: INSERT email_submissions (verdict, score, explanation, quarantined=verdict!='legitimate')
    R->>DB: AuditLog.append("scored"), AuditLog.append("quarantine") if applicable
    R-->>A: redirect to /result/<id> (score, badges, explainability table)
```

## Database schema (entity summary)

```mermaid
erDiagram
    USERS ||--o{ EMAIL_SUBMISSIONS : submits
    USERS ||--o{ AUDIT_LOG : "acts (nullable FK)"

    USERS {
        int id PK
        string username
        string email
        string password_hash "PBKDF2-SHA256"
        string role "analyst|admin"
        string totp_secret
        bool totp_enabled
        int failed_login_count
        datetime locked_until
    }
    EMAIL_SUBMISSIONS {
        int id PK
        int user_id FK
        string sha256_hash
        string sender
        string subject
        string spf_result
        string dkim_result
        string dmarc_result
        float risk_score
        string verdict
        text rule_indicators_json
        float ml_probability
        text ml_explanation_json
        text attachment_summary_json "metadata/hash only"
        bool quarantined
        string analyst_feedback
    }
    AUDIT_LOG {
        int id PK
        int user_id FK
        string event_type
        string prev_hash
        string entry_hash
        string timestamp_iso
    }
```

## Trust zones

| Zone | Contains | Trust level |
|---|---|---|
| Browser | Analyst/admin UI | Untrusted (CSRF, session-hijack surface) |
| Flask app layer | Blueprints, RBAC decorators | Trusted, but every input from Browser or Email zones is validated before use |
| **Email content zone** | Anything inside an uploaded `.eml`/`.txt` | **Always untrusted** — this is the Zero-Trust boundary; nothing here is executed, rendered, or trusted regardless of source |
| Database | SQLite via SQLAlchemy ORM | Trusted only via parameterised access; never receives raw email bytes or raw SQL |

## Why Logistic Regression over a black-box model

The brief requires an **explainability view showing the features/indicators
that influenced the risk score**. A linear model's per-prediction
explanation (`contribution = coefficient × standardised_value`) is *exact*,
not a post-hoc approximation — this is a direct, defensible way to satisfy
that requirement without introducing a separate explainability library
(SHAP/LIME), while still combining with independent rule-based indicators
in `risk_engine.py` for defence-in-depth against a single model being
gamed (see `docs/threat_model.md`, item 11).
