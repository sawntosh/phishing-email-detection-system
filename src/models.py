"""
SQLAlchemy models.

Security-relevant design choices:
- Passwords: never stored in plaintext; only PBKDF2-SHA256 hashes (Werkzeug).
- AuditLog: hash-chained (each row stores sha256(prev_hash + row_data)) so
  tampering with historical entries is detectable -- supports the
  "tamper-evident audit trail" and Section 6 monitoring/incident-response
  requirements.
- EmailSubmission stores only metadata + extracted features for attachments,
  never raw attachment bytes -- consistent with the Zero-Trust ingestion
  design (see analysis/zero_trust.py).
"""
import hashlib
import json
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utcnow():
    """Naive UTC datetime. SQLite silently drops tzinfo on round-trip
    through a DateTime column, so mixing naive (from DB) and aware
    (freshly constructed) datetimes elsewhere in the app raises
    TypeError on comparison. Standardising on naive-but-UTC avoids that
    everywhere a timestamp is read back and compared (see auth/routes.py
    lockout check)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # RBAC: two roles minimum per brief (FR1). 'admin' | 'analyst'
    role = db.Column(db.String(20), nullable=False, default="analyst")

    # 2FA (TOTP, RFC 6238)
    totp_secret = db.Column(db.String(32), nullable=False)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    is_active_flag = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    submissions = db.relationship("EmailSubmission", backref="submitted_by", lazy="dynamic")

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password, method="pbkdf2:sha256")

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_active(self):
        return self.is_active_flag

    @property
    def is_admin(self):
        return self.role == "admin"


class EmailSubmission(db.Model):
    """One analysed email. Raw attachment bytes are NEVER persisted --
    only hash + metadata, per Zero-Trust ingestion policy."""
    __tablename__ = "email_submissions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    original_filename = db.Column(db.String(255))
    sha256_hash = db.Column(db.String(64), index=True)

    sender = db.Column(db.String(320))
    sender_display_name = db.Column(db.String(255))
    subject = db.Column(db.Text)
    received_headers_summary = db.Column(db.Text)

    spf_result = db.Column(db.String(20))
    dkim_result = db.Column(db.String(20))
    dmarc_result = db.Column(db.String(20))

    risk_score = db.Column(db.Float)          # 0-100
    verdict = db.Column(db.String(20))        # legitimate | suspicious | phishing
    rule_indicators_json = db.Column(db.Text)  # JSON list of triggered rule indicators
    ml_probability = db.Column(db.Float)
    ml_explanation_json = db.Column(db.Text)  # JSON list of top contributing features
    attachment_summary_json = db.Column(db.Text)  # metadata/hash only, never content

    quarantined = db.Column(db.Boolean, default=False)
    analyst_feedback = db.Column(db.String(20), nullable=True)  # confirmed_phish|false_positive|None
    feedback_notes = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def rule_indicators(self):
        return json.loads(self.rule_indicators_json or "[]")

    def ml_explanation(self):
        return json.loads(self.ml_explanation_json or "[]")

    def attachment_summary(self):
        return json.loads(self.attachment_summary_json or "[]")


class AuditLog(db.Model):
    """Hash-chained, append-only audit trail. Every security-relevant event
    (login, 2FA, role-gated access, ingestion-pipeline stage, quarantine
    action) is recorded here. entry_hash = sha256(prev_hash || canonical
    row json); altering any historical row breaks every subsequent hash,
    which verify_chain() below detects."""
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    # Canonical ISO string captured at write time and reused verbatim by
    # verify_chain(). Needed because SQLite drops tzinfo/sub-second precision
    # on round-trip through the DateTime column, which would otherwise make
    # a freshly-recomputed hash disagree with the stored one for EVERY row,
    # not just tampered ones.
    timestamp_iso = db.Column(db.String(40), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)  # login_success, login_fail, 2fa_fail, ingest_stage, quarantine, role_denied ...
    ip_address = db.Column(db.String(45))
    detail = db.Column(db.Text)
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)

    @staticmethod
    def _canonical(row_dict):
        return json.dumps(row_dict, sort_keys=True, default=str)

    @classmethod
    def append(cls, event_type, user_id=None, username=None, ip_address=None, detail=""):
        last = cls.query.order_by(cls.id.desc()).first()
        prev_hash = last.entry_hash if last else "0" * 64
        ts = utcnow()
        ts_iso = ts.isoformat()
        row_dict = {
            "prev_hash": prev_hash,
            "timestamp": ts_iso,
            "user_id": user_id,
            "username": username,
            "event_type": event_type,
            "ip_address": ip_address,
            "detail": detail,
        }
        entry_hash = hashlib.sha256(cls._canonical(row_dict).encode()).hexdigest()
        entry = cls(
            timestamp=ts, timestamp_iso=ts_iso, user_id=user_id, username=username, event_type=event_type,
            ip_address=ip_address, detail=detail, prev_hash=prev_hash, entry_hash=entry_hash,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    @classmethod
    def verify_chain(cls):
        """Returns (is_valid: bool, first_broken_id: int|None)."""
        prev_hash = "0" * 64
        for row in cls.query.order_by(cls.id.asc()).all():
            row_dict = {
                "prev_hash": prev_hash,
                "timestamp": row.timestamp_iso,
                "user_id": row.user_id,
                "username": row.username,
                "event_type": row.event_type,
                "ip_address": row.ip_address,
                "detail": row.detail,
            }
            expected = hashlib.sha256(cls._canonical(row_dict).encode()).hexdigest()
            if expected != row.entry_hash:
                return False, row.id
            prev_hash = row.entry_hash
        return True, None
