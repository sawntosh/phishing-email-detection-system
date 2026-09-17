"""
Centralised configuration. All secrets are read from the environment
(.env, excluded from git) -- nothing sensitive is hard-coded here.
Satisfies SR-style requirement: "never hard-code secrets or credentials".
"""
import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-me-in-.env")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'phishdetect.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session / cookie hardening (SR6-equivalent)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    WTF_CSRF_TIME_LIMIT = None  # tokens valid for session lifetime

    # Zero-Trust ingestion limits (deny-by-default posture)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB hard cap on any upload
    ALLOWED_UPLOAD_EXTENSIONS = {".eml", ".txt"}
    ALLOWED_UPLOAD_MIMETYPES = {"message/rfc822", "text/plain", "application/octet-stream"}

    RATELIMIT_STORAGE_URI = "memory://"
