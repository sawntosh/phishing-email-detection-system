"""
Centralised configuration. All secrets are read from the environment
(.env, excluded from git) -- nothing sensitive is hard-coded here.
Satisfies SR-style requirement: "never hard-code secrets or credentials".
"""
import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Must run BEFORE the Config class body is evaluated, otherwise the
# class attributes below would silently ignore everything in .env.
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _database_uri():
    default = f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'phishdetect.db')}"
    url = os.environ.get("DATABASE_URL") or default
    prefix = "sqlite:///"
    if url.startswith(prefix):
        path = url[len(prefix):]
        # Relative SQLite paths resolve against the process CWD, which breaks
        # when the app is started from src/. Anchor them to the project root.
        if path and path != ":memory:" and not os.path.isabs(path):
            url = prefix + os.path.normpath(os.path.join(BASE_DIR, path))
    return url


def _env_flag(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-me-in-.env")
    SQLALCHEMY_DATABASE_URI = _database_uri()
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

    # Threat intelligence. Lookups are NEVER run automatically on ingestion
    # (an email is attacker-controlled input); an analyst must trigger them,
    # and every lookup is written to the audit log.
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    ENABLE_REDIRECT_RESOLVER = _env_flag("ENABLE_REDIRECT_RESOLVER")
    THREAT_INTEL_MAX_LOOKUPS = int(os.environ.get("THREAT_INTEL_MAX_LOOKUPS", "8"))
