"""
Structured application and security logging.

Design goals
  * One JSON object per line (json.dumps escapes CR/LF, so attacker-controlled
    text such as a username cannot forge extra log lines).
  * Levels INFO / WARNING / ERROR plus a dedicated SECURITY level (35) for
    authentication, authorisation and ingestion-gate events.
  * Never write secrets or email content: values of sensitive keys and
    "password=..." style fragments are redacted, and SQLAlchemy's
    "[parameters: ...]" dump (which can contain a submitted subject/sender)
    is stripped from exception text.
  * Every line carries the request id that is also shown to the user on the
    error page, so a reported error can be traced without exposing details.
"""
import json
import logging
import os
import re
import time
from logging.handlers import RotatingFileHandler

from flask import g, has_request_context, request

SECURITY = 35
logging.addLevelName(SECURITY, "SECURITY")

APP_LOGGER_NAME = "phishdetect"
SECURITY_LOGGER_NAME = "phishdetect.security"
_HANDLER_MARK = "_phishdetect_handler"

_SENSITIVE_KEY_RE = re.compile(r"pass(word|wd)?|pwd|secret|token|api[_-]?key|authorization|cookie|session|totp|otp", re.I)
_REDACT_INLINE_RE = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization|cookie|totp)\b(\s*[=:]\s*)((?:bearer\s+|basic\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+))"
)
_SQL_PARAMS_RE = re.compile(r"\[parameters:.*?\](?=\s*\(Background|\s*$|\n)", re.S)
_SQL_PARAMS_LOOSE_RE = re.compile(r"\[parameters:[^\]]*\]", re.S)
MAX_FIELD_CHARS = 300


def redact(text):
    text = _SQL_PARAMS_RE.sub("[parameters: REDACTED]", str(text))
    text = _SQL_PARAMS_LOOSE_RE.sub("[parameters: REDACTED]", text)
    return _REDACT_INLINE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


def _clean_value(key, value):
    if _SENSITIVE_KEY_RE.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = redact(value)
    return text if len(text) <= MAX_FIELD_CHARS else text[:MAX_FIELD_CHARS] + "...[truncated]"


class RequestContextFilter(logging.Filter):
    def filter(self, record):
        record.request_id = getattr(g, "request_id", None) if has_request_context() else None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "level": record.levelname,
            "logger": record.name,
            "event": redact(record.getMessage()),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        for key, value in (getattr(record, "fields", None) or {}).items():
            payload[key] = _clean_value(key, value)
        if record.exc_info:
            exc_type, exc, _ = record.exc_info
            payload["exception"] = f"{exc_type.__name__}: {redact(exc)}"[:1000]
            payload["traceback"] = redact(self.formatException(record.exc_info))[-4000:]
        return json.dumps(payload, ensure_ascii=True, default=str)


def security_log(event, **fields):
    """Emit a SECURITY-level structured event (auth, access control, ingestion gates)."""
    logging.getLogger(SECURITY_LOGGER_NAME).log(SECURITY, event, extra={"fields": fields})


def app_log(level, event, **fields):
    logging.getLogger(APP_LOGGER_NAME).log(level, event, extra={"fields": fields})


def _reset_handlers(logger):
    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARK, False):
            logger.removeHandler(handler)
            handler.close()


def _make_handler(handler):
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestContextFilter())
    setattr(handler, _HANDLER_MARK, True)
    return handler


def configure_logging(app):
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    to_file = app.config.get("LOG_TO_FILE", True) and not app.testing

    app_logger = logging.getLogger(APP_LOGGER_NAME)
    security_logger = logging.getLogger(SECURITY_LOGGER_NAME)
    for logger in (app_logger, security_logger, app.logger):
        _reset_handlers(logger)
    app_logger.setLevel(level)
    security_logger.setLevel(min(level, SECURITY))
    app_logger.propagate = False
    security_logger.propagate = False  # child of phishdetect: keep its own handlers only

    console = _make_handler(logging.StreamHandler())
    app_logger.addHandler(console)
    security_logger.addHandler(_make_handler(logging.StreamHandler()))

    # Flask's own logger (used by app.logger.warning(...) calls) shares the app handlers.
    app.logger.setLevel(level)
    app.logger.propagate = False
    app.logger.addHandler(_make_handler(logging.StreamHandler()))

    if to_file:
        log_dir = os.path.join(app.instance_path, "logs")
        try:
            os.makedirs(log_dir, exist_ok=True)
            app_logger.addHandler(_make_handler(RotatingFileHandler(
                os.path.join(log_dir, "app.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8")))
            security_logger.addHandler(_make_handler(RotatingFileHandler(
                os.path.join(log_dir, "security.log"), maxBytes=1_000_000, backupCount=10, encoding="utf-8")))
        except OSError as exc:
            app_logger.warning("file logging disabled: %s", exc)


def register_request_logging(app):
    import uuid

    @app.before_request
    def _start_request():
        g.request_id = uuid.uuid4().hex[:12]  # never trust a client-supplied id
        g.request_started = time.perf_counter()

    @app.after_request
    def _finish_request(response):
        response.headers["X-Request-ID"] = getattr(g, "request_id", "-")
        if not request.path.startswith("/static/"):
            from flask_login import current_user
            user_id = current_user.get_id() if current_user and current_user.is_authenticated else None
            app_log(
                logging.INFO, "request", method=request.method, path=request.path, status=response.status_code,
                duration_ms=round((time.perf_counter() - getattr(g, "request_started", time.perf_counter())) * 1000, 1),
                user_id=user_id,
            )
        return response
