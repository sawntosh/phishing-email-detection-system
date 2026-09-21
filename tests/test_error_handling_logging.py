import io
import json
import logging

import pyotp
import pytest
from flask import abort
from werkzeug.security import generate_password_hash

import logging_config
from conftest import login, make_user
from logging_config import JsonFormatter, redact, security_log
from models import AuditLog, User, db

GOOD_PASSWORD = "Str0ngPassw0rd!"


@pytest.fixture(autouse=True)
def _capture_app_loggers(caplog):
    """The app's loggers deliberately do not propagate to the root logger (no double logging),
    so attach pytest's capture handler to them directly."""
    names = ("phishdetect", "phishdetect.security")
    for name in names:
        logging.getLogger(name).addHandler(caplog.handler)
    yield
    for name in names:
        logging.getLogger(name).removeHandler(caplog.handler)


# ------------------------------------------------------ legacy password hashes
def _legacy_user(app, username="oldtimer", method="pbkdf2:sha256", password=GOOD_PASSWORD):
    user = User(username=username, email=f"{username}@example.com", role="analyst",
                totp_secret=pyotp.random_base32(), totp_enabled=True)
    user.password_hash = generate_password_hash(password, method=method)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.mark.parametrize("method", ["pbkdf2:sha256", "scrypt"])
def test_legacy_werkzeug_hash_still_verifies_and_is_upgraded_to_argon2(app, method):
    user = _legacy_user(app, method=method)
    assert user.password_hash.startswith(method.split(":")[0])
    assert user.check_password(GOOD_PASSWORD) is True
    assert user.password_hash.startswith("$argon2id$")
    assert user.check_password(GOOD_PASSWORD) is True  # and the new hash verifies


def test_wrong_password_on_legacy_hash_fails_and_keeps_the_old_hash(app):
    user = _legacy_user(app)
    before = user.password_hash
    assert user.check_password("not-the-password") is False
    assert user.password_hash == before


@pytest.mark.parametrize("garbage", ["", "plain-text-password", "$2b$12$notreallybcrypt", "pbkdf2:sha256:zzz$bad$hash", None])
def test_corrupt_stored_hash_is_a_failed_login_not_a_crash(app, garbage):
    user = _legacy_user(app, username="broken")
    user.password_hash = garbage
    assert user.check_password(GOOD_PASSWORD) is False


def test_full_login_flow_upgrades_a_legacy_hash_and_audits_it(client, app):
    user = _legacy_user(app, username="legacy_login")
    client.post("/auth/login", data={"username": user.username, "password": GOOD_PASSWORD}, follow_redirects=True)
    code = pyotp.TOTP(user.totp_secret).now()
    resp = client.post("/auth/verify-2fa", data={"token": code}, follow_redirects=True)
    assert resp.status_code == 200 and b"Dashboard" in resp.data
    assert db.session.get(User, user.id).password_hash.startswith("$argon2id$")
    events = [a.event_type for a in AuditLog.query.all()]
    assert "password_hash_upgraded" in events and "login_success" in events


def test_new_accounts_use_argon2(app):
    assert make_user("fresh").password_hash.startswith("$argon2id$")


# ------------------------------------------------------------- error pages
@pytest.fixture
def prod_like(app):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.route("/_boom")
    def _boom():
        raise RuntimeError("secret-db-password=hunter2 at C:\\internal\\path")

    @app.route("/_teapot/<int:code>")
    def _abort(code):
        abort(code)

    return app


def test_unhandled_exception_shows_friendly_page_without_leaking_details(client, prod_like):
    resp = client.get("/_boom")
    body = resp.get_data(as_text=True)
    assert resp.status_code == 500
    assert "Something went wrong" in body and "Error reference:" in body
    for leaked in ("RuntimeError", "hunter2", "Traceback", "C:\\internal", "def _boom", "test_error_handling_logging",
                   "site-packages", "secret-db-password"):
        assert leaked not in body
    assert len(resp.headers["X-Request-ID"]) == 12
    assert resp.headers["X-Request-ID"] in body


def test_unhandled_exception_is_logged_with_traceback_and_request_id(client, prod_like, caplog):
    with caplog.at_level(logging.ERROR, logger="phishdetect"):
        resp = client.get("/_boom")
    record = [r for r in caplog.records if r.getMessage() == "unhandled_exception"][0]
    line = json.loads(JsonFormatter().format(record))
    assert line["level"] == "ERROR" and line["exception"].startswith("RuntimeError")
    assert "hunter2" not in json.dumps(line)  # secret in the exception text is redacted in the log too
    assert line["path"] == "/_boom" and "traceback" in line
    assert resp.headers["X-Request-ID"]  # same id the user was shown


@pytest.mark.parametrize("code,expected", [(400, "Bad request"), (405, "Method not allowed"), (429, "Too many requests"),
                                           (401, "Sign in required")])
def test_common_http_errors_use_friendly_pages(client, prod_like, code, expected):
    resp = client.get(f"/_teapot/{code}")
    assert resp.status_code == code and expected in resp.get_data(as_text=True)


def test_404_and_403_pages_still_work_and_carry_a_reference(client, prod_like, analyst_user):
    assert b"404" in client.get("/definitely-not-a-page").data
    login(client, analyst_user)
    resp = client.get("/admin/audit-log")
    assert resp.status_code == 403 and b"403" in resp.data and b"Reference:" in resp.data


def test_oversized_upload_gets_a_friendly_413(client, analyst_user):
    login(client, analyst_user)
    resp = client.post("/upload", data={"message_text": "a" * (6 * 1024 * 1024)})
    assert resp.status_code == 413 and b"Upload too large" in resp.data


def test_exceptions_still_propagate_in_test_mode_so_bugs_are_not_hidden(client, app):
    @app.route("/_boom2")
    def _boom2():
        raise RuntimeError("visible in tests")
    with pytest.raises(RuntimeError, match="visible in tests"):
        client.get("/_boom2")


# ------------------------------------------------------------------ logging
def _format(**kwargs):
    record = logging.LogRecord("phishdetect.security", logging_config.SECURITY, __file__, 1, kwargs.pop("msg", "evt"), (), None)
    record.fields = kwargs
    return json.loads(JsonFormatter().format(record))


def test_sensitive_field_names_are_always_redacted():
    line = _format(password="hunter2", api_key="AKIA123", totp_secret="JBSWY3DP", authorization="Bearer x",
                   session_id="abc", cookie="c=1", user="alice")
    for key in ("password", "api_key", "totp_secret", "authorization", "session_id", "cookie"):
        assert line[key] == "[REDACTED]"
    assert line["user"] == "alice"


@pytest.mark.parametrize("text,leak", [
    ("login password=hunter2 failed", "hunter2"),
    ("token: abc.def.ghi rejected", "abc.def.ghi"),
    ("api_key=\"sk-live-123\" invalid", "sk-live-123"),
    ("Authorization: Bearer topsecret", "topsecret"),
])
def test_secrets_inside_message_text_are_redacted(text, leak):
    assert leak not in redact(text) and "[REDACTED]" in redact(text)


def test_sqlalchemy_parameter_dump_with_email_content_is_stripped():
    text = "(sqlite3.IntegrityError) NOT NULL failed [SQL: INSERT INTO email_submissions ...] [parameters: ('Urgent invoice', 'ceo@corp.com', 'wire the money')] (Background on this error)"
    cleaned = redact(text)
    assert "wire the money" not in cleaned and "ceo@corp.com" not in cleaned


def test_log_injection_via_newlines_cannot_forge_entries():
    forged = "bob\r\n{\"level\": \"SECURITY\", \"event\": \"login_success\", \"user\": \"admin\"}"
    rendered = JsonFormatter().format(_record_with(forged))
    assert "\n" not in rendered and "\r" not in rendered
    assert json.loads(rendered)["username"].startswith("bob")


def _record_with(username):
    record = logging.LogRecord("phishdetect.security", logging_config.SECURITY, __file__, 1, "login_fail", (), None)
    record.fields = {"username": username}
    return record


def test_long_values_are_truncated():
    assert len(_format(detail="x" * 5000)["detail"]) < 400


def test_security_level_is_registered():
    assert logging.getLevelName(35) == "SECURITY"


def test_audited_events_are_mirrored_to_the_security_log(client, analyst_user, caplog):
    with caplog.at_level(logging_config.SECURITY, logger="phishdetect.security"):
        client.post("/auth/login", data={"username": "analyst1", "password": "wrong-password-123"})
    messages = [(r.levelname, r.getMessage()) for r in caplog.records if r.name == "phishdetect.security"]
    assert ("SECURITY", "login_fail") in messages
    rendered = " ".join(JsonFormatter().format(r) for r in caplog.records)
    assert "wrong-password-123" not in rendered  # the attempted password is never logged


def test_role_denied_and_403_are_security_events(client, analyst_user, caplog):
    login(client, analyst_user)
    with caplog.at_level(logging_config.SECURITY, logger="phishdetect.security"):
        client.get("/admin/users")
    events = [r.getMessage() for r in caplog.records if r.name == "phishdetect.security"]
    assert "role_denied" in events and "access_denied" in events


def test_request_log_has_no_query_string_or_body(client, analyst_user, caplog):
    login(client, analyst_user)
    with caplog.at_level(logging.INFO, logger="phishdetect"):
        client.get("/?token=supersecret&q=1")
    lines = [JsonFormatter().format(r) for r in caplog.records if r.getMessage() == "request"]
    assert lines and all("supersecret" not in l and "token=" not in l for l in lines)
    assert any(json.loads(l)["path"] == "/" for l in lines)


def test_static_requests_are_not_logged(client, caplog):
    with caplog.at_level(logging.INFO, logger="phishdetect"):
        client.get("/static/css/style.css")
    assert not [r for r in caplog.records if r.getMessage() == "request"]


def test_pasted_email_content_never_appears_in_logs(client, analyst_user, caplog):
    login(client, analyst_user)
    with caplog.at_level(logging.DEBUG):
        client.post("/upload", data={"message_text": "CONFIDENTIAL merger details: wire $5,000,000 http://evil.example/x",
                                     "message_subject": "TOP SECRET SUBJECT"}, follow_redirects=True)
    rendered = " ".join(JsonFormatter().format(r) for r in caplog.records)
    assert "CONFIDENTIAL" not in rendered and "TOP SECRET SUBJECT" not in rendered and "5,000,000" not in rendered


def test_handlers_are_not_duplicated_when_apps_are_created_repeatedly(app):
    from app import create_app
    from conftest import TestConfig
    for _ in range(3):
        create_app(TestConfig)
    marked = [h for h in logging.getLogger("phishdetect").handlers if getattr(h, "_phishdetect_handler", False)]
    assert len(marked) == 1


def test_response_carries_request_id_header(client):
    resp = client.get("/auth/login")
    assert resp.headers["X-Request-ID"] and len(resp.headers["X-Request-ID"]) == 12
    assert client.get("/auth/login").headers["X-Request-ID"] != resp.headers["X-Request-ID"]


def test_file_logging_creates_rotating_files_outside_tests(tmp_path):
    from flask import Flask
    app = Flask("logtest", instance_path=str(tmp_path))
    app.config.update(LOG_LEVEL="INFO", LOG_TO_FILE=True)
    logging_config.configure_logging(app)
    security_log("unit_test_event", user="alice", password="nope")
    for logger in (logging.getLogger("phishdetect"), logging.getLogger("phishdetect.security"), app.logger):
        for handler in logger.handlers:
            handler.flush()
    text = (tmp_path / "logs" / "security.log").read_text()
    assert '"event": "unit_test_event"' in text and "nope" not in text and (tmp_path / "logs" / "app.log").exists()
    logging_config._reset_handlers(logging.getLogger("phishdetect"))
    logging_config._reset_handlers(logging.getLogger("phishdetect.security"))
    logging_config._reset_handlers(app.logger)


# ------------------------------------------------------------ instance folder
def test_instance_folder_is_the_project_root_instance_where_models_and_reports_live(app):
    import os
    from analysis.ml_classifier import MODEL_DIR
    assert os.path.normcase(app.instance_path) == os.path.normcase(MODEL_DIR)
    assert not app.instance_path.replace("\\", "/").rstrip("/").endswith("src/instance")


def test_model_performance_page_actually_shows_the_training_report(client, admin_user):
    login(client, admin_user)
    page = client.get("/admin/model-performance").get_data(as_text=True)
    assert "Classifier comparison" in page and "No text-model report found" not in page
