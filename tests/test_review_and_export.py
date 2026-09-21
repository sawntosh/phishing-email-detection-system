import csv
import io
import json

from conftest import login, make_user
from models import EmailSubmission, ExtractedIndicator
from test_detector_routes import PHISH_EML, LEGIT_EML, _upload


def _latest():
    return EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()


def _eml(subject, body="Hello there, are you free for lunch?"):
    return (f"From: \"Jordan Lee\" <jordan@company.com>\nSubject: {subject}\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            f"Content-Type: text/plain\n\n{body}\n").encode()


# ---------------------------------------------------------- indicators stored
def test_upload_persists_domains_and_suspicious_urls(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    kinds = {(i.kind, i.value.split("/")[2] if i.kind == "url" else i.value) for i in _latest().indicators}
    assert ("domain", "paypa1-secure.com") in kinds
    assert ("url", "paypa1-secure.com") in kinds


def test_attachment_hashes_become_indicators(client, analyst_user):
    login(client, analyst_user)
    eml = (b"From: a@b.com\nSubject: invoice\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n"
           b"--XX\nContent-Type: text/plain\n\nsee attached\n--XX\nContent-Type: application/pdf\n"
           b"Content-Disposition: attachment; filename=inv.pdf\nContent-Transfer-Encoding: base64\n\nSGVsbG8=\n--XX--\n")
    _upload(client, eml)
    hashes = [i for i in _latest().indicators if i.kind == "attachment_hash"]
    assert len(hashes) == 1 and len(hashes[0].value) == 64


def test_result_page_renders_defanged_indicators_and_explanations(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    html = client.get(f"/result/{_latest().id}").get_data(as_text=True)
    assert "paypa1-secure[.]com" in html
    assert "http://paypa1-secure.com" not in html and 'href="http://paypa1' not in html
    assert "embeds the brand" in html
    assert "How the score was built" in html


# ---------------------------------------------------------------- dashboard
def test_dashboard_shows_detection_and_false_positive_rates(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    _upload(client, LEGIT_EML)
    client.post(f"/result/{EmailSubmission.query.filter_by(verdict='phishing').first().id}/feedback",
                data={"feedback": "false_positive"})
    html = client.get("/").get_data(as_text=True)
    assert "Detection rate" in html and "False-positive rate" in html
    assert "Verdict distribution" in html and "Last 14 days" in html


def test_dashboard_is_empty_state_safe(client, analyst_user):
    login(client, analyst_user)
    assert client.get("/").status_code == 200


# ------------------------------------------------------------ review queue
def test_review_queue_requires_login(client):
    assert client.get("/review", follow_redirects=True).request.path.startswith("/auth/login")


def test_flagged_email_appears_in_pending_then_moves_after_false_positive(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    sid = _latest().id
    assert f"/result/{sid}" in client.get("/review?view=pending").get_data(as_text=True)

    client.post(f"/result/{sid}/feedback", data={"feedback": "false_positive", "notes": "internal test"})
    assert f"/result/{sid}" not in client.get("/review?view=pending").get_data(as_text=True)
    fp_page = client.get("/review?view=false_positive").get_data(as_text=True)
    assert f"/result/{sid}" in fp_page and "internal test" in fp_page
    assert EmailSubmission.query.get(sid).quarantined is False  # false positives are released


def test_confirmed_phish_stays_quarantined(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    sid = _latest().id
    client.post(f"/result/{sid}/feedback", data={"feedback": "confirmed_phish"})
    assert EmailSubmission.query.get(sid).quarantined is True
    assert f"/result/{sid}" in client.get("/review?view=confirmed_phish").get_data(as_text=True)


def test_review_queue_only_shows_own_submissions_to_analysts(client, app):
    a, b = make_user("ann", "analyst"), make_user("ben", "analyst")
    login(client, a)
    _upload(client, PHISH_EML)
    sid = _latest().id
    other = app.test_client()
    login(other, b)
    assert f"/result/{sid}" not in other.get("/review").get_data(as_text=True)


def test_invalid_feedback_value_is_rejected(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    assert client.post(f"/result/{_latest().id}/feedback", data={"feedback": "banana"}).status_code == 400


def test_feedback_export_csv_lists_reviewed_items(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    client.post(f"/result/{_latest().id}/feedback", data={"feedback": "false_positive", "notes": "n"})
    resp = client.get("/review/export.csv")
    assert resp.mimetype == "text/csv"
    rows = list(csv.reader(io.StringIO(resp.get_data(as_text=True))))
    assert rows[0][:2] == ["id", "sha256"] and rows[1][-3] == "false_positive"


# ------------------------------------------------------------------ exports
def test_export_all_csv_and_json(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    _upload(client, LEGIT_EML)
    rows = list(csv.reader(io.StringIO(client.get("/export/all/csv").get_data(as_text=True))))
    assert len(rows) == 3 and "verdict" in rows[0]
    payload = json.loads(client.get("/export/all/json").get_data(as_text=True))
    assert len(payload) == 2 and "indicators" in payload[0]
    assert client.get("/export/all/xml").status_code == 400


def test_export_all_only_includes_own_submissions(client, app):
    a, b = make_user("cy", "analyst"), make_user("di", "analyst")
    login(client, a)
    _upload(client, LEGIT_EML)
    other = app.test_client()
    login(other, b)
    assert json.loads(other.get("/export/all/json").get_data(as_text=True)) == []


def test_csv_export_neutralises_spreadsheet_formula_injection(client, analyst_user):
    login(client, analyst_user)
    _upload(client, _eml('=HYPERLINK("http://evil.example","click")'))
    sid = _latest().id
    for url in (f"/result/{sid}/export/csv", "/export/all/csv"):
        rows = list(csv.reader(io.StringIO(client.get(url).get_data(as_text=True))))
        header, values = rows[0], rows[1]
        assert values[header.index("subject")].startswith("'=")
        assert not any(v.startswith("=") for v in values)


def test_pdf_export_survives_markup_in_attacker_controlled_fields(client, analyst_user):
    login(client, analyst_user)
    _upload(client, _eml("<b>Unclosed & <font size=999>bold</i>", "body <para> & </x>"))
    resp = client.get(f"/result/{_latest().id}/export/pdf")
    assert resp.status_code == 200 and resp.data.startswith(b"%PDF")


def test_pdf_export_of_a_full_phishing_result(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    resp = client.get(f"/result/{_latest().id}/export/pdf")
    assert resp.status_code == 200 and resp.data.startswith(b"%PDF")


def test_json_export_contains_score_breakdown_and_indicators(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    data = json.loads(client.get(f"/result/{_latest().id}/export/json").get_data(as_text=True))
    for key in ("rule_score", "text_probability", "structured_probability", "indicators", "quarantined"):
        assert key in data
    assert any(i["kind"] == "domain" for i in data["indicators"])


# ------------------------------------------------------- threat-intel route
def test_threat_intel_without_configuration_only_warns(client, analyst_user, app):
    app.config.update(VIRUSTOTAL_API_KEY="", ENABLE_REDIRECT_RESOLVER=False)
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    resp = client.post(f"/result/{_latest().id}/threat-intel", follow_redirects=True)
    assert b"No external threat-intel source is configured" in resp.data
    assert all(i.intel_verdict is None for i in _latest().indicators)


def test_threat_intel_lookup_stores_results_and_quarantines_malicious(client, analyst_user, app, monkeypatch):
    from detector import routes
    app.config.update(VIRUSTOTAL_API_KEY="test-key", ENABLE_REDIRECT_RESOLVER=False)
    monkeypatch.setattr(routes.threat_intel, "lookup_domain",
                        lambda domain, key: {"verdict": "malicious", "malicious": 9, "suspicious": 0, "harmless": 1})
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    sid = _latest().id
    client.post(f"/result/{sid}/release")  # start from an un-quarantined state
    resp = client.post(f"/result/{sid}/threat-intel", follow_redirects=True)
    assert b"Worst result: malicious" in resp.data
    submission = EmailSubmission.query.get(sid)
    domain = [i for i in submission.indicators if i.kind == "domain"][0]
    assert domain.intel_verdict == "malicious" and domain.intel()["virustotal"]["malicious"] == 9
    assert submission.quarantined is True
    page = client.get(f"/result/{sid}").get_data(as_text=True)
    assert "VirusTotal: 9 malicious" in page


def test_threat_intel_respects_lookup_budget_and_reports_errors(client, analyst_user, app, monkeypatch):
    from detector import routes
    from analysis.threat_intel import ThreatIntelError
    app.config.update(VIRUSTOTAL_API_KEY="k", ENABLE_REDIRECT_RESOLVER=False)
    monkeypatch.setattr(routes.threat_intel, "lookup_domain",
                        lambda d, k: (_ for _ in ()).throw(ThreatIntelError("VirusTotal rate limit reached; try again later")))
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    resp = client.post(f"/result/{_latest().id}/threat-intel", follow_redirects=True)
    assert b"rate limit" in resp.data
    assert all(i.intel_verdict is None for i in _latest().indicators)


def test_threat_intel_redirect_resolution_flags_bad_final_destination(client, analyst_user, app, monkeypatch):
    from detector import routes
    app.config.update(VIRUSTOTAL_API_KEY="", ENABLE_REDIRECT_RESOLVER=True)
    monkeypatch.setattr(routes.threat_intel, "resolve_redirect_chain", lambda url: {
        "chain": [{"url": url, "status": 302}, {"url": "http://paypa1-login.top/verify", "status": 200}],
        "final_url": "http://paypa1-login.top/verify", "truncated": False, "hops": 1})
    login(client, analyst_user)
    _upload(client, _eml("Your parcel", "Track it: http://bit.ly/abc123 thanks"))
    sid = _latest().id
    client.post(f"/result/{sid}/threat-intel", follow_redirects=True)
    url_row = [i for i in EmailSubmission.query.get(sid).indicators if i.kind == "url"][0]
    assert url_row.intel_verdict == "suspicious"
    assert url_row.intel()["redirect_chain"]["final_findings"]


def test_threat_intel_is_access_controlled_and_audited(client, app, monkeypatch):
    from detector import routes
    from models import AuditLog
    app.config.update(VIRUSTOTAL_API_KEY="k", ENABLE_REDIRECT_RESOLVER=False)
    monkeypatch.setattr(routes.threat_intel, "lookup_domain", lambda d, k: {"verdict": "clean", "malicious": 0})
    owner, intruder = make_user("eve1", "analyst"), make_user("mal1", "analyst")
    login(client, owner)
    _upload(client, PHISH_EML)
    sid = _latest().id
    # Owner first: the app-context fixture shares flask.g between test clients, so the
    # last client to log in would otherwise be the identity Flask-Login sees.
    client.post(f"/result/{sid}/threat-intel")
    assert AuditLog.query.filter_by(event_type="threat_intel_lookup").count() == 1
    other = app.test_client()
    login(other, intruder)
    assert other.post(f"/result/{sid}/threat-intel").status_code == 403
    assert AuditLog.query.filter_by(event_type="threat_intel_lookup").count() == 1  # denied attempt not a lookup
    assert AuditLog.verify_chain()[0] is True


def test_threat_intel_requires_authentication(client, analyst_user):
    assert client.post("/result/1/threat-intel").status_code in (302, 401)


# ----------------------------------------------------------- admin + schema
def test_model_performance_page_renders_reports(client, admin_user):
    login(client, admin_user)
    resp = client.get("/admin/model-performance")
    assert resp.status_code == 200
    assert b"Threat-intelligence tools" in resp.data


def test_analyst_cannot_open_model_performance(client, analyst_user):
    login(client, analyst_user)
    assert client.get("/admin/model-performance").status_code == 403


def test_old_database_gets_new_columns_added_automatically(tmp_path):
    import sqlite3
    from app import create_app
    from config import Config
    db_file = tmp_path / "old.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE email_submissions (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, subject TEXT)")
    conn.commit()
    conn.close()

    class OldDbConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_file}"
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False

    create_app(OldDbConfig)
    conn = sqlite3.connect(db_file)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(email_submissions)")}
    conn.close()
    assert {"rule_score", "text_probability", "structured_probability", "verdict"} <= columns
    assert conn is not None and ExtractedIndicator.__tablename__ == "extracted_indicators"


def test_relative_sqlite_url_is_anchored_to_project_root(monkeypatch):
    import os
    import config
    monkeypatch.setenv("DATABASE_URL", "sqlite:///instance/relative.db")
    uri = config._database_uri()
    assert uri.startswith("sqlite:///") and os.path.isabs(uri[len("sqlite:///"):])
    assert uri.endswith(os.path.join("instance", "relative.db"))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    assert config._database_uri() == "sqlite:///:memory:"
