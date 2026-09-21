import io
import json
import os
import re

import pytest

from conftest import ROOT, login, make_user
from models import EmailSubmission, db
from test_detector_routes import LEGIT_EML, PHISH_EML, _upload
from ui_helpers import RISK_BANDS, fmt_dt, risk_band, verdict_view, event_tone


def _eml(subject, sender="a@example.com", body="Hello there, are you free for lunch on Friday?", extra=""):
    return (f"From: {sender}\nSubject: {subject}\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n{extra}"
            f"Content-Type: text/plain\n\n{body}\n").encode()


def _latest():
    return EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()


# ------------------------------------------------------------------ helpers
@pytest.mark.parametrize("score,key", [(0, "low"), (29.9, "low"), (30, "medium"), (59.9, "medium"), (60, "high"),
                                       (79.9, "high"), (80, "critical"), (100, "critical"), (None, "low"), ("junk", "low"),
                                       (-5, "low"), (250, "critical")])
def test_risk_band_edges_match_the_documented_scale(score, key):
    assert risk_band(score)["key"] == key


def test_bands_cover_the_whole_scale_and_agree_with_verdict_thresholds():
    assert [(b["lo"], b["hi"]) for b in RISK_BANDS] == [(0, 29), (30, 59), (60, 79), (80, 100)]
    from analysis import risk_engine
    assert RISK_BANDS[1]["lo"] == risk_engine.SUSPICIOUS_THRESHOLD and RISK_BANDS[2]["lo"] == risk_engine.PHISHING_THRESHOLD


def test_verdict_labels_and_unknown_fallback():
    assert verdict_view("legitimate")["label"] == "SAFE" and verdict_view("phishing")["tone"] == "danger"
    assert verdict_view("nonsense")["label"] == "UNKNOWN"


def test_datetime_formatting_is_consistent_and_none_safe():
    from datetime import datetime
    assert fmt_dt(datetime(2026, 9, 21, 13, 5)) == "21 Sep 2026, 13:05 UTC"
    assert fmt_dt(datetime(2026, 9, 21, 13, 5), with_time=False) == "21 Sep 2026"
    assert fmt_dt(None) == "—"


@pytest.mark.parametrize("event,tone", [("login_fail", "danger"), ("role_denied", "danger"), ("ingest_rejected", "danger"),
                                        ("quarantine", "warning"), ("login_success", "success"), ("something_else", "info")])
def test_audit_event_tones(event, tone):
    assert event_tone(event) == tone


# --------------------------------------------------------------- app shell
def test_authenticated_pages_share_the_shell_with_accessibility_landmarks(client, analyst_user):
    login(client, analyst_user)
    for path in ("/", "/upload", "/history", "/analytics", "/settings", "/review"):
        html = client.get(path).get_data(as_text=True)
        assert 'class="skip-link"' in html and 'id="main"' in html, path
        assert '<nav aria-label="Primary">' in html and 'aria-label="Notifications"' in html, path
        assert html.count("<h1") >= 1 and 'lang="en"' in html, path
        assert 'aria-current="page"' in html, path


def test_navigation_hides_admin_links_from_analysts_and_shows_them_to_admins(client, app):
    a, adm = make_user("nina", "analyst"), make_user("adam", "admin")
    login(client, a)
    html = client.get("/").get_data(as_text=True)
    assert "Audit Log" not in html and "Model Performance" not in html and ">Users<" not in html
    admin_client = app.test_client()
    login(admin_client, adm)
    html = admin_client.get("/").get_data(as_text=True)
    assert "Audit Log" in html and "Model Performance" in html and "Users" in html


def test_active_page_is_marked_in_the_sidebar(client, analyst_user):
    login(client, analyst_user)
    html = client.get("/history").get_data(as_text=True)
    assert re.search(r'<a href="/history"\s+aria-current="page"', html)
    assert not re.search(r'<a href="/analytics"\s+aria-current="page"', html)


def test_pages_only_load_self_hosted_scripts_and_styles(client, analyst_user):
    login(client, analyst_user)
    for path in ("/", "/upload", "/history"):
        html = client.get(path).get_data(as_text=True)
        for src in re.findall(r'<script[^>]*\ssrc="([^"]+)"', html) + re.findall(r'<link[^>]*href="([^"]+)"', html):
            assert src.startswith("/static/"), f"{path} loads a non-local asset: {src}"
        inline = [m for m in re.findall(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>", html, re.S) if m.strip()]
        assert not inline, f"{path} has inline script (blocked by the CSP)"
        assert not re.search(r'\son(click|load|submit|change|error)=', html)


def test_static_assets_are_served_and_the_old_stylesheet_is_gone(client):
    for asset in ("css/app.css", "js/app.js", "js/analyze.js", "js/theme-init.js"):
        assert client.get(f"/static/{asset}").status_code == 200, asset
    assert client.get("/static/css/style.css").status_code == 404


def test_css_defines_both_themes_and_the_semantic_tones_once():
    css = open(os.path.join(ROOT, "src", "static", "css", "app.css"), encoding="utf-8").read()
    assert '[data-theme="light"]' in css and ":root {" in css
    for tone in ("success", "warning", "danger", "critical", "info"):
        assert f".tone-{tone}" in css
    assert "prefers-reduced-motion" in css and ":focus-visible" in css


def test_no_hardcoded_status_colours_in_templates():
    tpl_dir = os.path.join(ROOT, "src", "templates")
    offenders = []
    for folder, _, files in os.walk(tpl_dir):
        for name in files:
            text = open(os.path.join(folder, name), encoding="utf-8").read()
            if re.search(r"#[0-9a-fA-F]{6}\b", text.replace("{#", "").replace("#}", "")) and name != "_icons.html":
                offenders.append(name)
    assert offenders == [], f"use design tokens instead of hex colours: {offenders}"


# ------------------------------------------------------------------ auth pages
def test_auth_pages_use_the_split_layout_without_the_app_sidebar(client):
    for path in ("/auth/login", "/auth/register"):
        html = client.get(path).get_data(as_text=True)
        assert 'class="auth"' in html and 'class="sidebar"' not in html
        assert "PhishGuard" in html and "<form" in html
        for label_for in re.findall(r'<label for="([^"]+)"', html):
            assert f'id="{label_for}"' in html, f"label for={label_for} has no matching input"
    assert b"Log in" in client.get("/auth/login").data


def test_anonymous_error_page_still_renders_content(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404 and b"Page not found" in resp.data and b'class="page page--public"' in resp.data


# --------------------------------------------------------------------- dashboard
def test_dashboard_empty_state_then_real_numbers(client, analyst_user):
    login(client, analyst_user)
    assert b"No email analyses yet" in client.get("/").data
    _upload(client, PHISH_EML)
    _upload(client, LEGIT_EML)
    html = client.get("/").get_data(as_text=True)
    assert "Total Emails Analysed" in html and "Average Risk Score" in html and "High-Risk Emails" in html
    assert re.search(r'kpi__label">Total Emails Analysed</div>\s*<div class="kpi__value">2</div>', html)
    for band in RISK_BANDS:
        assert band["label"] in html
    assert "No email analyses yet" not in html


def test_dashboard_kpis_never_depend_on_javascript_to_show_the_true_value(client, analyst_user):
    login(client, analyst_user)
    _upload(client, LEGIT_EML)
    html = client.get("/").get_data(as_text=True)
    assert "data-count" not in html
    assert re.search(r'kpi__value">1</div>', html)


def test_risk_band_counts_add_up_to_the_total(client, analyst_user):
    login(client, analyst_user)
    for subject in ("a", "b", "c"):
        _upload(client, _eml(subject))
    _upload(client, PHISH_EML)
    html = client.get("/").get_data(as_text=True)
    counts = [int(n) for n in re.findall(r'riskband__count">(\d+)<', html)]
    assert len(counts) == 4 and sum(counts) == 4


# ---------------------------------------------------------------------- history
def _seed(client, n):
    for i in range(n):
        _upload(client, _eml(f"Subject number {i}", body=f"Unique body {i} about project planning."))


def test_history_requires_login(client):
    assert client.get("/history", follow_redirects=True).request.path.startswith("/auth/login")


def test_history_lists_search_filters_sorts_and_paginates(client, analyst_user):
    login(client, analyst_user)
    _seed(client, 17)
    _upload(client, PHISH_EML)
    page1 = client.get("/history").get_data(as_text=True)
    assert page1.count("<tr>") == 16 and "18 results" in page1 and "page 1 of 2" in page1
    assert "page 2 of 2" in client.get("/history?page=2").get_data(as_text=True)

    found = client.get("/history?q=Subject+number+7").get_data(as_text=True)
    assert "Subject number 7" in found and "Subject number 8" not in found

    phishing = client.get("/history?verdict=phishing").get_data(as_text=True)
    assert "Verify your account now" in phishing and "Subject number" not in phishing

    top = client.get("/history?sort=score_desc").get_data(as_text=True)
    assert top.index("Verify your account now") < top.index("Subject number")


def test_history_search_treats_percent_and_underscore_literally(client, analyst_user):
    login(client, analyst_user)
    _seed(client, 3)
    assert "No matching analyses" in client.get("/history?q=%25").get_data(as_text=True)
    assert "No matching analyses" in client.get("/history?q=_").get_data(as_text=True)


@pytest.mark.parametrize("query", ["page=abc", "page=-4", "page=99999", "sort=DROP+TABLE", "verdict=;--", "status=%27+OR+1%3D1",
                                   "q=" + "x" * 500, "q=%3Cscript%3E"])
def test_history_tolerates_hostile_or_malformed_parameters(client, analyst_user, query):
    login(client, analyst_user)
    _seed(client, 2)
    resp = client.get("/history?" + query)
    assert resp.status_code == 200 and b"<script>" not in resp.data.split(b"<main")[1]


def test_history_shows_only_the_current_analysts_emails(client, app):
    a, b = make_user("hal", "analyst"), make_user("iris", "analyst")
    login(client, a)
    _upload(client, _eml("Halfs private subject"))
    other = app.test_client()
    login(other, b)
    assert "Halfs private subject" not in other.get("/history").get_data(as_text=True)


def test_history_status_filters(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    _upload(client, LEGIT_EML)
    sid = EmailSubmission.query.filter_by(verdict="phishing").first().id
    assert "Verify your account now" in client.get("/history?status=pending").get_data(as_text=True)
    client.post(f"/result/{sid}/feedback", data={"feedback": "false_positive"})
    assert "No matching analyses" in client.get("/history?status=pending").get_data(as_text=True)
    assert "Verify your account now" in client.get("/history?status=false_positive").get_data(as_text=True)


def test_history_empty_state_before_any_analysis(client, analyst_user):
    login(client, analyst_user)
    assert b"No email analyses yet" in client.get("/history").data


def test_subject_with_html_is_escaped_everywhere(client, analyst_user):
    login(client, analyst_user)
    payload = "<img src=x onerror=alert(1)>"
    _upload(client, _eml(payload))
    sid = _latest().id
    for path in ("/", "/history", f"/result/{sid}", "/review", "/analytics"):
        body = client.get(path).get_data(as_text=True)
        assert payload not in body, path
    assert "&lt;img src=x onerror=alert(1)&gt;" in client.get("/history").get_data(as_text=True)


# --------------------------------------------------------------------- analytics
def test_analytics_empty_state_and_populated_view(client, analyst_user):
    login(client, analyst_user)
    assert b"Nothing to analyse yet" in client.get("/analytics").data
    _upload(client, PHISH_EML)
    _upload(client, LEGIT_EML)
    html = client.get("/analytics").get_data(as_text=True)
    for heading in ("Phishing vs safe", "Risk-score distribution", "Detection trend", "Most common indicators",
                    "Suspicious domains", "Authentication failures", "Brand impersonation attempts"):
        assert heading in html
    assert "paypa1-secure[.]com" in html and "PayPal" in html and "hxxp" not in html.split("Suspicious domains")[0]


def test_analytics_is_scoped_to_the_user(client, app):
    a, b = make_user("kay", "analyst"), make_user("leo", "analyst")
    login(client, a)
    _upload(client, PHISH_EML)
    other = app.test_client()
    login(other, b)
    assert b"Nothing to analyse yet" in other.get("/analytics").data


# ---------------------------------------------------------------- result page
def test_result_page_has_all_sections_and_real_evidence(client, analyst_user):
    login(client, analyst_user)
    _upload(client, _eml("Reset now", sender='"PayPal Support" <help@paypa1-secure.com>',
                         body="Confirm your password at http://paypa1-secure.com/verify immediately",
                         extra="Reply-To: attacker@evil-mail.top\nReturn-Path: bounce@other-domain.ru\n"))
    s = _latest()
    assert s.reply_to == "attacker@evil-mail.top" and s.return_path == "bounce@other-domain.ru"
    html = client.get(f"/result/{s.id}").get_data(as_text=True)
    for text in ("Threat analysis", "ML confidence", "Sender Analysis", "URL Analysis", "Header Analysis", "Content Analysis",
                 "Authentication", "Recommended action", "Sender / Reply-To mismatch", "attacker@evil-mail.top",
                 "bounce@other-domain.ru", "Do not click links"):
        assert text in html, text
    for tab in ("Overview", "Headers", "URLs", "Content", "Attachments", "Authentication", "Indicators"):
        assert f'id="tab-{tab.lower()}"' in html
    assert 'role="tablist"' in html and "http://paypa1-secure.com" not in html


def test_result_page_for_a_safe_email_has_calm_wording_and_no_alarm_cards(client, analyst_user):
    login(client, analyst_user)
    _upload(client, LEGIT_EML)
    html = client.get(f"/result/{_latest().id}").get_data(as_text=True)
    assert "SAFE" in html and "Why this email looks safe" in html and "detected as safe" not in html
    assert "No indicators triggered" in html


def test_risk_information_is_never_conveyed_by_colour_alone(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    html = client.get(f"/result/{_latest().id}").get_data(as_text=True)
    assert re.search(r'class="badge tone-\w+[^"]*"[^>]*>\s*<svg[^>]*>.*?</svg>[A-Z]+', html, re.S)
    assert 'role="img" aria-label="Risk score' in html


def test_result_page_supports_emails_analysed_before_reply_to_was_stored(client, analyst_user):
    login(client, analyst_user)
    _upload(client, LEGIT_EML)
    s = _latest()
    s.reply_to = s.return_path = None
    db.session.commit()
    html = client.get(f"/result/{s.id}").get_data(as_text=True)
    assert "not present" in html and "recorded for emails analysed after this feature was added" in html


def test_presenter_summary_levels_and_authentication(client, analyst_user):
    from detector import presenter
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    s = _latest()
    view = presenter.build_result_view(s, [], [])
    by_key = {c["key"]: c for c in view["summary"]}
    assert by_key["auth"]["label_text"] == "FAILED" and by_key["auth"]["tone"] == "danger"
    assert by_key["url"]["level"] in ("high", "critical")
    assert all(c["label"] for c in view["summary"]) and by_key["sender"]["label"] == "Sender Analysis"
    assert view["cards"][0]["severity"] in ("critical", "high")
    assert [c["severity"] for c in view["cards"]] == sorted((c["severity"] for c in view["cards"]),
                                                             key=lambda v: ("none", "low", "medium", "high", "critical").index(v),
                                                             reverse=True)


def test_evidence_for_authentication_is_the_real_stored_result(client, analyst_user):
    from detector import presenter
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    view = presenter.build_result_view(_latest(), [], [])
    spf = [c for c in view["cards"] if c["code"] == "spf_fail"][0]
    assert ("Result", "SPF = fail") in spf["evidence"]


def test_json_export_includes_reply_to_and_return_path(client, analyst_user):
    login(client, analyst_user)
    _upload(client, _eml("x", extra="Reply-To: r@other.example\nReturn-Path: <rp@other.example>\n"))
    data = json.loads(client.get(f"/result/{_latest().id}/export/json").get_data(as_text=True))
    assert data["reply_to"] == "r@other.example" and data["return_path"] == "<rp@other.example>"


# ---------------------------------------------------------------- confirmations
def test_sensitive_actions_carry_confirmation_prompts(client, app):
    adm = make_user("root1", "admin")
    other = make_user("target1", "analyst")
    login(client, adm)
    users_html = client.get("/admin/users").get_data(as_text=True)
    assert "data-confirm=" in users_html and "Promote target1 to administrator" in users_html
    _upload(client, PHISH_EML)
    result_html = client.get(f"/result/{_latest().id}").get_data(as_text=True)
    assert result_html.count("data-confirm=") >= 3   # release, confirm phishing, mark false positive
    assert other.username in users_html


# ------------------------------------------------------------------ analyze page
def test_analyze_page_has_both_inputs_dropzone_and_accessible_status_regions(client, analyst_user):
    login(client, analyst_user)
    html = client.get("/upload").get_data(as_text=True)
    for needle in ('name="message_text"', 'name="email_file"', 'id="dropzone"', 'id="analysis-overlay"', 'role="progressbar"',
                   'id="form-error"', 'role="alert"', "Phishing sample", "Legitimate sample", ".msg"):
        assert needle in html, needle
    assert html.count('data-step') == 5 and "js/analyze.js" in html


def test_analyze_page_examples_are_inert_text_not_html(client, analyst_user):
    login(client, analyst_user)
    html = client.get("/upload").get_data(as_text=True)
    template = re.search(r'<template id="example-phish">(.*?)</template>', html, re.S).group(1)
    assert "<" not in template.replace("&lt;", "").replace("&gt;", "")


# ----------------------------------------------------------------------- settings
def test_settings_shows_profile_and_hides_system_status_from_analysts(client, app):
    a, adm = make_user("mo", "analyst"), make_user("ned", "admin")
    login(client, a)
    html = client.get("/settings").get_data(as_text=True)
    assert "mo@example.com" in html and "Two-factor authentication" in html and "System status" not in html
    admin_client = app.test_client()
    login(admin_client, adm)
    assert "System status" in admin_client.get("/settings").get_data(as_text=True)


def test_settings_does_not_expose_secrets(client, app, analyst_user):
    app.config["VIRUSTOTAL_API_KEY"] = "SUPER-SECRET-KEY-123"
    login(client, analyst_user)
    assert b"SUPER-SECRET-KEY-123" not in client.get("/settings").data


def test_totp_secret_and_password_hash_never_appear_in_pages(client, analyst_user):
    login(client, analyst_user)
    for path in ("/", "/settings", "/upload", "/history"):
        body = client.get(path).get_data(as_text=True)
        assert analyst_user.totp_secret not in body and analyst_user.password_hash not in body


# ---------------------------------------------------------------------- admin
def test_admin_pages_render_for_admins_and_stay_forbidden_for_analysts(client, app):
    adm, an = make_user("boss", "admin"), make_user("staff", "analyst")
    login(client, adm)
    _upload(client, PHISH_EML)
    for path in ("/admin/audit-log", "/admin/users", "/admin/model-performance"):
        assert client.get(path).status_code == 200, path
    assert b"Chain intact" in client.get("/admin/audit-log").data
    analyst_client = app.test_client()
    login(analyst_client, an)
    for path in ("/admin/audit-log", "/admin/users", "/admin/model-performance"):
        assert analyst_client.get(path).status_code == 403, path


def test_audit_log_page_escapes_hostile_detail_text(client, admin_user):
    from models import AuditLog
    AuditLog.append("login_fail", username="<b>evil</b>", detail="<script>alert(1)</script>")
    login(client, admin_user)
    html = client.get("/admin/audit-log").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_review_queue_empty_and_populated(client, analyst_user):
    login(client, analyst_user)
    assert b"You are all caught up" in client.get("/review").data
    _upload(client, PHISH_EML)
    assert b"Verify your account now" in client.get("/review").data


def test_safe_email_never_gets_a_wording_alarm_card_from_a_single_word(client, analyst_user):
    from detector import presenter
    login(client, analyst_user)
    _upload(client, LEGIT_EML)
    s = _latest()
    s.text_probability = 0.2
    view = presenter.build_result_view(s, [], [{"feature": "account", "value": 0.4, "contribution": 0.9, "source": "text"}])
    assert not [c for c in view["cards"] if c["code"] == "ml_text_terms"]
    s.text_probability = 0.9
    view = presenter.build_result_view(s, [], [{"feature": "account", "value": 0.4, "contribution": 0.9, "source": "text"}])
    assert [c for c in view["cards"] if c["code"] == "ml_text_terms"]
