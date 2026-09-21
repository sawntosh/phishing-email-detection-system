import io
import json

import pytest

from conftest import login
from detector import pasted
from models import EmailSubmission, AuditLog
from test_detector_routes import PHISH_EML, LEGIT_EML

PHISH_TEXT = ("Dear customer, your account will be suspended within 24 hours. Click here to verify your password "
              "immediately: http://paypa1-secure.com/verify?id=1")
LEGIT_TEXT = "Hey, are you free for lunch on Friday around 12:30? Let me know."


def _paste(client, text, subject="", sender="", **extra):
    data = {"message_text": text, "message_subject": subject, "message_sender": sender, **extra}
    return client.post("/upload", data=data, follow_redirects=True)


def _latest():
    return EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()


# ------------------------------------------------------------- page + happy paths
def test_upload_page_offers_both_options(client, analyst_user):
    login(client, analyst_user)
    html = client.get("/upload").get_data(as_text=True)
    assert 'name="message_text"' in html and 'name="email_file"' in html
    assert "Analyse a pasted message" in html and "Upload an email file" in html


def test_pasted_phishing_text_is_analysed_and_quarantined(client, analyst_user):
    login(client, analyst_user)
    resp = _paste(client, PHISH_TEXT, subject="Urgent: verify your account")
    assert resp.status_code == 200
    s = _latest()
    assert s.verdict in ("phishing", "suspicious") and s.quarantined is True
    assert s.subject == "Urgent: verify your account"
    assert s.original_filename == "pasted_message.txt"
    assert any(i.kind == "domain" and i.value == "paypa1-secure.com" for i in s.indicators)
    assert b"pasted_message.txt" in resp.data


def test_pasted_legitimate_text_is_not_quarantined(client, analyst_user):
    login(client, analyst_user)
    _paste(client, LEGIT_TEXT)
    s = _latest()
    assert s.verdict == "legitimate" and s.quarantined is False
    assert s.subject == pasted.DEFAULT_SUBJECT


def test_sender_field_feeds_header_analysis(client, analyst_user):
    login(client, analyst_user)
    _paste(client, "Please confirm your details.", subject="Account notice",
           sender='"PayPal Support" <help@totally-not-paypal.ru>')
    s = _latest()
    assert "totally-not-paypal.ru" in s.sender
    assert "Header: display_name_brand_mismatch" in s.rule_indicators()


def test_pasting_a_full_raw_email_keeps_authentication_results(client, analyst_user):
    login(client, analyst_user)
    _paste(client, PHISH_EML.decode())
    s = _latest()
    assert (s.spf_result, s.dkim_result, s.dmarc_result) == ("fail", "fail", "fail")
    assert s.original_filename == "pasted_message.eml"
    assert s.verdict == "phishing"


def test_pasted_and_uploaded_versions_of_same_email_agree(client, analyst_user):
    login(client, analyst_user)
    _paste(client, LEGIT_EML.decode())
    pasted_score = _latest().risk_score
    client.post("/upload", data={"email_file": (io.BytesIO(LEGIT_EML), "x.eml")},
                content_type="multipart/form-data", follow_redirects=True)
    assert _latest().risk_score == pasted_score


def test_non_ascii_text_is_supported(client, analyst_user):
    login(client, analyst_user)
    _paste(client, "Hola, ¿nos vemos mañana para almorzar? 你好 — café ☕", subject="Almuerzo ñandú")
    s = _latest()
    assert s is not None and s.verdict == "legitimate"
    assert "ñandú" in s.subject


def test_pasted_submission_is_audited_like_an_upload(client, analyst_user):
    login(client, analyst_user)
    _paste(client, LEGIT_TEXT)
    events = [a.event_type for a in AuditLog.query.all()]
    assert "ingest_accepted" in events and "scored" in events
    assert AuditLog.verify_chain()[0] is True


# ------------------------------------------------------------------ safety
@pytest.mark.parametrize("field", ["subject", "sender"])
def test_header_injection_through_subject_or_sender_is_neutralised(client, analyst_user, field):
    login(client, analyst_user)
    evil = "Hello\r\nBcc: victim@example.com\r\nX-Injected: yes"
    kwargs = {field: evil}
    _paste(client, LEGIT_TEXT, **kwargs)
    headers = json.loads(_latest().received_headers_summary)
    assert "Bcc" not in headers and "X-Injected" not in headers


def test_build_from_paste_collapses_newlines_and_caps_length():
    raw, name, mime = pasted.build_from_paste("body text here", subject="A\r\nB\nC" + "x" * 1000, sender="")
    header_block = raw.split(b"\r\n\r\n", 1)[0].decode()
    assert header_block.count("Subject:") == 1
    assert len(header_block) < 600
    assert (name, mime) == ("pasted_message.txt", "text/plain")


def test_raw_email_detection_is_strict():
    assert pasted.looks_like_raw_email("From: a@b.com\nSubject: x\n\nbody")
    assert pasted.looks_like_raw_email("Received: from x\nX-Custom: 1\n\nbody")
    assert not pasted.looks_like_raw_email("From: a@b.com")                     # no body separator
    assert not pasted.looks_like_raw_email("Hello: is this a header?\n\nbody")  # unknown header name
    assert not pasted.looks_like_raw_email("Dear customer,\n\nplease click")
    assert not pasted.looks_like_raw_email("")


def test_pasted_script_tags_are_never_executed_or_stored_raw(client, analyst_user):
    login(client, analyst_user)
    _paste(client, "<script>alert(1)</script> hi there, are we still meeting <b>tomorrow</b>?")
    page = client.get(f"/result/{_latest().id}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page


# ----------------------------------------------------------------- errors
def test_empty_submission_is_rejected_with_a_message(client, analyst_user):
    login(client, analyst_user)
    before = EmailSubmission.query.count()
    resp = client.post("/upload", data={"message_text": "", "message_subject": ""}, follow_redirects=True)
    assert b"Paste a message or choose" in resp.data
    assert EmailSubmission.query.count() == before


def test_whitespace_only_paste_is_rejected(client, analyst_user):
    login(client, analyst_user)
    resp = _paste(client, "   \r\n\t  \n ")
    assert b"Paste a message or choose" in resp.data
    assert EmailSubmission.query.count() == 0


def test_providing_both_a_paste_and_a_file_is_rejected(client, analyst_user):
    login(client, analyst_user)
    resp = client.post(
        "/upload",
        data={"message_text": LEGIT_TEXT, "email_file": (io.BytesIO(LEGIT_EML), "x.eml")},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert b"only one input" in resp.data
    assert EmailSubmission.query.count() == 0


def test_oversized_paste_is_refused_before_processing(client, analyst_user):
    login(client, analyst_user)
    resp = client.post("/upload", data={"message_text": "a" * (6 * 1024 * 1024)})
    assert resp.status_code == 413
    assert EmailSubmission.query.count() == 0


def test_pasting_requires_login(client):
    resp = client.post("/upload", data={"message_text": LEGIT_TEXT}, follow_redirects=False)
    assert resp.status_code in (302, 401)
    assert EmailSubmission.query.count() == 0
