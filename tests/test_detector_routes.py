import io

from conftest import login
from models import EmailSubmission

PHISH_EML = b"""From: "PayPal Security" <security@paypa1-secure.com>
Subject: Urgent: Verify your account now
Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain

Your account will be suspended within 24 hours. Click here to verify
your password: http://paypa1-secure.com/verify?id=1
"""

LEGIT_EML = b"""From: "Jordan Lee" <jordan@company.com>
Subject: Lunch on Friday?
Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Hey, are you free for lunch on Friday around 12:30?
"""


def _upload(client, content, filename="test.eml"):
    return client.post(
        "/upload",
        data={"email_file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_unauthenticated_upload_redirects_to_login(client):
    resp = client.get("/upload", follow_redirects=True)
    assert b"Log in" in resp.data or b"Login" in resp.data


def test_phishing_email_is_quarantined_by_default(client, analyst_user):
    login(client, analyst_user)
    resp = _upload(client, PHISH_EML)
    assert resp.status_code == 200
    submission = EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()
    assert submission is not None
    assert submission.quarantined is True
    assert submission.verdict in ("phishing", "suspicious")


def test_legitimate_email_is_not_quarantined(client, analyst_user):
    login(client, analyst_user)
    _upload(client, LEGIT_EML)
    submission = EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()
    assert submission.quarantined is False
    assert submission.verdict == "legitimate"


def test_rejected_file_type_does_not_create_submission(client, analyst_user):
    login(client, analyst_user)
    before = EmailSubmission.query.count()
    resp = _upload(client, b"MZ\x90\x00fakebinary", filename="malware.exe")
    assert b"Zero-Trust gate" in resp.data
    assert EmailSubmission.query.count() == before


def test_user_cannot_view_another_users_submission(client, app):
    from conftest import make_user
    u1 = make_user("alice", "analyst")
    u2 = make_user("bob", "analyst")
    login(client, u1)
    _upload(client, LEGIT_EML)
    submission = EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()

    client2 = app.test_client()
    login(client2, u2)
    resp = client2.get(f"/result/{submission.id}")
    assert resp.status_code == 403


def test_admin_can_view_any_submission(client, app):
    from conftest import make_user
    analyst = make_user("carol", "analyst")
    admin = make_user("dave", "admin")
    login(client, analyst)
    _upload(client, LEGIT_EML)
    submission = EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()

    admin_client = app.test_client()
    login(admin_client, admin)
    resp = admin_client.get(f"/result/{submission.id}")
    assert resp.status_code == 200


def test_export_json_contains_expected_fields(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    submission = EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()
    resp = client.get(f"/result/{submission.id}/export/json")
    assert resp.status_code == 200
    assert resp.mimetype == "application/json"


def test_analyst_feedback_marks_false_positive(client, analyst_user):
    login(client, analyst_user)
    _upload(client, PHISH_EML)
    submission = EmailSubmission.query.order_by(EmailSubmission.id.desc()).first()
    resp = client.post(
        f"/result/{submission.id}/feedback",
        data={"feedback": "false_positive", "notes": "known internal test"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    updated = EmailSubmission.query.get(submission.id)
    assert updated.analyst_feedback == "false_positive"
