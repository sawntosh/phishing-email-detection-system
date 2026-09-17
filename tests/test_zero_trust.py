import types
import pytest

from analysis import zero_trust
from analysis.zero_trust import ZeroTrustRejection
from config import Config

DEFAULT_KWARGS = dict(
    max_bytes=Config.MAX_CONTENT_LENGTH,
    allowed_ext=Config.ALLOWED_UPLOAD_EXTENSIONS,
    allowed_mimetypes=Config.ALLOWED_UPLOAD_MIMETYPES,
)

FAKE_USER = types.SimpleNamespace(is_active=True, locked_until=None)

SAMPLE_EML = b"""From: "Jordan Lee" <jordan@company.com>
Subject: Hello
Content-Type: text/plain

Hi there, just checking in.
"""


def test_g1_rejects_unauthenticated_user():
    with pytest.raises(ZeroTrustRejection) as exc:
        zero_trust.ingest(SAMPLE_EML, "test.eml", "text/plain", None, **DEFAULT_KWARGS)
    assert exc.value.gate == "G1_AUTHZ"


def test_g2_rejects_disallowed_extension():
    with pytest.raises(ZeroTrustRejection) as exc:
        zero_trust.ingest(SAMPLE_EML, "malware.exe", "application/octet-stream", FAKE_USER, **DEFAULT_KWARGS)
    assert exc.value.gate == "G2_SIZE_MIME"


def test_g2_rejects_oversized_upload():
    kwargs = dict(DEFAULT_KWARGS, max_bytes=10)
    with pytest.raises(ZeroTrustRejection) as exc:
        zero_trust.ingest(SAMPLE_EML, "test.eml", "text/plain", FAKE_USER, **kwargs)
    assert exc.value.gate == "G2_SIZE_MIME"


def test_g2_rejects_empty_upload():
    with pytest.raises(ZeroTrustRejection) as exc:
        zero_trust.ingest(b"", "test.eml", "text/plain", FAKE_USER, **DEFAULT_KWARGS)
    assert exc.value.gate == "G2_SIZE_MIME"


def test_g3_rejects_unparseable_content():
    junk = bytes(range(256)) * 4  # binary garbage, no headers at all
    with pytest.raises(ZeroTrustRejection) as exc:
        zero_trust.ingest(junk, "test.eml", "text/plain", FAKE_USER, **DEFAULT_KWARGS)
    assert exc.value.gate == "G3_STRUCTURE"


def test_valid_email_passes_all_gates_and_is_sanitised():
    result = zero_trust.ingest(SAMPLE_EML, "test.eml", "text/plain", FAKE_USER, **DEFAULT_KWARGS)
    assert result.subject == "Hello"
    assert "checking in" in result.body_text
    assert result.gates_passed == [
        "G1_AUTHZ", "G2_SIZE_MIME", "G3_STRUCTURE", "G4_SANITISE", "G5_ATTACHMENT_CONTAINMENT",
    ]


def test_html_body_is_sanitised_of_scripts():
    html_eml = b"""From: attacker@evil.com
Subject: hi
Content-Type: text/html

<html><body><script>alert('xss')</script><p onclick="steal()">click</p></body></html>
"""
    result = zero_trust.ingest(html_eml, "test.eml", "text/plain", FAKE_USER, **DEFAULT_KWARGS)
    assert "<script" not in result.body_html_sanitised
    assert "onclick" not in result.body_html_sanitised


def test_attachments_are_hashed_not_stored():
    eml_with_attachment = (
        b"From: a@b.com\nSubject: doc\nMIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUND\"\n\n"
        b"--BOUND\nContent-Type: text/plain\n\nSee attached.\n\n"
        b"--BOUND\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=\"invoice.pdf\"\n"
        b"Content-Transfer-Encoding: base64\n\nJVBERi0xLjQK\n--BOUND--"
    )
    result = zero_trust.ingest(eml_with_attachment, "test.eml", "text/plain", FAKE_USER, **DEFAULT_KWARGS)
    assert len(result.attachment_summaries) == 1
    summary = result.attachment_summaries[0]
    assert summary["filename"] == "invoice.pdf"
    assert len(summary["sha256"]) == 64
    assert "content" not in summary  # raw bytes never retained
