"""
Turns text pasted into the "Analyse a message" box into the same kind of bytes
an uploaded file would produce, so it goes through the identical Zero-Trust
pipeline (size / MIME / structure / sanitisation gates) -- there is no
separate, less-guarded path for pasted content.

Two shapes are accepted:
  * a full raw email (headers, blank line, body) copied from a mail client's
    "view source" -- passed through untouched so SPF/DKIM/DMARC and sender
    checks still work;
  * plain message text -- wrapped in a minimal RFC 5322 message. The optional
    subject/sender are collapsed to a single line and set through the stdlib
    EmailMessage API, which refuses embedded newlines, so a crafted subject
    cannot inject extra headers (e.g. "Hi\\r\\nBcc: ...").
"""
import re
from email.message import EmailMessage
from email import policy

DEFAULT_SUBJECT = "(pasted message)"
MAX_HEADER_FIELD_CHARS = 200

_RAW_HEADER_NAMES = {
    "from", "subject", "received", "return-path", "delivered-to", "authentication-results",
    "received-spf", "mime-version", "date", "to", "message-id", "reply-to", "content-type",
    "dkim-signature",
}
_HEADER_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]?")


class PastedMessageError(ValueError):
    """Bad pasted input; the message is safe to show to the user."""


def _one_line(value):
    return re.sub(r"\s+", " ", value or "").strip()[:MAX_HEADER_FIELD_CHARS]


def looks_like_raw_email(text):
    """True when the text starts with RFC 5322 style headers followed later by a blank line."""
    lines = text.lstrip("\r\n").splitlines()
    if not lines:
        return False
    match = _HEADER_LINE_RE.match(lines[0])
    if not match:
        return False
    name = match.group(1).lower()
    if name not in _RAW_HEADER_NAMES and not name.startswith("x-"):
        return False
    return any(not line.strip() for line in lines[1:])


def build_from_paste(text, subject="", sender=""):
    """Returns (raw_bytes, filename, mimetype) ready for zero_trust.ingest()."""
    text = (text or "").strip("﻿")
    if not text.strip():
        raise PastedMessageError("Please paste the message text to analyse.")

    if looks_like_raw_email(text):
        return text.lstrip("\r\n").encode("utf-8"), "pasted_message.eml", "message/rfc822"

    message = EmailMessage(policy=policy.SMTP)
    try:
        message["Subject"] = _one_line(subject) or DEFAULT_SUBJECT
        if _one_line(sender):
            message["From"] = _one_line(sender)
        message.set_content(text)
    except (ValueError, TypeError) as exc:
        raise PastedMessageError("The subject or sender contains characters that cannot be used.") from exc
    return message.as_bytes(), "pasted_message.txt", "text/plain"
