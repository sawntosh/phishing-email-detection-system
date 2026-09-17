"""
Content, keyword and structural analysis of the (already sanitised)
email body. Purely lexical/statistical -- never executes or renders
the body. Feeds both the rules engine and the ML feature vector.
"""
import re

URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "within 24 hours", "final notice", "your account will be closed",
    "unauthorized access", "click here", "confirm your identity",
    "limited time", "action required", "unusual activity", "locked",
]

CREDENTIAL_REQUEST_WORDS = [
    "password", "social security", "credit card", "verify your identity",
    "update your billing", "confirm your password", "login credentials",
    "pin number", "security code", "bank account details",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear account holder", "dear sir/madam"]


def _count_hits(text_lower: str, phrases) -> int:
    return sum(1 for p in phrases if p in text_lower)


def analyse_content(subject: str, body_text: str) -> dict:
    text = f"{subject or ''}\n{body_text or ''}"
    text_lower = text.lower()

    urgency_hits = _count_hits(text_lower, URGENCY_WORDS)
    credential_hits = _count_hits(text_lower, CREDENTIAL_REQUEST_WORDS)
    generic_greeting = any(g in text_lower for g in GENERIC_GREETINGS)

    exclamation_count = text.count("!")
    all_caps_words = len(re.findall(r"\b[A-Z]{4,}\b", text))
    has_html_form = bool(re.search(r"<form", text_lower))

    findings = []
    risk_points = 0

    if urgency_hits:
        findings.append(f"urgency_language_x{urgency_hits}")
        risk_points += min(urgency_hits * 5, 20)
    if credential_hits:
        findings.append(f"credential_request_language_x{credential_hits}")
        risk_points += min(credential_hits * 6, 24)
    if generic_greeting:
        findings.append("generic_greeting")
        risk_points += 5
    if exclamation_count >= 3:
        findings.append("excessive_exclamations")
        risk_points += 4
    if all_caps_words >= 3:
        findings.append("excessive_caps")
        risk_points += 4
    if has_html_form:
        findings.append("embedded_form")
        risk_points += 10

    return {
        "urgency_hits": urgency_hits,
        "credential_hits": credential_hits,
        "generic_greeting": generic_greeting,
        "exclamation_count": exclamation_count,
        "all_caps_words": all_caps_words,
        "has_html_form": has_html_form,
        "findings": findings,
        "risk_points": min(risk_points, 40),
    }
