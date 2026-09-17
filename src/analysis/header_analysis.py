"""
Header and sender analysis: spoofing indicators, display-name/address
mismatch, and parsing of Authentication-Results for SPF/DKIM/DMARC where
present. This module never queries DNS itself (no live SPF/DKIM
re-verification is performed) -- it parses what the receiving mail
server already recorded in Authentication-Results, which is the safe,
side-effect-free approach for offline analysis of a submitted .eml.
"""
import re
from email.utils import parseaddr

AUTH_RESULT_RE = re.compile(r"(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)


def parse_auth_results(raw_headers: dict) -> dict:
    combined = " ".join(v for k, v in raw_headers.items() if k.lower() in ("authentication-results", "received-spf"))
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for mechanism, result in AUTH_RESULT_RE.findall(combined):
        results[mechanism.lower()] = result.lower()
    return results


def analyse_headers(raw_headers: dict, sender_raw: str, subject: str) -> dict:
    findings = []
    risk_points = 0

    display_name, address = parseaddr(sender_raw or "")
    domain = address.split("@")[-1].lower() if "@" in address else ""

    auth = parse_auth_results(raw_headers)
    for mech in ("spf", "dkim", "dmarc"):
        if auth[mech] in ("fail", "softfail"):
            findings.append(f"{mech}_{auth[mech]}")
            risk_points += 12
        elif auth[mech] == "none":
            findings.append(f"{mech}_not_evaluated")
            risk_points += 3

    # Display-name brand impersonation with a mismatched real domain,
    # e.g. "PayPal Support <security@totally-not-paypal.ru>"
    if display_name:
        low = display_name.lower()
        for brand in ("paypal", "microsoft", "apple", "bank", "amazon", "support", "helpdesk", "it department", "admin"):
            if brand in low and brand not in domain:
                findings.append("display_name_brand_mismatch")
                risk_points += 10
                break

    reply_to = raw_headers.get("Reply-To", "")
    if reply_to:
        reply_domain = parseaddr(reply_to)[1].split("@")[-1].lower()
        if reply_domain and domain and reply_domain != domain:
            findings.append("reply_to_domain_mismatch")
            risk_points += 8

    if re.search(r"\d{5,}", domain):
        findings.append("numeric_heavy_sender_domain")
        risk_points += 4

    if subject and re.match(r"^(re|fwd):", subject.strip().lower()) and "received" not in raw_headers.get("References", "").lower() and not raw_headers.get("In-Reply-To"):
        findings.append("fake_reply_thread")
        risk_points += 6

    return {
        "sender_domain": domain,
        "display_name": display_name,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "findings": findings,
        "risk_points": min(risk_points, 45),
    }
