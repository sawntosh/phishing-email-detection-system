"""
View-model for the analysis result page.

Everything here is derived from data that was stored when the email was
analysed (indicator codes, SPF/DKIM/DMARC results, extracted URLs/domains,
ML explanation). Nothing is invented: if a value was not recorded, the page
says so. Severity is presentation metadata from analysis/explanations.py.
"""
import json
import re
from email.utils import parseaddr
from urllib.parse import urlparse

from analysis.explanations import (
    defang, explain_indicator, indicator_category, indicator_severity, indicator_title, strip_layer,
)
from ui_helpers import SEVERITY, risk_band, verdict_view

_SEV_ORDER = ("none", "low", "medium", "high", "critical")
_COUNT_RE = re.compile(r"_x(\d+)$")
_AUTH_STATUS = {
    "pass": ("PASSED", "success", "i-check-circle", "The receiving server confirmed this check."),
    "fail": ("FAILED", "danger", "i-x-circle", "The check failed: the message may not come from who it claims."),
    "softfail": ("SOFT FAIL", "warning", "i-alert", "The check was inconclusive-to-negative (soft failure)."),
    "neutral": ("NEUTRAL", "neutral", "i-info", "The domain published no assertion either way."),
    "none": ("NOT EVALUATED", "neutral", "i-info", "No result was recorded in the message headers."),
}


def _max_severity(levels):
    best = "none"
    for level in levels:
        if _SEV_ORDER.index(level) > _SEV_ORDER.index(best):
            best = level
    return best


def _sender_parts(sender):
    name, address = parseaddr(sender or "")
    return name, address, (address.split("@")[-1].lower() if "@" in address else "")


def _evidence(code, indicator, submission, url_rows):
    rows = []
    sender = submission.sender or "not recorded"
    if code == "reply_to_domain_mismatch":
        rows += [("From", sender), ("Reply-To", submission.reply_to or "not recorded")]
    elif code in ("display_name_brand_mismatch", "numeric_heavy_sender_domain", "fake_reply_thread"):
        rows += [("From", sender)]
        if code == "fake_reply_thread":
            rows += [("Subject", submission.subject or "not recorded")]
    elif re.match(r"^(spf|dkim|dmarc)_", code):
        mech = code.split("_")[0]
        rows += [("Result", f"{mech.upper()} = {getattr(submission, mech + '_result', None) or 'none'}")]
    elif indicator.startswith("URL:"):
        for row in url_rows:
            if code in row["findings"]:
                rows.append(("URL" if row["kind"] == "url" else "Domain", row["display"]))
                if row.get("redirect_target") and code.startswith(("open_redirect", "redirect_to", "nested", "double")):
                    rows.append(("Redirects to", defang(row["redirect_target"])))
            if len(rows) >= 6:
                break
    elif indicator.startswith("Content:"):
        counted = _COUNT_RE.search(code)
        detail = f"{counted.group(1)} matching phrase(s) in the subject/body" if counted else "Detected in the subject/body"
        rows += [("Found in", detail)]
    return rows[:6]


def _url_rows(submission):
    rows, url_domains = [], set()
    for ind in submission.indicators:
        if ind.kind != "url":
            continue
        parsed = urlparse(ind.value)
        findings = ind.findings()
        url_domains.add((parsed.hostname or "").lower())
        rows.append({
            "kind": "url", "display": defang(ind.value), "domain": defang((parsed.hostname or "")),
            "https": parsed.scheme == "https", "findings": findings, "blocklisted": ind.blocklisted,
            "redirect_target": ind.redirect_target, "intel_verdict": ind.intel_verdict,
            "severity": _max_severity([indicator_severity(f) for f in findings] + (["critical"] if ind.blocklisted else [])),
        })
    for ind in submission.indicators:
        if ind.kind != "domain":
            continue
        if any(ind.value in d for d in url_domains if d):
            continue  # already represented by one of its flagged URLs
        findings = ind.findings()
        rows.append({
            "kind": "domain", "display": defang(ind.value), "domain": defang(ind.value), "https": None, "findings": findings,
            "blocklisted": ind.blocklisted, "redirect_target": None, "intel_verdict": ind.intel_verdict,
            "severity": _max_severity([indicator_severity(f) for f in findings] + (["critical"] if ind.blocklisted else [])),
        })
    rows.sort(key=lambda r: -_SEV_ORDER.index(r["severity"]))
    return rows


def _auth_cells(submission):
    cells = []
    for mech in ("spf", "dkim", "dmarc"):
        value = (getattr(submission, f"{mech}_result", None) or "none").lower()
        label, tone, icon, desc = _AUTH_STATUS.get(value, _AUTH_STATUS["neutral"])
        cells.append({"name": mech.upper(), "value": value, "label": label, "tone": tone, "icon": icon, "desc": desc})
    return cells


def _auth_summary(cells):
    values = {c["value"] for c in cells}
    if values & {"fail"}:
        return "FAILED", "danger", "i-x-circle"
    if values & {"softfail"}:
        return "PARTIAL", "warning", "i-alert"
    if values == {"pass"}:
        return "PASSED", "success", "i-check-circle"
    if "pass" in values:
        return "PARTIAL", "warning", "i-alert"
    return "NOT EVALUATED", "neutral", "i-info"


def _recommendations(verdict, categories, has_attachments, quarantined):
    if verdict == "legitimate":
        return ["No phishing indicators of concern were found. Still treat unexpected requests for money or credentials with care."]
    tips = []
    if "url" in categories or has_attachments:
        tips.append("Do not click links or open attachments in this email.")
    if "content" in categories or "sender" in categories or "url" in categories:
        tips.append("Do not provide passwords, one-time codes or personal or payment details.")
    if categories & {"sender", "authentication", "header"}:
        tips.append("Verify the sender through an official channel you already trust (a known phone number or the organisation's own website), not contact details from this email.")
    tips.append("Report the email to your security team or mail provider, then delete it." if verdict == "phishing"
                else "If you are unsure, ask your security team to review it before acting on it.")
    if quarantined:
        tips.append("The message stays quarantined until an analyst releases it or marks it a false positive.")
    return tips


def build_result_view(submission, structured_terms, text_terms):
    verdict = verdict_view(submission.verdict)
    band = risk_band(submission.risk_score)
    url_rows = _url_rows(submission)

    cards, per_category = [], {"url": [], "sender": [], "authentication": [], "header": [], "content": []}
    for raw in submission.rule_indicators():
        code = strip_layer(raw)
        category = indicator_category(raw)
        severity = indicator_severity(raw)
        per_category[category].append(severity)
        cards.append({
            "code": code, "raw": raw, "category": category, "severity": severity, "sev": SEVERITY[severity],
            "title": indicator_title(raw), "explanation": explain_indicator(raw),
            "evidence": _evidence(code, raw, submission, url_rows),
        })
    # Only raise the wording card when the text model itself leans phishing; a lone word with a positive
    # weight in an otherwise safe email must not contradict a SAFE verdict.
    text_leans_phishing = submission.text_probability is not None and submission.text_probability >= 0.5
    positive_terms = [t for t in text_terms if t["contribution"] > 0][:6] if text_leans_phishing else []
    if positive_terms:
        per_category["content"].append("medium" if len(positive_terms) < 4 else "high")
        cards.append({
            "code": "ml_text_terms", "raw": "ML: text", "category": "content", "severity": "medium", "sev": SEVERITY["medium"],
            "title": "Wording resembles known phishing emails",
            "explanation": "The text model, trained on real phishing and legitimate mail, found words and phrases here that are much more common in phishing.",
            "evidence": [("Terms", ", ".join(t["feature"] for t in positive_terms))],
        })
    cards.sort(key=lambda c: -_SEV_ORDER.index(c["severity"]))

    auth_cells = _auth_cells(submission)
    auth_label, auth_tone, auth_icon = _auth_summary(auth_cells)
    auth_present = any(c["value"] != "none" for c in auth_cells)

    def level(category):
        sev = _max_severity(per_category[category])
        info = SEVERITY[sev]
        return {"level": sev, "label_text": info["label"], "tone": info["tone"], "status_icon": info["icon"]}

    summary = [
        {"key": "sender", "label": "Sender Analysis", "icon": "i-user", **level("sender")},
        {"key": "url", "label": "URL Analysis", "icon": "i-link", **level("url")},
        {"key": "header", "label": "Header Analysis", "icon": "i-server", **level("header")},
        {"key": "content", "label": "Content Analysis", "icon": "i-file", **level("content")},
        {"key": "auth", "label": "Authentication", "icon": "i-key", "label_text": auth_label, "tone": auth_tone, "status_icon": auth_icon},
    ]
    name, address, domain = _sender_parts(submission.sender)
    reply_name, reply_addr, reply_domain = _sender_parts(submission.reply_to)
    ret_name, ret_addr, ret_domain = _sender_parts(submission.return_path)
    try:
        header_names = json.loads(submission.received_headers_summary or "[]")
    except ValueError:
        header_names = []
    ml_probability = submission.ml_probability if submission.ml_probability is not None else 0.0
    categories = {c["category"] for c in cards if c["severity"] != "low"} if submission.verdict != "legitimate" else set()

    return {
        "verdict": verdict, "band": band, "cards": cards, "summary": summary, "url_rows": url_rows,
        "auth_cells": auth_cells, "auth_label": auth_label, "auth_tone": auth_tone, "auth_present": auth_present,
        "auth_cards": [c for c in cards if c["category"] == "authentication"],
        "reasons": [c for c in cards if c["severity"] in ("medium", "high", "critical")][:6],
        "recommendations": _recommendations(submission.verdict, categories or {c["category"] for c in cards},
                                            bool(submission.attachment_summary()), submission.quarantined),
        "confidence_pct": round(max(ml_probability, 1 - ml_probability) * 100),
        "sender": {"raw": submission.sender, "display_name": name, "address": address, "domain": domain},
        "reply_to": {"raw": submission.reply_to, "address": reply_addr, "domain": reply_domain},
        "return_path": {"raw": submission.return_path, "address": ret_addr, "domain": ret_domain},
        "reply_mismatch": bool(domain and reply_domain and domain != reply_domain),
        "return_mismatch": bool(domain and ret_domain and domain != ret_domain),
        "header_names": header_names,
        "header_cards": [c for c in cards if c["category"] in ("sender", "header")],
        "content_cards": [c for c in cards if c["category"] == "content"],
        "tab_counts": {"urls": len(url_rows), "attachments": len(submission.attachment_summary()), "indicators": len(cards)},
        "structured_terms": structured_terms, "text_terms": text_terms,
    }
