"""Human-readable explanations for every rule indicator the engine can emit."""
import re

_EXACT = {
    # URL / domain
    "ip_literal_host": "The link goes to a raw IP address instead of a named website - legitimate services almost never do this.",
    "punycode_domain": "The domain uses punycode (xn--), which can disguise look-alike characters from other alphabets.",
    "suspicious_tld": "The link uses a top-level domain that is heavily abused for throw-away phishing sites.",
    "url_shortener": "The link is shortened, hiding its real destination. Resolve it before trusting it.",
    "no_tls": "The link uses plain http:// with no encryption, unusual for any page asking for credentials.",
    "excessive_hyphens": "The domain contains many hyphens, a common pattern in fake brand domains.",
    "excessively_long_url": "The URL is unusually long, often used to bury the real host or hide tracking payloads.",
    "open_redirect_parameter": "The link passes another site's URL as a parameter and would bounce the reader to a different destination than the one shown.",
    "nested_url_in_url": "A second full URL is embedded inside this link, a trick used to make a malicious destination look like a trusted one.",
    "double_encoded_redirect": "The link contains a double-encoded URL, a common way to slip a redirect target past simple filters.",
    "known_malicious_domain": "The domain is on the built-in list of known phishing domains.",
    "redirect_to_suspicious_target": "The site this link redirects to is itself suspicious (look-alike, IP address, risky TLD or blocklisted).",
    "userinfo_in_url": "The URL has a 'name@host' section - text before the @ is decoration, the real destination is what follows it.",
    "nonstandard_port": "The link uses an unusual network port, typical of ad-hoc phishing kits.",
    "blocklisted_domain": "The domain appears in the local threat-intelligence blocklist of known phishing domains.",
    # Headers
    "display_name_brand_mismatch": "The sender's display name claims a brand or role that does not match the real sending domain (display-name spoofing).",
    "reply_to_domain_mismatch": "Replies would go to a different domain than the one the message came from.",
    "numeric_heavy_sender_domain": "The sender's domain contains a long run of digits, common in auto-generated abuse domains.",
    "fake_reply_thread": "The subject pretends to be a reply/forward but the message has no thread headers.",
    # Content
    "generic_greeting": "The message opens with a generic greeting ('Dear customer') instead of your name.",
    "excessive_exclamations": "Several exclamation marks - a pressure tactic.",
    "excessive_caps": "Multiple ALL-CAPS words, a common attention/pressure tactic.",
    "embedded_form": "The message embeds a form that could harvest what you type.",
}

_PREFIX = [
    ("lookalike_of_", "The domain is a near-copy of the well-known brand '{}' (typosquatting)."),
    ("brand_substring_", "The domain embeds the brand '{}' but is not that brand's real domain."),
    ("urgency_language_x", "Urgency or threat language was found ({} phrase(s)) - designed to make you act without thinking."),
    ("credential_request_language_x", "The message asks for credentials or sensitive details ({} phrase(s))."),
]

_AUTH_RE = re.compile(r"^(spf|dkim|dmarc)_(fail|softfail|not_evaluated)$")
_LAYER_RE = re.compile(r"^(?:URL|Header|Content):\s*")


def explain_indicator(indicator):
    code = _LAYER_RE.sub("", indicator or "")
    if code in _EXACT:
        return _EXACT[code]
    match = _AUTH_RE.match(code)
    if match:
        mech, result = match.group(1).upper(), match.group(2)
        if result == "not_evaluated":
            return f"No {mech} result was recorded, so the sender could not be verified."
        return f"{mech} authentication {result.replace('soft', 'soft-')}ed: the sending server is not authorised for the claimed domain."
    for prefix, template in _PREFIX:
        if code.startswith(prefix):
            return template.format(code[len(prefix):])
    return ""


def defang(value):
    """Make a URL/domain inert for display so nobody clicks it by accident."""
    value = (value or "").replace("http", "hxxp").replace("HTTP", "HXXP")
    return value.replace(".", "[.]")


# ---------------------------------------------------------------------------
# Presentation metadata: a short title, a severity and a category per indicator
# code. Used by the result page (evidence cards) and analytics; never affects scoring.
# ---------------------------------------------------------------------------
_TITLES = {
    "ip_literal_host": "Link points to a raw IP address",
    "punycode_domain": "Internationalised (punycode) domain",
    "suspicious_tld": "Link uses a high-abuse domain extension",
    "url_shortener": "Shortened link hides its destination",
    "no_tls": "Link is not encrypted (HTTP)",
    "excessive_hyphens": "Domain has unusually many hyphens",
    "excessively_long_url": "Unusually long URL",
    "userinfo_in_url": "Deceptive user@host link",
    "nonstandard_port": "Link uses a non-standard port",
    "open_redirect_parameter": "Link redirects to another site",
    "nested_url_in_url": "URL embedded inside a URL",
    "double_encoded_redirect": "Double-encoded redirect target",
    "redirect_to_suspicious_target": "Redirect leads to a suspicious site",
    "known_malicious_domain": "Domain is on the known-phishing list",
    "blocklisted_domain": "Domain is on the threat blocklist",
    "display_name_brand_mismatch": "Sender name impersonates a brand or role",
    "reply_to_domain_mismatch": "Sender / Reply-To mismatch",
    "numeric_heavy_sender_domain": "Sender domain contains many digits",
    "fake_reply_thread": "Fake reply/forward thread",
    "generic_greeting": "Generic greeting",
    "excessive_exclamations": "Excessive exclamation marks",
    "excessive_caps": "Excessive ALL-CAPS wording",
    "embedded_form": "Embedded data-entry form",
}
_SEVERITY = {
    "ip_literal_host": "high", "punycode_domain": "medium", "suspicious_tld": "medium", "url_shortener": "medium",
    "no_tls": "low", "excessive_hyphens": "low", "excessively_long_url": "low", "userinfo_in_url": "high",
    "nonstandard_port": "medium", "open_redirect_parameter": "high", "nested_url_in_url": "medium",
    "double_encoded_redirect": "medium", "redirect_to_suspicious_target": "high", "known_malicious_domain": "critical",
    "blocklisted_domain": "critical", "display_name_brand_mismatch": "high", "reply_to_domain_mismatch": "high",
    "numeric_heavy_sender_domain": "low", "fake_reply_thread": "low", "generic_greeting": "low",
    "excessive_exclamations": "low", "excessive_caps": "low", "embedded_form": "high",
}
_SENDER_CODES = {"display_name_brand_mismatch", "reply_to_domain_mismatch", "numeric_heavy_sender_domain"}
_AUTH_RE_FULL = re.compile(r"^(spf|dkim|dmarc)_(fail|softfail|not_evaluated)$")
_COUNT_RE = re.compile(r"^(urgency_language|credential_request_language)_x(\d+)$")


_BRANDS = {
    "paypal": "PayPal", "microsoft": "Microsoft", "apple": "Apple", "google": "Google", "amazon": "Amazon",
    "netflix": "Netflix", "bankofamerica": "Bank of America", "wellsfargo": "Wells Fargo",
    "americanexpress": "American Express", "dhl": "DHL", "auspost": "Australia Post", "commbank": "CommBank",
    "anz": "ANZ", "westpac": "Westpac", "nab": "NAB",
}


def brand_display(key):
    return _BRANDS.get((key or "").lower(), (key or "").title())


def strip_layer(indicator):
    return _LAYER_RE.sub("", indicator or "")


def indicator_title(indicator):
    code = strip_layer(indicator)
    if code in _TITLES:
        return _TITLES[code]
    auth = _AUTH_RE_FULL.match(code)
    if auth:
        mech, result = auth.group(1).upper(), auth.group(2)
        return f"{mech} not evaluated" if result == "not_evaluated" else f"{mech} authentication {result.replace('soft', 'soft-')}ed"
    if code.startswith("lookalike_of_"):
        return f"Look-alike of {brand_display(code[len('lookalike_of_'):])}"
    if code.startswith("brand_substring_"):
        return f"Possible {brand_display(code[len('brand_substring_'):])} impersonation"
    counted = _COUNT_RE.match(code)
    if counted:
        return "Urgency or threat language" if counted.group(1) == "urgency_language" else "Asks for credentials or sensitive data"
    return code.replace("_", " ").capitalize()


def indicator_severity(indicator):
    code = strip_layer(indicator)
    if code in _SEVERITY:
        return _SEVERITY[code]
    auth = _AUTH_RE_FULL.match(code)
    if auth:
        return {"fail": "high", "softfail": "medium", "not_evaluated": "low"}[auth.group(2)]
    if code.startswith(("lookalike_of_", "brand_substring_")):
        return "high"
    counted = _COUNT_RE.match(code)
    if counted:
        return "high" if (counted.group(1) == "credential_request_language" or int(counted.group(2)) >= 3) else "medium"
    return "low"


def indicator_category(indicator):
    """url | sender | authentication | header | content"""
    raw = indicator or ""
    code = strip_layer(raw)
    if raw.startswith("URL:"):
        return "url"
    if raw.startswith("Content:"):
        return "content"
    if code in _SENDER_CODES:
        return "sender"
    if _AUTH_RE_FULL.match(code):
        return "authentication"
    return "header"
