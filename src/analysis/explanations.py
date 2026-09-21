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
