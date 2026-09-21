"""
URL / domain analysis.
Covers: URL/domain extraction, look-alike (typosquat) domain detection,
suspicious-redirect checks (open-redirect parameters, nested/double-encoded
URLs, userinfo tricks, shorteners), IP-literal/punycode checks, and OFFLINE
reputation checks (a small built-in list plus an operator-maintained blocklist
file, see analysis/threat_intel.py).

All checks here are static/passive: no request is ever made to a URL found in
a submitted email during ingestion (that would be an SSRF / self-inflicted-
click risk). Live reputation and redirect-chain lookups exist, but only as
explicit, audited, analyst-triggered actions -- see threat_intel.py.
"""
import re
import ipaddress
from urllib.parse import urlparse, parse_qsl, unquote

import tldextract

from analysis import threat_intel

# Offline-safe extractor: never fetches the public suffix list over the
# network at analysis time (a live email/URL analysis tool must not make
# outbound calls driven by attacker-controlled input). Falls back to the
# bundled snapshot shipped with the tldextract package.
_extract = tldextract.TLDExtract(suffix_list_urls=())

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# A small set of frequently-impersonated brands for look-alike detection.
# In production this would be a maintained, larger reference list.
PROTECTED_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "bankofamerica", "wellsfargo", "americanexpress", "dhl", "auspost",
    "commbank", "anz", "westpac", "nab",
]

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "click", "link"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

# Query-parameter names commonly abused for open-redirect phishing (bounce
# through a trusted domain to an attacker-controlled destination).
REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirecturl", "redirect_uri", "redirect_url", "redir",
    "next", "continue", "return", "returnurl", "return_url", "return_to",
    "target", "dest", "destination", "go", "goto", "link", "out", "to",
    "u", "r", "q",
}
_REDIRECT_VALUE_RE = re.compile(r"^(?:https?:)?//([^/\s?#]+)", re.IGNORECASE)

# Small illustrative offline reputation lists checked locally -- no live
# network request is made (see module docstring). Swap `check_reputation`
# for a real threat-intel API (VirusTotal/PhishTank/Google Safe Browsing)
# behind an explicit, analyst-triggered, audit-logged action; never call
# one automatically during ingestion of attacker-controlled input.
KNOWN_MALICIOUS_DOMAINS = {
    "totally-not-paypal.ru", "paypa1-secure.com", "secure-appleid-verify.com",
    "account-verify-update.com", "signin-update-security.com",
}
KNOWN_SAFE_DOMAINS = {
    "paypal.com", "microsoft.com", "apple.com", "google.com", "amazon.com",
    "github.com", "wikipedia.org",
}

# Points per finding (default 6). Stronger signals are weighted higher.
# known_malicious_domain is scored separately through check_reputation().
FINDING_POINTS = {
    "open_redirect_parameter": 10,
    "redirect_to_suspicious_target": 12,
    "userinfo_in_url": 12,
    "blocklisted_domain": 30,
}

# Common leetspeak/homoglyph substitutions used in typosquatted domains
# (e.g. "paypa1" for "paypal", "micr0soft" for "microsoft").
_LEET_MAP = str.maketrans({"1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def _normalise_domain_label(label: str) -> str:
    return label.translate(_LEET_MAP).replace("-", "")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def extract_urls(text: str):
    return list(dict.fromkeys(URL_RE.findall(text or "")))


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def _find_redirect_target(parsed, own_registered_domain):
    """Return the full URL a redirect-style parameter points at, if it leaves the
    link's own registered domain (e.g. https://good.com/r?url=https://evil.com).
    Same-domain redirects (a login page sending you back to the same site) are
    ignored so they do not raise false alarms."""
    for key, value in parse_qsl(parsed.query, keep_blank_values=False):
        if key.lower() not in REDIRECT_PARAM_NAMES:
            continue
        candidate = unquote(value).strip()  # second decode handles double-encoded targets
        match = _REDIRECT_VALUE_RE.match(candidate)
        if not match:
            continue
        target_host = match.group(1).rsplit("@", 1)[-1].split(":")[0].lower()
        target_registered = (_extract(target_host).registered_domain or target_host).lower()
        if target_host and target_registered != own_registered_domain:
            return candidate if candidate.lower().startswith("http") else "https:" + candidate
    return None


def _check_redirect_indicators(url: str, parsed, own_registered_domain: str):
    """Static/passive open-redirect and nested-URL detection. Never follows the
    URL -- only inspects its own text, so it stays safe to run on fully
    attacker-controlled input. Returns (findings, redirect_target_url_or_None)."""
    findings = []

    redirect_target = _find_redirect_target(parsed, own_registered_domain)
    if redirect_target:
        findings.append("open_redirect_parameter")

    if url.lower().count("http://") + url.lower().count("https://") > 1:
        findings.append("nested_url_in_url")

    lowered_query = parsed.query.lower()
    if "%2f%2f" in lowered_query or "%253a%252f%252f" in lowered_query:
        findings.append("double_encoded_redirect")

    return findings, redirect_target


def check_reputation(registered_domain: str, host: str) -> dict:
    """Offline/static reputation lookup against a small local
    allow/deny list -- no live network request is made (see module
    docstring). This is the pluggable hook described in the assessment
    brief's "reputation/threat-intelligence lookup" requirement; swap the
    body for a real API call gated behind an explicit analyst action."""
    candidates = {registered_domain, host} - {""}
    if candidates & KNOWN_MALICIOUS_DOMAINS:
        return {"verdict": "known_malicious", "source": "local_denylist", "risk_points": 35}
    if candidates & KNOWN_SAFE_DOMAINS:
        return {"verdict": "known_safe", "source": "local_allowlist", "risk_points": 0}
    return {"verdict": "unknown", "source": "local_lists", "risk_points": 0}


def analyse_url(url: str, _depth: int = 0) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = _extract(url)
    registered_domain = ext.registered_domain.lower() if ext.registered_domain else host

    findings = []
    lookalike_of = None

    if _is_ip_literal(host):
        findings.append("ip_literal_host")
    if _is_punycode(host):
        findings.append("punycode_domain")
    if ext.suffix and ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        findings.append("suspicious_tld")
    if registered_domain in URL_SHORTENERS or host in URL_SHORTENERS:
        findings.append("url_shortener")
    if parsed.scheme == "http":
        findings.append("no_tls")
    if host.count("-") >= 3:
        findings.append("excessive_hyphens")
    if len(url) > 120:
        findings.append("excessively_long_url")

    # "http://paypal.com@evil.com/" -- everything before '@' is decoration, the real host is evil.com
    if "@" in parsed.netloc:
        findings.append("userinfo_in_url")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port not in (None, 80, 443):
        findings.append("nonstandard_port")

    redirect_findings, redirect_target = _check_redirect_indicators(url, parsed, registered_domain)
    findings.extend(redirect_findings)
    if redirect_target and _depth == 0:
        inner = analyse_url(redirect_target, _depth=1)
        if any(f != "no_tls" for f in inner["findings"]):
            findings.append("redirect_to_suspicious_target")

    reputation = check_reputation(registered_domain, host)
    if reputation["verdict"] == "known_malicious":
        findings.append("known_malicious_domain")
    elif threat_intel.is_blocklisted(host, registered_domain):
        findings.append("blocklisted_domain")

    domain_label = ext.domain.lower() if ext.domain else ""
    normalised_label = _normalise_domain_label(domain_label)
    for brand in PROTECTED_BRANDS:
        if domain_label == brand:
            break
        if brand in normalised_label and normalised_label != brand:
            findings.append(f"brand_substring_{brand}")
            lookalike_of = brand
            break
        dist = _levenshtein(normalised_label, brand)
        if 0 < dist <= 2 and abs(len(normalised_label) - len(brand)) <= 2:
            findings.append(f"lookalike_of_{brand}")
            lookalike_of = brand
            break

    scored = [f for f in findings if f != "known_malicious_domain"]
    risk_points = sum(FINDING_POINTS.get(f, 6) for f in scored) + reputation["risk_points"]

    return {
        "url": url,
        "host": host,
        "registered_domain": registered_domain,
        "findings": findings,
        "lookalike_of": lookalike_of,
        "redirect_target": redirect_target,
        "reputation": reputation,
        "risk_points": risk_points,
    }


def analyse_urls(text: str) -> dict:
    urls = extract_urls(text)
    results = [analyse_url(u) for u in urls]
    total_points = sum(r["risk_points"] for r in results)
    return {
        "url_count": len(urls),
        "unique_domains": len({r["registered_domain"] for r in results}),
        "results": results,
        "risk_points": min(total_points, 40),  # cap this category's contribution
    }
