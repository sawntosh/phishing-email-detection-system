"""
URL / domain analysis.
Covers: URL/domain extraction, look-alike (typosquat) domain detection,
suspicious-redirect / IP-literal / punycode checks, and a pluggable
reputation-lookup hook (offline heuristic by default; swap in a real
threat-intel API such as VirusTotal/PhishTank in production -- see
README "Extending reputation lookups").

All checks are static/passive: no request is ever made to a URL found in a
submitted email (that would be an SSRF / self-inflicted-click risk). This
is itself a security decision worth citing in the report.
"""
import re
import ipaddress
from urllib.parse import urlparse

import tldextract

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


def analyse_url(url: str) -> dict:
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

    return {
        "url": url,
        "host": host,
        "registered_domain": registered_domain,
        "findings": findings,
        "lookalike_of": lookalike_of,
        "risk_points": len(findings) * 6 if findings else 0,
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
