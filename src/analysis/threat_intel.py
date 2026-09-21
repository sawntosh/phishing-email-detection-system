"""
Threat-intelligence and redirect-chain checks.

Design rules (see docs/threat_model.md):
  * Ingestion NEVER makes a network request driven by email content. The only
    thing done at ingest time is an OFFLINE lookup in a local blocklist file.
  * Everything that touches the network is analyst-triggered, audited and
    rate-limited by the caller (detector/routes.py).
  * VirusTotal requests go to a fixed https host; only a strictly validated
    domain name or SHA-256 hex digest is ever placed in the URL path, so an
    attacker cannot steer the request (no SSRF / path injection).
  * The redirect resolver refuses any hop whose DNS answer is not a public
    global address, connects to the address it validated (no DNS-rebinding
    gap), sends HEAD only, caps hops and time, and never reads a body.
"""
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import quote, urljoin, urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_BLOCKLIST_PATH = os.path.join(BASE_DIR, "instance", "threat_intel", "blocklist.txt")

VT_BASE = "https://www.virustotal.com/api/v3"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

MAX_REDIRECT_HOPS = 5
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class ThreatIntelError(Exception):
    """Any failure of an external lookup; message is safe to show an analyst."""


# --------------------------------------------------------------------------
# Offline blocklist (safe to call on every ingest)
# --------------------------------------------------------------------------
_blocklist_cache = {"path": None, "mtime": None, "domains": frozenset()}


def blocklist_path():
    return os.environ.get("THREAT_BLOCKLIST_PATH") or DEFAULT_BLOCKLIST_PATH


def _clean_blocklist_line(line):
    line = line.strip().lower()
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        line = urlparse(line).hostname or ""
    line = line.split("#")[0].strip().lstrip("*.").rstrip(".")
    return line if DOMAIN_RE.match(line) else None


def load_blocklist():
    path = blocklist_path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _blocklist_cache.update(path=path, mtime=None, domains=frozenset())
        return _blocklist_cache["domains"]
    if _blocklist_cache["path"] == path and _blocklist_cache["mtime"] == mtime:
        return _blocklist_cache["domains"]
    domains = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            cleaned = _clean_blocklist_line(raw)
            if cleaned:
                domains.add(cleaned)
    _blocklist_cache.update(path=path, mtime=mtime, domains=frozenset(domains))
    return _blocklist_cache["domains"]


def is_blocklisted(host, registered_domain=""):
    """True if the host, its registered domain, or any parent domain is listed."""
    domains = load_blocklist()
    if not domains:
        return False
    host = (host or "").lower().rstrip(".")
    if registered_domain and registered_domain.lower() in domains:
        return True
    labels = host.split(".")
    return any(".".join(labels[i:]) in domains for i in range(len(labels) - 1))


# --------------------------------------------------------------------------
# VirusTotal (analyst-triggered)
# --------------------------------------------------------------------------
def _http_get_json(url, api_key, timeout=8):
    if not url.startswith(VT_BASE + "/"):
        raise ThreatIntelError("refusing to call a non-VirusTotal URL")
    # Safe: the startswith() guard above pins scheme and host to VT_BASE (https).
    req = urllib.request.Request(  # noqa: S310
        url, headers={"x-apikey": api_key, "Accept": "application/json", "User-Agent": "PhishDetect/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return resp.status, json.loads(resp.read(2_000_000))
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise ThreatIntelError(f"could not reach VirusTotal: {exc}") from exc


def _summarise_vt(status, payload):
    if status == 404:
        return {"verdict": "unknown", "detail": "not known to VirusTotal"}
    if status in (401, 403):
        raise ThreatIntelError("VirusTotal rejected the API key")
    if status == 429:
        raise ThreatIntelError("VirusTotal rate limit reached; try again later")
    if status != 200:
        raise ThreatIntelError(f"VirusTotal returned HTTP {status}")

    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    if malicious + suspicious + harmless + undetected == 0:
        verdict = "unknown"
    elif malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {
        "verdict": verdict, "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected, "reputation": attrs.get("reputation"),
    }


def lookup_domain(domain, api_key, http_get=_http_get_json):
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ThreatIntelError("not a valid domain name")
    status, payload = http_get(f"{VT_BASE}/domains/{domain}", api_key)
    return _summarise_vt(status, payload)


def lookup_file_hash(sha256, api_key, http_get=_http_get_json):
    sha256 = (sha256 or "").strip().lower()
    if not SHA256_RE.match(sha256):
        raise ThreatIntelError("not a valid SHA-256 digest")
    status, payload = http_get(f"{VT_BASE}/files/{sha256}", api_key)
    return _summarise_vt(status, payload)


# --------------------------------------------------------------------------
# Redirect-chain resolver (analyst-triggered, off unless enabled in config)
# --------------------------------------------------------------------------
class UnsafeTarget(ThreatIntelError):
    pass


def _is_public_ip(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def _resolve_public(host, port, resolver=socket.getaddrinfo):
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ThreatIntelError(f"DNS lookup failed for {host}") from exc
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise ThreatIntelError(f"no address for {host}")
    if not all(_is_public_ip(a) for a in addresses):
        raise UnsafeTarget(f"{host} resolves to a non-public address; not contacted")
    return addresses[0]


def _fetch_head(url, ip, timeout=5):
    """HEAD request to an already-validated IP. Returns (status, location)."""
    parsed = urlparse(url)
    host = parsed.hostname
    https = parsed.scheme == "https"
    port = parsed.port or (443 if https else 80)
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=~-._")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="/%:@!$&'()*+,;=~-._?")

    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        if https:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        request = (
            f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: PhishDetect-RedirectCheck/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii", "ignore"))
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()

    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    match = re.match(r"HTTP/\d\.\d\s+(\d{3})", head[0]) if head else None
    if not match:
        raise ThreatIntelError("unexpected response while following redirect")
    location = ""
    for line in head[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "location":
            location = value.strip()
            break
    return int(match.group(1)), location


def resolve_redirect_chain(url, resolver=socket.getaddrinfo, fetch=_fetch_head,
                           max_hops=MAX_REDIRECT_HOPS, timeout=5):
    chain = []
    current = url
    truncated = False
    for hop in range(max_hops + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise UnsafeTarget("only http/https URLs with a hostname can be followed")
        try:
            port = parsed.port
        except ValueError as exc:
            raise UnsafeTarget("invalid port") from exc
        if port not in (None, 80, 443):
            raise UnsafeTarget("non-standard port; not contacted")
        ip = _resolve_public(parsed.hostname, port or (443 if parsed.scheme == "https" else 80), resolver)
        status, location = fetch(current, ip, timeout)
        chain.append({"url": current, "status": status})
        if status in REDIRECT_STATUSES and location:
            if hop == max_hops:
                truncated = True
                break
            current = urljoin(current, location)
            continue
        break
    return {"chain": chain, "final_url": chain[-1]["url"], "truncated": truncated, "hops": len(chain) - 1}
