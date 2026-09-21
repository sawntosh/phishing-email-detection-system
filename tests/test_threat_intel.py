import pytest

from analysis import threat_intel
from analysis.threat_intel import ThreatIntelError, UnsafeTarget
from analysis.url_analysis import analyse_url


# ---------------------------------------------------------------- blocklist
def _write_blocklist(tmp_path, monkeypatch, lines):
    path = tmp_path / "blocklist.txt"
    path.write_text("\n".join(lines), encoding="utf-8")
    monkeypatch.setenv("THREAT_BLOCKLIST_PATH", str(path))


def test_blocklist_matches_domain_subdomain_and_url_entries(tmp_path, monkeypatch):
    _write_blocklist(tmp_path, monkeypatch, [
        "# comment", "", "evil-bank.top", "https://phish.example.org/login.php", "*.wild.click", "not a domain!!",
    ])
    assert threat_intel.is_blocklisted("evil-bank.top", "evil-bank.top")
    assert threat_intel.is_blocklisted("login.evil-bank.top", "evil-bank.top")
    assert threat_intel.is_blocklisted("phish.example.org", "example.org")
    assert threat_intel.is_blocklisted("x.wild.click", "wild.click")
    assert not threat_intel.is_blocklisted("example.org", "example.org")
    assert not threat_intel.is_blocklisted("good.com", "good.com")


def test_missing_blocklist_file_is_harmless():
    assert threat_intel.is_blocklisted("anything.com", "anything.com") is False


def test_blocklisted_domain_is_flagged_with_heavy_points(tmp_path, monkeypatch):
    _write_blocklist(tmp_path, monkeypatch, ["known-bad.top"])
    r = analyse_url("https://portal.known-bad.top/login")
    assert "blocklisted_domain" in r["findings"]
    assert r["risk_points"] >= 30


def test_blocklist_reloads_when_the_file_changes(tmp_path, monkeypatch):
    import os
    _write_blocklist(tmp_path, monkeypatch, ["first-bad.top"])
    assert threat_intel.is_blocklisted("first-bad.top", "first-bad.top")
    path = tmp_path / "blocklist.txt"
    path.write_text("second-bad.top\n", encoding="utf-8")
    os.utime(path, (path.stat().st_atime + 10, path.stat().st_mtime + 10))
    assert threat_intel.is_blocklisted("second-bad.top", "second-bad.top")
    assert not threat_intel.is_blocklisted("first-bad.top", "first-bad.top")


# ------------------------------------------------------------- VirusTotal
def _vt(status, stats=None):
    payload = {"data": {"attributes": {"last_analysis_stats": stats, "reputation": -5}}} if stats is not None else {}
    return lambda url, key, *a, **k: (status, payload)


def test_lookup_domain_verdicts():
    bad = threat_intel.lookup_domain("evil.top", "k", _vt(200, {"malicious": 7, "suspicious": 0, "harmless": 60, "undetected": 5}))
    assert bad["verdict"] == "malicious" and bad["malicious"] == 7
    warn = threat_intel.lookup_domain("meh.top", "k", _vt(200, {"malicious": 1, "harmless": 70}))
    assert warn["verdict"] == "suspicious"
    ok = threat_intel.lookup_domain("good.com", "k", _vt(200, {"malicious": 0, "harmless": 70}))
    assert ok["verdict"] == "clean"
    unknown = threat_intel.lookup_domain("new.top", "k", _vt(404))
    assert unknown["verdict"] == "unknown"


def test_lookup_raises_on_auth_and_rate_limit_errors():
    with pytest.raises(ThreatIntelError, match="API key"):
        threat_intel.lookup_domain("evil.top", "k", _vt(401))
    with pytest.raises(ThreatIntelError, match="rate limit"):
        threat_intel.lookup_domain("evil.top", "k", _vt(429))
    with pytest.raises(ThreatIntelError, match="HTTP 500"):
        threat_intel.lookup_domain("evil.top", "k", _vt(500))


@pytest.mark.parametrize("bad_domain", [
    "evil.top/../../users", "evil.top?x=1", "a b.com", "evil.top#frag", "", "localhost", "http://evil.top",
    "evil.top:8080", "user@evil.top", "-bad-.com",
])
def test_lookup_domain_rejects_anything_that_is_not_a_plain_domain(bad_domain):
    called = []
    with pytest.raises(ThreatIntelError):
        threat_intel.lookup_domain(bad_domain, "k", lambda *a, **k: called.append(a) or (200, {}))
    assert called == []  # no request was ever attempted


def test_lookup_file_hash_validates_and_queries_files_endpoint():
    seen = []
    def fake(url, key, *a, **k):
        seen.append(url)
        return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 1}}}}
    digest = "a" * 64
    assert threat_intel.lookup_file_hash(digest, "k", fake)["verdict"] == "malicious"
    assert seen == [f"{threat_intel.VT_BASE}/files/{digest}"]
    for bad in ("abc", "g" * 64, "../etc/passwd", digest + "/x"):
        with pytest.raises(ThreatIntelError):
            threat_intel.lookup_file_hash(bad, "k", fake)


def test_http_client_refuses_non_virustotal_urls():
    with pytest.raises(ThreatIntelError, match="non-VirusTotal"):
        threat_intel._http_get_json("http://169.254.169.254/latest/meta-data", "k")
    with pytest.raises(ThreatIntelError, match="non-VirusTotal"):
        threat_intel._http_get_json("https://evil.example/api/v3/domains/x.com", "k")


# ------------------------------------------------------- redirect resolver
def _resolver(mapping):
    def resolve(host, port, type=0):
        if host not in mapping:
            raise OSError("no such host")
        return [(2, 1, 6, "", (mapping[host], port))]
    return resolve


def _fetcher(routes):
    calls = []
    def fetch(url, ip, timeout):
        calls.append((url, ip))
        return routes[url]
    fetch.calls = calls
    return fetch


def test_public_ip_classification():
    for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert threat_intel._is_public_ip(ip)
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "169.254.169.254", "::1", "fe80::1",
               "::ffff:127.0.0.1", "::ffff:10.0.0.1", "100.64.0.1", "0.0.0.0", "not-an-ip"):
        assert not threat_intel._is_public_ip(ip), ip


def test_redirect_chain_is_followed_and_reported():
    fetch = _fetcher({
        "https://short.example/a": (301, "https://mid.example/b"),
        "https://mid.example/b": (302, "/final"),
        "https://mid.example/final": (200, ""),
    })
    result = threat_intel.resolve_redirect_chain(
        "https://short.example/a", resolver=_resolver({"short.example": "8.8.8.8", "mid.example": "1.1.1.1"}), fetch=fetch)
    assert [h["status"] for h in result["chain"]] == [301, 302, 200]
    assert result["final_url"] == "https://mid.example/final"
    assert result["hops"] == 2 and result["truncated"] is False
    assert [ip for _, ip in fetch.calls] == ["8.8.8.8", "1.1.1.1", "1.1.1.1"]  # connects to the validated IPs


def test_resolver_refuses_private_first_hop_without_connecting():
    fetch = _fetcher({})
    with pytest.raises(UnsafeTarget):
        threat_intel.resolve_redirect_chain("http://internal.example/", resolver=_resolver({"internal.example": "10.0.0.7"}), fetch=fetch)
    assert fetch.calls == []


def test_resolver_refuses_redirect_into_internal_network():
    fetch = _fetcher({"https://ok.example/": (302, "http://metadata.internal/latest")})
    resolver = _resolver({"ok.example": "8.8.8.8", "metadata.internal": "169.254.169.254"})
    with pytest.raises(UnsafeTarget):
        threat_intel.resolve_redirect_chain("https://ok.example/", resolver=resolver, fetch=fetch)
    assert len(fetch.calls) == 1  # the second hop was never contacted


def test_resolver_refuses_if_any_dns_answer_is_private():
    def resolver(host, port, type=0):
        return [(2, 1, 6, "", ("8.8.8.8", port)), (2, 1, 6, "", ("127.0.0.1", port))]
    with pytest.raises(UnsafeTarget):
        threat_intel.resolve_redirect_chain("https://rebind.example/", resolver=resolver, fetch=_fetcher({}))


@pytest.mark.parametrize("url", ["ftp://x.example/", "file:///etc/passwd", "gopher://x.example/", "https:///nohost",
                                 "http://x.example:22/", "http://x.example:8080/", "javascript:alert(1)"])
def test_resolver_refuses_unsafe_schemes_and_ports(url):
    with pytest.raises(UnsafeTarget):
        threat_intel.resolve_redirect_chain(url, resolver=_resolver({"x.example": "8.8.8.8"}), fetch=_fetcher({}))


def test_resolver_caps_hops_and_marks_truncated():
    routes = {f"https://loop.example/{i}": (302, f"https://loop.example/{i + 1}") for i in range(20)}
    fetch = _fetcher(routes)
    result = threat_intel.resolve_redirect_chain(
        "https://loop.example/0", resolver=_resolver({"loop.example": "8.8.8.8"}), fetch=fetch, max_hops=3)
    assert result["truncated"] is True
    assert len(fetch.calls) == 4  # initial request + 3 redirects, then stop


def test_resolver_reports_dns_failure_cleanly():
    with pytest.raises(ThreatIntelError, match="DNS lookup failed"):
        threat_intel.resolve_redirect_chain("https://nxdomain.example/", resolver=_resolver({}), fetch=_fetcher({}))
