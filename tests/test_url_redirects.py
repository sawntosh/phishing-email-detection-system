from analysis.url_analysis import analyse_url, analyse_urls


def test_cross_domain_open_redirect_is_flagged_with_target():
    r = analyse_url("https://trusted.example.com/r?url=https://evil-login.top/steal")
    assert "open_redirect_parameter" in r["findings"]
    assert r["redirect_target"] == "https://evil-login.top/steal"


def test_same_domain_redirect_is_not_flagged():
    r = analyse_url("https://accounts.example.com/login?continue=https://mail.example.com/inbox")
    assert "open_redirect_parameter" not in r["findings"]
    assert r["redirect_target"] is None


def test_relative_next_parameter_is_not_flagged():
    r = analyse_url("https://company.com/login?next=/dashboard")
    assert r["findings"] == []


def test_double_encoded_redirect_target_is_decoded():
    r = analyse_url("https://trusted.example.com/r?redirect=https%253A%252F%252Fevil.top%252Fx")
    assert "open_redirect_parameter" in r["findings"]
    assert "double_encoded_redirect" in r["findings"]


def test_protocol_relative_redirect_target_is_flagged():
    r = analyse_url("https://trusted.example.com/r?u=//evil.top/x")
    assert "open_redirect_parameter" in r["findings"]
    assert r["redirect_target"].startswith("https://evil.top")


def test_redirect_to_lookalike_domain_is_escalated():
    r = analyse_url("https://docs.example.com/url?q=https://paypa1-login.top/verify")
    assert "open_redirect_parameter" in r["findings"]
    assert "redirect_to_suspicious_target" in r["findings"]


def test_userinfo_trick_is_flagged():
    r = analyse_url("http://paypal.com@evil-host.top/login")
    assert "userinfo_in_url" in r["findings"]
    assert r["host"] == "evil-host.top"


def test_url_embedded_in_path_is_flagged_as_nested():
    r = analyse_url("https://good.example.com/redirect/http://evil.top/x")
    assert "nested_url_in_url" in r["findings"]


def test_nonstandard_port_is_flagged_but_default_ports_are_not():
    assert "nonstandard_port" in analyse_url("http://host.example.com:8081/x")["findings"]
    assert "nonstandard_port" not in analyse_url("https://host.example.com:443/x")["findings"]


def test_redirect_findings_add_meaningful_risk_points():
    r = analyse_url("https://trusted.example.com/r?url=https://evil-login.top/steal")
    assert r["risk_points"] >= 10
    assert analyse_urls("see https://trusted.example.com/r?url=https://evil-login.top/steal")["risk_points"] >= 10
