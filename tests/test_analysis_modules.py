from analysis.url_analysis import analyse_urls, analyse_url, check_reputation
from analysis.header_analysis import analyse_headers
from analysis.content_analysis import analyse_content


def test_lookalike_domain_detected():
    r = analyse_url("http://paypa1-secure.com/verify")
    impersonation_findings = [f for f in r["findings"] if f.startswith("lookalike_of_") or f.startswith("brand_substring_")]
    assert impersonation_findings, f"expected an impersonation finding, got {r['findings']}"
    assert "paypal" in impersonation_findings[0]


def test_ip_literal_url_flagged():
    r = analyse_url("http://192.168.1.10/login")
    assert "ip_literal_host" in r["findings"]


def test_legitimate_url_has_low_risk():
    r = analyse_url("https://company.com/portal/notes")
    assert r["risk_points"] == 0


def test_open_redirect_parameter_flagged():
    r = analyse_url("https://trusted-mailer.com/click?redirect=https://evil-xyz.top/login")
    assert "open_redirect_parameter" in r["findings"]


def test_open_redirect_ignores_benign_query_values():
    r = analyse_url("https://company.com/search?redirect=thanks-page")
    assert "open_redirect_parameter" not in r["findings"]


def test_nested_url_in_url_flagged():
    r = analyse_url("https://trusted-mailer.com/go?next=http://evil-xyz.top/login")
    assert "nested_url_in_url" in r["findings"]


def test_known_malicious_domain_flagged_via_reputation():
    r = analyse_url("https://totally-not-paypal.ru/verify")
    assert "known_malicious_domain" in r["findings"]
    assert r["reputation"]["verdict"] == "known_malicious"
    assert r["risk_points"] > 0


def test_known_safe_domain_has_no_reputation_penalty():
    result = check_reputation("paypal.com", "paypal.com")
    assert result["verdict"] == "known_safe"
    assert result["risk_points"] == 0


def test_unknown_domain_reputation_is_neutral():
    result = check_reputation("some-random-company.com", "some-random-company.com")
    assert result["verdict"] == "unknown"
    assert result["risk_points"] == 0


def test_analyse_urls_counts_unique_domains():
    text = "Visit http://company.com/a and http://company.com/b and http://evil-xyz.top/c"
    report = analyse_urls(text)
    assert report["url_count"] == 3
    assert report["unique_domains"] == 2


def test_spf_dkim_dmarc_fail_raises_header_risk():
    headers = {"Authentication-Results": "spf=fail smtp.mailfrom=x.com; dkim=fail; dmarc=fail"}
    report = analyse_headers(headers, '"PayPal Support" <sec@totally-not-paypal.ru>', "hi")
    assert report["spf"] == "fail"
    assert "display_name_brand_mismatch" in report["findings"]
    assert report["risk_points"] > 30


def test_clean_headers_have_low_risk():
    headers = {"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass"}
    report = analyse_headers(headers, '"Jordan Lee" <jordan@company.com>', "hello")
    assert report["risk_points"] == 0


def test_urgency_and_credential_language_detected():
    report = analyse_content("Urgent: Verify your account now", "Your account will be suspended, click here to verify your password immediately!!!")
    assert report["urgency_hits"] > 0
    assert report["credential_hits"] > 0
    assert report["risk_points"] > 0


def test_benign_content_has_low_risk():
    report = analyse_content("Lunch on Friday?", "Hey, are you free for lunch on Friday around 12:30?")
    assert report["risk_points"] == 0
