"""
Single source of truth for the numeric feature vector used by the ML
classifier. Both train_model.py and ml_classifier.py import this so the
model is always trained and scored on identically-derived features --
a common source of silent train/serve skew bugs in ML pipelines, avoided
here deliberately.
"""
from analysis.url_analysis import analyse_urls
from analysis.header_analysis import analyse_headers
from analysis.content_analysis import analyse_content

FEATURE_NAMES = [
    "url_count",
    "unique_domains",
    "has_ip_literal_url",
    "has_lookalike_domain",
    "has_url_shortener",
    "has_punycode_domain",
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "auth_not_evaluated_count",
    "display_name_mismatch",
    "reply_to_mismatch",
    "urgency_hits",
    "credential_hits",
    "generic_greeting",
    "exclamation_count",
    "all_caps_words",
    "has_html_form",
    "body_length",
    "attachment_count",
]


def extract_feature_dict(subject, body_text, sender_raw, raw_headers, attachment_count=0):
    url_report = analyse_urls(body_text)
    header_report = analyse_headers(raw_headers, sender_raw, subject)
    content_report = analyse_content(subject, body_text)

    url_findings_flat = [f for r in url_report["results"] for f in r["findings"]]

    return {
        "url_count": url_report["url_count"],
        "unique_domains": url_report["unique_domains"],
        "has_ip_literal_url": int("ip_literal_host" in url_findings_flat),
        "has_lookalike_domain": int(any(f.startswith("lookalike_of_") or f.startswith("brand_substring_") for f in url_findings_flat)),
        "has_url_shortener": int("url_shortener" in url_findings_flat),
        "has_punycode_domain": int("punycode_domain" in url_findings_flat),
        "spf_fail": int(header_report["spf"] in ("fail", "softfail")),
        "dkim_fail": int(header_report["dkim"] in ("fail", "softfail")),
        "dmarc_fail": int(header_report["dmarc"] in ("fail", "softfail")),
        "auth_not_evaluated_count": sum(1 for m in ("spf", "dkim", "dmarc") if header_report[m] == "not_evaluated" or header_report[m] == "none"),
        "display_name_mismatch": int("display_name_brand_mismatch" in header_report["findings"]),
        "reply_to_mismatch": int("reply_to_domain_mismatch" in header_report["findings"]),
        "urgency_hits": content_report["urgency_hits"],
        "credential_hits": content_report["credential_hits"],
        "generic_greeting": int(content_report["generic_greeting"]),
        "exclamation_count": content_report["exclamation_count"],
        "all_caps_words": content_report["all_caps_words"],
        "has_html_form": int(content_report["has_html_form"]),
        "body_length": len(body_text or ""),
        "attachment_count": attachment_count,
    }, url_report, header_report, content_report


def feature_dict_to_vector(feature_dict):
    return [feature_dict[name] for name in FEATURE_NAMES]
