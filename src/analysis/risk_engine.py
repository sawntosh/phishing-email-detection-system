"""
Hybrid risk engine: combines the rule-based indicator score (url + header
+ content modules) with the ML probability into one 0-100 risk score and
a human-readable explanation, per the "Content/keyword/structure analysis
with risk scoring and human-readable explanations" + "Hybrid detection
using rules plus an ML classifier" + "Explainability view" requirements.
"""
from analysis.url_analysis import analyse_urls
from analysis.header_analysis import analyse_headers
from analysis.content_analysis import analyse_content
from analysis.features import extract_feature_dict
from analysis.ml_classifier import classify

# Weights: rules are capped at 100 combined; ML probability is blended in.
RULE_WEIGHT = 0.55
ML_WEIGHT = 0.45


def score_email(subject, body_text, sender_raw, raw_headers, attachment_count=0):
    url_report = analyse_urls(body_text)
    header_report = analyse_headers(raw_headers, sender_raw, subject)
    content_report = analyse_content(subject, body_text)

    rule_points = url_report["risk_points"] + header_report["risk_points"] + content_report["risk_points"]
    rule_score_pct = min(rule_points, 100)

    feature_dict, _, _, _ = extract_feature_dict(subject, body_text, sender_raw, raw_headers, attachment_count)
    ml_probability, ml_explanation = classify(feature_dict)

    combined = RULE_WEIGHT * rule_score_pct + ML_WEIGHT * (ml_probability * 100)
    combined = round(min(max(combined, 0), 100), 1)

    if combined >= 70:
        verdict = "phishing"
    elif combined >= 35:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    all_rule_indicators = (
        [f"URL: {f}" for r in url_report["results"] for f in r["findings"]]
        + [f"Header: {f}" for f in header_report["findings"]]
        + [f"Content: {f}" for f in content_report["findings"]]
    )

    return {
        "risk_score": combined,
        "verdict": verdict,
        "rule_score_pct": rule_score_pct,
        "ml_probability": round(ml_probability, 4),
        "rule_indicators": all_rule_indicators,
        "ml_explanation": ml_explanation,
        "url_report": url_report,
        "header_report": header_report,
        "content_report": content_report,
    }
