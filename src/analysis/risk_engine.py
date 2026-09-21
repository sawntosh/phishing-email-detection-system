"""
Hybrid risk engine: combines the rule-based indicator score (url + header
+ content modules) with two ML signals into one 0-100 risk score and a
human-readable explanation:

  * text model        -- TF-IDF + Logistic Regression trained on a real phishing corpus
  * structured model  -- Logistic Regression over URL/header/content features

If no text model has been trained yet the engine degrades gracefully to
rules + structured model instead of failing.
"""
from analysis.url_analysis import analyse_urls
from analysis.header_analysis import analyse_headers
from analysis.content_analysis import analyse_content
from analysis.features import extract_feature_dict
from analysis.ml_classifier import classify
from analysis.text_model import get_text_model

# Rules and ML each contribute half of the final score.
RULE_WEIGHT = 0.5
ML_WEIGHT = 0.5
# Inside the ML half, the real-corpus text model gets the larger share.
TEXT_SHARE = 0.65

PHISHING_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30


def score_email(subject, body_text, sender_raw, raw_headers, attachment_count=0):
    url_report = analyse_urls(body_text)
    header_report = analyse_headers(raw_headers, sender_raw, subject)
    content_report = analyse_content(subject, body_text)

    rule_points = url_report["risk_points"] + header_report["risk_points"] + content_report["risk_points"]
    rule_score_pct = min(rule_points, 100)

    feature_dict, _, _, _ = extract_feature_dict(subject, body_text, sender_raw, raw_headers, attachment_count)
    structured_prob, structured_expl = classify(feature_dict)
    ml_explanation = [dict(item, source="structured") for item in structured_expl]

    text_model = get_text_model()
    text_prob = None
    if text_model is not None:
        text = f"{subject or ''}\n{body_text or ''}"
        text_prob = text_model.predict_proba(text)
        ml_explanation += text_model.explain(text)
        ml_probability = TEXT_SHARE * text_prob + (1 - TEXT_SHARE) * structured_prob
    else:
        ml_probability = structured_prob

    combined = RULE_WEIGHT * rule_score_pct + ML_WEIGHT * (ml_probability * 100)
    combined = round(min(max(combined, 0), 100), 1)

    if combined >= PHISHING_THRESHOLD:
        verdict = "phishing"
    elif combined >= SUSPICIOUS_THRESHOLD:
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
        "structured_probability": round(structured_prob, 4),
        "text_probability": round(text_prob, 4) if text_prob is not None else None,
        "rule_indicators": all_rule_indicators,
        "ml_explanation": ml_explanation,
        "url_report": url_report,
        "header_report": header_report,
        "content_report": content_report,
    }
