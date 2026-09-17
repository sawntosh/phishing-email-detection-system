from analysis.risk_engine import score_email

PHISH_HEADERS = {"Authentication-Results": "spf=fail; dkim=fail; dmarc=fail"}
LEGIT_HEADERS = {"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass"}


def test_obvious_phishing_email_scores_high_and_is_flagged():
    result = score_email(
        subject="Urgent: Verify your account now",
        body_text="Your account will be suspended within 24 hours. Click here to verify your password: "
                   "http://paypa1-secure.com/verify?id=1",
        sender_raw='"PayPal Security" <security@paypa1-secure.com>',
        raw_headers=PHISH_HEADERS,
    )
    assert result["risk_score"] > 50
    assert result["verdict"] in ("phishing", "suspicious")
    assert len(result["rule_indicators"]) > 0
    assert len(result["ml_explanation"]) > 0


def test_obvious_legitimate_email_scores_low():
    result = score_email(
        subject="Lunch on Friday?",
        body_text="Hey, are you free for lunch on Friday around 12:30?",
        sender_raw='"Jordan Lee" <jordan@company.com>',
        raw_headers=LEGIT_HEADERS,
    )
    assert result["risk_score"] < 50
    assert result["verdict"] == "legitimate"


def test_explanation_features_are_human_readable_and_bounded():
    result = score_email(
        subject="Final notice",
        body_text="Confirm your password now http://192.168.1.5/login",
        sender_raw="a@b.com",
        raw_headers={},
    )
    assert len(result["ml_explanation"]) <= 6
    for item in result["ml_explanation"]:
        assert set(item.keys()) == {"feature", "value", "contribution"}
