import json
import math

import pytest

from analysis import text_model
from analysis.text_model import ExplainableTextModel, analyzer, get_text_model, normalise

PHISH = [
    "Dear customer your account has been suspended please verify your password immediately click the link",
    "Urgent security alert confirm your bank account details to avoid suspension of your paypal account",
    "Your ebay account is limited update your billing information and confirm your identity now",
    "Security notification unusual activity detected verify your online banking login credentials today",
    "Final notice your account will be closed click here to confirm your password and card number",
] * 6
LEGIT = [
    "Thanks for the update lets meet on friday to discuss the project timeline and budget",
    "Can you send me the notes from yesterdays meeting I have a few questions for the group",
    "Attached is the agenda for next week let me know if you have any comments or changes",
    "Please call me when you get a chance so we can review the draft before the conference",
    "Great work on the report thanks everyone lunch is on me after the team meeting tomorrow",
] * 6


@pytest.fixture(scope="module")
def model():
    return ExplainableTextModel().fit(PHISH + LEGIT, [1] * len(PHISH) + [0] * len(LEGIT), min_df=1, max_df=1.0)


def test_separates_phishing_from_legitimate(model):
    phish = model.predict_proba("Dear customer verify your bank account password immediately")
    legit = model.predict_proba("Thanks lets meet on friday to discuss the project agenda")
    assert phish > 0.6 and legit < 0.4 and phish - legit > 0.4


def test_pure_python_inference_matches_scikit_learn_transform(model):
    text = "Urgent: verify your paypal account password now, dear customer! http://x.example/login"
    ours = model._weights(text)
    row = model.transform_matrix([text]).tocoo()
    theirs = {int(c): float(v) for c, v in zip(row.col, row.data)}
    assert set(ours) == set(theirs)
    for idx, value in theirs.items():
        assert ours[idx] == pytest.approx(value, abs=1e-12)


def test_probability_matches_the_logit_formula(model):
    text = "confirm your bank account password"
    weights = model._weights(text)
    logit = model.intercept + sum(model.coef[i] * w for i, w in weights.items())
    assert model.predict_proba(text) == pytest.approx(1 / (1 + math.exp(-logit)))


def test_explanations_sum_to_the_logit_and_carry_signs(model):
    text = "Dear customer verify your bank account password immediately"
    weights = model._weights(text)
    everything = model.explain(text, top_k=10_000)
    assert all(e["source"] == "text" for e in everything)
    total = sum(e["contribution"] for e in everything) + model.intercept
    assert total == pytest.approx(model.intercept + sum(model.coef[i] * w for i, w in weights.items()), abs=1e-2)
    assert everything[0]["contribution"] > 0  # phishing words dominate a phishing sentence
    assert len(model.explain(text, top_k=3)) <= 3


def test_json_roundtrip_gives_identical_predictions(model, tmp_path):
    path = tmp_path / "m.json"
    model.meta = {"trained_on": "unit test"}
    model.save(str(path))
    loaded = ExplainableTextModel.load(str(path))
    for text in (PHISH[0], LEGIT[0], "completely unseen words here"):
        assert loaded.predict_proba(text) == pytest.approx(model.predict_proba(text))
    assert loaded.meta["trained_on"] == "unit test"
    raw = json.loads(path.read_text())
    assert set(raw) == {"format_version", "vocab", "idf", "coef", "intercept", "meta"}  # plain data only, no pickle


def test_load_rejects_inconsistent_or_unknown_format(model, tmp_path):
    path = tmp_path / "bad.json"
    model.save(str(path))
    data = json.loads(path.read_text())
    data["format_version"] = 99
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        ExplainableTextModel.load(str(path))
    data["format_version"] = text_model.FORMAT_VERSION
    data["coef"] = data["coef"][:-1]
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        ExplainableTextModel.load(str(path))


def test_unseen_or_empty_text_is_handled(model):
    assert 0 <= model.predict_proba("") <= 1
    assert 0 <= model.predict_proba("zzzz qqqq xxxx") <= 1
    assert model.explain("") == []


def test_extreme_logits_do_not_overflow(model):
    model.intercept, saved = 5000.0, model.intercept
    try:
        assert model.predict_proba("anything") == 1.0
        model.intercept = -5000.0
        assert model.predict_proba("anything") == 0.0
    finally:
        model.intercept = saved


def test_normalise_neutralises_html_urls_and_addresses():
    cleaned = normalise("<b>Click</b> https://evil.example/login?x=1 or mail bob@corp.example NOW")
    assert "<b>" not in cleaned and "evil.example" not in cleaned and "bob@" not in cleaned
    assert "urltoken" in cleaned and "emailtoken" in cleaned


def test_corpus_artifact_terms_are_excluded_from_features():
    tokens = analyzer("Enron energy trading forwarded by Vince Kaminski, please verify your account")
    assert not ({"enron", "energy", "vince", "kaminski"} & set(tokens))
    assert "verify" in tokens and "verify account" in tokens


def test_oversized_input_is_truncated_not_processed_in_full():
    huge = "verify " * 100_000
    assert len(analyzer(huge)) < 8_000


def test_get_text_model_returns_none_when_no_model_file(tmp_path):
    assert get_text_model(str(tmp_path / "missing.json")) is None


def test_get_text_model_caches_and_reloads_on_change(model, tmp_path):
    import os
    path = tmp_path / "cached.json"
    model.save(str(path))
    first = get_text_model(str(path))
    assert get_text_model(str(path)) is first
    model.save(str(path))
    os.utime(path, (path.stat().st_atime + 10, path.stat().st_mtime + 10))
    assert get_text_model(str(path)) is not first
