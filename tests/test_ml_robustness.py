import pytest
from sklearn.model_selection import train_test_split

from analysis import adversarial
from analysis.adversarial import TRANSFORMS, dedupe, find_split_leakage
from analysis.synthetic_data import generate_dataset
from analysis.text_model import ExplainableTextModel

SAMPLE = "Urgent: please verify your account password immediately at http://paypa1-secure.example/login"
MIN_RECALL_UNDER_EVASION = 0.8


# ---- transform unit tests -----------------------------------------------
def test_transforms_change_trigger_words_only():
    for name, fn in TRANSFORMS.items():
        out = fn(SAMPLE)
        assert out != SAMPLE, name
        assert isinstance(out, str)


def test_transforms_are_deterministic():
    for fn in TRANSFORMS.values():
        assert fn(SAMPLE) == fn(SAMPLE)


def test_homoglyph_uses_non_ascii_lookalikes():
    out = adversarial.homoglyph("verify your password")
    assert not out.isascii()
    assert "verify" not in out


def test_zero_width_inserts_invisible_characters():
    assert adversarial.ZERO_WIDTH in adversarial.zero_width("verify")


def test_benign_text_without_trigger_words_is_untouched_by_word_transforms():
    text = "See you at lunch on Friday"
    for name in ("homoglyph", "leetspeak", "zero_width", "char_spacing", "synonym_swap", "html_comment_split"):
        assert TRANSFORMS[name](text) == text


# ---- leakage guard -------------------------------------------------------
def test_leakage_detector_flags_case_and_whitespace_duplicates():
    assert find_split_leakage(["Hello   World"], ["hello world", "other"]) == ["hello world"]
    assert find_split_leakage(["a"], ["b"]) == []


def test_dedupe_removes_exact_duplicates_keeping_first_label():
    texts, labels = dedupe(["x y", "X  Y", "z"], [1, 0, 0])
    assert texts == ["x y", "z"] and labels == [1, 0]


# ---- model robustness ----------------------------------------------------
@pytest.fixture(scope="module")
def split_and_model():
    samples = generate_dataset(n_per_class=350)
    texts, labels = dedupe([s["subject"] + "\n" + s["body_text"] for s in samples], [s["label"] for s in samples])
    train_t, test_t, y_train, y_test = train_test_split(texts, labels, test_size=0.25, random_state=42, stratify=labels)
    model = ExplainableTextModel().fit(train_t, y_train, min_df=2)
    return train_t, test_t, y_test, model


def _recall(model, texts):
    return sum(model.predict_proba(t) >= 0.5 for t in texts) / len(texts)


def test_no_train_test_leakage(split_and_model):
    train_t, test_t, _, _ = split_and_model
    assert find_split_leakage(train_t, test_t) == []


def test_baseline_recall_is_high(split_and_model):
    _, test_t, y_test, model = split_and_model
    phish = [t for t, y in zip(test_t, y_test) if y == 1]
    assert _recall(model, phish) >= 0.9


@pytest.mark.parametrize("attack", [n for n in TRANSFORMS if n not in ("benign_padding", "combined")])
def test_recall_survives_word_level_evasion(split_and_model, attack):
    _, test_t, y_test, model = split_and_model
    phish = [t for t, y in zip(test_t, y_test) if y == 1]
    assert _recall(model, [TRANSFORMS[attack](t) for t in phish]) >= MIN_RECALL_UNDER_EVASION


@pytest.mark.xfail(reason="KNOWN GAP: good-word padding dilutes the TF-IDF vector and flips the verdict; "
                          "blending with the rule engine is the intended mitigation", strict=False)
@pytest.mark.parametrize("attack", ["benign_padding", "combined"])
def test_recall_survives_padding_attack(split_and_model, attack):
    _, test_t, y_test, model = split_and_model
    phish = [t for t, y in zip(test_t, y_test) if y == 1]
    assert _recall(model, [TRANSFORMS[attack](t) for t in phish]) >= MIN_RECALL_UNDER_EVASION
