"""
Evasion transforms for robustness-testing the text classifier.

Each transform models a cheap, realistic trick a phishing author uses to slip past
a bag-of-words filter while the message still reads normally to a human. They are
deterministic so evaluation results are reproducible, and they only ever take
text in / text out -- nothing here touches the network or executes content.

Used by evaluate_adversarial.py and tests/test_ml_robustness.py.
"""
import re

# Words a phishing author would try to disguise (the ones the model leans on).
TRIGGER_WORDS = (
    "verify", "account", "password", "suspended", "urgent", "immediately", "confirm", "login",
    "security", "bank", "click", "identity", "billing", "update", "credit", "card", "paypal",
    "limited", "unusual", "activity", "closure", "final", "notice",
)
_TRIGGER_RE = re.compile(r"\b(" + "|".join(TRIGGER_WORDS) + r")\b", re.IGNORECASE)

# Latin -> visually identical Cyrillic letters.
HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}
ZERO_WIDTH = "​"

SYNONYMS = {
    "verify": "validate", "confirm": "check", "suspended": "restricted", "urgent": "time-sensitive",
    "immediately": "right away", "password": "passcode", "account": "profile", "click": "tap",
    "security": "safety", "identity": "details", "closure": "deactivation", "notice": "message",
    "unusual": "atypical", "activity": "behaviour", "update": "refresh", "billing": "payment",
}

BENIGN_PADDING = (
    " Thanks again for the great work on the project timeline. Let me know if the meeting on Friday still suits everyone,"
    " and I will send the agenda and notes from last week. Looking forward to catching up over lunch after the team update."
    " Please find the draft report attached for your comments before the conference."
)


def _map_words(text, fn):
    return _TRIGGER_RE.sub(lambda m: fn(m.group(0)), text)


def homoglyph(text):
    return _map_words(text, lambda w: "".join(HOMOGLYPHS.get(c.lower(), c) for c in w))


def leetspeak(text):
    return _map_words(text, lambda w: "".join(LEET.get(c.lower(), c) for c in w))


def zero_width(text):
    return _map_words(text, lambda w: ZERO_WIDTH.join(w))


def char_spacing(text):
    return _map_words(text, lambda w: " ".join(w))


def html_comment_split(text):
    return _map_words(text, lambda w: w[: len(w) // 2] + "<!-- -->" + w[len(w) // 2:])


def synonym_swap(text):
    return _map_words(text, lambda w: SYNONYMS.get(w.lower(), w))


def benign_padding(text):
    """Good-word attack: dilute phishing terms with innocuous text."""
    return text + BENIGN_PADDING * 3


def url_defang(text):
    text = re.sub(r"https?://", "hxxp://", text, flags=re.IGNORECASE)
    return re.sub(r"(?<=\w)\.(?=\w)", "[.]", text)


def combined(text):
    return benign_padding(synonym_swap(zero_width(text)))


TRANSFORMS = {
    "homoglyph": homoglyph,
    "leetspeak": leetspeak,
    "zero_width": zero_width,
    "char_spacing": char_spacing,
    "html_comment_split": html_comment_split,
    "synonym_swap": synonym_swap,
    "benign_padding": benign_padding,
    "url_defang": url_defang,
    "combined": combined,
}


def _key(text):
    return " ".join((text or "").lower().split())


def find_split_leakage(train_texts, test_texts):
    """Test texts that also appear (whitespace/case-insensitive) in train. A non-empty
    result means held-out metrics are inflated by memorised duplicates."""
    train_keys = {_key(t) for t in train_texts}
    return [t for t in test_texts if _key(t) in train_keys]


def dedupe(texts, labels):
    seen, out_t, out_l = set(), [], []
    for t, y in zip(texts, labels):
        k = _key(t)
        if k not in seen:
            seen.add(k)
            out_t.append(t)
            out_l.append(y)
    return out_t, out_l
