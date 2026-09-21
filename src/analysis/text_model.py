"""
Explainable text classifier trained on a REAL phishing corpus.

TF-IDF (unigrams + bigrams) -> Logistic Regression. It replaces the opaque
Doc2Vec + black-box classifiers used in the reference project with something
whose every prediction can be decomposed exactly:

    logit = intercept + sum_over_terms(coef[term] * tfidf[term])

so the explainability view can show the precise words/phrases that pushed an
email toward "phishing" or toward "legitimate" -- no SHAP/LIME approximation.

The model is stored as plain JSON (vocabulary, idf, coefficients). Pickle is
deliberately avoided: loading an untrusted pickle executes arbitrary code.

Inference is re-implemented in pure Python (no scikit-learn needed at serve
time) and is unit-tested to match scikit-learn's own transform bit-for-bit,
so training and serving cannot silently drift apart.
"""
import json
import math
import os
import re
from collections import Counter

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "instance")
TEXT_MODEL_PATH = os.path.join(MODEL_DIR, "model_text.json")

FORMAT_VERSION = 1
MAX_INPUT_CHARS = 20000  # bound CPU cost per message (submission bodies are attacker-controlled)

_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\S+@\S+")
_TOKEN_RE = re.compile(r"[a-z][a-z']{1,24}")

STOPWORDS = frozenset("""
a about above after again all am an and any are as at be because been before being below between both but by
can could did do does doing down during each few for from further had has have having he her here hers herself
him himself his how i if in into is it its itself just me more most my myself no nor not now of off on once only
or other our ours ourselves out over own same she should so some such than that the their theirs them themselves
then there these they this those through to too under until up very was we were what when where which while who
whom why will with would you your yours yourself yourselves re fw fwd
""".split())

# Tokens that identify WHICH CORPUS an email came from rather than whether it is phishing
# (the legitimate class is Enron-era corporate mail; the phishing class is 2015-2021
# Nazario mail). Left in, the model would learn "sounds like Enron" == legitimate.
CORPUS_ARTIFACT_TERMS = frozenset("""
enron ect hou houston ees corp eott ena epmi nom hpl enronxgate dynegy tw fyi
pm am cc subject forwarded forward original message sent image
energy gas power trading trade deal deals pipeline market markets
jeff mark john vince steve chris mike david susan kay sally kevin tim bob jim joe mary sara
kaminski skilling lay kenneth louise stacey shirley debra gerald tana drew
""".split())


def normalise(text):
    text = (text or "")[:MAX_INPUT_CHARS]
    text = _TAG_RE.sub(" ", text)
    text = _URL_RE.sub(" urltoken ", text)
    text = _EMAIL_RE.sub(" emailtoken ", text)
    return text.lower()


def analyzer(text):
    tokens = [t.strip("'") for t in _TOKEN_RE.findall(normalise(text))]
    tokens = [t for t in tokens if len(t) >= 2 and t not in STOPWORDS and t not in CORPUS_ARTIFACT_TERMS]
    bigrams = [f"{a} {b}" for a, b in zip(tokens, tokens[1:])]
    return tokens + bigrams


def _sigmoid(z):
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class ExplainableTextModel:
    def __init__(self, vocab=None, idf=None, coef=None, intercept=0.0, meta=None):
        self.vocab = vocab or {}
        self.idf = idf or []
        self.coef = coef or []
        self.intercept = intercept
        self.meta = meta or {}
        self._terms = None
        self._vectorizer = None  # only present right after fit(); never serialised

    # ---- training -----------------------------------------------------
    def fit(self, texts, labels, max_features=20000, min_df=3, max_df=0.9, C=1.0):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        vectorizer = TfidfVectorizer(
            analyzer=analyzer, min_df=min_df, max_df=max_df, max_features=max_features,
            sublinear_tf=True, norm="l2",
        )
        matrix = vectorizer.fit_transform(texts)
        clf = LogisticRegression(C=C, max_iter=3000, class_weight="balanced")
        clf.fit(matrix, labels)

        self.vocab = {term: int(i) for term, i in vectorizer.vocabulary_.items()}
        self.idf = [float(v) for v in vectorizer.idf_]
        self.coef = [float(c) for c in clf.coef_[0]]
        self.intercept = float(clf.intercept_[0])
        self._terms = None
        self._vectorizer = vectorizer
        return self

    def transform_matrix(self, texts):
        """scikit-learn feature matrix (training-time only), used to benchmark other classifiers."""
        return self._vectorizer.transform(texts)

    # ---- inference (pure python) --------------------------------------
    def _weights(self, text):
        counts = Counter(t for t in analyzer(text) if t in self.vocab)
        weights = {}
        for term, count in counts.items():
            idx = self.vocab[term]
            weights[idx] = (1.0 + math.log(count)) * self.idf[idx]
        norm = math.sqrt(sum(w * w for w in weights.values()))
        if not norm:
            return {}
        return {i: w / norm for i, w in weights.items()}

    def predict_proba(self, text):
        weights = self._weights(text)
        return _sigmoid(self.intercept + sum(self.coef[i] * w for i, w in weights.items()))

    def _term_list(self):
        if self._terms is None:
            terms = [""] * len(self.vocab)
            for term, idx in self.vocab.items():
                terms[idx] = term
            self._terms = terms
        return self._terms

    def explain(self, text, top_k=8):
        weights = self._weights(text)
        terms = self._term_list()
        ranked = sorted(((self.coef[i] * w, i, w) for i, w in weights.items()), key=lambda t: abs(t[0]), reverse=True)
        return [
            {"feature": terms[i], "value": round(w, 4), "contribution": round(contrib, 4), "source": "text"}
            for contrib, i, w in ranked[:top_k]
            if abs(contrib) > 1e-6
        ]

    def top_terms(self, k=15):
        terms = self._term_list()
        order = sorted(range(len(self.coef)), key=lambda i: self.coef[i])
        return {
            "legitimate": [{"term": terms[i], "coef": round(self.coef[i], 3)} for i in order[:k]],
            "phishing": [{"term": terms[i], "coef": round(self.coef[i], 3)} for i in reversed(order[-k:])],
        }

    # ---- persistence ---------------------------------------------------
    def save(self, path=TEXT_MODEL_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "format_version": FORMAT_VERSION, "vocab": self.vocab, "idf": self.idf,
                "coef": self.coef, "intercept": self.intercept, "meta": self.meta,
            }, fh)

    @classmethod
    def load(cls, path=TEXT_MODEL_PATH):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("format_version") != FORMAT_VERSION:
            raise ValueError("Text model has an unsupported format; retrain via train_model.py")
        if not (len(data["idf"]) == len(data["coef"]) == len(data["vocab"])):
            raise ValueError("Text model file is inconsistent; retrain via train_model.py")
        return cls(data["vocab"], data["idf"], data["coef"], data["intercept"], data.get("meta"))


_cache = {"path": None, "mtime": None, "model": None}


def get_text_model(path=None):
    """Cached loader. Returns None (never raises) when no text model has been trained,
    so the risk engine can degrade gracefully to rules + structured model."""
    path = path or TEXT_MODEL_PATH
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["model"]
    model = ExplainableTextModel.load(path)
    _cache.update(path=path, mtime=mtime, model=model)
    return model
