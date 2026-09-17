"""
Hybrid ML classifier: Logistic Regression over the interpretable feature
vector defined in features.py. Logistic Regression is chosen deliberately
over a black-box model (e.g. gradient boosting / neural net) because its
coefficients give an exact, faithful, per-prediction explanation
(contribution_i = coefficient_i * feature_value_i) -- this directly
satisfies the "Explainability view showing the features/indicators that
influenced the risk score" core requirement without needing a separate
post-hoc approximation library such as SHAP/LIME.
"""
import json
import os

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from analysis.features import FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "instance")
MODEL_PATH = os.path.join(MODEL_DIR, "model.json")


class ExplainableLogisticModel:
    """Thin wrapper that (de)serialises to plain JSON (no pickle -- avoids
    deserialisation of arbitrary objects, a supply-chain/RCE risk with
    pickle-based model files loaded from disk)."""

    def __init__(self, coef=None, intercept=0.0, mean=None, scale=None):
        self.coef = coef
        self.intercept = intercept
        self.mean = mean
        self.scale = scale

    def fit(self, X, y):
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        clf = LogisticRegression(max_iter=1000, class_weight="balanced")
        clf.fit(Xs, y)
        self.coef = clf.coef_[0].tolist()
        self.intercept = float(clf.intercept_[0])
        self.mean = scaler.mean_.tolist()
        self.scale = scaler.scale_.tolist()
        return self

    def _scaled(self, x_row):
        return [(x - m) / s if s else 0.0 for x, m, s in zip(x_row, self.mean, self.scale)]

    def predict_proba(self, x_row):
        z = self._scaled(x_row)
        logit = self.intercept + sum(c * v for c, v in zip(self.coef, z))
        prob = 1 / (1 + np.exp(-logit))
        return float(prob)

    def explain(self, x_row, top_k=6):
        z = self._scaled(x_row)
        contributions = [c * v for c, v in zip(self.coef, z)]
        ranked = sorted(
            zip(FEATURE_NAMES, contributions, x_row), key=lambda t: abs(t[1]), reverse=True
        )
        return [
            {"feature": name, "value": val, "contribution": round(contrib, 4)}
            for name, contrib, val in ranked[:top_k]
            if abs(contrib) > 1e-6
        ]

    def save(self, path=MODEL_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "coef": self.coef, "intercept": self.intercept,
                "mean": self.mean, "scale": self.scale,
                "feature_names": FEATURE_NAMES,
            }, f, indent=2)

    @classmethod
    def load(cls, path=MODEL_PATH):
        with open(path) as f:
            data = json.load(f)
        if data.get("feature_names") != FEATURE_NAMES:
            raise ValueError("Model was trained on a different feature schema; retrain via train_model.py")
        return cls(coef=data["coef"], intercept=data["intercept"], mean=data["mean"], scale=data["scale"])


_model_cache = None


def get_model():
    global _model_cache
    if _model_cache is None:
        _model_cache = ExplainableLogisticModel.load()
    return _model_cache


def classify(feature_dict):
    from analysis.features import feature_dict_to_vector
    x_row = feature_dict_to_vector(feature_dict)
    model = get_model()
    prob = model.predict_proba(x_row)
    explanation = model.explain(x_row)
    return prob, explanation
