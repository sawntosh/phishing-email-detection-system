"""
Trains the explainable logistic-regression phishing classifier and
reports the held-out evaluation metrics required by the assessment
brief: precision, recall, F1, confusion matrix, false-positive rate.

Run:  python train_model.py
Output: src/../instance/model.json (loaded by analysis/ml_classifier.py)
        instance/model_eval_report.json (for the report / dashboard)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

from analysis.synthetic_data import generate_dataset
from analysis.features import extract_feature_dict, feature_dict_to_vector
from analysis.ml_classifier import ExplainableLogisticModel, MODEL_DIR


def build_feature_matrix(samples):
    X, y = [], []
    for s in samples:
        fd, *_ = extract_feature_dict(
            s["subject"], s["body_text"], s["sender_raw"], s["raw_headers"], s["attachment_count"]
        )
        X.append(feature_dict_to_vector(fd))
        y.append(s["label"])
    return X, y


def main():
    print("Generating synthetic training corpus (see analysis/synthetic_data.py for the documented limitation)...")
    samples = generate_dataset(n_per_class=350)
    X, y = build_feature_matrix(samples)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = ExplainableLogisticModel().fit(X_train, y_train)

    y_pred = [1 if model.predict_proba(row) >= 0.5 else 0 for row in X_test]
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    report = {
        "n_train": len(X_train),
        "n_test": len(X_test),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "note": "Held-out split of a synthetic, template-generated corpus (see analysis/synthetic_data.py). "
                "This validates the pipeline end-to-end; retrain on an authorised real phishing corpus "
                "before drawing real-world accuracy conclusions.",
    }

    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save()
    with open(os.path.join(MODEL_DIR, "model_eval_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nModel saved to {os.path.join(MODEL_DIR, 'model.json')}")


if __name__ == "__main__":
    main()
