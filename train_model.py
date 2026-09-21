"""
Trains the two ML components of the hybrid detector and writes the reports
shown on the admin "Model performance" page.

  1. Text model (the main learner)  -- TF-IDF + Logistic Regression, trained on the REAL
     Nazario phishing + Enron corpora in data/. Also benchmarked against other
     classifiers (Linear SVM, Naive Bayes, Random Forest, Decision Tree) on the
     identical split, the way the reference project compared ten classifiers.
  2. Structured model               -- Logistic Regression over hand-built URL / header /
     content features. The public corpora contain no raw headers, so this model is
     trained on the documented synthetic generator, which is the only place
     SPF/DKIM/DMARC and Reply-To signal exist.

Run:
    python train_model.py                        # real corpus if data/ exists, else synthetic
    python train_model.py --source synthetic     # fast, offline (used by the test-suite)
    python train_model.py --data-dir data --max-legit 15000

Outputs (instance/):
    model.json               structured model            model_eval_report.json
    model_text.json          text model                  text_model_report.json
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from analysis.dataset_loader import load_real_corpus, real_corpus_available  # noqa: E402
from analysis.features import extract_feature_dict, feature_dict_to_vector  # noqa: E402
from analysis.ml_classifier import ExplainableLogisticModel, MODEL_DIR  # noqa: E402
from analysis.synthetic_data import generate_dataset  # noqa: E402
from analysis.text_model import ExplainableTextModel, TEXT_MODEL_PATH  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))


def _metrics(y_true, y_pred, scores=None):
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": round(float((tp + tn) / max(tp + tn + fp + fn, 1)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if scores is not None:
        out["roc_auc"] = round(float(roc_auc_score(y_true, scores)), 4)
    return out


def _write_json(name, payload):
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(os.path.join(MODEL_DIR, name), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


# --------------------------------------------------------------------------
# 1. structured model (synthetic; carries the header signal)
# --------------------------------------------------------------------------
def train_structured():
    print("[structured] generating synthetic corpus (documented limitation: no public corpus has raw headers)...")
    samples = generate_dataset(n_per_class=350)
    X, y = [], []
    for s in samples:
        fd, *_ = extract_feature_dict(s["subject"], s["body_text"], s["sender_raw"], s["raw_headers"], s["attachment_count"])
        X.append(feature_dict_to_vector(fd))
        y.append(s["label"])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = ExplainableLogisticModel().fit(X_train, y_train)
    probs = [model.predict_proba(r) for r in X_test]
    report = {"n_train": len(X_train), "n_test": len(X_test), **_metrics(y_test, [int(p >= 0.5) for p in probs], probs)}
    report["note"] = ("Held-out split of a synthetic, template-generated corpus (analysis/synthetic_data.py). "
                      "Validates the structured-feature pipeline end to end; NOT a real-world accuracy claim.")
    model.save()
    _write_json("model_eval_report.json", report)
    print(f"[structured] precision={report['precision']} recall={report['recall']} f1={report['f1_score']}")
    return samples


# --------------------------------------------------------------------------
# 2. text model (real corpus) + classifier benchmark
# --------------------------------------------------------------------------
def _benchmark(text_model, train_texts, y_train, test_texts, y_test, deployed_probs):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.svm import LinearSVC
    from sklearn.tree import DecisionTreeClassifier

    X_train = text_model.transform_matrix(train_texts)
    X_test = text_model.transform_matrix(test_texts)

    rows = [{
        "name": "Logistic Regression (deployed, explainable)", "deployed": True, "train_seconds": None,
        **_metrics(y_test, [int(p >= 0.5) for p in deployed_probs], deployed_probs),
    }]
    candidates = [
        ("Linear SVM", LinearSVC(class_weight="balanced")),
        ("Multinomial Naive Bayes", MultinomialNB()),
        ("Random Forest", RandomForestClassifier(n_estimators=100, n_jobs=-1, class_weight="balanced_subsample", random_state=42)),
        ("Decision Tree", DecisionTreeClassifier(class_weight="balanced", random_state=42)),
    ]
    for name, clf in candidates:
        started = time.time()
        clf.fit(X_train, y_train)
        elapsed = round(time.time() - started, 1)
        preds = clf.predict(X_test)
        scores = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else clf.decision_function(X_test)
        rows.append({"name": name, "deployed": False, "train_seconds": elapsed, **_metrics(y_test, preds, scores)})
        print(f"[benchmark] {name:<26} f1={rows[-1]['f1_score']} fpr={rows[-1]['false_positive_rate']} ({elapsed}s)")
    return rows


def train_text(source, data_dir, max_legit, synthetic_samples):
    if source == "real":
        print(f"[text] loading real corpus from {data_dir} ...")
        samples, corpus_stats = load_real_corpus(data_dir, max_legit=max_legit)
        provenance = corpus_stats["sources"]
    else:
        print("[text] using the synthetic corpus (no real data requested/available).")
        samples = [{"subject": s["subject"], "body_text": s["body_text"], "label": s["label"]} for s in synthetic_samples]
        corpus_stats = {"note": "synthetic template corpus"}
        provenance = "synthetic template corpus (analysis/synthetic_data.py)"

    texts = [(s["subject"] + "\n" + s["body_text"]) for s in samples]
    labels = [s["label"] for s in samples]
    train_texts, test_texts, y_train, y_test = train_test_split(texts, labels, test_size=0.25, random_state=42, stratify=labels)
    print(f"[text] {len(train_texts)} train / {len(test_texts)} test  (phishing share {sum(labels) / len(labels):.1%})")

    started = time.time()
    model = ExplainableTextModel().fit(train_texts, y_train, min_df=2 if source == "synthetic" else 3)
    print(f"[text] fitted in {time.time() - started:.1f}s, vocabulary={len(model.vocab)}")

    probs = [model.predict_proba(t) for t in test_texts]  # pure-python serving path, not sklearn
    deployed = _metrics(y_test, [int(p >= 0.5) for p in probs], probs)
    print(f"[text] held-out: precision={deployed['precision']} recall={deployed['recall']} "
          f"f1={deployed['f1_score']} fpr={deployed['false_positive_rate']} auc={deployed['roc_auc']}")

    comparison = _benchmark(model, train_texts, y_train, test_texts, y_test, probs)

    model.meta = {"trained_on": provenance, "n_train": len(train_texts), "n_test": len(test_texts),
                  "phishing_share": round(sum(labels) / len(labels), 4)}
    model.save()

    report = {
        "source": source,
        "provenance": provenance,
        "corpus": corpus_stats,
        "n_train": len(train_texts),
        "n_test": len(test_texts),
        "phishing_share": round(sum(labels) / len(labels), 4),
        "deployed": deployed,
        "comparison": comparison,
        "top_terms": model.top_terms(15),
        "note": ("Held-out 25% stratified split; exact-duplicate messages removed before splitting. Read with care: "
                 "the legitimate class is 2000s-era Enron corporate mail and the phishing class is 2015-2021 mail, so part "
                 "of the separation is style/era rather than intent. Corpus-specific tokens are excluded, and the score "
                 "is blended with rule-based checks, but expect lower accuracy on modern legitimate marketing mail."
                 if source == "real" else
                 "Synthetic corpus -- proof-of-pipeline only, not a real-world accuracy claim."),
    }
    _write_json("text_model_report.json", report)
    print(f"[text] saved {TEXT_MODEL_PATH}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=["auto", "real", "synthetic"], default="auto")
    parser.add_argument("--data-dir", default=os.path.join(ROOT, "data"))
    parser.add_argument("--max-legit", type=int, default=15000, help="cap on legitimate (Enron) messages used")
    args = parser.parse_args(argv)

    source = args.source
    if source == "auto":
        source = "real" if real_corpus_available(args.data_dir) else "synthetic"
    if source == "real" and not real_corpus_available(args.data_dir):
        sys.exit(f"No corpus found under {args.data_dir}/phishing and {args.data_dir}/enron (see README).")

    synthetic_samples = train_structured()
    train_text(source, args.data_dir, args.max_legit, synthetic_samples)
    print("\nDone. Start the app with:  cd src && python app.py")


if __name__ == "__main__":
    main()
