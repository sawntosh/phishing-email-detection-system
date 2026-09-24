"""
Adversarial-robustness evaluation of the text classifier.

Trains the text model on the same stratified split as train_model.py, then measures how much
held-out PHISHING recall drops when trigger words are disguised (homoglyphs, zero-width
characters, spacing, leetspeak, HTML-comment splitting, synonyms, benign padding, defanged
URLs, and a combined attack). Also runs a train/test leakage check.

    python evaluate_adversarial.py                       # real corpus if data/ exists, else synthetic
    python evaluate_adversarial.py --source synthetic
    python evaluate_adversarial.py --out docs/evidence/adversarial_eval.json

This is a measurement tool; tests/test_ml_robustness.py holds the pass/fail bar.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

from sklearn.model_selection import train_test_split  # noqa: E402

from analysis.adversarial import TRANSFORMS, dedupe, find_split_leakage  # noqa: E402
from analysis.dataset_loader import load_real_corpus, real_corpus_available  # noqa: E402
from analysis.synthetic_data import generate_dataset  # noqa: E402
from analysis.text_model import ExplainableTextModel  # noqa: E402

THRESHOLD = 0.5


def load_texts(source, data_dir, max_legit):
    if source == "real":
        samples, _ = load_real_corpus(data_dir, max_legit=max_legit)
        provenance = "Nazario phishing (2015-2021) + Enron"
    else:
        samples = generate_dataset(n_per_class=350)
        provenance = "synthetic template corpus"
    return [(s["subject"] + "\n" + s["body_text"]) for s in samples], [s["label"] for s in samples], provenance


def flagged_share(model, texts):
    return sum(model.predict_proba(t) >= THRESHOLD for t in texts) / len(texts) if texts else 0.0


def evaluate(source="synthetic", data_dir=os.path.join(ROOT, "data"), max_legit=15000):
    texts, labels, provenance = load_texts(source, data_dir, max_legit)
    n_raw = len(texts)
    texts, labels = dedupe(texts, labels)

    train_t, test_t, y_train, y_test = train_test_split(texts, labels, test_size=0.25, random_state=42, stratify=labels)
    leaked = find_split_leakage(train_t, test_t)

    model = ExplainableTextModel().fit(train_t, y_train, min_df=2 if source == "synthetic" else 3)

    phish = [t for t, y in zip(test_t, y_test) if y == 1]
    legit = [t for t, y in zip(test_t, y_test) if y == 0]
    base = flagged_share(model, phish)
    fpr = flagged_share(model, legit)

    rows = []
    for name, fn in TRANSFORMS.items():
        r = flagged_share(model, [fn(t) for t in phish])
        rows.append({"attack": name, "recall": round(r, 4), "recall_drop": round(base - r, 4),
                     "missed": int(round((1 - r) * len(phish)))})
    return {
        "source": source, "provenance": provenance, "threshold": THRESHOLD,
        "n_raw": n_raw, "n_after_dedupe": len(texts), "n_train": len(train_t), "n_test": len(test_t),
        "n_test_phishing": len(phish), "n_test_legitimate": len(legit),
        "leakage": {"duplicate_test_messages_in_train": len(leaked)},
        "baseline": {"phishing_recall": round(base, 4), "legitimate_false_positive_rate": round(fpr, 4)},
        "attacks": rows,
        "note": ("Only phishing messages are perturbed; recall = share still classified phishing. "
                 "Synthetic-corpus figures validate the harness, not real-world robustness."
                 if source == "synthetic" else
                 "Real-corpus figures; the legitimate class is era-skewed Enron mail (see README limitations)."),
    }


def print_report(rep):
    print(f"Corpus: {rep['provenance']}  raw={rep['n_raw']} unique={rep['n_after_dedupe']} "
          f"train={rep['n_train']} test={rep['n_test']} (phish={rep['n_test_phishing']}, legit={rep['n_test_legitimate']})")
    print(f"Leakage: {rep['leakage']['duplicate_test_messages_in_train']} test messages duplicated in train")
    b = rep["baseline"]
    print(f"Baseline: phishing recall={b['phishing_recall']}  legitimate FPR={b['legitimate_false_positive_rate']}\n")
    print(f"{'attack':<20}{'recall':>8}{'drop':>8}{'missed':>8}")
    for r in rep["attacks"]:
        print(f"{r['attack']:<20}{r['recall']:>8}{r['recall_drop']:>8}{r['missed']:>8}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", choices=["auto", "real", "synthetic"], default="auto")
    p.add_argument("--data-dir", default=os.path.join(ROOT, "data"))
    p.add_argument("--max-legit", type=int, default=15000)
    p.add_argument("--out", help="write the JSON report here")
    args = p.parse_args(argv)
    source = args.source
    if source == "auto":
        source = "real" if real_corpus_available(args.data_dir) else "synthetic"
    rep = evaluate(source, args.data_dir, args.max_legit)
    print_report(rep)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2)
        print(f"\nWrote {args.out}")
    return rep


if __name__ == "__main__":
    main()
