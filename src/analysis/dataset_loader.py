"""
Loader for the real phishing / legitimate-mail corpora.

Expected layout (same CSV format as the reference project's Notebook/Dataset):

    data/phishing/*.csv   -> label 1  (Jose Nazario phishing corpus, 2015-2021)
    data/enron/*.csv      -> label 0  (Enron e-mail dataset)

Each CSV has at least a `subject` and a `content` column. Only text is
available in these corpora (no raw headers), so the text model is trained
on subject + body; SPF/DKIM/DMARC and sender checks stay rule-based.

Exact-duplicate messages are removed before splitting: phishing campaigns are
mailed in bulk, and identical copies landing in both train and test would
inflate the evaluation numbers.
"""
import csv
import glob
import os
import random
import re
import sys

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

MIN_BODY_CHARS = 40
_WS_RE = re.compile(r"\s+")


def _read_rows(pattern):
    for path in sorted(glob.glob(pattern)):
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                yield row


def _load_class(directory, label, seed_rng=None, limit=None):
    seen = set()
    samples = []
    raw_rows = 0
    for row in _read_rows(os.path.join(directory, "*.csv")):
        raw_rows += 1
        subject = (row.get("subject") or "").strip()
        body = (row.get("content") or "").strip()
        if len(body) < MIN_BODY_CHARS:
            continue
        key = _WS_RE.sub(" ", (subject + " " + body).lower())
        if key in seen:
            continue
        seen.add(key)
        samples.append({"subject": subject, "body_text": body, "label": label})
    stats = {"raw_rows": raw_rows, "usable_unique": len(samples)}
    if limit and len(samples) > limit:
        seed_rng.shuffle(samples)
        samples = samples[:limit]
    stats["used"] = len(samples)
    return samples, stats


def real_corpus_available(data_dir):
    return bool(glob.glob(os.path.join(data_dir, "phishing", "*.csv"))) and \
        bool(glob.glob(os.path.join(data_dir, "enron", "*.csv")))


def load_real_corpus(data_dir, max_legit=15000, seed=42):
    """Returns (samples, stats). All unique phishing rows are kept; the (much larger)
    legitimate set is randomly down-sampled to max_legit."""
    # Reproducible corpus sampling; not a security context.
    rng = random.Random(seed)  # nosec B311
    phish, phish_stats = _load_class(os.path.join(data_dir, "phishing"), 1, rng)
    legit, legit_stats = _load_class(os.path.join(data_dir, "enron"), 0, rng, limit=max_legit)
    samples = phish + legit
    rng.shuffle(samples)
    return samples, {"phishing": phish_stats, "legitimate": legit_stats,
                     "sources": "Nazario phishing corpus (2015-2021) + Enron e-mail dataset"}
