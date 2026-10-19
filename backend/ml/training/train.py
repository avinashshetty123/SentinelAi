"""Train and evaluate the baseline TF-IDF + logistic-regression SMS spam classifier.

Dataset: UCI "SMS Spam Collection" (Almeida & Hidalgo, 2011), CC BY 4.0.
         https://archive.ics.uci.edu/dataset/228/sms+spam+collection

Usage (from backend/):
    python -m ml.training.train            # downloads the dataset if missing, trains, evaluates, exports

Outputs:
    ml/artifacts/sms_spam_tfidf_lr.json   portable model (vocabulary, idf, coefficients) - no pickle
    ml/evaluation/metrics.json            held-out metrics, split sizes, configuration

The exported model is loaded by app/services/detection/classifier.py, which re-implements the exact
TF-IDF transform in pure Python. tests/test_classifier.py verifies parity with scikit-learn.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "datasets"
RAW_FILE = DATASET_DIR / "SMSSpamCollection"
ARTIFACT = ROOT / "artifacts" / "sms_spam_tfidf_lr.json"
METRICS = ROOT / "evaluation" / "metrics.json"
DATASET_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"

SEED = 42
TEST_SIZE = 0.2
VECTORIZER_PARAMS = {
    "lowercase": True,
    "token_pattern": r"(?u)\b\w\w+\b",
    "ngram_range": (1, 2),
    "min_df": 2,
    "max_df": 0.95,
    "sublinear_tf": True,
    "norm": "l2",
    "smooth_idf": True,
    "max_features": 15000,
}
LR_PARAMS = {"C": 4.0, "class_weight": "balanced", "max_iter": 2000, "solver": "liblinear"}
MODEL_VERSION = "sms-tfidf-lr-1.0"


def ensure_dataset() -> None:
    if RAW_FILE.exists():
        return
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {DATASET_URL}")
    with urllib.request.urlopen(DATASET_URL, timeout=60) as resp:  # fixed, trusted URL
        data = resp.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        member = next(n for n in zf.namelist() if n.endswith("SMSSpamCollection"))
        RAW_FILE.write_bytes(zf.read(member))


def load() -> pd.DataFrame:
    rows = []
    for line_no, line in enumerate(RAW_FILE.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        label, sep, text = line.partition("\t")
        if not sep or label not in ("ham", "spam"):
            raise ValueError(f"Malformed line {line_no}: unexpected label/format")
        rows.append((label, text))
    df = pd.DataFrame(rows, columns=["label", "text"])
    df["y"] = (df["label"] == "spam").astype(int)
    return df


def main() -> None:
    ensure_dataset()
    df = load()
    raw_counts = df["label"].value_counts().to_dict()
    # Exact/near-exact duplicates (case/whitespace-insensitive) would leak between train and test.
    df["key"] = df["text"].str.lower().map(lambda s: re.sub(r"\s+", " ", s).strip())
    conflicting = df.groupby("key")["y"].nunique()
    conflicting_keys = set(conflicting[conflicting > 1].index)
    df = df[~df["key"].isin(conflicting_keys)].drop_duplicates("key").reset_index(drop=True)
    dedup_counts = df["label"].value_counts().to_dict()

    train_df, test_df = train_test_split(df, test_size=TEST_SIZE, stratify=df["y"], random_state=SEED)
    assert not set(train_df["key"]) & set(test_df["key"]), "leakage: duplicate text across splits"

    vectorizer = TfidfVectorizer(**VECTORIZER_PARAMS)
    x_train = vectorizer.fit_transform(train_df["text"])
    x_test = vectorizer.transform(test_df["text"])
    model = LogisticRegression(random_state=SEED, **LR_PARAMS)
    model.fit(x_train, train_df["y"])

    proba = model.predict_proba(x_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(test_df["y"], pred, average="binary")
    tn, fp, fn, tp = confusion_matrix(test_df["y"], pred).ravel()

    metrics = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": {
            "name": "UCI SMS Spam Collection",
            "url": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
            "license": "CC BY 4.0",
            "sha256": hashlib.sha256(RAW_FILE.read_bytes()).hexdigest(),
            "raw_class_counts": raw_counts,
            "after_dedup_class_counts": dedup_counts,
            "conflicting_label_texts_removed": len(conflicting_keys),
        },
        "split": {
            "method": "stratified random split after de-duplication",
            "seed": SEED,
            "test_size": TEST_SIZE,
            "train_size": len(train_df),
            "test_size_rows": len(test_df),
            "train_class_counts": train_df["label"].value_counts().to_dict(),
            "test_class_counts": test_df["label"].value_counts().to_dict(),
        },
        "config": {
            "vectorizer": {**VECTORIZER_PARAMS, "ngram_range": list(VECTORIZER_PARAMS["ngram_range"])},
            "logistic_regression": LR_PARAMS,
            "decision_threshold": 0.5,
            "sklearn_version": sklearn.__version__,
        },
        "test_metrics": {
            "precision_spam": round(float(precision), 4),
            "recall_spam": round(float(recall), 4),
            "f1_spam": round(float(f1), 4),
            "roc_auc": round(float(roc_auc_score(test_df["y"], proba)), 4),
            "false_positive_rate": round(float(fp / (fp + tn)), 4),
            "accuracy": round(float((tp + tn) / len(test_df)), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
    }

    vocab = {term: int(idx) for term, idx in vectorizer.vocabulary_.items()}
    artifact = {
        "model_version": MODEL_VERSION,
        "type": "tfidf_logistic_regression",
        "positive_label": "spam",
        "tokenizer": {
            "lowercase": True,
            "token_pattern": VECTORIZER_PARAMS["token_pattern"],
            "ngram_range": list(VECTORIZER_PARAMS["ngram_range"]),
        },
        "sublinear_tf": True,
        "norm": "l2",
        "vocabulary": vocab,
        "idf": [round(float(v), 6) for v in vectorizer.idf_],
        "coef": [round(float(v), 6) for v in model.coef_[0]],
        "intercept": round(float(model.intercept_[0]), 6),
        "metrics_summary": metrics["test_metrics"],
        "dataset": {k: metrics["dataset"][k] for k in ("name", "url", "license")},
        "trained_at": metrics["trained_at"],
    }
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    METRICS.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(artifact, separators=(",", ":")), encoding="utf-8")
    METRICS.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # Persist a small parity sample so tests can compare pure-Python inference with scikit-learn.
    sample = test_df.sample(n=50, random_state=SEED)
    parity = [
        {"text": t, "proba": round(float(p), 6)}
        for t, p in zip(sample["text"], model.predict_proba(vectorizer.transform(sample["text"]))[:, 1], strict=True)
    ]
    (ROOT / "evaluation" / "parity_sample.json").write_text(json.dumps(parity, indent=1), encoding="utf-8")

    print(json.dumps(metrics["test_metrics"], indent=2))
    print(f"Wrote {ARTIFACT.relative_to(ROOT.parent)} ({ARTIFACT.stat().st_size // 1024} KiB)")
    np.random.seed(SEED)


if __name__ == "__main__":
    main()
