from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.services.detection.classifier import TfidfLogRegClassifier, load_classifier

ROOT = Path(__file__).resolve().parents[1]


def test_artifact_loads_and_parity_with_sklearn() -> None:
    classifier = load_classifier(get_settings().classifier_path)
    assert classifier is not None
    samples = json.loads((ROOT / "ml" / "evaluation" / "parity_sample.json").read_text(encoding="utf-8"))
    worst = max(abs(classifier.predict(s["text"]).spam_probability - s["proba"]) for s in samples)
    assert worst < 1e-4


def test_obvious_spam_vs_ham() -> None:
    classifier = load_classifier(get_settings().classifier_path)
    assert classifier is not None
    assert classifier.predict("WINNER! You have won a free prize. Call now to claim your cash award").spam_probability > 0.8
    assert classifier.predict("Are we still on for dinner at 7 tonight?").spam_probability < 0.3


def test_inconsistent_artifact_rejected() -> None:
    with pytest.raises(ValueError):
        TfidfLogRegClassifier({"type": "tfidf_logistic_regression", "model_version": "x",
                               "tokenizer": {"lowercase": True, "token_pattern": r"\w+", "ngram_range": [1, 1]},
                               "sublinear_tf": True, "vocabulary": {"a": 0}, "idf": [1.0, 2.0], "coef": [0.1],
                               "intercept": 0.0})


def test_missing_artifact_returns_none(tmp_path: Path) -> None:
    assert load_classifier(tmp_path / "missing.json") is None
    load_classifier(get_settings().classifier_path)  # restore for other tests
