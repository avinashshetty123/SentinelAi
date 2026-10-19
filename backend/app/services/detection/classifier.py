"""Pure-Python inference for the exported TF-IDF + logistic-regression baseline.

The model was trained on the UCI SMS Spam Collection (spam vs. ham, 2011–2012 SMS). It detects
*spam-like language*; it was not trained on modern scam categories and its probability is not a fraud
probability. Its score contribution is bounded by the scoring engine.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinel.classifier")


@dataclass(frozen=True)
class ClassifierPrediction:
    spam_probability: float
    model_version: str


class TfidfLogRegClassifier:
    def __init__(self, artifact: dict[str, Any]) -> None:
        if artifact.get("type") != "tfidf_logistic_regression":
            raise ValueError("Unsupported classifier artifact type")
        tokenizer = artifact["tokenizer"]
        self.model_version: str = artifact["model_version"]
        self.lowercase: bool = tokenizer["lowercase"]
        self.token_re = re.compile(tokenizer["token_pattern"])
        self.ngram_min, self.ngram_max = tokenizer["ngram_range"]
        self.sublinear_tf: bool = artifact["sublinear_tf"]
        self.vocabulary: dict[str, int] = artifact["vocabulary"]
        self.idf: list[float] = artifact["idf"]
        self.coef: list[float] = artifact["coef"]
        self.intercept: float = artifact["intercept"]
        self.metrics_summary: dict[str, Any] = artifact.get("metrics_summary", {})
        self.dataset: dict[str, Any] = artifact.get("dataset", {})
        if not (len(self.idf) == len(self.coef) == len(self.vocabulary)):
            raise ValueError("Classifier artifact dimensions are inconsistent")

    def _ngrams(self, text: str) -> list[str]:
        tokens = self.token_re.findall(text.lower() if self.lowercase else text)
        grams: list[str] = []
        for n in range(self.ngram_min, self.ngram_max + 1):
            if n == 1:
                grams.extend(tokens)
            else:
                grams.extend(" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1))
        return grams

    def predict(self, text: str) -> ClassifierPrediction:
        counts = Counter(self.vocabulary[g] for g in self._ngrams(text) if g in self.vocabulary)
        weights: dict[int, float] = {}
        for idx, tf in counts.items():
            value = (1.0 + math.log(tf)) if self.sublinear_tf else float(tf)
            weights[idx] = value * self.idf[idx]
        norm = math.sqrt(sum(v * v for v in weights.values()))
        z = self.intercept
        if norm > 0:
            z += sum((v / norm) * self.coef[idx] for idx, v in weights.items())
        probability = 1.0 / (1.0 + math.exp(-z)) if z > -700 else 0.0
        return ClassifierPrediction(spam_probability=probability, model_version=self.model_version)


_classifier: TfidfLogRegClassifier | None = None
_load_error: str | None = None


def load_classifier(path: Path) -> TfidfLogRegClassifier | None:
    global _classifier, _load_error
    try:
        _classifier = TfidfLogRegClassifier(json.loads(path.read_text(encoding="utf-8")))
        _load_error = None
    except FileNotFoundError:
        _classifier, _load_error = None, "artifact_missing"
    except (ValueError, KeyError, json.JSONDecodeError):
        _classifier, _load_error = None, "artifact_invalid"
        logger.warning("Classifier artifact could not be loaded")
    return _classifier


def get_classifier() -> TfidfLogRegClassifier | None:
    return _classifier


def classifier_load_error() -> str | None:
    return _load_error
