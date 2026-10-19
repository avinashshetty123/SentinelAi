# ML baseline evaluation

## Dataset

- **Name:** UCI SMS Spam Collection (Almeida & Gómez Hidalgo, 2011)
- **Source:** https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- **License:** CC BY 4.0
- **File SHA-256:** `7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d`
- **Raw counts:** 4 827 ham and 747 spam.
- **Validation:** every line must be `ham|spam<TAB>text`. Malformed lines abort training.
- **De-duplication:** messages are compared after lower-casing and collapsing whitespace. 4 517 ham and 642 spam remain. No texts had conflicting labels. De-duplicating *before* splitting prevents identical messages from appearing in both train and test, and an assertion in the training script enforces this.

## Procedure

`backend/ml/training/train.py`, reproduced with `python -m ml.training.train`:

- **Split:** stratified 80/20 with seed 42. Train has 4 127 rows (3 613 ham, 514 spam); test has 1 032 rows (904 ham, 128 spam).
- **Vectorizer:** `TfidfVectorizer(lowercase, token_pattern=\b\w\w+\b, ngram_range=(1,2), min_df=2, max_df=0.95, sublinear_tf, l2, max_features=15000)`.
- **Classifier:** `LogisticRegression(C=4.0, class_weight="balanced", solver="liblinear")`.
- **Decision threshold:** 0.5.
- **Environment:** scikit-learn 1.7.2.

The model is exported as portable JSON (`ml/artifacts/sms_spam_tfidf_lr.json`, 336 KiB) holding the vocabulary, IDF, coefficients and intercept. **No pickle is used.** Inference is pure Python, so the runtime image has no scikit-learn dependency. `tests/test_classifier.py` checks parity against scikit-learn on 50 held-out messages; the maximum difference is below 1e-4 (observed: 5e-7).

## Held-out results (test split, n = 1 032)

| Metric (spam = positive) | Value |
|---|---|
| Precision | 0.938 |
| Recall | 0.945 |
| F1 | 0.942 |
| ROC AUC | 0.997 |
| False-positive rate | 0.009 |
| Accuracy | 0.986 |

| | Predicted ham | Predicted spam |
|---|---|---|
| **Actual ham** | 896 | 8 |
| **Actual spam** | 7 | 121 |

These numbers come from `ml/evaluation/metrics.json`, which the training script writes. They are not hand-edited.

## How the model is used

- **Contribution:** the spam-class probability `p` adds `round(12 · min(1, (p − 0.5)/0.45))` points when `p ≥ 0.5`, capped at 12. The classifier alone cannot move a message out of LOW (< 25).
- **Display:** the UI shows the probability as a *spam-class probability* from this specific model, not a fraud probability.

## Limitations

- **Domain shift.** The data is 2011–2012 UK/Singapore SMS spam. Modern scams such as UPI collect requests, task scams, crypto investment and AI-written phishing are under-represented. The model has **not** been evaluated on such messages, so no claims are made about them.
- **Spam is not scam.** Marketing spam scores high and well-written scams may score low. That is why the classifier's weight is small and the rules carry the decision.
- **Language.** The model is English-only, and the bag-of-words approach ignores word order beyond bigrams.
- **Calibration and robustness.** Calibration was not separately evaluated; logistic regression is roughly calibrated, but class weighting shifts probabilities. Adversarial robustness was not evaluated.
- **No production feedback loop.** There is no retraining on user data, and none is planned, because raw text is not stored.

## LLM is not ML training

The Groq LLM is used for explanations at inference time. No model was trained or fine-tuned with Groq, and its outputs are never treated as ground truth for these metrics.
