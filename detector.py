"""
detector.py  -  Uses the trained model on ONE request and explains the decision.
Used by both the dashboard (app.py) and the test script.
"""
import joblib
from scipy.sparse import hstack, csr_matrix
from features import (decode, extract_features, features_matrix, categorize,
                      risk_level, RECOMMENDATION, FEATURE_LABELS)


class Detector:
    def __init__(self, path="models/model.pkl"):
        saved = joblib.load(path)
        self.vectorizer = saved["vectorizer"]
        self.scaler = saved["scaler"]
        self.model = saved["model"]
        self.ngrams = self.vectorizer.get_feature_names_out()

    def analyze(self, raw):
        # 1. same feature pipeline as in training
        tfidf = self.vectorizer.transform([raw])
        hand = self.scaler.transform(features_matrix([raw]))
        X = hstack([tfidf, csr_matrix(hand)]).tocsr()

        # 2. the model's probability of "attack" IS the risk score
        prob = float(self.model.predict_proba(X)[0, 1])
        is_attack = prob >= 0.5
        f = extract_features(raw)

        result = {
            "request": raw,
            "action": "BLOCK" if is_attack else "ALLOW",
            "is_attack": is_attack,
            "risk_score": round(prob * 100, 1),
            "risk_level": risk_level(prob),
            "category": categorize(f) if is_attack else "Benign",
        }
        result["recommendation"] = RECOMMENDATION[result["category"]] if is_attack else "No action needed."
        result.update(self.explain(raw, X, f))
        return result

    def explain(self, raw, X, f):
        """Explainable AI: which parts of the request pushed the score up?
        contribution of a pattern = (its TF-IDF value) x (its weight in Logistic Regression)"""
        text = decode(raw)
        n = len(self.ngrams)
        contributions = X.multiply(self.model.coef_[0]).tocsr()
        scored = [(self.ngrams[i], v) for i, v in zip(contributions.indices, contributions.data) if i < n and v > 0]
        top = sorted(scored, key=lambda t: -t[1])[:6]

        # mark the suspicious patterns inside the decoded request
        hot = [False] * len(text)
        for gram, _ in top:
            pos = text.find(gram)
            while pos != -1:
                for k in range(pos, pos + len(gram)):
                    hot[k] = True
                pos = text.find(gram, pos + 1)
        pieces, current, state = [], "", None
        for ch, h in zip(text, hot):
            if state is not None and h != state:
                pieces.append({"text": current, "hot": state}); current = ""
            current += ch; state = h
        if current:
            pieces.append({"text": current, "hot": state})

        # plain-language reasons from the security features
        reasons = [f"{label}: {f[key]}" for key, label in FEATURE_LABELS.items() if f[key] > 0]
        return {"highlight": pieces, "top_patterns": [g for g, _ in top], "reasons": reasons}


def make_request(method, path, params="", body=""):
    """Build the same text format that was used for training."""
    text = f"{method} {path}"
    if params:
        text += "?" + params
    if body:
        text += " BODY: " + body
    return text
