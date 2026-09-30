"""
2_train_models.py  -  STEPS 2-4: feature engineering, train & compare models, evaluate.

Flow:  dataset.csv -> split train/test -> features -> 5 models -> metrics -> save best explainable model
"""
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import confusion_matrix, roc_auc_score
from features import decode, features_matrix

# ---------- 1. load data and split 80% train / 20% test ----------
data = pd.read_csv("data/dataset.csv")
data["y"] = (data["label"] == "attack").astype(int)          # 1 = attack, 0 = normal
train, test = train_test_split(data, test_size=0.2, random_state=42,
                               stratify=data["label"] + data["source"])
y_train, y_test = train["y"].values, test["y"].values
print("train:", len(train), " test:", len(test))

# ---------- 2. feature engineering ----------
# (a) TEXT features: TF-IDF on character n-grams of length 2-4  (NLP idea:
#     the model learns pieces such as "<sc", "or 1", "../" that appear in attacks)
vectorizer = TfidfVectorizer(preprocessor=decode, analyzer="char", ngram_range=(2, 4),
                             max_features=30000, sublinear_tf=True, min_df=3)
T_train = vectorizer.fit_transform(train["request"])
T_test = vectorizer.transform(test["request"])

# (b) SECURITY features: 12 counts from features.py, scaled to a similar range
scaler = StandardScaler()
H_train = scaler.fit_transform(features_matrix(train["request"]))
H_test = scaler.transform(features_matrix(test["request"]))

# (c) combine both kinds side by side
X_train = hstack([T_train, csr_matrix(H_train)]).tocsr()
X_test = hstack([T_test, csr_matrix(H_test)]).tocsr()


# ---------- 3. security metrics ----------
def evaluate(y_true, y_pred, score):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)                       # = Detection Rate
    return {"Precision": precision, "Recall": recall,
            "F1": 2 * precision * recall / (precision + recall),
            "FPR": fp / (fp + tn),                # normal traffic wrongly blocked
            "FNR": fn / (fn + tp),                # attacks missed
            "DetectionRate": recall,
            "ROC_AUC": roc_auc_score(y_true, score),
            "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn)}


# ---------- 4. train and compare models ----------
results = {}

lr = LogisticRegression(C=5, max_iter=2000).fit(X_train, y_train)
results["Logistic Regression"] = evaluate(y_test, lr.predict(X_test), lr.predict_proba(X_test)[:, 1])

svm = LinearSVC(C=0.5).fit(X_train, y_train)
results["Linear SVM"] = evaluate(y_test, svm.predict(X_test), svm.decision_function(X_test))

nb = MultinomialNB(alpha=0.1).fit(T_train, y_train)                # Naive Bayes: text features only
results["Naive Bayes"] = evaluate(y_test, nb.predict(T_test), nb.predict_proba(T_test)[:, 1])

rf = RandomForestClassifier(n_estimators=150, random_state=0, n_jobs=-1)
rf.fit(H_train, y_train)                                           # Random Forest: security features only
results["Random Forest"] = evaluate(y_test, rf.predict(H_test), rf.predict_proba(H_test)[:, 1])

# Anomaly detection (no labels!): learn what NORMAL looks like, flag anything different
iso = IsolationForest(n_estimators=150, contamination=0.05, random_state=0)
iso.fit(H_train[y_train == 0])
iso_pred = (iso.predict(H_test) == -1).astype(int)
results["Isolation Forest (anomaly)"] = evaluate(y_test, iso_pred, -iso.decision_function(H_test))

table = pd.DataFrame(results).T.round(4)
print("\n", table[["Precision", "Recall", "F1", "FPR", "FNR", "ROC_AUC"]])
table.to_csv("reports/model_comparison.csv")

# ---------- 5. save the deployed model ----------
# We deploy Logistic Regression: it gives a probability (= risk score) and its weights
# tell us which n-grams/features pushed a request towards "attack" (explainable AI).
joblib.dump({"vectorizer": vectorizer, "scaler": scaler, "model": lr}, "models/model.pkl", compress=3)
test[["request", "label", "source"]].sample(1000, random_state=1).to_csv("data/test_samples.csv", index=False)

# metrics per data source (real CSIC vs synthetic)
pred = lr.predict(X_test)
per_source = {}
for s in test["source"].unique():
    m = (test["source"] == s).values
    per_source[s] = evaluate(y_test[m], pred[m], lr.predict_proba(X_test[m])[:, 1])
json.dump({"deployed": "Logistic Regression", "overall": results["Logistic Regression"],
           "per_source": per_source, "n_train": len(train), "n_test": len(test)},
          open("reports/metrics.json", "w"), indent=2)

# ---------- 6. charts ----------
names = list(results.keys())
x = np.arange(len(names))
plt.figure(figsize=(9, 4.5))
for i, metric in enumerate(["Precision", "Recall", "F1"]):
    plt.bar(x + (i - 1) * 0.27, [results[n][metric] for n in names], 0.27, label=metric)
plt.xticks(x, names, rotation=15, ha="right", fontsize=9)
plt.ylim(0, 1.05); plt.legend(); plt.title("Model comparison (test set)")
plt.tight_layout(); plt.savefig("reports/model_comparison.png", dpi=130); plt.close()

cm = confusion_matrix(y_test, pred)
plt.figure(figsize=(4.5, 4)); plt.imshow(cm, cmap="Blues")
plt.xticks([0, 1], ["normal", "attack"]); plt.yticks([0, 1], ["normal", "attack"])
for i in range(2):
    for j in range(2):
        plt.text(j, i, cm[i, j], ha="center", va="center", fontsize=14,
                 color="white" if cm[i, j] > cm.max() / 2 else "black")
plt.xlabel("Predicted"); plt.ylabel("Actual"); plt.title("Confusion matrix (deployed model)")
plt.tight_layout(); plt.savefig("reports/confusion_matrix.png", dpi=130); plt.close()

ngrams = vectorizer.get_feature_names_out()
top = np.argsort(lr.coef_[0][:len(ngrams)])[-15:]
plt.figure(figsize=(6, 5)); plt.barh([repr(ngrams[i]) for i in top], lr.coef_[0][top], color="crimson")
plt.title("Character patterns that signal an attack"); plt.tight_layout()
plt.savefig("reports/top_attack_patterns.png", dpi=130); plt.close()
print("\nSaved: models/model.pkl and reports/*")
