"""4_make_report.py - writes reports/EVALUATION_REPORT.md from the real metric files."""
import json
import pandas as pd

m = json.load(open("reports/metrics.json"))
o = m["overall"]
comp = pd.read_csv("reports/model_comparison.csv", index_col=0)

lines = ["| Model | Precision | Recall (Detection Rate) | F1 | False Positive Rate | False Negative Rate | ROC-AUC |", "|---|---|---|---|---|---|---|"]
for name, r in comp.iterrows():
    lines.append(f"| {name} | {r.Precision:.4f} | {r.Recall:.4f} | {r.F1:.4f} | {r.FPR:.4f} | {r.FNR:.4f} | {r.ROC_AUC:.4f} |")
comparison_table = "\n".join(lines)

src = ["| Test subset | Precision | Recall | F1 | FPR | FNR |", "|---|---|---|---|---|---|"]
for s, r in m["per_source"].items():
    src.append(f"| {s} | {r['Precision']:.4f} | {r['Recall']:.4f} | {r['F1']:.4f} | {r['FPR']:.4f} | {r['FNR']:.4f} |")
source_table = "\n".join(src)

open("reports/EVALUATION_REPORT.md", "w").write(f"""# Evaluation Report - Intelligent Web Attack Detection

## 1. Data and preprocessing
- **Real data:** CSIC 2010 HTTP dataset (public) - 34,594 unique requests after removing duplicates.
- **Synthetic data:** generic requests (/login, /search ...) with SQLi, XSS, path traversal, command injection.
- **Cleaning:** removed empty rows and duplicate requests (duplicates would leak between train and test), URL-decoded twice.
- **Split:** 80% training ({m['n_train']} requests) / 20% test ({m['n_test']} requests), stratified.

## 2. Features
- **Text (NLP):** TF-IDF on character n-grams (length 2-4).
- **Security features (12):** length, number of parameters, special characters, quotes, angle brackets, SQL keywords, SQL tautology (OR 1=1), SQL comments, XSS keywords, traversal patterns, shell-command patterns, percent-encoded characters.

## 3. Model comparison (test set)
{comparison_table}

![comparison](model_comparison.png)

## 4. Deployed model: Logistic Regression
| Metric | Value |
|---|---|
| Precision | {o['Precision']:.4f} |
| Recall = Detection Rate | {o['Recall']:.4f} |
| F1-score | {o['F1']:.4f} |
| False Positive Rate | {o['FPR']:.4f} |
| False Negative Rate | {o['FNR']:.4f} |
| TP / FP / TN / FN | {o['TP']} / {o['FP']} / {o['TN']} / {o['FN']} |

{source_table}

![confusion](confusion_matrix.png)
![patterns](top_attack_patterns.png)

## 5. Security interpretation
- **False Positive Rate ({o['FPR']*100:.2f}%)**: share of normal requests wrongly blocked - keeps real users happy.
- **False Negative Rate ({o['FNR']*100:.2f}%)**: share of attacks that got through. Most misses are subtle CSIC "parameter tampering" requests without an obvious payload.
- **Why Logistic Regression is deployed:** almost as accurate as Linear SVM, but it outputs a probability (our risk score) and its weights show which patterns caused the alert (explainability).
- **Random Forest / Naive Bayes** are weaker because they use only one kind of feature. **Isolation Forest** (anomaly detection, no labels) is weakest but needs no attack examples.
- The synthetic subset scores ~100% because it is simple and repetitive; the CSIC result is the honest, harder benchmark.

## 6. Limitations and future work
- CSIC 2010 is old and covers a single web shop.
- The attack family (SQLi, XSS ...) is decided by simple rules on the features, because CSIC only has normal/attack labels.
- Future: newer datasets, HTTP header features, deep learning, drift monitoring.
""")
print("report written")
