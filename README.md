# 🛡️ Intelligent Web Attack Detection (ML for Cybersecurity)
Detects **SQL injection, XSS, path traversal and command injection** in HTTP requests and returns a
**risk score, threat category and explanation**. Built for SIH1750 (web application security).

## Run it (VS Code terminal, in this folder)
```bash
python -m venv venv
venv\Scripts\activate           # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
python app.py                   # open http://127.0.0.1:5000
```
The model is already trained. To retrain everything from scratch (about 2 minutes): `python 1_prepare_data.py`, `python 2_train_models.py`, `python 3_test_examples.py`, `python 4_make_report.py` (or `run_all.bat`).

## Deliverables
| Deliverable | Where |
|---|---|
| Source code | `features.py`, `1_prepare_data.py`, `2_train_models.py`, `detector.py`, `app.py`, `templates/` |
| Dataset / reference | `data/` + `data/DATASET_REFERENCE.md` |
| Trained model | `models/model.pkl` |
| Architecture | `docs/ARCHITECTURE.md` |
| Evaluation report | `reports/EVALUATION_REPORT.md` (+ charts, `model_comparison.csv`) |
| Working demo | `python app.py` |
| Presentation | `docs/Presentation.pptx` |
| Explain-the-code guide | `docs/CODE_EXPLAINED.md` |

## Requirements covered
Load and clean data · feature engineering (TF-IDF + 12 security features) · 5 models compared (Logistic Regression, Linear SVM, Naive Bayes, Random Forest, Isolation Forest anomaly detection) ·
Precision / Recall / F1 / FPR / FNR / Detection Rate · Explainable AI · real-time simulation mode · interactive dashboard · demo firewall.

## Demo script
1. Dashboard → click **Benign search** (ALLOWED), then **SQL injection**, **XSS**, **Path traversal**, **Command injection**, **Encoded SQLi** (BLOCKED + highlighted evidence).
2. Click **Start simulation** and watch the live log, blocked counter, detection rate and false-positive rate.
3. Firewall: `curl "http://127.0.0.1:5000/protected/x?q=hello"` → 200, `curl "http://127.0.0.1:5000/protected/x?f=../../etc/passwd"` → 403.
4. `python 3_test_examples.py` → 18/18 unseen payloads correct.

## Safety
Requests are only analysed as text and never executed. Test only against your own local app.
