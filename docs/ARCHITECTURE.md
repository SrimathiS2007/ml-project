# Architecture

```
HTTP request  ->  decode (URL-decode x2, lowercase)
              ->  features: TF-IDF char n-grams  +  12 security counts
              ->  Logistic Regression  ->  probability of attack
              ->  risk score 0-100, level (Low/Medium/High/Critical)
              ->  category (SQLi / XSS / traversal / command injection) + explanation
              ->  dashboard  (scan, simulation mode, live log)  and demo firewall (HTTP 403)
```

| Step | File |
|---|---|
| 1 Load + clean data | `1_prepare_data.py` |
| 2 Feature engineering | `features.py` + top of `2_train_models.py` |
| 3 Train + compare models, metrics, charts | `2_train_models.py` |
| 4 Predict + explain one request | `detector.py` |
| 5 Dashboard + API | `app.py`, `templates/index.html` |
| 6 Tests on unseen payloads | `3_test_examples.py` |
| 7 Report | `4_make_report.py` -> `reports/EVALUATION_REPORT.md` |
