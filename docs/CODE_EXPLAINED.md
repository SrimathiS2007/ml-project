# How to explain this project (viva guide)

## 30-second pitch
"Normal firewalls use fixed rules, so attackers bypass them with encoding and tricks. Our system **learns** attack patterns
from real traffic (CSIC 2010). For every HTTP request it gives a **risk score, the attack type and an explanation**."

## The pipeline in 5 sentences
1. **Data** (`1_prepare_data.py`): real CSIC 2010 requests + small synthetic set; we remove duplicates and shuffle.
2. **Features** (`features.py`): we decode the request, then compute 12 counts (SQL words, quotes, `<script`, `../` ...) and TF-IDF of character pieces.
3. **Training** (`2_train_models.py`): 80% of the data trains 5 models, 20% (never seen) tests them.
4. **Evaluation**: Precision, Recall, F1, False Positive Rate, False Negative Rate, Detection Rate.
5. **Prediction** (`detector.py`): probability of attack = risk score; the model's weights tell which patterns caused it.

## File by file
| File | What it does | Key idea to say |
|---|---|---|
| `features.py` | request -> 12 numbers | attackers leave traces: quotes, `union select`, `../`, `<script` |
| `1_prepare_data.py` | builds `dataset.csv` | drop duplicates, otherwise the same request is in train and test |
| `2_train_models.py` | trains and compares models | one shared feature matrix, five models, same test set |
| `detector.py` | risk score + explanation | contribution = TF-IDF value x model weight |
| `app.py` | Flask website + API | `/api/scan`, `/api/simulate`, `/protected` firewall |

## Key concepts (be ready)
- **TF-IDF on character n-grams**: cut text into 2-4 letter pieces (`"or "`, `"<sc"`), weight rare-but-telling pieces higher. Works even when the attacker changes case or spacing.
- **Why decode twice**: `%2527` -> `%27` -> `'`. Attackers double-encode to hide.
- **Logistic Regression**: one weight per feature; sum -> probability. Positive weight = pushes to "attack". That is why it is *explainable*.
- **Linear SVM**: similar, slightly higher score, but no direct probability.
- **Naive Bayes / Random Forest**: only one feature type each, so weaker.
- **Isolation Forest**: anomaly detection - trained ONLY on normal traffic, flags requests that look different. No attack labels needed.
- **Precision** = of blocked requests, how many were real attacks. **Recall / Detection Rate** = of all attacks, how many we caught.
  **FPR** = normal requests wrongly blocked. **FNR** = attacks missed. **F1** = balance of precision and recall.
- **Risk levels**: score >= 90 Critical, >= 70 High, >= 40 Medium, else Low. Score >= 50 is blocked.
- **Simulation mode**: replays held-out test requests one by one, so live numbers are honest.

## Likely questions
- *Why not just regex rules?* They miss obfuscated variants and cannot rank risk; ML generalises from examples.
- *Why is Logistic Regression deployed if SVM is slightly better?* Probability + explainability matter more than +0.2% F1 for a security analyst.
- *Why is synthetic accuracy ~100%?* It is repetitive; CSIC is the honest benchmark.
- *Limitations?* Old dataset, one web app, category by rules, no header features.
- *Is it safe?* Requests are only analysed as text; nothing is sent to any real target.
