"""
app.py  -  The web dashboard (Flask).   Run:  python app.py   then open http://127.0.0.1:5000

Pages / API:
  /                  dashboard (scan a request, simulation mode, live log)
  /api/scan          POST  -> analyse one request
  /api/simulate      GET   -> replay a random held-out test request and compare with the truth
  /api/stats         GET   -> counters + log
  /protected/...     demo firewall: attacks get HTTP 403
"""
import datetime
import pandas as pd
from flask import Flask, request, jsonify, render_template
from detector import Detector, make_request

app = Flask(__name__)
detector = Detector()
samples = pd.read_csv("data/test_samples.csv")            # requests the model never saw in training

stats = {"total": 0, "blocked": 0, "TP": 0, "FP": 0, "TN": 0, "FN": 0, "categories": {}}
log = []


def record(result, truth=None):
    """Update counters and the live log."""
    stats["total"] += 1
    if result["is_attack"]:
        stats["blocked"] += 1
        stats["categories"][result["category"]] = stats["categories"].get(result["category"], 0) + 1
    if truth:                                             # only in simulation mode we know the truth
        real_attack = truth == "attack"
        if real_attack and result["is_attack"]: stats["TP"] += 1
        elif real_attack: stats["FN"] += 1
        elif result["is_attack"]: stats["FP"] += 1
        else: stats["TN"] += 1
    log.insert(0, {"time": datetime.datetime.now().strftime("%H:%M:%S"), "request": result["request"][:100],
                   "action": result["action"], "score": result["risk_score"], "level": result["risk_level"],
                   "category": result["category"], "truth": truth or ""})
    del log[100:]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    j = request.json
    result = detector.analyze(make_request(j["method"], j["path"], j["params"], j["body"]))
    record(result)
    return jsonify(result)


@app.route("/api/simulate")
def simulate():
    row = samples.sample(1).iloc[0]
    result = detector.analyze(row["request"])
    record(result, truth=row["label"])
    result["truth"] = row["label"]
    return jsonify(result)


@app.route("/api/stats")
def get_stats():
    tp, fp, tn, fn = stats["TP"], stats["FP"], stats["TN"], stats["FN"]
    live = {"detection_rate": tp / max(tp + fn, 1), "fpr": fp / max(fp + tn, 1), "known": tp + fp + tn + fn}
    return jsonify({**stats, "live": live, "log": log[:20]})


@app.route("/api/reset", methods=["POST"])
def reset():
    stats.update(total=0, blocked=0, TP=0, FP=0, TN=0, FN=0, categories={})
    log.clear()
    return jsonify(ok=True)


@app.before_request
def firewall():
    """Demo WAF: every request to /protected/... is scanned by the ML model first."""
    if request.path.startswith("/protected"):
        text = make_request(request.method, request.path, request.query_string.decode(), request.get_data(as_text=True))
        result = detector.analyze(text)
        record(result)
        if result["is_attack"]:
            return jsonify(blocked=True, category=result["category"], risk_score=result["risk_score"]), 403


@app.route("/protected/<path:page>", methods=["GET", "POST"])
def protected(page):
    return jsonify(status="request allowed", page=page)


if __name__ == "__main__":
    app.run(port=5000)
