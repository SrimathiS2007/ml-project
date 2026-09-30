"""
features.py  -  Turn a raw HTTP request into numbers the ML model can learn from.

Two kinds of features are used:
  1. TEXT features  : TF-IDF over character n-grams (done in 2_train_models.py)
  2. SECURITY features: 12 simple counts written by us (this file)
"""
import re
import urllib.parse
import numpy as np


def decode(text):
    """Attackers hide payloads with URL-encoding (%27 = ').  We decode TWICE
    (to catch double-encoding like %2527) and lowercase everything."""
    text = str(text)
    for _ in range(2):
        text = urllib.parse.unquote_plus(text, encoding="latin-1")
    return text.lower()


# ---- keyword lists that are typical for each attack family ----
SQL_WORDS = ["select", "union", "insert", "update", "delete", "drop", "from", "where",
             "sleep", "exec", "having", "order by", "information_schema"]
SQL_REGEX = re.compile(r"\b(" + "|".join(SQL_WORDS) + r")\b")
TAUTOLOGY = re.compile(r"(or|and)\W*\w+\W*=\W*\w+")          # e.g.  OR 1=1   /  OR 'a'='a'
XSS_WORDS = ["<script", "onerror", "onload", "javascript:", "alert(", "<img", "<svg", "<iframe", "document.cookie"]
TRAVERSAL_WORDS = ["../", "..\\", "/etc/passwd", "/etc/shadow", "win.ini", "boot.ini"]
SHELL_SEPARATORS = [";", "|", "&&", "`"]
SHELL_COMMANDS = ["ls", "cat", "whoami", "id", "ping", "dir", "wget", "curl", "uname"]

# names of the 12 security features (same order as the matrix columns)
FEATURE_NAMES = ["length", "num_params", "special_chars", "quotes", "angle_brackets",
                 "sql_words", "sql_tautology", "sql_comment", "xss_words",
                 "traversal_words", "cmd_words", "encoded_percent"]

# friendly names used in the explanation shown to the user
FEATURE_LABELS = {"sql_words": "SQL keywords", "sql_tautology": "SQL tautology (OR 1=1 style)",
                  "sql_comment": "SQL comment markers (-- or /*)", "xss_words": "XSS keywords (<script, onerror ...)",
                  "traversal_words": "Path traversal patterns (../, /etc/passwd)",
                  "cmd_words": "Shell command injection patterns", "quotes": "Quote characters",
                  "angle_brackets": "Angle brackets < >"}


def extract_features(raw):
    """Return a dictionary with the 12 security features of ONE request."""
    text = decode(raw)
    compact = text.replace(" ", "")                            # "; cat" -> ";cat"
    cmd_count = compact.count("$(")
    for sep in SHELL_SEPARATORS:
        for cmd in SHELL_COMMANDS:
            cmd_count += compact.count(sep + cmd)
    return {
        "length": len(text),
        "num_params": text.count("="),
        "special_chars": sum(text.count(c) for c in "'\"<>;|&`$(){}[]\\*"),
        "quotes": text.count("'") + text.count('"'),
        "angle_brackets": text.count("<") + text.count(">"),
        "sql_words": len(SQL_REGEX.findall(text)),
        "sql_tautology": len(TAUTOLOGY.findall(compact)),
        "sql_comment": text.count("--") + text.count("/*"),
        "xss_words": sum(text.count(w) for w in XSS_WORDS),
        "traversal_words": sum(text.count(w) for w in TRAVERSAL_WORDS),
        "cmd_words": cmd_count,
        "encoded_percent": str(raw).count("%"),
    }


def features_matrix(requests):
    """Feature table for many requests: one row per request, 12 columns."""
    rows = []
    for r in requests:
        f = extract_features(r)
        rows.append([f[name] for name in FEATURE_NAMES])
    return np.array(rows, dtype=float)


def categorize(f):
    """Decide WHICH attack family it looks like (security interpretation)."""
    scores = {
        "SQL Injection": f["sql_words"] + 2 * f["sql_tautology"] + f["sql_comment"],
        "Cross-Site Scripting (XSS)": 3 * f["xss_words"],
        "Path Traversal": 3 * f["traversal_words"],
        "Command Injection": 4 * f["cmd_words"],
    }
    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else "Suspicious request / parameter tampering"


RECOMMENDATION = {
    "SQL Injection": "Use parameterized queries (prepared statements) and a least-privilege database user.",
    "Cross-Site Scripting (XSS)": "Encode all output, validate input and add a Content-Security-Policy header.",
    "Path Traversal": "Never build file paths from user input; allow only a fixed list of files.",
    "Command Injection": "Avoid calling the OS shell; use safe library functions and allow-lists.",
    "Suspicious request / parameter tampering": "Validate parameter names, types and lengths against what the page expects.",
}


def risk_level(prob):
    """Convert attack probability (0-1) into a risk level."""
    if prob >= 0.90: return "Critical"
    if prob >= 0.70: return "High"
    if prob >= 0.40: return "Medium"
    return "Low"
