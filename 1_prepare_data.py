"""
1_prepare_data.py  -  STEP 1: load and clean the data.

Data used (both public / synthetic, as the hackathon rules require):
  * CSIC 2010 HTTP dataset  (real traffic, already parsed into data/csic_parsed.csv)
  * A small SYNTHETIC set   (generic pages like /login, /search, generated below)
Every row is:  request text , label ("normal" or "attack") , source
"""
import random
import urllib.parse
import pandas as pd

random.seed(1)

# ---------- 1. load the real dataset ----------
csic = pd.read_csv("data/csic_parsed.csv")
print("CSIC rows:", len(csic))

# ---------- 2. build the synthetic dataset ----------
PATHS = ["/login", "/search", "/products", "/profile", "/download", "/comment", "/view", "/contact"]
PARAMS = ["id", "q", "user", "file", "name", "page", "comment", "email"]
BENIGN = ["laptop", "blue shirt", "john", "alice", "new york", "cheap flights", "python tutorial",
          "42", "1234", "hello world", "alice@example.com", "report.pdf", "images/logo.png",
          "select a size", "drop me a message", "union station timings", "O'Brien",
          "Tom & Jerry", "5 > 3 is true", "admin", "cats and dogs", "please delete my old post"]
ATTACKS = {
    "sqli": ["' OR '1'='1", "admin'--", "1; DROP TABLE users", "1 UNION SELECT username,password FROM users",
             "' OR 1=1 --", "1' AND SLEEP(5)--", "x' UNION SELECT NULL,NULL--", "1 OR 1=1",
             "'; EXEC xp_cmdshell('dir');--", "1' ORDER BY 3--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)", "<iframe src=javascript:alert(1)>",
            "\"><script>alert(document.domain)</script>", "<body onload=alert('XSS')>"],
    "path_traversal": ["../../etc/passwd", "..\\..\\windows\\win.ini", "../../../../etc/shadow",
                       "....//....//etc/passwd", "/var/www/../../etc/hosts", "../../boot.ini"],
    "cmd_injection": ["; ls -la", "| cat /etc/passwd", "&& whoami", "`id`", "$(whoami)",
                      "; ping -c 4 127.0.0.1", "| dir C:\\", "; cat /etc/shadow"],
}


def disguise(payload):
    """Make attacks harder: random UPPER/lower case and URL-encoding (like real attackers)."""
    if random.random() < 0.3:
        payload = "".join(c.upper() if random.random() < 0.5 else c.lower() for c in payload)
    if random.random() < 0.3:
        payload = urllib.parse.quote(payload)
    return payload


def make_request(value):
    """Wrap a value (benign or attack) into a GET or POST request."""
    path, param = random.choice(PATHS), random.choice(PARAMS)
    if random.random() < 0.6:
        return f"GET {path}?{param}={value}"
    return f"POST {path} BODY: {param}={value}"


rows = []
for family, payloads in ATTACKS.items():
    for _ in range(700):
        rows.append((make_request(disguise(random.choice(payloads))), "attack", "synthetic"))
for _ in range(3000):
    rows.append((make_request(random.choice(BENIGN)), "normal", "synthetic"))
synthetic = pd.DataFrame(rows, columns=["request", "label", "source"])

# ---------- 3. clean + combine ----------
data = pd.concat([csic, synthetic], ignore_index=True)
data = data.dropna()
data = data.drop_duplicates("request")          # duplicates would leak between train and test!
data = data.sample(frac=1, random_state=42).reset_index(drop=True)
data.to_csv("data/dataset.csv", index=False)

print("\nFinal dataset:", len(data), "unique requests")
print(data.groupby(["source", "label"]).size())
