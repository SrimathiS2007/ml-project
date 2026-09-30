"""Parse the raw CSIC 2010 HTTP dataset into a clean CSV (request, label).

Download the 3 raw files (normalTrafficTraining.txt, normalTrafficTest.txt,
anomalousTrafficTest.txt) into data/raw/ and run:  python parse_csic.py
Source: Gimenez, Villegas, Marañón - "HTTP DATASET CSIC 2010" (CSIC, Spain).
"""
import re, sys, os, pandas as pd

START = re.compile(r"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/\d\.\d\s*$")
FILES = {"normalTrafficTraining.txt": "normal",
         "normalTrafficTest.txt": "normal",
         "anomalousTrafficTest.txt": "attack"}

def strip_host(url):
    return re.sub(r"^https?://[^/]+", "", url)

def parse_file(path, label):
    lines = open(path, encoding="latin-1").read().replace("\r", "").split("\n")
    out, i, n = [], 0, len(lines)
    while i < n:
        m = START.match(lines[i])
        if not m:
            i += 1; continue
        method, url = m.group(1), strip_host(m.group(2))
        i += 1; clen = 0
        while i < n and lines[i].strip() != "":
            if lines[i].lower().startswith("content-length:"):
                try: clen = int(lines[i].split(":")[1])
                except ValueError: clen = 0
            i += 1
        i += 1                                   # blank line after headers
        body = ""
        if clen > 0 and i < n and not START.match(lines[i]):
            body = lines[i]; i += 1
        req = f"{method} {url}" + (f" BODY: {body}" if body else "")
        out.append((req, label))
    return out

if __name__ == "__main__":
    raw = sys.argv[1] if len(sys.argv) > 1 else "data/raw"
    rows = []
    for f, lab in FILES.items():
        p = os.path.join(raw, f)
        r = parse_file(p, lab); print(f, len(r)); rows += r
    df = pd.DataFrame(rows, columns=["request", "label"])
    before = len(df)
    df = df.drop_duplicates("request").reset_index(drop=True)   # avoid train/test leakage
    df["source"] = "csic2010"
    df.to_csv("data/csic_parsed.csv", index=False)
    print(f"{before} parsed -> {len(df)} unique requests"); print(df.label.value_counts())
