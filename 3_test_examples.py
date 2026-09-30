"""
3_test_examples.py  -  Tries the detector on hand-written requests it has NEVER seen.
Run:  python 3_test_examples.py
"""
from detector import Detector

CASES = [  # (request, 0 = should be allowed, 1 = should be blocked)
    ("GET /search?q=running shoes", 0), ("POST /login BODY: user=alice&pwd=Summer2024", 0),
    ("GET /products?id=42&sort=price", 0), ("GET /profile?name=O'Neil", 0),
    ("GET /blog?title=how to select a good laptop", 0), ("GET /contact?msg=please drop me a line", 0),
    ("GET /login?user=admin' OR '1'='1", 1), ("GET /item?id=5 UNION SELECT user,pass FROM accounts--", 1),
    ("GET /item?id=1; DROP TABLE orders--", 1), ("GET /item?id=1%27%20oR%201%3D1%23", 1),
    ("GET /c?t=<script>alert(1)</script>", 1), ("GET /c?t=<img src=x onerror=alert(document.cookie)>", 1),
    ("GET /c?u=javascript:alert(1)", 1), ("GET /dl?f=../../../../etc/passwd", 1),
    ("GET /dl?f=..%2f..%2f..%2fwindows/win.ini", 1), ("GET /ping?h=127.0.0.1 | whoami", 1),
    ("GET /ping?h=`id`", 1), ("GET /ping?h=8.8.8.8 && cat /etc/shadow", 1),
]
detector = Detector()
correct = 0
for request, expected in CASES:
    r = detector.analyze(request)
    ok = int(r["is_attack"]) == expected
    correct += ok
    print("PASS" if ok else "FAIL", f"{r['risk_score']:5.1f}", f"{r['category']:<40}", request)
print(f"\n{correct}/{len(CASES)} correct")
