import requests, json

tests = [
    ("https://www.google.com", "benign"),
    ("https://www.youtube.com", "benign"),
    ("https://www.github.com", "benign"),
    ("https://www.microsoft.com", "benign"),
    ("https://www.amazon.com", "benign"),
    # Known phishing / malicious
    ("http://payp4l-secure-login.tk/verify?user=1&token=abc", "phishing"),
    ("https://faceb00k-login.cf/update/credentials", "phishing"),
]

print(f"{'URL':<50} {'GOT':12} {'EXPECTED':12} {'CONF':>8}  {'RISK':>6}")
print("-" * 100)
for url, expected in tests:
    r = requests.post("http://127.0.0.1:8000/analyze", json={"url": url})
    if r.status_code != 200:
        print(f"ERROR {r.status_code}: {url}")
        continue
    d = r.json()
    label    = d.get("label", "ERR")
    conf     = d.get("confidence", 0)
    risk     = d.get("risk_score", 0)
    ok = "OK" if label == expected else "FAIL"
    print(f"{url:<50} [{label:12}] [{expected:12}] {conf:>8.2%}  {risk:>6.4f}  {ok}")
