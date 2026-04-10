import json
from urllib.request import Request, urlopen

GEMINI_API_KEY="AIzaSyBYYp-8e3fPHjBDql5yfSpt2R0uEoMIyfQ"
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={GEMINI_API_KEY}"

req = Request(url, headers={"User-Agent": "InfraSentinel-CI/1.0"}, method="GET")

with urlopen(req, timeout=10) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    for m in data.get("models", []):
        print(m.get("name"))
