import json
import os
from urllib.request import Request, urlopen
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={GEMINI_API_KEY}"

req = Request(url, headers={"User-Agent": "InfraSentinel-CI/1.0"}, method="GET")

with urlopen(req, timeout=10) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    for m in data.get("models", []):
        print(m.get("name"))
