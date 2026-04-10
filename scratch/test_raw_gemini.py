import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError

GEMINI_API_KEY="AIzaSyBYYp-8e3fPHjBDql5yfSpt2R0uEoMIyfQ"
model = "gemini-1.5-flash"
url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"

payload = {
    "contents": [{"parts": [{"text": "Hello"}]}]
}

req = Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urlopen(req, timeout=10) as resp:
        print(f"Success! Status: {resp.status}")
        print(resp.read().decode("utf-8"))
except HTTPError as exc:
    print(f"HTTP Error {exc.code}")
    print(exc.read().decode("utf-8"))
except Exception as exc:
    print(f"Error: {exc}")
