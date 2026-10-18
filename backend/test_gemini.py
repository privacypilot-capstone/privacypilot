"""Run this from backend/ folder: python test_gemini.py
It tries several model names and reports which ones actually work."""
import os, requests
from dotenv import load_dotenv
load_dotenv()

key = os.getenv("GEMINI_API_KEY", "")
if not key:
    print("ERROR: GEMINI_API_KEY not in .env")
    exit(1)

# First: list all models the API key can see
print("Fetching available models...")
r = requests.get(
    f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
    timeout=15
)
if r.status_code == 200:
    models = r.json().get("models", [])
    print(f"Found {len(models)} models. Those supporting generateContent:")
    for m in models:
        if "generateContent" in m.get("supportedGenerationMethods", []):
            print(f"  {m['name']}")
else:
    print(f"Could not list models: {r.status_code} {r.text[:200]}")
    print()
    # Fallback: try common names
    candidates = [
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
        "gemini-2.5-flash",
        "gemini-2.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-flash-latest",
        "gemini-pro",
    ]
    print("Trying candidate model names:")
    payload = {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
    for name in candidates:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{name}:generateContent?key={key}"
        resp = requests.post(url, json=payload, timeout=10)
        status = "✅ WORKS" if resp.status_code == 200 else f"❌ {resp.status_code}"
        print(f"  {name}: {status}")
