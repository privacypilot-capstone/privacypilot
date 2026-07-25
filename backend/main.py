from fastapi import FastAPI

app = FastAPI(title="PrivacyPilot API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok", "message": "PrivacyPilot is running"}

@app.get("/")
def root():
    return {"project": "PrivacyPilot", "team": ["K040", "K042", "K059"]}