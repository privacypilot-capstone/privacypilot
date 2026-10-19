# PrivacyPilot

DPDP Act 2023 compliance engine. It scans a GitHub repository's source code and its privacy policy, then reports where the code's handling of personal data is not covered by the policy.

## Checks

| Check | Provision | Implemented in |
| --- | --- | --- |
| Notice Gap — PII in code but not in the policy | Section 5 / Section 6(1) | `backend/dpdp/rule_engine.py` |
| Third-Party Transmission — PII sent to an SDK, HTTP call or queue | Section 5 / Section 8(2) | `rule_engine.py`, `scanners/sinks.py` |
| PII in Logger Output | Section 8(5) | `rule_engine.py`, `scanners/sinks.py` |
| Purpose–PII Linkage — code use not covered by a stated purpose | Section 6(1) | `rule_engine.py`, `scanners/code_scanner.py`, `scanners/policy_parser.py` |
| Vague Purpose Statement | DPDP Rules 2025, Rule 3(b)(ii) | `scanners/policy_parser.py`, `rule_engine.py` |

Severity tiers (Aadhaar, PAN, health, financial and biometric data are treated as "critical") are a design choice of this project; the Act itself does not define a sensitive-data class. This tool is a research prototype and does not give legal advice.

## Setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt  # includes celery, sentence-transformers, reportlab and en_core_web_lg
```

Check what is installed: `GET http://localhost:8000/health` lists every optional component and reports `"degraded"` if any is missing (for example, without `sentence-transformers` the Rule 3(b)(ii) check cannot run).

Run the stack:

```bash
docker compose up               # backend, worker, Postgres, Redis
cd frontend && npm install && npm run dev
```

## Tests

```bash
pytest -q tests
```

`tests/test_production.py` imports and runs the real backend modules; each test is tagged with the audit defect it guards. Add a test there for every new feature or fix.

`prototypes/` holds the early feasibility scripts used to check whether each planned strategy would work. They carry their own copies of the logic, are not part of the test suite, and are kept for reference only.
