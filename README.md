# PrivacyPilot

DPDP Act 2023 compliance engine. It scans a GitHub repository's source code and its privacy policy, then reports where the code's handling of personal data is not covered by the policy.

## Checks

| Check | Provision | Implemented in |
| --- | --- | --- |
| Notice Gap — PII in code but not in the policy | Section 5 / Section 6(1) | `backend/dpdp/rule_engine.py` |
| Third-Party Transmission — PII sent to an SDK, HTTP call or queue | Section 8(2) | `rule_engine.py`, `scanners/sinks.py` |
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

## Large repositories

The whole repository is downloaded as one tarball (one API request) and every source file is scanned; vendored, minified, generated (`*.min.js`, `node_modules/`, `dist/` …) and >1 MB files are skipped. Only if the tarball download fails does the scanner fall back to fetching files one by one through the API, capped at 300 files (`MAX_API_FILES`), and then it refuses to start if the GitHub rate limit can't cover it. Presidio NER (the expensive step) runs once per file in a batch, only on lines where a kept result is possible, and only for the entity types used. Full `ohcnetwork/care` (1014 files): about 45 s.

The code scan stops starting new files after 7 minutes (`CODE_SCAN_BUDGET_S` in `tasks.py`) so it always finishes inside the worker's 10-minute limit; a partial result carries a warning such as "Partial scan: 900 of 1014 source files were scanned", shown on the dashboard. Scans still "queued"/"running" after 15 minutes are reported as failed.

## Tests

```bash
pytest -q tests
```

`tests/test_production.py` imports and runs the real backend modules; each test is tagged with the audit defect it guards. Add a test there for every new feature or fix.

`tests/test_synthetic_repos.py` runs the whole pipeline offline on snapshots of the five synthetic evaluation repos (`tests/fixtures/synthetic`, commits in `SOURCES.txt`) and checks consent gaps and every Section 8(2) / 8(5) finding exactly against the planted violations. Rule 3 and vagueness are model-based and are not asserted there.

`prototypes/` holds the early feasibility scripts used to check whether each planned strategy would work. They carry their own copies of the logic, are not part of the test suite, and are kept for reference only.
