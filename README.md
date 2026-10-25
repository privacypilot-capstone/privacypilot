# PrivacyPilot

DPDP Act 2023 compliance engine. It scans a GitHub repository's source code and its privacy policy, then reports where the code's handling of personal data is not covered by the policy.

## Checks

| Check | Provision | Implemented in |
| --- | --- | --- |
| Notice Gap — PII in code but not in the policy | Section 5 / Section 6(1) | `backend/dpdp/rule_engine.py` |
| Third-Party Transmission — PII sent to an SDK, HTTP call or queue | Section 8(2) | `rule_engine.py`, `scanners/sinks.py` |
| PII in Logger Output (print, logging, console) | Section 8(5) | `rule_engine.py`, `scanners/sinks.py` |
| PII Sent to External Logging Service (Sentry, Datadog, CloudWatch) | Section 8(5) / Section 8(2) | `rule_engine.py`, `scanners/sinks.py` |
| Purpose–PII Linkage — code use not covered by a stated purpose | Section 6(1) | `rule_engine.py`, `scanners/code_scanner.py`, `scanners/policy_parser.py` |
| Vague Purpose Statement | DPDP Rules 2025, Rule 3(b)(ii) | `scanners/policy_parser.py`, `rule_engine.py` |

Each violation is reported once per check and data category (third-party and logging checks: once per category and recipient; all local log calls are one recipient, "application logs"; vague purposes: once per category, listing every vague policy statement that covers it). It lists every location it covers (a line of code, or for a vague purpose a statement of the policy) — in the evidence text and as `locations` in the API — and a call spanning several lines is one location. One piece of code can still raise several violations when it breaches several provisions.

Nothing is truncated in the outputs: the results page lists every violation with all its code locations and pages through every finding (50/200/500 per page); the HTML and PDF reports (`/report/{id}`, `?format=pdf`) list every violation, location and finding; and `/scans/{id}/violations.csv` and `/scans/{id}/findings.csv` export them all. Stored code lines are cut only above 1,000 characters (minified code), marked with "…".

What does not produce violations (findings are still listed): code in test, mock, fixture and migration files (set `PRIVACYPILOT_INCLUDE_TEST_CODE=1` to include it); message queues (Celery, Kafka, RabbitMQ, Redis, Pub/Sub), which are the application's own infrastructure; HTTP calls whose URL cannot be resolved statically; logging inside bundled libraries and minified files; and, in bundled code, the generic SDK words "segment" and "analytics". Purpose statements with stock vague wording ("improve our services") are reported as vague and do not count as stating a purpose.

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

### API and worker must share one database and the same code

The API creates each scan's row; the worker updates it and stores chunk results that reference it. Both must use the same database and run the same code.

**Local settings stay out of git.** Put anything specific to your machine in git-ignored files:

- `backend/.env`: copy `backend/.env.example`. When the API runs on the host and the worker in Docker, set `DATABASE_URL` to the Docker Postgres as seen from the host, e.g. `postgresql://pilot:pilot@localhost:15432/privacypilot` if your override maps port 15432.
- `docker-compose.override.yml` (or `docker-compose.local.yml`): port changes and other compose overrides. `docker compose` applies `docker-compose.override.yml` automatically.
- `frontend/.env.local`: `VITE_API_URL` if the API is not on `http://localhost:8000`.

**What the API checks** (`GET /health` → `database`; `POST /scan` is refused with HTTP 503 and the reason while a check fails):

| Shown | Cause | Fix |
|---|---|---|
| "running older code … restart it" | The worker was started before the code changed. Celery never reloads code, while `uvicorn --reload` does. | `docker compose restart worker` |
| "different database" | The worker's database is not the API's. They are compared by an instance id stored in the database, so `localhost:15432` and `db:5432` are correctly the same. | Same `DATABASE_URL` for both |
| "Redis … is not reachable" | Redis is down or `REDIS_URL` is wrong | Start Redis / fix `REDIS_URL` |
| "No scan worker answered" | No worker is running. The scan is queued and waits. | Start the worker |

If a worker still gets a scan it cannot see, it stops with "Scan N does not exist in the worker's database …" and the API shows that error at once. If any chunk task fails, the scan is marked failed at once with that error. The worker also brings the database schema up to date when it starts, so a worker restarted on new code before the API never writes to a column that does not exist yet.

## Large repositories

There is no file-count limit and no overall scan time limit; every source file in the repository is scanned, including bundled third-party code.

1. **Download once.** The scan is pinned to the default branch's current commit, which is downloaded as one tarball, streamed to disk with no size cap, into a volume shared by all worker processes (`PRIVACYPILOT_SNAPSHOT_DIR`). If the archive cannot be downloaded, files are listed from the git tree and fetched one by one; on a GitHub rate limit the task waits for the reset instead of failing.
2. **Tag every file's origin.** `first_party` (the repository's own code), `third_party` (`node_modules/`, `vendor/`, `site-packages/`, `third_party/`, …) or `generated` (`dist/`, `build/`, `.next/`, `*.min.js`, `*.bundle.js`). Only `.d.ts` declarations, `.git/` and `__pycache__/` are left out, because they contain no executable code.
3. **Scan identical bundled files once.** Dependencies repeat the same files many times (one copy per dependent in nested `node_modules`). Each distinct third-party/generated file (same content and extension) is scanned once and its findings are copied to every other copy, with that copy's path. First-party files are always scanned individually.
4. **Split into chunks.** Files are split into chunks of at most 100 files / 1 MB (`CHUNK_MAX_FILES`, `CHUNK_MAX_BYTES`); a larger file gets a chunk of its own. Minified files with very long lines are analysed in 2,000-character windows, so a whole bundle on one line never exceeds spaCy's limit.
5. **Scan in parallel.** Each chunk is its own Celery task, and the worker's processes scan chunks in parallel while the privacy policy is parsed.
6. **Combine.** A final task merges all chunks, runs the rule engine and saves **every** finding.

How third-party code counts in the rules:

| Rule | Uses |
|---|---|
| Rule 2: third-party transmission, Section 8(2) / 8(5) | all findings; the evidence says when the call is inside bundled third-party or generated code |
| Rule 1: notice gap, Section 5 / 6(1) | first-party findings only (a library that handles e-mail addresses internally does not mean the application collects them) |
| Rule 3: purpose linkage, Section 6(1) | first-party files only (module types come from the application's own paths) |

Time limits apply per chunk (`CHUNK_SOFT_LIMIT_S`, default 240 s), never to the whole scan. A file still running when its chunk hits the limit is retried alone; a file that exceeds the limit twice is named on the result as not scanned.

### Making scans faster

- **Worker processes.** The worker runs one process per CPU core by default (`WORKER_CONCURRENCY` overrides it: `WORKER_CONCURRENCY=2 docker compose up` on a small machine).
- **Shared model memory.** The spaCy model is loaded once in the worker's parent process before the pool starts, and shared by all its processes, so adding processes costs much less memory than a full ~1 GB copy each. `PRELOAD_MODELS=0` turns this off. The policy parser reuses the same spaCy model instead of loading a second copy.
- **No thread oversubscription.** Each process uses one math-library thread (`OMP_NUM_THREADS=1` etc.); parallelism comes from the processes.
- **More containers.** `docker compose up --scale worker=3` adds worker containers; they share the snapshot volume. Workers on other machines also work: they fetch the files they need from GitHub.

The frontend shows live progress ("1,840 of 5,210 source files scanned"). A scan is marked failed only if it stops making progress for 15 minutes while no other scan is progressing either, i.e. no worker is running.

### All findings on the results page

The results page lists every finding, 50 per page, from `GET /scans/{id}/findings?offset=&limit=&category=&origin=&sensitivity=&transmitted=true&q=`. You can filter by origin (your code / third-party / generated), PII category, "sent to a third party / logged", and search by file or code.

## Tests

```bash
pytest -q tests
```

`tests/test_production.py` imports and runs the real backend modules; each test is tagged with the audit defect it guards. Add a test there for every new feature or fix.

`tests/test_synthetic_repos.py` runs the whole pipeline offline on snapshots of the five synthetic evaluation repos (`tests/fixtures/synthetic`, commits in `SOURCES.txt`) and checks consent gaps and every Section 8(2) / 8(5) finding (category and recipient) exactly against the reviewed ground truth `eval/privacy_pilot_ground_truth_reviewed_v5.csv`; the test lists the documented exceptions. Rule 3 and vagueness are model-based and are not asserted there.

Scoring an evaluation run: `python eval/compute_metrics.py [--contract-unverified count|ignore] [--ground-truth PATH]`. Reported violations are compared as (rule, category, recipient) with duplicates removed; `--contract-unverified ignore` leaves out Section 8(2) items where the policy already names the recipient. The script also prints per-rule results.

`prototypes/` holds the early feasibility scripts used to check whether each planned strategy would work. They carry their own copies of the logic, are not part of the test suite, and are kept for reference only.
