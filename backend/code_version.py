"""
Version of the code the scan WORKER executes, as a short hash.

The API and the worker must run the same code: the API queues tasks and
reads results that the worker's code defines. With Docker the worker reads
the same source files as the API, but a running Celery worker never reloads
them, so after a `git pull` (or any edit) it keeps executing the old code
until it is restarted, while `uvicorn --reload` already runs the new code.
The API compares this hash with the one each worker reports and says
"restart the worker" instead of failing in some indirect way.

Only the modules the worker runs are hashed (not main.py or the LLM client),
so editing API-only code does not ask for a worker restart. Line endings are
normalised, so a checkout with CRLF endings hashes the same everywhere.
"""
import hashlib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_FILES = ("tasks.py", "database.py", "scoring.py")
_DIRS = ("scanners", "dpdp", "models")


def compute() -> str:
    h = hashlib.sha1()
    paths = [_ROOT / f for f in _FILES]
    for d in _DIRS:
        paths += sorted((_ROOT / d).rglob("*.py"))
    for p in sorted(paths):
        if "__pycache__" in p.parts or not p.is_file():
            continue
        h.update(p.relative_to(_ROOT).as_posix().encode())
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()[:12]
