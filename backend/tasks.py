import os
from dotenv import load_dotenv
# Must be first — loads backend/.env before any os.getenv() call. Explicit
# path, so it does not depend on the directory the worker was started from.
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

import json
from datetime import datetime

from celery import Celery, chord, group, signals
from celery.exceptions import SoftTimeLimitExceeded
from celery.worker.control import inspect_command

# ── Celery application ────────────────────────────────────────────────────────
# Both broker and result backend point at the Redis container (or localhost in
# local dev).  REDIS_URL can be overridden in .env or docker-compose environment.
# Default for a process started on the host; docker compose sets
# redis://redis:6379/0 for the containers.
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ── How a scan of any size finishes ───────────────────────────────────────────
# A repository is never scanned by one long task. The pipeline is:
#
#   run_scan_task      pin the commit, download it ONCE (streamed to disk, no
#                      size cap), split the source files into small chunks
#        │
#        ├── scan_chunk_task × N   one bounded batch of files each, run in
#        │                         parallel by every worker process
#        └── parse_policy_task     the privacy policy, in parallel
#        │
#   finalize_scan_task combine all chunks, run the rule engine, score, save
#
# Every task's running time is bounded by its OWN input (one chunk is at most
# CHUNK_MAX_FILES files / CHUNK_MAX_BYTES bytes), never by the size of the
# repository, so time limits are per chunk and no repository is too large.
# A file still running when its chunk hits the soft limit is retried alone in
# a second round; only a file that alone exceeds the limit twice is reported
# as not scanned (by name, on the result).
CHUNK_SOFT_LIMIT_S = int(os.getenv("CHUNK_SOFT_LIMIT_S", "240"))
CHUNK_HARD_LIMIT_S = CHUNK_SOFT_LIMIT_S + 60
MAX_ROUNDS = 2

celery_app = Celery(
    "privacypilot",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,          # STARTED state visible before SUCCESS
    worker_prefetch_multiplier=1,     # fair dispatch: one chunk per process at a time
    # If a worker process dies mid-chunk (OOM, restart), the chunk goes back
    # on the queue instead of being lost and leaving the scan unfinished.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=24 * 3600,
    # No global time limit: limits are set per task below.
    # The API reads task states from Redis while answering a status poll; a
    # Redis that is down must fail that read quickly, not hang the request.
    redis_socket_connect_timeout=5,
    redis_socket_timeout=10,
    # Queueing a scan while Redis is down must fail in seconds with a clear
    # error, not hang the HTTP request.
    broker_connection_timeout=5,
    task_publish_retry_policy={"max_retries": 2, "interval_start": 0,
                               "interval_step": 1, "interval_max": 2},
)

from code_version import compute as _code_version
CODE_VERSION = _code_version()   # computed when this process started


# ── Which database is this worker using? ─────────────────────────────────────
# The API and the worker must use the SAME database: the API creates the scan
# row, the worker updates it and stores chunk results that reference it. If
# they differ (e.g. the API run locally on SQLite, the worker in Docker on
# Postgres) every worker write misses the row. This remote-control command is
# answered by the worker's main process — even while all its pool processes
# are busy scanning — so the API can compare databases in about a second.

@inspect_command()
def privacypilot_database(state):
    from database import describe_database_url, database_instance_id
    return {"database": describe_database_url(), "instance_id": database_instance_id(),
            "code_version": CODE_VERSION}


def worker_databases(timeout: float = 1.0) -> dict:
    """{worker hostname: {"database", "instance_id"}} for every live worker."""
    replies = celery_app.control.broadcast(
        "privacypilot_database", reply=True, timeout=timeout) or []
    out = {}
    for r in replies:
        for host, body in r.items():
            out[host] = body if isinstance(body, dict) else {}
    return out


# ── Load the NLP models once, before the pool forks ──────────────────────────
# With the prefork pool, worker_init runs in the main process before the
# pool processes are created, so the spaCy model behind Presidio (~600 MB)
# is loaded ONCE and shared copy-on-write by every pool process, instead of
# each process loading its own copy when it takes its first chunk. Faster
# start, and far less memory per process, which is what allows more
# processes (higher --concurrency) on the same machine.
# PRELOAD_MODELS=0 turns this off (e.g. for a quick test worker).
# sentence-transformers (torch) is NOT preloaded: torch is not fork-safe, and
# only the one policy task per scan uses it.

@signals.worker_init.connect
def _prepare_database(**_):
    """Bring the schema up to date from the worker too. The worker writes
    columns added by newer code (e.g. findings.origin); if the worker is
    restarted on new code before the API is, the columns must already exist.
    Both steps are idempotent. The instance id is NOT created here: only the
    API creates it, so a worker on a different database is still detected."""
    try:
        from database import create_tables, migrate_tables, describe_database_url
        create_tables()
        migrate_tables()
        print(f"[worker] database = {describe_database_url()}; code version {CODE_VERSION}")
    except Exception as e:
        print(f"[worker] WARNING: could not prepare the database: {e}")


@signals.worker_init.connect
def _preload_models(**_):
    if os.getenv("PRELOAD_MODELS", "1") == "0":
        return
    try:
        from scanners.presidio_scanner import get_analyzer
        get_analyzer()
        print("[worker] models preloaded")
    except Exception as e:
        print(f"[worker] model preload skipped: {e}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _db():
    from database import SessionLocal
    return SessionLocal()


def _update_scan(scan_id: int, **fields) -> None:
    """Set fields on the scan row and record a heartbeat."""
    from database import Scan
    db = _db()
    try:
        fields.setdefault("last_progress_at", datetime.utcnow())
        db.query(Scan).filter(Scan.id == scan_id).update(fields, synchronize_session=False)
        db.commit()
    finally:
        db.close()


class ScanRowMissing(RuntimeError):
    pass


def _require_scan(scan_id: int) -> None:
    """Fail fast, with the cause, when this worker cannot see the scan row."""
    from database import Scan, describe_database_url
    db = _db()
    try:
        exists = db.query(Scan.id).filter(Scan.id == scan_id).first() is not None
    finally:
        db.close()
    if not exists:
        raise ScanRowMissing(
            f"Scan {scan_id} does not exist in the worker's database "
            f"({describe_database_url()}). The API and the worker are using "
            f"different databases: set the same DATABASE_URL for both (see "
            f"README → 'API and worker must share one database')."
        )


def _fail_scan(scan_id: int, message) -> None:
    _update_scan(scan_id, status="failed", phase="failed", error_message=str(message)[:2000])
    print(f"[task] Scan {scan_id} FAILED: {message}")


def _findings_to_json(findings) -> str:
    return json.dumps([f.model_dump(mode="json") for f in findings])


def _findings_from_json(text: str | None):
    from models.dataflow import DataFlowObject
    return [DataFlowObject(**d) for d in json.loads(text or "[]")]


def _catmap_to_json(m: dict) -> dict:
    return {k.value: sorted(v) for k, v in m.items()}


def _catmap_from_json(m: dict) -> dict:
    from models.dataflow import PIICategory
    return {PIICategory(k): set(v) for k, v in m.items()}


# ── 1. Orchestrator ──────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.run_scan_task", max_retries=None)
def run_scan_task(self, scan_id: int, repo_url: str, token: str, policy_url: str):
    """
    Pin the commit, put its source files on disk, and fan the scan out.

    Receives a pre-created scan_id (created by the HTTP handler with
    status='queued') so the HTTP response can return immediately. Returns as
    soon as the chunk tasks are queued; progress is reported on the scan row
    (phase, files_done / files_total, last_progress_at).

    No time limit: the only long step is the download, which is streamed and
    protected by per-read network timeouts (a stalled connection fails and is
    retried rather than hanging), and which records a heartbeat as it goes.

    Security: the GitHub token travels only in Redis task messages; it is
    never written to the database.
    """
    from scanners import repo_snapshot as rs

    # Not inside the try below: when the row is missing there is nothing to
    # mark as failed here. The task fails with this message, which the API
    # reads from Celery (tasks.run_scan_task's result) and shows on the scan.
    _require_scan(scan_id)

    try:
        _update_scan(scan_id, status="running", phase="downloading")
        print(f"[task] Scan {scan_id} running — repo: {repo_url}")
        rs.prune_old_snapshots()

        ref = rs.resolve_repo(repo_url, token)
        manifest = rs.ensure_snapshot(
            ref, token, on_progress=lambda _bytes: _update_scan(scan_id))
        to_scan, duplicates = rs.plan_unique(manifest["files"])
        chunks = rs.make_chunks(to_scan)
        origins = manifest.get("origins") or rs.origin_counts(manifest["files"])
        print(f"[task] Scan {scan_id} — {ref.full_name}@{ref.sha[:7]}: "
              f"{len(manifest['files'])} source files ({origins}), "
              f"{len(duplicates)} identical bundled copies reused, "
              f"{len(to_scan)} scanned in {len(chunks)} chunks ({manifest['mode']} mode)")

        _update_scan(
            scan_id,
            phase="scanning",
            files_total=len(to_scan),
            files_done=0,
            chunks_total=len(chunks),
            coverage=json.dumps({
                "total_source_files": len(manifest["files"]),
                "origins": origins,
                "duplicates": duplicates,
            }),
        )

        header = [
            scan_chunk_task.s(scan_id, i, 1, ref.full_name, ref.sha, paths, token)
            for i, paths in enumerate(chunks)
        ] + [parse_policy_task.s(policy_url, token)]
        # on_error: if any task of the chord raises (e.g. a database error
        # while saving a chunk), the scan is marked failed with that error at
        # once, instead of sitting "running" until the stall detector fires.
        chord(group(header))(
            finalize_scan_task.s(scan_id, 1, ref.full_name, ref.sha, token)
            .on_error(scan_failed_errback.s(scan_id))
        )
        return {"scan_id": scan_id, "chunks": len(chunks), "files": len(manifest["files"])}

    except rs.RateLimited as e:
        _update_scan(scan_id, phase="waiting for GitHub rate limit")
        raise self.retry(countdown=e.retry_after, exc=e)
    except Exception as exc:
        _fail_scan(scan_id, exc)
        raise


# ── 2. One chunk of files ────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.scan_chunk_task", max_retries=None,
                 soft_time_limit=CHUNK_SOFT_LIMIT_S, time_limit=CHUNK_HARD_LIMIT_S)
def scan_chunk_task(self, scan_id: int, chunk_no: int, round_no: int,
                    full_name: str, sha: str, paths: list, token: str):
    """
    Scan one bounded batch of files and store the result in scan_chunks.

    Never raises for a bad file (it is recorded as failed) so one file can't
    stop the scan. On the soft time limit, the files not yet finished are
    returned as `unfinished` and retried one per task in the next round. On
    a GitHub rate limit (API fallback mode only) the task waits for the
    reset and retries instead of failing.
    """
    from scanners import repo_snapshot as rs

    try:
        result = run_chunk(rs.SnapshotReader(rs.RepoRef(full_name, sha), token), paths)
    except rs.RateLimited as e:
        raise self.retry(countdown=e.retry_after, exc=e)
    if result["unfinished"]:
        print(f"[task] Scan {scan_id} chunk {chunk_no}: time limit, "
              f"{len(result['unfinished'])} file(s) moved to the next round")
    save_chunk(scan_id, chunk_no, round_no, result)
    return {"chunk": chunk_no, "round": round_no, "unfinished": result["unfinished"]}


def run_chunk(reader, paths: list) -> dict:
    """Scan `paths` one file at a time; on the soft time limit, return what
    is done plus the files not finished (the current one included)."""
    from scanners.code_scanner import scan_files

    out = {"findings": [], "usage_map": {}, "scanned": [], "failed": {}, "unfinished": []}
    i = 0
    try:
        for i, path in enumerate(paths):
            f, u, st = scan_files(reader, [path])
            out["findings"].extend(f)
            for cat, mods in u.items():
                out["usage_map"].setdefault(cat, set()).update(mods)
            out["scanned"].extend(st["scanned"])
            out["failed"].update(st["failed"])
    except SoftTimeLimitExceeded:
        out["unfinished"] = list(paths[i:])
    return out


def save_chunk(scan_id: int, chunk_no: int, round_no: int, result: dict) -> None:
    """Store one chunk's result and advance the progress counter (idempotent:
    a chunk re-delivered after a worker crash replaces its earlier row and is
    not counted twice)."""
    from database import Scan, ScanChunk
    db = _db()
    try:
        old = db.query(ScanChunk).filter(
            ScanChunk.scan_id == scan_id, ScanChunk.chunk_no == chunk_no,
            ScanChunk.round == round_no).first()
        if old is not None:
            db.delete(old)
        db.add(ScanChunk(
            scan_id=scan_id, chunk_no=chunk_no, round=round_no,
            findings=_findings_to_json(result["findings"]),
            usage_map=json.dumps(_catmap_to_json(result["usage_map"])),
            scanned=json.dumps(result["scanned"]),
            failed=json.dumps(result["failed"]),
            unfinished=json.dumps(result["unfinished"]),
        ))
        if old is None:
            db.query(Scan).filter(Scan.id == scan_id).update({
                Scan.files_done: Scan.files_done + len(result["scanned"]) + len(result["failed"]),
                Scan.last_progress_at: datetime.utcnow(),
            }, synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── 3. Privacy policy (in parallel with the chunks) ──────────────────────────

@celery_app.task(name="tasks.parse_policy_task", soft_time_limit=540, time_limit=600)
def parse_policy_task(policy_url: str, token: str):
    """The policy is one document, so this task's time does not depend on
    the repository. Errors are returned (not raised) so the finalize step
    can report them on the scan."""
    from scanners.policy_parser import parse_privacy_policy
    try:
        claims, purpose_map, vagueness, disclosed = parse_privacy_policy(policy_url, token)
    except Exception as e:
        return {"policy_error": f"Privacy policy could not be processed: {e}"}
    return {"policy": {
        "claims":       _findings_to_json(claims),
        "purpose_map":  _catmap_to_json(purpose_map),
        "vagueness":    vagueness,
        "disclosed":    _catmap_to_json(disclosed),
    }}


# ── 4. Combine, apply the rules, save ────────────────────────────────────────

FINDINGS_INSERT_BATCH = 5000


def _insert_findings(db, scan_id: int, findings: list, gap_categories: set) -> None:
    from sqlalchemy import insert
    from database import Finding
    for i in range(0, len(findings), FINDINGS_INSERT_BATCH):
        db.execute(insert(Finding), [{
            "scan_id":         scan_id,
            "source":          f.source,
            "file_path":       f.file_path,
            "line_number":     f.line_number,
            "raw_text":        f.raw_text,
            "field_name":      f.field_name,
            "pii_category":    f.pii_category.value,
            "sensitivity":     f.sensitivity.value,
            "third_party_sdk": f.third_party_sdk,
            # A gap is a category the APPLICATION collects without notice.
            "is_gap":          f.origin == "first_party" and f.pii_category in gap_categories,
            "origin":          f.origin,
        } for f in findings[i:i + FINDINGS_INSERT_BATCH]])

@celery_app.task(bind=True, name="tasks.finalize_scan_task",
                 soft_time_limit=1500, time_limit=1800)
def finalize_scan_task(self, results, scan_id: int, round_no: int,
                       full_name: str, sha: str, token: str, policy: dict | None = None):
    """
    Runs once every chunk of a round (and the policy task) has finished.

    Files left unfinished by a chunk's time limit are re-queued one file per
    task for one more round; after that, the scan is completed from every
    stored chunk.
    """
    try:
        if policy is None:
            p = next((r for r in results if isinstance(r, dict)
                      and ("policy" in r or "policy_error" in r)), None)
            if p is None or "policy_error" in p:
                _fail_scan(scan_id, (p or {}).get("policy_error", "Policy task returned no result"))
                return None
            policy = p["policy"]

        unfinished = sorted({path for r in results if isinstance(r, dict)
                             for path in r.get("unfinished", [])})
        if unfinished and round_no < MAX_ROUNDS:
            print(f"[task] Scan {scan_id}: retrying {len(unfinished)} slow file(s) one per task")
            base = 1_000_000 * round_no
            chord(group([
                scan_chunk_task.s(scan_id, base + i, round_no + 1, full_name, sha, [path], token)
                for i, path in enumerate(unfinished)
            ]))(finalize_scan_task.s(scan_id, round_no + 1, full_name, sha, token, policy)
                .on_error(scan_failed_errback.s(scan_id)))
            return None

        _update_scan(scan_id, phase="finalizing")
        return complete_scan(scan_id, policy)
    except Exception as exc:
        _fail_scan(scan_id, exc)
        raise


@celery_app.task(name="tasks.scan_failed_errback")
def scan_failed_errback(request, exc, traceback, scan_id: int):
    """Chord error callback: Celery calls it as (request, exc, traceback)
    followed by the bound scan_id."""
    msg = str(exc)
    # A chord reports a failed member as "Dependency <id> raised <Error>(...)".
    _fail_scan(scan_id, f"A scan task failed: {msg}")


ORIGIN_ORDER = {"first_party": 0, "generated": 1, "third_party": 2}


def _expand_duplicates(findings: list, scanned: set, failed: dict, duplicates: dict):
    """Give every identical copy of a bundled file the findings and status
    of the one copy that was scanned (repo_snapshot.plan_unique)."""
    from scanners.repo_snapshot import classify_path
    if not duplicates:
        return findings
    by_path: dict = {}
    for f in findings:
        by_path.setdefault(f.file_path, []).append(f)
    extra = []
    for copy, original in duplicates.items():
        if original in failed:
            failed[copy] = failed[original]
            continue
        if original not in scanned:
            continue
        scanned.add(copy)
        origin = classify_path(copy)
        for f in by_path.get(original, []):
            extra.append(f.model_copy(update={"file_path": copy, "origin": origin}))
    return findings + extra


def complete_scan(scan_id: int, policy: dict) -> dict:
    """Merge every stored chunk, run the rule engine, score and persist."""
    from database import Scan, ScanChunk, Finding, Violation
    from scanners.code_scanner import coverage_note
    from dpdp.rule_engine import run_dpdp_rules
    from scoring import calculate_compliance_score

    db = _db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        rows = (db.query(ScanChunk).filter(ScanChunk.scan_id == scan_id)
                  .order_by(ScanChunk.round, ScanChunk.chunk_no).all())

        code_findings, usage_map = [], {}
        scanned, failed, still_unfinished = set(), {}, set()
        for r in rows:
            code_findings.extend(_findings_from_json(r.findings))
            for cat, mods in _catmap_from_json(json.loads(r.usage_map or "{}")).items():
                usage_map.setdefault(cat, set()).update(mods)
            scanned.update(json.loads(r.scanned or "[]"))
            failed.update(json.loads(r.failed or "{}"))
            still_unfinished.update(json.loads(r.unfinished or "[]"))
        # A file unfinished in round 1 but scanned in round 2 is fine; one
        # still unfinished after the last round is reported by name.
        for path in sorted(still_unfinished - scanned - set(failed)):
            failed[path] = (f"exceeded the per-file time limit ({CHUNK_SOFT_LIMIT_S} s) "
                            f"in {MAX_ROUNDS} attempts")

        prior = json.loads(scan.coverage or "{}")
        duplicates = prior.get("duplicates") or {}
        code_findings = _expand_duplicates(code_findings, scanned, failed, duplicates)
        for f in code_findings:
            f.origin = f.origin or "first_party"
        # Application code first: the rule engine cites the first location it
        # meets, so this makes it cite first-party code whenever it can, and
        # the results page lists the application's own findings first.
        code_findings.sort(key=lambda f: (ORIGIN_ORDER.get(f.origin, 3),
                                          f.file_path or "", f.line_number or 0))
        first_party = [f for f in code_findings if f.origin == "first_party"]

        policy_claims = _findings_from_json(policy["claims"])
        purpose_map   = _catmap_from_json(policy["purpose_map"])
        disclosed     = _catmap_from_json(policy["disclosed"])
        vagueness     = policy["vagueness"]

        print(f"[task] Scan {scan_id} — {len(code_findings)} code findings "
              f"({len(first_party)} first-party) from {len(scanned)} files; "
              f"{len(policy_claims)} policy claims")

        # Rule 1 (notice gap) is about what the APPLICATION collects, so gap
        # categories come from first-party code: a bundled library that
        # handles e-mail addresses internally does not mean the application
        # collects them. Rule 2 (third-party transmission) gets every finding,
        # third-party code included (see dpdp/rule_engine.py). usage_map
        # (Rule 3) is built from first-party files only by the scanner.
        code_pii       = {f.pii_category for f in first_party}
        policy_pii     = {f.pii_category for f in policy_claims}
        gap_categories = code_pii - policy_pii

        violations = run_dpdp_rules(
            code_findings, policy_claims, gap_categories,
            usage_map=usage_map, purpose_map=purpose_map,
            vagueness_warnings=vagueness, disclosed_sdks=disclosed,
        )
        compliance = calculate_compliance_score(
            violations, len(code_findings), len(gap_categories))

        by_origin = {o: 0 for o in ORIGIN_ORDER}
        for f in code_findings:
            by_origin[f.origin] = by_origin.get(f.origin, 0) + 1
        coverage = {
            "total_source_files": prior.get("total_source_files")
                                  or (len(scanned) + len(failed)),
            "scanned": len(scanned),
            "failed": failed,
            "origins": prior.get("origins", {}),
            "duplicates_reused": len(duplicates),
            "findings_by_origin": by_origin,
        }

        scan.findings_count   = len(code_findings)
        scan.policy_count     = len(policy_claims)
        scan.gaps_count       = len(gap_categories)
        scan.gap_categories   = json.dumps(sorted(c.value for c in gap_categories))
        scan.violations_count = len(violations)
        scan.files_done       = scan.files_total if scan.files_total is not None else len(scanned)
        scan.coverage         = json.dumps(coverage)
        scan.status           = "complete"
        scan.phase            = "complete"
        scan.last_progress_at = datetime.utcnow()
        # Coverage note (None when every source file was scanned); shown to
        # the user as a notice on a completed scan.
        scan.error_message    = coverage_note(coverage)

        # EVERY finding is stored (previously only the first 200), in bulk:
        # one multi-row INSERT per batch instead of one ORM object each.
        _insert_findings(db, scan_id, code_findings, gap_categories)
        for v in violations:
            db.add(Violation(
                scan_id        = scan_id,
                dpdp_section   = v.dpdp_section,
                section_title  = v.section_title,
                severity       = v.severity,
                pii_category   = v.pii_category,
                evidence       = v.evidence,
                recommendation = v.recommendation,
                recipient      = getattr(v, "recipient", None),
                locations      = json.dumps(getattr(v, "locations", None) or []),
            ))
        # The per-chunk rows have served their purpose.
        db.query(ScanChunk).filter(ScanChunk.scan_id == scan_id).delete(synchronize_session=False)
        db.commit()
        print(f"[task] Scan {scan_id} complete — {len(violations)} violations, "
              f"score {compliance.get('score', '?')}, "
              f"{coverage['scanned']}/{coverage['total_source_files']} files")
        return {
            "scan_id":          scan_id,
            "status":           "complete",
            "violations_count": len(violations),
            "compliance_score": compliance.get("score"),
            "gaps_count":       len(gap_categories),
            "coverage":         {**coverage, "failed": len(failed)},
        }
    finally:
        db.close()
