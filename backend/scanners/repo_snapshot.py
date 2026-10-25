"""
Repository snapshot
===================
Gets a repository's source files onto local disk ONCE per commit so that
any number of scan workers can read them, however large the repository is.

  resolve_repo()    → owner/name + the exact commit SHA to scan
  ensure_snapshot() → downloads that commit as ONE tarball, streamed to disk
                      (no size cap, no file-count cap) and extracts every
                      source file; idempotent and safe to call from several
                      processes at once (file lock)
  list_source_files_via_api() / fetch_file_via_api()
                    → fallback when the archive cannot be downloaded:
                      file list from the git tree, contents fetched per
                      file by the chunk tasks, which wait for the GitHub
                      rate-limit reset instead of giving up
  make_chunks()     → splits the file list into small, bounded batches

Nothing here has a time limit of its own. Network calls use connect/read
timeouts, so a stalled connection fails (and is retried) instead of hanging.
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import requests

# Which files are scanned. SCAN_EXTS must match the languages the code
# scanner understands; everything else in the repository is not source code
# it can analyse.
from scanners.code_scanner import SCAN_EXTS

# Every scannable file is scanned, including third-party code bundled into
# the repository: a vendored SDK is exactly where personal data can leave for
# a third party, so excluding it would hide the transmissions Rule 2 detects.
# Each file is instead tagged with its ORIGIN, which the rule engine uses:
#   first_party  the repository's own code
#   third_party  bundled dependencies (node_modules/, vendor/, site-packages/ ...)
#   generated    build output (dist/, build/, *.min.js, *.bundle.js ...)
THIRD_PARTY_DIRS = {"node_modules", "vendor", "site-packages", "bower_components",
                    ".venv", "venv", "third_party", "third-party", "external",
                    # copied-in libraries: "libs" / "vendors" folders, JSPM and
                    # CocoaPods packages (a project's own code lives in lib/ or
                    # src/, which stay first-party)
                    "libs", "vendors", "jspm_packages", "Pods"}
GENERATED_DIRS = {"dist", "build", ".next", "coverage", "out"}
GENERATED_SUFFIXES = (".min.js", ".bundle.js")
# Not code at all: type declarations contain no executable statements, and
# git internals / bytecode caches are not part of the source tree.
NON_CODE_SUFFIXES = (".d.ts",)
NON_CODE_DIRS = {".git", "__pycache__"}
ORIGINS = ("first_party", "third_party", "generated")

SNAPSHOT_ROOT = Path(os.getenv(
    "PRIVACYPILOT_SNAPSHOT_DIR",
    os.path.join(tempfile.gettempdir(), "privacypilot-snapshots"),
))
SNAPSHOT_MAX_AGE_S = 6 * 3600          # pruned after this long unused
_CONNECT_TIMEOUT, _READ_TIMEOUT = 15, 120   # per network read, not per download
_DOWNLOAD_ATTEMPTS = 3
_LOCK_STALE_S = 30 * 60                 # a lock older than this is abandoned

# Chunk bounds. A chunk is the unit of work of one Celery task, so these keep
# every task short no matter how big the repository is.
# Smaller chunks spread a repository over more worker processes (better
# parallelism) and make a time-limited chunk lose less work.
CHUNK_MAX_FILES = int(os.getenv("CHUNK_MAX_FILES", "100"))
CHUNK_MAX_BYTES = int(os.getenv("CHUNK_MAX_BYTES", str(1024 * 1024)))


class RateLimited(Exception):
    """GitHub rate limit hit; retry after `retry_after` seconds."""
    def __init__(self, retry_after: int):
        super().__init__(f"GitHub rate limit; retry in {retry_after}s")
        self.retry_after = retry_after


@dataclass
class RepoRef:
    full_name: str
    sha: str


def classify_path(path: str) -> str:
    """'first_party' | 'third_party' | 'generated' for a scannable file,
    'other' for anything that is not source code the scanner understands."""
    parts = PurePosixPath(path).parts
    dirs = parts[:-1]
    if not path.endswith(SCAN_EXTS) or path.endswith(NON_CODE_SUFFIXES):
        return "other"
    if any(p in NON_CODE_DIRS for p in dirs):
        return "other"
    # Third-party wins over generated: node_modules/x/dist/a.js is a dependency.
    if any(p in THIRD_PARTY_DIRS for p in dirs):
        return "third_party"
    if (any(p in GENERATED_DIRS for p in dirs) or path.endswith(GENERATED_SUFFIXES)
            or ".min." in parts[-1]):           # script.min.1.1.js, app.min.v2.js
        return "generated"
    return "first_party"


def origin_counts(files: list[dict]) -> dict:
    out = {o: 0 for o in ORIGINS}
    for f in files:
        out[f.get("origin", "first_party")] += 1
    return out


def _headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _raise_for_rate_limit(resp) -> None:
    if resp.status_code in (403, 429) and (
        resp.headers.get("X-RateLimit-Remaining") == "0" or "Retry-After" in resp.headers
    ):
        if "Retry-After" in resp.headers:
            wait = int(resp.headers["Retry-After"])
        else:
            wait = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60)) - int(time.time())
        raise RateLimited(max(wait, 1) + 5)


def resolve_repo(repo_url: str, token: str | None) -> RepoRef:
    """owner/name and the default branch's current commit SHA.

    The SHA pins the scan: every chunk task reads the same commit even if
    someone pushes while a large scan is running.
    """
    full_name = repo_url.rstrip("/").split("github.com/")[-1].removesuffix(".git")
    api = f"https://api.github.com/repos/{full_name}"
    resp = requests.get(api, headers=_headers(token), timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
    _raise_for_rate_limit(resp)
    if resp.status_code == 404:
        raise ValueError(
            f"Repository {full_name} not found. If it is private, provide a token with access to it."
        )
    resp.raise_for_status()
    branch = resp.json()["default_branch"]
    resp = requests.get(f"{api}/commits/{branch}", headers=_headers(token),
                        timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
    _raise_for_rate_limit(resp)
    resp.raise_for_status()
    return RepoRef(full_name=full_name, sha=resp.json()["sha"])


def snapshot_dir(ref: RepoRef) -> Path:
    return SNAPSHOT_ROOT / ref.full_name.replace("/", "__") / ref.sha


def _manifest_path(d: Path) -> Path:
    # v2: manifests list every scannable file with its origin. A snapshot
    # written by the earlier version (third-party files left out) has no v2
    # manifest, so it is downloaded again instead of being reused.
    return d / "manifest.v2.json"


def load_manifest(ref: RepoRef) -> dict | None:
    p = _manifest_path(snapshot_dir(ref))
    return json.loads(p.read_text()) if p.exists() else None


def _acquire_lock(lock: Path) -> bool:
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            if time.time() - lock.stat().st_mtime > _LOCK_STALE_S:
                lock.unlink(missing_ok=True)       # holder died; take over
        except FileNotFoundError:
            pass
        return False


def ensure_snapshot(ref: RepoRef, token: str | None, on_progress=None) -> dict:
    """
    Make sure the commit's source files are on disk; return its manifest:
      {"mode": "archive", "files": [{"path", "size", "origin"}...],
       "origins": {"first_party": n, "third_party": n, "generated": n}}
    or, when the archive cannot be downloaded,
      {"mode": "api", "files": [...], "origins": {...}}  (files fetched later).

    Safe to call concurrently: one process downloads, the others wait.
    `on_progress(bytes_downloaded)` is called about every 8 MB, so the caller
    can record a heartbeat during a long download.
    """
    d = snapshot_dir(ref)
    d.parent.mkdir(parents=True, exist_ok=True)
    lock = d.with_name(d.name + ".lock")
    while True:
        m = load_manifest(ref)
        if m is not None:
            os.utime(_manifest_path(d))            # mark as recently used
            return m
        if _acquire_lock(lock):
            break
        time.sleep(2)
    try:
        if load_manifest(ref) is None:
            try:
                manifest = _download_archive(ref, token, d, on_progress)
            except RateLimited:
                raise
            except Exception as e:
                print(f"[snapshot] archive download failed ({e}); using per-file API")
                manifest = list_source_files_via_api(ref, token)
                d.mkdir(parents=True, exist_ok=True)
            _manifest_path(d).write_text(json.dumps(manifest))
        return load_manifest(ref)
    finally:
        lock.unlink(missing_ok=True)


def _download_archive(ref: RepoRef, token: str | None, d: Path, on_progress) -> dict:
    url = f"https://api.github.com/repos/{ref.full_name}/tarball/{ref.sha}"
    last_err = None
    for attempt in range(_DOWNLOAD_ATTEMPTS):
        tmp = d.with_name(d.name + f".download-{os.getpid()}.tar.gz")
        try:
            with requests.get(url, headers=_headers(token), stream=True,
                              timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT)) as resp:
                _raise_for_rate_limit(resp)
                resp.raise_for_status()
                done, next_report = 0, 8 << 20
                with open(tmp, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=1 << 20):
                        fh.write(chunk)
                        done += len(chunk)
                        if on_progress and done >= next_report:
                            on_progress(done)
                            next_report += 8 << 20
            print(f"[snapshot] {ref.full_name}@{ref.sha[:7]}: {done / 1e6:.1f} MB downloaded")
            return _extract_sources(tmp, d)
        except RateLimited:
            raise
        except Exception as e:
            last_err = e
            time.sleep(2 ** attempt)
        finally:
            Path(tmp).unlink(missing_ok=True)
    raise RuntimeError(f"tarball download failed after {_DOWNLOAD_ATTEMPTS} attempts: {last_err}")


def _extract_sources(tar_path: Path, d: Path) -> dict:
    """Extract only scannable source files; never trust archive paths."""
    staging = d.with_name(d.name + f".staging-{os.getpid()}")
    shutil.rmtree(staging, ignore_errors=True)
    files = []
    with tarfile.open(tar_path, mode="r:*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = member.name.split("/")[1:]           # drop "owner-repo-sha/"
            if not parts or member.name.startswith("/") or any(p in ("", ".", "..") for p in parts):
                continue
            path = "/".join(parts)
            kind = classify_path(path)
            if kind == "other":
                continue
            src = tar.extractfile(member)
            if src is None:
                continue
            out = staging / "files" / path
            out.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha1()
            with open(out, "wb") as fh:
                for block in iter(lambda: src.read(1 << 20), b""):
                    h.update(block)
                    fh.write(block)
            files.append({"path": path, "size": member.size, "origin": kind,
                          "hash": h.hexdigest()})
    files.sort(key=lambda f: f["path"])
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    if not (staging / "files").exists():
        (staging / "files").mkdir(parents=True)
    staging.rename(d)
    return {"mode": "archive", "files": files, "origins": origin_counts(files)}


def list_source_files_via_api(ref: RepoRef, token: str | None) -> dict:
    """Fallback file list from the git tree API (no file count limit)."""
    files = []

    def walk(tree_sha: str, prefix: str):
        url = f"https://api.github.com/repos/{ref.full_name}/git/trees/{tree_sha}"
        resp = requests.get(url, headers=_headers(token), params={"recursive": "1"},
                            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
        _raise_for_rate_limit(resp)
        resp.raise_for_status()
        data = resp.json()
        if data.get("truncated"):
            # Recursive listing was cut off (very large tree): walk level by
            # level instead so no file is silently missed.
            resp = requests.get(url, headers=_headers(token),
                                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            _raise_for_rate_limit(resp)
            resp.raise_for_status()
            for e in resp.json()["tree"]:
                p = f"{prefix}{e['path']}"
                if e["type"] == "tree":
                    if e["path"] not in NON_CODE_DIRS:
                        walk(e["sha"], p + "/")
                elif e["type"] == "blob":
                    _add(p, e.get("size", 0), e.get("sha"))
            return
        for e in data["tree"]:
            if e["type"] == "blob":
                _add(f"{prefix}{e['path']}", e.get("size", 0), e.get("sha"))

    def _add(path: str, size: int, blob_sha: str | None):
        kind = classify_path(path)
        if kind != "other":
            # The git blob id is a hash of the content, so identical files
            # share it — the same use as the sha1 computed in archive mode.
            files.append({"path": path, "size": size, "origin": kind, "hash": blob_sha})

    walk(ref.sha, "")
    files.sort(key=lambda f: f["path"])
    return {"mode": "api", "files": files, "origins": origin_counts(files)}


def fetch_file_via_api(ref: RepoRef, path: str, token: str | None) -> bytes:
    """One file's raw content at the pinned commit (fallback mode)."""
    url = f"https://api.github.com/repos/{ref.full_name}/contents/{path}"
    headers = _headers(token) | {"Accept": "application/vnd.github.raw+json"}
    resp = requests.get(url, headers=headers, params={"ref": ref.sha},
                        timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
    _raise_for_rate_limit(resp)
    resp.raise_for_status()
    return resp.content


class SnapshotReader:
    """
    Stands in for a PyGithub repo in code_scanner._scan_single_file():
    get_contents(path) serves the file from the on-disk snapshot, or — in API
    mode, or on a host that has no copy of the snapshot — from the API,
    caching it on disk for later readers.
    """
    def __init__(self, ref: RepoRef, token: str | None):
        self.ref, self.token = ref, token
        self.root = snapshot_dir(ref) / "files"

    def get_contents(self, path: str):
        local = self.root / path
        if not local.exists():
            data = fetch_file_via_api(self.ref, path, self.token)
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
        return _Content(local.read_bytes())


class _Content:
    def __init__(self, data: bytes): self.decoded_content = data


def plan_unique(files: list[dict]) -> tuple[list[dict], dict]:
    """
    Split the file list into the files to scan and identical copies.

    Bundled dependencies repeat the same file many times (node_modules nests
    one copy of a package per dependent; vendored libraries ship the same
    helpers in several places). A file's findings depend only on its content
    and its language (extension), so each distinct (content, extension) of
    third-party / generated code is scanned once and its findings are reused
    for every copy, with the copy's own path.

    First-party files are always scanned individually: their path also
    decides the module type behind Rule 3 (e.g. analytics/ vs auth/).

    Returns (to_scan, duplicates) where duplicates = {copy_path: scanned_path}.
    """
    to_scan, duplicates, first_seen = [], {}, {}
    for f in files:
        h = f.get("hash")
        if f.get("origin", "first_party") == "first_party" or not h:
            to_scan.append(f)
            continue
        key = (h, PurePosixPath(f["path"]).suffix)
        if key in first_seen:
            duplicates[f["path"]] = first_seen[key]
        else:
            first_seen[key] = f["path"]
            to_scan.append(f)
    return to_scan, duplicates


def make_chunks(files: list[dict],
                max_files: int = CHUNK_MAX_FILES,
                max_bytes: int = CHUNK_MAX_BYTES) -> list[list[str]]:
    """
    Split [{"path", "size"}] into batches of at most `max_files` files and
    `max_bytes` bytes. A single file larger than `max_bytes` gets a chunk of
    its own (it is scanned, not skipped). Every file appears exactly once.
    """
    chunks, cur, cur_bytes = [], [], 0
    for f in files:
        size = f.get("size") or 0
        if cur and (len(cur) >= max_files or cur_bytes + size > max_bytes):
            chunks.append(cur)
            cur, cur_bytes = [], 0
        cur.append(f["path"])
        cur_bytes += size
    if cur:
        chunks.append(cur)
    return chunks


def prune_old_snapshots(max_age_s: int = SNAPSHOT_MAX_AGE_S) -> None:
    """Best-effort removal of snapshots nobody has used for a while."""
    if not SNAPSHOT_ROOT.exists():
        return
    cutoff = time.time() - max_age_s
    for repo_dir in SNAPSHOT_ROOT.iterdir():
        if not repo_dir.is_dir():
            continue
        for snap in repo_dir.iterdir():
            m = snap / "manifest.json"
            try:
                if snap.is_dir() and m.exists() and m.stat().st_mtime < cutoff:
                    shutil.rmtree(snap, ignore_errors=True)
            except FileNotFoundError:
                pass
