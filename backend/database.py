from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import json
import os

# Every entry point (API, worker, scripts) must read the same settings, so the
# database module loads backend/.env itself rather than relying on whoever
# imported it first. Variables already set (e.g. by docker compose) win.
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# Default: a SQLite file next to this module. (It used to be relative to the
# current directory, so starting the API from another folder silently created
# and used a second, empty database.)
_DEFAULT_SQLITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "privacypilot.db")
DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{_DEFAULT_SQLITE}"
# SQLAlchemy 2.x maps plain postgresql:// → psycopg3; we ship psycopg2, so
# rewrite the scheme to use the psycopg2 dialect explicitly.
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# SQLite needs check_same_thread=False for FastAPI's threading model
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
# pool_pre_ping: test a pooled connection before using it, so a connection
# the server closed (restart, idle timeout) is replaced instead of failing
# the next query.
engine = create_engine(DATABASE_URL, connect_args=connect_args,
                       pool_pre_ping=not DATABASE_URL.startswith("sqlite"))
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ── Tables ────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id           = Column(Integer, primary_key=True, index=True)
    repo_url     = Column(String, nullable=False)
    policy_url   = Column(String, nullable=False)
    status = Column(String, default="running")
    error_message = Column(Text, nullable=True)   # populated when status == "failed"
    created_at   = Column(DateTime, default=datetime.utcnow)
    findings_count   = Column(Integer, default=0)
    policy_count     = Column(Integer, default=0)
    gaps_count       = Column(Integer, default=0)
    violations_count = Column(Integer, default=0)
    # JSON list of PII categories in code but absent from the policy. Stored
    # explicitly (scans saved by older versions persisted only their first
    # 200 findings, so Finding.is_gap alone could miss categories).
    gap_categories   = Column(Text, nullable=True)

    # ── Progress of a chunked scan (tasks.py) ────────────────────────────
    # phase: queued → downloading → scanning → finalizing → complete/failed
    phase            = Column(String, nullable=True)
    files_total      = Column(Integer, nullable=True)   # source files to scan
    files_done       = Column(Integer, default=0)       # scanned or failed so far
    # Live progress inside running chunks (files_done moves only when a whole
    # chunk of up to 100 files is saved). Approximate; capped at files_total.
    files_seen       = Column(Integer, default=0)
    # The privacy policy is parsed in parallel: queued → parsing → done/failed
    policy_state     = Column(String, nullable=True)
    chunks_total     = Column(Integer, nullable=True)
    # Heartbeat: updated on every completed chunk and during the download.
    # A scan is declared dead only when THIS stops moving, never because
    # the repository is big and the scan is simply taking long.
    last_progress_at = Column(DateTime, nullable=True)
    coverage         = Column(Text, nullable=True)      # JSON, see coverage_note()
    # Celery id of the orchestrator task, so the API can ask Celery whether
    # it failed (e.g. on a worker that cannot see this scan row).
    task_id          = Column(String, nullable=True)


    findings   = relationship("Finding",   back_populates="scan")
    ai_summary = Column(Text, nullable=True)   # cached LLM executive summary

    violations = relationship("Violation", back_populates="scan")


class ScanChunk(Base):
    """
    Result of one chunk task: the findings of a batch of files. Kept in the
    database (not passed through Celery) so the finalize step can combine
    any number of chunks, from any worker, across retry rounds.
    """
    __tablename__ = "scan_chunks"

    id          = Column(Integer, primary_key=True, index=True)
    scan_id     = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    chunk_no    = Column(Integer, nullable=False)
    round       = Column(Integer, default=1)
    findings    = Column(Text, nullable=True)   # JSON list of DataFlowObject dicts
    usage_map   = Column(Text, nullable=True)   # JSON {category: [module types]}
    scanned     = Column(Text, nullable=True)   # JSON list of paths
    failed      = Column(Text, nullable=True)   # JSON {path: reason}
    unfinished  = Column(Text, nullable=True)   # JSON list of paths (hit the time limit)
    created_at  = Column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id               = Column(Integer, primary_key=True, index=True)
    scan_id          = Column(Integer, ForeignKey("scans.id"), index=True)
    source           = Column(String)
    file_path        = Column(String, nullable=True)
    line_number      = Column(Integer, nullable=True)
    raw_text         = Column(Text)
    field_name       = Column(String)
    pii_category     = Column(String)
    sensitivity      = Column(String)
    third_party_sdk  = Column(String, nullable=True)
    is_gap           = Column(Boolean, nullable=True)
    # first_party | third_party | generated (repo_snapshot.classify_path);
    # NULL on scans saved before third-party code was scanned.
    origin           = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")


class Violation(Base):
    __tablename__ = "violations"

    id             = Column(Integer, primary_key=True, index=True)
    scan_id        = Column(Integer, ForeignKey("scans.id"))
    dpdp_section   = Column(String)   # e.g. "Section 6"
    section_title  = Column(String)   # e.g. "Consent Requirements"
    severity       = Column(String)   # critical / high / medium
    pii_category   = Column(String)
    evidence       = Column(Text)     # what triggered this
    recommendation = Column(Text)     # what to fix
    # Third-party transmission / logging only: the SDK, host or logger the
    # data reaches (e.g. "firebase", "maps.googleapis.com", "application logs").
    recipient      = Column(String, nullable=True)
    # JSON list of every code location behind the violation
    # ([{"file", "line", ...}]; DPDPViolation.locations).
    locations      = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="violations")



class InstanceMeta(Base):
    """
    One row, key 'instance_id': a random id created the first time the API
    starts against a database. The API and the worker each read it; equal ids
    prove they use the same database, whatever host name each one uses to
    reach it (localhost:15432 from the host vs db:5432 inside Docker).
    """
    __tablename__ = "privacypilot_meta"

    key   = Column(String, primary_key=True)
    value = Column(String, nullable=False)


# ── Demo requests (landing page "See demo") ──────────────────────────────────

class DemoRequest(Base):
    """
    A visitor who asked to watch the product demo, with the consent they gave.
    Only what the notice lists is stored; the notice version and the time of
    consent are kept so the consent can be shown later (DPDP Act S. 6).
    """
    __tablename__ = "demo_requests"

    id               = Column(Integer, primary_key=True, index=True)
    name             = Column(String(100), nullable=False)
    email            = Column(String(254), nullable=False, index=True)
    organisation     = Column(String(120), nullable=True)
    role             = Column(String(80),  nullable=True)
    use_case         = Column(Text,        nullable=True)
    accepted_terms   = Column(Boolean, nullable=False, default=False)
    consent_contact  = Column(Boolean, nullable=False, default=False)   # required to watch
    consent_updates  = Column(Boolean, nullable=False, default=False)   # optional
    notice_version   = Column(String(20),  nullable=False)
    consented_at     = Column(DateTime, default=datetime.utcnow, nullable=False)


# ── Chat tables (LLM compliance chatbot) ─────────────────────────────────────

class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id         = Column(Integer, primary_key=True, index=True)
    scan_id    = Column(Integer, ForeignKey("scans.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    messages = relationship("ChatMessage", back_populates="session",
                            order_by="ChatMessage.id")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("chat_sessions.id"), nullable=False)
    role       = Column(String, nullable=False)   # 'user' | 'assistant'
    content    = Column(Text,   nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("ChatSession", back_populates="messages")


def create_tables():
    Base.metadata.create_all(bind=engine)

def migrate_tables():
    """Apply additive schema migrations to existing tables (idempotent)."""
    import sqlalchemy as sa
    # Use plain ALTER TABLE (no IF NOT EXISTS) — SQLite doesn't support that syntax.
    # The try/except below makes it idempotent: if the column exists, the error is swallowed.
    migrations = [
        "ALTER TABLE scans ADD COLUMN ai_summary TEXT",
        "ALTER TABLE scans ADD COLUMN error_message TEXT",
        "ALTER TABLE scans ADD COLUMN gap_categories TEXT",
        "ALTER TABLE scans ADD COLUMN phase VARCHAR",
        "ALTER TABLE scans ADD COLUMN files_total INTEGER",
        "ALTER TABLE scans ADD COLUMN files_done INTEGER DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN files_seen INTEGER DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN policy_state VARCHAR",
        "ALTER TABLE scans ADD COLUMN chunks_total INTEGER",
        "ALTER TABLE scans ADD COLUMN last_progress_at TIMESTAMP",
        "ALTER TABLE scans ADD COLUMN coverage TEXT",
        "ALTER TABLE scans ADD COLUMN task_id VARCHAR",
        "ALTER TABLE findings ADD COLUMN origin VARCHAR",
        "ALTER TABLE violations ADD COLUMN recipient VARCHAR",
        "ALTER TABLE violations ADD COLUMN locations TEXT",
        # The results page pages through a scan's findings; without this an
        # index-less scan of every finding of every scan runs per page.
        "CREATE INDEX IF NOT EXISTS ix_findings_scan_id ON findings (scan_id)",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(sa.text(sql))
                conn.commit()
            except Exception as e:
                # On Postgres, a failed statement (e.g. "column already
                # exists") leaves the connection's transaction in an
                # aborted state — every subsequent statement on this same
                # connection fails too ("current transaction is aborted")
                # until it's explicitly rolled back. Without this, the
                # FIRST already-applied migration in the list silently
                # poisons every migration listed after it, regardless of
                # whether they themselves would have succeeded.
                conn.rollback()
                msg = str(e).lower()
                if not any(t in msg for t in ("already exists", "duplicate column")):
                    print(f"[db] migration skipped: {e}")


def describe_database_url(url: str | None = None) -> str:
    """The database a process is using, safe to log or show: dialect, host,
    port and database name — never the user name or password."""
    from sqlalchemy.engine import make_url
    try:
        u = make_url(url or DATABASE_URL)
    except Exception:
        return "unparseable DATABASE_URL"
    if u.get_backend_name() == "sqlite":
        return f"sqlite:{os.path.abspath(u.database) if u.database else ':memory:'}"
    return f"{u.get_backend_name()}://{u.host or 'localhost'}:{u.port or ''}/{u.database or ''}"


def database_instance_id(create: bool = False) -> str | None:
    """This database's PrivacyPilot instance id (see InstanceMeta); created
    when `create` is set and missing. None if absent or unreadable."""
    import uuid
    db = SessionLocal()
    try:
        row = db.get(InstanceMeta, "instance_id")
        if row is None and create:
            db.add(InstanceMeta(key="instance_id", value=uuid.uuid4().hex))
            try:
                db.commit()
            except Exception:          # another API process created it first
                db.rollback()
            row = db.get(InstanceMeta, "instance_id")
        return row.value if row else None
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


def scan_gap_categories(scan, findings=None) -> list[str]:
    """
    The scan's consent-gap categories, sorted.

    Uses the persisted Scan.gap_categories list; scans saved before that
    column existed fall back to the stored findings' is_gap flags.
    """
    raw = getattr(scan, "gap_categories", None)
    if raw:
        try:
            return sorted(json.loads(raw))
        except (TypeError, ValueError):
            pass
    return sorted({f.pii_category for f in (findings or []) if f.is_gap})


def location_short(loc: dict) -> str:
    """Compact form for one CSV cell: 'path:line' or 'privacy policy statement N'."""
    if "policy" in loc:
        return (f"privacy policy statement {loc['statement']}" if loc.get("statement")
                else "privacy policy")
    return f"{loc.get('file')}:{loc.get('line')}"


def violation_locations(v) -> list:
    """Every code location behind a stored violation ([] for violations
    stored before locations were recorded)."""
    import json
    try:
        locs = json.loads(getattr(v, "locations", None) or "[]")
    except (TypeError, ValueError):
        return []
    return locs if isinstance(locs, list) else []


def location_label(loc: dict) -> str:
    """'path line N (sinks) (module: …) [third-party code]' — the same form the
    rule engine uses in evidence text. A privacy-policy location (vague
    purpose statement) reads 'privacy policy (URL), statement N: "…"'."""
    if "policy" in loc:
        where = f"privacy policy ({loc['policy']})" if loc.get("policy") else "privacy policy"
        if loc.get("statement"):
            where += f", statement {loc['statement']}"
        return where + (f': "{loc["text"]}"' if loc.get("text") else "")
    s = f"{loc.get('file') or 'unknown file'} line {loc.get('line')}"
    if loc.get("sinks"):
        s += f" ({', '.join(loc['sinks'])})"
    if loc.get("modules"):
        s += f" (module: {', '.join(loc['modules'])})"
    tag = {"third_party": "third-party code", "generated": "generated code"}.get(loc.get("origin"))
    if tag:
        s += f" [{tag}]"
    return s


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()