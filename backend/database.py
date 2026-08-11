from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://pilot:pilot@db:5432/privacypilot"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ── Tables ────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id           = Column(Integer, primary_key=True, index=True)
    repo_url     = Column(String, nullable=False)
    policy_url   = Column(String, nullable=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    findings_count   = Column(Integer, default=0)
    policy_count     = Column(Integer, default=0)
    gaps_count       = Column(Integer, default=0)
    violations_count = Column(Integer, default=0)

    findings   = relationship("Finding",   back_populates="scan")
    violations = relationship("Violation", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id               = Column(Integer, primary_key=True, index=True)
    scan_id          = Column(Integer, ForeignKey("scans.id"))
    source           = Column(String)
    file_path        = Column(String, nullable=True)
    line_number      = Column(Integer, nullable=True)
    raw_text         = Column(Text)
    field_name       = Column(String)
    pii_category     = Column(String)
    sensitivity      = Column(String)
    third_party_sdk  = Column(String, nullable=True)
    is_gap           = Column(Boolean, nullable=True)

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

    scan = relationship("Scan", back_populates="violations")


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()