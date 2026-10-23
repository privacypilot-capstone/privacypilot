from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class PIICategory(str, Enum):
    AADHAAR    = "aadhaar"
    PAN        = "pan"
    PHONE      = "phone"
    EMAIL      = "email"
    LOCATION   = "location"
    HEALTH     = "health"
    FINANCIAL  = "financial"
    NAME       = "name"
    DOB        = "date_of_birth"
    BIOMETRIC  = "biometric"
    UNKNOWN    = "unknown"

class Sensitivity(str, Enum):
    SENSITIVE = "sensitive"
    PERSONAL  = "personal"
    UNKNOWN   = "unknown"

class DataFlowObject(BaseModel):
    source:       str
    file_path:    Optional[str] = None
    line_number:  Optional[int] = None
    raw_text:     str
    field_name:   str
    pii_category: PIICategory
    sensitivity:  Sensitivity
    third_party_sdk:         Optional[str]       = None
    policy_claim_matched:    Optional[str]       = None
    is_gap:                  Optional[bool]      = None
    dpdp_sections_violated:  Optional[List[str]] = None
    severity:                Optional[str]       = None
    # first_party | third_party | generated — where the file came from
    # (repo_snapshot.classify_path). None for policy claims.
    origin:                  Optional[str]       = None
    # Code-module labels of the file the finding is in (code_scanner
    # classify_module: analytics, payment, …). None for policy claims and
    # findings stored before this field existed.
    module_types:            Optional[List[str]] = None
    # For a finding inside a (possibly multi-line) sink call: the line the
    # call starts on. Several findings in one call are one transmission.
    call_line:               Optional[int]       = None