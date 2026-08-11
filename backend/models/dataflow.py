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
    SENSITIVE = "sensitive"   # aadhaar, health, biometric, financial
    PERSONAL  = "personal"    # name, email, phone, dob, location
    UNKNOWN   = "unknown"

class DataFlowObject(BaseModel):
    # Where it was found
    source:       str                    # "code_scanner" or "policy_parser"
    file_path:    Optional[str] = None   # e.g. "app/models/user.py"
    line_number:  Optional[int] = None

    # What was found
    raw_text:     str                    # the actual line or clause
    field_name:   str                    # e.g. "phone_number"
    pii_category: PIICategory
    sensitivity:  Sensitivity

    # Where data goes
    third_party_sdk: Optional[str] = None  # e.g. "firebase", "twilio"

    # Filled later by Consent Gap Detector
    policy_claim_matched: Optional[str]  = None
    is_gap:               Optional[bool] = None

    # Filled later by DPDP Mapper
    dpdp_sections_violated: Optional[List[str]] = None
    severity: Optional[str] = None  # "critical" | "high" | "medium" | "low"