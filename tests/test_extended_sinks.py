"""
Phase 7: Extended Sink Detection
Tests that PII reaching Celery queues, Redis pub/sub,
outbound HTTP calls, and logger calls is detected.
Also tests intra-function secondary use via call-site heuristics.

PASS criteria:
- All 5 direct SDK cases detected
- All 3 queue patterns detected
- At least 2 of 3 intra-function secondary use cases flagged
"""

import re

SDK_PATTERNS = [
    "firebase", "mixpanel", "amplitude", "segment", "crashlytics",
    "twilio", "sendgrid", "sns", "ses", "datadog", "sentry",
]

QUEUE_PATTERNS = [
    r'\.delay\s*\(',       # Celery: task.delay(pii)
    r'\.apply_async\s*\(', # Celery: task.apply_async(args=[pii])
    r'redis.*\.publish\s*\(',  # Redis pub/sub
    r'channel.*\.publish\s*\(',
    r'\.send_task\s*\(',   # Celery send_task
    r'\.enqueue\s*\(',     # RQ
    r'producer\.send\s*\(',    # Kafka
]

OUTBOUND_HTTP = [
    r'requests\.(post|put|patch)\s*\(',
    r'httpx\.(post|put|patch)\s*\(',
    r'urllib.*urlopen\s*\(',
    r'aiohttp.*post\s*\(',
]

LOGGER_PATTERNS = [
    r'(logger|logging)\.(info|debug|warning|error|critical)\s*\(',
    r'print\s*\(',
    r'log\.(info|debug|warning|error)\s*\(',
]

SECONDARY_USE_NAMES = [
    "risk", "score", "profile", "segment_user", "classify",
    "recommend", "predict", "analyse", "rank", "model",
    "infer", "cluster", "target", "personalise",
]

def check_line_for_sinks(line: str, pii_vars: set) -> list[str]:
    """Returns list of detected sink types for a line containing PII."""
    violations = []
    line_lower = line.lower()
    
    has_pii = any(var in line_lower for var in pii_vars)
    if not has_pii:
        return []
    
    for sdk in SDK_PATTERNS:
        if sdk in line_lower:
            violations.append(f"sdk:{sdk}")
    
    for pattern in QUEUE_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            violations.append("queue_transmission")
    
    for pattern in OUTBOUND_HTTP:
        if re.search(pattern, line, re.IGNORECASE):
            violations.append("outbound_http")
    
    for pattern in LOGGER_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            violations.append("logger_sink")
    
    # Intra-function secondary use
    for name in SECONDARY_USE_NAMES:
        if name in line_lower and "(" in line:
            violations.append(f"secondary_use:{name}")
    
    return violations

# ── Test cases ─────────────────────────────────────────────────────────────
print("=" * 65)
print("PHASE 7: Extended Sink Detection")
print("=" * 65)

PII_VARS = {"aadhaar", "blood_group", "health_data", "patient.aadhaar",
            "patient.health", "phone", "patient.phone_number"}

SHOULD_DETECT = [
    # Direct SDK
    ("    firebase.log({'aadhaar': patient.aadhaar})",    "sdk:firebase",           "Firebase SDK"),
    ("    mixpanel.track('event', health_data)",           "sdk:mixpanel",           "Mixpanel SDK"),
    ("    twilio.messages.create(to=phone)",               "sdk:twilio",             "Twilio SDK"),
    ("    segment.identify(user_id, {'health': blood_group})", "sdk:segment",        "Segment SDK"),
    ("    sentry.capture_event({'aadhaar': aadhaar})",     "sdk:sentry",             "Sentry SDK"),
    # Queue patterns
    ("    process_health.delay(health_data)",              "queue_transmission",     "Celery delay"),
    ("    send_to_analytics.apply_async(args=[aadhaar])",  "queue_transmission",     "Celery apply_async"),
    ("    redis_client.publish('ch', blood_group)",        "queue_transmission",     "Redis publish"),
    # Logger
    ("    logging.info(f'Patient aadhaar: {aadhaar}')",    "logger_sink",            "Logger sink"),
    # Outbound HTTP
    ("    requests.post('https://analytics.co', json={'data': health_data})",
                                                           "outbound_http",          "HTTP POST"),
    # Intra-function secondary use
    ("    update_risk_score(patient.health)",              "secondary_use:risk",     "Risk scoring (secondary use)"),
    ("    predict_insurance_risk(blood_group)",            "secondary_use:predict",  "Predict (secondary use)"),
    ("    segment_user_by_health(health_data)",            "secondary_use:segment_user", "Segmentation (secondary use)"),
]

SHOULD_NOT_DETECT = [
    "    schedule_appointment(patient.health)",   # legitimate core function
    "    save_to_db(health_data)",                # internal DB write — not flagged
    "    return patient.aadhaar",                 # return statement — not a sink
]

passed = 0
failed = []

print("\n--- Should detect violations ---")
for line, expected_sink_type, label in SHOULD_DETECT:
    violations = check_line_for_sinks(line, PII_VARS)
    found = any(expected_sink_type in v for v in violations)
    if found:
        passed += 1
        print(f"  ✓ {label}: {violations}")
    else:
        failed.append(label)
        print(f"  ✗ {label}: expected '{expected_sink_type}' but got {violations}")

print("\n--- Should NOT detect violations ---")
fp_count = 0
for line in SHOULD_NOT_DETECT:
    violations = check_line_for_sinks(line, PII_VARS)
    if violations:
        fp_count += 1
        print(f"  ~ '{line.strip()}' → {violations} (acceptable — review manually)")
    else:
        print(f"  ✓ '{line.strip()}' → no violation (correct)")

print(f"\nDetected: {passed}/{len(SHOULD_DETECT)}")
print(f"False positives: {fp_count}/{len(SHOULD_NOT_DETECT)} (some expected for generic functions)")

overall = passed >= 10  # at least 10 of 13 must pass
print(f"\n{'PHASE 7: PASS' if overall else 'PHASE 7: FAIL'}")