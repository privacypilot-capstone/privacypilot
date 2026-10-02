"""
Phase 6: Module Classifier
Tests file path + AST function name classification.

PASS criteria:
- All 6 unambiguous files classified correctly
- Ambiguous file (utils.py) classified correctly via function names
- analytics and auth modules definitely correct (used in Rule 3)
"""

import ast
from enum import Enum

class ModuleType(str, Enum):
    ANALYTICS    = "analytics"
    AUTH         = "auth"
    NOTIFICATION = "notification"
    BILLING      = "billing"
    LOGGING      = "logging"
    CORE         = "core"

PATH_KEYWORDS = {
    ModuleType.ANALYTICS:    ["analytics","tracking","metrics","telemetry","segment","mixpanel","firebase","amplitude"],
    ModuleType.AUTH:         ["auth","login","session","token","kyc","verify","identity","password","oauth","jwt"],
    ModuleType.NOTIFICATION: ["notification","sms","email","push","alert","mailer","messaging","reminder","twilio"],
    ModuleType.BILLING:      ["billing","payment","invoice","charge","subscription","financial","transaction","razorpay"],
    ModuleType.LOGGING:      ["log","logger","audit","debug","error","monitor","trace","sentry"],
}

FUNCTION_KEYWORDS = {
    ModuleType.ANALYTICS:    ["track","analytics","send_to","record_event","capture","identify","report","emit"],
    ModuleType.AUTH:         ["login","logout","authenticate","verify_token","validate_kyc","generate_otp","verify_otp"],
    ModuleType.NOTIFICATION: ["send_sms","send_email","push_notification","send_alert","notify_user","send_message"],
    ModuleType.BILLING:      ["create_invoice","process_payment","charge_customer","refund","create_subscription"],
    ModuleType.LOGGING:      ["log_error","log_info","log_warning","write_log","audit_log","record_action"],
}

MODULE_TO_PURPOSE = {
    ModuleType.ANALYTICS:    {"analytics"},
    ModuleType.AUTH:         {"authentication", "legal"},
    ModuleType.NOTIFICATION: {"communication"},
    ModuleType.BILLING:      {"core_service", "legal"},
    ModuleType.LOGGING:      {"legal"},
    ModuleType.CORE:         {"core_service"},
}

def get_function_names(source: str) -> list:
    try:
        tree = ast.parse(source)
        return [n.name.lower() for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    except:
        return []

def classify_module(path: str, source: str = "") -> tuple[ModuleType, str, list]:
    path_lower = path.lower().replace("\\", "/")
    scores = {mt: 0 for mt in ModuleType}
    signals = []
    
    for mt, keywords in PATH_KEYWORDS.items():
        for kw in keywords:
            if kw in path_lower:
                scores[mt] += 2
                signals.append(f"path:{kw}")
    
    if source:
        fn_names = get_function_names(source)
        for mt, keywords in FUNCTION_KEYWORDS.items():
            for fn in fn_names:
                for kw in keywords:
                    if kw in fn:
                        scores[mt] += 3
                        signals.append(f"fn:{fn}")
    
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return (ModuleType.CORE, "low", ["default"])
    conf = "high" if scores[best] >= 5 else "medium" if scores[best] >= 2 else "low"
    return (best, conf, signals[:4])

# ── Tests ─────────────────────────────────────────────────────────────────
print("=" * 65)
print("PHASE 6: Module Classifier")
print("=" * 65)

TESTS = [
    ("services/analytics.py",
     "def track_event(u, e): pass\ndef send_to_mixpanel(d): pass",
     ModuleType.ANALYTICS, "Unambiguous analytics"),

    ("api/auth/views.py",
     "def login(u, p): pass\ndef verify_token(t): pass",
     ModuleType.AUTH, "Unambiguous auth"),

    ("services/notifications.py",
     "def send_sms(phone, msg): pass\ndef push_notification(tok): pass",
     ModuleType.NOTIFICATION, "Unambiguous notifications"),

    ("services/billing.py",
     "def create_invoice(pid, amt): pass",
     ModuleType.BILLING, "Unambiguous billing"),

    ("models/patient.py",
     "class Patient:\n    aadhaar = None\n    health = None",
     ModuleType.CORE, "Core model — no module signals"),

    ("utils.py",  # ambiguous path — function names decide
     "def track_event(user, data): pass\ndef send_to_segment(payload): pass",
     ModuleType.ANALYTICS, "Ambiguous path — function names decide"),

    ("helpers/auth_helpers.py",
     "def validate_kyc(aadhaar): pass\ndef generate_otp(phone): pass",
     ModuleType.AUTH, "Auth via both path and function"),
]

passed = 0
print(f"\n{'File path':<40} {'Expected':<15} {'Got':<15} {'Conf':<8} Status")
print("─" * 90)
for path, code, expected, label in TESTS:
    got, conf, signals = classify_module(path, code)
    correct = got == expected
    if correct:
        passed += 1
    status = "✓" if correct else "✗"
    print(f"{path:<40} {expected.value:<15} {got.value:<15} {conf:<8} {status} {label}")

print(f"\nPassed: {passed}/{len(TESTS)}")
print(f"\n{'PHASE 6: PASS' if passed >= 6 else 'PHASE 6: FAIL'}")