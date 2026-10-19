# ── Phase 9: JavaScript taint via tree-sitter ────────────────────────────

from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs

JS_LANGUAGE = Language(tsjs.language())
js_parser = Parser(JS_LANGUAGE)

PII_FIELDS_JS = {
    "bloodGroup":     "health",
    "blood_group":    "health",
    "aadhaarNumber":  "aadhaar",
    "aadhaar_number": "aadhaar",
    "phoneNumber":    "phone",
    "phone_number":   "phone",
    "panNumber":      "pan",
    "biometricHash":  "biometric",
}

SDK_SINKS_JS = {
    "firebase", "mixpanel", "twilio", "segment",
    "amplitude", "analytics", "logger", "console",
}


def get_node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8")


def build_taint_map_js(source_code: str) -> dict[str, str]:
    """
    Build taint map for JavaScript source using tree-sitter.
    Handles:
    - Member expression: patient.bloodGroup
    - Variable declarator: const data = patient.bloodGroup
    - Alias: const record = data
    """
    source_bytes = source_code.encode("utf-8")
    tree = js_parser.parse(source_bytes)
    taint_map = {}

    def walk(node):
        # Variable declaration: const data = patient.bloodGroup
        if node.type == "variable_declarator":
            name_node  = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")

            if name_node and value_node:
                var_name = get_node_text(name_node, source_bytes)
                rhs_taint = None

                # Case 1: RHS is member expression — patient.bloodGroup
                if value_node.type == "member_expression":
                    prop = value_node.child_by_field_name("property")
                    if prop:
                        field_name = get_node_text(prop, source_bytes)
                        if field_name in PII_FIELDS_JS:
                            rhs_taint = PII_FIELDS_JS[field_name]

                # Case 2: RHS is identifier already in taint_map — alias
                elif value_node.type == "identifier":
                    rhs_name = get_node_text(value_node, source_bytes)
                    if rhs_name in taint_map:
                        rhs_taint = taint_map[rhs_name]

                if rhs_taint:
                    taint_map[var_name] = rhs_taint

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return taint_map


def find_sink_violations_js(source_code: str, taint_map: dict) -> list[dict]:
    source_bytes = source_code.encode("utf-8")
    tree = js_parser.parse(source_bytes)
    violations = []

    def check_arg_for_taint(arg_node) -> str | None:
        """
        Recursively check an argument node for tainted variables.
        Handles: direct identifier, object literal values,
        array elements, nested objects.
        """
        # Direct identifier: firebase.log(phone)
        if arg_node.type == "identifier":
            name = get_node_text(arg_node, source_bytes)
            if name in taint_map:
                return name

        # Object literal: firebase.log({ to: phone, data: health })
        if arg_node.type == "object":
            for child in arg_node.children:
                if child.type == "pair":
                    value_node = child.child_by_field_name("value")
                    if value_node:
                        result = check_arg_for_taint(value_node)
                        if result:
                            return result

        # Array: firebase.log([phone, data])
        if arg_node.type == "array":
            for child in arg_node.children:
                result = check_arg_for_taint(child)
                if result:
                    return result

        return None

    def walk(node):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")

            if func_node and args_node:
                func_text = get_node_text(func_node, source_bytes).lower()
                is_sdk = any(sdk in func_text for sdk in SDK_SINKS_JS)

                if is_sdk:
                    for arg in args_node.children:
                        tainted_var = check_arg_for_taint(arg)
                        if tainted_var:
                            violations.append({
                                "line":         node.start_point[0] + 1,
                                "sink":         func_text,
                                "pii_category": taint_map[tainted_var],
                                "variable":     tainted_var,
                            })

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return violations

# ── JavaScript test cases ──────────────────────────────────────────────────
print("\n" + "=" * 65)
print("PHASE 9: JavaScript Taint via tree-sitter")
print("=" * 65)

# JS Test 1: Direct field access + alias (same as Python Test 1)
JS_CODE_1 = """
function processPatient(patient) {
    const data   = patient.bloodGroup;
    const record = data;
    firebase.log(record);
}
"""

print("\n--- JS Test 1: Direct field access + alias ---")
taint_js1 = build_taint_map_js(JS_CODE_1)
violations_js1 = find_sink_violations_js(JS_CODE_1, taint_js1)
print(f"  Taint map: {taint_js1}")
print(f"  Violations: {violations_js1}")
j1_taint_ok = (taint_js1.get("data") == "health" and
               taint_js1.get("record") == "health")
j1_viol_ok  = any(v["pii_category"] == "health" for v in violations_js1)
print(f"  {'✓' if j1_taint_ok else '✗'} Taint propagated through alias")
print(f"  {'✓' if j1_viol_ok  else '✗'} Firebase violation detected")

# JS Test 2: Cross-line (same V5 pattern as Python)
JS_CODE_2 = """
function sendReminder(patient) {
    const phone = patient.phoneNumber;
    twilio.messages.create({ to: phone });
}
"""

print("\n--- JS Test 2: Cross-line Twilio (V5 equivalent in JavaScript) ---")
taint_js2 = build_taint_map_js(JS_CODE_2)
violations_js2 = find_sink_violations_js(JS_CODE_2, taint_js2)
print(f"  Taint map: {taint_js2}")
print(f"  Violations: {violations_js2}")
j2_taint_ok = taint_js2.get("phone") == "phone"
j2_viol_ok  = any(v["pii_category"] == "phone" for v in violations_js2)
print(f"  {'✓' if j2_taint_ok else '✗'} phoneNumber correctly tainted")
print(f"  {'✓' if j2_viol_ok  else '✗'} Cross-line Twilio violation detected")

# JS Test 3: No false positives
JS_CODE_3 = """
function scheduleAppointment(patient) {
    const slot = patient.appointmentTime;
    firebase.log(slot);
}
"""

print("\n--- JS Test 3: No false positive (appointmentTime not PII) ---")
taint_js3 = build_taint_map_js(JS_CODE_3)
violations_js3 = find_sink_violations_js(JS_CODE_3, taint_js3)
j3_clean = len(violations_js3) == 0
print(f"  Taint map: {taint_js3}")
print(f"  {'✓' if j3_clean else '✗'} No false positive")

js_all = [j1_taint_ok, j1_viol_ok, j2_taint_ok, j2_viol_ok, j3_clean]
js_passed = sum(js_all)
print(f"\nJS tests passed: {js_passed}/5")
print(f"{'PHASE 9: PASS' if js_passed >= 4 else 'PHASE 9: FAIL'}")

JS_CODE_4 = """
function trackPatient(patient) {
    const aadhaar = patient.aadhaarNumber;
    firebase.logEvent('patient_visit', { user_id: aadhaar, timestamp: Date.now() });
}
"""

print("\n--- JS Test 4: Object literal argument (common real-world pattern) ---")
taint_js4 = build_taint_map_js(JS_CODE_4)
violations_js4 = find_sink_violations_js(JS_CODE_4, taint_js4)
print(f"  Taint map: {taint_js4}")
print(f"  Violations: {violations_js4}")
j4_viol_ok = any(v["pii_category"] == "aadhaar" for v in violations_js4)
print(f"  {'✓' if j4_viol_ok else '✗'} Object literal argument detected")