"""
LLM-prompt baseline for the real-world set (report, Section 4.7).

One prompt per repository: the privacy policy plus the lines of source code that
mention personal data, logging or network calls (with 2 lines of context), then
the question "which DPDP violations of these five kinds does this code have?".
No PrivacyPilot analysis is used. The answer is parsed into the same units as
PrivacyPilot's report so both are scored against the same reference set.

Usage (from the project root, with an LLM key in backend/.env):
    python eval/llm_baseline.py --workdir C:\\work\\llm_baseline --out llm_baseline.json
Optional: --repos name1,name2  --budget-chars 90000  --dry-run (build prompts only)

Repositories are cloned at the annotated commits (Appendix A.3); policies are
fetched from the URLs in the annotation workbook (Scope sheet).
"""
import argparse, json, os, re, subprocess, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

REPOS = {  # name: (git url, commit, policy url)
    "urbanclap-engg/smart-docs-parser": ("https://github.com/urbanclap-engg/smart-docs-parser", "427c7bdf35c99e571e461bfa1056d35006325d1f", "https://www.urbancompany.com/privacy-policy"),
    "surepassio/mrz-surepass": ("https://github.com/surepassio/mrz-surepass", "a9ccccb369abf0b2a6555b64242d41c70aaca397", "https://surepass.io/privacy-policy/"),
    "Sunbird-Ed/SunbirdEd-portal": ("https://github.com/Sunbird-Ed/SunbirdEd-portal", "9efc8b5819c6417bed695716bffc2d3cd231471e", "https://www.sunbird.org/privacy-policy"),
    "Sunbird-Ed/SunbirdEd-mobile-app": ("https://github.com/Sunbird-Ed/SunbirdEd-mobile-app", "9de5e085d0c73e18df5f995427b05bf4d0ec712d", "https://www.sunbird.org/privacy-policy"),
    "Sunbird-Ed/sunbird-client-services": ("https://github.com/Sunbird-Ed/sunbird-client-services", "495367d8e85cd806a7411344dde11ca9705990a1", "https://www.sunbird.org/privacy-policy"),
    "razorpay/razorpay-python": ("https://github.com/razorpay/razorpay-python", "8960507a29854c8a484d130139179c2429c2f45c", "https://razorpay.com/privacy-policy/"),
    "razorpay/razorpay-node": ("https://github.com/razorpay/razorpay-node", "b9e8527225a7322ba2671a3bc0b848fd019d2d8c", "https://razorpay.com/privacy-policy/"),
    "zerodha/pykiteconnect": ("https://github.com/zerodha/pykiteconnect", "2f67c46ead6864425744abe5ec386979ee39c69f", "https://zerodha.com/privacy-policy/"),
    "zerodha/kiteconnectjs": ("https://github.com/zerodha/kiteconnectjs", "795128916c5e48118b781fe8535b58b872fdc45a", "https://zerodha.com/privacy-policy/"),
}
EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
CATS = ["aadhaar", "pan", "phone", "email", "location", "health", "financial", "name", "date_of_birth", "biometric"]
CHECKS = ["Notice gap", "Third-party transmission", "Personal data in logs", "Purpose linkage", "Vague purpose"]
KEY = re.compile(r"aad(h)?a(a)?r|\bpan\b|phone|mobile|msisdn|e[-_]?mail|latitude|longitude|geolocation|location|health|medical|"
                 r"account_?(no|number)|ifsc|card_?number|first_?name|last_?name|full_?name|user_?name|\bdob\b|birth|fingerprint|biometric|"
                 r"console\.|logger\.|logging\.|\bprint\(|axios|fetch\(|requests\.|http", re.I)

PROMPT = """You are auditing a software repository against India's Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025.
You are given the organisation's privacy policy and excerpts of the repository's source code (file path, then lines).

Report violations of exactly these five kinds, using these data categories only: {cats}.
1. "Notice gap": the code processes a category that the privacy policy does not disclose.
2. "Third-party transmission": the code sends a category to a third party (give "recipient") that the policy does not name for that category.
3. "Personal data in logs": the code writes a category to logs (use recipient "logs").
4. "Purpose linkage": the code uses a category for a purpose the policy does not state for it.
5. "Vague purpose": the policy states no specific purpose for a category it covers.
Report only what the material supports. Answer with JSON only: a list of objects
{{"check": one of {checks}, "category": one of the categories, "recipient": string or null, "evidence": "file path or policy quote"}}.

=== PRIVACY POLICY ===
{policy}

=== SOURCE EXCERPTS ===
{code}
"""

def clone(name, url, sha, workdir):
    d = os.path.join(workdir, name.replace("/", "__"))
    if not os.path.isdir(d):
        subprocess.run(["git", "clone", "--quiet", url, d], check=True)
    subprocess.run(["git", "-C", d, "checkout", "--quiet", sha], check=True)
    return d

def excerpts(root, budget):
    scored = []
    for dp, dn, fs in os.walk(root):
        dn[:] = [x for x in dn if x not in (".git", "node_modules", "dist", "build")]
        for fn in fs:
            if not fn.endswith(EXT):
                continue
            p = os.path.join(dp, fn)
            lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
            hit = [i for i, l in enumerate(lines) if KEY.search(l) and len(l) < 400]
            if not hit:
                continue
            keep = sorted({j for i in hit for j in range(max(0, i - 2), min(len(lines), i + 3))})
            body = "\n".join(f"{j+1}: {lines[j][:200]}" for j in keep)[:3000]   # per-file cap: spread the budget over many files
            scored.append((len(hit), os.path.relpath(p, root).replace("\\", "/"), body))
    scored.sort(key=lambda t: -t[0])          # files with the most mentions first
    out, used = [], 0
    for _, rel, body in scored:
        chunk = f"--- {rel}\n{body}\n"
        if used + len(chunk) > budget:
            continue
        out.append(chunk); used += len(chunk)
    return "".join(out), used, len(scored), len(out)

def parse(answer):
    m = re.search(r"\[.*\]", answer, re.S)
    items = json.loads(m.group(0)) if m else []
    units = set()
    for it in items:
        c, k = it.get("check"), str(it.get("category", "")).lower()
        if c in CHECKS and k in CATS:
            rec = (it.get("recipient") or "").strip().lower() or None
            units.add((c, k, rec if c in ("Third-party transmission", "Personal data in logs") else None))
    return sorted(units, key=str)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True); ap.add_argument("--out", default="llm_baseline.json")
    ap.add_argument("--repos", default=""); ap.add_argument("--budget-chars", type=int, default=90000)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    from dotenv import load_dotenv; load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend", ".env"))
    from scanners.policy_parser import fetch_policy_text
    import llm_client
    os.makedirs(a.workdir, exist_ok=True)
    res = {}
    for name, (url, sha, pol_url) in REPOS.items():
        if a.repos and not any(r in name for r in a.repos.split(",")):
            continue
        root = clone(name, url, sha, a.workdir)
        policy = fetch_policy_text(pol_url)[1][:40000]
        code, used, nfiles, nkept = excerpts(root, a.budget_chars)
        prompt = PROMPT.format(cats=", ".join(CATS), checks=json.dumps(CHECKS), policy=policy, code=code)
        print(f"{name}: {nkept}/{nfiles} files with mentions, {used} chars of code, prompt {len(prompt)} chars")
        if a.dry_run:
            continue
        ans = llm_client._llm_call("You are a careful privacy-compliance auditor.", [{"role": "user", "content": prompt}])
        res[name] = {"units": parse(ans), "files_with_mentions": nfiles, "files_in_prompt": nkept, "raw": ans}
        json.dump(res, open(a.out, "w"), indent=1)
    print("written", a.out)

if __name__ == "__main__":
    main()
