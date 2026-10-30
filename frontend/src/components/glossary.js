// Plain-English meanings of the terms used on the results page, for readers
// who are not developers or lawyers. Shown when a term is hovered or tapped
// (components/Term.jsx) and listed in the glossary panel.

export const GLOSSARY = {
  // ── Basics ────────────────────────────────────────────────────────────
  pii: { term: 'PII (personal data)', text: 'Short for "personally identifiable information": any detail that can identify a person, such as a name, phone number, e-mail address, Aadhaar or PAN number.' },
  finding: { term: 'Finding', text: 'One place in your code where personal data appears. A finding is not a problem on its own; it is what the checks look at.' },
  violation: { term: 'Violation', text: 'Something in your app that may go against the DPDP Act and should be fixed. Each one says what is wrong, where, and how to fix it.' },
  consent_gap: { term: 'Consent gap', text: 'A kind of personal data your app collects that your privacy policy does not tell people about. Users cannot properly agree to something they were never told.' },
  notice_gap: { term: 'Notice gap', text: 'Same as a consent gap: personal data used in your code but missing from your privacy policy.' },
  critical_issue: { term: 'Critical issue', text: 'A violation involving highly sensitive data (Aadhaar, PAN, health, financial or biometric data). Fix these first.' },
  compliance_score: { term: 'Compliance score', text: 'A score out of 100. It starts at 100 and drops with every violation, more for serious ones. Any critical issue caps the rating at "Poor", whatever the number.' },
  dpdp_act: { term: 'DPDP Act', text: "India's Digital Personal Data Protection Act, 2023: the law on how organisations must collect, use, share and protect people's personal data." },
  dpdp_rules: { term: 'DPDP Rules', text: 'The Digital Personal Data Protection Rules, 2025: the detailed rules issued under the Act, for example what a privacy notice must contain.' },
  privacy_policy: { term: 'Privacy policy', text: 'The page on your website or app that tells people what personal data you collect, why, and who you share it with.' },
  data_fiduciary: { term: 'Data fiduciary', text: 'The organisation that decides why and how personal data is used: usually you, the owner of the app.' },
  data_processor: { term: 'Data processor', text: 'An outside company that handles personal data for you, such as a cloud, SMS, e-mail or payment provider. The law requires a contract with it.' },
  third_party: { term: 'Third party', text: 'An outside company or service, not part of your organisation.' },
  recipient: { term: 'Recipient', text: 'The outside service or company the personal data is sent to.' },
  sdk: { term: 'SDK', text: 'A ready-made code package from another company (for example a payments, analytics or messaging service) built into your app. Data passed to it usually leaves your systems.' },
  logs: { term: 'Logs', text: 'Records an app writes while it runs, mainly for fixing bugs. Many people can read them, so personal data should not be written into them.' },
  evidence: { term: 'Evidence', text: 'What the scan found that led to this result, in words.' },
  locations: { term: 'Locations', text: 'The exact files and line numbers in your code (or statements in your policy) where this was found, so a developer can go straight to them.' },
  fix: { term: 'Fix', text: 'The recommended step to resolve this violation.' },
  source_files: { term: 'Source files', text: 'The files that make up your app’s code.' },
  repository: { term: 'Repository', text: 'The folder (usually on GitHub) that holds all of your app’s code and its history.' },
  vague_purpose: { term: 'Vague purpose', text: 'Your privacy policy gives a reason for using data in general words (like "to improve our services") instead of saying exactly what it is used for.' },
  csv: { term: 'CSV', text: 'A simple spreadsheet file you can open in Excel or Google Sheets.' },

  // ── Severity ─────────────────────────────────────────────────────────
  sev_critical: { term: 'Critical', text: 'Highly sensitive data (Aadhaar, PAN, health, financial or biometric) is involved. Fix immediately.' },
  sev_high: { term: 'High', text: 'A likely breach of the Act involving personal data. Fix soon.' },
  sev_medium: { term: 'Medium', text: 'Needs checking: for example, confirming that you have a contract with a service that receives data.' },
  sev_low: { term: 'Low', text: 'A smaller issue, such as unclear wording in the privacy policy.' },
  severity: { term: 'Severity', text: 'How serious a violation is: Critical, High, Medium or Low.' },
  sensitivity: { term: 'Sensitivity', text: 'How harmful it would be if this data leaked. "High" covers Aadhaar, PAN, health, financial and biometric data.' },

  // ── Where code comes from ──────────────────────────────────────────────
  origin: { term: 'Origin', text: 'Who wrote the code: your team, an outside library, or a build tool.' },
  origin_first_party: { term: 'Your code', text: 'Code written by your own team.' },
  origin_third_party: { term: 'Third-party code', text: 'Code from outside libraries copied into your project (for example a node_modules folder).' },
  origin_generated: { term: 'Generated / built code', text: 'Files produced automatically by build tools, not written by hand.' },
  sent_to: { term: 'Sent to', text: 'The outside service this data is passed to in the code, if any.' },
  code: { term: 'Code', text: 'The line of code where the personal data was found.' },
  detected_by: { term: 'Detected by', text: 'Which of PrivacyPilot’s methods spotted this personal data.' },

  // ── Detection methods ──────────────────────────────────────────────────
  det_code_scanner: { term: 'Pattern match', text: 'Recognised from the shape of the data or the name of a field, for example a 12-digit Aadhaar number or a field called "email".' },
  det_presidio_scanner: { term: 'Language analysis', text: 'An AI language model (named-entity recognition) spotted personal data such as a person’s name in text.' },
  det_taint_analysis: { term: 'Data-flow tracking', text: 'The data was followed through the code to where it is sent or saved.' },
  det_scope_inference: { term: 'Inferred', text: 'The data is not passed by name, but the code sends documents or images containing it to a service that reads them (for example OCR).' },
  det_policy_parser: { term: 'Privacy policy', text: 'Found by reading your privacy policy.' },
  det_policy_parser_bullets: { term: 'Privacy policy', text: 'Found by reading a list in your privacy policy.' },

  // ── Kinds of personal data ─────────────────────────────────────────────
  cat_aadhaar: { term: 'Aadhaar', text: 'The 12-digit national identity number. Highly sensitive.' },
  cat_pan: { term: 'PAN', text: 'Permanent Account Number: the 10-character income-tax ID. Highly sensitive.' },
  cat_phone: { term: 'Phone', text: 'Mobile or landline numbers.' },
  cat_email: { term: 'E-mail', text: 'E-mail addresses.' },
  cat_location: { term: 'Location', text: 'Addresses, GPS coordinates or other details of where a person is or lives.' },
  cat_health: { term: 'Health', text: 'Medical conditions, reports, prescriptions or other health details. Highly sensitive.' },
  cat_financial: { term: 'Financial', text: 'Bank account, card, UPI or payment details. Highly sensitive.' },
  cat_name: { term: 'Name', text: 'A person’s name.' },
  cat_date_of_birth: { term: 'Date of birth', text: 'A person’s date of birth or age.' },
  cat_biometric: { term: 'Biometric', text: 'Fingerprints, face scans, iris scans or similar body measurements. Highly sensitive.' },
  cat_unknown: { term: 'Unknown', text: 'Personal data whose exact kind could not be determined.' },

  // ── DPDP sections used by the checks ──────────────────────────────────
  'Section 5': { term: 'Section 5 (Notice)', text: 'Before asking for consent, you must tell people what personal data you collect and why, how to use their rights, and how to complain.' },
  'Section 6(1)': { term: 'Section 6(1) (Consent)', text: 'People must freely agree to a specific purpose, and you may use only the data needed for that purpose.' },
  'Section 8(1)': { term: 'Section 8(1)', text: 'You remain responsible for personal data even when an outside service handles it for you.' },
  'Section 8(2)': { term: 'Section 8(2) (Data processors)', text: 'You may let an outside service handle personal data for you only under a valid contract.' },
  'Section 8(5)': { term: 'Section 8(5) (Security)', text: 'You must take reasonable security measures to protect personal data from leaks, for example by keeping it out of logs.' },
  'Rule 3(b)(ii)': { term: 'Rule 3(b)(ii) (DPDP Rules 2025)', text: 'Your privacy notice must state clearly the specific purpose for which each kind of data is used.' },

  // ── Violation titles ──────────────────────────────────────────────────
  'Notice Gap — Undisclosed Data Collection': { text: 'Your code collects this kind of personal data, but your privacy policy does not mention it.' },
  'Security Safeguard — PII in Logger Output': { text: 'Personal data is written into the app’s logs, where many people can see it and it can leak.' },
  'Security Safeguard — PII Sent to External Logging Service': { text: 'Personal data is sent to an outside logging or monitoring service.' },
  'Third-Party Transmission — Processor Contract Unverified': { text: 'Personal data goes to an outside service that your policy names. The scan cannot see contracts, so confirm you have one with this service.' },
  'Third-Party Transmission — Undisclosed Data Processor': { text: 'Personal data goes to an outside service that your privacy policy does not mention.' },
  'Purpose–PII Linkage — Processing Exceeds Stated Purpose': { text: 'Your code uses this data for something your privacy policy does not give as a reason.' },
  'Vague Purpose Statement': { text: 'Your privacy policy explains why it uses this data only in vague words. Say exactly what it is used for.' },
};

// Terms shown in the glossary panel, in reading order.
export const GLOSSARY_PANEL = [
  'pii', 'finding', 'violation', 'consent_gap', 'severity', 'critical_issue', 'compliance_score',
  'dpdp_act', 'dpdp_rules', 'privacy_policy', 'data_fiduciary', 'data_processor', 'third_party',
  'recipient', 'sdk', 'logs', 'vague_purpose', 'sensitivity', 'origin', 'source_files',
];
export const GLOSSARY_SECTIONS = ['Section 5', 'Section 6(1)', 'Section 8(2)', 'Section 8(5)', 'Rule 3(b)(ii)'];

export const lookup = (k) => (k == null ? null : GLOSSARY[k] || null);
