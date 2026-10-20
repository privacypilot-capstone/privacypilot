import { useParams, Link } from 'react-router-dom';

const SECTIONS = [
  {
    slug: 'section-5',
    id: 'Section 5',
    label: 'Notice',
    title: 'Notice — Disclosure Before Collection',
    act: 'DPDP Act 2023',
    what: 'Every request for consent must be accompanied or preceded by a notice from the Data Fiduciary. Under Section 5(1) the notice must state (i) the personal data and the purpose for which it is to be processed, (ii) how the Data Principal can withdraw consent and exercise their rights under Sections 6(4) and 13, and (iii) how they can complain to the Data Protection Board. Rule 3 of the DPDP Rules 2025 adds that it must give an itemised description of the personal data in clear and plain language.',
    why: 'Notice is the foundation of consent. Without disclosure, no consent can be free, specific, or informed. Section 5 is the first obligation regulators check because every downstream violation — undisclosed sharing, purpose creep, retention issues — can be traced back to a deficient notice.',
    howpp: [
      'Scans every source file to build a catalogue of all PII categories handled by the codebase.',
      'Parses the privacy policy to extract which PII categories it discloses to users.',
      'Computes the set difference — any category found in code but absent from the policy is a Section 5 violation.',
      'Severity is elevated to "critical" for high-risk categories (Aadhaar, biometric, health, financial, PAN). This is PrivacyPilot\'s own risk tier — the Act does not define a sensitive class of personal data.',
    ],
    example: {
      code: '// users.js\nconst profile = { email, phone, aadhaar_hash };',
      violation: 'Aadhaar hash collected but not mentioned in privacy policy.',
      fix: 'Add "Aadhaar number (hashed)" to the privacy policy under Data Collected, state the purpose, and implement a consent gate before collection.',
    },
  },
  {
    slug: 'section-6-1',
    id: 'Section 6(1)',
    label: 'Consent',
    title: 'Consent — Free, Specific, Informed, Unambiguous',
    act: 'DPDP Act 2023',
    what: 'Consent under Section 6(1) must be free, specific, informed, unconditional and unambiguous, given with a clear affirmative action, and limited to the personal data necessary for the specified purpose. Pre-ticked boxes, bundled consent, or consent obtained after incomplete notice do not meet this standard.',
    why: 'Section 6(1) makes consent the primary legal basis for processing personal data for Indian Data Fiduciaries. Any processing that happens without valid consent — even if the data is collected legitimately — is a standalone violation. It is also triggered whenever Section 5 is violated, because notice is a precondition of informed consent.',
    howpp: [
      'Rule 1 (Notice Gap) fires jointly under Section 5 and Section 6(1) — undisclosed collection automatically invalidates consent.',
      'Rule 3 (Purpose–PII Linkage) also cites Section 6(1) — processing data for a purpose not stated in the policy means consent was never obtained for that use.',
      'Both rules carry the Section 6(1) citation so compliance officers know the consent chain is broken, not just the notice.',
    ],
    example: {
      code: '// analytics.js\nfirebase.logEvent("purchase", { email, revenue });',
      violation: 'Email transmitted to Firebase for analytics. Policy states email is used only for account recovery.',
      fix: 'Either restrict Firebase to non-PII event data, or update the policy to disclose analytics use and obtain fresh specific consent for that purpose.',
    },
  },
  {
    slug: 'section-8-2',
    id: 'Section 8(2)',
    label: 'Processor Contracts',
    title: 'Data Processor Contracts — Third-Party Obligations',
    act: 'DPDP Act 2023',
    what: 'Section 8(2) allows a Data Fiduciary to engage a Data Processor (any entity that processes personal data on its behalf) only under a valid contract. Under Section 8(1) the fiduciary remains responsible for complying with the Act for any processing the processor does on its behalf, and Rule 6(1)(f) of the DPDP Rules 2025 expects that contract to provide for security safeguards.',
    why: 'Most modern applications transmit personal data to dozens of third-party services — analytics SDKs, communication providers, payment processors, cloud queues. Section 8(2) ensures that outsourcing processing does not dilute user rights. Without a Data Processing Agreement (DPA), sharing is unlawful even if the policy mentions the third party.',
    howpp: [
      'Identifies every code location where a PII field is co-located with a third-party SDK call (Firebase, Mixpanel, Amplitude, Segment, Twilio, SendGrid, etc.).',
      'Also follows PII through variable assignments (AST taint analysis) to the call that sends it, so a value read on one line and sent on another is still caught.',
      'Checks whether the privacy policy names that SDK in the same sentence as that data category. A negated mention ("we never share your phone number with Twilio") does not count as disclosure.',
      'Not named → a Section 8(2) "Undisclosed Data Processor" finding (critical for high-risk data, otherwise high). Named → a medium Section 8(2) "Processor Contract Unverified" finding, because whether a valid contract exists cannot be verified from the policy or the code.',
      'High-risk categories (Aadhaar, PAN, health, financial, biometric — PrivacyPilot\'s own tier) are escalated to "critical" severity.',
    ],
    example: {
      code: '// onboarding.js\nmixpanel.track("signup", { email, phone });',
      violation: 'Email and phone transmitted to Mixpanel. Privacy policy does not mention Mixpanel as a data processor.',
      fix: '1. Execute a valid contract (Data Processing Agreement) with Mixpanel. 2. Name Mixpanel in the policy\'s list of processors. 3. Minimise what is sent — e.g. an opaque user ID instead of email and phone.',
    },
  },
  {
    slug: 'section-8-5',
    id: 'Section 8(5)',
    label: 'Security Safeguards',
    title: 'Security Safeguards — Preventing Unauthorised Disclosure',
    act: 'DPDP Act 2023',
    what: 'Section 8(5) requires every Data Fiduciary to protect personal data in its possession or under its control — including processing done on its behalf by a Data Processor — by taking reasonable security safeguards to prevent personal data breach. Rule 6 of the DPDP Rules 2025 lists the minimum safeguards, such as encryption, obfuscation or masking, access control, and logging and monitoring of access. (The separate duty to implement "appropriate technical and organisational measures" is Section 8(4).)',
    why: 'Log files and monitoring systems are among the most common vectors for personal data leakage. Logs flow into cloud observability platforms (Datadog, CloudWatch, Sentry), are often retained indefinitely, and are accessible to a broad set of internal and vendor employees. PII in logs is a breach waiting to happen — and a regulator\'s first stop in a post-incident audit.',
    howpp: [
      'Detects any code location where a PII field appears in a log, print, or monitoring-sink statement.',
      'Matches against a broad set of sink patterns: logging, logger, log.info/debug/warning/error, console.log, print, Sentry, CloudWatch, Datadog.',
      'Each match is a dedicated Section 8(5) violation — distinct from SDK transmission violations.',
      'Recommendations specify PII-scrubbing filters and structured logging patterns.',
    ],
    example: {
      code: '// auth.js\nlogger.info(`Login attempt for ${email} from ${ip}`);',
      violation: 'Email and IP logged in plain text — exposed via log aggregation services to potentially unauthorised parties.',
      fix: 'Replace with structured logging and a PII-scrubbing middleware: logger.info("Login attempt", { userId, ip: maskIP(ip) }). Never log raw PII fields.',
    },
  },
  {
    slug: 'rule-3-b',
    id: 'Rule 3(b)(ii)',
    label: 'Purpose Clarity',
    title: 'Purpose Clarity — DPDP Rules 2025, Rule 3(b)(ii)',
    act: 'DPDP Rules 2025',
    what: 'Rule 3(b)(ii) of the DPDP Rules 2025 requires that a Data Fiduciary\'s notice specifies the purpose of processing personal data in clear and plain language. Vague or generic purpose statements — "to improve services", "for analytics", "for business purposes" — do not satisfy this requirement because they do not give the Data Principal enough information to make a meaningful consent decision.',
    why: 'A vague purpose statement is a legal loophole that enables unlimited data use under a single consent. It also makes consent non-specific, invalidating it under Section 6(1). Regulators consistently flag imprecise purpose language as a first-order compliance failure because it is easy to identify and impossible to defend.',
    howpp: [
      'Takes each policy sentence that names a PII category and compares it, using all-MiniLM-L6-v2 sentence embeddings, with six reference purpose sentences (service delivery, analytics, marketing, security, communication, research). This is zero-shot similarity — no model is trained.',
      'When the top-two similarity scores are within 0.08 of each other, the purpose statement is ambiguous — it reads equally as two different things.',
      'The most ambiguous sentence for each PII category is flagged as one Rule 3(b)(ii) violation, quoting the sentence and showing the margin.',
      'Recommendations identify the ambiguous language and suggest concrete rewrites.',
    ],
    example: {
      code: '// privacy policy excerpt\n"We use your data to provide and improve our services."',
      violation: 'Purpose classifier scores: service_delivery=0.41, analytics=0.38. Margin 0.03 < threshold 0.08 — ambiguous.',
      fix: 'Split into two specific clauses: "We use your email address to authenticate your account and send transaction receipts (service delivery). We use anonymised usage patterns to improve feature performance (analytics)."',
    },
  },
];

export default function DpdpaDetail() {
  const { slug } = useParams();
  const section = SECTIONS.find(s => s.slug === slug);

  if (!section) {
    return (
      <div className="dpdpa-page">
        <div className="dpdpa-not-found">
          <h1>Section not found</h1>
          <Link to="/" className="dpdpa-back">← Back to PrivacyPilot</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="dpdpa-page">
      <header className="dpdpa-header">
        <div className="dpdpa-header-inner">
          <Link to="/" className="dpdpa-back">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="16" height="16"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
            PrivacyPilot
          </Link>
          <div className="dpdpa-header-meta">
            <span className="dpdpa-act-badge">{section.act}</span>
          </div>
        </div>
      </header>

      <main className="dpdpa-main">
        <div className="dpdpa-hero">
          <span className="dpdpa-id-pill">{section.id}</span>
          <h1 className="dpdpa-title">{section.title}</h1>
          <p className="dpdpa-tagline">{section.label} obligation under the {section.act}</p>
        </div>

        <div className="dpdpa-body">

          <div className="dpdpa-card">
            <div className="dpdpa-card-label">What the law says</div>
            <p className="dpdpa-card-text">{section.what}</p>
          </div>

          <div className="dpdpa-card">
            <div className="dpdpa-card-label">Why it matters</div>
            <p className="dpdpa-card-text">{section.why}</p>
          </div>

          <div className="dpdpa-card dpdpa-card-accent">
            <div className="dpdpa-card-label">How PrivacyPilot checks it</div>
            <ul className="dpdpa-check-list">
              {section.howpp.map((step, i) => (
                <li key={i} className="dpdpa-check-item">
                  <span className="dpdpa-check-num">{String(i + 1).padStart(2, '0')}</span>
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="dpdpa-card">
            <div className="dpdpa-card-label">Example violation</div>
            <div className="dpdpa-example">
              <div className="dpdpa-code-block">
                <div className="dpdpa-code-label">Code</div>
                <pre className="dpdpa-pre"><code>{section.example.code}</code></pre>
              </div>
              <div className="dpdpa-ex-row dpdpa-ex-violation">
                <span className="dpdpa-ex-tag dpdpa-ex-tag-red">Violation</span>
                <span>{section.example.violation}</span>
              </div>
              <div className="dpdpa-ex-row dpdpa-ex-fix">
                <span className="dpdpa-ex-tag dpdpa-ex-tag-green">Fix</span>
                <span>{section.example.fix}</span>
              </div>
            </div>
          </div>

        </div>

        <div className="dpdpa-cta-row">
          <Link to="/app" className="dpdpa-cta-btn">Run a compliance scan →</Link>
          <Link to="/#coverage" className="dpdpa-ghost-btn">← All DPDPA sections</Link>
        </div>
      </main>

      <footer className="dpdpa-footer">
        <span>© 2025 PrivacyPilot · DPDP Act 2023 Compliance Engine</span>
        <div className="dpdpa-footer-sections">
          {SECTIONS.map(s => (
            <Link key={s.slug} to={`/dpdpa/${s.slug}`} className={`dpdpa-footer-link${s.slug === slug ? ' active' : ''}`}>
              {s.id}
            </Link>
          ))}
        </div>
      </footer>
    </div>
  );
}
