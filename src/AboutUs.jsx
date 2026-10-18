import { Link } from 'react-router-dom';

const TEAM = [
  {
    name: 'Nishika Shah',
    role: 'Full-Stack & Compliance Engine',
    bio: 'Led the DPDPA rule engine design, PII detection pipeline, and frontend architecture. Focused on translating legal obligations into deterministic automated checks.',
    initials: 'NS',
    color: '#10b981',
  },
  {
    name: 'Mridulika Mukerji',
    role: 'NLP & Policy Parsing',
    bio: 'Built the privacy policy parsing system — purpose extraction, PII category identification, and the vagueness classifier that powers the Rule 3(b)(ii) check.',
    initials: 'MM',
    color: '#6366f1',
  },
  {
    name: 'Atharva Naik',
    role: 'Backend & Report Generation',
    bio: 'Engineered the backend scan orchestration, scoring system, AI executive summary integration, and the PDF report generation pipeline.',
    initials: 'AN',
    color: '#f59e0b',
  },
];

const VALUES = [
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    ),
    title: 'Accuracy first',
    desc: 'Every check maps to a specific provision of the DPDP Act 2023 or DPDP Rules 2025. No generic advice, no invented obligations.',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        <path d="M8 11h6M11 8v6"/>
      </svg>
    ),
    title: 'Code-native',
    desc: 'Compliance tools that only read policy documents miss half the picture. PrivacyPilot reads your actual code — where the data really flows.',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>
      </svg>
    ),
    title: 'Speed',
    desc: 'A full repository audit should take minutes, not weeks. PrivacyPilot runs PII detection, policy parsing, and rule checks in parallel — done under 2 minutes.',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="16" y1="13" x2="8" y2="13"/>
        <line x1="16" y1="17" x2="8" y2="17"/>
      </svg>
    ),
    title: 'Actionable output',
    desc: 'Scan results include severity ratings, exact file locations, legal citations, and specific remediation steps — not just a list of problems.',
  },
];

export default function AboutUs() {
  return (
    <div className="about-page">

      {/* ── Header ── */}
      <header className="about-header">
        <div className="about-header-inner">
          <Link to="/" className="about-back">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="16" height="16">
              <path d="M19 12H5M12 5l-7 7 7 7"/>
            </svg>
            PrivacyPilot
          </Link>
          <span className="about-header-label">About</span>
        </div>
      </header>

      <main className="about-main">

        {/* ── Hero ── */}
        <section className="about-hero">
          <span className="about-kicker">Who we are</span>
          <h1 className="about-h1">Built by engineers who read the Act</h1>
          <p className="about-sub">
            PrivacyPilot is a B.Tech capstone project at MPSTME, Mumbai —
            an automated DPDPA compliance engine that does the work lawyers and auditors
            spend weeks on, in under two minutes.
          </p>
        </section>

        {/* ── Mission ── */}
        <section className="about-mission">
          <div className="about-mission-card">
            <div className="about-section-label">Our mission</div>
            <p className="about-mission-text">
              Indian developers shouldn't need a compliance team to know whether their codebase
              respects the DPDP Act 2023. We built PrivacyPilot to make that knowledge instant,
              precise, and actionable — so privacy becomes a property of the code itself,
              not a checkbox reviewed once a year.
            </p>
          </div>
        </section>

        {/* ── What it is ── */}
        <section className="about-what">
          <div className="about-section-label">What PrivacyPilot actually does</div>
          <div className="about-what-grid">
            <div className="about-what-item">
              <span className="about-what-num">01</span>
              <div>
                <div className="about-what-title">Scans your repository</div>
                <p className="about-what-desc">Regex + NER classifiers detect every PII category across 20+ types in all files — not just surface strings but contextual usage.</p>
              </div>
            </div>
            <div className="about-what-item">
              <span className="about-what-num">02</span>
              <div>
                <div className="about-what-title">Parses your privacy policy</div>
                <p className="about-what-desc">NLP extracts which PII types your policy claims to collect, identifies purpose statements, and scores their specificity.</p>
              </div>
            </div>
            <div className="about-what-item">
              <span className="about-what-num">03</span>
              <div>
                <div className="about-what-title">Runs five DPDPA rule checks</div>
                <p className="about-what-desc">S.5, S.6(1), S.8(2), S.8(5), and Rule 3(b)(ii) — each mapped to a deterministic algorithm, not an LLM guess.</p>
              </div>
            </div>
            <div className="about-what-item">
              <span className="about-what-num">04</span>
              <div>
                <div className="about-what-title">Delivers a compliance report</div>
                <p className="about-what-desc">Score, violation breakdown, AI executive summary via Gemini/Claude, and a downloadable PDF — ready for your DPO in minutes.</p>
              </div>
            </div>
          </div>
        </section>

        {/* ── Values ── */}
        <section className="about-values">
          <div className="about-section-label">What we believe</div>
          <div className="about-values-grid">
            {VALUES.map((v, i) => (
              <div key={i} className="about-value-card">
                <div className="about-value-icon">{v.icon}</div>
                <div className="about-value-title">{v.title}</div>
                <p className="about-value-desc">{v.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Team ── */}
        <section className="about-team">
          <div className="about-section-label">The team</div>
          <div className="about-team-grid">
            {TEAM.map((m, i) => (
              <div key={i} className="about-team-card">
                <div className="about-avatar" style={{ background: m.color + '20', color: m.color, border: `2px solid ${m.color}30` }}>
                  {m.initials}
                </div>
                <div className="about-team-name">{m.name}</div>
                <div className="about-team-role">{m.role}</div>
                <p className="about-team-bio">{m.bio}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Tech ── */}
        <section className="about-tech">
          <div className="about-section-label">Under the hood</div>
          <div className="about-tech-grid">
            {[
              ['Frontend', 'React · Vite · React Router'],
              ['NLP / ML', 'spaCy · scikit-learn · sentence-transformers'],
              ['Backend', 'FastAPI · Python'],
              ['AI Summary', 'Google Gemini · Anthropic Claude'],
              ['Reports', 'WeasyPrint · PDF generation'],
              ['Act coverage', 'DPDP Act 2023 · DPDP Rules 2025'],
            ].map(([label, stack], i) => (
              <div key={i} className="about-tech-item">
                <div className="about-tech-label">{label}</div>
                <div className="about-tech-stack">{stack}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ── CTA ── */}
        <div className="about-cta-row">
          <Link to="/app" className="about-cta-btn">Try PrivacyPilot →</Link>
          <Link to="/" className="about-ghost-btn">Back to home</Link>
        </div>

      </main>

      <footer className="about-footer">
        <span>© 2025 PrivacyPilot · MPSTME, Mumbai · B.Tech Capstone Project</span>
        <div className="about-footer-links">
          <Link to="/#features">Features</Link>
          <Link to="/dpdpa/section-5">DPDPA</Link>
          <Link to="/app">Scan now</Link>
        </div>
      </footer>

    </div>
  );
}
