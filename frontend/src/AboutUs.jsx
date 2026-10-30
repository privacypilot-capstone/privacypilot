import { Link } from 'react-router-dom';

const TEAM = [
  {
    name: 'Nishika Shah',
    role: 'Full-Stack & Compliance Engine',
    bio: 'Led the DPDPA rule engine design, PII detection pipeline, and frontend architecture. Focused on translating legal obligations into deterministic automated checks.',
    initials: 'NS',
    photo: '/team/nishika-shah.webp',
    linkedin: 'https://www.linkedin.com/in/nishika-shah-629b85268/',
    color: '#10b981',
  },
  {
    name: 'Mridulika Mukerji',
    role: 'NLP & Policy Parsing',
    bio: 'Built the privacy policy parsing system — purpose extraction, PII category identification, and the vagueness classifier that powers the Rule 3(b)(ii) check.',
    initials: 'MM',
    photo: '/team/mridulika-mukerji.webp',
    linkedin: 'https://www.linkedin.com/in/mridulika-mukerji-abb229316/',
    color: '#6366f1',
  },
  {
    name: 'Atharva Naik',
    role: 'Backend & Report Generation',
    bio: 'Engineered the backend scan orchestration, scoring system, AI executive summary integration, and the PDF report generation pipeline.',
    initials: 'AN',
    photo: '/team/atharva-naik.webp',
    linkedin: 'https://www.linkedin.com/in/atharva-naik-015095214/',
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
    desc: 'Every check maps to a specific provision of the DPDP Act 2023 or DPDP Rules 2025. Where PrivacyPilot adds its own judgement, such as treating Aadhaar or health data as critical, it says so.',
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
    desc: 'A repository audit should take minutes, not weeks. PrivacyPilot scans code in parallel chunks while it reads the privacy policy: about half a minute for a small repository, a few minutes for one with 1,500 source files.',
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
            an automated DPDP Act compliance engine that checks an application's source code
            against its privacy policy, in minutes.
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
                <p className="about-what-desc">Pattern matching, named-entity recognition and data-flow tracking find ten kinds of personal data (Aadhaar, PAN, health, financial, biometric and more) in every source file, and follow where the data goes.</p>
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
                <p className="about-what-desc">S.5, S.6(1), S.8(2), S.8(5) and Rule 3(b)(ii). The checks are fixed rules (judging vague purpose wording also uses a small language model); no generative AI is used to find violations.</p>
              </div>
            </div>
            <div className="about-what-item">
              <span className="about-what-num">04</span>
              <div>
                <div className="about-what-title">Delivers a compliance report</div>
                <p className="about-what-desc">Score, violation breakdown with exact code locations, an AI executive summary (Google Gemini, with OpenAI as fallback), and downloadable PDF, HTML and CSV reports.</p>
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
                {m.photo
                  ? <img className="about-avatar about-avatar-photo" src={m.photo} alt={`Photo of ${m.name}`}
                      width="76" height="76" loading="lazy" style={{ border: `2px solid ${m.color}40` }} />
                  : <div className="about-avatar" style={{ background: m.color + '20', color: m.color, border: `2px solid ${m.color}30` }}>
                      {m.initials}
                    </div>}
                <div className="about-team-name">{m.name}</div>
                <div className="about-team-role">{m.role}</div>
                <p className="about-team-bio">{m.bio}</p>
                {m.linkedin && (
                  <a className="about-team-link" href={m.linkedin} target="_blank" rel="noopener noreferrer"
                    aria-label={`${m.name} on LinkedIn (opens in a new tab)`}>
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true">
                      <path d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.86 0-2.14 1.45-2.14 2.94v5.67H9.34V9h3.42v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z"/>
                    </svg>
                    LinkedIn
                  </a>
                )}
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
              ['Backend', 'Python · FastAPI'],
              ['Scan pipeline', 'Celery workers · Redis · PostgreSQL'],
              ['Code analysis', 'Python ast · tree-sitter (JavaScript / TypeScript) · data-flow tracking'],
              ['NLP', 'spaCy · Microsoft Presidio · sentence-transformers'],
              ['AI summary & chat', 'Google Gemini · OpenAI (fallback)'],
              ['Reports', 'ReportLab (PDF) · HTML · CSV'],
              ['Security', 'Encrypted GitHub tokens · personal data masked before any AI call'],
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
