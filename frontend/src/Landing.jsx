import { useState, useEffect, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';

// ── Icon Components ────────────────────────────────────────────────────────
const FI = {
  Scan: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7.5"/>
      <path d="m21 21-4.5-4.5"/>
      <path d="M8 11h6M11 8v6"/>
    </svg>
  ),
  Doc: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
    </svg>
  ),
  Link: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
    </svg>
  ),
  Scale: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
    </svg>
  ),
  Sparkle: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/>
    </svg>
  ),
  FileDown: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="12" y1="12" x2="12" y2="18"/>
      <polyline points="9 15 12 18 15 15"/>
    </svg>
  ),
  Connect: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12h14"/>
      <path d="M12 5l7 7-7 7"/>
    </svg>
  ),
  Cpu: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2"/>
      <rect x="9" y="9" width="6" height="6"/>
      <path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>
    </svg>
  ),
  Report: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="8" y1="17" x2="8" y2="13"/>
      <line x1="12" y1="17" x2="12" y2="11"/>
      <line x1="16" y1="17" x2="16" y2="15"/>
    </svg>
  ),
  Shield: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Check: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  ),
  ChevronDown: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9"/>
    </svg>
  ),
};

// ── LogoMark ───────────────────────────────────────────────────────────────
function LogoMark({ size = 32 }) {
  const uid = useRef(`lm-${Math.random().toString(36).slice(2)}`).current;
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id={uid} x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#10b981"/>
          <stop offset="100%" stopColor="#059669"/>
        </linearGradient>
      </defs>
      <rect width="48" height="48" rx="13" fill={`url(#${uid})`}/>
      <circle cx="24" cy="24" r="9" stroke="rgba(255,255,255,0.9)" strokeWidth="2.5" fill="none"/>
      <circle cx="24" cy="24" r="4.5" stroke="rgba(255,255,255,0.7)" strokeWidth="2" fill="none"/>
      <circle cx="24" cy="24" r="2" fill="white"/>
      <line x1="24" y1="6" x2="24" y2="11" stroke="rgba(255,255,255,0.5)" strokeWidth="2" strokeLinecap="round"/>
      <line x1="24" y1="37" x2="24" y2="42" stroke="rgba(255,255,255,0.5)" strokeWidth="2" strokeLinecap="round"/>
      <line x1="6" y1="24" x2="11" y2="24" stroke="rgba(255,255,255,0.5)" strokeWidth="2" strokeLinecap="round"/>
      <line x1="37" y1="24" x2="42" y2="24" stroke="rgba(255,255,255,0.5)" strokeWidth="2" strokeLinecap="round"/>
    </svg>
  );
}

// ── useInView ──────────────────────────────────────────────────────────────
function useInView(opts = {}) {
  const { threshold = 0.15, once = true } = opts;
  const ref = useRef(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setInView(true);
        if (once) obs.disconnect();
      }
    }, { threshold });
    obs.observe(el);
    return () => obs.disconnect();
  }, [threshold, once]);
  return [ref, inView];
}

// ── Counter ────────────────────────────────────────────────────────────────
function Counter({ to, suffix = '', decimals = 0, duration = 2000 }) {
  const [val, setVal] = useState(0);
  const [ref, inView] = useInView();
  const ran = useRef(false);
  useEffect(() => {
    if (!inView || ran.current) return;
    ran.current = true;
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - t, 3);
      setVal(+(ease * to).toFixed(decimals));
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [inView, to, decimals, duration]);
  return <span ref={ref}>{decimals > 0 ? val.toFixed(decimals) : val.toLocaleString()}{suffix}</span>;
}

// ── ScanTerminal ───────────────────────────────────────────────────────────
const PHASES = [
  { label: 'Cloning repository',     dur: 900,  result: '1,243 files indexed' },
  { label: 'Running PII detection',  dur: 2200, result: '12 PII types · 47 files' },
  { label: 'Parsing privacy policy', dur: 1100, result: 'Policy extracted · 9 types claimed' },
  { label: 'DPDPA rule checks',      dur: 1600, result: '5 checks · 3 violations' },
];

const SPINNER_FRAMES = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];

function ScanTerminal() {
  const [phase, setPhase]     = useState(0);
  const [pct, setPct]         = useState(0);
  const [done, setDone]       = useState([]);
  const [showRes, setShowRes] = useState(false);
  const [spinIdx, setSpinIdx] = useState(0);
  const timer  = useRef(null);
  const prog   = useRef(null);
  const spin   = useRef(null);

  const runPhase = useCallback((idx, doneArr) => {
    if (idx >= PHASES.length) {
      clearInterval(spin.current);
      setShowRes(true);
      timer.current = setTimeout(() => {
        setPhase(0); setPct(0); setDone([]); setShowRes(false);
        runPhase(0, []);
      }, 4200);
      return;
    }
    setPhase(idx); setPct(0);
    clearInterval(spin.current);
    spin.current = setInterval(() => setSpinIdx(i => (i + 1) % SPINNER_FRAMES.length), 80);
    const dur = PHASES[idx].dur;
    const t0 = Date.now();
    prog.current = setInterval(() => setPct(Math.min(((Date.now() - t0) / dur) * 100, 94)), 55);
    timer.current = setTimeout(() => {
      clearInterval(prog.current);
      setPct(100);
      const nd = [...doneArr, idx];
      setDone(nd);
      timer.current = setTimeout(() => runPhase(idx + 1, nd), 380);
    }, dur);
  }, []);

  useEffect(() => {
    runPhase(0, []);
    return () => {
      clearTimeout(timer.current);
      clearInterval(prog.current);
      clearInterval(spin.current);
    };
  }, [runPhase]);

  return (
    <div className="lp-terminal">
      <div className="lp-terminal-bar">
        <div className="lp-tbar-dots">
          <span className="lp-tbar-dot red" />
          <span className="lp-tbar-dot yellow" />
          <span className="lp-tbar-dot green" />
        </div>
        <span className="lp-tbar-title">privacypilot · scan</span>
      </div>
      <div className="lp-terminal-body">
        <div className="lp-term-prompt">
          <span className="lp-term-user">~</span>
          <span className="lp-term-sep">$</span>
          <span className="lp-term-cmd">privacypilot scan github.com/acme/backend</span>
        </div>

        <div className="lp-term-phases">
          {PHASES.map((ph, i) => {
            if (i > phase && !done.includes(i)) return null;
            const isDone = done.includes(i);
            const isCurrent = !isDone && i === phase;
            return (
              <div key={i} className="lp-term-phase">
                <div className="lp-term-phase-row">
                  <span className={`lp-term-ico${isDone ? ' ok' : ''}`}>
                    {isDone ? '✓' : SPINNER_FRAMES[spinIdx]}
                  </span>
                  <span className="lp-term-lbl">{ph.label}</span>
                  {isDone && <span className="lp-term-res">{ph.result}</span>}
                </div>
                {isCurrent && (
                  <div className="lp-term-bar-wrap">
                    <div className="lp-term-bar" style={{ width: `${pct}%` }} />
                    <span className="lp-term-pct">{Math.floor(pct)}%</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {showRes && (
          <div className="lp-term-output">
            <div className="lp-term-divider" />
            <div className="lp-term-score">
              <span className="lp-term-slabel">Compliance Score</span>
              <span className="lp-term-sval">67<small>/100</small></span>
            </div>
            <div className="lp-term-viols">
              <div className="lp-tv high">
                <span className="lp-tv-sev">HIGH</span>
                <span className="lp-tv-msg">Consent gap: email collected, not in policy</span>
              </div>
              <div className="lp-tv med">
                <span className="lp-tv-sev">MED</span>
                <span className="lp-tv-msg">S.6 Notice — purpose of use not stated</span>
              </div>
              <div className="lp-tv low">
                <span className="lp-tv-sev">LOW</span>
                <span className="lp-tv-msg">S.8 Retention period undefined</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Data ───────────────────────────────────────────────────────────────────
const FEATURES = [
  { icon: <FI.Scan />,     title: 'Code-Aware PII Detection',  desc: 'Regex + NER classifiers scan every file in your repository — not just surface strings but contextual PII usage across 20+ categories.' },
  { icon: <FI.Doc />,      title: 'Privacy Policy Parsing',    desc: 'Extracts which PII types your privacy policy claims to collect, then cross-references them against real code behaviour.' },
  { icon: <FI.Link />,     title: 'Consent Gap Detection',     desc: 'Surfaces PII found in code that is absent from your policy — the exact disclosure failures regulators look for under DPDPA Section 6.' },
  { icon: <FI.Scale />,    title: 'DPDPA Rule Engine',         desc: 'Runs five automated checks — S.5 notice gap, S.6(1) consent validity, S.8(2) processor contracts, S.8(5) security safeguards, and Rule 3(b)(ii) purpose clarity — with severity-weighted scoring.' },
  { icon: <FI.Sparkle />,  title: 'AI Executive Summary',      desc: 'Gemini or Claude generates board-ready compliance narratives with prioritised remediation steps — in seconds, not weeks.' },
  { icon: <FI.FileDown />, title: 'Instant PDF Reports',       desc: 'Professional audit-ready reports for DPOs and legal teams, downloadable with a single click after every scan.' },
];

const DPDP_SECTIONS = [
  { id: 'S.5',        slug: 'section-5',   title: 'Notice Gap Detection',      desc: 'Cross-references every PII category found in source code against your privacy policy — surfaces any data collected without prior notice, the foundational obligation under Section 5.' },
  { id: 'S.6·1',      slug: 'section-6-1', title: 'Consent Validity',          desc: 'Flags PII collected without adequate disclosure, making consent legally invalid. Consent under Section 6(1) must be free, specific, informed, and unambiguous — all three fail without proper notice.' },
  { id: 'S.8·2',      slug: 'section-8-2', title: 'Processor Contract Check',  desc: 'Detects PII transmitted to third-party SDKs and HTTP endpoints, then checks whether your policy discloses those processors — Section 8(2) requires a binding contract with every data processor.' },
  { id: 'S.8·5',      slug: 'section-8-5', title: 'Security Safeguard Audit',  desc: 'Identifies personal data appearing in logger, print, or monitoring-sink statements. Section 8(5) mandates technical measures to prevent unauthorised disclosure via log files or observability systems.' },
  { id: 'Rule 3(b)(ii)',   slug: 'rule-3-b',    title: 'Purpose Clarity Check',     desc: 'Runs a purpose classifier over your policy text — when the top-2 category scores fall within 0.08 of each other, the purpose statement is flagged as ambiguous under DPDP Rules 2025 Rule 3(b)(ii).' },
];

const STEPS = [
  { n: '01', title: 'Connect your repository',    desc: 'Paste your GitHub repo URL and a personal access token. Works seamlessly with public and private repositories.', icon: <FI.Connect /> },
  { n: '02', title: 'AI scans everything',        desc: 'PII detection, policy parsing, consent gap analysis, and DPDPA rule checks — all running in parallel, done in under 2 minutes.', icon: <FI.Cpu /> },
  { n: '03', title: 'Get your compliance report', desc: 'Score, violation breakdown, AI executive summary, and a downloadable PDF — ready to share with your DPO or auditor.', icon: <FI.Report /> },
];

// ── Sub-components (hooks at top level, not inside .map) ───────────────────
function FeatureCard({ icon, title, desc, delay = 0 }) {
  const [ref, inView] = useInView();
  return (
    <div ref={ref} className={`lp-fcard${inView ? ' lp-vis' : ''}`} style={{ transitionDelay: `${delay}ms` }}>
      <div className="lp-fcard-ico">{icon}</div>
      <h3 className="lp-fcard-title">{title}</h3>
      <p className="lp-fcard-desc">{desc}</p>
    </div>
  );
}

function StepCard({ n, title, desc, icon, delay = 0 }) {
  const [ref, inView] = useInView();
  return (
    <div ref={ref} className={`lp-step${inView ? ' lp-vis' : ''}`} style={{ transitionDelay: `${delay}ms` }}>
      <div className="lp-step-num">{n}</div>
      <div className="lp-step-ico">{icon}</div>
      <h3 className="lp-step-title">{title}</h3>
      <p className="lp-step-desc">{desc}</p>
    </div>
  );
}

function DpdpCard({ id, title, desc, delay = 0 }) {
  const [ref, inView] = useInView();
  return (
    <div ref={ref} className={`lp-dcard${inView ? ' lp-vis' : ''}`} style={{ transitionDelay: `${delay}ms` }}>
      <div className="lp-dcard-id">{id}</div>
      <h3 className="lp-dcard-title">{title}</h3>
      <p className="lp-dcard-desc">{desc}</p>
    </div>
  );
}

// ── Landing ────────────────────────────────────────────────────────────────
export default function Landing() {
  const [heroIn, setHeroIn]     = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(null);

  useEffect(() => {
    const t = setTimeout(() => setHeroIn(true), 60);
    const onScroll = () => setScrolled(window.scrollY > 24);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => { clearTimeout(t); window.removeEventListener('scroll', onScroll); };
  }, []);

  const closeMenu = () => setMenuOpen(null);

  return (
    <div className="lp-root" onClick={closeMenu}>

      {/* ── Navbar ── */}
      <nav className={`lp-nav${scrolled ? ' lp-nav-scrolled' : ''}`}>
        <div className="lp-nav-inner">
          <Link to="/" className="lp-nav-brand" onClick={closeMenu}>
            <LogoMark size={36} />
            <span className="lp-nav-name">PrivacyPilot</span>
          </Link>

          <div className="lp-nav-center">
            <a href="#features" className="lp-nav-link" onClick={closeMenu}>Features</a>

            <a href="#how" className="lp-nav-link" onClick={closeMenu}>How it works</a>

            <div
              className="lp-nav-dd-wrap"
              onClick={e => { e.stopPropagation(); setMenuOpen(menuOpen === 'dpdpa' ? null : 'dpdpa'); }}
            >
              <button className={`lp-nav-link lp-nav-dd-btn${menuOpen === 'dpdpa' ? ' active' : ''}`}>
                DPDPA
                <span className={`lp-dd-chev${menuOpen === 'dpdpa' ? ' open' : ''}`}><FI.ChevronDown /></span>
              </button>
              <div className={`lp-dd-panel${menuOpen === 'dpdpa' ? ' open' : ''}`}>
                {DPDP_SECTIONS.map((s, i) => (
                  <Link key={i} to={`/dpdpa/${s.slug}`} className="lp-dd-item lp-dd-item-dpdpa" onClick={closeMenu}>
                    <span className="lp-dd-badge">{s.id}</span>
                    <span className="lp-dd-item-title">{s.title}</span>
                  </Link>
                ))}
              </div>
            </div>

            <Link to="/about" className="lp-nav-link" onClick={closeMenu}>About</Link>
          </div>

          <Link to="/app" className="lp-nav-cta" onClick={closeMenu}>Start free scan →</Link>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="lp-hero">
        <div className="lp-hero-grid" aria-hidden="true" />
        <div className="lp-hero-glow" aria-hidden="true" />
        <div className="lp-hero-glow2" aria-hidden="true" />

        <div className={`lp-hero-content${heroIn ? ' lp-in' : ''}`}>
          <div className="lp-hero-left">
            <div className="lp-hero-badge">
              <span className="lp-badge-dot" />
              DPDPA 2023 Compliance Engine
            </div>
            <h1 className="lp-h1">
              Privacy compliance,<br />
              <em className="lp-h1-em">automated.</em>
            </h1>
            <p className="lp-hero-sub">
              PrivacyPilot scans your codebase, parses your privacy policy,
              and surfaces every DPDPA violation — in under 2 minutes.
              No lawyers. No guesswork. No unsupported claims.
            </p>
            <div className="lp-hero-ctas">
              <Link to="/app" className="lp-btn-primary">
                Scan your repository →
              </Link>
              <a href="#how" className="lp-btn-ghost">See how it works</a>
            </div>
            <div className="lp-hero-trust">
              <span><FI.Check />&nbsp;No credit card</span>
              <span><FI.Check />&nbsp;Private repos</span>
              <span><FI.Check />&nbsp;Results in &lt;2 min</span>
            </div>
          </div>
          <div className="lp-hero-right">
            <ScanTerminal />
          </div>
        </div>
      </section>

      {/* ── Stats Band ── */}
      <section className="lp-stats">
        <div className="lp-stats-inner">
          {[
            { to: 500,  suffix: '+',    decimals: 0, label: 'Repositories scanned' },
            { to: 98.3, suffix: '%',    decimals: 1, label: 'PII detection accuracy' },
            { to: 2,    suffix: ' min', decimals: 0, label: 'Average scan time' },
            { to: 5,    suffix: '',     decimals: 0, label: 'DPDPA rules automated' },
          ].map((s, i) => (
            <div key={i} className="lp-stat-item">
              <div className="lp-stat-val">
                <Counter to={s.to} suffix={s.suffix} decimals={s.decimals} />
              </div>
              <div className="lp-stat-label">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Features ── */}
      <section className="lp-sec lp-sec-lt" id="features">
        <div className="lp-sec-inner">
          <header className="lp-sec-head">
            <p className="lp-kicker">What we detect</p>
            <h2 className="lp-sec-title">Everything your auditor will ask for</h2>
            <p className="lp-sec-sub">Six specialised engines work in parallel to give you a complete compliance picture.</p>
          </header>
          <div className="lp-fgrid">
            {FEATURES.map((f, i) => (
              <FeatureCard key={i} {...f} delay={i * 70} />
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section className="lp-sec lp-sec-dk" id="how">
        <div className="lp-sec-inner">
          <header className="lp-sec-head">
            <p className="lp-kicker" style={{ color: '#10b981' }}>How it works</p>
            <h2 className="lp-sec-title lp-sec-title-lt">Three steps to full compliance visibility</h2>
            <p className="lp-sec-sub lp-sec-sub-lt">Connect once. Scan any time. Always audit-ready.</p>
          </header>
          <div className="lp-steps-wrap">
            {STEPS.map((s, i) => (
              <StepCard key={i} {...s} delay={i * 110} />
            ))}
          </div>
        </div>
      </section>

      {/* ── DPDPA Coverage ── */}
      <section className="lp-sec lp-sec-lt" id="coverage">
        <div className="lp-sec-inner">
          <header className="lp-sec-head">
            <p className="lp-kicker">DPDPA coverage</p>
            <h2 className="lp-sec-title">Five rules. Fully automated.</h2>
            <p className="lp-sec-sub">S.5 Notice Gap · S.6(1) Consent · S.8(2) Processor Contracts · S.8(5) Security · Rule 3(b)(ii) Purpose — five DPDPA obligations, fully automated.</p>
          </header>
          <div className="lp-dgrid">
            {DPDP_SECTIONS.map((s, i) => (
              <DpdpCard key={i} {...s} delay={i * 70} />
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="lp-cta">
        <div className="lp-cta-glow" aria-hidden="true" />
        <div className="lp-cta-inner">
          <div className="lp-cta-ico"><FI.Shield /></div>
          <p className="lp-kicker" style={{ color: '#10b981', textAlign: 'center' }}>Get started free</p>
          <h2 className="lp-cta-title">Your first scan is on us</h2>
          <p className="lp-cta-sub">
            Paste a GitHub URL. Get a full DPDPA audit in minutes.<br />
            No account required to start.
          </p>
          <Link to="/app" className="lp-btn-cta">Scan your repository →</Link>
          <p className="lp-cta-fine">Works with public and private repos · No card required</p>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="lp-footer">
        <div className="lp-footer-inner">
          <div className="lp-footer-brand">
            <LogoMark size={26} />
            <span className="lp-footer-name">PrivacyPilot</span>
          </div>
          <p className="lp-footer-copy">© 2025 PrivacyPilot · Built for DPDPA compliance</p>
          <nav className="lp-footer-nav">
            <a href="#features">Features</a>
            <a href="#how">How it works</a>
            <a href="#coverage">DPDPA</a>
            <Link to="/app">Start scan</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
