import { useState, useEffect, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import './landing.css';
import DemoModal from './components/DemoModal';
import { CONTACT_EMAIL } from './legalNotice';

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
  { label: 'Finding personal data',  dur: 2200, result: '6 categories · 47 files' },
  { label: 'Parsing privacy policy', dur: 1100, result: 'Policy extracted · 9 types claimed' },
  { label: 'DPDP Act checks',        dur: 1600, result: '5 checks · 3 findings' },
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
                <span className="lp-tv-msg">S.5 Notice gap: phone number in code, not in policy</span>
              </div>
              <div className="lp-tv med">
                <span className="lp-tv-sev">HIGH</span>
                <span className="lp-tv-msg">S.8(5) Email written to application logs</span>
              </div>
              <div className="lp-tv low">
                <span className="lp-tv-sev">LOW</span>
                <span className="lp-tv-msg">Rule 3(b)(ii) Vague purpose: “improve our services”</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Extra icons ────────────────────────────────────────────────────────────
const XI = {
  Play: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8" fill="currentColor"/>
    </svg>
  ),
  Menu: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
  ),
  Close: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
  ),
  Mail: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>
    </svg>
  ),
  Pin: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s7-6.2 7-12a7 7 0 1 0-14 0c0 5.8 7 12 7 12z"/><circle cx="12" cy="10" r="2.5"/>
    </svg>
  ),
  Flow: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/>
      <path d="M6 8.5v3a4 4 0 0 0 4 4h5.5"/><path d="M8.5 6h7"/>
    </svg>
  ),
  Balance: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3v18"/><path d="M5 21h14"/><path d="M4 7h16"/>
      <path d="m4 7-3 7a4 4 0 0 0 6 0z"/><path d="m20 7-3 7a4 4 0 0 0 6 0z"/>
    </svg>
  ),
  Layers: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="m12 2 10 5-10 5L2 7z"/><path d="m2 12 10 5 10-5"/><path d="m2 17 10 5 10-5"/>
    </svg>
  ),
  Gauge: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 14l4-4"/><path d="M3.3 19a10 10 0 1 1 17.4 0"/>
    </svg>
  ),
  Lock: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>
    </svg>
  ),
  Code: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
    </svg>
  ),
};


// ── Data ───────────────────────────────────────────────────────────────────
const FEATURES = [
  { icon: <FI.Scan />,    title: 'Personal data in your code',
    desc: 'Finds ten categories — Aadhaar, PAN, phone, e-mail, name, date of birth, location, health, financial and biometric data — using identifier patterns, Presidio named-entity recognition and a Verhoeff checksum that confirms Aadhaar numbers.' },
  { icon: <XI.Flow />,    title: 'Data-flow tracing',
    desc: 'Taint analysis (Python’s ast, tree-sitter for JavaScript and TypeScript) follows personal data inside each function to log calls and to 15 third-party SDKs such as Firebase, Mixpanel, Segment, Twilio and AWS S3.' },
  { icon: <FI.Doc />,     title: 'Privacy policy parsing',
    desc: 'Three passes read your policy: which data it discloses, the purpose stated for each category (spaCy dependency parsing and MiniLM sentence embeddings) and the third parties it names.' },
  { icon: <XI.Balance />, title: 'Five DPDP Act checks',
    desc: 'Notice gaps (S. 5, 6(1)), undisclosed processors (S. 8(2)), personal data in logs (S. 8(5)), purpose linkage (S. 6(1)) and vague purposes (Rule 3(b)(ii)), each with a severity.' },
  { icon: <XI.Layers />,  title: 'Your code, kept separate',
    desc: 'Bundled libraries and generated files are scanned and labelled separately, and test, mock and example code does not raise violations unless you switch it on.' },
  { icon: <XI.Gauge />,   title: 'Built for large repositories',
    desc: 'Files are scanned in parallel chunks of up to 100, so each task’s time depends on its own files. The largest repository we tested had 1,568 source files.' },
  { icon: <FI.Sparkle />, title: 'Optional AI summary and chat',
    desc: 'With a Gemini, OpenAI or Anthropic key, an LLM writes an executive summary and answers questions about a scan. Secrets and personal values are masked first, and detection never uses an LLM.' },
  { icon: <FI.FileDown />, title: 'Reports and exports',
    desc: 'HTML and PDF reports, CSV exports of every violation and every finding, and a REST API with interactive documentation.' },
  { icon: <XI.Lock />,    title: 'Secure by design',
    desc: 'Your GitHub token is encrypted while a scan is queued and never stored, logs are redacted, and policy URLs are restricted to public addresses.' },
];

const DPDP_SECTIONS = [
  { id: 'S.5',           slug: 'section-5',   title: 'Notice Gap',              desc: 'Personal data categories found in your code that your privacy notice does not mention — the notice duty under Section 5.' },
  { id: 'S.6(1)',        slug: 'section-6-1', title: 'Purpose Limitation',      desc: 'Code modules that use a category for a purpose the policy does not state. Consent under Section 6(1) covers only the specified purpose.' },
  { id: 'S.8(2)',        slug: 'section-8-2', title: 'Processor Contracts',     desc: 'Personal data reaching third-party SDKs and APIs that the policy does not name. A processor may be engaged only under a valid contract.' },
  { id: 'S.8(5)',        slug: 'section-8-5', title: 'Security Safeguards',     desc: 'Personal data written to logs or sent to monitoring services, a common route to a breach that Section 8(5) asks you to prevent.' },
  { id: 'Rule 3(b)(ii)', slug: 'rule-3-b',    title: 'Purpose Clarity',         desc: 'Purpose statements that use only stock or generic wording, such as “to improve our services”, where Rule 3 asks for a specified purpose.' },
];

const STEPS = [
  { n: '01', title: 'Connect your repository',   desc: 'Paste a GitHub repository URL, your privacy policy link and an access token. Public and private repositories work.', icon: <FI.Connect /> },
  { n: '02', title: 'Code and policy are analysed', desc: 'Files are scanned in parallel chunks while the policy is parsed, then the two are cross-checked against the DPDP Act.', icon: <FI.Cpu /> },
  { n: '03', title: 'Review the evidence',       desc: 'Each finding names the provision, the file and line or policy clause behind it, and a suggested fix.', icon: <FI.Report /> },
];

const STATS = [
  { to: 5,    suffix: '',  decimals: 0, label: 'DPDP checks' },
  { to: 3,    suffix: '',  decimals: 0, label: 'Languages supported' },
  { to: 1568, suffix: '',  decimals: 0, label: 'Files in the largest repository tested' },
  { to: 940,  suffix: '',  decimals: 0, label: 'Human-labelled evaluation units' },
];

const DEMO = [
  { key: 'scan',     label: 'Start a scan',      img: '/demo/scan-form.webp', w: 780, h: 700, title: 'Three inputs, one click',               desc: 'Repository URL, privacy policy link and a GitHub token. The token is encrypted while the scan is queued and never written to the database.' },
  { key: 'results',  label: 'Results',           img: '/demo/results.webp',   w: 1680, h: 802,  title: 'Score, gaps and summary at a glance', desc: 'Violations by severity, undisclosed data categories and an optional AI executive summary.' },
  { key: 'evidence', label: 'Evidence',          img: '/demo/evidence.webp',  w: 1658, h: 443,  title: 'Every finding shows its evidence',     desc: 'The provision, the exact file and line, and a suggested fix — so developers can act on it directly.' },
  { key: 'findings', label: 'Findings explorer', img: '/demo/findings.webp',  w: 1600, h: 759,  title: 'Filter every finding',                 desc: 'Search and filter all personal-data findings by category, origin and whether data leaves your system.' },
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

function DpdpCard({ id, slug, title, desc, delay = 0 }) {
  const [ref, inView] = useInView();
  return (
    <div ref={ref} className={`lp-dcard${inView ? ' lp-vis' : ''}`} style={{ transitionDelay: `${delay}ms` }}>
      <Link to={`/dpdpa/${slug}`} className="lp-dcard-link">
        <div className="lp-dcard-id">{id}</div>
        <h3 className="lp-dcard-title">{title}</h3>
        <p className="lp-dcard-desc">{desc}</p>
        <span className="lp-dcard-more">Read the provision →</span>
      </Link>
    </div>
  );
}

function DemoTour() {
  const [active, setActive] = useState(0);
  const tabs = useRef([]);
  const onKey = (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const next = (active + (e.key === 'ArrowRight' ? 1 : DEMO.length - 1)) % DEMO.length;
    setActive(next);
    tabs.current[next]?.focus();
  };
  const d = DEMO[active];
  return (
    <div className="lp-demo">
      <div className="lp-demo-tabs" role="tablist" aria-label="Product tour" onKeyDown={onKey}>
        {DEMO.map((t, i) => (
          <button key={t.key} ref={el => (tabs.current[i] = el)} role="tab" id={`demo-tab-${t.key}`}
            aria-selected={i === active} aria-controls="demo-panel" tabIndex={i === active ? 0 : -1}
            className={`lp-demo-tab${i === active ? ' active' : ''}`} onClick={() => setActive(i)}>
            <span className="lp-demo-tab-n">{String(i + 1).padStart(2, '0')}</span>{t.label}
          </button>
        ))}
      </div>
      <div className="lp-demo-panel" id="demo-panel" role="tabpanel" aria-labelledby={`demo-tab-${d.key}`}>
        <div className="lp-demo-copy">
          <h3>{d.title}</h3>
          <p>{d.desc}</p>
        </div>
        <div className={`lp-browser${d.key === 'scan' ? ' lp-browser-narrow' : ''}`}>
          <div className="lp-browser-bar">
            <span className="lp-tbar-dot red" /><span className="lp-tbar-dot yellow" /><span className="lp-tbar-dot green" />
            <span className="lp-browser-url">privacypilot / {d.label.toLowerCase()}</span>
          </div>
          <img key={d.key} src={d.img} width={d.w} height={d.h} alt={`${d.label} screen of PrivacyPilot`} className="lp-browser-img" loading="lazy" />
        </div>
        <p className="lp-demo-note">Screens from real scans; repository names are blurred.</p>
      </div>
    </div>
  );
}

function ContactForm() {
  const [form, setForm] = useState({ name: '', email: '', org: '', message: '' });
  const [errors, setErrors] = useState({});
  const [sent, setSent] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const submit = (e) => {
    e.preventDefault();
    const er = {};
    if (!form.name.trim()) er.name = 'Please enter your name.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) er.email = 'Please enter a valid e-mail address.';
    if (form.message.trim().length < 10) er.message = 'Please write at least a sentence.';
    setErrors(er);
    if (Object.keys(er).length) return;
    const body = `${form.message}\n\n— ${form.name}${form.org ? `, ${form.org}` : ''} (${form.email})`;
    window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('PrivacyPilot enquiry from ' + form.name)}&body=${encodeURIComponent(body)}`;
    setSent(true);
  };
  if (sent) return (
    <div className="lp-contact-sent" role="status">
      <div className="lp-contact-sent-ico"><FI.Check /></div>
      <h3>Almost there</h3>
      <p>Your e-mail app should have opened with your message. Press send there and we will reply soon.</p>
      <button type="button" className="lp-link-btn" onClick={() => setSent(false)}>Write another message</button>
    </div>
  );
  return (
    <form className="lp-contact-form" onSubmit={submit} noValidate>
      <div className="lp-field-row">
        <label className="lp-field">
          <span>Name</span>
          <input value={form.name} onChange={set('name')} autoComplete="name" aria-invalid={!!errors.name} />
          {errors.name && <em>{errors.name}</em>}
        </label>
        <label className="lp-field">
          <span>Work e-mail</span>
          <input type="email" value={form.email} onChange={set('email')} autoComplete="email" aria-invalid={!!errors.email} />
          {errors.email && <em>{errors.email}</em>}
        </label>
      </div>
      <label className="lp-field">
        <span>Organisation <small>(optional)</small></span>
        <input value={form.org} onChange={set('org')} autoComplete="organization" />
      </label>
      <label className="lp-field">
        <span>How can we help?</span>
        <textarea rows={5} value={form.message} onChange={set('message')} aria-invalid={!!errors.message}
          placeholder="Tell us about your product, the repositories you would like to scan or the demo you want to see." />
        {errors.message && <em>{errors.message}</em>}
      </label>
      <button type="submit" className="lp-btn-primary lp-contact-submit">Send message →</button>
    </form>
  );
}

// ── Landing ────────────────────────────────────────────────────────────────
export default function Landing() {
  const [heroIn, setHeroIn]     = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [demoOpen, setDemoOpen] = useState(false);
  const openDemo = (e) => { e?.preventDefault(); e?.stopPropagation(); setMenuOpen(null); setMobileOpen(false); setDemoOpen(true); };

  useEffect(() => {
    const t = setTimeout(() => setHeroIn(true), 60);
    const onScroll = () => setScrolled(window.scrollY > 24);
    const onKey = (e) => { if (e.key === 'Escape') { setMenuOpen(null); setMobileOpen(false); } };
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('keydown', onKey);
    return () => { clearTimeout(t); window.removeEventListener('scroll', onScroll); window.removeEventListener('keydown', onKey); };
  }, []);

  useEffect(() => {
    document.body.style.overflow = mobileOpen ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [mobileOpen]);

  const closeMenu = () => { setMenuOpen(null); setMobileOpen(false); };

  return (
    <div className="lp-root" onClick={() => setMenuOpen(null)}>
      <a href="#main" className="lp-skip">Skip to content</a>

      {/* ── Navbar ── */}
      <nav className={`lp-nav${scrolled || mobileOpen ? ' lp-nav-scrolled' : ''}`} aria-label="Main">
        <div className="lp-nav-inner">
          <Link to="/" className="lp-nav-brand" onClick={closeMenu}>
            <LogoMark size={36} />
            <span className="lp-nav-name">PrivacyPilot</span>
          </Link>

          <div className="lp-nav-center">
            <a href="#features" className="lp-nav-link" onClick={closeMenu}>Features</a>
            <a href="#how" className="lp-nav-link" onClick={closeMenu}>How it works</a>
            <div className="lp-nav-dd-wrap"
              onClick={e => { e.stopPropagation(); setMenuOpen(menuOpen === 'dpdpa' ? null : 'dpdpa'); }}>
              <button className={`lp-nav-link lp-nav-dd-btn${menuOpen === 'dpdpa' ? ' active' : ''}`}
                aria-expanded={menuOpen === 'dpdpa'} aria-haspopup="true">
                DPDP Act
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
            <a href="#contact" className="lp-nav-link" onClick={closeMenu}>Contact us</a>
          </div>

          <div className="lp-nav-actions">
            <button type="button" className="lp-nav-ghost" onClick={openDemo}><XI.Play />See demo</button>
            <Link to="/app" className="lp-nav-cta" onClick={closeMenu}>Start a scan →</Link>
          </div>

          <button className="lp-nav-burger" aria-label={mobileOpen ? 'Close menu' : 'Open menu'} aria-expanded={mobileOpen}
            aria-controls="lp-mobile-menu" onClick={e => { e.stopPropagation(); setMobileOpen(!mobileOpen); }}>
            {mobileOpen ? <XI.Close /> : <XI.Menu />}
          </button>
        </div>

        <div id="lp-mobile-menu" className={`lp-mobile${mobileOpen ? ' open' : ''}`} hidden={!mobileOpen}>
          <a href="#features" onClick={closeMenu}>Features</a>
          <a href="#how" onClick={closeMenu}>How it works</a>
          <button type="button" className="lp-mobile-btn" onClick={openDemo}>See demo</button>
          <a href="#coverage" onClick={closeMenu}>DPDP Act checks</a>
          <Link to="/about" onClick={closeMenu}>About</Link>
          <a href="#contact" onClick={closeMenu}>Contact us</a>
          <Link to="/app" className="lp-nav-cta lp-mobile-cta" onClick={closeMenu}>Start a scan →</Link>
        </div>
      </nav>

      <main id="main">
      {/* ── Hero ── */}
      <section className="lp-hero">
        <div className="lp-hero-grid" aria-hidden="true" />
        <div className="lp-hero-glow" aria-hidden="true" />
        <div className="lp-hero-glow2" aria-hidden="true" />

        <div className={`lp-hero-content${heroIn ? ' lp-in' : ''}`}>
          <div className="lp-hero-left">
            <div className="lp-hero-badge">
              <span className="lp-badge-dot" />
              DPDP Act 2023 compliance checks
            </div>
            <h1 className="lp-h1">
              Privacy compliance,<br />
              <em className="lp-h1-em">checked in code.</em>
            </h1>
            <p className="lp-hero-sub">
              PrivacyPilot reads your source code and your privacy policy together and flags likely
              DPDP Act gaps, each with the file, line or policy clause behind it. Built to support
              your legal review, not to replace it.
            </p>
            <div className="lp-hero-ctas">
              <Link to="/app" className="lp-btn-primary">Scan your repository →</Link>
              <button type="button" className="lp-btn-ghost lp-btn-reset" onClick={openDemo}><XI.Play />&nbsp;See demo</button>
            </div>
            <div className="lp-hero-trust">
              <span><FI.Check />&nbsp;Python, JavaScript &amp; TypeScript</span>
              <span><FI.Check />&nbsp;Public &amp; private repos</span>
              <span><FI.Check />&nbsp;Evidence for every finding</span>
            </div>
          </div>
          <div className="lp-hero-right" aria-hidden="true">
            <ScanTerminal />
          </div>
        </div>
      </section>

      {/* ── Stats Band ── */}
      <section className="lp-stats" aria-label="PrivacyPilot in numbers">
        <div className="lp-stats-inner">
          {STATS.map((s, i) => (
            <div key={i} className="lp-stat-item">
              <div className="lp-stat-val"><Counter to={s.to} suffix={s.suffix} decimals={s.decimals} /></div>
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
            <h2 className="lp-sec-title">What PrivacyPilot checks</h2>
            <p className="lp-sec-sub">Code analysis and policy analysis run side by side, then meet in five DPDP Act checks.</p>
          </header>
          <div className="lp-fgrid">
            {FEATURES.map((f, i) => <FeatureCard key={i} {...f} delay={i * 70} />)}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section className="lp-sec lp-sec-dk" id="how">
        <div className="lp-sec-inner">
          <header className="lp-sec-head">
            <p className="lp-kicker" style={{ color: '#10b981' }}>How it works</p>
            <h2 className="lp-sec-title lp-sec-title-lt">From repository to evidence in three steps</h2>
            <p className="lp-sec-sub lp-sec-sub-lt">Connect once and rescan whenever your code or your policy changes.</p>
          </header>
          <div className="lp-steps-wrap">
            {STEPS.map((s, i) => <StepCard key={i} {...s} delay={i * 110} />)}
          </div>
        </div>
      </section>

      {/* ── Demo ── */}
      <section className="lp-sec lp-sec-lt lp-demo-sec" id="demo">
        <div className="lp-sec-inner">
          <header className="lp-sec-head">
            <p className="lp-kicker">Product tour</p>
            <h2 className="lp-sec-title">A quick tour of the product</h2>
            <p className="lp-sec-sub">The screens you will use, from starting a scan to tracing a finding back to its line of code.</p>
          </header>
          <DemoTour />
        </div>
      </section>

      {/* ── DPDP Coverage ── */}
      <section className="lp-sec lp-sec-tint" id="coverage">
        <div className="lp-sec-inner">
          <header className="lp-sec-head">
            <p className="lp-kicker">DPDP Act coverage</p>
            <h2 className="lp-sec-title">Five checks, each tied to a provision</h2>
            <p className="lp-sec-sub">Every finding is an indicator of possible non-compliance with the section named on it, for your legal reviewer to confirm.</p>
          </header>
          <div className="lp-dgrid">
            {DPDP_SECTIONS.map((s, i) => <DpdpCard key={i} {...s} delay={i * 70} />)}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="lp-cta">
        <div className="lp-cta-glow" aria-hidden="true" />
        <div className="lp-cta-inner">
          <div className="lp-cta-ico"><FI.Shield /></div>
          <p className="lp-kicker" style={{ color: '#10b981', textAlign: 'center' }}>Get started</p>
          <h2 className="lp-cta-title">Run your first scan</h2>
          <p className="lp-cta-sub">
            Paste a GitHub URL and your privacy policy link.<br />
            PrivacyPilot runs on your own infrastructure with Docker.
          </p>
          <div className="lp-cta-row">
            <Link to="/app" className="lp-btn-cta">Scan your repository →</Link>
            <a href="#contact" className="lp-btn-ghost">Talk to us</a>
          </div>
        </div>
      </section>

      {/* ── Contact ── */}
      <section className="lp-sec lp-sec-lt" id="contact">
        <div className="lp-sec-inner lp-contact">
          <div className="lp-contact-intro">
            <p className="lp-kicker">Contact us</p>
            <h2 className="lp-sec-title">Questions, a demo or a pilot?</h2>
            <p className="lp-contact-lead">Tell us what you would like to scan or see. We usually reply within two working days.</p>
            <ul className="lp-contact-list">
              {CONTACT_EMAIL && (
                <li><span className="lp-contact-ico"><XI.Mail /></span><a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a></li>
              )}
              <li><span className="lp-contact-ico"><XI.Pin /></span>MPSTME, SVKM’s NMIMS, Mumbai, India</li>
              <li><span className="lp-contact-ico"><XI.Code /></span>Capstone project, B.Tech CSE (Cybersecurity)</li>
            </ul>
          </div>
          <div className="lp-contact-card">
            <ContactForm />
          </div>
        </div>
      </section>
      </main>

      {/* ── Footer ── */}
      <footer className="lp-footer">
        <div className="lp-footer-grid">
          <div className="lp-footer-col lp-footer-about">
            <div className="lp-footer-brand">
              <LogoMark size={26} />
              <span className="lp-footer-name">PrivacyPilot</span>
            </div>
            <p>DPDP Act 2023 compliance checks for source code and privacy policies.</p>
          </div>
          <nav className="lp-footer-col" aria-label="Product">
            <h4>Product</h4>
            <a href="#features">Features</a>
            <a href="#how">How it works</a>
            <a href="#demo" onClick={openDemo}>See demo</a>
            <Link to="/app">Start a scan</Link>
          </nav>
          <nav className="lp-footer-col" aria-label="DPDP Act">
            <h4>DPDP Act</h4>
            {DPDP_SECTIONS.map(s => <Link key={s.slug} to={`/dpdpa/${s.slug}`}>{s.id} {s.title}</Link>)}
          </nav>
          <nav className="lp-footer-col" aria-label="Company">
            <h4>Project</h4>
            <Link to="/about">About</Link>
            <a href="#contact">Contact us</a>
            <Link to="/legal">Terms &amp; privacy</Link>
          </nav>
        </div>
        <div className="lp-footer-bottom">
          <p>© {new Date().getFullYear()} PrivacyPilot · MPSTME, NMIMS Mumbai</p>
          <p>Findings are indicators for legal review, not legal advice.</p>
        </div>
      </footer>

      <DemoModal open={demoOpen} onClose={() => setDemoOpen(false)} />
    </div>
  );
}
