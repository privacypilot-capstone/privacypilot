import { useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from './Layout';
import ResultsDashboard from './components/ResultsDashboard';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const SCAN_STEPS = [
  { label: 'Downloading repository',    sub: 'Fetching the whole repository as one archive' },
  { label: 'Scanning for PII',          sub: 'Running regex + NER classifiers' },
  { label: 'Parsing privacy policy',    sub: 'Extracting PII disclosures' },
  { label: 'Detecting consent gaps',    sub: 'Comparing code vs. policy claims' },
  { label: 'Running DPDP rule engine',  sub: 'Checking 4 DPDP Act provisions + Rule 3(b)(ii)' },
  { label: 'Computing compliance score',sub: 'Calculating risk-weighted score' },
];

const LogoMark = () => (
  <svg width="30" height="34" viewBox="0 0 64 72" fill="none">
    <path d="M32 3 L60 14 V38 C60 55 48 67 32 72 C16 67 4 55 4 38 V14 Z"
      fill="rgba(16,185,129,0.12)" stroke="#10b981" strokeWidth="1.5"/>
    <rect x="31" y="30" width="2" height="22" fill="#10b981"/>
    <rect x="23" y="52" width="18" height="2.5" rx="1.2" fill="#10b981"/>
    <rect x="14" y="22" width="36" height="2" rx="1" fill="#10b981"/>
    <circle cx="32" cy="21" r="2.5" fill="#10b981"/>
    <rect x="14.5" y="24" width="1.5" height="9" fill="#10b981"/>
    <rect x="48" y="24" width="1.5" height="9" fill="#10b981"/>
  </svg>
);

const GithubIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.387-1.333-1.756-1.333-1.756-1.09-.745.083-.73.083-.73 1.205.085 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.418-1.305.762-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23a11.5 11.5 0 0 1 3-.405c1.02.005 2.045.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12"/>
  </svg>
);

const PolicyIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="9" y1="13" x2="15" y2="13"/>
    <line x1="9" y1="17" x2="12" y2="17"/>
  </svg>
);

const LockIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
);

const SearchIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
);

const AlertIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);

export default function App() {
  const [repo,      setRepo]   = useState('');
  const [policy,   setPolicy] = useState('');
  const [token,    setToken]  = useState('');
  const [loading,  setLoad]   = useState(false);
  const [live,     setLive]   = useState(null);   // server progress: {phase, files_done, files_total, percent}
  const [result,   setResult] = useState(null);
  const [error,    setError]  = useState('');
  const [aiSummary, setAiSummary] = useState(null);
  const [aiLoading, setAiLoad]    = useState(false);
  const [aiError,   setAiError]   = useState('');
  // Which step is active comes from the scan's real phase on the server
  // (not a timer): downloading → scanning (with file counts) → finalizing.
  const phase   = live?.phase || 'queued';
  const stepIdx = phase === 'finalizing' ? 4
                : phase === 'scanning'   ? 1
                : 0;

  const fetchAI = async (scanId) => {
    setAiLoad(true);
    setAiError('');
    try {
      const r = await fetch(`${API}/scans/${scanId}/summary`);
      if (r.ok) {
        const d = await r.json();
        setAiSummary(d.summary);
      } else {
        const d = await r.json().catch(() => ({}));
        setAiError(d.detail || `AI summary failed (HTTP ${r.status})`);
      }
    } catch (e) {
      setAiError(`Could not reach the AI summary service: ${e.message}`);
    }
    setAiLoad(false);
  };

  const startScan = async () => {
    setError('');
    setResult(null);
    setAiSummary(null);
    setAiError('');
    setLive(null);
    setLoad(true);
    try {
      // ── Step 1: Enqueue the scan (returns immediately with scan_id) ──
      const r = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          github_repo_url:    repo.trim(),
          privacy_policy_url: policy.trim(),
          github_token:       token.trim(),
        }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        throw new Error(d.detail || `Server error ${r.status}`);
      }
      const { scan_id } = await r.json();

      // ── Step 2: Poll until complete or failed ──
      // No fixed time limit: a large repository simply takes longer. The
      // server marks a scan failed only when it stops making progress, so
      // polling ends either way.
      const POLL_INTERVAL = 4000;   // ms between polls
      for (;;) {
        await new Promise(res => setTimeout(res, POLL_INTERVAL));
        const sr = await fetch(`${API}/scans/${scan_id}/status`);
        if (!sr.ok) throw new Error(`Status check failed: ${sr.status}`);
        const sd = await sr.json();
        setLive(sd.progress || null);
        if (sd.status === 'complete') break;
        if (sd.status === 'failed')   throw new Error(sd.error_message || 'The scan worker encountered an error. Check backend logs.');
      }

      // ── Step 3: Fetch full result ──
      const rr = await fetch(`${API}/scans/${scan_id}/result`);
      if (!rr.ok) {
        const d = await rr.json().catch(() => ({}));
        throw new Error(d.detail || `Could not fetch results: ${rr.status}`);
      }
      const data = await rr.json();
      setResult(data);
      fetchAI(scan_id);
    } catch (e) {
      setError(e.message || 'Scan failed. Check backend logs.');
    } finally {
      setLoad(false);
    }
  };

  const canScan  = repo.trim() && policy.trim() && token.trim() && !loading;
  const progress = phase === 'finalizing' ? 95
                 : phase === 'scanning'   ? 10 + 0.8 * (live?.percent ?? 0)
                 : 5;
  const stepSub  = phase === 'scanning' && live?.files_total != null
                 ? `${live.files_done.toLocaleString()} of ${live.files_total.toLocaleString()} source files scanned`
                 : phase.startsWith('waiting')
                 ? 'Waiting for the GitHub API rate limit to reset'
                 : SCAN_STEPS[stepIdx].sub;

  /* ─── Results view (keeps sidebar Layout) ─────────────────── */
  if (result && !loading) {
    return (
      <Layout>
        <div className="topbar">
          <div className="topbar-breadcrumb"><span>Scan Results</span></div>
          <div className="topbar-right">
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => { setResult(null); setAiSummary(null); setAiError(''); setError(''); }}
            >
              ← New Scan
            </button>
          </div>
        </div>
        <div className="page-content">
          <ResultsDashboard
            scanId={result.scan_id}
            result={result}
            violations={result.violations}
            findings={result.sample_findings}
            compliance={result.compliance}
            aiSummary={aiSummary}
            aiLoading={aiLoading}
            aiError={aiError}
          />
        </div>
      </Layout>
    );
  }

  /* ─── Standalone full-page scan / loading ─────────────────── */
  return (
    <div className="sa-page">
      {/* Background layers */}
      <div className="sa-bg-grid" />
      <div className="sa-bg-glow-top" />
      <div className="sa-bg-glow-bottom" />

      {/* Navbar */}
      <nav className="sa-nav">
        <Link to="/" className="sa-nav-logo">
          <LogoMark />
          <span className="sa-nav-name">PrivacyPilot</span>
        </Link>
        <Link to="/" className="sa-nav-back">← Back to home</Link>
      </nav>

      {/* Content */}
      <main className="sa-main">

        {loading ? (
          /* ── Loading state ─────────────── */
          <div className="sa-loading">
            <div className="sa-orb">
              <div className="sa-ring sa-ring-1" />
              <div className="sa-ring sa-ring-2" />
              <div className="sa-ring-icon"><SearchIcon /></div>
            </div>

            <div className="sa-loading-step-label">{SCAN_STEPS[stepIdx].label}</div>
            <div className="sa-loading-step-sub">{stepSub}</div>

            <div className="sa-prog-track">
              <div className="sa-prog-bar" style={{ width: `${progress}%` }}>
                <span className="sa-prog-dot" />
              </div>
            </div>

            <div className="sa-steps-list">
              {SCAN_STEPS.map((s, i) => (
                <div
                  key={i}
                  className={`sa-step-row${i === stepIdx ? ' sa-step-active' : i < stepIdx ? ' sa-step-done' : ''}`}
                >
                  <div className="sa-step-indicator">
                    {i < stepIdx
                      ? <span className="sa-step-check">✓</span>
                      : i === stepIdx
                        ? <span className="sa-step-spin" />
                        : null}
                  </div>
                  <span className="sa-step-text">{s.label}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* ── Scan form ─────────────────── */
          <div className="sa-wrap">
            {/* Hero */}
            <header className="sa-hero">
              <div className="sa-hero-pill">
                <span className="sa-hero-dot" />
                DPDP Act 2023 · India
              </div>
              <h1 className="sa-hero-h1">
                Scan your app.<br />
                <em className="sa-hero-em">Know your risk.</em>
              </h1>
              <p className="sa-hero-p">
                Drop in a GitHub repo and a privacy policy URL — get a full compliance
                report in under 60 seconds.
              </p>
            </header>

            {/* Form card */}
            <div className="sa-card">
              {error && (
                <div className="sa-err-banner">
                  <AlertIcon />
                  <span>{error}</span>
                  <button className="sa-err-x" onClick={() => setError('')}>×</button>
                </div>
              )}

              <div className="sa-field">
                <label className="sa-label">GitHub Repository URL</label>
                <div className="sa-input-row">
                  <span className="sa-icon"><GithubIcon /></span>
                  <input
                    type="url"
                    className="sa-input"
                    placeholder="https://github.com/org/repo"
                    value={repo}
                    onChange={e => setRepo(e.target.value)}
                  />
                </div>
                <span className="sa-hint">Public or private — token grants access</span>
              </div>

              <div className="sa-field">
                <label className="sa-label">Privacy Policy URL</label>
                <div className="sa-input-row">
                  <span className="sa-icon"><PolicyIcon /></span>
                  <input
                    type="url"
                    className="sa-input"
                    placeholder="https://yourapp.com/privacy"
                    value={policy}
                    onChange={e => setPolicy(e.target.value)}
                  />
                </div>
                <span className="sa-hint">Must be publicly accessible</span>
              </div>

              <div className="sa-field">
                <label className="sa-label">
                  GitHub Personal Access Token
                  <span className="sa-label-tag">🔒 never stored</span>
                </label>
                <div className="sa-input-row">
                  <span className="sa-icon"><LockIcon /></span>
                  <input
                    type="password"
                    className="sa-input"
                    placeholder="ghp_••••••••••••••••••••••"
                    value={token}
                    onChange={e => setToken(e.target.value)}
                  />
                </div>
                <span className="sa-hint">Used only for GitHub API — never stored or logged</span>
              </div>

              <button
                className={`sa-submit${canScan ? '' : ' sa-submit-off'}`}
                onClick={startScan}
                disabled={!canScan}
              >
                <SearchIcon />
                Start DPDP Scan
              </button>
            </div>

            {/* Feature chips */}
            <div className="sa-chips">
              {['PII Detection','Consent Gaps','SDK Checks','AI Summary','PDF Report','Compliance Chat'].map(c => (
                <span key={c} className="sa-chip">{c}</span>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
