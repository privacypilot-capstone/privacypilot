import { useEffect, useState } from 'react';
import ScoreRing from './ScoreRing';
import ChatPanel from './ChatPanel';
import { CheckCircle, Sparkle, AlertTriangle, AlertOctagon, Search, ShieldAlert, ShieldCheck, FileText, Download } from './Icons';
import Term, { SectionTerms, CategoryTerm } from './Term';
import Markdown from './Markdown';
import '../results.css';
import { GLOSSARY, GLOSSARY_PANEL, GLOSSARY_SECTIONS } from './glossary';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

function scoreColor(score) {
  if (score >= 80) return '#22c55e';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

// Colour per backend rating band (same palette as scoreColor's bands).
function ratingColor(rating) {
  return {
    Good:     '#22c55e',
    Moderate: '#eab308',
    Poor:     '#f97316',
    Critical: '#ef4444',
  }[rating] ?? '#ef4444';
}

function scoreRating(score) {
  if (score >= 80) return 'Good';
  if (score >= 60) return 'Moderate';
  if (score >= 40) return 'Poor';
  return 'Critical Risk';
}

// Same wording as the backend's location labels (database.location_label).
function locationLabel(l) {
  if ('policy' in l) {   // a statement in the privacy policy (vague purpose)
    let p = l.policy ? `privacy policy (${l.policy})` : 'privacy policy';
    if (l.statement) p += `, statement ${l.statement}`;
    return l.text ? `${p}: "${l.text}"` : p;
  }
  let s = `${l.file || 'unknown file'} line ${l.line}`;
  if (l.sinks && l.sinks.length)     s += ` (${l.sinks.join(', ')})`;
  if (l.modules && l.modules.length) s += ` (module: ${l.modules.join(', ')})`;
  if (l.origin === 'third_party')    s += ' [third-party code]';
  if (l.origin === 'generated')      s += ' [generated code]';
  return s;
}

function ViolationCard({ v, refId }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="v-card animate-in">
      <div className="v-card-header" onClick={() => setOpen(o => !o)}>
        {refId && <span className="v-card-id" title="Violation ID: use it to refer to this violation (it is the same in the PDF and CSV reports)">{refId}</span>}
        <span className={`v-card-badge ${v.severity}`}><Term k={`sev_${v.severity}`}>{v.severity.toUpperCase()}</Term></span>
        <div className="v-card-meta">
          <div className="v-card-section"><SectionTerms value={v.dpdp_section} /> — <Term k={v.section_title}>{v.section_title}</Term></div>
          <div className="v-card-pii">
            <Term k="pii">PII</Term> Category: <span className="pii-chip"><CategoryTerm cat={v.pii_category} /></span>
          </div>
        </div>
        <svg
          className={`v-card-chevron ${open ? 'open' : ''}`}
          width="16" height="16" viewBox="0 0 24 24"
          fill="none" stroke="currentColor" strokeWidth="2.5"
        >
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </div>
      {open && (
        <div className="v-card-body animate-in">
          {v.recipient && (
            <div className="v-detail-row">
              <div className="v-detail-label"><Term k="recipient">Recipient</Term></div>
              <div className="v-detail-value mono">{v.recipient}</div>
            </div>
          )}
          <div className="v-detail-row">
            <div className="v-detail-label"><Term k="evidence">Evidence</Term></div>
            <div className="v-detail-value">{v.evidence}</div>
          </div>
          {v.locations && v.locations.length > 0 && (
            <div className="v-detail-row">
              <div className="v-detail-label"><Term k="locations">Locations</Term> ({v.locations.length})</div>
              <ol className="v-detail-value mono" style={{ margin: 0, paddingLeft: 22, fontSize: 12, wordBreak: 'break-all' }}>
                {v.locations.map((l, i) => <li key={i}>{locationLabel(l)}</li>)}
              </ol>
            </div>
          )}
          <div className="v-detail-row">
            <div className="v-detail-label"><Term k="fix">Fix</Term></div>
            <div className="v-detail-value fix" style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}><CheckCircle size={15} style={{ marginTop: 2, color: '#16a34a' }} /><span>{v.recommendation}</span></div>
          </div>
        </div>
      )}
    </div>
  );
}

// The LLM summary, with its light Markdown (bold, `code`, lists) rendered.
function AISummary({ text }) {
  if (!text) return null;

  return (
    <div className="ai-card mb-24 animate-in">
      <div className="ai-card-header">
        <div className="ai-card-icon"><Sparkle size={16} /></div>
        <div>
          <div className="ai-card-title">AI Executive Summary</div>
        </div>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: '#818cf8', fontWeight: 600 }}>
          Powered by Gemini / GPT
        </span>
      </div>
      <div className="ai-card-body">
        {/* Safe Markdown → React elements: the model can echo text from the
            scanned privacy policy, so it is never injected as HTML. */}
        <Markdown text={text} />
      </div>
    </div>
  );
}

const ORIGIN_LABEL = {
  first_party: 'Your code',
  third_party: 'Third-party',
  generated:   'Generated / built',
};
const PAGE_SIZES = [50, 200, 500];
const SENS_TEXT = {
  high: 'Highly sensitive (Aadhaar, PAN, health, financial or biometric data): serious harm if it leaks.',
  medium: 'Personal data that could cause harm if it leaks, such as contact details.',
  low: 'Personal data with lower risk if it leaks.',
};

// A collapsible list of every term, for readers who want to read them all at once.
function GlossaryPanel() {
  const [open, setOpen] = useState(false);
  return (
    <div className="card mb-24 glossary-card">
      <button type="button" className="glossary-toggle" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        <span className="glossary-q" aria-hidden="true">?</span>
        <span>
          <strong>New to these terms?</strong>
          <span className="glossary-hint">Hover over or tap any <span className="term term-demo">underlined word</span> to see what it means, or open the plain-English glossary.</span>
        </span>
        <span className="glossary-chev">{open ? 'Hide glossary' : 'Open glossary'}</span>
      </button>
      {open && (
        <div className="glossary-body animate-in">
          <dl className="glossary-list">
            {GLOSSARY_PANEL.map(k => (
              <div key={k}><dt>{GLOSSARY[k].term}</dt><dd>{GLOSSARY[k].text}</dd></div>
            ))}
          </dl>
          <div className="glossary-sub">Parts of the law the checks refer to</div>
          <dl className="glossary-list">
            {GLOSSARY_SECTIONS.map(k => (
              <div key={k}><dt>{GLOSSARY[k].term}</dt><dd>{GLOSSARY[k].text}</dd></div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

function sensitivityColor(s) {
  return s === 'high' ? '#ef4444' : s === 'medium' ? '#f97316' : '#22c55e';
}

// Every finding of the scan, read from GET /scans/{id}/findings one page at a
// time (a large repository can have tens of thousands), with server-side
// filters by category, origin, "sent to a third party" and a text search.
function AllFindings({ scanId, fallback }) {
  const [filters, setFilters] = useState({ category: '', origin: '', transmitted: false });
  const [search, setSearch]   = useState('');
  const [q, setQ]             = useState('');
  const [offset, setOffset]   = useState(0);
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0]);
  const [data, setData]       = useState(null);
  const [error, setError]     = useState(null);
  const [loading, setLoading] = useState(false);

  // Debounce the search box so typing does not send a request per key.
  useEffect(() => {
    const t = setTimeout(() => { setQ(search.trim()); setOffset(0); }, 350);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    if (!scanId) return;
    const params = new URLSearchParams({ offset: String(offset), limit: String(pageSize) });
    if (filters.category)    params.set('category', filters.category);
    if (filters.origin)      params.set('origin', filters.origin);
    if (filters.transmitted) params.set('transmitted', 'true');
    if (q)                   params.set('q', q);
    let cancelled = false;
    setLoading(true);
    fetch(`${API}/scans/${scanId}/findings?${params}`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => { if (!cancelled) { setData(d); setError(null); } })
      .catch(e => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [scanId, offset, pageSize, filters, q]);

  const update = (patch) => { setFilters(f => ({ ...f, ...patch })); setOffset(0); };

  // Older backend without the endpoint: show the sample it returned.
  const items = data?.items ?? (error ? (fallback || []) : []);
  const total = data?.total ?? items.length;
  const facets = data?.facets;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + pageSize, total);

  return (
    <div className="card mb-24">
      <div className="card-header" style={{ flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div className="card-header-title">All <Term k="pii">PII</Term> <Term k="finding">Findings</Term></div>
          <div className="card-header-subtitle">
            Every finding in the repository — your code, bundled third-party code and build output
          </div>
        </div>
        <span className="section-count" style={{ marginLeft: 'auto' }}>
          {facets ? Object.values(facets.origin).reduce((a, b) => a + b, 0) : total} total
        </span>
        {scanId && (
          <a href={`${API}/scans/${scanId}/findings.csv`} className="btn btn-secondary btn-sm"
             title="Every finding of this scan as a CSV file">
            Download all (<Term k="csv">CSV</Term>)
          </a>
        )}
      </div>

      {facets && (
        <div className="card-body" style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', paddingBottom: 0 }}>
          <div className="filter-tabs" style={{ marginLeft: 0 }}>
            {['', 'first_party', 'third_party', 'generated'].map(o => (
              (o === '' || facets.origin[o]) ? (
                <button key={o || 'all'}
                        className={`filter-tab ${filters.origin === o ? 'active' : ''}`}
                        onClick={() => update({ origin: o })}>
                  {o === '' ? 'All origins'
                    : o === 'first_party' ? `${ORIGIN_LABEL[o]} (${facets.origin[o]})`
                    : <><Term k={`origin_${o}`}>{ORIGIN_LABEL[o]}</Term> ({facets.origin[o]})</>}
                </button>
              ) : null
            ))}
          </div>
          <select value={filters.category} onChange={e => update({ category: e.target.value })}
                  aria-label="PII category" style={{ fontSize: 12.5, padding: '4px 8px' }}>
            <option value="">All categories</option>
            {Object.entries(facets.category).sort((a, b) => b[1] - a[1]).map(([c, n]) => (
              <option key={c} value={c}>{c} ({n})</option>
            ))}
          </select>
          <label style={{ fontSize: 12.5, display: 'flex', alignItems: 'center', gap: 6 }}>
            <input type="checkbox" checked={filters.transmitted}
                   onChange={e => update({ transmitted: e.target.checked })} />
            Sent to a <Term k="third_party">third party</Term> / <Term k="logs">logged</Term> ({facets.transmitted})
          </label>
          <input type="search" placeholder="Search file or code…" value={search}
                 onChange={e => setSearch(e.target.value)}
                 style={{ fontSize: 12.5, padding: '4px 8px', minWidth: 180, flex: '1 1 180px' }} />
        </div>
      )}

      {error && !data && (
        <div className="card-body" style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
          Could not load the full list ({error}); showing a sample.
        </div>
      )}

      <div style={{ overflowX: 'auto', opacity: loading ? 0.6 : 1 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th><Term k="pii">PII Type</Term></th>
              <th><Term k="sensitivity">Sensitivity</Term></th>
              <th>File Path</th>
              <th>Line</th>
              <th><Term k="origin">Origin</Term></th>
              <th><Term k="sent_to">Sent to</Term></th>
              <th><Term k="code">Code</Term></th>
              <th><Term k="detected_by">Detected By</Term></th>
            </tr>
          </thead>
          <tbody>
            {items.map(f => (
              <tr key={f.id ?? `${f.file_path}:${f.line_number}:${f.pii_category}`}>
                <td><span className="pii-chip"><CategoryTerm cat={f.pii_category} /></span></td>
                <td><span style={{ fontSize: 12, fontWeight: 600, color: sensitivityColor(f.sensitivity) }}>{f.sensitivity ? <Term text={SENS_TEXT[f.sensitivity] || GLOSSARY.sensitivity.text}>{f.sensitivity}</Term> : '—'}</span></td>
                <td className="mono" style={{ maxWidth: 260, wordBreak: 'break-all' }}>
                  {f.file_path || '—'}
                </td>
                <td className="mono">{f.line_number || '—'}</td>
                <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{f.origin && f.origin !== 'first_party' && ORIGIN_LABEL[f.origin]
                  ? <Term k={`origin_${f.origin}`}>{ORIGIN_LABEL[f.origin]}</Term>
                  : ORIGIN_LABEL.first_party}</td>
                <td className="mono" style={{ fontSize: 12 }}>{f.third_party_sdk ? <Term k="sdk">{f.third_party_sdk}</Term> : '—'}</td>
                <td className="mono"
                    style={{ maxWidth: 320, wordBreak: 'break-all', whiteSpace: 'pre-wrap', fontSize: 12 }}>
                  {f.raw_text}
                </td>
                <td><span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{GLOSSARY[`det_${f.source}`] ? <Term k={`det_${f.source}`} /> : f.source}</span></td>
              </tr>
            ))}
            {items.length === 0 && !loading && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 24 }}>No findings match these filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {data && total > PAGE_SIZES[0] && (
        <div className="card-body" style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'flex-end', fontSize: 12.5, flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            Per page
            <select value={pageSize} aria-label="Findings per page"
                    onChange={e => { setPageSize(Number(e.target.value)); setOffset(0); }}
                    style={{ fontSize: 12.5, padding: '2px 6px' }}>
              {PAGE_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <span>{from}–{to} of {total}</span>
          <button className="btn btn-secondary btn-sm" disabled={offset === 0 || loading}
                  onClick={() => setOffset(0)}>« First</button>
          <button className="btn btn-secondary btn-sm" disabled={offset === 0 || loading}
                  onClick={() => setOffset(Math.max(0, offset - pageSize))}>‹ Prev</button>
          <button className="btn btn-secondary btn-sm" disabled={to >= total || loading}
                  onClick={() => setOffset(offset + pageSize)}>Next ›</button>
          <button className="btn btn-secondary btn-sm" disabled={to >= total || loading}
                  onClick={() => setOffset(Math.floor((total - 1) / pageSize) * pageSize)}>Last »</button>
        </div>
      )}
    </div>
  );
}

export default function ResultsDashboard({ scanId, result, violations, findings, compliance, aiSummary, aiLoading, aiError }) {
  const [sevFilter, setSevFilter] = useState('all');

  // Use the backend's rating when it is present: scoring.py caps the rating
  // at "Poor" whenever a critical violation exists, which a score-only
  // threshold cannot know (1 critical → score 80 → would show "Good").
  // The score-band helpers are only a fallback for responses without it.
  const score  = compliance?.score ?? 0;
  const rating = compliance?.rating ?? scoreRating(score);
  const color  = compliance?.rating ? ratingColor(compliance.rating) : scoreColor(score);

  // Violation IDs (V-01, …) come from the server; older servers send none,
  // so number them in the order received (the server's recorded order).
  const width = Math.max(2, String(violations?.length || 0).length);
  const fallbackRef = new Map((violations || []).map((v, i) => [v, `V-${String(i + 1).padStart(width, '0')}`]));
  const refOf = (v) => v.ref || fallbackRef.get(v);

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  violations?.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

  const displayViolations = sevFilter === 'all'
    ? [...(violations || [])].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    : (violations || []).filter(v => v.severity === sevFilter);

  const gaps = result?.gaps_detected
    ?? [...new Set((findings || []).filter(f => f.is_gap).map(f => f.pii_category))];

  const reportUrl    = `${API}/report/${scanId}`;
  const reportPdfUrl = `${API}/report/${scanId}?format=pdf`;

  return (
    <div className="animate-in">
      {/* ── Coverage warning (files that could not be scanned) ── */}
      {result?.warning && (
        <div className="card card-pad mb-24" role="status"
             style={{ background: '#fffbeb', border: '1px solid #f59e0b', color: '#92400e', fontSize: 13.5 }}>
          <AlertTriangle size={15} style={{ verticalAlign: -3, marginRight: 6 }} />{result.warning}
        </div>
      )}
      {/* ── What was scanned ── */}
      {result?.coverage?.origins && Object.keys(result.coverage.origins).length > 0 && (
        <div className="card card-pad mb-24" style={{ fontSize: 13 }}>
          Scanned {result.coverage.scanned ?? '—'} of {result.coverage.total_source_files ?? '—'} <Term k="source_files">source files</Term>:{' '}
          {result.coverage.origins.first_party ?? 0} in your code,{' '}
          {result.coverage.origins.third_party ?? 0} bundled <Term k="origin_third_party">third-party</Term>,{' '}
          {result.coverage.origins.generated ?? 0} <Term k="origin_generated">generated / built</Term>.
          {result.coverage.duplicates_reused > 0 && (
            <> {result.coverage.duplicates_reused} identical bundled copies were scanned once and their results reused.</>
          )}
          {' '}Third-party and generated code counts towards third-party transmission (<Term k="Section 8(2)">Section 8</Term>) only;
          {' '}<Term k="notice_gap">notice gaps</Term> and purpose checks use your own code.
        </div>
      )}
      {/* ── How vague purposes were judged (Rule 3(b)(ii)) ── */}
      {result?.coverage?.vagueness_scope && (
        <div className="card card-pad mb-24" style={{ fontSize: 13 }} data-testid="vagueness-scope">
          <strong><Term k="vague_purpose">Vague-purpose</Term> setting:</strong>{' '}
          {result.coverage.vagueness_scope === 'notice'
            ? 'whole notice. A category is reported as vague only if no statement in the policy gives it a specific purpose.'
            : 'every statement (default). Each generic purpose statement is reported, even if another statement gives the category a specific purpose.'}
          {' '}The other setting can be chosen with PRIVACYPILOT_VAGUENESS_SCOPE (README, "Checks").
        </div>
      )}
      <GlossaryPanel />
      {/* ── Metric strip ── */}
      <div className="metrics-row mb-24">
        <div className="metric-card">
          <div className="metric-icon" style={{ background: '#f0f9ff', color: '#0ea5e9' }}><Search size={20} /></div>
          <div className="metric-label"><Term k="pii">PII</Term> <Term k="finding">Findings</Term></div>
          <div className="metric-value" style={{ color: '#0ea5e9' }}>
            {result?.findings_count ?? findings?.length ?? '—'}
          </div>
          <div className="metric-sub">in source code</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon" style={{ background: '#fef2f2', color: '#ef4444' }}><AlertOctagon size={20} /></div>
          <div className="metric-label"><Term k="violation">Violations</Term></div>
          <div className="metric-value" style={{ color: violations?.length > 0 ? '#ef4444' : '#22c55e' }}>
            {violations?.length ?? '—'}
          </div>
          <div className="metric-sub"><Term k="dpdp_act">DPDP Act</Term> breaches</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon" style={{ background: '#fffbeb', color: '#f59e0b' }}><AlertTriangle size={20} /></div>
          <div className="metric-label"><Term k="consent_gap">Consent Gaps</Term></div>
          <div className="metric-value" style={{ color: gaps?.length > 0 ? '#f59e0b' : '#22c55e' }}>
            {gaps?.length ?? '—'}
          </div>
          <div className="metric-sub">undisclosed <Term k="pii">PII</Term> types</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon" style={{ background: counts.critical > 0 ? '#fef2f2' : '#f0fdf4', color: counts.critical > 0 ? '#ef4444' : '#22c55e' }}>
            {counts.critical > 0 ? <ShieldAlert size={20} /> : <ShieldCheck size={20} />}
          </div>
          <div className="metric-label"><Term k="critical_issue">Critical Issues</Term></div>
          <div className="metric-value" style={{ color: counts.critical > 0 ? '#ef4444' : '#22c55e' }}>
            {counts.critical}
          </div>
          <div className="metric-sub">need immediate action</div>
        </div>
      </div>

      {/* ── Score + AI summary ── */}
      <div className="score-section mb-24">
        <div className="score-card">
          <div className="score-ring-wrap">
            <ScoreRing score={score} color={color} size={160} />
          </div>
          <div className="score-rating"><Term k="compliance_score">{rating} Compliance</Term></div>
          <div className="score-detail">
            <Term k="dpdp_act">DPDP Act 2023</Term> <Term k="compliance_score">compliance score</Term><br/>based on violation <Term k="severity">severity</Term>
          </div>
          <div className="score-chips">
            {counts.critical > 0 && <span className="score-chip critical">{counts.critical} <Term k="sev_critical">Critical</Term></span>}
            {counts.high     > 0 && <span className="score-chip high">{counts.high} <Term k="sev_high">High</Term></span>}
            {counts.medium   > 0 && <span className="score-chip medium">{counts.medium} <Term k="sev_medium">Medium</Term></span>}
            {counts.low      > 0 && <span className="score-chip low">{counts.low} <Term k="sev_low">Low</Term></span>}
          </div>
          {/* Report buttons */}
          <div style={{ marginTop: 20, display: 'flex', gap: 8, width: '100%' }}>
            <a href={reportUrl} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ flex: 1, justifyContent: 'center' }}>
              <FileText size={14} style={{ marginRight: 6 }} />HTML
            </a>
            <a href={reportPdfUrl} target="_blank" rel="noreferrer" className="btn btn-primary btn-sm" style={{ flex: 1, justifyContent: 'center' }}>
              <Download size={14} style={{ marginRight: 6 }} />PDF
            </a>
          </div>
        </div>

        {/* AI Summary */}
        <div>
          {aiLoading && (
            <div className="ai-card" style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '24px 20px' }}>
              <div style={{ width: 24, height: 24, border: '3px solid var(--border)', borderTopColor: 'var(--indigo-600)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', flexShrink: 0 }}/>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13.5, color: 'var(--indigo-600)' }}>Generating AI Executive Summary…</div>
                <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 4 }}>Analyzing violations and building remediation plan</div>
              </div>
            </div>
          )}
          {!aiLoading && aiSummary && <AISummary text={aiSummary} />}
          {!aiLoading && !aiSummary && (
            <div className="card card-pad" style={{ color: 'var(--text-muted)', fontSize: 13.5, textAlign: 'center', padding: 32 }}>
              <div style={{ marginBottom: 12, color: 'var(--text-muted)', display: 'flex', justifyContent: 'center' }}><Sparkle size={30} /></div>
              {aiError ? (
                <div>AI summary unavailable — {aiError}</div>
              ) : (
                <div>AI summary unavailable — set <code>GEMINI_API_KEY</code> or <code>OPENAI_API_KEY</code> in the backend</div>
              )}
            </div>
          )}

          {/* Consent Gaps */}
          {gaps && gaps.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-header">
                <div>
                  <div className="card-header-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><AlertTriangle size={16} style={{ color: '#f59e0b' }} /><Term k="consent_gap">Consent Gaps</Term></div>
                  <div className="card-header-subtitle"><Term k="pii">PII</Term> types in code not disclosed in <Term k="privacy_policy">privacy policy</Term></div>
                </div>
                <span className="section-count" style={{ marginLeft: 'auto' }}>{gaps.length}</span>
              </div>
              <div className="card-body">
                <div className="gaps-row">
                  {gaps.map(g => <span key={g} className="gap-chip"><CategoryTerm cat={g} /></span>)}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Violations list ── */}
      {violations && violations.length > 0 && (
        <div className="violations-section">
          <div className="section-header">
            <div className="section-title"><Term k="dpdp_act">DPDP</Term> <Term k="violation">Violations</Term></div>
            <span className="section-count">{violations.length}</span>
            {scanId && (
              <a href={`${API}/scans/${scanId}/violations.csv`} className="btn btn-secondary btn-sm"
                 title="Every violation with all its code locations, as a CSV file">
                Download (<Term k="csv">CSV</Term>)
              </a>
            )}
            <div className="filter-tabs">
              {['all', 'critical', 'high', 'medium', 'low'].map(f => (
                <button
                  key={f}
                  className={`filter-tab ${sevFilter === f ? 'active' : ''}`}
                  onClick={() => setSevFilter(f)}
                >
                  {f === 'all' ? 'All' : <Term k={`sev_${f}`}>{f.charAt(0).toUpperCase() + f.slice(1)}</Term>}
                  {f !== 'all' && counts[f] > 0 && ` (${counts[f]})`}
                </button>
              ))}
            </div>
          </div>
          <div className="v-list">
            {displayViolations.map((v, i) => <ViolationCard key={refOf(v) || i} v={v} refId={refOf(v)} />)}
            {displayViolations.length === 0 && (
              <div className="empty-state" style={{ padding: '32px 20px' }}>
                <div className="empty-sub">No {sevFilter} severity violations.</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Every finding (paged from the backend) ── */}
      {(scanId || (findings && findings.length > 0)) && (
        <AllFindings scanId={scanId} fallback={findings} />
      )}

      {/* AI Chat Widget */}
      {scanId && <ChatPanel scanId={scanId} />}
    </div>
  );
}
