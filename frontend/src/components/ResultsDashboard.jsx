import { useEffect, useState } from 'react';
import ScoreRing from './ScoreRing';
import ChatPanel from './ChatPanel';

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
  let s = `${l.file || 'unknown file'} line ${l.line}`;
  if (l.sinks && l.sinks.length)     s += ` (${l.sinks.join(', ')})`;
  if (l.modules && l.modules.length) s += ` (module: ${l.modules.join(', ')})`;
  if (l.origin === 'third_party')    s += ' [third-party code]';
  if (l.origin === 'generated')      s += ' [generated code]';
  return s;
}

function ViolationCard({ v }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="v-card animate-in">
      <div className="v-card-header" onClick={() => setOpen(o => !o)}>
        <span className={`v-card-badge ${v.severity}`}>{v.severity.toUpperCase()}</span>
        <div className="v-card-meta">
          <div className="v-card-section">{v.dpdp_section} — {v.section_title}</div>
          <div className="v-card-pii">
            PII Category: <span className="pii-chip">{v.pii_category}</span>
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
              <div className="v-detail-label">Recipient</div>
              <div className="v-detail-value mono">{v.recipient}</div>
            </div>
          )}
          <div className="v-detail-row">
            <div className="v-detail-label">Evidence</div>
            <div className="v-detail-value">{v.evidence}</div>
          </div>
          {v.locations && v.locations.length > 0 && (
            <div className="v-detail-row">
              <div className="v-detail-label">Code locations ({v.locations.length})</div>
              <ol className="v-detail-value mono" style={{ margin: 0, paddingLeft: 22, fontSize: 12, wordBreak: 'break-all' }}>
                {v.locations.map((l, i) => <li key={i}>{locationLabel(l)}</li>)}
              </ol>
            </div>
          )}
          <div className="v-detail-row">
            <div className="v-detail-label">Fix</div>
            <div className="v-detail-value fix">✅ {v.recommendation}</div>
          </div>
        </div>
      )}
    </div>
  );
}

// Render **bold** spans as <strong> with React elements, never as raw HTML:
// the LLM output can echo text from the scanned privacy policy, so it is
// untrusted (it was previously injected with dangerouslySetInnerHTML).
function renderBold(paragraph) {
  return paragraph.split(/\*\*(.+?)\*\*/g).map((part, i) =>
    i % 2 === 1 ? <strong key={i}>{part}</strong> : part
  );
}

// Format raw markdown from LLM into readable paragraphs
function AISummary({ text }) {
  if (!text) return null;
  const clean = text
    .replace(/#{1,3} /g, '')
    .split(/\n\n+/)
    .filter(p => p.trim());

  return (
    <div className="ai-card mb-24 animate-in">
      <div className="ai-card-header">
        <div className="ai-card-icon">✦</div>
        <div>
          <div className="ai-card-title">AI Executive Summary</div>
        </div>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: '#818cf8', fontWeight: 600 }}>
          Powered by Gemini / GPT
        </span>
      </div>
      <div className="ai-card-body">
        {clean.map((p, i) => (
          <p key={i}>{renderBold(p)}</p>
        ))}
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
          <div className="card-header-title">All PII Findings</div>
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
            Download all (CSV)
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
                  {o === '' ? 'All origins' : `${ORIGIN_LABEL[o]} (${facets.origin[o]})`}
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
            Sent to a third party / logged ({facets.transmitted})
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
              <th>PII Type</th>
              <th>Sensitivity</th>
              <th>File Path</th>
              <th>Line</th>
              <th>Origin</th>
              <th>Sent to</th>
              <th>Code</th>
              <th>Detected By</th>
            </tr>
          </thead>
          <tbody>
            {items.map(f => (
              <tr key={f.id ?? `${f.file_path}:${f.line_number}:${f.pii_category}`}>
                <td><span className="pii-chip">{f.pii_category}</span></td>
                <td><span style={{ fontSize: 12, fontWeight: 600, color: sensitivityColor(f.sensitivity) }}>{f.sensitivity || '—'}</span></td>
                <td className="mono" style={{ maxWidth: 260, wordBreak: 'break-all' }}>
                  {f.file_path || '—'}
                </td>
                <td className="mono">{f.line_number || '—'}</td>
                <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{ORIGIN_LABEL[f.origin] || ORIGIN_LABEL.first_party}</td>
                <td className="mono" style={{ fontSize: 12 }}>{f.third_party_sdk || '—'}</td>
                <td className="mono"
                    style={{ maxWidth: 320, wordBreak: 'break-all', whiteSpace: 'pre-wrap', fontSize: 12 }}>
                  {f.raw_text}
                </td>
                <td><span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{f.source}</span></td>
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
          ⚠️ {result.warning}
        </div>
      )}
      {/* ── What was scanned ── */}
      {result?.coverage?.origins && Object.keys(result.coverage.origins).length > 0 && (
        <div className="card card-pad mb-24" style={{ fontSize: 13 }}>
          Scanned {result.coverage.scanned ?? '—'} of {result.coverage.total_source_files ?? '—'} source files:{' '}
          {result.coverage.origins.first_party ?? 0} in your code,{' '}
          {result.coverage.origins.third_party ?? 0} bundled third-party,{' '}
          {result.coverage.origins.generated ?? 0} generated / built.
          {result.coverage.duplicates_reused > 0 && (
            <> {result.coverage.duplicates_reused} identical bundled copies were scanned once and their results reused.</>
          )}
          {' '}Third-party and generated code counts towards third-party transmission (Section 8) only;
          notice gaps and purpose checks use your own code.
        </div>
      )}
      {/* ── Metric strip ── */}
      <div className="metrics-row mb-24">
        <div className="metric-card">
          <div className="metric-icon" style={{ background: '#f0f9ff', fontSize: 20 }}>🔍</div>
          <div className="metric-label">PII Findings</div>
          <div className="metric-value" style={{ color: '#0ea5e9' }}>
            {result?.findings_count ?? findings?.length ?? '—'}
          </div>
          <div className="metric-sub">in source code</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon" style={{ background: '#fef2f2', fontSize: 20 }}>🚨</div>
          <div className="metric-label">Violations</div>
          <div className="metric-value" style={{ color: violations?.length > 0 ? '#ef4444' : '#22c55e' }}>
            {violations?.length ?? '—'}
          </div>
          <div className="metric-sub">DPDP act breaches</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon" style={{ background: '#fffbeb', fontSize: 20 }}>⚠️</div>
          <div className="metric-label">Consent Gaps</div>
          <div className="metric-value" style={{ color: gaps?.length > 0 ? '#f59e0b' : '#22c55e' }}>
            {gaps?.length ?? '—'}
          </div>
          <div className="metric-sub">undisclosed PII types</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon" style={{ background: counts.critical > 0 ? '#fef2f2' : '#f0fdf4', fontSize: 20 }}>
            {counts.critical > 0 ? '🔴' : '🟢'}
          </div>
          <div className="metric-label">Critical Issues</div>
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
          <div className="score-rating">{rating} Compliance</div>
          <div className="score-detail">
            DPDP Act 2023 compliance score<br/>based on violation severity
          </div>
          <div className="score-chips">
            {counts.critical > 0 && <span className="score-chip critical">{counts.critical} Critical</span>}
            {counts.high     > 0 && <span className="score-chip high">{counts.high} High</span>}
            {counts.medium   > 0 && <span className="score-chip medium">{counts.medium} Medium</span>}
            {counts.low      > 0 && <span className="score-chip low">{counts.low} Low</span>}
          </div>
          {/* Report buttons */}
          <div style={{ marginTop: 20, display: 'flex', gap: 8, width: '100%' }}>
            <a href={reportUrl} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ flex: 1, justifyContent: 'center' }}>
              📄 HTML
            </a>
            <a href={reportPdfUrl} target="_blank" rel="noreferrer" className="btn btn-primary btn-sm" style={{ flex: 1, justifyContent: 'center' }}>
              ⬇ PDF
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
              <div style={{ fontSize: 32, marginBottom: 12 }}>🤖</div>
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
                  <div className="card-header-title">⚠️ Consent Gaps</div>
                  <div className="card-header-subtitle">PII types in code not disclosed in privacy policy</div>
                </div>
                <span className="section-count" style={{ marginLeft: 'auto' }}>{gaps.length}</span>
              </div>
              <div className="card-body">
                <div className="gaps-row">
                  {gaps.map(g => <span key={g} className="gap-chip">{g}</span>)}
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
            <div className="section-title">DPDP Violations</div>
            <span className="section-count">{violations.length}</span>
            {scanId && (
              <a href={`${API}/scans/${scanId}/violations.csv`} className="btn btn-secondary btn-sm"
                 title="Every violation with all its code locations, as a CSV file">
                Download (CSV)
              </a>
            )}
            <div className="filter-tabs">
              {['all', 'critical', 'high', 'medium', 'low'].map(f => (
                <button
                  key={f}
                  className={`filter-tab ${sevFilter === f ? 'active' : ''}`}
                  onClick={() => setSevFilter(f)}
                >
                  {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
                  {f !== 'all' && counts[f] > 0 && ` (${counts[f]})`}
                </button>
              ))}
            </div>
          </div>
          <div className="v-list">
            {displayViolations.map((v, i) => <ViolationCard key={i} v={v} />)}
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
