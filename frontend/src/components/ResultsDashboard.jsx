import { useState } from 'react';
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
          <div className="v-detail-row">
            <div className="v-detail-label">Evidence</div>
            <div className="v-detail-value">{v.evidence}</div>
          </div>
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
      {/* ── Partial-coverage warning (large repos: file cap / time limit) ── */}
      {result?.warning && (
        <div className="card card-pad mb-24" role="status"
             style={{ background: '#fffbeb', border: '1px solid #f59e0b', color: '#92400e', fontSize: 13.5 }}>
          ⚠️ {result.warning}
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

      {/* ── Sample Findings table ── */}
      {findings && findings.length > 0 && (
        <div className="card mb-24">
          <div className="card-header">
            <div>
              <div className="card-header-title">PII Findings in Code</div>
              <div className="card-header-subtitle">Detected across repository files</div>
            </div>
            <span className="section-count" style={{ marginLeft: 'auto' }}>{findings.length} shown</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>PII Type</th>
                  <th>Sensitivity</th>
                  <th>File Path</th>
                  <th>Line</th>
                  <th>Detected By</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <tr key={i}>
                    <td><span className="pii-chip">{f.pii_category}</span></td>
                    <td>
                      <span style={{
                        fontSize: 12, fontWeight: 600,
                        color: f.sensitivity === 'high' ? '#ef4444' : f.sensitivity === 'medium' ? '#f97316' : '#22c55e',
                      }}>{f.sensitivity}</span>
                    </td>
                    <td className="mono" style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.file_path || '—'}
                    </td>
                    <td className="mono">{f.line_number || '—'}</td>
                    <td><span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{f.source}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* AI Chat Widget */}
      {scanId && <ChatPanel scanId={scanId} />}
    </div>
  );
}
