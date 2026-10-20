/**
 * ScanResults — shared results view used by both App.jsx (fresh scan)
 * and ScanDetail.jsx (historical scan loaded from API).
 *
 * Props:
 *   result      – the /scan POST response  (fresh scan)   OR
 *   violations  – array from /scans/{id}/violations       (history view)
 *   scanMeta    – { id, repo_url, findings_count, gaps_count, violations_count, compliance }
 *   aiSummary   – string | null
 *   summaryLoading – bool
 */

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const SEV_COLOR = {
  critical: '#dc3545',
  high:     '#fd7e14',
  medium:   '#ffc107',
  low:      '#16a34a',
}

export default function ScanResults({ result, violations, scanMeta, aiSummary, summaryLoading }) {
  // Normalise: result (fresh) vs scanMeta + violations (history)
  const compliance  = result?.compliance  ?? scanMeta?.compliance  ?? null
  const scanId      = result?.scan_id     ?? scanMeta?.id          ?? null
  const viols       = result?.violations  ?? violations             ?? []
  const sampleFinds = result?.sample_findings ?? []
  const uniqueGaps  = [...new Set(result?.gaps_detected ?? [])]
  const gapCount    = result?.gaps_count  ?? scanMeta?.gaps_count  ?? uniqueGaps.length
  const findCount   = result?.code_findings_count ?? scanMeta?.findings_count ?? 0
  const violCount   = result?.violations_count    ?? scanMeta?.violations_count ?? viols.length

  return (
    <div style={{ marginTop: '1.5rem' }}>

      {/* ── Compliance score ─────────────────────────────── */}
      {compliance && (
        <div
          className="score-box"
          style={{ borderColor: compliance.color, color: compliance.color }}
        >
          <div className="score-num" style={{ color: compliance.color }}>
            {compliance.score}
            <span className="score-denom">/100</span>
          </div>
          <div className="score-label">{compliance.rating} Compliance</div>
          <div className="score-sub">
            {compliance.critical_count ?? 0} critical ·{' '}
            {compliance.high_count     ?? 0} high ·{' '}
            {compliance.medium_count   ?? 0} medium severity violations
          </div>
        </div>
      )}

      {/* ── AI Executive Summary ─────────────────────────── */}
      {(summaryLoading || aiSummary) && (
        <div className="ai-panel" style={{ marginBottom: '1.25rem' }}>
          <div className="ai-header">
            <span style={{ fontSize: '18px' }}>🤖</span>
            <span className="ai-header-title">AI Compliance Summary</span>
            <span className="ai-badge">Powered by Gemini</span>
          </div>
          <div className="ai-body">
            {summaryLoading
              ? <span style={{ color: '#64748b' }}>⏳ Generating executive summary…</span>
              : aiSummary}
          </div>
        </div>
      )}

      {/* ── Stats row ────────────────────────────────────── */}
      <div className="stat-row">
        <span className="stat-pill">📄 {findCount} PII findings</span>
        <span className="stat-pill" style={{ background: gapCount > 0 ? '#dc3545' : '#16a34a' }}>
          ⚠️ {gapCount} consent gap{gapCount !== 1 ? 's' : ''}
        </span>
        <span className="stat-pill" style={{ background: violCount > 0 ? '#7c3aed' : '#16a34a' }}>
          🚨 {violCount} violation{violCount !== 1 ? 's' : ''}
        </span>
      </div>

      {/* ── Consent gaps ─────────────────────────────────── */}
      {uniqueGaps.length > 0 && (
        <>
          <div className="section-title">⚠️ Consent Gaps Detected ({uniqueGaps.length})</div>
          <p style={{ fontSize: '13px', color: '#475569', marginBottom: '8px' }}>
            These PII types are in the source code but <strong>NOT</strong> disclosed in the privacy policy:
          </p>
          <div className="gap-wrap">
            {uniqueGaps.map(g => <span key={g} className="gap-chip">{g}</span>)}
          </div>
        </>
      )}

      {/* ── DPDP violations ──────────────────────────────── */}
      {viols.length > 0 && (
        <>
          <div className="section-title">🚨 DPDP Act Violations ({viols.length})</div>
          {viols.map((v, i) => {
            const color = SEV_COLOR[v.severity] ?? '#64748b'
            const textColor = v.severity === 'medium' ? '#92400e' : '#fff'
            return (
              <div key={i} className="v-card" style={{ borderLeftColor: color }}>
                <div className="v-header">
                  <span className="v-title">{v.dpdp_section} — {v.section_title}</span>
                  <span className="v-badge" style={{ background: color, color: textColor }}>
                    {v.severity.toUpperCase()}
                  </span>
                </div>
                <div className="v-body">
                  <p><strong>PII Type:</strong> <span className="v-pii">{v.pii_category}</span></p>
                  <p><strong>Evidence:</strong> {v.evidence}</p>
                  <p className="v-fix"><strong>Fix:</strong> {v.recommendation}</p>
                </div>
              </div>
            )
          })}
        </>
      )}

      {/* ── Sample findings ───────────────────────────────── */}
      {sampleFinds.length > 0 && (
        <>
          <div className="section-title">Sample Code Findings</div>
          {sampleFinds.map((f, i) => (
            <div key={i} className="finding-row">
              <span className="finding-tag">{f.pii_category}</span>
              <span className="finding-path">{f.file_path} line {f.line_number}</span>
              <div className="finding-code">{f.raw_text}</div>
            </div>
          ))}
        </>
      )}

      {/* ── Report buttons ────────────────────────────────── */}
      {scanId && (
        <div className="report-row">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => window.open(`${API}/report/${scanId}`, '_blank')}
          >
            📄 View HTML Report
          </button>
          <button
            className="btn btn-danger btn-sm"
            onClick={() => window.open(`${API}/report/${scanId}?format=pdf`, '_blank')}
          >
            ⬇️ Download PDF
          </button>
          <span className="scan-meta">Scan #{scanId} saved ✓</span>
        </div>
      )}
    </div>
  )
}
