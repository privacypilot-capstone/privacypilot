import { useState } from 'react'

const STYLE = {
  page:  { padding: '2rem', fontFamily: 'sans-serif', maxWidth: '860px', margin: '0 auto' },
  h1:    { fontSize: '2rem', marginBottom: '0.25rem' },
  sub:   { color: '#666', marginBottom: '2rem' },
  label: { display: 'block', fontWeight: 'bold', marginBottom: '4px', marginTop: '16px' },
  input: { width: '100%', padding: '8px 12px', fontSize: '14px', borderRadius: '6px',
           border: '1px solid #ccc', boxSizing: 'border-box' },
  btn:   { marginTop: '20px', padding: '10px 28px', fontSize: '15px', background: '#1a1a2e',
           color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' },
  result:{ marginTop: '2rem', background: '#f5f5f5', borderRadius: '8px', padding: '1.5rem' },
  // Gap chip — inline pill inside a flex-wrap container
  chip:  { display: 'inline-flex', alignItems: 'center',
           background: '#fff3cd', border: '1px solid #ffc107', borderRadius: '99px',
           padding: '4px 14px', fontFamily: 'monospace', fontSize: '13px', fontWeight: '600' },
  stat:  { display: 'inline-block', background: '#1a1a2e', color: '#fff',
           borderRadius: '6px', padding: '8px 20px', margin: '4px 8px 4px 0',
           fontWeight: 'bold', fontSize: '1.1rem' },
}

// Severity → { bg, border, cardBg, label }
const SEV = {
  critical: { bg: '#dc3545', border: '#dc3545', card: '#fff5f5' },
  high:     { bg: '#fd7e14', border: '#fd7e14', card: '#fff8f0' },
  medium:   { bg: '#ffc107', border: '#ffc107', card: '#fffdf0' },
  low:      { bg: '#28a745', border: '#28a745', card: '#f0fff4' },
}

export default function App() {
  const [form,    setForm]    = useState({ github_repo_url: '', privacy_policy_url: '', github_token: '' })
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const runScan = async () => {
    setLoading(true)
    setResult(null)
    setError(null)
    try {
      const res = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Scan failed')
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // Deduplicate gap categories — backend returns a set but be defensive
  const uniqueGaps = result ? [...new Set(result.gaps_detected ?? [])] : []

  return (
    <>
      <div style={{ background: '#1a1a2e', padding: '10px 2rem', display: 'flex', gap: '20px' }}>
        <span style={{ color: '#fff', fontWeight: 'bold' }}>PrivacyPilot</span>
        <a href="/" style={{ color: '#aaa', fontSize: '14px', textDecoration: 'none' }}>New Scan</a>
        <a href="/history" style={{ color: '#aaa', fontSize: '14px', textDecoration: 'none' }}>History</a>
      </div>

      <div style={STYLE.page}>
        <h1 style={STYLE.h1}>PrivacyPilot</h1>
        <p style={STYLE.sub}>DPDP Act 2023 Compliance Scanner</p>

        <label style={STYLE.label}>GitHub Repository URL</label>
        <input style={STYLE.input} placeholder="https://github.com/owner/repo"
          value={form.github_repo_url}
          onChange={e => update('github_repo_url', e.target.value)} />

        <label style={STYLE.label}>Privacy Policy URL</label>
        <input style={STYLE.input} placeholder="https://example.com/privacy"
          value={form.privacy_policy_url}
          onChange={e => update('privacy_policy_url', e.target.value)} />

        <label style={STYLE.label}>GitHub Token</label>
        <input style={STYLE.input} type="password" placeholder="ghp_..."
          value={form.github_token}
          onChange={e => update('github_token', e.target.value)} />

        <button style={STYLE.btn} onClick={runScan} disabled={loading}>
          {loading ? 'Scanning… (this takes 2–3 min)' : 'Run Compliance Scan'}
        </button>

        {error && <p style={{ color: 'red', marginTop: '1rem' }}>{error}</p>}

        {result && (
          <div style={STYLE.result}>
            <h2 style={{ marginTop: 0 }}>Scan Results</h2>

            {/* ── Compliance score card ──────────────────────────────── */}
            {result.compliance && (
              <div style={{
                textAlign: 'center', padding: '1.5rem', background: '#fff',
                borderRadius: '10px', marginBottom: '1.2rem',
                border: '2px solid ' + result.compliance.color,
              }}>
                <div style={{ fontSize: '4rem', fontWeight: 'bold', color: result.compliance.color }}>
                  {result.compliance.score}
                  <span style={{ fontSize: '1.5rem', color: '#888' }}>/100</span>
                </div>
                <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: result.compliance.color }}>
                  {result.compliance.rating} Compliance
                </div>
                <div style={{ fontSize: '13px', color: '#666', marginTop: '6px' }}>
                  {result.compliance.critical_count ?? 0} critical ·{' '}
                  {result.compliance.high_count    ?? 0} high ·{' '}
                  {result.compliance.medium_count  ?? 0} medium severity violations
                </div>
              </div>
            )}

            {/* ── Summary stats ──────────────────────────────────────── */}
            <div style={{ marginBottom: '1rem' }}>
              <span style={STYLE.stat}>{result.code_findings_count} PII findings in code</span>
              <span style={STYLE.stat}>{result.policy_claims_count} claims in policy</span>
              <span style={{
                ...STYLE.stat,
                background: result.gaps_count > 0 ? '#dc3545' : '#28a745',
              }}>
                {uniqueGaps.length} consent gap{uniqueGaps.length !== 1 ? 's' : ''}
              </span>
            </div>

            {/* ── Consent gaps ───────────────────────────────────────── */}
            {uniqueGaps.length > 0 && (
              <div style={{
                background: '#fff', border: '1px solid #dee2e6',
                borderRadius: '8px', padding: '1rem 1.2rem', marginBottom: '1.2rem',
              }}>
                <h3 style={{ margin: '0 0 6px' }}>
                  ⚠️ Consent Gaps Detected ({uniqueGaps.length})
                </h3>
                <p style={{ color: '#666', fontSize: '13px', margin: '0 0 12px' }}>
                  These PII types are processed in the source code but are <strong>NOT</strong> disclosed in the privacy policy:
                </p>
                {/* Flex-wrap chip row — no more duplicate block divs */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {uniqueGaps.map(g => (
                    <span key={g} style={STYLE.chip}>{g}</span>
                  ))}
                </div>
              </div>
            )}

            {/* ── DPDP Violations ────────────────────────────────────── */}
            {result.violations && result.violations.length > 0 && (
              <>
                <h3 style={{ marginTop: '1rem', marginBottom: '10px' }}>
                  🚨 DPDP Act Violations ({result.violations.length})
                </h3>
                {result.violations.map((v, i) => {
                  const sev = SEV[v.severity] ?? SEV.medium
                  return (
                    <div key={i} style={{
                      border: `1px solid ${sev.border}`,
                      borderLeft: `4px solid ${sev.bg}`,
                      borderRadius: '8px', padding: '1rem', marginBottom: '10px',
                      background: sev.card,
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <strong style={{ fontSize: '14px' }}>{v.dpdp_section} — {v.section_title}</strong>
                        <span style={{
                          background: sev.bg, color: v.severity === 'medium' ? '#333' : '#fff',
                          padding: '2px 10px', borderRadius: '99px',
                          fontSize: '11px', fontWeight: 'bold', whiteSpace: 'nowrap', marginLeft: '8px',
                        }}>
                          {v.severity.toUpperCase()}
                        </span>
                      </div>
                      <p style={{ fontSize: '13px', margin: '6px 0 4px', color: '#444' }}>
                        <strong>PII Type:</strong>{' '}
                        <span style={{
                          background: '#e9ecef', borderRadius: '4px',
                          padding: '1px 8px', fontFamily: 'monospace', fontSize: '12px',
                        }}>{v.pii_category}</span>
                      </p>
                      <p style={{ fontSize: '13px', margin: '4px 0', color: '#555' }}>
                        <strong>Evidence:</strong> {v.evidence}
                      </p>
                      <p style={{ fontSize: '13px', margin: '4px 0', color: '#2d6a4f' }}>
                        <strong>Fix:</strong> {v.recommendation}
                      </p>
                    </div>
                  )
                })}
              </>
            )}

            {/* ── Sample code findings ────────────────────────────────── */}
            {result.sample_findings && result.sample_findings.length > 0 && (
              <>
                <h3 style={{ marginTop: '1.5rem', marginBottom: '8px' }}>Sample Code Findings</h3>
                {result.sample_findings.map((f, i) => (
                  <div key={i} style={{
                    background: '#e8f4fd', border: '1px solid #0d6efd',
                    borderRadius: '6px', padding: '8px 14px', marginBottom: '6px',
                  }}>
                    <span style={{
                      background: '#0d6efd', color: '#fff', borderRadius: '4px',
                      padding: '1px 8px', fontFamily: 'monospace', fontSize: '12px', marginRight: '8px',
                    }}>{f.pii_category}</span>
                    <span style={{ fontSize: '13px', color: '#333' }}>
                      {f.file_path} line {f.line_number}
                    </span>
                    <div style={{ fontSize: '12px', color: '#555', marginTop: '4px', fontFamily: 'monospace' }}>
                      {f.raw_text}
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* ── Report buttons ──────────────────────────────────────── */}
            {result.scan_id && (
              <div style={{ marginTop: '1.2rem' }}>
                <p style={{ fontSize: '12px', color: '#888', marginBottom: '10px' }}>
                  Scan #{result.scan_id} saved ✓
                </p>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button
                    onClick={() => window.open('http://localhost:8000/report/' + result.scan_id, '_blank')}
                    style={{
                      padding: '8px 20px', fontSize: '13px', borderRadius: '6px',
                      background: '#1a1a2e', color: '#fff', border: 'none', cursor: 'pointer',
                    }}
                  >View Full Report</button>
                  <button
                    onClick={() => window.open('http://localhost:8000/report/' + result.scan_id + '?format=pdf')}
                    style={{
                      padding: '8px 20px', fontSize: '13px', borderRadius: '6px',
                      background: '#dc3545', color: '#fff', border: 'none', cursor: 'pointer',
                    }}
                  >Download PDF</button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  )
}
