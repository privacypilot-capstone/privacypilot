import { useState } from 'react'

const STYLE = {
  page:    { padding: '2rem', fontFamily: 'sans-serif', maxWidth: '800px', margin: '0 auto' },
  h1:      { fontSize: '2rem', marginBottom: '0.25rem' },
  sub:     { color: '#666', marginBottom: '2rem' },
  label:   { display: 'block', fontWeight: 'bold', marginBottom: '4px', marginTop: '16px' },
  input:   { width: '100%', padding: '8px 12px', fontSize: '14px', borderRadius: '6px',
              border: '1px solid #ccc', boxSizing: 'border-box' },
  btn:     { marginTop: '20px', padding: '10px 28px', fontSize: '15px', background: '#1a1a2e',
              color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' },
  result:  { marginTop: '2rem', background: '#f5f5f5', borderRadius: '8px', padding: '1.5rem' },
  gap:     { background: '#fff3cd', border: '1px solid #ffc107', borderRadius: '6px',
              padding: '8px 14px', marginBottom: '8px', fontFamily: 'monospace' },
  stat:    { display: 'inline-block', background: '#1a1a2e', color: '#fff',
              borderRadius: '6px', padding: '8px 20px', margin: '4px 8px 4px 0',
              fontWeight: 'bold', fontSize: '1.1rem' },
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

  return (
    <div style={STYLE.page}>
      <h1 style={STYLE.h1}>PrivacyPilot</h1>
      <p style={STYLE.sub}>DPDP Act Compliance Scanner</p>

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
        {loading ? 'Scanning... (this takes 2–3 min)' : 'Run Compliance Scan'}
      </button>

      {error && <p style={{ color: 'red', marginTop: '1rem' }}>{error}</p>}

      {result && (
        <div style={STYLE.result}>
          <h2>Scan Results</h2>

          <div>
            <span style={STYLE.stat}>{result.code_findings_count} PII findings in code</span>
            <span style={STYLE.stat}>{result.policy_claims_count} claims in policy</span>
            <span style={{ ...STYLE.stat, background: result.gaps_count > 0 ? '#dc3545' : '#28a745' }}>
              {result.gaps_count} consent gaps
            </span>
          </div>

          {result.gaps_count > 0 && (
            <>
              <h3 style={{ marginTop: '1.5rem' }}>⚠️ Consent Gaps Detected</h3>
              <p style={{ color: '#666', fontSize: '14px' }}>
                These PII types are processed in the code but NOT mentioned in the privacy policy:
              </p>
              {result.gaps_detected.map(g => (
                <div key={g} style={STYLE.gap}>{g}</div>
              ))}
            </>
          )}

          <h3 style={{ marginTop: '1.5rem' }}>Sample Code Findings</h3>
          {result.sample_findings.map((f, i) => (
            <div key={i} style={{ ...STYLE.gap, background: '#e8f4fd', borderColor: '#0d6efd' }}>
              <strong>{f.pii_category}</strong> — {f.file_path} line {f.line_number}<br />
              <span style={{ fontSize: '12px', color: '#444' }}>{f.raw_text}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}