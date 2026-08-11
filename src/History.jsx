import { useState, useEffect } from 'react'

export default function History() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('http://localhost:8000/scans')
      .then(r => r.json())
      .then(data => { setScans(data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  if (loading) return <p style={{ padding: '2rem' }}>Loading history...</p>

  return (
    <>
      <div style={{ background: '#1a1a2e', padding: '10px 2rem', display: 'flex', gap: '20px' }}>
        <span style={{ color: '#fff', fontWeight: 'bold' }}>PrivacyPilot</span>
        <a href="/" style={{ color: '#aaa', fontSize: '14px', textDecoration: 'none' }}>New Scan</a>
        <a href="/history" style={{ color: '#fff', fontSize: '14px', textDecoration: 'none', fontWeight: 'bold' }}>History</a>
      </div>

      <div style={{ padding: '2rem', fontFamily: 'sans-serif', maxWidth: '800px', margin: '0 auto' }}>
        <h2>Scan History</h2>
        {scans.length === 0 && <p>No scans yet.</p>}
        {scans.map(s => (
          <div key={s.id} style={{
            border: '1px solid #ddd', borderRadius: '8px',
            padding: '1rem', marginBottom: '10px', background: '#fafafa'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <strong>{s.repo_url.replace('https://github.com/', '')}</strong>
                <div style={{ marginTop: '6px', fontSize: '13px', color: '#555' }}>
                  {s.findings_count} findings · {s.gaps_count} gaps ·{' '}
                  <span style={{
                    color: s.violations_count > 0 ? '#dc3545' : '#28a745',
                    fontWeight: 'bold'
                  }}>
                    {s.violations_count} violations
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: '#aaa', marginTop: '4px' }}>
                  Scan #{s.id} · {new Date(s.created_at).toLocaleString()}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '8px', flexShrink: 0, marginLeft: '1rem' }}>
  <button
    onClick={() => window.open('http://localhost:8000/report/' + s.id, '_blank')}
    style={{
      padding: '6px 14px', fontSize: '12px', borderRadius: '6px',
      background: '#1a1a2e', color: '#fff', border: 'none', cursor: 'pointer'
    }}
  >
    View Report
  </button>
  <button
    onClick={() => window.open('http://localhost:8000/report/' + s.id + '?format=pdf')}
    style={{
      padding: '6px 14px', fontSize: '12px', borderRadius: '6px',
      background: '#dc3545', color: '#fff', border: 'none', cursor: 'pointer'
    }}
  >
    Download PDF
  </button>
</div>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}