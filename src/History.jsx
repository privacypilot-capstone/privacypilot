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
    <div style={{ padding: '2rem', fontFamily: 'sans-serif', maxWidth: '800px', margin: '0 auto' }}>
      <h2>Scan History</h2>
      {scans.length === 0 && <p>No scans yet.</p>}
      {scans.map(s => (
        <div key={s.id} style={{
          border: '1px solid #ddd', borderRadius: '8px',
          padding: '1rem', marginBottom: '10px',
          background: '#fafafa'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <strong>{s.repo_url.replace('https://github.com/', '')}</strong>
            <span style={{ fontSize: '12px', color: '#888' }}>
              {new Date(s.created_at).toLocaleString()}
            </span>
          </div>
          <div style={{ marginTop: '8px', fontSize: '13px', color: '#555' }}>
            {s.findings_count} PII findings ·{' '}
            {s.gaps_count} gaps ·{' '}
            <span style={{ color: s.violations_count > 0 ? '#dc3545' : '#28a745', fontWeight: 'bold' }}>
              {s.violations_count} violations
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}