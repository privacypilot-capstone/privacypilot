import { useState, useEffect } from 'react'

function App() {
  const [status, setStatus] = useState('checking...')

  useEffect(() => {
    fetch('http://localhost:8000/health')
      .then(r => r.json())
      .then(d => setStatus(d.message))
      .catch(() => setStatus('cannot reach backend'))
  }, [])

  return (
    <div style={{ padding: '2rem', fontFamily: 'monospace' }}>
      <h1>PrivacyPilot</h1>
      <p>Backend status: <strong>{status}</strong></p>
    </div>
  )
}

export default App