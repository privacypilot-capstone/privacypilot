import { useState, useEffect, useRef } from 'react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function ChatPanel({ scanId }) {
  const [open,       setOpen]       = useState(false)
  const [sessionId,  setSessionId]  = useState(null)
  const [msgs,       setMsgs]       = useState([])
  const [input,      setInput]      = useState('')
  const [loading,    setLoading]    = useState(false)
  const bodyRef = useRef(null)

  useEffect(() => {
    if (!scanId) return
    fetch(`${API}/chat/sessions?scan_id=${scanId}`, { method: 'POST' })
      .then(r => r.json())
      .then(d => setSessionId(d.session_id))
      .catch(() => {})
  }, [scanId])

  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight
  }, [msgs, loading])

  const send = async () => {
    const text = input.trim()
    if (!text || !sessionId || loading) return
    setInput('')
    setMsgs(m => [...m, { role: 'user', content: text }])
    setLoading(true)
    try {
      const res = await fetch(`${API}/chat/sessions/${sessionId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      })
      const d = await res.json()
      setMsgs(m => [...m, { role: 'assistant', content: d.content }])
    } catch {
      setMsgs(m => [...m, { role: 'assistant', content: '⚠️ Connection error. Please try again.' }])
    } finally {
      setLoading(false)
    }
  }

  if (!scanId) return null

  return (
    <>
      <button
        className="chat-fab"
        style={{ background: open ? '#dc3545' : '#1a1a2e' }}
        onClick={() => setOpen(o => !o)}
        title="Ask the DPDP compliance advisor"
      >
        {open ? '✕' : '💬'}
      </button>

      {open && (
        <div className="chat-panel">
          <div className="chat-header">
            <span>🛡️ DPDP Compliance Advisor</span>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>Scan #{scanId}</span>
          </div>

          <div className="chat-body" ref={bodyRef}>
            {msgs.length === 0 && (
              <div className="chat-empty">
                <div style={{ fontSize: '28px', marginBottom: '8px' }}>🔍</div>
                Ask anything about this scan.<br />
                <span style={{ fontSize: '12px' }}>
                  "Which violation is most urgent?"<br />
                  "What does Section 8(2) require?"
                </span>
              </div>
            )}
            {msgs.map((m, i) => (
              <div key={i} className={m.role === 'user' ? 'bubble-user' : 'bubble-bot'}>
                {m.content}
              </div>
            ))}
            {loading && <div className="bubble-typing">⏳ Thinking…</div>}
          </div>

          <div className="chat-input-row">
            <input
              className="chat-input"
              placeholder="Ask a compliance question…"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && send()}
              disabled={loading || !sessionId}
            />
            <button className="chat-send" onClick={send} disabled={loading || !sessionId}>
              Send
            </button>
          </div>
        </div>
      )}
    </>
  )
}
