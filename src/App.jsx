import { useState, useEffect, useRef } from 'react'

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
  // ── Chat panel ─────────────────────────────────────────────────────────
  chatBtn: {
    position: 'fixed', bottom: '28px', right: '28px', width: '56px', height: '56px',
    borderRadius: '50%', background: '#1a1a2e', color: '#fff', border: 'none',
    fontSize: '24px', cursor: 'pointer', boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
  },
  chatPanel: {
    position: 'fixed', bottom: '96px', right: '28px', width: '380px',
    height: '500px', background: '#fff', borderRadius: '14px',
    boxShadow: '0 8px 40px rgba(0,0,0,0.18)', display: 'flex', flexDirection: 'column',
    zIndex: 1000, border: '1px solid #dee2e6', overflow: 'hidden',
  },
  chatHeader: {
    background: '#1a1a2e', color: '#fff', padding: '12px 16px',
    fontWeight: 'bold', fontSize: '14px', display: 'flex',
    justifyContent: 'space-between', alignItems: 'center',
  },
  chatBody: {
    flex: 1, overflowY: 'auto', padding: '12px 14px',
    display: 'flex', flexDirection: 'column', gap: '10px',
  },
  chatInputRow: {
    display: 'flex', gap: '8px', padding: '10px 12px',
    borderTop: '1px solid #dee2e6', background: '#f8f9fa',
  },
  chatInput: {
    flex: 1, padding: '8px 12px', borderRadius: '20px',
    border: '1px solid #ccc', fontSize: '13px', outline: 'none',
  },
  chatSend: {
    padding: '8px 16px', borderRadius: '20px', background: '#1a1a2e',
    color: '#fff', border: 'none', cursor: 'pointer', fontSize: '13px',
  },
  bubbleUser: {
    alignSelf: 'flex-end', background: '#1a1a2e', color: '#fff',
    borderRadius: '16px 16px 4px 16px', padding: '8px 14px',
    fontSize: '13px', maxWidth: '80%', lineHeight: 1.5,
  },
  bubbleBot: {
    alignSelf: 'flex-start', background: '#f0f4ff', color: '#111',
    borderRadius: '16px 16px 16px 4px', padding: '8px 14px',
    fontSize: '13px', maxWidth: '85%', lineHeight: 1.5, whiteSpace: 'pre-wrap',
  },
  bubbleTyping: {
    alignSelf: 'flex-start', background: '#f0f4ff', color: '#888',
    borderRadius: '16px', padding: '8px 14px', fontSize: '13px',
  },
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

  // ── Chat state ─────────────────────────────────────────────────────────
  const [chatOpen,    setChatOpen]    = useState(false)
  const [sessionId,   setSessionId]   = useState(null)
  const [chatMsgs,    setChatMsgs]    = useState([])
  const [chatInput,   setChatInput]   = useState('')
  const [chatLoading, setChatLoading] = useState(false)
  const [aiSummary,   setAiSummary]   = useState(null)
  const [summaryLoading, setSummaryLoading] = useState(false)
  const chatBodyRef = useRef(null)

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (chatBodyRef.current) {
      chatBodyRef.current.scrollTop = chatBodyRef.current.scrollHeight
    }
  }, [chatMsgs, chatLoading])

  // When a scan completes: fetch AI summary and create a chat session
  useEffect(() => {
    if (!result?.scan_id) return
    // Fetch AI summary
    setSummaryLoading(true)
    fetch(`http://localhost:8000/scans/${result.scan_id}/summary`)
      .then(r => r.json())
      .then(d => setAiSummary(d.summary))
      .catch(() => setAiSummary(null))
      .finally(() => setSummaryLoading(false))
    // Create chat session
    fetch(`http://localhost:8000/chat/sessions?scan_id=${result.scan_id}`, { method: 'POST' })
      .then(r => r.json())
      .then(d => setSessionId(d.session_id))
      .catch(() => {})
  }, [result?.scan_id])

  const sendChatMessage = async () => {
    const text = chatInput.trim()
    if (!text || !sessionId || chatLoading) return
    setChatInput('')
    setChatMsgs(m => [...m, { role: 'user', content: text }])
    setChatLoading(true)
    try {
      const res = await fetch(`http://localhost:8000/chat/sessions/${sessionId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      })
      const data = await res.json()
      setChatMsgs(m => [...m, { role: 'assistant', content: data.content }])
    } catch {
      setChatMsgs(m => [...m, { role: 'assistant', content: '⚠️ Connection error. Please try again.' }])
    } finally {
      setChatLoading(false)
    }
  }

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

        {/* ── AI Executive Summary ────────────────────────────────────── */}
        {(summaryLoading || aiSummary) && (
          <div style={{
            marginTop: '1.5rem', background: '#fff', border: '1px solid #dee2e6',
            borderRadius: '10px', overflow: 'hidden',
          }}>
            <div style={{
              background: 'linear-gradient(135deg, #1a1a2e, #16213e)',
              padding: '12px 18px', display: 'flex', alignItems: 'center', gap: '10px',
            }}>
              <span style={{ fontSize: '18px' }}>🤖</span>
              <span style={{ color: '#fff', fontWeight: 'bold', fontSize: '15px' }}>
                AI Compliance Summary
              </span>
              <span style={{
                marginLeft: 'auto', background: 'rgba(255,255,255,0.15)',
                color: '#ccc', fontSize: '11px', padding: '2px 8px', borderRadius: '99px',
              }}>Powered by Gemini</span>
            </div>
            <div style={{ padding: '1rem 1.2rem', fontSize: '14px', lineHeight: 1.7, color: '#333' }}>
              {summaryLoading
                ? <span style={{ color: '#888' }}>⏳ Generating executive summary…</span>
                : <span style={{ whiteSpace: 'pre-wrap' }}>{aiSummary}</span>
              }
            </div>
          </div>
        )}
      </div>

    {/* ── Floating chat button ────────────────────────────────────────── */}
    {result?.scan_id && (
      <>
        <button
          style={{
            ...STYLE.chatBtn,
            background: chatOpen ? '#dc3545' : '#1a1a2e',
          }}
          onClick={() => setChatOpen(o => !o)}
          title="Ask the DPDP compliance advisor"
        >
          {chatOpen ? '✕' : '💬'}
        </button>

        {chatOpen && (
          <div style={STYLE.chatPanel}>
            {/* Header */}
            <div style={STYLE.chatHeader}>
              <span>🛡️ DPDP Compliance Advisor</span>
              <span style={{ fontSize: '11px', color: '#aaa' }}>
                Scan #{result.scan_id}
              </span>
            </div>

            {/* Messages */}
            <div style={STYLE.chatBody} ref={chatBodyRef}>
              {chatMsgs.length === 0 && (
                <div style={{ color: '#888', fontSize: '13px', textAlign: 'center', marginTop: '2rem' }}>
                  <div style={{ fontSize: '28px', marginBottom: '8px' }}>🔍</div>
                  Ask me anything about your compliance scan.<br />
                  <span style={{ fontSize: '12px' }}>
                    e.g. "Which violation should I fix first?" or<br />
                    "What does Section 8(2) require?"
                  </span>
                </div>
              )}

              {chatMsgs.map((m, i) => (
                <div key={i} style={m.role === 'user' ? STYLE.bubbleUser : STYLE.bubbleBot}>
                  {m.content}
                </div>
              ))}

              {chatLoading && (
                <div style={STYLE.bubbleTyping}>
                  <span>⏳ Thinking…</span>
                </div>
              )}
            </div>

            {/* Input */}
            <div style={STYLE.chatInputRow}>
              <input
                style={STYLE.chatInput}
                placeholder="Ask a compliance question…"
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && sendChatMessage()}
                disabled={chatLoading || !sessionId}
              />
              <button
                style={{
                  ...STYLE.chatSend,
                  opacity: (chatLoading || !sessionId) ? 0.5 : 1,
                }}
                onClick={sendChatMessage}
                disabled={chatLoading || !sessionId}
              >Send</button>
            </div>
          </div>
        )}
      </>
    )}
  </>
  )
}
