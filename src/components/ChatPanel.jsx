import { useState, useRef, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function ChatPanel({ scanId }) {
  const [open, setOpen]         = useState(false);
  const [sessionId, setSession] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState('');
  const [typing, setTyping]     = useState(false);
  const bottomRef               = useRef(null);
  const inputRef                = useRef(null);

  // Create session on first open
  useEffect(() => {
    if (!open || sessionId || !scanId) return;
    fetch(`${API}/chat/sessions?scan_id=${scanId}`, { method: 'POST' })
      .then(r => r.json())
      .then(d => {
        setSession(d.session_id);
        setMessages([{
          role: 'assistant',
          content: `👋 Hi! I'm your DPDP compliance advisor for this scan.\n\nAsk me anything about the violations found, how to fix them, or what the DPDP Act requires.`,
        }]);
      })
      .catch(() => {});
  }, [open, scanId, sessionId]);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, typing]);

  const send = async () => {
    const text = input.trim();
    if (!text || !sessionId || typing) return;
    setInput('');
    setMessages(m => [...m, { role: 'user', content: text }]);
    setTyping(true);
    try {
      const r = await fetch(`${API}/chat/sessions/${sessionId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      });
      const d = await r.json();
      setMessages(m => [...m, { role: 'assistant', content: d.content }]);
    } catch {
      setMessages(m => [...m, { role: 'assistant', content: '⚠️ Could not reach the AI advisor. Please try again.' }]);
    } finally {
      setTyping(false);
    }
  };

  const handleKey = e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  return (
    <>
      {/* Floating Action Button */}
      <button
        className="chat-fab"
        onClick={() => { setOpen(o => !o); setTimeout(() => inputRef.current?.focus(), 200); }}
        title="AI Compliance Advisor"
      >
        {open ? '✕' : '💬'}
      </button>

      {/* Chat Panel */}
      {open && (
        <div className="chat-panel animate-in">
          {/* Header */}
          <div className="chat-header">
            <div className="chat-header-icon">🤖</div>
            <div>
              <div className="chat-header-title">AI Compliance Advisor</div>
              <div className="chat-header-sub">DPDP Act 2023 Expert</div>
            </div>
            <button className="chat-close" onClick={() => setOpen(false)}>✕</button>
          </div>

          {/* Messages */}
          <div className="chat-messages">
            {messages.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>
                {!sessionId ? 'Starting session…' : 'Ask your first question'}
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`chat-msg ${m.role}`}>
                <div className="chat-msg-role">{m.role === 'user' ? 'You' : 'PrivacyPilot AI'}</div>
                <div className="chat-bubble">
                  {m.content.split('\n').map((line, j) => (
                    <span key={j}>{line}{j < m.content.split('\n').length - 1 ? <br/> : null}</span>
                  ))}
                </div>
              </div>
            ))}
            {typing && (
              <div className="chat-msg assistant">
                <div className="chat-msg-role">PrivacyPilot AI</div>
                <div className="chat-typing">
                  <span/><span/><span/>
                </div>
              </div>
            )}
            <div ref={bottomRef}/>
          </div>

          {/* Input */}
          <div className="chat-input-area">
            <textarea
              ref={inputRef}
              className="chat-input"
              placeholder={sessionId ? 'Ask about violations, fixes, DPDP sections…' : 'Connecting…'}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              disabled={!sessionId || typing}
              rows={1}
            />
            <button
              className="chat-send"
              onClick={send}
              disabled={!input.trim() || !sessionId || typing}
            >
              ➤
            </button>
          </div>
        </div>
      )}
    </>
  );
}
