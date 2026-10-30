import { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { MessageCircle, X, Sparkle, Send } from './Icons';
import Markdown from './Markdown';

export const BOT_NAME = 'Vidhi';   // Hindi/Sanskrit for "law" or "rule"

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
          content: `Hi, I'm **${BOT_NAME}**, PrivacyPilot's DPDP compliance assistant.\n\nI have the results of this scan. Ask me about the violations found, how to fix them, or what the DPDP Act requires.`,
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
      setMessages(m => [...m, { role: 'assistant', content: `${BOT_NAME} could not be reached. Please try again.` }]);
    } finally {
      setTyping(false);
    }
  };

  const handleKey = e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  // Rendered into <body>: an animated ancestor (transform) would otherwise
  // pin "position: fixed" to that container instead of the screen.
  return createPortal(
    <>
      {/* Floating Action Button */}
      <button
        className="chat-fab"
        onClick={() => { setOpen(o => !o); setTimeout(() => inputRef.current?.focus(), 200); }}
        title={open ? 'Close chat' : `Ask ${BOT_NAME}`}
        aria-label={open ? 'Close chat' : `Ask ${BOT_NAME}, the DPDP compliance assistant`}
        aria-expanded={open}
      >
        {open ? <X size={22} /> : <MessageCircle size={22} />}
        {!open && <span className="chat-fab-label">Ask {BOT_NAME}</span>}
      </button>

      {/* Chat Panel */}
      {open && (
        <div className="chat-panel animate-in" role="dialog" aria-label={`${BOT_NAME} chat`}>
          {/* Header */}
          <div className="chat-header">
            <div className="chat-header-icon"><Sparkle size={18} /></div>
            <div>
              <div className="chat-header-title">{BOT_NAME}</div>
              <div className="chat-header-sub">DPDP compliance assistant · PrivacyPilot</div>
            </div>
            <button className="chat-close" onClick={() => setOpen(false)} aria-label="Close chat"><X size={16} /></button>
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
                <div className="chat-msg-role">{m.role === 'user' ? 'You' : BOT_NAME}</div>
                <div className="chat-bubble">
                  {m.role === 'user' ? m.content : <Markdown text={m.content || ''} />}
                </div>
              </div>
            ))}
            {typing && (
              <div className="chat-msg assistant">
                <div className="chat-msg-role">{BOT_NAME}</div>
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
              <Send size={16} />
            </button>
          </div>
        </div>
      )}
    </>,
    document.body
  );
}
