import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { NOTICE_VERSION, NOTICE_ITEMS, CONTACT_EMAIL, DEMO_VIDEO } from '../legalNotice';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const STORE_KEY = 'pp_demo_consent';
const STEPS = ['Your details', 'Consent', 'Watch the demo'];
const ROLES = ['Developer or engineer', 'Security or privacy', 'Legal or DPO', 'Product or management', 'Student or researcher', 'Other'];

function readConsent() {
  try {
    const v = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
    return v && v.version === NOTICE_VERSION ? v : null;
  } catch { return null; }
}
function saveConsent(v) {
  try { localStorage.setItem(STORE_KEY, JSON.stringify(v)); } catch { /* private mode */ }
}
function forgetConsent() {
  try { localStorage.removeItem(STORE_KEY); } catch { /* private mode */ }
}

const Check = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
);
const Close = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
);

export default function DemoModal({ open, onClose }) {
  const prior = readConsent();
  const [step, setStep] = useState(prior ? 2 : 0);
  const [form, setForm] = useState({ name: '', email: '', organisation: '', role: '', use_case: '' });
  const [consent, setConsent] = useState({ terms: false, contact: false, updates: false });
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [apiError, setApiError] = useState('');
  const dialogRef = useRef(null);
  const lastFocus = useRef(null);

  // Open/close housekeeping: focus, scroll lock, Escape, simple focus trap.
  useEffect(() => {
    if (!open) return;
    lastFocus.current = document.activeElement;
    setStep(readConsent() ? 2 : 0);
    setApiError('');
    document.body.style.overflow = 'hidden';
    document.documentElement.style.overflow = 'hidden';
    const t = setTimeout(() => dialogRef.current?.querySelector('input, button, video')?.focus(), 30);
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'Tab' && dialogRef.current) {
        const f = [...dialogRef.current.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, video')];
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(t);
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
      document.documentElement.style.overflow = '';
      lastFocus.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const nextFromDetails = (e) => {
    e.preventDefault();
    const er = {};
    if (!form.name.trim()) er.name = 'Please enter your name.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) er.email = 'Please enter a valid work e-mail.';
    setErrors(er);
    if (!Object.keys(er).length) setStep(1);
  };

  const submitConsent = async (e) => {
    e.preventDefault();
    if (!consent.terms || !consent.contact) return;
    setBusy(true); setApiError('');
    try {
      const r = await fetch(`${API}/demo-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...form,
          accepted_terms: consent.terms,
          consent_contact: consent.contact,
          consent_updates: consent.updates,
          notice_version: NOTICE_VERSION,
        }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        const detail = d.detail && typeof d.detail === 'object' ? Object.values(d.detail).join(' ') : d.detail;
        throw new Error(detail || `The request failed (HTTP ${r.status}).`);
      }
      saveConsent({ version: NOTICE_VERSION, at: new Date().toISOString() });
      setStep(2);
    } catch (err) {
      setApiError(err.message === 'Failed to fetch'
        ? 'We could not reach the PrivacyPilot server. Please try again in a moment.'
        : err.message);
    } finally {
      setBusy(false);
    }
  };

  const agreedOn = readConsent()?.at;

  return (
    <div className="dm-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`dm-dialog${step === 2 ? ' dm-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="dm-title" ref={dialogRef}>
        <button className="dm-close" onClick={onClose} aria-label="Close"><Close /></button>

        <ol className="dm-steps" aria-label="Progress">
          {STEPS.map((s, i) => (
            <li key={s} className={i < step ? 'done' : i === step ? 'current' : ''} aria-current={i === step ? 'step' : undefined}>
              <span className="dm-step-dot">{i < step ? <Check /> : i + 1}</span>
              <span className="dm-step-label">{s}</span>
            </li>
          ))}
        </ol>

        {step === 0 && (
          <form onSubmit={nextFromDetails} noValidate className="dm-body">
            <h2 id="dm-title">See PrivacyPilot in action</h2>
            <p className="dm-lead">Tell us a little about yourself and we will show you a short walkthrough of a scan.</p>
            <div className="dm-grid">
              <label className="dm-field">
                <span>Full name <i aria-hidden="true">*</i></span>
                <input value={form.name} onChange={set('name')} autoComplete="name" required aria-invalid={!!errors.name} />
                {errors.name && <em>{errors.name}</em>}
              </label>
              <label className="dm-field">
                <span>Work e-mail <i aria-hidden="true">*</i></span>
                <input type="email" value={form.email} onChange={set('email')} autoComplete="email" required aria-invalid={!!errors.email} />
                {errors.email && <em>{errors.email}</em>}
              </label>
              <label className="dm-field">
                <span>Organisation</span>
                <input value={form.organisation} onChange={set('organisation')} autoComplete="organization" maxLength={120} />
              </label>
              <label className="dm-field">
                <span>Role</span>
                <select value={form.role} onChange={set('role')}>
                  <option value="">Select…</option>
                  {ROLES.map(r => <option key={r}>{r}</option>)}
                </select>
              </label>
            </div>
            <label className="dm-field">
              <span>What would you like to scan? <small>(optional)</small></span>
              <textarea rows={3} value={form.use_case} onChange={set('use_case')} maxLength={1000}
                placeholder="For example: a Node.js back end for a fintech app" />
            </label>
            <div className="dm-actions">
              <span className="dm-hint"><i aria-hidden="true">*</i> Required</span>
              <button type="submit" className="dm-btn">Continue →</button>
            </div>
          </form>
        )}

        {step === 1 && (
          <form onSubmit={submitConsent} className="dm-body">
            <h2 id="dm-title">Before you watch</h2>
            <p className="dm-lead">Please read how we use your details. You can change your mind at any time.</p>
            <dl className="dm-notice" tabIndex={0} aria-label="Privacy notice">
              {NOTICE_ITEMS.map(n => (
                <div key={n.label}><dt>{n.label}</dt><dd>{n.text}</dd></div>
              ))}
              <div><dt>Contact</dt><dd>{CONTACT_EMAIL
                ? <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
                : <>Use the contact form on our home page.</>}</dd></div>
            </dl>
            <p className="dm-version">Notice version {NOTICE_VERSION} · <Link to="/legal" target="_blank" rel="noopener">Read the full Terms and Privacy Notice</Link></p>

            <fieldset className="dm-checks">
              <legend className="dm-sr">Consent</legend>
              <label className="dm-check">
                <input type="checkbox" checked={consent.terms} onChange={e => setConsent({ ...consent, terms: e.target.checked })} />
                <span>I have read and agree to the <Link to="/legal#terms" target="_blank" rel="noopener">Terms of Use</Link> and the <Link to="/legal#privacy" target="_blank" rel="noopener">Privacy Notice</Link>. <i aria-hidden="true">*</i></span>
              </label>
              <label className="dm-check">
                <input type="checkbox" checked={consent.contact} onChange={e => setConsent({ ...consent, contact: e.target.checked })} />
                <span>I consent to PrivacyPilot using the details above to show me the demo and to contact me about it. <i aria-hidden="true">*</i></span>
              </label>
              <label className="dm-check">
                <input type="checkbox" checked={consent.updates} onChange={e => setConsent({ ...consent, updates: e.target.checked })} />
                <span>Send me occasional product updates (optional).</span>
              </label>
            </fieldset>

            {apiError && <div className="dm-error" role="alert">{apiError}</div>}

            <div className="dm-actions">
              <button type="button" className="dm-btn-ghost" onClick={() => setStep(0)}>← Back</button>
              <button type="submit" className="dm-btn" disabled={!consent.terms || !consent.contact || busy}>
                {busy ? 'Saving…' : 'Agree and watch demo'}
              </button>
            </div>
          </form>
        )}

        {step === 2 && (
          <div className="dm-body">
            <h2 id="dm-title">How a PrivacyPilot scan works</h2>
            <div className="dm-video">
              <video controls autoPlay muted playsInline preload="metadata" poster={DEMO_VIDEO ? undefined : "/demo/privacypilot-demo-poster.jpg"}>
                {DEMO_VIDEO ? <source src={DEMO_VIDEO} /> : <>
                  <source src="/demo/privacypilot-demo.webm" type="video/webm" />
                  <source src="/demo/privacypilot-demo.mp4" type="video/mp4" />
                  <track kind="captions" src="/demo/privacypilot-demo.vtt" srcLang="en" label="English" />
                </>}
                Your browser cannot play this video.
              </video>
            </div>
            <div className="dm-actions dm-after">
              <p className="dm-consent-note">
                {agreedOn && <>You agreed to the notice on {new Date(agreedOn).toLocaleDateString()}. </>}
                To withdraw consent, {CONTACT_EMAIL ? <a href={`mailto:${CONTACT_EMAIL}?subject=Withdraw%20consent`}>e-mail us</a> : <>use the contact form</>}.{' '}
                <button type="button" className="dm-link" onClick={() => { forgetConsent(); setStep(0); }}>Not you?</button>
              </p>
              <div className="dm-after-ctas">
                <a href="#contact" className="dm-btn-ghost" onClick={onClose}>Talk to us</a>
                <Link to="/app" className="dm-btn">Start a scan →</Link>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
