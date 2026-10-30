import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { GLOSSARY, lookup } from './glossary';
import '../term.css';

/* A term with a plain-English explanation. The explanation appears on
   hover, on keyboard focus, and on tap (touch screens); Escape, scrolling
   or a tap elsewhere closes it. It is drawn in <body> so tables and cards
   with overflow: hidden cannot clip it. */
export default function Term({ k, children, text, className = '' }) {
  const entry = text ? { text } : lookup(k);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState(null);
  const ref = useRef(null);
  const tipRef = useRef(null);
  const timer = useRef(null);
  const id = `term-${useId().replace(/:/g, '')}`;

  const show = () => { clearTimeout(timer.current); timer.current = setTimeout(() => setOpen(true), 90); };
  const hide = () => { clearTimeout(timer.current); timer.current = setTimeout(() => setOpen(false), 120); };

  useLayoutEffect(() => {
    if (!open || !ref.current || !tipRef.current) return;
    const r = ref.current.getBoundingClientRect();
    const t = tipRef.current.getBoundingClientRect();
    const m = 8;
    let left = r.left + r.width / 2 - t.width / 2;
    left = Math.max(m, Math.min(left, window.innerWidth - t.width - m));
    const above = r.top - t.height - 10;
    const below = r.bottom + 10;
    const top = above >= m ? above : below;
    setPos({ left, top, arrow: Math.max(12, Math.min(t.width - 12, r.left + r.width / 2 - left)), flip: above < m });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    const onDown = (e) => {
      if (!ref.current?.contains(e.target) && !tipRef.current?.contains(e.target)) setOpen(false);
    };
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    window.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onDown);
    return () => {
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
      window.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onDown);
    };
  }, [open]);

  useEffect(() => () => clearTimeout(timer.current), []);

  if (!entry) return <>{children}</>;
  return (
    <>
      <span
        ref={ref}
        className={`term ${className}`}
        tabIndex={0}
        role="button"
        aria-describedby={open ? id : undefined}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={() => setOpen(true)}
        onBlur={hide}
        onClick={(e) => { e.stopPropagation(); setOpen(o => !o); }}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); setOpen(o => !o); } }}
      >
        {children ?? entry.term}
      </span>
      {open && createPortal(
        <div
          ref={tipRef}
          id={id}
          role="tooltip"
          className={`term-tip${pos?.flip ? ' below' : ''}`}
          style={pos ? { left: pos.left, top: pos.top, '--arrow': `${pos.arrow}px` } : { left: -9999, top: 0 }}
          onMouseEnter={() => clearTimeout(timer.current)}
          onMouseLeave={hide}
        >
          {entry.term && <strong>{entry.term}</strong>}
          <span>{entry.text}</span>
        </div>,
        document.body
      )}
    </>
  );
}

/* "Section 8(5) / Section 8(2)" or "DPDP Rules 2025, Rule 3(b)(ii)": each
   part that has an entry becomes its own explained term. */
export function SectionTerms({ value }) {
  if (!value) return null;
  const parts = value.split(/(Section \d+(?:\(\d+\))?|Rule \d+(?:\([a-z]\))?(?:\([ivx]+\))?)/g);
  return parts.map((p, i) => (GLOSSARY[p] ? <Term key={i} k={p}>{p}</Term> : p));
}

/* A personal-data category such as "aadhaar" with its meaning. */
export function CategoryTerm({ cat, children }) {
  const k = `cat_${String(cat || '').toLowerCase()}`;
  return GLOSSARY[k] ? <Term k={k}>{children ?? cat}</Term> : <>{children ?? cat}</>;
}
