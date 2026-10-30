import { Fragment } from 'react';

/* ── Minimal, safe Markdown → React (no HTML injection) ─────────────
   Handles what the model actually sends: **bold**, *italic*, `code`,
   headings, bullet and numbered lists, and paragraphs. */
function inline(text, key = 0) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|__[^_]+__|`[^`]+`|\*[^*\s][^*]*\*)/g;
  let last = 0, m, i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith('**') || t.startsWith('__')) out.push(<strong key={`${key}-${i++}`}>{t.slice(2, -2)}</strong>);
    else if (t.startsWith('`')) out.push(<code key={`${key}-${i++}`}>{t.slice(1, -1)}</code>);
    else out.push(<em key={`${key}-${i++}`}>{t.slice(1, -1)}</em>);
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  // any stray markers left over (unbalanced ** etc.) are dropped
  return out.map(x => typeof x === 'string'
    ? x.replace(/\*+|__|`/g, '')   // leftover Markdown marks (code spans are separate elements)
    : x);
}

export default function Markdown({ text }) {
  const blocks = [];
  let list = null, para = [];
  const flushPara = () => { if (para.length) { blocks.push({ t: 'p', lines: para }); para = []; } };
  const flushList = () => { if (list) { blocks.push(list); list = null; } };
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.trimEnd();
    const bullet = line.match(/^\s*[-*•]\s+(.*)$/);
    const num = line.match(/^\s*(\d+)[.)]\s+(.*)$/);
    const head = line.match(/^\s*#{1,6}\s+(.*)$/);
    if (bullet || num) {
      flushPara();
      const type = bullet ? 'ul' : 'ol';
      if (!list || list.t !== type) { flushList(); list = { t: type, items: [] }; }
      list.items.push(bullet ? bullet[1] : num[2]);
    } else if (head) {
      flushPara(); flushList(); blocks.push({ t: 'h', text: head[1] });
    } else if (!line.trim()) {
      flushPara(); flushList();
    } else {
      flushList(); para.push(line.trim());
    }
  }
  flushPara(); flushList();
  return blocks.map((b, i) =>
    b.t === 'p'  ? <p key={i}>{b.lines.map((l, j) => <Fragment key={j}>{j > 0 && <br />}{inline(l, `${i}-${j}`)}</Fragment>)}</p>
  : b.t === 'h'  ? <p key={i} className="chat-md-h">{inline(b.text, i)}</p>
  : b.t === 'ul' ? <ul key={i}>{b.items.map((x, j) => <li key={j}>{inline(x, `${i}-${j}`)}</li>)}</ul>
  :                <ol key={i}>{b.items.map((x, j) => <li key={j}>{inline(x, `${i}-${j}`)}</li>)}</ol>);
}
