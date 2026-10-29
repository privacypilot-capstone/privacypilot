// Text of the notice shown before the demo video, and of the /legal page.
// NOTICE_VERSION must equal DEMO_NOTICE_VERSION in backend/main.py; bump both
// whenever the wording changes, so stored consents point to the text agreed to.
export const NOTICE_VERSION = '2026-10-29';
export const RETENTION = '12 months';
export const CONTACT_EMAIL = import.meta.env.VITE_CONTACT_EMAIL || '';
// Your own screen recording: put it in public/demo/ (or anywhere) and set VITE_DEMO_VIDEO_URL.
export const DEMO_VIDEO = import.meta.env.VITE_DEMO_VIDEO_URL || '';

export const NOTICE_ITEMS = [
  { label: 'What we collect', text: 'Your name and work e-mail, and, if you give them, your organisation, your role and what you would like to scan.' },
  { label: 'Why', text: 'To show you the product demo and to contact you about it. If you tick the optional box, also to send you occasional product updates.' },
  { label: 'How long', text: `Up to ${RETENTION}, after which your details are deleted automatically.` },
  { label: 'Who sees it', text: 'Only the PrivacyPilot team. Your details are not sold or shared with anyone else.' },
  { label: 'Your rights', text: 'You can withdraw consent, and ask us to show, correct or erase your details, at any time by contacting us. Withdrawing is as easy as giving consent.' },
];
