import { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { NOTICE_VERSION, NOTICE_ITEMS, CONTACT_EMAIL, RETENTION } from './legalNotice';
import './landing.css';

const contact = CONTACT_EMAIL
  ? <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
  : <Link to="/#contact">the contact form on our home page</Link>;

export default function Legal() {
  const { hash } = useLocation();
  useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView();
    else window.scrollTo(0, 0);
  }, [hash]);

  return (
    <div className="lg-root">
      <header className="lg-head">
        <Link to="/" className="lg-back">← PrivacyPilot</Link>
      </header>
      <main className="lg-main">
        <h1>Terms of Use and Privacy Notice</h1>
        <p className="lg-meta">Version {NOTICE_VERSION}</p>
        <nav className="lg-toc" aria-label="On this page">
          <a href="#terms">Terms of Use</a>
          <a href="#privacy">Privacy Notice</a>
        </nav>

        <section id="terms">
          <h2>Terms of Use</h2>
          <ol>
            <li><strong>What PrivacyPilot is.</strong> PrivacyPilot is a capstone project of students of MPSTME, SVKM’s NMIMS, Mumbai. It analyses source code and privacy policies and reports likely gaps against the Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025.</li>
            <li><strong>Not legal advice.</strong> Findings are indicators of possible non-compliance, produced automatically. They may be wrong or incomplete and must be confirmed by a qualified legal reviewer. Do not rely on them as legal advice.</li>
            <li><strong>Your content.</strong> Only scan repositories and policies you are allowed to analyse. You remain responsible for the access tokens you provide; use a token with read-only access.</li>
            <li><strong>Demo material.</strong> The demo video shows real scans with repository names blurred. It is provided for information only.</li>
            <li><strong>No warranty.</strong> PrivacyPilot is provided “as is”, without any warranty, and the team is not liable for decisions taken on the basis of its output.</li>
            <li><strong>Changes.</strong> We may update these terms. The version above changes when we do, and we ask again for agreement before you watch the demo.</li>
          </ol>
        </section>

        <section id="privacy">
          <h2>Privacy Notice for demo requests</h2>
          <p>This notice explains how we handle the details you give us when you ask to watch the PrivacyPilot demo. We process them only with your consent, given by ticking the boxes before the video plays.</p>
          <dl className="lg-dl">
            {NOTICE_ITEMS.map(n => (
              <div key={n.label}><dt>{n.label}</dt><dd>{n.text}</dd></div>
            ))}
          </dl>
          <h3>Withdrawing consent and your other rights</h3>
          <p>Contact us at {contact} to withdraw your consent or to see, correct or erase your details. We will delete your details and stop contacting you. Your details are deleted automatically after {RETENTION} in any case.</p>
          <h3>Scans</h3>
          <p>When you run a scan, the GitHub token you enter is encrypted while the scan is queued, is used only to download the repository and is never written to the database. Scan results are stored so you can open them again from the scan history.</p>
          <h3>Grievances</h3>
          <p>If you are unhappy with how we handled your details, contact us at {contact}. You may also approach the Data Protection Board of India.</p>
        </section>
      </main>
    </div>
  );
}
