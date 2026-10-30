import { Link, useLocation } from 'react-router-dom';
import LogoMark from './components/LogoMark';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// SVG icons as inline components
const Icon = {
  Shield: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Scan: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  ),
  History: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="12 8 12 12 14 14"/><path d="M3.05 11a9 9 0 1 0 .5-4.3"/>
      <polyline points="3 3 3 7 7 7"/>
    </svg>
  ),
  Report: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
    </svg>
  ),
  Dot: () => (
    <svg viewBox="0 0 8 8" fill="currentColor" style={{width:8,height:8}}>
      <circle cx="4" cy="4" r="4"/>
    </svg>
  ),
};

export default function Layout({ children }) {
  const location = useLocation();
  const path = location.pathname;

  const navItems = [
    { to: '/app',     label: 'New Scan',    Icon: Icon.Scan    },
    { to: '/history', label: 'Scan History', Icon: Icon.History },
  ];

  return (
    <div className="app-shell">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <LogoMark size={32} />
          </div>
          <div>
            <div className="sidebar-logo-text">PrivacyPilot</div>
            <div className="sidebar-logo-tag">DPDP Compliance</div>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-label">Navigation</div>
          <Link to="/" className="sidebar-link">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
              <polyline points="9 22 9 12 15 12 15 22"/>
            </svg>
            Home
          </Link>
        </div>
        <div className="sidebar-section">
          <div className="sidebar-section-label">Platform</div>
          {navItems.map(({ to, label, Icon: NavIcon }) => (
            <Link
              key={to}
              to={to}
              className={`sidebar-link ${path === to || (to !== '/app' && path !== '/app' && path.startsWith(to)) ? 'active' : ''}`}
            >
              <NavIcon />
              {label}
            </Link>
          ))}
        </div>

        <div className="sidebar-section" style={{ marginTop: 8 }}>
          <div className="sidebar-section-label">Resources</div>
          <a
            href={`${API}/docs`}
            target="_blank"
            rel="noreferrer"
            className="sidebar-link"
          >
            <Icon.Report />
            API Docs
          </a>
        </div>

        <div className="sidebar-footer">
          <div className="sidebar-footer-text">
            <strong>DPDP Act 2023</strong>
            India Digital Personal Data Protection
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <div className="main">
        {children}
      </div>
    </div>
  );
}
