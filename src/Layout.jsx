import { Link, useLocation } from 'react-router-dom';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/* ── Brand mark ──────────────────────────────────────────────────────────── */
const LogoMark = ({ size = 28, uid = 'sb' }) => {
  const slId = `pp-sl-${uid}`;
  const clId = `pp-cl-${uid}`;
  const h = Math.round(size * 72 / 64);
  return (
    <svg width={size} height={h} viewBox="0 0 64 72" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id={slId} x1="0" y1="0" x2="64" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="50%" stopColor="#0d1f3c"/>
          <stop offset="50%" stopColor="#0e3535"/>
        </linearGradient>
        <clipPath id={clId}>
          <path d="M32 3 L60 14 V38 C60 55 48 67 32 72 C16 67 4 55 4 38 V14 Z"/>
        </clipPath>
      </defs>
      <path d="M32 3 L60 14 V38 C60 55 48 67 32 72 C16 67 4 55 4 38 V14 Z" fill={`url(#${slId})`}/>
      <path d="M32 3 L60 14 V38 C60 55 48 67 32 72 C16 67 4 55 4 38 V14 Z" fill="none" stroke="rgba(255,255,255,0.18)" strokeWidth="1.2"/>
      <line x1="32" y1="5" x2="32" y2="70" stroke="rgba(255,255,255,0.1)" strokeWidth="0.8" clipPath={`url(#${clId})`}/>
      <rect x="31" y="30" width="2" height="22" fill="white"/>
      <rect x="23" y="52" width="18" height="2.5" rx="1.2" fill="white"/>
      <rect x="14" y="22" width="36" height="2" rx="1" fill="white"/>
      <circle cx="32" cy="21" r="2.5" fill="white"/>
      <rect x="14.5" y="24" width="1.5" height="9" fill="white"/>
      <rect x="48" y="24" width="1.5" height="9" fill="white"/>
      <path d="M10 33 Q15.75 41 21.5 33" stroke="white" strokeWidth="1.6" strokeLinecap="round" fill="none"/>
      <path d="M42.5 33 Q48.25 41 54 33" stroke="white" strokeWidth="1.6" strokeLinecap="round" fill="none"/>
    </svg>
  );
};

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
            <LogoMark size={28} uid="sb" />
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
