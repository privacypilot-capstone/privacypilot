import { Link, useLocation } from 'react-router-dom'

export default function Navbar() {
  const { pathname } = useLocation()
  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <span>🛡️</span> PrivacyPilot
      </div>
      <Link to="/"        className={'navbar-link' + (pathname === '/'        ? ' active' : '')}>New Scan</Link>
      <Link to="/history" className={'navbar-link' + (pathname === '/history' ? ' active' : '')}>History</Link>
    </nav>
  )
}
