import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Layout from './Layout';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function scoreColor(violations, status) {
  if (status !== 'complete') return '#94a3b8';
  if (violations === 0) return '#22c55e';
  if (violations <= 2) return '#f97316';
  return '#ef4444';
}

function ScoreMini({ violations, status }) {
  if (status !== 'complete') return <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>—</span>;
  const color = scoreColor(violations, status);
  return (
    <div className="mini-score" style={{ color }}>
      <svg width="32" height="32" viewBox="0 0 32 32">
        <circle cx="16" cy="16" r="13" fill="none" stroke="#e2e8f0" strokeWidth="3"/>
        <circle
          cx="16" cy="16" r="13"
          fill="none" stroke={color} strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={`${Math.max(0, 82 - violations * 8)} 82`}
          transform="rotate(-90 16 16)"
        />
      </svg>
      <span style={{ fontSize: 14, fontWeight: 700 }}>{violations}v</span>
    </div>
  );
}

function StatusBadge({ status }) {
  const map = {
    complete: 'complete',
    failed:   'failed',
    running:  'running',
    queued:   'queued',
  };
  return (
    <span className={`status-pill ${map[status] || 'queued'}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function formatDate(iso) {
  const d = new Date(iso);
  const now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 60)     return 'Just now';
  if (diff < 3600)   return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400)  return `${Math.floor(diff/3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff/86400)}d ago`;
  return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
}

function shortRepo(url) {
  return url.replace('https://github.com/', '').replace(/\/$/, '');
}

export default function History() {
  const [scans,  setScans]  = useState([]);
  const [loading,setLoad]   = useState(true);
  const [error,  setError]  = useState('');
  const [search, setSearch] = useState('');
  const [sortBy, setSort]   = useState('date');

  useEffect(() => {
    fetch(`${API}/scans`)
      .then(r => r.json())
      .then(d => { setScans(d); setLoad(false); })
      .catch(e => { setError(e.message); setLoad(false); });
  }, []);

  const filtered = scans
    .filter(s => !search || s.repo_url.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      if (sortBy === 'date') return new Date(b.created_at) - new Date(a.created_at);
      if (sortBy === 'violations') return (b.violations_count || 0) - (a.violations_count || 0);
      if (sortBy === 'findings')   return (b.findings_count  || 0) - (a.findings_count  || 0);
      return 0;
    });

  const total   = scans.length;
  const done    = scans.filter(s => s.status === 'complete').length;
  const failed  = scans.filter(s => s.status === 'failed').length;
  const critArr = scans.filter(s => s.violations_count > 0);

  return (
    <Layout>
      <div className="topbar">
        <div className="topbar-breadcrumb">
          <span>Scan History</span>
        </div>
        <div className="topbar-right">
          <Link to="/app" className="btn btn-primary btn-sm">
            + New Scan
          </Link>
        </div>
      </div>

      <div className="page-content">
        {/* Summary strip */}
        <div className="metrics-row mb-24">
          <div className="metric-card">
            <div className="metric-icon" style={{ background: '#f0f4ff', fontSize: 20 }}>📊</div>
            <div className="metric-label">Total Scans</div>
            <div className="metric-value">{total}</div>
            <div className="metric-sub">all time</div>
          </div>
          <div className="metric-card">
            <div className="metric-icon" style={{ background: '#f0fdf4', fontSize: 20 }}>✅</div>
            <div className="metric-label">Completed</div>
            <div className="metric-value" style={{ color: '#22c55e' }}>{done}</div>
            <div className="metric-sub">successful scans</div>
          </div>
          <div className="metric-card">
            <div className="metric-icon" style={{ background: '#fef2f2', fontSize: 20 }}>❌</div>
            <div className="metric-label">Failed</div>
            <div className="metric-value" style={{ color: failed > 0 ? '#ef4444' : '#94a3b8' }}>{failed}</div>
            <div className="metric-sub">scan errors</div>
          </div>
          <div className="metric-card">
            <div className="metric-icon" style={{ background: '#fffbeb', fontSize: 20 }}>⚠️</div>
            <div className="metric-label">With Violations</div>
            <div className="metric-value" style={{ color: critArr.length > 0 ? '#f59e0b' : '#22c55e' }}>{critArr.length}</div>
            <div className="metric-sub">repos need attention</div>
          </div>
        </div>

        {/* Table card */}
        <div className="card">
          <div className="card-header" style={{ gap: 12 }}>
            <div>
              <div className="card-header-title">All Scans</div>
              <div className="card-header-subtitle">{filtered.length} results</div>
            </div>
            {/* Search */}
            <div style={{ position: 'relative', marginLeft: 'auto' }}>
              <span style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
              </span>
              <input
                type="text"
                placeholder="Search repos…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{
                  paddingLeft: 32, paddingRight: 12, height: 34,
                  border: '1.5px solid var(--border)', borderRadius: 8,
                  fontSize: 13, width: 220, outline: 'none',
                  fontFamily: 'var(--font)',
                }}
              />
            </div>
            {/* Sort */}
            <select
              value={sortBy}
              onChange={e => setSort(e.target.value)}
              style={{
                padding: '6px 12px', border: '1.5px solid var(--border)',
                borderRadius: 8, fontSize: 13, color: 'var(--text-secondary)',
                fontFamily: 'var(--font)', outline: 'none', cursor: 'pointer',
              }}
            >
              <option value="date">Sort: Newest</option>
              <option value="violations">Sort: Most Violations</option>
              <option value="findings">Sort: Most Findings</option>
            </select>
          </div>

          {loading && (
            <div style={{ padding: '48px', textAlign: 'center' }}>
              <div className="loading-spinner" style={{ margin: '0 auto 16px' }}/>
              <div style={{ color: 'var(--text-muted)', fontSize: 14 }}>Loading scan history…</div>
            </div>
          )}

          {error && !loading && (
            <div className="error-banner" style={{ margin: 20 }}>
              <div className="error-icon">⚠️</div>
              <div className="error-text"><strong>Failed to load</strong>{error}</div>
            </div>
          )}

          {!loading && !error && filtered.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">🔍</div>
              <div className="empty-title">
                {scans.length === 0 ? 'No scans yet' : 'No results'}
              </div>
              <div className="empty-sub">
                {scans.length === 0
                  ? 'Run your first DPDP compliance scan to see results here.'
                  : 'Try a different search term.'}
              </div>
              {scans.length === 0 && (
                <Link to="/app" className="btn btn-primary">Start Your First Scan</Link>
              )}
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div style={{ overflowX: 'auto' }}>
              <table className="scans-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Repository</th>
                    <th>Status</th>
                    <th>Violations</th>
                    <th>Findings</th>
                    <th>Gaps</th>
                    <th>Scanned</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((s, idx) => (
                    <tr key={s.id}>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12.5, fontWeight: 600 }}>
                        {s.id}
                      </td>
                      <td>
                        <div className="scan-repo">{shortRepo(s.repo_url).split('/')[1] || s.repo_url}</div>
                        <div className="scan-repo-sub">{shortRepo(s.repo_url)}</div>
                      </td>
                      <td><StatusBadge status={s.status} /></td>
                      <td>
                        <span style={{
                          fontWeight: 700, fontSize: 15,
                          color: scoreColor(s.violations_count, s.status),
                        }}>
                          {s.status === 'complete' ? s.violations_count : '—'}
                        </span>
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
                        {s.status === 'complete' ? s.findings_count : '—'}
                      </td>
                      <td style={{ fontWeight: 600, color: s.gaps_count > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
                        {s.status === 'complete' ? s.gaps_count : '—'}
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12.5, whiteSpace: 'nowrap' }}>
                        {formatDate(s.created_at)}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          {s.status === 'complete' && (
                            <>
                              <Link
                                to={`/scan/${s.id}`}
                                className="btn btn-secondary btn-sm"
                              >
                                View
                              </Link>
                              <a
                                href={`${API}/report/${s.id}?format=pdf`}
                                target="_blank"
                                rel="noreferrer"
                                className="btn btn-sm"
                                style={{ background: '#f0fdf4', color: '#16a34a', border: '1px solid #bbf7d0', padding: '5px 10px' }}
                              >
                                PDF
                              </a>
                            </>
                          )}
                          {s.status === 'failed' && (
                            <Link to="/app" className="btn btn-secondary btn-sm">Retry</Link>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
