import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import Layout from './Layout';
import ResultsDashboard from './components/ResultsDashboard';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function ScanDetail() {
  const { id }    = useParams();
  const scanId    = parseInt(id, 10);

  const [scan,      setScan]      = useState(null);
  const [result,    setResult]    = useState(null);
  const [aiSummary, setAiSummary] = useState(null);
  const [aiLoading, setAiLoad]    = useState(false);
  const [loading,   setLoad]      = useState(true);
  const [error,     setError]     = useState('');

  useEffect(() => {
    if (!scanId) return;
    setLoad(true);
    Promise.all([
      fetch(`${API}/scans`).then(r => r.json()),
      fetch(`${API}/scans/${scanId}/result`).then(r => r.json()),
    ])
      .then(([scans, res]) => {
        const found = scans.find(s => s.id === scanId);
        if (!found) throw new Error('Scan not found');
        setScan(found);
        setResult(res);
        setLoad(false);
        // Fetch AI summary
        setAiLoad(true);
        return fetch(`${API}/scans/${scanId}/summary`);
      })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setAiSummary(d.summary); })
      .catch(e => { setError(e.message); setLoad(false); })
      .finally(() => setAiLoad(false));
  }, [scanId]);

  function shortRepo(url) {
    return url?.replace('https://github.com/', '') || url;
  }

  function formatDate(iso) {
    return new Date(iso).toLocaleString('en-IN', {
      day: 'numeric', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  }

  if (loading) {
    return (
      <Layout>
        <div className="topbar">
          <div className="topbar-breadcrumb">
            <Link to="/history" style={{ color: 'var(--text-muted)' }}>History</Link>
            <span>/</span>
            <span>Scan #{id}</span>
          </div>
        </div>
        <div className="page-content" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
          <div style={{ textAlign: 'center' }}>
            <div className="loading-spinner" style={{ margin: '0 auto 16px' }}/>
            <div style={{ color: 'var(--text-muted)', fontSize: 14 }}>Loading scan details…</div>
          </div>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="topbar">
          <div className="topbar-breadcrumb">
            <Link to="/history" style={{ color: 'var(--text-muted)' }}>History</Link>
            <span>/</span>
            <span>Scan #{id}</span>
          </div>
        </div>
        <div className="page-content">
          <div className="error-banner">
            <div className="error-icon">⚠️</div>
            <div className="error-text">
              <strong>Failed to load scan</strong>
              {error}
            </div>
          </div>
          <Link to="/history" className="btn btn-secondary">← Back to History</Link>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="topbar">
        <div className="topbar-breadcrumb">
          <Link to="/history" style={{ color: 'var(--indigo-600)', fontWeight: 600 }}>History</Link>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
          <span style={{ color: 'var(--text-muted)' }}>Scan #{id}</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
          <span>{shortRepo(scan?.repo_url)}</span>
        </div>
        <div className="topbar-right">
          <a
            href={`${API}/report/${scanId}`}
            target="_blank"
            rel="noreferrer"
            className="btn btn-secondary btn-sm"
          >
            📄 HTML Report
          </a>
          <a
            href={`${API}/report/${scanId}?format=pdf`}
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary btn-sm"
          >
            ⬇ PDF Report
          </a>
        </div>
      </div>

      <div className="page-content">
        {/* Scan meta bar */}
        {scan && (
          <div className="card card-pad mb-24" style={{ display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 3 }}>Repository</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'SF Mono, Consolas, monospace' }}>
                {shortRepo(scan.repo_url)}
              </div>
            </div>
            <div style={{ width: 1, height: 36, background: 'var(--border)' }}/>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 3 }}>Scanned</div>
              <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-secondary)' }}>{formatDate(scan.created_at)}</div>
            </div>
            <div style={{ width: 1, height: 36, background: 'var(--border)' }}/>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 3 }}>Status</div>
              <span className={`status-pill ${scan.status}`}>{scan.status}</span>
            </div>
            <div style={{ marginLeft: 'auto' }}>
              <Link to="/history" className="btn btn-ghost btn-sm">← All Scans</Link>
            </div>
          </div>
        )}

        <ResultsDashboard
          scanId={scanId}
          result={result}
          violations={result?.violations || []}
          findings={result?.sample_findings || []}
          compliance={result?.compliance}
          aiSummary={aiSummary}
          aiLoading={aiLoading}
        />
      </div>
    </Layout>
  );
}
