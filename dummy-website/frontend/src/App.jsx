import { useCallback, useEffect, useState } from 'react';

const EVALUATOR_URL = 'http://localhost:5173';

export default function App() {
  const [user, setUser] = useState(null);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ count: 0, latest_id: 0 });
  const [services, setServices] = useState(null);
  const [msg, setMsg] = useState('');

  const refresh = useCallback(async () => {
    try {
      const [h, r] = await Promise.all([
        fetch('/health').then((x) => x.json()),
        fetch('/logs/recent?limit=40').then((x) => x.json()),
      ]);
      setStats({ count: h.logs_buffered, latest_id: h.latest_id });
      setLogs(r.logs || []);
    } catch {
      setMsg('Log generator backend offline — start port 8100');
    }
  }, []);

  useEffect(() => {
    fetch('/api/services').then((r) => r.json()).then(setServices).catch(() => {});
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const login = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: fd.get('user'), password: fd.get('pass') }),
    });
    const data = await res.json();
    if (data.success) {
      setUser(fd.get('user'));
      setMsg('Logged in — auth logs recorded');
    } else {
      setMsg('Login failed — security log generated');
    }
    refresh();
  };

  const hitApi = async () => {
    await fetch('/api/products');
    setMsg('API request served — web + app logs generated');
    refresh();
  };

  if (!user) {
    return (
      <div className="shell">
        <div className="top">
          <div className="brand">Secure<span>Corp</span></div>
          <span className="badge">● Log generator running</span>
        </div>
        <form className="login-form card" onSubmit={login}>
          <h2>Employee Portal Login</h2>
          <p style={{ marginBottom: 8 }}>Simulated auth — generates real security logs</p>
          <input name="user" placeholder="Username" defaultValue="alice" required />
          <input name="pass" type="password" placeholder="Password" defaultValue="demo123" required />
          <button type="submit">Sign In</button>
          <p style={{ fontSize: 12, color: 'var(--muted)' }}>{msg}</p>
        </form>
      </div>
    );
  }

  return (
    <div className="shell">
      <div className="top">
        <div className="brand">Secure<span>Corp</span> Portal</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <span className="badge">● {stats.count.toLocaleString()} logs buffered</span>
          <button className="secondary" type="button" onClick={() => setUser(null)}>Logout</button>
        </div>
      </div>

      <div className="stats">
        <div className="stat"><b>{stats.count}</b><span>Total logs</span></div>
        <div className="stat"><b>{stats.latest_id}</b><span>Latest ID</span></div>
        <div className="stat"><b>5</b><span>Log sources</span></div>
      </div>

      <div className="grid">
        <div className="card">
          <h2>🖥 Simulated Infrastructure</h2>
          {services && Object.entries(services).filter(([k]) => !k.includes('hint') && k !== 'log_feed').map(([k, v]) => (
            <div key={k} className="svc">
              <span className="dot" />
              <strong style={{ textTransform: 'capitalize', minWidth: 110 }}>{k}</strong>
              <span style={{ color: 'var(--muted)' }}>{v.status || 'online'} — {v.host || v.hosts?.join(', ')}</span>
            </div>
          ))}
          <p style={{ marginTop: 14 }}>
            Background generator continuously emits auth, web, app, firewall & network logs
            (including attack patterns).
          </p>
          <button type="button" onClick={hitApi} style={{ marginTop: 12 }}>Trigger API Request</button>
          {msg && <p style={{ marginTop: 8, fontSize: 12 }}>{msg}</p>}
        </div>

        <div className="card">
          <h2>📡 ThreatScope Evaluator</h2>
          <p>
            Logs are exposed at <code>/logs/recent</code> for the separate evaluator app.
          </p>
          <p style={{ marginTop: 10 }}>
            <a href={EVALUATOR_URL} target="_blank" rel="noreferrer">Open ThreatScope Dashboard →</a>
          </p>
          <p style={{ marginTop: 10, fontSize: 12 }}>
            Evaluator pulls via <code>GET /analyze/live</code> on port 8000
          </p>
        </div>

        <div className="card" style={{ gridColumn: '1 / -1' }}>
          <h2>📋 Live Log Tail (internal)</h2>
          <div className="log-box">
            {logs.map((l) => (
              <div key={l.id} className={`log-line ${l.severity === 'CRITICAL' ? 'critical' : ''}`}>
                #{l.id} [{l.host}] {l.event} {l.attack_pattern ? `⚠ ${l.attack_pattern}` : ''} — {l.message || l.path || l.user || ''}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
