import { useMemo, useState } from 'react';

export default function LogStreamTab({ logs }) {
  const [sevFilter, setSevFilter] = useState('all');
  const [srcFilter, setSrcFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [shown, setShown] = useState(500);

  const filtered = useMemo(() => {
    return logs.filter((l) => {
      if (sevFilter !== 'all' && l.severity !== sevFilter) return false;
      if (srcFilter !== 'all' && l.source !== srcFilter) return false;
      if (search) {
        const hay = `${l.message} ${l.ip || ''} ${l.category || ''}`.toLowerCase();
        if (!hay.includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [logs, sevFilter, srcFilter, search]);

  const rows = filtered.slice(0, shown);

  return (
    <div className="tab-content active">
      <div className="log-stream-header">
        <h2 className="section-heading">📋 Log Stream</h2>
        <div className="log-controls">
          <select className="filter-select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
            <option value="all">All Severities</option>
            <option value="INFO">INFO</option>
            <option value="WARN">WARN</option>
            <option value="ERROR">ERROR</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <select className="filter-select" value={srcFilter} onChange={(e) => setSrcFilter(e.target.value)}>
            <option value="all">All Sources</option>
            <option value="authentication">Authentication</option>
            <option value="webserver">Web Server</option>
            <option value="application">Application</option>
            <option value="firewall">Firewall</option>
            <option value="network">Network</option>
          </select>
          <input
            className="filter-input"
            placeholder="🔍 Search logs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <span className="log-count">{rows.length.toLocaleString()} entries</span>
        </div>
      </div>

      <div className="log-table-wrap">
        <table className="dash-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Source</th>
              <th>Category</th>
              <th>IP</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((l, i) => (
              <tr key={`${l.line_number}-${i}`}>
                <td>{l.line_number || i + 1}</td>
                <td>{(l.timestamp || '').replace('T', ' ').replace('Z', '')}</td>
                <td><span className={`sev-pill sev-${l.severity}`}>{l.severity || 'INFO'}</span></td>
                <td>{l.source || '-'}</td>
                <td>{l.category || '-'}</td>
                <td>{l.ip || l.source_ip || l.src_ip || '-'}</td>
                <td title={l.message}>{l.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="table-footer">
        {shown < filtered.length && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShown((s) => s + 500)}>
            Load 500 More
          </button>
        )}
        <span className="footer-note">
          {rows.length < filtered.length
            ? `Showing ${rows.length} of ${filtered.length} filtered logs`
            : `Showing all ${filtered.length} filtered logs`}
        </span>
      </div>
    </div>
  );
}
