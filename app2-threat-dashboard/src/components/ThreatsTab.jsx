import { useMemo, useState } from 'react';

const SEV_COLOR = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

export default function ThreatsTab({ analysis, onSelectAlert }) {
  const [sevFilter, setSevFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [ipFilter, setIpFilter] = useState('');

  const alerts = analysis?.alerts || [];
  const findingsById = Object.fromEntries((analysis?.findings || []).map((f) => [f.id, f]));

  const filtered = useMemo(() => {
    return alerts.filter((al) => {
      const finding = findingsById[al.finding_ids?.[0]];
      const type = finding?.type || '';
      const ip = (al.evidence || []).map((e) => e.source_ip || e.ip).join(' ');
      if (sevFilter !== 'all' && al.severity !== sevFilter) return false;
      if (typeFilter !== 'all' && type !== typeFilter) return false;
      if (ipFilter && !ip.includes(ipFilter)) return false;
      return true;
    });
  }, [alerts, findingsById, sevFilter, typeFilter, ipFilter]);

  return (
    <div className="tab-content active">
      <div className="threats-header">
        <h2 className="section-heading">⚠️ Detected Threats & Anomalies</h2>
        <div className="threats-filters">
          <select className="filter-select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select className="filter-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="all">All Types</option>
            <option value="brute_force">Brute Force</option>
            <option value="port_scan">Port Scan</option>
            <option value="sql_injection">SQL Injection</option>
            <option value="xss">XSS</option>
            <option value="directory_traversal">Dir Traversal</option>
            <option value="behavioral_anomaly">Behavioral Anomaly</option>
          </select>
          <input
            className="filter-input"
            placeholder="🔍 Filter by IP..."
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
          />
        </div>
      </div>

      <div className="threats-list">
        {!filtered.length ? (
          <div className="empty-state">No threats match your filters.</div>
        ) : (
          filtered.map((al) => (
            <article
              key={al.id}
              className={`threat-card sev-${al.severity}`}
              style={{ borderLeft: `4px solid ${SEV_COLOR[al.severity] || '#3b82f6'}`, cursor: 'pointer' }}
              onClick={() => onSelectAlert(al)}
            >
              <div className="threat-body" style={{ gridColumn: '1 / -1' }}>
                <div className="threat-head" style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 8, flexWrap: 'wrap' }}>
                  <h3 className="threat-title">
                    {al.known_threat && <span className="known-badge">KNOWN</span>}
                    {al.title}
                  </h3>
                  <span className={`threat-badge badge-${al.severity}`}>
                    {al.severity} ({al.severity_score?.toFixed(1)})
                  </span>
                </div>
                <p className="threat-desc">{al.summary}</p>
                <p style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 6 }}>
                  <strong>Attack stage:</strong> {al.attack_stage}
                  {al.system_id && <> · <strong>System:</strong> {al.system_id}</>}
                  {al.known_threat && <> · <strong>Memory:</strong> seen {al.memory_occurrences}× since {al.memory_first_seen?.slice(0, 10)}</>}
                  {al.active_exploitation && ' · Active exploitation likely'}
                </p>
              </div>
            </article>
          ))
        )}
      </div>
    </div>
  );
}
