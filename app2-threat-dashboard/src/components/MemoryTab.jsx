export default function MemoryTab({ analysis }) {
  const systems = analysis?.system_ids || [];
  const known = analysis?.known_threats || [];
  const hits = analysis?.memory_hits || [];
  const stats = analysis?.memory_stats || {};

  return (
    <div className="tab-content active">
      <div className="cve-header">
        <h2 className="section-heading">🧠 System Threat Memory</h2>
        <div className="cve-meta">
          <span className="cve-source">Per-host memory — recognizes previously seen attacks</span>
          <span className="cve-status ok">
            {systems.length} system(s) · {known.length} known threat(s)
          </span>
        </div>
      </div>

      <div className="cards-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 20 }}>
        <div className="summary-card card-cve">
          <div className="card-icon">🖥</div>
          <div className="card-body">
            <div className="card-value">{stats.systems_tracked ?? systems.length}</div>
            <div className="card-label">Systems Tracked</div>
          </div>
        </div>
        <div className="summary-card card-threats">
          <div className="card-icon">🔁</div>
          <div className="card-body">
            <div className="card-value">{stats.recurring_findings ?? 0}</div>
            <div className="card-label">Recurring This Scan</div>
          </div>
        </div>
        <div className="summary-card card-critical">
          <div className="card-icon">🆕</div>
          <div className="card-body">
            <div className="card-value">{stats.new_findings ?? 0}</div>
            <div className="card-label">New Threats</div>
          </div>
        </div>
        <div className="summary-card card-ips">
          <div className="card-icon">📌</div>
          <div className="card-body">
            <div className="card-value">{stats.known_hits_this_scan ?? hits.length}</div>
            <div className="card-label">Known Log Hits</div>
          </div>
        </div>
      </div>

      <div className="cve-keywords">
        {systems.map((s) => (
          <span key={s} className="kw-chip active">🖥 {s}</span>
        ))}
      </div>

      <h3 className="section-heading" style={{ fontSize: 14, marginBottom: 12 }}>Known Threat Signatures</h3>
      <div className="cve-grid">
        {!known.length ? (
          <div className="empty-state">
            No threats in memory yet. Upload logs once to teach the system; re-upload to see recognition.
          </div>
        ) : (
          known.map((t) => (
            <article key={t.id} className="cve-card cve-matched">
              <div className="cve-card-top">
                <span className="cve-id">{t.title}</span>
                <span className={`cve-cvss badge-${t.severity}`}>{t.severity}</span>
              </div>
              <p className="cve-desc">{t.sample_message || t.threat_type}</p>
              <div className="cve-tags">
                <span className="cve-tag">{t.system_id}</span>
                <span className="cve-tag">{t.threat_type}</span>
                {t.source_ip && <span className="cve-tag">{t.source_ip}</span>}
                <span className="cve-tag">×{t.occurrence_count}</span>
              </div>
              <div className="cve-footer">
                <span>First: {t.first_seen?.slice(0, 10)} · Last: {t.last_seen?.slice(0, 10)}</span>
              </div>
            </article>
          ))
        )}
      </div>

      {hits.length > 0 && (
        <>
          <h3 className="section-heading" style={{ fontSize: 14, margin: '20px 0 12px' }}>
            Recognized Malicious Log Lines (this scan)
          </h3>
          <div className="related-logs-wrap" style={{ maxHeight: 300 }}>
            {hits.map((h) => (
              <div key={`${h.line_number}-${h.fingerprint}`} className="related-log-line">
                <span className="known-badge">KNOWN</span>
                <code>#{h.line_number}</code> [{h.system_id}] {h.threat_type} — {h.message}
                <span style={{ color: 'var(--text-3)', marginLeft: 8 }}>
                  (seen {h.occurrence_count}× since {h.first_seen?.slice(0, 10)})
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
