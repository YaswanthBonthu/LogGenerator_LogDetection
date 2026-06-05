export default function ThreatModal({ alert, onClose }) {
  if (!alert) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <h2 className="modal-title">
          {alert.known_threat && <span className="known-badge">KNOWN</span>}
          {alert.title}
        </h2>

        {alert.known_threat && (
          <div className="modal-section" style={{ background: 'rgba(124,58,237,0.1)', padding: 12, borderRadius: 8, border: '1px solid rgba(124,58,237,0.3)' }}>
            <strong>System memory match</strong> — This threat was seen before on{' '}
            <code>{alert.system_id}</code> ({alert.memory_occurrences} occurrence(s) since {alert.memory_first_seen?.slice(0, 10)}).
          </div>
        )}

        <div className="modal-section">
          <div className="modal-section-title">Summary</div>
          <p>{alert.summary}</p>
        </div>

        <div className="modal-section">
          <div className="modal-section-title">Technical Detail</div>
          <p style={{ color: 'var(--text-2)', fontSize: 13 }}>{alert.technical_detail}</p>
        </div>

        <div className="modal-section">
          <div className="modal-section-title">Evidence (line-linked)</div>
          <div className="related-logs-wrap">
            {(alert.evidence || []).map((e) => (
              <div key={e.line_number} className="related-log-line">
                <code>#{e.line_number}</code> [{e.source}] {e.message}
              </div>
            ))}
          </div>
        </div>

        <div className="modal-section">
          <div className="modal-section-title">Ordered Remediation</div>
          <ol style={{ paddingLeft: 20, color: 'var(--text-2)', fontSize: 13 }}>
            {(alert.remediation || []).map((r) => (
              <li key={r.priority} style={{ marginBottom: 8 }}>
                <strong>{r.priority}.</strong> {r.action}
                <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{r.rationale}</div>
              </li>
            ))}
          </ol>
        </div>

        {(alert.related_cves || []).length > 0 && (
          <div className="modal-section">
            <div className="modal-section-title">Related CVEs</div>
            <div className="cve-correlations">
              {alert.related_cves.map((c) => (
                <div key={c.cve_id} className="cve-mini-card">
                  <div className="cve-mini-id">{c.cve_id} — CVSS {c.cvss_score ?? 'N/A'}</div>
                  <div className="cve-mini-desc">{c.description?.slice(0, 200)}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
