function cvssClass(score) {
  if (!score) return 'cvss-none';
  if (score >= 9) return 'cvss-critical';
  if (score >= 7) return 'cvss-high';
  if (score >= 4) return 'cvss-medium';
  return 'cvss-low';
}

export default function CVETab({ analysis }) {
  const cves = analysis?.cves || [];
  const software = analysis?.software_fingerprints || [];

  return (
    <div className="tab-content active">
      <div className="cve-header">
        <h2 className="section-heading">🔗 CVE Correlation Panel</h2>
        <div className="cve-meta">
          <span className="cve-source">Source: NVD (National Vulnerability Database)</span>
          <span className={`cve-status ${cves.length ? 'ok' : 'loading'}`}>
            {cves.length ? `✅ ${cves.length} CVEs correlated` : '⏳ Not loaded'}
          </span>
        </div>
      </div>

      <div className="cve-keywords">
        {software.slice(0, 20).map((s) => (
          <span key={`${s.product}-${s.version}`} className="kw-chip active">
            {s.product}{s.version ? ` ${s.version}` : ''}
          </span>
        ))}
      </div>

      <div className="cve-grid">
        {!cves.length ? (
          <div className="empty-state">No CVEs matched for detected software.</div>
        ) : (
          cves.slice(0, 40).map((c) => (
            <article key={c.cve_id} className={`cve-card ${c.matched ? 'cve-matched' : ''}`}>
              <div className="cve-card-top">
                <span className="cve-id">{c.cve_id}</span>
                <span className={`cve-cvss ${cvssClass(c.cvss_score)}`}>
                  CVSS {c.cvss_score ?? 'N/A'}
                </span>
              </div>
              <p className="cve-desc">{c.description}</p>
              <div className="cve-tags">
                {c.matched_product && <span className="cve-tag">{c.matched_product}</span>}
                {c.matched_version && <span className="cve-tag">v{c.matched_version}</span>}
                {c.epss_score != null && <span className="cve-tag">EPSS {(c.epss_score * 100).toFixed(1)}%</span>}
                {c.actively_exploited && <span className="cve-tag">⚡ Exploited</span>}
              </div>
              <div className="cve-footer">
                <span>{c.cvss_severity || '—'}</span>
                {c.references?.[0] && (
                  <a className="cve-link" href={c.references[0]} target="_blank" rel="noreferrer">
                    Reference ↗
                  </a>
                )}
              </div>
            </article>
          ))
        )}
      </div>
    </div>
  );
}
