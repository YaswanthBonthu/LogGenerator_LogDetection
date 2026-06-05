export default function Header({ filename, logCount, onReload, liveMode, pipelineMode, onRefreshLive }) {
  return (
    <header className="dash-header">
      <div className="dash-brand">
        <span className="brand-icon">🛡</span>
        <span className="brand-name">Threat<span className="brand-accent">Scope</span></span>
        <span className="brand-version">v2.0 — Evaluator</span>
        {liveMode && (
          <span className="brand-version" style={{ color: pipelineMode === 'full' ? '#10b981' : '#f59e0b', borderColor: 'inherit' }}>
            ● LIVE {pipelineMode === 'full' ? '(full)' : '(fast)'}
          </span>
        )}
      </div>
      <div className="dash-meta">
        <span className="meta-item">📄 {filename}</span>
        <span className="meta-item">🕐 {new Date().toLocaleString()}</span>
        <span className="meta-item">📊 {logCount.toLocaleString()} logs</span>
        {liveMode && (
          <button type="button" className="btn btn-primary btn-sm" onClick={onRefreshLive}>
            🔄 Full Analysis (CVE + AI)
          </button>
        )}
        <button type="button" className="btn btn-ghost btn-sm" onClick={onReload}>
          ↩ Disconnect
        </button>
      </div>
    </header>
  );
}
