const TABS = [
  { id: 'overview', label: '📊 Overview' },
  { id: 'threats', label: '⚠️ Threats' },
  { id: 'memory', label: '🧠 Memory' },
  { id: 'logs', label: '📋 Log Stream' },
  { id: 'cve', label: '🔗 CVE Correlation' },
];

export default function TabNav({ active, onChange }) {
  return (
    <nav className="tab-nav">
      {TABS.map((t) => (
        <button
          key={t.id}
          type="button"
          className={`tab-btn ${active === t.id ? 'active' : ''}`}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </nav>
  );
}
