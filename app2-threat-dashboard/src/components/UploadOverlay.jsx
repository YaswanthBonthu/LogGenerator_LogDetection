import { useRef, useState } from 'react';

export default function UploadOverlay({ onFile, onLiveConnect, loading }) {
  const inputRef = useRef(null);
  const [drag, setDrag] = useState(false);

  const pick = (file) => {
    if (file) onFile(file);
  };

  return (
    <div className="upload-overlay">
      <div className="upload-box" style={{ maxWidth: 520 }}>
        <div className="upload-glow" />
        <div className="upload-icon">🛡</div>
        <h1 className="upload-title">ThreatScope</h1>
        <p className="upload-sub">Security Log Evaluator — separate from log sources</p>

        <button
          type="button"
          className="btn btn-primary upload-btn"
          style={{ width: '100%', marginBottom: 16, justifyContent: 'center' }}
          disabled={loading}
          onClick={onLiveConnect}
        >
          {loading ? <><span className="spinner" /> Connecting...</> : '📡 Connect Live Feed (SecureCorp)'}
        </button>
        <p style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 16 }}>
          Pulls continuous logs from dummy website on port 8100 → full pipeline
        </p>

        <div className="upload-or">or upload a file</div>

        <div
          className={`drop-zone ${drag ? 'drag-over' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            pick(e.dataTransfer.files?.[0]);
          }}
          onClick={() => inputRef.current?.click()}
        >
          <span className="drop-icon">📂</span>
          <span className="drop-text">{loading ? 'Analyzing...' : 'Drop log file here'}</span>
          <span className="drop-formats">JSON · NDJSON · CSV · Syslog</span>
        </div>

        <label className="btn btn-ghost upload-btn" htmlFor="file-input" style={{ marginTop: 12 }}>
          📁 Browse File
        </label>
        <input
          ref={inputRef}
          id="file-input"
          type="file"
          accept=".json,.csv,.log,.txt"
          style={{ display: 'none' }}
          onChange={(e) => pick(e.target.files?.[0])}
        />
      </div>
    </div>
  );
}
