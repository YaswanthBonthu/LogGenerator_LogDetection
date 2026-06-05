import { useCallback, useEffect, useRef, useState } from 'react';
import {
  analyzeFile, analyzeLive, checkHealth, checkLogSource,
  fetchRawLogs, parseFile,
} from './api';
import UploadOverlay from './components/UploadOverlay';
import Header from './components/Header';
import TabNav from './components/TabNav';
import OverviewTab from './components/OverviewTab';
import ThreatsTab from './components/ThreatsTab';
import LogStreamTab from './components/LogStreamTab';
import CVETab from './components/CVETab';
import MemoryTab from './components/MemoryTab';
import ThreatModal from './components/ThreatModal';
import Toast from './components/Toast';

const LIVE_INTERVAL_MS = 20000;

function mapRawLogs(raw) {
  const eventMap = {
    authentication: 'authentication',
    http_request: 'webserver',
    connection_attempt: 'firewall',
    log_entry: 'application',
    network_flow: 'network',
  };
  return raw.map((l, i) => ({
    timestamp: l.timestamp,
    source: eventMap[l.event] || l.service || 'unknown',
    severity: l.severity === 'WARNING' ? 'WARN' : (l.severity || 'INFO'),
    category: l.attack_pattern || (l.status === 'failed' ? 'failed_auth' : 'normal'),
    ip: l.source_ip,
    message: l.message || [l.event, l.user, l.path, l.method].filter(Boolean).join(' '),
    line_number: l.id || i + 1,
    details: l,
  }));
}

export default function App() {
  const [analysis, setAnalysis] = useState(null);
  const [logs, setLogs] = useState([]);
  const [filename, setFilename] = useState('');
  const [tab, setTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState('');
  const [liveMode, setLiveMode] = useState(false);
  const [pipelineMode, setPipelineMode] = useState('fast');
  const [toast, setToast] = useState({ message: '', type: 'ok' });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const liveTimer = useRef(null);
  const fullAnalysisDone = useRef(false);

  const showToast = useCallback((message, type = 'ok') => {
    setToast({ message, type });
    setTimeout(() => setToast({ message: '', type: 'ok' }), 2600);
  }, []);

  const applyResult = useCallback(async (result, label, isLive = false) => {
    if (isLive) {
      const raw = await fetchRawLogs(undefined, 400);
      setLogs(mapRawLogs(raw));
    } else {
      const parsed = (result.anomalies || []).flatMap((x) => x.related_logs || []);
      setLogs(parsed);
    }
    setAnalysis(result);
    setFilename(label);
    setPipelineMode(result.stats?.pipeline_mode || 'fast');
  }, []);

  const runLiveAnalysis = useCallback(async ({ mode = 'fast', silent = false, showStage = false } = {}) => {
    if (!silent) setLoading(true);
    if (showStage) setLoadingStage(mode === 'fast' ? 'Quick scan (rules)...' : 'Full pipeline (CVE + AI)...');
    try {
      const result = await analyzeLive({ limit: mode === 'fast' ? 400 : 1200, mode });
      await applyResult(result, mode === 'fast' ? '🔴 Live — SecureCorp' : '🔴 Live — Full Analysis', true);
      if (!silent) {
        showToast(mode === 'fast' ? 'Quick analysis ready.' : 'Full analysis complete (CVE + reasoning).');
      }
    } catch (err) {
      if (!silent) showToast(`Live feed error: ${err.message}`, 'error');
    } finally {
      if (!silent) setLoading(false);
      if (showStage) setLoadingStage('');
    }
  }, [applyResult, showToast]);

  useEffect(() => {
    checkHealth().catch(() => showToast('Evaluator API offline — start port 8000', 'error'));
  }, [showToast]);

  useEffect(() => {
    if (!liveMode) {
      if (liveTimer.current) clearInterval(liveTimer.current);
      fullAnalysisDone.current = false;
      return undefined;
    }

    (async () => {
      setLoadingStage('Connecting & quick scan...');
      await runLiveAnalysis({ mode: 'fast', silent: true, showStage: true });
      setLoadingStage('');
      setTab('overview');

      if (!fullAnalysisDone.current) {
        fullAnalysisDone.current = true;
        runLiveAnalysis({ mode: 'full', silent: true });
      }
    })();

    liveTimer.current = setInterval(() => runLiveAnalysis({ mode: 'fast', silent: true }), LIVE_INTERVAL_MS);
    return () => clearInterval(liveTimer.current);
  }, [liveMode, runLiveAnalysis]);

  const handleFile = async (file) => {
    if (!file) return;
    setLiveMode(false);
    setLoading(true);
    setLoadingStage('Analyzing file...');
    showToast('Analyzing logs...', 'warn');
    try {
      const result = await analyzeFile(file);
      let parsed = (result.anomalies || []).flatMap((x) => x.related_logs || []);
      if (!parsed.length) parsed = await parseFile(file);
      setAnalysis(result);
      setLogs(parsed);
      setFilename(file.name);
      setTab('overview');
      showToast('Analysis completed.');
    } catch (err) {
      showToast(`Error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
      setLoadingStage('');
    }
  };

  const connectLive = async () => {
    setLoading(true);
    setLoadingStage('Checking log source...');
    try {
      await checkLogSource();
      setLiveMode(true);
      showToast('Connected — loading quick results first', 'ok');
    } catch {
      showToast('SecureCorp offline — start dummy website port 8100', 'error');
      setLiveMode(false);
    } finally {
      setLoading(false);
    }
  };

  const reload = () => {
    setLiveMode(false);
    setAnalysis(null);
    setLogs([]);
    setFilename('');
    setTab('overview');
    setSelectedAlert(null);
    setLoadingStage('');
  };

  if (!analysis && !liveMode) {
    return (
      <>
        <UploadOverlay onFile={handleFile} onLiveConnect={connectLive} loading={loading} />
        <Toast message={toast.message} type={toast.type} />
      </>
    );
  }

  if (liveMode && !analysis) {
    return (
      <>
        <div className="upload-overlay">
          <div className="upload-box">
            <span className="spinner" />
            <p style={{ marginTop: 16 }}>{loadingStage || 'Running quick pipeline...'}</p>
            <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
              Fast mode: rules only · Full CVE + AI loads in background
            </p>
          </div>
        </div>
        <Toast message={toast.message} type={toast.type} />
      </>
    );
  }

  return (
    <div className="dashboard">
      <Header
        filename={filename}
        logCount={logs.length || analysis?.total_logs || 0}
        onReload={reload}
        liveMode={liveMode}
        pipelineMode={pipelineMode}
        onRefreshLive={() => runLiveAnalysis({ mode: 'full', showStage: true })}
      />
      <TabNav active={tab} onChange={setTab} />

      {tab === 'overview' && <OverviewTab analysis={analysis} />}
      {tab === 'threats' && <ThreatsTab analysis={analysis} onSelectAlert={setSelectedAlert} />}
      {tab === 'memory' && <MemoryTab analysis={analysis} />}
      {tab === 'logs' && <LogStreamTab logs={logs} />}
      {tab === 'cve' && <CVETab analysis={analysis} />}

      <ThreatModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      <Toast message={toast.message} type={toast.type} />
    </div>
  );
}
