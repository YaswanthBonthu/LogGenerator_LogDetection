import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
);

const chartOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#94a3b8', boxWidth: 12 } } },
  scales: {
    x: { ticks: { color: '#64748b', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.04)' } },
    y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.04)' } },
  },
};

function riskColor(score) {
  const pct = Math.min(100, (score || 0) * 10);
  if (pct >= 80) return '#ef4444';
  if (pct >= 60) return '#f97316';
  return '#10b981';
}

export default function OverviewTab({ analysis }) {
  const alerts = analysis?.alerts || [];
  const stats = analysis?.stats || {};
  const timeline = analysis?.timeline || [];
  const risk = analysis?.risk_score || 0;

  const threatIps = new Set(
    alerts.flatMap((a) => (a.evidence || []).map((e) => e.source_ip).filter(Boolean)),
  );

  const findingTypes = stats.finding_types || {};
  const severities = stats.severities || {};
  const sources = stats.sources || {};

  const timelineLabels = [...new Set(timeline.map((t) => t.time))].sort();
  const threatSeries = timelineLabels.map(
    (t) => timeline.find((p) => p.time === t && p.series === 'threat')?.count || 0,
  );
  const normalSeries = timelineLabels.map(
    (t) => timeline.find((p) => p.time === t && p.series === 'normal')?.count || 0,
  );

  const topIps = {};
  (analysis?.findings || []).forEach((f) => {
    if (f.source_ip) topIps[f.source_ip] = (topIps[f.source_ip] || 0) + (f.event_count || 1);
  });
  const ipSorted = Object.entries(topIps).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <div className="tab-content active">
      <div className="cards-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))' }}>
        <div className="summary-card card-total">
          <div className="card-icon">📊</div>
          <div className="card-body">
            <div className="card-value">{(analysis?.total_logs || 0).toLocaleString()}</div>
            <div className="card-label">Total Logs</div>
          </div>
        </div>
        <div className="summary-card card-threats">
          <div className="card-icon">⚠️</div>
          <div className="card-body">
            <div className="card-value">{(analysis?.findings || []).length}</div>
            <div className="card-label">Threats Detected</div>
          </div>
        </div>
        <div className="summary-card card-critical">
          <div className="card-icon">🚨</div>
          <div className="card-body">
            <div className="card-value">{alerts.filter((x) => x.severity === 'CRITICAL').length}</div>
            <div className="card-label">Critical Alerts</div>
          </div>
        </div>
        <div className="summary-card card-ips">
          <div className="card-icon">🌐</div>
          <div className="card-body">
            <div className="card-value">{threatIps.size}</div>
            <div className="card-label">Unique Source IPs</div>
          </div>
        </div>
        <div className="summary-card card-cve">
          <div className="card-icon">🔗</div>
          <div className="card-body">
            <div className="card-value">{(analysis?.cves || []).length}</div>
            <div className="card-label">CVEs Matched</div>
          </div>
        </div>
        <div className="summary-card card-score">
          <div className="card-icon">🧠</div>
          <div className="card-body">
            <div className="card-value">{analysis?.memory_stats?.recurring_findings ?? 0}</div>
            <div className="card-label">Known (Recurring)</div>
          </div>
        </div>
        <div className="summary-card card-score">
          <div className="card-icon">🎯</div>
          <div className="card-body">
            <div className="card-value">{Number(risk).toFixed(1)}</div>
            <div className="card-label">Risk Score</div>
          </div>
          <div className="risk-meter">
            <div
              className="risk-fill"
              style={{ width: `${Math.min(100, risk * 10)}%`, background: riskColor(risk) }}
            />
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-card chart-wide">
          <div className="chart-header">
            <h3 className="chart-title">🕐 Threat Timeline</h3>
          </div>
          <div className="chart-wrap">
            <Line
              data={{
                labels: timelineLabels,
                datasets: [
                  { label: 'Threat', data: threatSeries, borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.3 },
                  { label: 'Normal', data: normalSeries, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.05)', fill: true, tension: 0.3 },
                ],
              }}
              options={chartOpts}
            />
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-header">
            <h3 className="chart-title">💀 Attack Distribution</h3>
          </div>
          <div className="chart-wrap">
            <Doughnut
              data={{
                labels: Object.keys(findingTypes),
                datasets: [{
                  data: Object.values(findingTypes),
                  backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#7c3aed', '#3b82f6', '#10b981'],
                }],
              }}
              options={{ ...chartOpts, scales: undefined }}
            />
          </div>
        </div>
      </div>

      <div className="charts-row">
        <div className="chart-card">
          <div className="chart-header">
            <h3 className="chart-title">🎚 Severity Breakdown</h3>
          </div>
          <div className="chart-wrap">
            <Bar
              data={{
                labels: Object.keys(severities),
                datasets: [{ label: 'Logs', data: Object.values(severities), backgroundColor: '#7c3aed' }],
              }}
              options={chartOpts}
            />
          </div>
        </div>
        <div className="chart-card">
          <div className="chart-header">
            <h3 className="chart-title">🗄 Log Sources</h3>
          </div>
          <div className="chart-wrap">
            <Bar
              data={{
                labels: Object.keys(sources),
                datasets: [{ label: 'Logs', data: Object.values(sources), backgroundColor: '#00d4ff' }],
              }}
              options={chartOpts}
            />
          </div>
        </div>
        <div className="chart-card chart-wide">
          <div className="chart-header">
            <h3 className="chart-title">🌐 Top Attacking IPs</h3>
          </div>
          <div className="chart-wrap">
            <Bar
              data={{
                labels: ipSorted.map(([ip]) => ip),
                datasets: [{ label: 'Events', data: ipSorted.map(([, c]) => c), backgroundColor: '#f97316' }],
              }}
              options={{ ...chartOpts, indexAxis: 'y' }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
