const API_BASE = import.meta.env.VITE_API_BASE || '/api';
export const LOG_SOURCE_URL = import.meta.env.VITE_LOG_SOURCE || 'http://127.0.0.1:8100/logs/recent';

export async function checkHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Backend unavailable');
  return res.json();
}

export async function checkLogSource(url = LOG_SOURCE_URL) {
  const base = url.replace(/\/logs\/recent$/, '');
  const res = await fetch(`${base}/health`);
  if (!res.ok) throw new Error('Log source offline');
  return res.json();
}

export async function analyzeFile(file, mode = 'full') {
  const fd = new FormData();
  fd.append('file', file);
  fd.append('hostname', 'securecorp');
  fd.append('environment', 'production');

  const res = await fetch(`${API_BASE}/analyze/upload`, { method: 'POST', body: fd });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(txt || 'Analysis failed');
  }
  return res.json();
}

export async function analyzeLive({
  sourceUrl = LOG_SOURCE_URL,
  limit = 400,
  sinceId = 0,
  mode = 'fast',
} = {}) {
  const params = new URLSearchParams({
    source_url: sourceUrl,
    limit: String(limit),
    since_id: String(sinceId),
    hostname: 'securecorp',
    environment: 'production',
    mode,
  });
  const res = await fetch(`${API_BASE}/analyze/live?${params}`);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(txt || 'Live analysis failed');
  }
  return res.json();
}

export async function fetchRawLogs(url = LOG_SOURCE_URL, limit = 400) {
  const res = await fetch(`${url}?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch logs');
  const data = await res.json();
  return data.logs || [];
}

export async function parseFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch(`${API_BASE}/parse`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error('Parse failed');
  return res.json();
}
