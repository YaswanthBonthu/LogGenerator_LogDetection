const $ = (id) => document.getElementById(id);
const API = location.origin;
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function jget(url) { const r = await fetch(url); return r.json(); }

function bars(obj, container) {
  const entries = Object.entries(obj || {});
  const max = Math.max(1, ...entries.map(([, v]) => v));
  container.innerHTML = entries.length
    ? entries.map(([k, v]) => `
      <div class="bar"><span class="lab" title="${esc(k)}">${esc(k)}</span>
        <span class="track"><span class="fill" style="width:${(v / max) * 100}%"></span></span>
        <span class="v">${v.toLocaleString()}</span></div>`).join("")
    : '<span class="muted">—</span>';
}

function ipBars(list, container) {
  const max = Math.max(1, ...list.map((x) => x.events));
  container.innerHTML = list.length
    ? list.map((x) => `
      <div class="bar"><span class="lab" title="${esc(x.ip)}">${esc(x.ip)}</span>
        <span class="track"><span class="fill" style="width:${(x.events / max) * 100}%"></span></span>
        <span class="v">${x.events.toLocaleString()}</span></div>`).join("")
    : '<span class="muted">—</span>';
}

function kpis(d) {
  const sev = d.alerts_by_severity || {};
  const cards = [
    ["Events ingested", d.total_events.toLocaleString()],
    ["Total alerts", d.total_alerts],
    ["Critical", sev.CRITICAL || 0],
    ["High", sev.HIGH || 0],
    ["AI enrichment", d.ai && d.ai.ai_enabled ? `on (${d.ai.model})` : "off (fallback)"],
  ];
  $("kpis").innerHTML = cards.map(([l, n]) =>
    `<div class="kpi"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
}

function renderAlert(a) {
  const cve = a.cve
    ? `<span class="cve">${esc(a.cve.id)} · CVSS ${a.cve.cvss} · ${esc(a.cve.source || "")}</span>` : "";
  const aiTag = a.ai ? '<span class="pill">GPT-4o</span>' : '<span class="pill">rule-based</span>';
  return `<div class="alert ${esc(a.severity)}">
    <div class="top">
      <span class="sev ${esc(a.severity)}">${esc(a.severity)}</span>
      <span class="title">${esc(a.title)}</span>
      ${cve} ${aiTag}
    </div>
    <div class="meta">events: ${a.count} · first: ${esc((a.first_ts || "").slice(0, 19))} · last: ${esc((a.last_ts || "").slice(0, 19))}
      ${a.software ? "· " + esc(a.software) + " " + esc(a.version) : ""}</div>
    <div class="aibox"><span class="lab">Explanation</span><div>${esc(a.ai_explanation)}</div></div>
    <div class="aibox"><span class="lab">Recommended action</span><div class="rem">${esc(a.ai_remediation || a.recommended_action)}</div></div>
  </div>`;
}

async function refresh() {
  try {
    const ins = await jget(`${API}/api/insights`);
    kpis(ins);
    bars(ins.events_by_source, $("bySource"));
    bars(ins.alerts_by_severity, $("bySev"));
    bars(ins.alerts_by_threat, $("byThreat"));
    ipBars(ins.top_source_ips || [], $("topIps"));
    const badge = $("monBadge");
    badge.textContent = `monitor: ${ins.monitor_running ? "live" : "stopped"} · cursor ${ins.cursor}`;
    badge.className = "badge " + (ins.monitor_running ? "on" : "off");

    const { alerts } = await jget(`${API}/api/alerts`);
    $("alertCount").textContent = alerts.length ? `(${alerts.length})` : "";
    if (alerts.length) {
      $("alerts").classList.remove("muted");
      $("alerts").innerHTML = alerts.map(renderAlert).join("");
    }
  } catch (e) { /* backend starting */ }
}
setInterval(refresh, 2000);
refresh();
