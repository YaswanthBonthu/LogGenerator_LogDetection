/* ═══════════════════════════════════════════════════════════
   CyberLog Forge — app.js
   Realistic multi-source log generator
═══════════════════════════════════════════════════════════ */

'use strict';

// ─── Globals ────────────────────────────────────────────────
let generatedLogs = [];

// ─── Data Tables ────────────────────────────────────────────
const USERS = ['alice','bob','charlie','dave','eve','frank','grace','henry','ivan','julia',
               'karen','liam','mia','noah','olivia','peter','quinn','rachel','sam','tara'];
const SERVICES = ['sshd','apache2','nginx','mysqld','postgresql','ftpd','smtpd','httpd','auditd','cron'];
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
  'python-requests/2.31.0',
  'curl/7.88.1',
  'Nikto/2.1.6',
  'sqlmap/1.7.11',
  'Nmap Scripting Engine',
  'Go-http-client/1.1',
  'Mozilla/5.0 (compatible; Googlebot/2.1)'
];
const PATHS = ['/','/','/index.html','/login','/dashboard','/api/v1/users','/api/v1/data',
               '/static/js/main.js','/favicon.ico','/health','/metrics','/admin','/api/v1/products'];
const ATTACK_PATHS = {
  sqli: ["/?id=1' OR '1'='1","/?q=1 UNION SELECT null,null,null--","/api/users?id=1;DROP TABLE users--",
         "/login?user=admin'--&pass=x","/?search=1' AND 1=SLEEP(5)--"],
  xss:  ["/?q=<script>alert(1)</script>","/?name=<img src=x onerror=alert(1)>",
         "/search?q=<svg onload=alert(document.cookie)>","/?redirect=javascript:alert(1)"],
  traversal: ["/../../../etc/passwd","/..%2F..%2F..%2Fetc%2Fshadow","/static/../../../etc/hosts",
              "/download?file=../../../windows/win.ini","/img/../../../../etc/passwd"],
  c2_domains: ['update-check.net','telemetry-cdn.com','cdn-assets.io','api-service.xyz','data-sync.cc']
};
const HTTP_METHODS = ['GET','GET','GET','GET','POST','POST','PUT','DELETE','PATCH'];
const HTTP_CODES_NORMAL = [200,200,200,200,200,204,301,304,404];
const HTTP_CODES_ATTACK = [200,400,403,404,500,503];
const FIREWALL_ACTIONS = ['ALLOW','ALLOW','ALLOW','ALLOW','DENY','DROP'];
const PROTOCOLS = ['TCP','UDP','ICMP','TCP','TCP'];
const PORTS_COMMON = [80,443,22,21,25,3306,5432,6379,8080,8443,3389,53];
const PORTS_SCAN   = [21,22,23,25,53,80,110,111,135,139,143,443,445,
                      993,995,1723,3306,3389,5900,8080,8443,8888];
const APP_EVENTS = ['User session created','DB query executed','Cache hit','Cache miss',
                    'Email sent','File uploaded','Report generated','API rate limit hit',
                    'Session expired','Background job completed','Config reloaded'];
const PRIV_CMDS = ['sudo su -','sudo bash','chmod 4755 /bin/bash','usermod -aG sudo attacker',
                   'visudo','crontab -e','pkexec bash','sudo -s'];

function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randFloat(min, max) { return (Math.random() * (max - min) + min).toFixed(2); }
function randIP(prefix) {
  if (prefix) return `${prefix}.${randInt(1,254)}.${randInt(1,254)}`;
  const prefixes = ['10.0','192.168','172.16','203.0.113','198.51.100','185.220','45.33','104.21','185.181','91.134'];
  const p = rand(prefixes);
  return `${p}.${randInt(1,254)}.${randInt(1,254)}`;
}
function randInternalIP() { return `10.0.${randInt(0,10)}.${randInt(1,254)}`; }
function fmtISO(d) { return d.toISOString(); }

// ─── Log Generators ─────────────────────────────────────────

function genAuthLog(ts, severity, attackType, attackIntensity) {
  const user = rand(USERS);
  const ip   = randIP();
  const svc  = rand(['sshd','login','sudo','pam_unix','su']);
  let msg, category = 'normal', details = {};

  if (attackType === 'brute_force') {
    msg = `Failed password for ${user} from ${ip} port ${randInt(1024,65535)} ssh2`;
    category = 'brute_force';
    severity = randInt(1,10) > 3 ? 'ERROR' : 'CRITICAL';
    details = { attempts: randInt(5, 50*attackIntensity), source_ip: ip, target_user: user };
  } else if (attackType === 'privilege_escalation') {
    const cmd = rand(PRIV_CMDS);
    msg = `${user} : TTY=pts/0 ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`;
    category = 'privilege_escalation';
    severity = 'CRITICAL';
    details = { command: cmd, source_user: user, target_user: 'root' };
  } else {
    const r = Math.random();
    if (r < 0.7) {
      msg = `Accepted publickey for ${user} from ${ip} port ${randInt(1024,65535)} ssh2`;
      details = { auth_method: 'publickey', source_ip: ip, user };
    } else if (r < 0.88) {
      msg = `Accepted password for ${user} from ${ip} port ${randInt(1024,65535)} ssh2`;
      details = { auth_method: 'password', source_ip: ip, user };
    } else {
      msg = `Failed password for invalid user ${rand(['admin','root','test','support'])} from ${ip}`;
      severity = 'WARN';
      category = 'failed_auth';
      details = { source_ip: ip, auth_method: 'password' };
    }
  }
  return { timestamp: fmtISO(ts), source: 'authentication', severity, category, ip, user, service: svc, message: msg, details };
}

function genWebServerLog(ts, severity, attackType, attackIntensity) {
  const ip     = randIP();
  const method = rand(HTTP_METHODS);
  let path, status, ua, category = 'normal', details = {};

  if (attackType === 'sql_injection') {
    path   = rand(ATTACK_PATHS.sqli);
    status = rand([200, 500, 403]);
    ua     = rand(['sqlmap/1.7.11','python-requests/2.31.0','curl/7.88.1']);
    category = 'sql_injection';
    severity = 'CRITICAL';
    details  = { payload: path, signature: 'SQL_INJECTION' };
  } else if (attackType === 'xss') {
    path   = rand(ATTACK_PATHS.xss);
    status = rand([200, 400, 403]);
    ua     = rand(USER_AGENTS);
    category = 'xss';
    severity = 'ERROR';
    details  = { payload: path, signature: 'XSS_ATTEMPT' };
  } else if (attackType === 'directory_traversal') {
    path   = rand(ATTACK_PATHS.traversal);
    status = rand([200, 403, 404]);
    ua     = rand(USER_AGENTS);
    category = 'directory_traversal';
    severity = 'CRITICAL';
    details  = { payload: path, signature: 'PATH_TRAVERSAL' };
  } else if (attackType === 'ddos') {
    path   = rand(['/','/api/data','/search']);
    status = rand([200, 503]);
    ua     = rand(['Go-http-client/1.1','python-requests/2.31.0','curl/7.88.1']);
    category = 'ddos';
    severity = 'CRITICAL';
    details  = { requests_per_sec: randInt(200*attackIntensity, 1000*attackIntensity), signature: 'DDOS_FLOOD' };
  } else {
    path   = rand(PATHS);
    status = rand(HTTP_CODES_NORMAL);
    ua     = rand(USER_AGENTS.slice(0,5));
  }

  const bytes = randInt(200, 65000);
  const resp  = randInt(10, 800);
  const msg   = `${ip} - - [${ts.toUTCString()}] "${method} ${path} HTTP/1.1" ${status} ${bytes} ${resp}ms "${ua}"`;
  return { timestamp: fmtISO(ts), source: 'webserver', severity, category, ip, method, path, status, bytes, response_ms: resp, user_agent: ua, message: msg, details };
}

function genApplicationLog(ts, severity, attackType) {
  const event = rand(APP_EVENTS);
  const svc   = rand(['auth-service','api-gateway','db-connector','cache-layer','job-runner','notification-svc']);
  const txId  = Math.random().toString(36).substr(2,9).toUpperCase();
  let msg, category = 'normal', details = {};

  if (attackType === 'sql_injection') {
    msg = `Database error: syntax error in query near 'UNION SELECT' - possible injection attempt`;
    severity = 'CRITICAL';
    category = 'sql_injection';
    details  = { error_code: 'DB_SYNTAX_ERROR', signature: 'UNION_SELECT', tx_id: txId };
  } else if (attackType === 'privilege_escalation') {
    msg = `Unauthorized role escalation attempt by user accessing /admin endpoint`;
    severity = 'CRITICAL';
    category = 'privilege_escalation';
    details  = { endpoint: '/admin', tx_id: txId };
  } else if (attackType === 'c2_beacon') {
    const domain = rand(ATTACK_PATHS.c2_domains);
    msg = `Outbound connection to suspicious domain ${domain} - possible C2 traffic`;
    severity = 'CRITICAL';
    category = 'c2_beacon';
    details  = { domain, signature: 'C2_BEACON', tx_id: txId };
  } else {
    const logLevels = { INFO: ['INFO','DEBUG'], WARN: ['WARN'], ERROR: ['ERROR'], CRITICAL: ['FATAL'] };
    const lvl = rand(logLevels[severity] || ['INFO']);
    msg = `[${lvl}] [${svc}] [txId=${txId}] ${event} - duration=${randInt(1,200)}ms`;
    details = { service: svc, tx_id: txId, duration_ms: randInt(1,200) };
  }
  return { timestamp: fmtISO(ts), source: 'application', severity, category, service: svc, tx_id: txId, message: msg, details };
}

function genFirewallLog(ts, severity, attackType, attackIntensity) {
  const srcIp  = randIP();
  const dstIp  = randInternalIP();
  const proto  = rand(PROTOCOLS);
  let srcPort, dstPort, action, category = 'normal', details = {};

  if (attackType === 'port_scan') {
    srcPort = randInt(1024, 65535);
    dstPort = rand(PORTS_SCAN);
    action  = 'DROP';
    category = 'port_scan';
    severity = 'WARN';
    details  = { scanned_ports: randInt(10*attackIntensity, 100*attackIntensity), signature: 'PORT_SCAN' };
  } else if (attackType === 'ddos') {
    srcPort = randInt(1024, 65535);
    dstPort = rand([80, 443, 8080]);
    action  = randInt(1,10) > 5 ? 'DROP' : 'ALLOW';
    category = 'ddos';
    severity = 'CRITICAL';
    details  = { pps: randInt(5000*attackIntensity, 50000*attackIntensity), signature: 'DDOS_MITIGATE' };
  } else {
    srcPort = randInt(1024, 65535);
    dstPort = rand(PORTS_COMMON);
    action  = rand(FIREWALL_ACTIONS);
    if (action === 'DENY' || action === 'DROP') { severity = 'WARN'; category = 'blocked'; }
  }

  const msg = `${action} ${proto} ${srcIp}:${srcPort} -> ${dstIp}:${dstPort} len=${randInt(40,1500)} ttl=${randInt(32,128)}`;
  return { timestamp: fmtISO(ts), source: 'firewall', severity, category, src_ip: srcIp, dst_ip: dstIp,
           src_port: srcPort, dst_port: dstPort, protocol: proto, action, message: msg, details };
}

function genNetworkLog(ts, severity, attackType, attackIntensity) {
  const srcIp  = randIP();
  const dstIp  = randInternalIP();
  const proto  = rand(PROTOCOLS);
  let msg, category = 'normal', details = {};

  if (attackType === 'port_scan') {
    const ports = Array.from({length: randInt(5,20)}, () => rand(PORTS_SCAN));
    msg = `SCAN DETECTED: ${srcIp} probing ports ${ports.join(',')} on ${dstIp}`;
    category = 'port_scan';
    severity = 'ERROR';
    details  = { ports_probed: ports, signature: 'NMAP_SCAN' };
  } else if (attackType === 'c2_beacon') {
    const domain = rand(ATTACK_PATHS.c2_domains);
    msg = `DNS query for ${domain} from ${srcIp} - flagged as C2 infrastructure`;
    category = 'c2_beacon';
    severity = 'CRITICAL';
    details  = { query: domain, type: 'A', signature: 'C2_DNS' };
  } else if (attackType === 'ddos') {
    msg = `ANOMALY: Traffic spike ${randInt(1,10)}Gbps from ${srcIp} to ${dstIp} - exceeds baseline by ${randInt(200*attackIntensity,1000*attackIntensity)}%`;
    category = 'ddos';
    severity = 'CRITICAL';
    details  = { gbps: parseFloat(randFloat(0.5, 10*attackIntensity)), baseline_pct: randInt(200,1000) };
  } else {
    const bytes = randInt(500, 1500000);
    const pkts  = randInt(1, 1000);
    msg = `FLOW ${proto} ${srcIp}:${randInt(1024,65535)} -> ${dstIp}:${rand(PORTS_COMMON)} bytes=${bytes} pkts=${pkts} duration=${randInt(1,3600)}s`;
    details = { bytes, packets: pkts, protocol: proto };
  }
  return { timestamp: fmtISO(ts), source: 'network', severity, category, src_ip: srcIp, dst_ip: dstIp, protocol: proto, message: msg, details };
}

// ─── Attack Burst Generator ──────────────────────────────────
function generateAttackBurst(attackType, intensity, startTs, endTs, sources) {
  const logs = [];
  const count = Math.floor(randInt(10, 30) * intensity);
  const span  = endTs - startTs;

  for (let i = 0; i < count; i++) {
    const ts = new Date(startTs.getTime() + Math.random() * span);
    const src = rand(sources);
    let log = null;

    try {
      if (src === 'authentication') log = genAuthLog(ts, 'ERROR', attackType, intensity);
      else if (src === 'webserver')  log = genWebServerLog(ts, 'ERROR', attackType, intensity);
      else if (src === 'application')log = genApplicationLog(ts, 'ERROR', attackType);
      else if (src === 'firewall')   log = genFirewallLog(ts, 'ERROR', attackType, intensity);
      else if (src === 'network')    log = genNetworkLog(ts, 'ERROR', attackType, intensity);
    } catch(e) { /* skip */ }

    if (log) logs.push(log);
  }
  return logs;
}

// ─── Severity chooser ───────────────────────────────────────
function chooseSeverity(mix) {
  const r = Math.random() * 100;
  if (r < mix.info) return 'INFO';
  if (r < mix.info + mix.warn) return 'WARN';
  if (r < mix.info + mix.warn + mix.error) return 'ERROR';
  return 'CRITICAL';
}

// ─── Main Generator ─────────────────────────────────────────
function generateLogs(config) {
  const { volume, startTs, endTs, sources, severityMix, attacks, anomalyRatio } = config;
  const logs = [];
  const span = endTs - startTs;

  const normalCount  = Math.floor(volume * (1 - anomalyRatio / 100));
  const attackCount  = volume - normalCount;

  // Normal logs
  for (let i = 0; i < normalCount; i++) {
    const ts  = new Date(startTs.getTime() + Math.random() * span);
    const src = rand(sources);
    const sev = chooseSeverity(severityMix);
    let log = null;
    try {
      if (src === 'authentication') log = genAuthLog(ts, sev, null, 1);
      else if (src === 'webserver')  log = genWebServerLog(ts, sev, null, 1);
      else if (src === 'application')log = genApplicationLog(ts, sev, null);
      else if (src === 'firewall')   log = genFirewallLog(ts, sev, null, 1);
      else if (src === 'network')    log = genNetworkLog(ts, sev, null, 1);
    } catch(e) { /* skip */ }
    if (log) logs.push(log);
  }

  // Attack logs
  const activeAttacks = Object.entries(attacks).filter(([,v]) => v.enabled);
  if (activeAttacks.length > 0 && attackCount > 0) {
    const perAttack = Math.floor(attackCount / activeAttacks.length);
    for (const [type, cfg] of activeAttacks) {
      // Generate burst in a random sub-window
      const burstStart = new Date(startTs.getTime() + Math.random() * span * 0.8);
      const burstEnd   = new Date(burstStart.getTime() + span * 0.2);
      const burst = generateAttackBurst(type, cfg.intensity, burstStart, burstEnd, sources);
      // Fill remaining with spread attacks
      const remaining = perAttack - burst.length;
      for (let i = 0; i < Math.max(0, remaining); i++) {
        const ts  = new Date(startTs.getTime() + Math.random() * span);
        const src = rand(sources);
        let log = null;
        try {
          if (src === 'authentication') log = genAuthLog(ts, 'ERROR', type, cfg.intensity);
          else if (src === 'webserver')  log = genWebServerLog(ts, 'ERROR', type, cfg.intensity);
          else if (src === 'application')log = genApplicationLog(ts, 'ERROR', type);
          else if (src === 'firewall')   log = genFirewallLog(ts, 'ERROR', type, cfg.intensity);
          else if (src === 'network')    log = genNetworkLog(ts, 'ERROR', type, cfg.intensity);
        } catch(e) { /* skip */ }
        if (log) logs.push(log);
      }
      logs.push(...burst);
    }
  }

  // Sort by timestamp
  logs.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  return logs;
}

// ─── Export Functions ────────────────────────────────────────
function exportJSON(logs) {
  const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `cyberlog_forge_${Date.now()}.json`);
}

function exportCSV(logs) {
  if (!logs.length) return;
  const keys = ['timestamp','source','severity','category','ip','user','message'];
  const header = keys.join(',');
  const rows = logs.map(l =>
    keys.map(k => {
      const v = l[k] !== undefined ? String(l[k]) : '';
      return `"${v.replace(/"/g, '""')}"`;
    }).join(',')
  );
  const csv = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  downloadBlob(blob, `cyberlog_forge_${Date.now()}.csv`);
}

function exportSyslog(logs) {
  const lines = logs.map(l => {
    const pri = l.severity === 'CRITICAL' ? 2 : l.severity === 'ERROR' ? 3 : l.severity === 'WARN' ? 4 : 6;
    const ts = l.timestamp.replace('T',' ').replace('Z','');
    const host = l.ip || 'cyberlog-forge';
    const svc  = l.service || l.source;
    return `<${pri}>1 ${l.timestamp} ${host} ${svc} - - - ${l.message}`;
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  downloadBlob(blob, `cyberlog_forge_${Date.now()}.log`);
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url; a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Rendering ──────────────────────────────────────────────
function renderLogs(logs, format) {
  const output = document.getElementById('log-output');
  if (!logs.length) {
    output.innerHTML = `<div class="log-placeholder">
      <div class="placeholder-icon">⚠️</div>
      <div class="placeholder-title">No Logs Generated</div>
      <div class="placeholder-sub">Check your source selection and try again.</div>
    </div>`;
    return;
  }

  const preview = logs.slice(0, 300); // Show max 300 in preview

  if (format === 'json') {
    output.innerHTML = preview.map(l => {
      const json = JSON.stringify(l, null, 2);
      const highlighted = json
        .replace(/("[\w_]+"):/g, '<span class="json-key">$1</span>:')
        .replace(/: (".*?")/g, ': <span class="json-str">$1</span>')
        .replace(/: (\d+\.?\d*)/g, ': <span class="json-num">$1</span>')
        .replace(/: (true|false)/g, ': <span class="json-bool">$1</span>');
      return `<div class="log-json">${highlighted}</div>`;
    }).join('');
  } else if (format === 'table') {
    const rows = preview.map(l => `
      <tr>
        <td>${l.timestamp.replace('T',' ').replace('.000Z','')}</td>
        <td><span class="sev-badge sev-${l.severity.toLowerCase()}">${l.severity}</span></td>
        <td>${l.source}</td>
        <td>${l.category || 'normal'}</td>
        <td>${l.ip || l.src_ip || '-'}</td>
        <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.message}</td>
      </tr>`).join('');
    output.innerHTML = `<table class="log-table">
      <thead><tr><th>Timestamp</th><th>Severity</th><th>Source</th><th>Category</th><th>IP</th><th>Message</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  } else {
    // Syslog style / text
    output.innerHTML = preview.map(l => {
      const sevClass = `sev-${l.severity.toLowerCase()}-text`;
      return `<div class="log-line">
        <span class="ll-ts">${l.timestamp.replace('T',' ').substring(0,22)}</span>
        <span class="ll-src">[${l.source.substring(0,8)}]</span>
        <span class="ll-sev ${sevClass}">${l.severity}</span>
        <span class="ll-msg">${l.message}</span>
      </div>`;
    }).join('');
  }

  if (logs.length > 300) {
    output.innerHTML += `<div style="text-align:center;padding:12px;color:var(--text-muted);font-size:12px">
      ⚠ Preview limited to 300 entries. All ${logs.length} entries will be included in export.
    </div>`;
  }
}

function updateStats(logs) {
  const normal    = logs.filter(l => l.category === 'normal' || l.category === 'blocked' || l.category === 'failed_auth').length;
  const anomalous = logs.length - normal;
  const critical  = logs.filter(l => l.severity === 'CRITICAL').length;
  const sources   = new Set(logs.map(l => l.source)).size;

  document.getElementById('st-total').textContent    = logs.length.toLocaleString();
  document.getElementById('st-normal').textContent   = normal.toLocaleString();
  document.getElementById('st-anomalous').textContent= anomalous.toLocaleString();
  document.getElementById('st-critical').textContent = critical.toLocaleString();
  document.getElementById('st-sources').textContent  = sources;
  document.getElementById('stat-count').textContent  = `${logs.length.toLocaleString()} logs ready`;
}

// ─── Config Readers ─────────────────────────────────────────
function getConfig() {
  const sources = [...document.querySelectorAll('input[name="source"]:checked')].map(el => el.value);
  if (!sources.length) { alert('Select at least one log source!'); return null; }

  const volume = parseInt(document.getElementById('vol-input').value, 10) || 500;
  const startVal = document.getElementById('time-start').value;
  const endVal   = document.getElementById('time-end').value;
  const startTs  = startVal ? new Date(startVal) : new Date(Date.now() - 86400000);
  const endTs    = endVal   ? new Date(endVal)   : new Date();

  if (startTs >= endTs) { alert('Start time must be before end time!'); return null; }

  const info     = parseInt(document.getElementById('sev-info').value, 10);
  const warn     = parseInt(document.getElementById('sev-warn').value, 10);
  const error    = parseInt(document.getElementById('sev-error').value, 10);
  const critical = parseInt(document.getElementById('sev-critical').value, 10);
  const total    = info + warn + error + critical || 100;
  const mix = {
    info:     (info / total) * 100,
    warn:     (warn / total) * 100,
    error:    (error / total) * 100,
    critical: (critical / total) * 100
  };

  const anomalyRatio = parseInt(document.getElementById('anomaly-ratio').value, 10);

  const attackDefs = [
    ['brute_force', 'atk-bruteforce', 'int-bruteforce'],
    ['port_scan',   'atk-portscan',   'int-portscan'],
    ['sql_injection','atk-sqli',      'int-sqli'],
    ['xss',         'atk-xss',        'int-xss'],
    ['directory_traversal','atk-traversal','int-traversal'],
    ['ddos',        'atk-ddos',       'int-ddos'],
    ['privilege_escalation','atk-privesc','int-privesc'],
    ['c2_beacon',   'atk-c2',         'int-c2']
  ];

  const attacks = {};
  for (const [type, toggleId, intId] of attackDefs) {
    const enabled  = document.getElementById(toggleId).checked;
    const intensity = parseInt(document.getElementById(intId).value, 10);
    attacks[type] = { enabled, intensity };
  }

  return { volume, startTs, endTs, sources, severityMix: mix, attacks, anomalyRatio };
}

// ─── UI Init ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // Set default times
  const now  = new Date();
  const yday = new Date(now - 86400000);
  const fmt  = d => d.toISOString().slice(0,16);
  document.getElementById('time-start').value = fmt(yday);
  document.getElementById('time-end').value   = fmt(now);

  // Volume slider sync
  const volSlider = document.getElementById('vol-slider');
  const volInput  = document.getElementById('vol-input');
  volSlider.addEventListener('input', () => { volInput.value = volSlider.value; });
  volInput.addEventListener('input',  () => {
    const v = Math.min(100000, Math.max(10, parseInt(volInput.value)||10));
    volSlider.value = Math.min(v, 10000);
    volInput.value  = v;
  });

  // Severity sliders
  ['info','warn','error','critical'].forEach(sev => {
    const sl  = document.getElementById(`sev-${sev}`);
    const val = document.getElementById(`sev-${sev}-val`);
    sl.addEventListener('input', () => { val.textContent = sl.value + '%'; });
  });

  // Intensity sliders
  document.querySelectorAll('.intensity-slider').forEach(sl => {
    const valEl = document.getElementById(sl.id.replace('int-','intval-'));
    sl.addEventListener('input', () => { if(valEl) valEl.textContent = sl.value; });
  });

  // Attack toggles → show/hide controls
  document.querySelectorAll('.attack-toggle').forEach(toggle => {
    const id   = toggle.id.replace('atk-','ctrl-');
    const ctrl = document.getElementById(id);
    toggle.addEventListener('change', () => {
      if (ctrl) ctrl.classList.toggle('hidden', !toggle.checked);
    });
  });

  // Anomaly ratio
  const ratioSlider = document.getElementById('anomaly-ratio');
  ratioSlider.addEventListener('input', () => {
    const v = parseInt(ratioSlider.value, 10);
    const n = 100 - v;
    document.getElementById('ratio-normal-label').textContent = `Normal: ${n}%`;
    document.getElementById('ratio-attack-label').textContent = `Attack: ${v}%`;
    document.getElementById('ratio-bar-n').style.width = n + '%';
    document.getElementById('ratio-bar-a').style.width = v + '%';
  });

  // Preview format toggle
  document.getElementById('preview-format').addEventListener('change', () => {
    if (generatedLogs.length) renderLogs(generatedLogs, document.getElementById('preview-format').value);
  });

  // Clear
  document.getElementById('btn-clear').addEventListener('click', () => {
    generatedLogs = [];
    document.getElementById('log-output').innerHTML = `<div class="log-placeholder">
      <div class="placeholder-icon">⚡</div>
      <div class="placeholder-title">Ready to Generate</div>
      <div class="placeholder-sub">Configure your settings on the left and click <strong>Generate Logs</strong></div>
    </div>`;
    updateStats([]);
    document.getElementById('stat-count').textContent = '0 logs ready';
  });

  // Generate
  document.getElementById('btn-generate').addEventListener('click', async () => {
    const config = getConfig();
    if (!config) return;

    const btn = document.getElementById('btn-generate');
    btn.disabled = true;
    btn.textContent = '⚙️ Generating...';
    btn.classList.add('generating');

    const pw = document.getElementById('progress-wrap');
    const pb = document.getElementById('progress-bar');
    const pl = document.getElementById('progress-label');
    pw.style.display = 'flex';

    // Use chunked async generation to keep UI responsive
    await new Promise(resolve => {
      let done = 0;
      const total = config.volume;
      const CHUNK = 500;
      const allLogs = [];

      const step = () => {
        const chunkConfig = { ...config, volume: Math.min(CHUNK, total - done) };
        if (chunkConfig.volume <= 0) { resolve(allLogs); return; }
        const chunk = generateLogs({ ...chunkConfig, volume: chunkConfig.volume });
        allLogs.push(...chunk);
        done += CHUNK;
        const pct = Math.min(100, Math.round(done / total * 100));
        pb.style.setProperty('--progress', pct + '%');
        pl.textContent = `Generating... ${pct}%`;
        if (done < total) setTimeout(step, 0);
        else resolve(allLogs);
      };
      setTimeout(step, 0);
    }).then(logs => {
      generatedLogs = logs;
      // Full generation at once (simpler & correct)
    });

    // Actually generate all at once properly
    generatedLogs = generateLogs(config);
    updateStats(generatedLogs);
    renderLogs(generatedLogs, document.getElementById('preview-format').value);

    pb.style.setProperty('--progress', '100%');
    pl.textContent = 'Done!';
    setTimeout(() => { pw.style.display = 'none'; }, 1500);

    btn.disabled = false;
    btn.textContent = '⚡ Generate Logs';
    btn.classList.remove('generating');
  });

  // Exports
  document.getElementById('btn-export-json').addEventListener('click', () => {
    if (!generatedLogs.length) { alert('Generate logs first!'); return; }
    exportJSON(generatedLogs);
  });
  document.getElementById('btn-export-csv').addEventListener('click', () => {
    if (!generatedLogs.length) { alert('Generate logs first!'); return; }
    exportCSV(generatedLogs);
  });
  document.getElementById('btn-export-syslog').addEventListener('click', () => {
    if (!generatedLogs.length) { alert('Generate logs first!'); return; }
    exportSyslog(generatedLogs);
  });
});
