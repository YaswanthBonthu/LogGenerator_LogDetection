const $ = (id) => document.getElementById(id);
const API = location.origin;

async function jget(url) { const r = await fetch(url); return r.json(); }
async function jpost(url, body) {
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

// --- app feature buttons ----------------------------------------------------
$("loginBtn").onclick = async () => {
  const d = await jpost(`${API}/api/login`, { username: $("u").value, password: $("p").value });
  $("loginOut").textContent = JSON.stringify(d);
};
$("searchBtn").onclick = async () => {
  const d = await jget(`${API}/api/products?q=${encodeURIComponent($("q").value)}`);
  $("searchOut").textContent = JSON.stringify(d);
};
$("profileBtn").onclick = async () => {
  const d = await jget(`${API}/api/users/${encodeURIComponent($("uid").value)}`);
  $("profileOut").textContent = JSON.stringify(d);
};
$("fileBtn").onclick = async () => {
  const r = await fetch(`${API}/api/files?name=${encodeURIComponent($("fname").value)}`);
  $("fileOut").textContent = await r.text();
};

// --- simulator --------------------------------------------------------------
$("simStart").onclick = async () => {
  const attacks = {};
  document.querySelectorAll(".atk").forEach((c) => (attacks[c.value] = c.checked));
  await jpost(`${API}/api/sim/start`, {
    duration_sec: parseInt($("dur").value, 10),
    rate: parseInt($("rate").value, 10),
    brute_force_n: parseInt($("bfn").value, 10),
    attacks,
  });
};
$("simStop").onclick = () => jpost(`${API}/api/sim/stop`);

// --- live polling: status + log tail ---------------------------------------
let tailOffset = 0;
const tailLines = [];

async function poll() {
  try {
    const s = await jget(`${API}/api/sim/status`);
    $("simStatus").classList.toggle("muted", !s.running);
    $("simStatus").innerHTML =
      `Simulator: <b>${s.running ? "running" : "idle"}</b> · ` +
      `total logged: <b>${(s.total_logged || 0).toLocaleString()}</b>`;

    const d = await jget(`${API}/api/logs?offset=${tailOffset}`);
    tailOffset = d.next_offset;
    for (const e of d.events) {
      const cls = `lvl-${e.severity}`;
      const atk = e.attack_class ? ` [${e.attack_class}]` : "";
      tailLines.push(`<span class="${cls}">${e.ts.slice(11, 19)} ${e.severity} ${e.source}${atk} — ${e.message}</span>`);
    }
    while (tailLines.length > 300) tailLines.shift();
    if (d.events.length) {
      const el = $("tail");
      el.innerHTML = tailLines.join("\n");
      el.scrollTop = el.scrollHeight;
    }
  } catch (e) { /* server not ready */ }
}
setInterval(poll, 1500);
poll();
