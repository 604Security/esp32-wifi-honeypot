// Served pages. DASH_HTML = operator dashboard (over the management link).
// NEUTRAL_HTML = what a device that joins a decoy AP sees (generic, logs nothing it can see).
#pragma once

const char NEUTRAL_HTML[] PROGMEM = R"rawliteral(<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connecting…</title><style>
html,body{height:100%;margin:0;background:#f2f3f5;color:#444;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.w{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px}
.s{width:44px;height:44px;border:4px solid #d4d7dc;border-top-color:#888;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}p{font-size:15px}
</style></head><body><div class="w"><div class="s"></div><p>Checking connection…</p></div></body></html>
)rawliteral";

const char DASH_HTML[] PROGMEM = R"rawliteral(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>esp32-wifi-honeypot</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0A0E14; --panel:#111720; --panel2:#0D131C; --line:#1E2A3A; --ink:#DCE6F2; --muted:#6F8199;
  --green:#39E0A0; --amber:#FFC24B; --red:#FF5A6A; --cyan:#4BD6FF; --purple:#B58CFF;
  --mono:"Share Tech Mono",ui-monospace,Menlo,monospace; --sans:"Inter",system-ui,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;
  background-image:radial-gradient(rgba(75,214,255,.04) 1px,transparent 1px);background-size:22px 22px}
a{color:var(--cyan)}
header{display:flex;flex-wrap:wrap;align-items:center;gap:10px 18px;padding:14px 18px;border-bottom:1px solid var(--line);background:var(--panel2)}
.logo{font-family:var(--mono);font-size:19px;color:var(--green);letter-spacing:1px}
.logo b{color:var(--ink)}
.live{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:13px;color:var(--green)}
.live i{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{50%{opacity:.3}}
.scope{margin-left:auto;font-size:12px;color:var(--muted);max-width:360px;text-align:right}
main{padding:18px;max-width:1500px;margin:0 auto}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.tile .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.tile .v{font-family:var(--mono);font-size:26px;margin-top:3px}
.tile .v small{font-size:13px;color:var(--muted)}
.tile.ssid .v{font-size:18px;color:var(--amber);word-break:break-all}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:16px}
button{font:inherit;font-weight:600;cursor:pointer;background:var(--panel);color:var(--ink);border:1px solid var(--line);
  border-radius:9px;padding:9px 14px}
button:hover{border-color:var(--cyan)}
button.on{background:var(--green);color:#042;border-color:var(--green)}
button.warn:hover{border-color:var(--amber)}
.sp{flex:1}
.hint{color:var(--muted);font-size:13px}
input[type=text]{font:inherit;font-family:var(--mono);background:var(--panel2);color:var(--ink);border:1px solid var(--line);
  border-radius:9px;padding:9px 12px;min-width:320px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px;
  padding:8px 10px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg)}
td{padding:9px 10px;border-bottom:1px solid var(--panel)}
tr.assoc td{background:rgba(57,224,160,.06)}
tr.flash{animation:flash 1.2s ease-out}
@keyframes flash{from{background:rgba(75,214,255,.25)}}
.mac{font-family:var(--mono);font-size:13px}
.chip{display:inline-block;font-size:12px;padding:2px 8px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--muted)}
.chip.rnd{color:var(--amber);border-color:rgba(255,194,75,.4)}
.chip.vendor{color:var(--cyan);border-color:rgba(75,214,255,.35)}
.chip.ss{color:var(--purple);border-color:rgba(181,140,255,.35);margin:1px 2px}
.rssi{display:inline-flex;align-items:center;gap:6px}
.rssi .m{width:46px;height:7px;border-radius:4px;background:var(--panel2);overflow:hidden;border:1px solid var(--line)}
.rssi .m i{display:block;height:100%;background:var(--green)}
.tag{font-family:var(--mono);font-size:11px;padding:1px 6px;border-radius:5px;border:1px solid var(--line);color:var(--muted)}
.tag.a{color:var(--green);border-color:rgba(57,224,160,.4)}
.ua{color:var(--muted);font-size:12px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.empty{color:var(--muted);text-align:center;padding:40px}
footer{color:var(--muted);font-size:12px;padding:16px 18px;border-top:1px solid var(--line);margin-top:20px}
@media(max-width:640px){.scope{display:none}.ua{max-width:120px}}
</style>
</head>
<body>
<header>
  <span class="logo">wifi&#8209;<b>honeypot</b></span>
  <span class="live"><i></i>LIVE</span>
  <span class="scope">Defensive sensor &middot; metadata only &middot; your network / authorized use. No credential capture.</span>
</header>
<main>
  <div class="tiles" id="tiles"></div>
  <div class="bar">
    <button id="snif" class="on">Sniffer: on</button>
    <button id="deep" class="warn">Deep scan (1/6/11)</button>
    <button id="clear" class="warn">Clear view</button>
    <a href="/log.jsonl"><button>Download log</button></a>
    <span class="sp"></span>
    <input type="text" id="ssids" placeholder="decoy SSIDs, comma separated">
    <button id="setss">Set decoys</button>
  </div>
  <div style="overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)">
    <table>
      <thead><tr>
        <th>Last seen</th><th>MAC</th><th>Vendor</th><th>Signal</th><th>Status</th>
        <th>Joined</th><th>Probed SSIDs</th><th>IP / fingerprint</th><th>Seen</th>
      </tr></thead>
      <tbody id="rows"><tr><td colspan="9" class="empty">Listening…</td></tr></tbody>
    </table>
  </div>
</main>
<footer>
  esp32-wifi-honeypot &middot; rotating open decoy APs + passive probe sniffing &middot; records MAC/OUI, RSSI, probe history, HTTP User-Agent.
  Single radio: the decoy AP shares the management channel; "Deep scan" hops 1/6/11 and briefly pauses the dashboard.
</footer>
<script>
const $ = id => document.getElementById(id);
const api = p => fetch(p, {cache:'no-store'}).then(r => r.json());
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const seen = new Set();

function ago(sec, now){ if(!sec) return '—'; const d = now - sec; if(d<0) return 'now';
  if(d<60) return d+'s'; if(d<3600) return (d/60|0)+'m'; return (d/3600|0)+'h'; }
function rssiPct(r){ return Math.max(0, Math.min(100, (r + 100) * 1.6)); }
function rssiColor(r){ return r > -60 ? 'var(--green)' : r > -75 ? 'var(--amber)' : 'var(--red)'; }

async function tick(){
  let st, cs;
  try { st = await api('/api/state'); cs = await api('/api/contacts'); }
  catch(e){ return; }
  $('tiles').innerHTML = [
    ['Decoy AP', esc(st.ssid), 'ssid'],
    ['Channel', st.channel],
    ['Devices seen', st.totalSeen],
    ['Connected now', st.associated],
    ['Probe frames', st.probeFrames],
    ['Dashboard', st.mgmtIp + '', 'small'],
  ].map(([k,v,c]) => `<div class="tile ${c==='ssid'?'ssid':''}"><div class="k">${k}</div><div class="v" ${c==='small'?'style="font-size:15px"':''}>${v}</div></div>`).join('');
  $('snif').textContent = 'Sniffer: ' + (st.sniffer ? 'on' : 'off');
  $('snif').classList.toggle('on', st.sniffer);
  if (!$('ssids').matches(':focus') && !$('ssids').value) $('ssids').placeholder = (st.decoys||[]).join(', ');

  cs.sort((a,b) => (b.last||0) - (a.last||0) || b.rssi - a.rssi);
  if (!cs.length) { $('rows').innerHTML = '<tr><td colspan="9" class="empty">No devices yet. Decoy AP is up and the sniffer is listening on channel ' + st.channel + '.</td></tr>'; return; }
  $('rows').innerHTML = cs.map(c => {
    const isNew = !seen.has(c.mac); seen.add(c.mac);
    const vendor = c.randomized ? '<span class="chip rnd">randomized</span>'
      : c.vendor === 'unknown' ? '<span class="chip">unknown</span>' : `<span class="chip vendor">${esc(c.vendor)}</span>`;
    const probes = c.probes.length ? c.probes.map(p => `<span class="chip ss">${esc(p)}</span>`).join('') : '<span class="hint">—</span>';
    const fp = [c.ip ? esc(c.ip) : '', c.host ? esc(c.host) : '', c.ua ? esc(c.ua) : ''].filter(Boolean).join(' · ');
    return `<tr class="${c.assoc?'assoc':''} ${isNew?'flash':''}">
      <td>${ago(c.last, st.now)}</td>
      <td class="mac">${esc(c.mac)}</td>
      <td>${vendor}</td>
      <td><span class="rssi"><span class="m"><i style="width:${rssiPct(c.rssi)}%;background:${rssiColor(c.rssi)}"></i></span>${c.rssi}</span></td>
      <td>${c.assoc?'<span class="tag a">ASSOC</span>':'<span class="tag">probe</span>'}</td>
      <td>${c.joined?esc(c.joined):'<span class="hint">—</span>'}</td>
      <td>${probes}</td>
      <td class="ua" title="${fp}">${fp||'<span class="hint">—</span>'}</td>
      <td>${c.seen}</td>
    </tr>`;
  }).join('');
}

$('snif').onclick = () => api('/api/sniffer?on=' + ($('snif').classList.contains('on')?0:1)).then(tick);
$('clear').onclick = () => { if(confirm('Clear the live view? (The SD log is kept.)')){ seen.clear(); api('/api/clear').then(tick); } };
$('deep').onclick = () => { if(confirm('Deep scan hops channels 1/6/11 for ~9s. The dashboard pauses until it returns.')) api('/api/scan?deep=1'); };
$('setss').onclick = () => { const v = $('ssids').value.trim(); if(v) api('/api/ssids?set=' + encodeURIComponent(v)).then(()=>{ $('ssids').value=''; tick(); }); };

tick();
setInterval(tick, 2000);
</script>
</body>
</html>
)rawliteral";
