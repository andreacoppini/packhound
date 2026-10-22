"use strict";

// Everything shown here that came off the network (service names, SSDP
// headers, SDP session names) is attacker-controlled text, so all of it goes
// through esc() before it touches innerHTML.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const KINDS = { video: "IPTV video", audio: "Audio", disc: "Discovery", time: "Timing", net: "Network ctl", unk: "Unknown" };

const ui = {
  fam: 4,
  kind: "all",
  filter: "",
  sortKey: "status",
  sortAsc: false,
  sel: "",
  tab: "detail",
  win: 60,
  showLinkLocal: true,
  running: false,
  last: null,
};

// ---- preferences, kept in this browser only ----
const store = {
  get(k, d) { try { const v = localStorage.getItem("packhound." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("packhound." + k, JSON.stringify(v)); } catch { /* private window */ } },
};

function fmtRate(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + " Gb/s";
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " Mb/s";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " kb/s";
  return Math.round(b) + " b/s";
}
function fmtNum(n) { return n >= 100 ? Math.round(n).toLocaleString() : (Math.round(n * 10) / 10).toString(); }
function fmtDur(s) {
  s = Math.max(0, Math.floor(s));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}
function hhmmss(t) { return new Date(t).toLocaleTimeString(); }

let toastTimer;
function toast(msg, ok) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (ok ? " ok" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), ok ? 3500 : 7000);
}

async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

// ---- setup ----

async function init() {
  const info = await api("/api/info");
  $("ver").textContent = info.version;
  showUpdate(info.update);

  const sel = $("iface");
  sel.innerHTML = info.interfaces.map((i) => `<option value="${esc(i.name)}">${esc(i.display)}</option>`).join("");
  const want = info.defaults.iface || store.get("iface", "");
  if (want && info.interfaces.some((i) => i.name === want)) sel.value = want;

  const mode = store.get("mode", info.defaults.mode || "capture");
  for (const r of document.querySelectorAll("input[name=mode]")) r.checked = r.value === mode;
  $("groups").value = info.defaults.groups || store.get("groups", "");
  $("joinToo").checked = store.get("joinToo", true);
  if (!info.live) {
    $("liveWhy").textContent = info.liveWhy + ". Until then, Capture everything falls back to joining the listed groups.";
    $("liveWhy").hidden = false;
  }
  ui.common = info.common;

  const cfg = Object.assign({}, info.config, store.get("config", {}));
  $("silentAfter").value = cfg.silentAfter;
  $("dropPct").value = cfg.dropPct;
  $("errPerMin").value = cfg.errPerMin;
  $("newSenders").checked = cfg.newSenders;
  $("avgSeconds").value = String(cfg.avgSeconds);
  ui.showLinkLocal = store.get("showLinkLocal", true);
  $("showLinkLocal").checked = ui.showLinkLocal;
  ui.fam = store.get("fam", 4);
  ui.win = store.get("win", 60);
  for (const b of document.querySelectorAll("#win button")) b.classList.toggle("on", +b.dataset.win === ui.win);
  setFam(ui.fam);
  pushConfig();
  modeChanged();

  for (const s of document.querySelectorAll("section > h2")) {
    s.addEventListener("click", () => s.parentElement.classList.toggle("collapsed"));
  }
  wire();
  poll();
  setInterval(poll, 1000);
}

function showUpdate(u) {
  if (!u) return;
  const a = $("update");
  a.textContent = "Update: " + u.latest;
  a.href = u.url;
  a.hidden = false;
}

function mode() { return document.querySelector("input[name=mode]:checked").value; }

function modeChanged() {
  const m = mode();
  store.set("mode", m);
  $("joinTooRow").classList.toggle("disabled", m !== "capture");
  $("joinToo").disabled = m !== "capture";
  $("iface").disabled = m === "demo" || ui.running;
}

function readConfig() {
  return {
    silentAfter: +$("silentAfter").value || 5,
    dropPct: +$("dropPct").value || 0,
    errPerMin: +$("errPerMin").value || 0,
    newSenders: $("newSenders").checked,
    avgSeconds: +$("avgSeconds").value || 1,
  };
}

async function pushConfig() {
  const c = readConfig();
  store.set("config", c);
  try { await api("/api/config", c); } catch (e) { toast(e.message); }
}

function wire() {
  $("listen").onclick = async () => {
    try {
      if (ui.running) {
        await api("/api/stop", {});
      } else {
        $("groupErr").hidden = true;
        const req = { iface: $("iface").value, mode: mode(), groups: $("groups").value, join: $("joinToo").checked };
        store.set("iface", req.iface);
        store.set("groups", req.groups);
        await api("/api/start", req);
        ui.sel = "";
      }
      poll();
    } catch (e) {
      if (/line \d+/.test(e.message)) {
        $("groupErr").textContent = e.message;
        $("groupErr").hidden = false;
      }
      toast(e.message);
    }
  };
  $("record").onclick = async () => {
    const rec = ui.last && ui.last.engine.recording;
    try {
      if (rec && rec.active) {
        await api("/api/record", { on: false });
        const name = rec.name;
        toast("Saved " + rec.path, true);
        window.location.href = "/api/recording?name=" + encodeURIComponent(name);
      } else {
        const st = await api("/api/record", { on: true });
        toast("Recording to " + st.path, true);
      }
      poll();
    } catch (e) { toast(e.message); }
  };
  for (const r of document.querySelectorAll("input[name=mode]")) r.onchange = modeChanged;
  $("joinToo").onchange = () => store.set("joinToo", $("joinToo").checked);
  $("addCommon").onclick = () => {
    const g = $("groups");
    const have = g.value.trim();
    if (!have.includes("224.0.0.251:5353")) g.value = (have ? have + "\n" : "") + ui.common;
    store.set("groups", g.value);
  };
  $("clearGroups").onclick = () => { $("groups").value = ""; store.set("groups", ""); };
  $("groups").onchange = () => store.set("groups", $("groups").value);
  for (const id of ["silentAfter", "dropPct", "errPerMin", "newSenders", "avgSeconds"]) $(id).onchange = pushConfig;
  $("showLinkLocal").onchange = () => { ui.showLinkLocal = $("showLinkLocal").checked; store.set("showLinkLocal", ui.showLinkLocal); render(); };
  $("filter").oninput = () => { ui.filter = $("filter").value.toLowerCase(); render(); };
  $("clear").onclick = async () => { await api("/api/clear", {}); ui.sel = ""; poll(); };
  $("expCsv").onclick = () => (window.location.href = "/api/export?fmt=csv");
  $("expJson").onclick = () => (window.location.href = "/api/export?fmt=json");
  $("expand").onclick = () => {
    const big = $("drawer").classList.toggle("big");
    $("expand").textContent = big ? "Shrink" : "Expand";
  };
  for (const b of document.querySelectorAll(".fam")) b.onclick = () => { setFam(+b.dataset.fam); render(); };
  for (const th of document.querySelectorAll("thead th[data-k]")) {
    th.onclick = () => {
      const k = th.dataset.k;
      if (ui.sortKey === k) ui.sortAsc = !ui.sortAsc;
      else { ui.sortKey = k; ui.sortAsc = !["bps", "pps", "avgSize", "jitterMs", "status"].includes(k); }
      render();
    };
  }
  for (const t of document.querySelectorAll(".tab")) {
    t.onclick = () => {
      ui.tab = t.dataset.tab;
      for (const x of document.querySelectorAll(".tab")) x.classList.toggle("on", x === t);
      for (const p of document.querySelectorAll(".pane")) p.hidden = p.id !== "pane-" + ui.tab;
      renderDrawer();
    };
  }
  for (const b of document.querySelectorAll("#win button")) {
    b.onclick = () => {
      ui.win = +b.dataset.win;
      store.set("win", ui.win);
      for (const x of document.querySelectorAll("#win button")) x.classList.toggle("on", x === b);
      poll();
    };
  }
  $("rows").onclick = (e) => {
    const tr = e.target.closest("tr[data-key]");
    if (!tr) return;
    select(tr.dataset.key);
  };
  $("pane-alerts").onclick = (e) => {
    const g = e.target.closest("[data-key]");
    if (g) select(g.dataset.key, true);
  };
}

function select(key, toDetail) {
  ui.sel = key;
  if (ui.last) {
    const r = ui.last.snap.rows.find((x) => x.key === key);
    if (r && r.family !== ui.fam) setFam(r.family);
  }
  if (toDetail) document.querySelector('.tab[data-tab="detail"]').click();
  render();
  poll();
}

function setFam(f) {
  ui.fam = f;
  store.set("fam", f);
  for (const b of document.querySelectorAll(".fam")) b.classList.toggle("on", +b.dataset.fam === f);
}

// ---- polling ----

let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  let st;
  try {
    st = await api(`/api/state?sel=${encodeURIComponent(ui.sel)}&win=${ui.win}`);
  } catch (e) {
    $("stateText").textContent = "Console disconnected: is Packhound still running?";
    $("dot").className = "dot";
    polling = false;
    return;
  }
  // A fault in drawing the page is not a lost connection; say what it was.
  try {
    ui.last = st;
    if (st.update) showUpdate(st.update);
    render();
  } catch (e) {
    $("stateText").textContent = "Console error: " + e.message;
    console.error(e);
  } finally {
    polling = false;
  }
}

function isLinkLocal(r) {
  return r.family === 4 ? r.addr.startsWith("224.0.0.") : r.addr.toLowerCase().startsWith("ff02:");
}

function visibleRows() {
  const rows = ui.last ? ui.last.snap.rows : [];
  return rows.filter((r) => {
    if (r.family !== ui.fam) return false;
    if (!ui.showLinkLocal && isLinkLocal(r)) return false;
    if (ui.kind !== "all" && r.kind !== ui.kind) return false;
    if (ui.filter) {
      const hay = [r.group, r.type, r.name, r.sender, r.status, KINDS[r.kind]].join(" ").toLowerCase();
      if (!hay.includes(ui.filter)) return false;
    }
    return true;
  });
}

function render() {
  if (!ui.last) return;
  const { engine: eng, snap } = ui.last;
  snap.rows = snap.rows || [];
  snap.alerts = snap.alerts || [];
  snap.log = snap.log || [];
  ui.running = eng.running;

  // header
  const lb = $("listen");
  lb.textContent = eng.running ? "Stop" : "Listen";
  lb.className = eng.running ? "danger" : "primary";
  $("aside").classList.toggle("locked", eng.running);
  for (const r of document.querySelectorAll("input[name=mode]")) {
    r.disabled = eng.running;
    if (eng.running) r.checked = r.value === eng.mode;
  }
  $("groups").readOnly = eng.running;
  $("iface").disabled = eng.running || mode() === "demo";
  const rec = eng.recording;
  const recording = rec && rec.active;
  $("record").disabled = !eng.running && !recording;
  $("record").textContent = recording ? `Stop recording · ${(rec.bytes / 1048576).toFixed(1)} MB` : "Record";
  $("record").className = recording ? "rec" : "";
  if (eng.running) {
    const modeName = { capture: "capturing", join: `joined ${eng.joined} groups`, demo: "demo traffic" }[eng.mode] || eng.mode;
    const since = (new Date(snap.now) - new Date(eng.started)) / 1000;
    $("stateText").textContent = eng.mode === "demo" ? `Demo traffic · ${fmtDur(since)}` : `Listening on ${eng.iface} · ${modeName} · ${fmtDur(since)}`;
    $("dot").className = "dot " + (recording ? "rec" : "on");
  } else {
    $("stateText").textContent = eng.failed ? "Stopped: " + eng.failed : "Not listening";
    $("dot").className = "dot";
  }
  const t = snap.totals;
  const ld = $("localDrop");
  ld.hidden = !(t.localDropsMin > 0);
  if (t.localDropsMin > 0) {
    ld.textContent = `This PC dropped ${t.localDropsMin.toLocaleString()} packets in the last minute`;
    ld.title = "The capture buffer overflowed before Packhound could read these packets. Errors on streams while this happens may be on this machine, not on the network.";
  }
  $("cStreams").textContent = t.streams;
  $("cSenders").textContent = t.senders;
  $("cRate").textContent = fmtRate(t.bps);
  $("cPps").textContent = fmtNum(t.pps);
  $("cProblems").textContent = t.problems;
  $("cProblems").parentElement.classList.toggle("live", t.problems > 0);
  $("n4").textContent = t.v4;
  $("n6").textContent = t.v6;

  // kind chips, for the current family
  const fam = snap.rows.filter((r) => r.family === ui.fam && (ui.showLinkLocal || !isLinkLocal(r)));
  const counts = {};
  for (const r of fam) counts[r.kind] = (counts[r.kind] || 0) + 1;
  if (ui.kind !== "all" && !counts[ui.kind]) ui.kind = "all";
  const chips = [["all", "All", fam.length], ...Object.keys(KINDS).filter((k) => counts[k]).map((k) => [k, KINDS[k], counts[k]])];
  $("chips").innerHTML = chips.map(([k, l, n]) => `<button class="chip${ui.kind === k ? " on" : ""}" data-kind="${k}">${l} ${n}</button>`).join("");
  for (const c of $("chips").children) c.onclick = () => { ui.kind = c.dataset.kind; render(); };

  // table
  const rows = visibleRows();
  const k = ui.sortKey, dir = ui.sortAsc ? 1 : -1;
  rows.sort((a, b) => {
    // Status sorts by how much attention a stream needs: Lost, then
    // Degraded, then the rest, busiest first within each.
    if (k === "status") return ((HEALTH[b.statusLevel] - HEALTH[a.statusLevel]) * (ui.sortAsc ? -1 : 1)) || b.bps - a.bps;
    const x = a[k], y = b[k];
    if (typeof x === "number") return (x - y) * dir || b.bps - a.bps;
    return String(x).localeCompare(String(y), undefined, { numeric: true }) * dir;
  });
  for (const th of document.querySelectorAll("thead th[data-k]")) {
    th.classList.toggle("sorted", th.dataset.k === k);
    th.classList.toggle("asc", th.dataset.k === k && ui.sortAsc);
  }
  if (!ui.sel && rows.length) ui.sel = (rows.find((r) => r.kind === "video" || r.kind === "audio") || rows[0]).key;
  $("rows").innerHTML = rows.map(rowHTML).join("");
  $("nRows").textContent = `${rows.length} rows`;
  const empty = $("empty");
  empty.hidden = rows.length > 0;
  if (!rows.length) {
    empty.innerHTML = snap.rows.length
      ? "Nothing matches. Try another filter, or the other address family."
      : eng.running
        ? "Listening. Streams appear as their first packet arrives."
        : "Press <b>Listen</b> to start. Pick <b>Demo</b> to see what it looks like without a network.";
  }

  $("nAlerts").textContent = snap.alerts.length ? snap.alerts.length : "";
  renderDrawer();
}

function spark(values, color) {
  const max = Math.max(...values, 1);
  const pts = values.map((v, i) => `${((i * 96) / (values.length - 1)).toFixed(1)},${(20 - (v / max) * 18).toFixed(1)}`).join(" ");
  return `<svg class="spark" width="96" height="22" viewBox="0 0 96 22" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
}

const HEALTH = { err: 3, warn: 2, ok: 1, idle: 0 };
const KCOL = { video: "#4da3ff", audio: "#b49cff", disc: "#3ecfaa", time: "#f0b429", net: "#8794a5", unk: "#8794a5" };

function rowHTML(r) {
  const color = r.status === "Lost" ? "#ff6b6b" : KCOL[r.kind];
  const jit = r.jitterMs >= 0 ? r.jitterMs.toFixed(2) + " ms" : "-";
  const title = r.reason ? ` title="${esc(r.reason)}"` : "";
  return `<tr data-key="${esc(r.key)}"${r.key === ui.sel ? ' class="sel"' : ""}>
<td class="m">${esc(r.group)}</td>
<td><span class="badge k-${r.kind}">${esc(r.type)}</span></td>
<td class="name" title="${esc(r.name)}">${esc(r.name)}</td>
<td class="m">${esc(r.sender)}</td>
<td class="num m">${fmtRate(r.bps)}</td>
<td>${spark(r.spark, color)}</td>
<td class="num m">${fmtNum(r.pps)}</td>
<td class="num m">${r.avgSize ? r.avgSize.toLocaleString() + " B" : "-"}</td>
<td class="num m">${jit}</td>
<td class="m e-${r.errLevel}">${esc(r.errors)}</td>
<td><span class="st st-${r.statusLevel}"${title}>${esc(r.status)}</span></td>
</tr>`;
}

// ---- drawer ----

function tableHTML(t) {
  if (!t.rows || !t.rows.length) return "";
  return `<div><p class="ttl">${esc(t.title)}</p><div class="box"><table><thead><tr>${t.cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${t.rows
    .map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`)
    .join("")}</tbody></table></div></div>`;
}

function chartHTML(d) {
  const s = d.series || [];
  const W = 600, H = 160;
  const max = Math.max(...s, 1);
  const pts = s.map((v, i) => `${((i * W) / Math.max(1, s.length - 1)).toFixed(1)},${(H - 6 - (v / max) * (H - 18)).toFixed(1)}`).join(" ");
  const color = d.status === "Lost" ? "#ff6b6b" : KCOL[d.kind];
  const grid = [0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${W}" y1="${(H * f).toFixed(0)}" y2="${(H * f).toFixed(0)}" stroke="#1d242e"/>`).join("");
  const label = { 60: "1 minute", 600: "10 minutes", 3600: "1 hour" }[ui.win];
  return `<div class="gcap"><span>Bit rate, last ${label}${d.step > 1 ? ` (${d.step} s averages)` : ""}</span><span class="mono">peak ${fmtRate(max === 1 ? 0 : max)}</span></div>
<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Bit rate over time">${grid}
<polygon points="0,${H} ${pts} ${W},${H}" fill="${color}" fill-opacity=".12"/>
<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>
<div class="gcap mono"><span>−${label}</span><span>now</span></div>`;
}

function renderDrawer() {
  if (!ui.last) return;
  const { snap } = ui.last;
  const d = snap.detail && snap.detail.key === ui.sel ? snap.detail : null;
  if (ui.tab === "detail") {
    const p = $("pane-detail");
    if (!d) {
      p.innerHTML = `<div class="empty">Pick a stream in the table to see its detail.</div>`;
      return;
    }
    const kv = (d.kv || []).map((x) => `<dt>${esc(x.k)}</dt><dd>${esc(x.v)}</dd>`).join("");
    p.innerHTML = `<div class="detail">
<div class="facts"><div class="dhead"><span class="g">${esc(d.group)}</span><span class="badge k-${d.kind}">${esc(d.type)}</span><span class="st st-${d.statusLevel}">${esc(d.status)}</span></div>
<div class="dname">${esc(d.name)}</div><dl class="kv">${kv}</dl></div>
<div class="graph">${chartHTML(d)}</div>
<div class="tables">${(d.tables || []).map(tableHTML).join("")}</div></div>`;
  } else if (ui.tab === "senders") {
    $("pane-senders").innerHTML = d ? `<div class="detail"><div class="tables">${tableHTML(d.senders) || '<div class="empty">No senders.</div>'}</div></div>` : `<div class="empty">Pick a stream in the table.</div>`;
  } else if (ui.tab === "alerts") {
    const a = snap.alerts.slice().reverse();
    $("pane-alerts").innerHTML = a.length
      ? a.map((x) => `<div class="alert"><span class="when">${hhmmss(x.time)}</span><span><span class="st st-${x.level}">${{ ok: "OK", warn: "Warning", err: "Problem" }[x.level]}</span></span><span class="grp" data-key="${esc(x.key)}">${esc(x.group)}</span><span>${esc(x.name ? x.name + ": " : "")}${esc(x.message)}</span></div>`).join("")
      : `<div class="empty">No alerts. Video and audio streams raise one when they stop, degrade or gain a sender.</div>`;
  } else {
    const p = $("pane-log");
    const atEnd = p.scrollTop + p.clientHeight >= p.scrollHeight - 20;
    p.innerHTML = snap.log.map((l) => `<span class="t">${hhmmss(l.time)}</span>  ${esc(l.message)}`).join("\n");
    if (atEnd) p.scrollTop = p.scrollHeight;
  }
}

init().catch((e) => toast("Could not load the console: " + e.message));
