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
  if (r.status === 401) {
    window.location.href = "/login.html";
    throw new Error("Logged out");
  }
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
  ui.interfaces = info.interfaces;
  $("remoteProto").value = info.defaults.remote || store.get("remote", "erspan");
  $("remoteFrom").value = info.defaults.from || store.get("from", "");
  $("remoteSession").value = info.defaults.session || store.get("session", "");
  // The background service: who is logged in, and the settings dialog.
  ui.server = info.server;
  if (info.server) {
    $("who").textContent = info.server.user + "@" + info.server.hostname;
    $("who").hidden = false;
    $("settingsBtn").hidden = false;
    $("logout").hidden = false;
    $("settingsBtn").onclick = () => window.openSettings && window.openSettings();
    const h = document.createElement("div");
    h.className = "hint";
    h.textContent = "The service keeps listening with these settings, and resumes them after a restart.";
    $("liveWhy").after(h);
  }

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
  $("remoteOpts").hidden = m !== "remote";
  remoteHelp();
}

// remoteHelp fills in the switch configuration examples with the address
// the mirror should go to: the chosen interface's.
function remoteHelp() {
  const tzsp = $("remoteProto").value === "tzsp";
  $("sessionRow").hidden = tzsp;
  const ifc = (ui.interfaces || []).find((i) => i.name === $("iface").value);
  const ip = ((ifc && ifc.addrs) || []).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a)) || "<this machine>";
  $("remoteWhere").textContent = tzsp
    ? `Point the switch at ${ip}, UDP port 37008.`
    : `Point the switch's ERSPAN session at ${ip}. Packhound receives it as root, or else through this interface's capture device, with the same access Capture everything needs.`;
  $("remoteHelp").textContent = tzsp
    ? `MikroTik RouterOS (the packet sniffer streams TZSP):
/tool sniffer set streaming-enabled=yes streaming-server=${ip} \\
    filter-interface=ether2 filter-direction=rx
/tool sniffer start

The sniffer runs on the router's CPU: fine for a few channels,
not for a whole IPTV feed.`
    : `Mirror the receive direction only: both directions
double every packet.

Cisco IOS-XE:
monitor session 1 type erspan-source
 source interface Gi1/0/1 rx
 destination
  erspan-id 1
  ip address ${ip}
  origin ip address <switch IP>
 no shutdown

Arista EOS:
monitor session ph source Ethernet1 rx
monitor session ph destination tunnel mode gre source <switch IP> destination ${ip}

Aruba CX:
mirror session 1
 destination tunnel ${ip} source <switch IP>
 source interface 1/1/1 rx
 enable

Juniper EX:
set forwarding-options analyzer ph input ingress interface ge-0/0/1.0
set forwarding-options analyzer ph output ip-address ${ip}

Ruckus ICX (FastIron with ERSPAN):
monitor-profile 1 type erspan
 source-ip <switch IP>
 destination-ip ${ip}
interface ethernet 1/1/1
 monitor profile 1 input

Syntax varies by release: check your switch's guide.`;
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
        const req = {
          iface: $("iface").value, mode: mode(), groups: $("groups").value, join: $("joinToo").checked,
          remote: $("remoteProto").value, from: $("remoteFrom").value.trim(), session: $("remoteSession").value.trim(),
        };
        store.set("iface", req.iface);
        store.set("remote", req.remote);
        store.set("from", req.from);
        store.set("session", req.session);
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
  $("remoteProto").onchange = remoteHelp;
  $("iface").addEventListener("change", remoteHelp);
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
  $("expCsv").onclick = () => (window.location.href = "/api/export?fmt=csv" + viewParam());
  $("expJson").onclick = () => (window.location.href = "/api/export?fmt=json" + viewParam());
  $("openCap").onclick = () => $("capFile").click();
  $("capFile").onchange = () => {
    const f = $("capFile").files[0];
    $("capFile").value = "";
    if (f) openCapture(f);
  };
  $("fileClose").onclick = async () => {
    ui.view = "";
    ui.sel = "";
    try { await fetch("/api/import", { method: "DELETE", headers: { "Content-Type": "application/json" } }); } catch (e) {}
    poll();
  };
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
  $("pane-detail").onclick = (e) => {
    const v = e.target.closest("[data-vlc]");
    if (v) openVLC(v.dataset.vlc);
    const c = e.target.closest("[data-copy]");
    if (c) {
      navigator.clipboard.writeText(c.dataset.copy).then(() => toast("Copied " + c.dataset.copy, true), () => toast("Could not copy; select the URL and copy it by hand"));
    }
  };
  // Double-clicking a playable stream opens it in VLC.
  $("rows").ondblclick = (e) => {
    const tr = e.target.closest("tr[data-key]");
    const r = tr && ui.last && ui.last.snap.rows.find((x) => x.key === tr.dataset.key);
    if (r && r.playURL && !ui.server) openVLC(r.key);
  };
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

async function openVLC(key) {
  try {
    const r = await api("/api/vlc", { key });
    toast("Opening " + r.url + " in VLC", true);
  } catch (e) {
    toast(e.message);
  }
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

// ---- capture files ----

// viewParam asks the service for the capture file's figures, not live ones.
function viewParam() {
  return ui.view === "file" ? "&view=file" : "";
}

// openCapture uploads a capture file and shows it once it has been read.
// The upload is the file itself, read by the service as it arrives; its
// progress is polled meanwhile.
async function openCapture(f) {
  const bar = $("fileBar");
  bar.hidden = false;
  $("fileClose").hidden = true;
  $("fileText").textContent = `Reading ${f.name}…`;
  const progress = setInterval(async () => {
    try {
      const st = await api("/api/import");
      const v = st.file;
      if (v && !v.done) {
        const pct = f.size ? ` ${Math.min(100, Math.round((100 * v.read) / f.size))}%` : "";
        $("fileText").textContent = `Reading ${f.name}:${pct} · ${v.packets.toLocaleString()} multicast packets`;
      }
    } catch (e) {}
  }, 500);
  try {
    const r = await fetch(`/api/import?name=${encodeURIComponent(f.name)}`, {
      method: "POST", headers: { "Content-Type": "application/vnd.tcpdump.pcap" }, body: f,
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || r.statusText);
    ui.view = "file";
    ui.sel = "";
  } catch (e) {
    toast(`${f.name}: ${e.message}`);
  } finally {
    clearInterval(progress);
    $("fileClose").hidden = false;
    poll();
  }
}

// drawFile shows the banner for the capture file being viewed, and hides
// what only means something live.
function drawFile(file) {
  const on = ui.view === "file" && file && file.done;
  if (ui.view === "file" && !file) ui.view = ""; // closed elsewhere
  document.body.classList.toggle("fileview", !!on);
  $("mosaicLink").href = on ? "mosaic?view=file" : "mosaic";
  if (!on) {
    if (!$("fileClose").hidden) $("fileBar").hidden = true;
    return;
  }
  $("fileBar").hidden = false;
  const t = (s) => new Date(s).toLocaleTimeString([], { hour12: false });
  const dur = (new Date(file.last) - new Date(file.first)) / 1000;
  let text = `Viewing capture ${file.name}: ${new Date(file.first).toLocaleDateString()} ${t(file.first)} to ${t(file.last)} (${fmtDur(dur)}), ${file.packets.toLocaleString()} multicast packets`;
  if (file.mirrored) text += `, ${file.mirrored.toLocaleString()} of them unwrapped from ERSPAN or TZSP`;
  if (!file.packets) text += ". There is no multicast traffic in this file.";
  $("fileText").textContent = text;
}

// ---- polling ----

let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  let st;
  try {
    st = await api(`/api/state?sel=${encodeURIComponent(ui.sel)}&win=${ui.win}${viewParam()}`);
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

// mirrorText says whether the switch's mirror is arriving: frames a
// second (from the change since the last poll) and from where.
function mirrorText(m, since) {
  const proto = m.proto === "tzsp" ? "TZSP" : "ERSPAN";
  const prev = ui.mirrorPrev;
  const now = Date.now();
  if (prev && now > prev.t) ui.mirrorRate = Math.max(0, ((m.frames - prev.frames) * 1000) / (now - prev.t));
  ui.mirrorPrev = { t: now, frames: m.frames };
  if (!m.frames) {
    const ignored = m.ignored ? ` (${m.ignored.toLocaleString()} ignored: another switch or session, or unreadable)` : "";
    const via = m.via && !/socket$/.test(m.via) ? ` via ${m.via}` : "";
    return `Waiting for ${proto} at ${m.listen}${via} · ${fmtDur(since)}${ignored}`;
  }
  const session = m.session >= 0 ? `, session ${m.session}` : "";
  const via = m.via && !/socket$/.test(m.via) ? ` via ${m.via}` : "";
  return `Mirror from ${m.from}${session} · ${proto}${via} · ${Math.round(ui.mirrorRate || 0).toLocaleString()} frames/s · ${fmtDur(since)}`;
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
  drawFile(ui.last.file);
  // A mirror's groups never reach this machine, so a player here cannot join them.
  document.body.classList.toggle("remotemode", eng.running && eng.mode === "remote");

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
  for (const id of ["remoteProto", "remoteFrom", "remoteSession"]) $(id).disabled = eng.running;
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
    if (eng.mirror) $("stateText").textContent = mirrorText(eng.mirror, since);
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
<td class="m">${esc(r.group)}${r.playURL && !ui.server ? ' <span class="playable" title="Double-click to open in VLC">▶</span>' : ""}</td>
<td><span class="badge k-${r.kind}">${esc(r.type)}</span></td>
<td class="name" title="${esc(r.name)}">${esc(r.name)}</td>
<td class="m">${esc(r.sender)}${r.senderName ? ` <span class="sname">${esc(r.senderName)}</span>` : ""}</td>
<td class="num m">${fmtRate(r.bps)}</td>
<td>${spark(r.spark, color)}</td>
<td class="num m">${fmtNum(r.pps)}</td>
<td class="num m">${r.avgSize ? r.avgSize.toLocaleString() + " B" : "-"}</td>
<td class="num m">${jit}</td>
<td class="m e-${r.errLevel}">${esc(r.errors)}${r.sourceErrors ? ` <span class="srcerr" title="Continuity errors made by the sender in the last minute: every datagram arrived, so nothing was lost on the network">+${r.sourceErrors} at sender</span>` : ""}</td>
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

// setPane replaces a drawer pane's content without losing the reader's
// place: nothing happens when the content is unchanged (as when listening has
// stopped), and otherwise the pane and every scrolling table in it keep their
// scroll positions. A different stream (key) starts again at the top.
function setPane(el, html, key) {
  if (el._html === html) return;
  const same = el._key === key;
  const boxes = same ? [...el.querySelectorAll(".box")].map((b) => [b.scrollTop, b.scrollLeft]) : [];
  const top = same ? el.scrollTop : 0;
  el.innerHTML = html;
  el._html = html;
  el._key = key;
  el.querySelectorAll(".box").forEach((b, i) => {
    if (boxes[i]) [b.scrollTop, b.scrollLeft] = boxes[i];
  });
  el.scrollTop = top;
}

function renderDrawer() {
  if (!ui.last) return;
  const { snap } = ui.last;
  const d = snap.detail && snap.detail.key === ui.sel ? snap.detail : null;
  if (ui.tab === "detail") {
    const p = $("pane-detail");
    if (!d) {
      setPane(p, `<div class="empty">Pick a stream in the table to see its detail.</div>`, "");
      return;
    }
    const kv = (d.kv || []).map((x) => `<dt>${esc(x.k)}</dt><dd>${esc(x.v)}</dd>`).join("");
    setPane(p, `<div class="detail">
<div class="facts"><div class="dhead"><span class="g">${esc(d.group)}</span><span class="badge k-${d.kind}">${esc(d.type)}</span><span class="st st-${d.statusLevel}">${esc(d.status)}</span></div>
${d.playURL ? `<div class="play">${ui.server ? "" : `<button class="small primary" data-vlc="${esc(d.key)}" title="Start VLC on this computer playing ${esc(d.playURL)}">Open in VLC</button>`}<a class="small" href="/api/playlist?key=${encodeURIComponent(d.key)}" title="A playlist file any player opens">Playlist .m3u</a><button class="small" data-copy="${esc(d.playURL)}" title="Copy the URL, to paste into a player">Copy URL</button><span class="m url">${esc(d.playURL)}</span></div>` : ""}
<div class="dname">${esc(d.name)}</div><dl class="kv">${kv}</dl></div>
<div class="graph">${chartHTML(d)}</div>
<div class="tables">${(d.tables || []).map(tableHTML).join("")}</div></div>`, d.key);
  } else if (ui.tab === "senders") {
    setPane($("pane-senders"), d ? `<div class="detail"><div class="tables">${tableHTML(d.senders) || '<div class="empty">No senders.</div>'}</div></div>` : `<div class="empty">Pick a stream in the table.</div>`, d ? d.key : "");
  } else if (ui.tab === "alerts") {
    const a = snap.alerts.slice().reverse();
    setPane($("pane-alerts"), a.length
      ? a.map((x) => `<div class="alert"><span class="when">${hhmmss(x.time)}</span><span><span class="st st-${x.level}">${{ ok: "OK", warn: "Warning", err: "Problem" }[x.level]}</span></span><span class="grp" data-key="${esc(x.key)}">${esc(x.group)}</span><span>${esc(x.name ? x.name + ": " : "")}${esc(x.message)}</span></div>`).join("")
      : `<div class="empty">No alerts. Video and audio streams raise one when they stop, degrade or gain a sender.</div>`, "alerts");
  } else {
    const p = $("pane-log");
    const atEnd = p.scrollTop + p.clientHeight >= p.scrollHeight - 20;
    setPane(p, snap.log.map((l) => `<span class="t">${hhmmss(l.time)}</span>  ${esc(l.message)}`).join("\n"), "log");
    if (atEnd) p.scrollTop = p.scrollHeight;
  }
}

init().catch((e) => toast("Could not load the console: " + e.message));
