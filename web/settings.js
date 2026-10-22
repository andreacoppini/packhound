"use strict";

// The service's Settings dialog: SNMP, the REST API, the login, and on the
// appliance the host itself. Loaded after app.js and uses its helpers.

const S = { tab: "snmp", data: null };

window.openSettings = async function () {
  try {
    S.data = await api("/api/settings");
  } catch (e) {
    toast(e.message);
    return;
  }
  drawSettings();
  $("settings").hidden = false;
};

function closeSettings() { $("settings").hidden = true; }

async function saveSettings(body, msg) {
  try {
    S.data = await api("/api/settings", body);
    toast(msg || "Saved", true);
    drawSettings();
  } catch (e) { toast(e.message); }
}

async function system(body, msg) {
  try {
    S.data = await api("/api/system", body);
    toast(msg || "Applied", true);
    drawSettings();
  } catch (e) { toast(e.message); }
}

const val = (id) => document.getElementById(id).value;
const checked = (id) => document.getElementById(id).checked;

function drawSettings() {
  const d = S.data;
  const tabs = [["snmp", "SNMP"], ["api", "REST API"], ["account", "Password"]];
  if (d.system) tabs.push(["network", "Network"], ["system", "System"]);
  if (!tabs.some((t) => t[0] === S.tab)) S.tab = "snmp";
  const host = location.host;
  let body = "";

  if (S.tab === "snmp") {
    const sn = d.snmp, info = d.snmpInfo || {};
    const base = sn.baseOID;
    body = `
<label class="check"><input type="checkbox" id="snEnabled" ${sn.enabled ? "checked" : ""}> SNMP agent on (v1 and v2c, read-only)</label>
<div class="grid2">
  <label><span>Community</span><input type="text" id="snCommunity" value="${esc(sn.community)}" autocomplete="off"></label>
  <label><span>UDP port</span><input type="number" id="snPort" value="${sn.port}" min="1" max="65535"></label>
  <label><span>Managers allowed (addresses or networks; blank for any)</span><input type="text" id="snAllow" value="${esc((sn.allow || []).join(", "))}" placeholder="10.0.0.10, 192.168.50.0/24"></label>
  <label><span>Base OID</span><input type="text" id="snBase" value="${esc(base)}"></label>
  <label><span>Location (sysLocation)</span><input type="text" id="snLoc" value="${esc(sn.location)}"></label>
  <label><span>Contact (sysContact)</span><input type="text" id="snContact" value="${esc(sn.contact)}"></label>
</div>
<div class="actions"><button class="primary" id="snSave">Save</button><a href="/PACKHOUND-MIB.txt" download><button type="button">Download the MIB</button></a></div>
<div class="hint">${info.running ? `Answering: ${info.requests || 0} requests so far, ${info.refused || 0} refused (wrong community or manager).` : "Not running."}</div>
<h3>What to poll</h3>
<div class="hint">Each stream is a row of the table, indexed by its address and port: 1 (IPv4), 4 (address length), the four octets, then the port. For 239.192.1.1:1234 the index is <code>1.4.239.192.1.1.1234</code>.</div>
<pre>Streams (Gauge32)            ${base}.1.2.0
Degraded / lost now          ${base}.1.4.0   ${base}.1.5.0
Total rate, kbit/s           ${base}.1.7.0

Per stream: ${base}.2.1.&lt;column&gt;.&lt;index&gt;
  2 group    3 name    6 sender    7 status (1 receiving, 2 degraded, 3 lost, 4 periodic, 5 quiet)
  9 bit/s    10 kbit/s    11 packets/s    12 average size    13 jitter (µs)
  14 errors lost on the way, last minute    15 errors made by the sender, last minute
  16 senders    17 packets (Counter64)    18 bytes (Counter64)    19 seconds since the last packet

For example, the rate of 239.192.1.1:1234 in kbit/s:
  ${base}.2.1.10.1.4.239.192.1.1.1234</pre>
<div class="hint">The base OID sits under net-snmp's arc for private MIBs. If your organisation has an IANA enterprise number, you can move the tree under it.</div>`;
  } else if (S.tab === "api") {
    const tok = d.api.token;
    body = `
<label class="check"><input type="checkbox" id="apiEnabled" ${d.api.enabled ? "checked" : ""}> REST API and Prometheus metrics on</label>
<label><span>API token</span><input type="text" id="apiToken" value="${esc(tok)}" readonly></label>
<div class="actions"><button class="primary" id="apiSave">Save</button><button id="apiCopy">Copy token</button><button id="apiNew">Make a new token</button></div>
<div class="hint">Send the token as <code>Authorization: Bearer &lt;token&gt;</code>, as <code>X-API-Key</code>, or as <code>?token=</code> for tools that cannot set headers. The API is read-only.</div>
<h3>Endpoints</h3>
<pre>GET https://${esc(host)}/api/v1/summary                 counts and totals
GET https://${esc(host)}/api/v1/streams                 every stream
GET https://${esc(host)}/api/v1/streams?kind=video      filter: kind, status, family
GET https://${esc(host)}/api/v1/streams/239.192.1.1:1234   one stream, with its detail
GET https://${esc(host)}/api/v1/alerts?since=2026-10-22T08:00:00Z
GET https://${esc(host)}/metrics                        Prometheus

curl -k -H "Authorization: Bearer ${esc(tok)}" https://${esc(host)}/api/v1/streams</pre>`;
  } else if (S.tab === "account") {
    body = `
<div class="hint">Logged in as <b>${esc(ui.server.user)}</b>. ${d.system ? "On the appliance the same password opens the VM console and SSH." : ""}</div>
<div class="grid2">
  <label><span>Current password</span><input type="password" id="pwCur" autocomplete="current-password"></label>
  <label><span>New password (at least 8 characters)</span><input type="password" id="pwNew" autocomplete="new-password"></label>
  <label><span>New password again</span><input type="password" id="pwNew2" autocomplete="new-password"></label>
</div>
<div class="actions"><button class="primary" id="pwSave">Change password</button></div>`;
  } else if (S.tab === "network") {
    const sys = d.system;
    const rows = sys.interfaces.map((f) => {
      const c = sys.config[f.name] || { mode: "" };
      return `<div class="ifrow" data-if="${esc(f.name)}">
  <b class="m">${esc(f.name)}</b>
  <div class="stat">${esc(f.mac)} · ${f.carrier ? "link up " + esc(f.speed || "") : "no link"} · ${esc((f.addrs || []).join(" ") || "no address")}</div>
  <select class="ifmode">
    ${[["dhcp", "DHCP"], ["static", "Static address"], ["capture", "Monitoring only"], ["off", "Off"], ["", "Not configured"]].map(([v, l]) => `<option value="${v}" ${c.mode === v ? "selected" : ""}>${l}</option>`).join("")}
  </select>
  <div class="ifedit" ${c.mode === "static" ? "" : "hidden"}>
    <input type="text" class="ifaddr" placeholder="192.168.1.50/24" value="${esc(c.address || "")}" aria-label="Address">
    <input type="text" class="ifgw" placeholder="Gateway" value="${esc(c.gateway || "")}" aria-label="Gateway">
    <input type="text" class="ifdns" placeholder="DNS servers" value="${esc((c.dns || []).join(" "))}" aria-label="DNS servers">
  </div>
  <div class="actions" style="grid-column:1/-1"><button class="small ifapply">Apply ${esc(f.name)}</button></div>
</div>`;
    }).join("");
    body = `
<div class="hint warn">Changing the interface you reached this page through can cut you off. Its new address takes effect at once.</div>
${rows}
<label><span>Host name</span><input type="text" id="sysHost" value="${esc(sys.hostname)}"></label>
<div class="actions"><button id="hostSave">Save host name</button></div>
<div class="hint">"Monitoring only" brings an interface up with no address, for a mirror port or an IPTV VLAN. Some switches ignore joins sent from an interface with no address: if a joined group does not arrive, give the interface an address on that VLAN.</div>`;
  } else if (S.tab === "system") {
    const sys = d.system;
    body = `
<div class="hint">Up ${esc(sys.uptime)} · Packhound ${esc($("ver").textContent)}</div>
<div class="grid2">
  <label><span>Time zone</span><input type="text" id="tz" value="${esc(sys.timezone)}" placeholder="Europe/London"></label>
  <label><span>Time servers (blank: Debian's pool)</span><input type="text" id="ntp" value="${esc((sys.ntp || []).join(" "))}" placeholder="pool.ntp.org"></label>
</div>
<div class="actions"><button id="timeSave">Save time settings</button></div>
<label class="check"><input type="checkbox" id="ssh" ${sys.ssh ? "checked" : ""}> SSH on (log in with the same user name and password)</label>
<h3>Power</h3>
<div class="grid2"><label><span>Your password, to confirm</span><input type="password" id="pwrPw" autocomplete="current-password"></label></div>
<div class="actions"><button id="reboot">Reboot</button><button class="danger" id="shutdown">Shut down</button></div>`;
  }

  $("settings").innerHTML = `<div class="dialog" role="dialog" aria-label="Settings">
<header><div class="brand">Settings</div><span class="spacer"></span><button id="setClose">Close</button></header>
<div class="stabs">${tabs.map(([k, l]) => `<div class="stab ${S.tab === k ? "on" : ""}" data-stab="${k}">${l}</div>`).join("")}</div>
<div class="spane">${body}</div></div>`;
  wireSettings();
}

function wireSettings() {
  const on = (id, f) => { const e = document.getElementById(id); if (e) e.onclick = f; };
  on("setClose", closeSettings);
  for (const t of document.querySelectorAll(".stab")) t.onclick = () => { S.tab = t.dataset.stab; drawSettings(); };
  on("snSave", () => saveSettings({
    section: "snmp",
    snmp: {
      enabled: checked("snEnabled"), community: val("snCommunity"), port: +val("snPort"),
      allow: val("snAllow").split(/[\s,]+/).filter(Boolean), baseOID: val("snBase"),
      location: val("snLoc"), contact: val("snContact"),
    },
  }, "SNMP settings saved"));
  on("apiSave", () => saveSettings({ section: "api", api: { enabled: checked("apiEnabled"), newKey: false } }));
  on("apiNew", () => {
    if (confirm("Make a new token? Anything using the old one stops working.")) saveSettings({ section: "api", api: { enabled: checked("apiEnabled"), newKey: true } }, "New token made");
  });
  on("apiCopy", () => navigator.clipboard.writeText(val("apiToken")).then(() => toast("Token copied", true), () => toast("Select the token and copy it")));
  on("pwSave", () => {
    if (val("pwNew") !== val("pwNew2")) return toast("The new passwords do not match");
    saveSettings({ section: "password", password: { current: val("pwCur"), new: val("pwNew") } }, "Password changed");
  });
  for (const row of document.querySelectorAll(".ifrow")) {
    const mode = row.querySelector(".ifmode");
    mode.onchange = () => (row.querySelector(".ifedit").hidden = mode.value !== "static");
    row.querySelector(".ifapply").onclick = () => {
      if (!mode.value) return toast("Pick a mode first");
      system({
        action: "iface",
        iface: {
          name: row.dataset.if, mode: mode.value, address: row.querySelector(".ifaddr").value.trim(),
          gateway: row.querySelector(".ifgw").value.trim(), dns: row.querySelector(".ifdns").value.split(/[\s,]+/).filter(Boolean),
        },
      }, row.dataset.if + " applied");
    };
  }
  on("hostSave", () => system({ action: "hostname", hostname: val("sysHost") }, "Host name saved"));
  on("timeSave", () => system({ action: "time", timezone: val("tz"), ntp: val("ntp").split(/[\s,]+/).filter(Boolean) }, "Time settings saved"));
  const ssh = document.getElementById("ssh");
  if (ssh) ssh.onchange = () => system({ action: "ssh", ssh: ssh.checked }, ssh.checked ? "SSH on" : "SSH off");
  const power = (action) => async () => {
    if (!confirm(action === "reboot" ? "Reboot the appliance?" : "Shut the appliance down? It will need starting from the hypervisor.")) return;
    try {
      await api("/api/system", { action, password: val("pwrPw") });
      toast(action === "reboot" ? "Rebooting: this page reconnects when it is back" : "Shutting down", true);
    } catch (e) { toast(e.message); }
  };
  on("reboot", power("reboot"));
  on("shutdown", power("shutdown"));
}

document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("settings").hidden) closeSettings(); });
