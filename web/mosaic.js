"use strict";

// The mosaic: a still of every transport stream, with its state, whether
// audio is arriving, and how old the picture is. The list is polled every
// two seconds; an image is fetched only when its URL changes, which is when
// a new still has been taken.

const $ = (id) => document.getElementById(id);
const token = new URLSearchParams(location.search).get("token");
const api = token ? "api/v1/mosaic?token=" + encodeURIComponent(token) : "api/mosaic";

const tiles = new Map(); // channel id -> tile element
let last = null;

function store(k, v) { try { localStorage.setItem("mosaic." + k, v); } catch (e) {} }
function stored(k) { try { return localStorage.getItem("mosaic." + k); } catch (e) { return null; } }

function setSize(px) {
  document.documentElement.style.setProperty("--tile", px + "px");
  for (const b of $("size").querySelectorAll("button")) b.classList.toggle("on", b.dataset.size === String(px));
  store("size", px);
}

function ago(t, now) {
  if (!t) return "";
  const s = Math.max(0, Math.round((now - new Date(t)) / 1000));
  if (s < 60) return s + " s";
  if (s < 3600) return Math.round(s / 60) + " min";
  return Math.round(s / 3600) + " h";
}

function rate(bps) {
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " Mb/s";
  if (bps >= 1e3) return Math.round(bps / 1e3) + " kb/s";
  return Math.round(bps) + " b/s";
}

const speaker = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M2 6h3l4-3v10l-4-3H2z"/>';
const AUDIO_ON = speaker + '<path d="M11 5.5a3.5 3.5 0 0 1 0 5M12.5 3.5a6 6 0 0 1 0 9" stroke="currentColor" fill="none" stroke-width="1.4" stroke-linecap="round"/></svg>';
const AUDIO_OFF = speaker + '<path d="M11 5.5l4 5M15 5.5l-4 5" stroke="currentColor" fill="none" stroke-width="1.4" stroke-linecap="round"/></svg>';

function tile(id) {
  let el = tiles.get(id);
  if (el) return el;
  el = document.createElement("figure");
  el.className = "tile";
  el.innerHTML = '<div class="pic"><img alt="" decoding="async"><div class="over"></div>' +
    '<span class="audio"></span><span class="age"></span><span class="errs"></span></div>' +
    '<figcaption><span class="dot"></span><span class="nm"></span><span class="grp"></span></figcaption>';
  tiles.set(id, el);
  return el;
}

function draw() {
  if (!last) return;
  const now = new Date();
  const q = $("filter").value.trim().toLowerCase();
  const onlyProblems = $("problems").checked;
  const grid = $("grid");
  const keep = new Set();
  let shown = 0, problems = 0;
  for (const c of last.channels) {
    const bad = c.statusLevel !== "ok" || c.errLevel === "err";
    if (bad) problems++;
    if (q && !(c.name || "").toLowerCase().includes(q) && !c.group.includes(q)) continue;
    if (onlyProblems && !bad) continue;
    shown++;
    keep.add(c.id);
    const el = tile(c.id);
    el.dataset.level = c.statusLevel;
    const img = el.querySelector("img");
    if (c.image && img.getAttribute("src") !== c.image) img.src = c.image;
    img.hidden = !c.image;

    let over = "";
    if (c.status === "Lost") over = "No signal";
    else if (c.scrambled) over = "Scrambled";
    else if (!c.image) over = c.problem || (last.decoder ? "Waiting for a picture" : "No decoder");
    const ov = el.querySelector(".over");
    ov.textContent = over;
    ov.hidden = !over;
    ov.classList.toggle("dim", !!c.image);

    const au = el.querySelector(".audio");
    au.hidden = !c.hasAudio;
    au.innerHTML = c.audio ? AUDIO_ON : AUDIO_OFF;
    au.className = "audio " + (c.audio ? "on" : "off");
    au.title = c.audio ? "Audio arriving" : "No audio arriving";

    const age = el.querySelector(".age");
    age.textContent = c.shotAt ? ago(c.shotAt, now) : "";
    age.classList.toggle("stale", c.shotAt && now - new Date(c.shotAt) > 3 * last.interval * 1000);

    const errs = el.querySelector(".errs");
    errs.textContent = c.errLevel === "err" && c.status !== "Lost" ? c.errors : "";
    errs.hidden = !errs.textContent;

    el.querySelector(".dot").className = "dot st-" + c.statusLevel;
    el.querySelector(".nm").textContent = c.name || c.group;
    el.querySelector(".grp").textContent = c.name ? c.group : "";
    el.title = [c.name, c.group, c.video, rate(c.bps), c.status + (c.reason ? ": " + c.reason : ""),
      c.senderName ? "from " + c.senderName + " (" + c.sender + ")" : "from " + c.sender].filter(Boolean).join("\n");
    if (el.parentNode !== grid || grid.children[shown - 1] !== el) grid.insertBefore(el, grid.children[shown - 1] || null);
  }
  for (const [id, el] of tiles) {
    if (!keep.has(id)) el.remove();
    if (!last.channels.some((c) => c.id === id)) tiles.delete(id);
  }
  $("count").textContent = last.channels.length + " channels" + (problems ? " · " + problems + " with problems" : "");
  $("note").hidden = !last.note;
  $("note").textContent = last.note || "";
  const empty = $("empty");
  empty.hidden = shown > 0;
  empty.textContent = last.channels.length ? "No channel matches." :
    "No transport streams yet. Start listening in the console, with the channels' groups.";
}

async function poll() {
  try {
    const r = await fetch(api, { cache: "no-store" });
    if (r.status === 401) { location.href = "login.html"; return; }
    if (!r.ok) throw new Error(r.status);
    last = await r.json();
    document.body.classList.remove("offline");
  } catch (e) {
    document.body.classList.add("offline");
  }
  draw();
}

for (const b of $("size").querySelectorAll("button")) b.onclick = () => setSize(b.dataset.size);
$("filter").oninput = draw;
$("problems").onchange = () => { store("problems", $("problems").checked ? "1" : ""); draw(); };
$("full").onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen();
setSize(stored("size") || 280);
$("problems").checked = stored("problems") === "1";
poll();
setInterval(poll, 2000);
