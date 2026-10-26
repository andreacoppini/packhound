"use strict";

// The live preview: a channel, encoded small by Packhound, played as HLS.
// Safari plays HLS itself; other browsers play it with hls.js. Starts muted,
// as browsers only autoplay muted video; the controls unmute it.

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const ch = params.get("ch");
const token = params.get("token");
const embedded = params.get("embed") === "1";
const base = token ? "api/v1/" : "api/";
const tokenQ = token ? "?token=" + encodeURIComponent(token) : "";

let hls = null;
let q = null;
let mediaErrors = 0;

function message(text) {
  $("msg").textContent = text || "";
  $("msg").hidden = !text;
}

function playlistURL(quality) {
  return `${base}live/${encodeURIComponent(ch)}/${quality}/index.m3u8${tokenQ}`;
}

async function play(quality) {
  q = quality;
  for (const b of $("quality").querySelectorAll("button")) b.classList.toggle("on", b.dataset.q === q);
  if (hls) { hls.destroy(); hls = null; }
  const video = $("video");
  video.removeAttribute("src");
  video.load();
  message(q === "audio" ? "Starting the audio…" : "Starting the preview…");
  // Ask for the playlist first: it says why when a preview cannot start
  // (busy, scrambled), which a player would only report as a failure.
  const url = playlistURL(q);
  try {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      message("Cannot preview: " + (j.error || r.statusText));
      return;
    }
  } catch (e) {
    message("Cannot reach Packhound");
    return;
  }
  if (quality !== q) return; // changed meanwhile
  video.classList.toggle("audioonly", q === "audio");
  if (video.canPlayType("application/vnd.apple.mpegurl")) {
    video.src = url;
  } else if (window.Hls && Hls.isSupported()) {
    hls = new Hls({ liveSyncDurationCount: 2, maxBufferLength: 10, backBufferLength: 10 });
    mediaErrors = 0;
    // Stopping hls.js from inside its own event has to wait for the event
    // to finish.
    const stop = (text) => {
      message(text);
      const h = hls;
      hls = null;
      if (h) setTimeout(() => h.destroy(), 0);
    };
    const me = hls;
    hls.on(Hls.Events.ERROR, (_, d) => {
      if (hls !== me) return; // stopped already
      // A browser without H.264 or AAC can never play it: say so, and stop.
      if (d.details === Hls.ErrorDetails.MANIFEST_INCOMPATIBLE_CODECS_ERROR || d.details === Hls.ErrorDetails.BUFFER_ADD_CODEC_ERROR) {
        stop("This browser cannot play H.264 video with AAC sound; try another browser");
        return;
      }
      if (!d.fatal) return;
      if (d.type === Hls.ErrorTypes.NETWORK_ERROR) {
        message("The preview stopped; retrying…");
        setTimeout(() => quality === q && play(q), 3000);
      } else if (++mediaErrors <= 2 && hls) {
        hls.recoverMediaError();
      } else {
        stop("The preview cannot be played here");
      }
    });
    hls.loadSource(url);
    hls.attachMedia(video);
  } else {
    message("This browser cannot play the preview");
    return;
  }
  video.play().catch(() => {});
}

$("video").addEventListener("playing", () => message(q === "audio" ? "Audio only" : ""));

// The channel's name and state, from the mosaic's list.
async function info() {
  try {
    const r = await fetch(`${base}mosaic${tokenQ}`, { cache: "no-store" });
    const d = await r.json();
    const c = d.channels.find((x) => x.id === ch);
    if (!c) return null;
    $("name").textContent = c.name || c.group;
    $("group").textContent = c.name ? c.group : "";
    $("dot").className = "dot st-" + c.statusLevel;
    document.title = (c.name || c.group) + " · Packhound preview";
    const notes = [];
    if (c.status !== "Receiving") notes.push(c.status + (c.reason ? ": " + c.reason : ""));
    if (c.hasAudio && !c.audio) notes.push("no audio arriving");
    $("note").textContent = notes.join(" · ");
    return c;
  } catch (e) {
    return null;
  }
}

for (const b of $("quality").querySelectorAll("button")) b.onclick = () => play(b.dataset.q);
if (embedded) {
  document.body.classList.add("embedded");
  const nt = $("newTab");
  nt.href = location.pathname + "?" + new URLSearchParams({ ch, ...(token ? { token } : {}) });
  nt.hidden = false;
}

(async () => {
  if (!ch) { message("No channel given"); return; }
  const c = await info();
  // Radio has no picture: play its audio.
  play(c && !c.video && c.hasAudio ? "audio" : "low");
  setInterval(info, 5000);
})();
