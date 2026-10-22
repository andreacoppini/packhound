"use strict";
document.getElementById("login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = document.getElementById("err");
  err.hidden = true;
  const r = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user: document.getElementById("user").value, password: document.getElementById("password").value }),
  });
  if (r.ok) {
    window.location.href = "/";
    return;
  }
  const j = await r.json().catch(() => ({}));
  err.textContent = j.error || "Could not log in";
  err.hidden = false;
});
