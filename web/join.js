/* Gauntlet join page (D4) — enter a code, pick a side, land in the right view. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  // Where each cell lands after joining.
  const DEST = { blue_cell: "/participant.html", white_cell: "/participant.html", red_cell: "/red.html" };

  async function doJoin() {
    const err = $("joinErr"); err.hidden = true;
    const code = $("joinCode").value.trim().toUpperCase();
    const cell = $("joinCell").value;
    const display_name = $("joinName").value.trim();
    if (!code) { err.textContent = "Enter a join code."; err.hidden = false; return; }
    try {
      const res = await fetch("/api/join", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token() ? { Authorization: `Bearer ${token()}` } : {}) },
        body: JSON.stringify({ code, cell, display_name: display_name || null }),
      });
      if (res.status === 401) { location.href = "/index.html"; return; }
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(typeof j.detail === "string" ? j.detail : "Could not join");
      }
      const joined = await res.json();
      // Joined — go to the matching fog-of-war view, on this session.
      location.href = `${DEST[joined.cell] || "/participant.html"}?session=${encodeURIComponent(joined.session_id)}`;
    } catch (e) { err.textContent = e.message; err.hidden = false; }
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/index.html"; return; }
    // Prefill the code from ?code= (e.g. a shared link / QR).
    const p = new URLSearchParams(location.search);
    if (p.get("code")) $("joinCode").value = p.get("code").toUpperCase();
    $("btnJoin").addEventListener("click", doJoin);
    $("joinCode").addEventListener("keydown", (e) => { if (e.key === "Enter") doJoin(); });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
