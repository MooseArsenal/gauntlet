/* Partner mode (L2): list, create and enter client organisations. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function toast(m) { const el = $("toast"); el.textContent = m; el.hidden = false; clearTimeout(el._t); el._t = setTimeout(() => (el.hidden = true), 2600); }
  function initTheme() {
    let t = "light"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  async function api(path, method = "GET", body) {
    const t = token(); const headers = t ? { Authorization: `Bearer ${t}` } : {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in via the console."); }
    if (!res.ok) { let d = res.statusText; try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : d; } catch (e) { /* noop */ } throw new Error(d); }
    return res.status === 204 ? null : res.json();
  }
  async function load() {
    try {
      const out = await api("/api/partner/clients");
      $("lead").textContent = `${out.partner} runs exercises for ${out.clients.length} client organisation${out.clients.length === 1 ? "" : "s"}.`;
      $("addPanel").hidden = false; $("listPanel").hidden = false;
      $("count").textContent = `— ${out.clients.length}`;
      $("clients").innerHTML = out.clients.length
        ? `<table class="dfields"><thead><tr><th>Client</th><th>Since</th><th></th></tr></thead><tbody>` +
          out.clients.map((c) => `<tr><td><b>${esc(c.name)}</b> <span class="hint">${esc(c.slug)}</span></td><td>${esc(new Date(c.created_at).toLocaleDateString())}</td>` +
            `<td><button class="btn small" data-enter="${c.id}">Enter</button> <button class="btn ghost small" data-unlink="${c.id}">Unlink</button></td></tr>`).join("") + `</tbody></table>`
        : '<p class="muted">No clients yet.</p>';
      $("clients").querySelectorAll("[data-enter]").forEach((b) => b.addEventListener("click", () => enter(Number(b.dataset.enter))));
      $("clients").querySelectorAll("[data-unlink]").forEach((b) => b.addEventListener("click", async () => {
        if (!confirm("Unlink this client? Your partner accounts inside it are deactivated; its data stays.")) return;
        try { await api(`/api/partner/clients/${b.dataset.unlink}`, "DELETE"); toast("Unlinked."); load(); } catch (e) { toast(e.message); }
      }));
    } catch (e) { $("lead").textContent = e.message; }
  }
  async function enter(id) {
    try {
      const out = await api(`/api/partner/clients/${id}/enter`, "POST");
      try {
        localStorage.setItem("gauntlet-partner-token", token());
        localStorage.setItem("gauntlet-token", out.access_token);
        if (out.refresh_token) localStorage.setItem("gauntlet-refresh", out.refresh_token);
      } catch (e) { /* noop */ }
      location.href = "/";
    } catch (e) { toast(e.message); }
  }
  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    $("btnAdd").addEventListener("click", async () => {
      const name = $("clientName").value.trim(); if (!name) return;
      try { await api("/api/partner/clients", "POST", { name }); $("clientName").value = ""; toast("Client created."); load(); } catch (e) { toast(e.message); }
    });
    load();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
