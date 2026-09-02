/* Gauntlet members page (U-1) — an admin's view of the organisation: add
 * people, change roles, deactivate leavers, reset a lost authenticator, clear
 * a lockout, sign someone out everywhere. Every action is audit-logged. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const ROLES = ["participant", "evaluator", "facilitator", "admin"];
  let me = null;
  let members = [];

  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function toast(m) { const el = $("toast"); el.textContent = m; el.hidden = false; clearTimeout(el._t); el._t = setTimeout(() => (el.hidden = true), 2600); }
  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  async function api(path, method = "GET", body) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    const t = token();
    if (t) headers["Authorization"] = `Bearer ${t}`;
    const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in via the console."); }
    if (!res.ok) {
      let d = res.statusText;
      try {
        const j = await res.json();
        d = typeof j.detail === "string" ? j.detail
          : (j.detail && j.detail.password) ? j.detail.password.join("; ")
          : JSON.stringify(j.detail || j);
      } catch (e) { /* noop */ }
      throw new Error(d);
    }
    return res.status === 204 ? null : res.json();
  }

  async function load() {
    me = await api("/api/auth/me");
    if (me.role !== "admin") {
      $("memLead").textContent = "Only an organisation admin can manage members.";
      return;
    }
    members = await api("/api/members");
    $("memLead").textContent = "Add people, set roles, deactivate leavers, and recover locked-out accounts.";
    $("addPanel").hidden = false; $("listPanel").hidden = false; $("scimPanel").hidden = false; $("licPanel").hidden = false; loadLicense();
    render();
  }

  function render() {
    const active = members.filter((m) => m.is_active).length;
    $("memCount").textContent = `— ${members.length} member${members.length === 1 ? "" : "s"}, ${active} active`;
    const head = '<div class="mem-row mem-head"><span>Member</span><span>Role</span><span>2FA</span><span>Status</span><span>Actions</span></div>';
    $("memTable").innerHTML = head + members.map((m) => {
      const self = m.id === me.id;
      const roleSel = `<select data-act="role" data-id="${m.id}" ${self ? "disabled" : ""}>` +
        ROLES.map((r) => `<option value="${r}" ${r === m.role ? "selected" : ""}>${r}</option>`).join("") + "</select>";
      const status = m.is_active ? '<span class="pill running">active</span>' : '<span class="pill paused">inactive</span>';
      const mfa = m.mfa_enabled ? '<span class="v-detected">on</span>' : '<span class="muted">off</span>';
      const acts = [
        !self ? `<button class="btn ghost small" data-act="${m.is_active ? "deactivate" : "activate"}" data-id="${m.id}">${m.is_active ? "Deactivate" : "Reactivate"}</button>` : '<span class="muted">(you)</span>',
        `<button class="btn ghost small" data-act="reset-mfa" data-id="${m.id}" title="Clear their authenticator so they re-enrol">Reset 2FA</button>`,
        `<button class="btn ghost small" data-act="unlock" data-id="${m.id}" title="Clear a login lockout">Unlock</button>`,
        `<button class="btn ghost small" data-act="password" data-id="${m.id}" title="Set a temporary password">Set password</button>`,
        `<button class="btn ghost small" data-act="revoke" data-id="${m.id}" title="Sign out of every device">Sign out all</button>`,
      ].join("");
      return `<div class="mem-row ${m.is_active ? "" : "mem-off"}">` +
        `<span class="mem-who"><b>${esc(m.email)}</b><small>${esc(m.name || "")}${m.sso_linked ? " · SSO" : ""}</small></span>` +
        `<span>${roleSel}</span><span>${mfa}</span><span>${status}</span><span class="mem-acts">${acts}</span></div>`;
    }).join("");
    $("memTable").querySelectorAll("[data-act]").forEach((el) => {
      const ev = el.tagName === "SELECT" ? "change" : "click";
      el.addEventListener(ev, () => act(el.getAttribute("data-act"), Number(el.getAttribute("data-id")), el));
    });
  }

  async function act(kind, id, el) {
    const m = members.find((x) => x.id === id);
    if (!m) return;
    try {
      if (kind === "role") {
        await api(`/api/members/${id}`, "PATCH", { role: el.value });
        toast(`${m.email} is now ${el.value}.`);
      } else if (kind === "deactivate" || kind === "activate") {
        if (kind === "deactivate" && !confirm(`Deactivate ${m.email}? They are signed out everywhere and cannot sign in again until reactivated.`)) return;
        await api(`/api/members/${id}`, "PATCH", { is_active: kind === "activate" });
        toast(kind === "activate" ? `${m.email} reactivated.` : `${m.email} deactivated.`);
      } else if (kind === "reset-mfa") {
        if (!confirm(`Reset two-factor for ${m.email}? They will be signed out and must enrol again.`)) return;
        await api(`/api/members/${id}/reset-mfa`, "POST");
        toast("Two-factor cleared.");
      } else if (kind === "unlock") {
        await api(`/api/members/${id}/unlock`, "POST");
        toast("Lockout cleared.");
      } else if (kind === "password") {
        const pw = prompt(`Temporary password for ${m.email} (at least 10 characters):`);
        if (!pw) return;
        await api(`/api/members/${id}/set-password`, "POST", { password: pw });
        toast("Password set; they are signed out everywhere.");
      } else if (kind === "revoke") {
        await api(`/api/members/${id}/revoke-sessions`, "POST");
        toast("Signed out of every device.");
      }
      members = await api("/api/members");
      render();
    } catch (e) { toast(e.message); members = await api("/api/members").catch(() => members); render(); }
  }

  async function add() {
    const err = $("addErr"); err.hidden = true;
    try {
      await api("/api/auth/users", "POST", {
        email: $("addEmail").value.trim(), name: $("addName").value.trim(),
        role: $("addRole").value, password: $("addPassword").value,
      });
      $("addEmail").value = ""; $("addName").value = ""; $("addPassword").value = "";
      toast("Member added.");
      members = await api("/api/members"); render();
    } catch (e) { err.textContent = e.message; err.hidden = false; }
  }

  // L1: what this deployment is entitled to, and where to put a licence.
  async function loadLicense() {
    let lic;
    try { lic = await api("/api/license"); } catch (e) { return; }
    const state = lic.state === "active" ? `${lic.tier} · ${lic.customer || ""} · expires ${lic.exp} (${lic.days_left} days)`
      : lic.state === "grace" ? `${lic.tier} · EXPIRED ${-lic.days_left} days ago — ${lic.grace_days + lic.days_left} days of grace left`
      : lic.state === "expired" ? "expired — running as Community" : lic.state === "invalid" ? `invalid licence: ${lic.error}` : "Community (no licence)";
    $("licState").textContent = "— " + state;
    $("licGrid").innerHTML = lic.all_features.map((f) =>
      `<span class="lic-feat ${lic.features.includes(f) ? "on" : ""}">${lic.features.includes(f) ? "✓" : "○"} ${esc(lic.labels[f] || f)}</span>`).join("");
    const brandOn = lic.features.includes("white_label");
    $("brandPanel").hidden = false;
    $("brandPanel").querySelector(".eyebrow").innerHTML = `Branding ${brandOn ? '<span class="hint">— your name, colour and logo on the console and every PDF</span>' : '<span class="pill">Team</span> <span class="hint">— not in this deployment\'s tier</span>'}`;
    $("brandPanel").querySelectorAll("input,button").forEach((el) => { el.disabled = !brandOn; });
    if (brandOn) {
      try { const b = await api("/api/branding"); if (b.custom) { $("brName").value = b.name; $("brTag").value = b.tagline || ""; $("brAccent").value = b.accent || "#d9480f"; $("brFooter").value = b.footer || ""; } } catch (e) { /* noop */ }
    }
    const lnk = $("lnkPartner"); if (lnk) lnk.hidden = !lic.features.includes("partner_mode");
    const scimOn = lic.features.includes("scim");
    const scimPanel = $("scimPanel");
    if (scimPanel) scimPanel.querySelector(".eyebrow").innerHTML = `SCIM provisioning ${scimOn ? '<span class="hint">— let the identity provider create and deactivate members</span>' : '<span class="pill">Enterprise</span> <span class="hint">— not in this deployment\'s tier</span>'}`;
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    $("btnAdd").addEventListener("click", add);
    // M5: SCIM token lifecycle — shown once, hash-only at rest.
    $("btnBrandSave").addEventListener("click", async () => {
      let logo = "";
      const f = $("brLogo").files[0];
      if (f) {
        if (f.size > 64 * 1024) { toast("Logo must be under 64 KB."); return; }
        logo = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.onerror = rej; r.readAsDataURL(f); });
      }
      try {
        await api("/api/admin/branding", "PUT", { name: $("brName").value.trim(), tagline: $("brTag").value.trim(), accent: $("brAccent").value, footer: $("brFooter").value.trim(), logo });
        toast("Branding saved."); if (window.GauntletBrand) window.GauntletBrand.apply();
      } catch (e) { toast(e.message); }
    });
    $("btnBrandClear").addEventListener("click", async () => {
      try { await api("/api/admin/branding", "DELETE"); toast("Branding reset."); location.reload(); } catch (e) { toast(e.message); }
    });
    $("btnLicInstall").addEventListener("click", async () => {
      const token = $("licToken").value.trim(); if (!token) { toast("Paste a licence token."); return; }
      try { await api("/api/admin/license", "POST", { token }); $("licToken").value = ""; toast("Licence installed."); loadLicense(); }
      catch (e) { toast(e.message); }
    });
    $("btnLicRemove").addEventListener("click", async () => {
      try { await api("/api/admin/license", "DELETE"); toast("Licence removed — running as Community."); loadLicense(); }
      catch (e) { toast(e.message); }
    });
    $("btnScimMint").addEventListener("click", async () => {
      try {
        const out = await api("/api/admin/scim-token", "POST");
        $("scimBase").value = out.base_url; $("scimToken").value = out.token; $("scimOut").hidden = false;
        toast("SCIM token minted — copy it now.");
      } catch (e) { toast(e.message); }
    });
    $("btnScimRevoke").addEventListener("click", async () => {
      try { await api("/api/admin/scim-token", "DELETE"); $("scimOut").hidden = true; toast("SCIM token revoked."); }
      catch (e) { toast(e.message); }
    });
    load().catch((e) => { $("memLead").textContent = e.message; });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
