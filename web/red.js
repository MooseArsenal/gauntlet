/* Gauntlet red-cell view — submit adversary moves, see instantly whether the
 * blue cell's controls detect them (the core learning loop), live over the WS.
 * Submitting a move needs an evaluator+ account (same guard as the API). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let sessions = [];
  let socket = null;

  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  async function api(path, method = "GET", body) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    const t = token();
    if (t) headers["Authorization"] = `Bearer ${t}`;
    const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in via the console."); }
    if (!res.ok) {
      let d = res.statusText; try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail || j); } catch (e) { /* noop */ }
      throw new Error(d);
    }
    return res.status === 204 ? null : res.json();
  }
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
  function setLive(on) { const p = $("livePill"); p.textContent = on ? "live" : "offline"; p.className = "pill " + (on ? "running" : "paused"); }
  function sid() { return Number($("sessionSel").value); }

  const STAFF = ["admin", "facilitator", "evaluator"];
  async function loadSessions() {
    // H1: staff pick any session; a participant sees the sessions they joined
    // as the red cell (the server enforces the same rule on every call).
    const me = await api("/api/auth/me");
    if (STAFF.includes(me.role)) {
      sessions = await api("/api/sessions");
    } else {
      sessions = (await api("/api/sessions/mine")).filter((m) => m.cell === "red_cell").map((m) => m.session);
    }
    $("sessionSel").innerHTML = sessions.length
      ? sessions.map((s) => `<option value="${s.id}">${esc(s.name)} · ${esc(s.status)}</option>`).join("")
      : '<option value="">no sessions</option>';
    if (!sessions.length) {
      $("rcScore").innerHTML = '<p class="hint" style="grid-column:1/-1">You are not in a red cell yet. Ask your facilitator for a join code, then pick <b>Red cell</b> on <a href="/join.html">Join by code</a>.</p>';
      return;
    }
    const want = Number(new URLSearchParams(location.search).get("session")) || 0;
    if (want && sessions.some((s) => s.id === want)) $("sessionSel").value = String(want);
    await onSession();
  }

  async function onSession() {
    if (!sid()) return;
    // Suggest the current scene's techniques + default target (through the red
    // cell's own fog-of-war view — never the full session state).
    try {
      const state = await api(`/api/sessions/${sid()}/cell/red_cell`);
      const inj = state.current_inject;
      const techs = (inj && inj.attack_techniques) || [];
      $("rcQuick").innerHTML = techs.length
        ? `<span class="rc-hint">This scene:</span>` + techs.map((t) => `<button class="rc-chip" data-t="${esc(t)}">${esc(t)}</button>`).join("")
        : "";
      $("rcQuick").querySelectorAll(".rc-chip").forEach((b) => b.addEventListener("click", () => {
        const cur = $("rcTech").value.split(",").map((x) => x.trim()).filter(Boolean);
        const t = b.getAttribute("data-t");
        if (!cur.includes(t)) cur.push(t);
        $("rcTech").value = cur.join(", ");
      }));
      if (inj && inj.target_asset && !$("rcTarget").value) $("rcTarget").placeholder = `e.g. ${inj.target_asset} (current scene target)`;
    } catch (e) { $("rcQuick").innerHTML = ""; }
    subscribe(sid());
    await refresh();
  }

  async function refresh() {
    if (!sid()) return;
    try {
      const [sb, moves] = await Promise.all([
        api(`/api/sessions/${sid()}/scoreboard`),
        api(`/api/sessions/${sid()}/red-actions`),
      ]);
      renderScore(sb);
      renderLog(moves);
    } catch (e) { /* noop */ }
  }

  function renderScore(sb) {
    if (!sb || !sb.red_actions) { $("rcScore").innerHTML = '<p class="hint" style="grid-column:1/-1">No moves yet — run one to see how you do.</p>'; $("rcScoreTech").innerHTML = ""; return; }
    const evade = sb.red_actions ? Math.round((sb.missed / sb.red_actions) * 100) + "%" : "—";
    const tiles = [
      { k: "Evasion rate", v: evade, tone: "good" },
      { k: "Got through", v: sb.missed, tone: "good" },
      { k: "Caught", v: sb.detected, tone: "crit" },
      { k: "Moves", v: sb.red_actions, tone: "info" },
    ];
    $("rcScore").innerHTML = tiles.map((t) =>
      `<div class="stile ${t.tone}"><span class="v">${esc(String(t.v))}</span><span class="k">${esc(t.k)}</span></div>`).join("");
    const tech = (sb.by_technique || []).filter((r) => r.technique && r.technique !== "(unspecified)");
    $("rcScoreTech").innerHTML = !tech.length ? "" :
      `<p class="score-lbl">Caught by technique</p>` + tech.map((r) => {
        const pct = r.attempts ? Math.round((r.detected / r.attempts) * 100) : 0;
        return `<div class="tcov"><span class="tt">${esc(r.technique)}</span>` +
          `<span class="bar"><span class="fill fill-crit" style="width:${pct}%"></span></span>` +
          `<span class="n">${r.detected}/${r.attempts}</span></div>`;
      }).join("");
  }

  function renderLog(moves) {
    $("rcLog").innerHTML = (moves || []).slice().reverse().map((e) => {
      const p = e.payload || {};
      const caught = p.detected;
      return `<li class="k-red"><span class="tclock">${esc(e.game_clock || "--:--")}</span>` +
        `<b>${esc((p.techniques || []).join(", ") || "move")}</b> → ` +
        `<span class="${caught ? "v-detected" : "v-missed"}">${caught ? "caught" : "through"}</span></li>`;
    }).join("") || '<li class="muted">No moves yet.</li>';
  }

  async function submitMove() {
    const techniques = $("rcTech").value.split(",").map((t) => t.trim()).filter(Boolean);
    const target = $("rcTarget").value.trim();
    if (!techniques.length) { toast("Add at least one technique."); return; }
    try {
      const out = await api(`/api/sessions/${sid()}/red-actions`, "POST",
        { action: "red-cell move", techniques, target });
      renderVerdict(out.ruling);
      await refresh();
    } catch (e) { toast(e.message); }
  }

  function renderVerdict(r) {
    const box = $("rcVerdict");
    box.hidden = false;
    const caught = r.detected;
    box.className = "rc-verdict " + (caught ? "caught" : "through");
    const controls = (r.controls_hit || []).map((c) =>
      `<span class="rc-ctl">${esc(c.name)}${c.deception ? " ⚑" : ""}</span>`).join("");
    box.innerHTML = (window.GauntletGame ? window.GauntletGame.diceHtml(r) : "") +
      `<div class="rc-vhead"><span class="rc-vtag">${caught ? "CAUGHT" : "UNDETECTED"}</span>` +
      `<span class="rc-vsub">${caught ? (r.time_to_detect_min != null ? "detected in " + r.time_to_detect_min + " min" : "detected") : "you got through"}</span></div>` +
      `<p class="rc-vrat">${esc(r.rationale || "")}</p>` +
      (controls ? `<div class="rc-ctls">${controls}</div>` : "");
  }

  async function wsTicket(s) {
    const t = token();
    const res = await fetch(`/api/sessions/${s}/ws-ticket`, { method: "POST", headers: t ? { Authorization: `Bearer ${t}` } : {} });
    if (!res.ok) throw new Error("ticket");
    return (await res.json()).ticket;
  }

  async function subscribe(s) {
    if (socket) { try { socket.onclose = null; socket.close(); } catch (e) { /* noop */ } }
    let ticket;
    try { ticket = await wsTicket(s); } catch (e) { setLive(false); return; }
    if (sid() !== s) return;
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    try {
      socket = new WebSocket(`${scheme}://${location.host}/ws/sessions/${s}?ticket=${encodeURIComponent(ticket)}`);
      socket.onopen = () => setLive(true);
      socket.onmessage = (ev) => { try { if (JSON.parse(ev.data).type === "changed") { refresh(); onSuggest(); } } catch (e) { /* noop */ } };
      socket.onclose = () => { setLive(false); if (sid() === s) setTimeout(() => subscribe(s), 2000); };
    } catch (e) { setLive(false); }
  }
  async function onSuggest() { /* refresh scene technique suggestions quietly */
    try { const state = await api(`/api/sessions/${sid()}/cell/red_cell`); const inj = state.current_inject;
      const techs = (inj && inj.attack_techniques) || [];
      if (techs.length) {
        $("rcQuick").innerHTML = `<span class="rc-hint">This scene:</span>` + techs.map((t) => `<button class="rc-chip" data-t="${esc(t)}">${esc(t)}</button>`).join("");
        $("rcQuick").querySelectorAll(".rc-chip").forEach((b) => b.addEventListener("click", () => {
          const cur = $("rcTech").value.split(",").map((x) => x.trim()).filter(Boolean);
          const t = b.getAttribute("data-t"); if (!cur.includes(t)) cur.push(t); $("rcTech").value = cur.join(", ");
        }));
      }
    } catch (e) { /* noop */ }
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    $("sessionSel").addEventListener("change", onSession);
    $("rcSubmit").addEventListener("click", submitMove);
    loadSessions();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
