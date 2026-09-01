/* Gauntlet participant view — read-only fog-of-war, live over WebSocket. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let sessions = [];
  let scenarioCache = {};
  let socket = null;

  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  async function api(path) {
    const t = token();
    const res = await fetch(path, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in via the console."); }
    if (!res.ok) throw new Error(res.statusText);
    return res.json();
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "dark"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  function setLive(on) {
    const p = $("livePill");
    p.textContent = on ? "live" : "offline";
    p.className = "pill " + (on ? "running" : "paused");
  }

  async function loadSessions() {
    sessions = await api("/api/sessions");
    $("sessionSel").innerHTML = sessions.length
      ? sessions.map((s) => `<option value="${s.id}">${esc(s.name)} · ${s.status}</option>`).join("")
      : '<option value="">no sessions</option>';
    if (sessions.length) await onSession();
  }

  async function onSession() {
    const sid = Number($("sessionSel").value);
    const session = sessions.find((s) => s.id === sid);
    if (!session) return;
    if (!scenarioCache[session.scenario_id]) {
      scenarioCache[session.scenario_id] = await api(`/api/scenarios/${session.scenario_id}`);
    }
    const cells = (scenarioCache[session.scenario_id].cells || [])
      .filter((c) => c.kind !== "control");  // participants aren't the White Cell
    $("cellSel").innerHTML = cells.length
      ? cells.map((c) => `<option value="${c.key}">${esc(c.name)}</option>`).join("")
      : '<option value="blue_cell">Participants</option>';
    subscribe(sid);
    await loadView();
  }

  async function loadView() {
    const sid = Number($("sessionSel").value);
    const cell = $("cellSel").value;
    if (!sid || !cell) return;
    const view = await api(`/api/sessions/${sid}/cell/${cell}`);
    renderScene(view.current_inject);
    renderFeed(view.timeline);
  }

  function renderScene(inj) {
    const box = $("scene");
    if (!inj) { box.innerHTML = '<p class="muted">Nothing has been sent to your cell yet. Stand by.</p>'; return; }
    box.innerHTML =
      `<div class="scene-head"><span class="chan">${esc(inj.channel)}</span>` +
      `<span class="code">${esc(inj.code)}</span><span class="gc">${esc(inj.clock)}</span></div>` +
      `<h2 style="font-size:1.3rem;margin:.2rem 0 .5rem">${esc(inj.title)}</h2>` +
      `<p class="narrative">${esc(inj.narrative)}</p>` +
      ((inj.expected_actions || []).length
        ? `<div class="scene-meta"><div><span class="lbl">Consider</span><ul>${
            inj.expected_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul></div></div>`
        : "");
  }

  function renderFeed(events) {
    $("feed").innerHTML = events.slice().reverse().map((e) => {
      const p = e.payload || {};
      let text = e.kind;
      if (e.kind === "inject_fired") text = `<b>${esc(e.ref)}</b> ${esc(p.title || "")}`;
      else if (e.kind === "status") text = `Exercise ${esc(p.status || "")}`;
      return `<li class="k-${e.kind}"><span class="tclock">${esc(e.game_clock || "--:--")}</span>${text}</li>`;
    }).join("") || '<li class="muted">No updates yet.</li>';
  }

  async function wsTicket(sid) {
    const t = token();
    const res = await fetch(`/api/sessions/${sid}/ws-ticket`, {
      method: "POST", headers: t ? { Authorization: `Bearer ${t}` } : {},
    });
    if (!res.ok) throw new Error("ticket");
    return (await res.json()).ticket;
  }

  async function subscribe(sid) {
    if (socket) { try { socket.onclose = null; socket.close(); } catch (e) { /* noop */ } }
    let ticket;
    try { ticket = await wsTicket(sid); }
    catch (e) { setLive(false); return; }
    if (Number($("sessionSel").value) !== sid) return;
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    try {
      socket = new WebSocket(`${scheme}://${location.host}/ws/sessions/${sid}?ticket=${encodeURIComponent(ticket)}`);
      socket.onopen = () => setLive(true);
      socket.onmessage = (ev) => { try { if (JSON.parse(ev.data).type === "changed") loadView(); } catch (e) { /* noop */ } };
      socket.onclose = () => { setLive(false); if (Number($("sessionSel").value) === sid) setTimeout(() => subscribe(sid), 2000); };
    } catch (e) { setLive(false); }
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    $("sessionSel").addEventListener("change", onSession);
    $("cellSel").addEventListener("change", loadView);
    loadSessions();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
