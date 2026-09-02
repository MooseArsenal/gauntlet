/* Gauntlet run-day mode (M3): the pre-brief the room reads before the first
 * inject, and a projector view of the current scene. Staff only; the
 * facilitator keeps driving from the console — this is the second screen.
 * Keys: B pre-brief · P projector · F full screen. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let sid = 0, view = "brief", socket = null, scenario = null, injects = [], bank = null;

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
    let t = "light"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  function setLive(on) { const p = $("livePill"); p.textContent = on ? "live" : "offline"; p.className = "pill " + (on ? "running" : "paused"); }

  function setView(v) {
    view = v;
    $("briefView").hidden = v !== "brief";
    $("projView").hidden = v !== "projector";
    $("brandSub").textContent = v === "brief" ? "Pre-brief" : "Projector";
    $("stripLeft").textContent = v === "brief" ? "Exercise control · Pre-brief" : "Exercise control · Projector";
    const u = new URL(location.href); u.searchParams.set("view", v); history.replaceState(null, "", u);
    refresh();
  }
  function fullScreen() {
    document.body.classList.toggle("rd-full");
    try { if (document.body.classList.contains("rd-full")) document.documentElement.requestFullscreen?.(); else document.exitFullscreen?.(); } catch (e) { /* noop */ }
  }

  function header(session, inj) {
    $("statusPill").textContent = session.status; $("statusPill").className = "pill " + session.status;
    $("sessName").textContent = session.name;
    $("clock").textContent = inj ? inj.clock || "T+00:00" : (session.status === "setup" ? "T+00:00" : "—");
  }

  async function loadScenario(id) {
    if (scenario && scenario.id === id) return scenario;
    scenario = await api(`/api/scenarios/${id}`);
    injects = scenario.injects || [];
    return scenario;
  }

  async function refresh() {
    if (!sid) return;
    try {
      const state = await api(`/api/sessions/${sid}`);
      await loadScenario(state.session.scenario_id);
      header(state.session, state.current_inject);
      if (view === "brief") renderBrief(state); else await renderProjector(state);
    } catch (e) { toast(e.message); }
  }

  function renderBrief(state) {
    const s = state.session;
    $("bfName").textContent = s.name;
    $("bfScenario").innerHTML = `${esc(scenario.name)} · <b>${esc(scenario.threat_actor || "")}</b> · ${esc(scenario.exercise_type || "tabletop")}`;
    $("bfRoe").textContent = scenario.rules_of_engagement || "Facilitated exercise only. 'Pause' halts play at any time. No production access. All actions are simulated.";
    $("bfScope").textContent = scenario.scope || "Discussion-based tabletop. No live systems are touched.";
    $("bfObjectives").innerHTML = (scenario.objectives || []).map((o) =>
      `<li><b>${esc(o.code)}</b>${esc(o.title)}</li>`).join("") || "<li class='muted'>No objectives declared.</li>";
    const cells = (scenario.cells && scenario.cells.length) ? scenario.cells :
      [{ key: "blue_cell", name: "Blue cell", kind: "participant" }, { key: "red_cell", name: "Red cell", kind: "participant" }, { key: "white_cell", name: "White cell", kind: "control" }];
    $("bfCells").innerHTML = cells.map((c) => `<li><span>${esc(c.name || c.key)}</span><span class="kind">${esc(c.kind || "")}</span></li>`).join("");
    $("btnStart").hidden = s.status !== "setup";
    $("btnStart").textContent = "Start exercise";
    api(`/api/sessions/${sid}/lobby`).then((rows) => {
      $("bfCount").textContent = rows.length ? `· ${rows.length} joined` : "";
      $("bfLobby").innerHTML = rows.map((r) => `<li><span>${esc(r.display_name || "someone")}</span><span class="pill">${esc(r.cell.replace("_", " "))}</span></li>`).join("") ||
        '<li class="muted">No one has joined yet.</li>';
    }).catch(() => { /* noop */ });
    // The join code is not on the summary; keep whatever was issued this page-load.
    $("bfJoinUrl").textContent = `${location.origin}/join.html`;
  }

  async function issueCode() {
    try { const j = await api(`/api/sessions/${sid}/join-code`, "POST"); $("bfCode").textContent = j.join_code; toast("Join code issued."); }
    catch (e) { toast(e.message); }
  }

  async function start() {
    try { await api(`/api/sessions/${sid}/start`, "POST"); toast("Exercise started."); setView("projector"); }
    catch (e) { toast(e.message); }
  }

  async function renderProjector(state) {
    const s = state.session;
    // The room sees what the blue cell may see — never the white cell's reasoning.
    let inj = null;
    try { const v = await api(`/api/sessions/${sid}/cell/blue_cell`); inj = v.current_inject; } catch (e) { inj = state.current_inject; }
    const box = $("scene");
    if (s.status === "setup") {
      box.innerHTML = `<p class="muted">The exercise has not started. Use the pre-brief (B) until the facilitator starts it.</p>`;
    } else if (!inj) {
      box.innerHTML = `<p class="muted">Nothing is on screen for the room right now. Stand by.</p>`;
    } else {
      box.innerHTML =
        `<div class="scene-head"><span class="chan">${esc(inj.channel)}</span><span class="code">${esc(inj.code)}</span><span class="gc">${esc(inj.clock)}</span></div>` +
        `<h2>${esc(inj.title)}</h2><p class="narrative">${esc(inj.narrative)}</p>` +
        ((inj.expected_actions || []).length ? `<span class="lbl">Consider</span><ul>${inj.expected_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>` : "");
    }
    $("pausedBanner").hidden = s.status !== "paused";
    $("doneBanner").hidden = s.status !== "complete";
    // kill-chain journey map, shared with the console
    try {
      if (!bank) { try { bank = await api("/api/catalog/injects"); } catch (e) { bank = []; } }
      const fired = new Set((state.timeline || []).filter((e) => e.kind === "inject_fired").map((e) => e.ref));
      if (inj) fired.add(inj.code);
      if (window.KillChain) window.KillChain.render($("kc"), { injects, bank, mode: "live", currentCode: inj ? inj.code : null, firedCodes: fired });
    } catch (e) { $("kc").innerHTML = ""; }
    // tally
    const tl = state.timeline || [];
    const adj = tl.filter((e) => e.kind === "adjudication" || e.kind === "red_action");
    $("tDetected").textContent = adj.filter((e) => e.payload && e.payload.detected).length;
    $("tMissed").textContent = adj.filter((e) => !(e.payload && e.payload.detected)).length;
    $("tInjects").textContent = tl.filter((e) => e.kind === "inject_fired").length;
    $("feed").innerHTML = tl.slice().reverse().slice(0, 12).map((e) => {
      const p = e.payload || {};
      let text = esc(e.kind);
      if (e.kind === "inject_fired") text = `<b>${esc(e.ref)}</b> ${esc(p.title || "")}`;
      else if (e.kind === "adjudication" || e.kind === "red_action") text = `${(p.techniques || []).map(esc).join(", ") || "move"} → <span class="${p.detected ? "v-detected" : "v-missed"}">${p.detected ? "detected" : "missed"}</span>`;
      else if (e.kind === "status") text = `Exercise ${esc(p.status || "")}`;
      else if (e.kind === "decision") text = `Decision → ${esc(p.label || p.goto || "")}`;
      else if (e.kind === "note") return "";
      return `<li class="k-${esc(e.kind)}"><span class="tclock">${esc(e.game_clock || "--:--")}</span>${text}</li>`;
    }).join("") || '<li class="muted">No updates yet.</li>';
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
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    try {
      socket = new WebSocket(`${scheme}://${location.host}/ws/sessions/${s}?ticket=${encodeURIComponent(ticket)}`);
      socket.onopen = () => setLive(true);
      socket.onmessage = (ev) => { try { if (JSON.parse(ev.data).type === "changed") refresh(); } catch (e) { /* noop */ } };
      socket.onclose = () => { setLive(false); setTimeout(() => subscribe(s), 2000); };
    } catch (e) { setLive(false); }
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    const q = new URLSearchParams(location.search);
    sid = Number(q.get("session")) || 0;
    if (!sid) { toast("Open this page from an exercise in the console."); return; }
    $("btnBrief").addEventListener("click", () => setView("brief"));
    $("btnProjector").addEventListener("click", () => setView("projector"));
    $("btnFull").addEventListener("click", fullScreen);
    $("btnIssueCode").addEventListener("click", issueCode);
    $("btnStart").addEventListener("click", start);
    $("btnConsole").href = `/?session=${sid}`;
    document.addEventListener("keydown", (e) => {
      if (e.target && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
      if (e.key === "b" || e.key === "B") setView("brief");
      else if (e.key === "p" || e.key === "P") setView("projector");
      else if (e.key === "f" || e.key === "F") fullScreen();
    });
    setView(q.get("view") === "projector" ? "projector" : "brief");
    subscribe(sid);
  }
  document.addEventListener("DOMContentLoaded", init);
})();
