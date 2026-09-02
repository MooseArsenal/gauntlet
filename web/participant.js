/* Gauntlet participant view — read-only fog-of-war, live over WebSocket.
 *
 * H1: which cell you see through is decided by the server. Staff pick any
 * session and any cell; a participant sees the sessions they joined by code,
 * through the cell they joined as — the selector is informational for them. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const STAFF = ["admin", "facilitator", "evaluator"];
  let sessions = [];
  let joinedCell = {};      // session id -> the cell this user joined as
  let staff = false;
  let scenarioCache = {};
  let socket = null;

  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  async function api(path, method = "GET", body) {
    const t = token();
    const headers = t ? { Authorization: `Bearer ${t}` } : {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in via the console."); }
    if (!res.ok) {
      let d = res.statusText;
      try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : d; } catch (e) { /* noop */ }
      throw new Error(d);
    }
    return res.json();
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
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
  function wantedSession() {
    const p = new URLSearchParams(location.search);
    return Number(p.get("session")) || 0;
  }

  async function loadSessions() {
    const me = await api("/api/auth/me");
    staff = STAFF.includes(me.role);
    if (staff) {
      sessions = await api("/api/sessions");
    } else {
      const mine = await api("/api/sessions/mine");
      sessions = mine.map((m) => m.session);
      joinedCell = Object.fromEntries(mine.map((m) => [m.session.id, m.cell]));
    }
    $("sessionSel").innerHTML = sessions.length
      ? sessions.map((s) => `<option value="${s.id}">${esc(s.name)} · ${esc(s.status)}</option>`).join("")
      : '<option value="">no sessions</option>';
    if (!sessions.length) {
      $("scene").innerHTML = staff
        ? '<p class="muted">No sessions yet.</p>'
        : '<p class="muted">You have not joined an exercise yet. Ask your facilitator for a join code, then use <a href="/join.html">Join by code</a>.</p>';
      return;
    }
    const want = wantedSession();
    if (want && sessions.some((s) => s.id === want)) $("sessionSel").value = String(want);
    await onSession();
  }

  async function onSession() {
    const sid = Number($("sessionSel").value);
    const session = sessions.find((s) => s.id === sid);
    if (!session) return;
    if (staff) {
      if (!scenarioCache[session.scenario_id]) {
        scenarioCache[session.scenario_id] = await api(`/api/scenarios/${session.scenario_id}`);
      }
      const cells = (scenarioCache[session.scenario_id].cells || [])
        .filter((c) => c.kind !== "control");  // the participant page shows participant cells
      $("cellSel").innerHTML = cells.length
        ? cells.map((c) => `<option value="${esc(c.key)}">${esc(c.name)}</option>`).join("")
        : '<option value="blue_cell">Participants</option>';
      $("cellSel").disabled = false;
    } else {
      const cell = joinedCell[sid] || "blue_cell";
      const label = cell.replace("_cell", "").replace(/^\w/, (c) => c.toUpperCase());
      $("cellSel").innerHTML = `<option value="${esc(cell)}">${esc(label)} cell (you)</option>`;
      $("cellSel").disabled = true;
    }
    const strip = document.querySelector(".strip span");
    if (strip) {
      const cell = $("cellSel").value || "";
      strip.textContent = `Exercise control · Participant view · ${cell.replace("_cell", "").replace(/^\w/, (c) => c.toUpperCase())} cell`;
    }
    subscribe(sid);
    await loadView();
  }

  async function loadView() {
    const sid = Number($("sessionSel").value);
    const cell = $("cellSel").value;
    if (!sid || !cell) return;
    try {
      const view = await api(`/api/sessions/${sid}/cell/${encodeURIComponent(cell)}`);
      renderScene(view.current_inject);
      renderDecision(view, sid);
      renderFeed(view.timeline);
      renderAttendance(view, sid);
    } catch (e) {
      $("scene").innerHTML = `<p class="muted">${esc(e.message)}</p>`;
      $("feed").innerHTML = "";
    }
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

  // P1: the decision card — answer once, from your own device; the proctor
  // sees the tally and still makes the ruling.
  let decisionTimer = null;
  function renderDecision(view, sid) {
    const box = $("decision"); if (!box) return;
    clearInterval(decisionTimer);
    const d = view.decision, inj = view.current_inject, mine = view.my_response;
    if (!d || !inj) { box.hidden = true; box.innerHTML = ""; return; }
    box.hidden = false;
    if (mine) {
      box.innerHTML = `<p class="eyebrow">Your decision · ${esc(inj.code)}</p>` +
        `<p class="dc-done"><b>${esc(mine.label || mine.text || "")}</b>` +
        (mine.latency_sec != null ? ` <span class="hint">recorded after ${esc(String(mine.latency_sec))} s</span>` : "") + `</p>` +
        `<p class="hint">Recorded on the exercise timeline. The proctor decides what happens next.</p>`;
      return;
    }
    const opts = (d.options || []).map((o) =>
      `<button class="dc-opt" data-k="${esc(o.key)}"><span class="dc-key">${esc(o.key.toUpperCase())}</span>${esc(o.label)}</button>`).join("");
    box.innerHTML = `<p class="eyebrow">${d.kind === "comms" ? "Communications decision" : "Decision"} · ${esc(inj.code)}${d.time_limit_sec ? ` <span class="hint" id="dcClock"></span>` : ""}</p>` +
      `<p class="dc-prompt">${esc(d.prompt)}</p><div class="dc-opts">${opts}</div>` +
      (d.free_text ? `<textarea id="dcText" rows="${d.kind === "comms" ? 5 : 3}" placeholder="${d.kind === "comms" ? "Draft the statement you would issue (required)…" : opts ? "Or write what you would do…" : "What does your team do first?"}"></textarea><button class="btn primary" id="dcSend">${d.kind === "comms" ? "Issue statement" : "Submit decision"}</button>` : "") +
      `<p class="loginerr" id="dcErr" hidden></p>`;
    const send = async (option, text) => {
      try {
        await api(`/api/sessions/${sid}/respond`, "POST", { option: option || null, text: text || "", inject_code: inj.code });
        toast("Decision recorded."); await loadView();
      } catch (e) { $("dcErr").textContent = e.message; $("dcErr").hidden = false; }
    };
    let picked = null;
    box.querySelectorAll(".dc-opt").forEach((b) => b.addEventListener("click", () => {
      if (d.kind !== "comms") { send(b.dataset.k, ""); return; }
      picked = b.dataset.k; box.querySelectorAll(".dc-opt").forEach((x) => x.classList.toggle("on", x === b));
    }));
    const sendBtn = $("dcSend");
    if (sendBtn) sendBtn.addEventListener("click", () => send(picked, $("dcText").value.trim()));
    if (d.time_limit_sec) {
      const fired = (view.timeline || []).filter((e) => e.kind === "inject_fired" && e.ref === inj.code).pop();
      const t0 = fired ? new Date(fired.at).getTime() : Date.now();
      const tick = () => {
        const left = Math.max(0, Math.round(d.time_limit_sec - (Date.now() - t0) / 1000));
        const el = $("dcClock"); if (el) el.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left`;
        if (left <= 0) clearInterval(decisionTimer);
      };
      tick(); decisionTimer = setInterval(tick, 1000);
    }
  }

  // P6: once the exercise is complete and certified, your own certificate.
  function renderAttendance(view, sid) {
    const box = $("attendance"); if (!box) return;
    if (view.session.status !== "complete") { box.hidden = true; return; }
    box.hidden = false;
    box.innerHTML = `<p class="eyebrow">Your participation</p><p class="hint">When the facilitator has issued the exercise certificate, download your own certificate of participation.</p><button class="btn" id="btnMyCert">My certificate (PDF)</button>`;
    $("btnMyCert").addEventListener("click", async () => {
      try {
        const t = token();
        const res = await fetch(`/api/sessions/${sid}/my-attendance.pdf`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
        if (!res.ok) { let d = "Not available yet."; try { d = (await res.json()).detail || d; } catch (e) { /* noop */ } throw new Error(d); }
        const url = URL.createObjectURL(await res.blob()); const a = document.createElement("a");
        a.href = url; a.download = "my-certificate.pdf"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 4000);
      } catch (e) { toast(e.message); }
    });
  }

  function renderFeed(events) {
    $("feed").innerHTML = events.slice().reverse().map((e) => {
      const p = e.payload || {};
      let text = esc(e.kind);
      if (e.kind === "inject_fired") text = `<b>${esc(e.ref)}</b> ${esc(p.title || "")}`;
      else if (e.kind === "status") text = `Exercise ${esc(p.status || "")}`;
      return `<li class="k-${esc(e.kind)}"><span class="tclock">${esc(e.game_clock || "--:--")}</span>${text}</li>`;
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
    loadSessions().catch((e) => { $("scene").innerHTML = `<p class="muted">${esc(e.message)}</p>`; });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
