/* Gauntlet facilitator console — vanilla SPA over the Gauntlet API. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  let currentSid = null;
  let currentUser = null;   // set on sign-in / session restore; drives role-gated UI
  let currentInjectId = null;
  let selectedRating = "note";
  let detectStreak = 0;   // consecutive detections — a little momentum
  let objectives = [];

  // ---- auth tokens ------------------------------------------------------- //
  // Access token is short-lived; a rotating refresh token (M9) buys a new one
  // silently on 401 so the session survives past the access TTL.
  const TOKEN_KEY = "gauntlet-token";
  const REFRESH_KEY = "gauntlet-refresh";
  function getToken() { try { return localStorage.getItem(TOKEN_KEY) || ""; } catch (e) { return ""; } }
  function setToken(t) { try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); } catch (e) { /* noop */ } }
  function getRefresh() { try { return localStorage.getItem(REFRESH_KEY) || ""; } catch (e) { return ""; } }
  function setRefresh(t) { try { t ? localStorage.setItem(REFRESH_KEY, t) : localStorage.removeItem(REFRESH_KEY); } catch (e) { /* noop */ } }
  function setTokens(access, refresh) { setToken(access || ""); if (refresh !== undefined) setRefresh(refresh || ""); }
  function clearTokens() { setToken(""); setRefresh(""); }

  // Serialise refresh attempts so a burst of 401s triggers only one rotation.
  let refreshInflight = null;
  async function tryRefresh() {
    const rt = getRefresh();
    if (!rt) return false;
    if (!refreshInflight) {
      refreshInflight = (async () => {
        try {
          const res = await fetch("/api/auth/refresh", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refresh_token: rt }),
          });
          if (!res.ok) return false;
          const data = await res.json();
          setTokens(data.access_token, data.refresh_token);
          return true;
        } catch (e) { return false; }
        finally { refreshInflight = null; }
      })();
    }
    return refreshInflight;
  }

  // ---- api helper -------------------------------------------------------- //
  async function api(path, method = "GET", body, _retried) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(path, {
      method, headers, body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) {
      if (!_retried && await tryRefresh()) return api(path, method, body, true);
      clearTokens();
      showLogin();
      throw new Error("Please sign in.");
    }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (e) { /* noop */ }
      throw new Error(detail);
    }
    return res.status === 204 ? null : res.json();
  }

  function toast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(t._timer);
    t._timer = setTimeout(() => (t.hidden = true), 2600);
  }

  // ---- theme ------------------------------------------------------------- //
  function initTheme() {
    let t = "dark";
    try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("gauntlet-theme", next); } catch (e) { /* noop */ }
    });
  }

  // ---- auth views -------------------------------------------------------- //
  function showLogin() {
    $("loginView").hidden = false;
    const mfaEl = $("mfaView");
    if (mfaEl) mfaEl.hidden = true;
    $("emptyState").hidden = true;
    $("console").hidden = true;
    $("sessionMeta").hidden = true;
    $("userChip").hidden = true;
    $("btnNew").hidden = true;
    $("btnGuided").hidden = true;
    $("btnEditor").hidden = true;
    $("btnMembers").hidden = true;
    $("btnTour").hidden = true;
    ["btnPause", "btnResume", "btnVerify", "btnCertificate", "btnHotwash", "btnRunday"].forEach((id) => ($(id).hidden = true));
  }

  async function finishLogin(data) {
    setTokens(data.access_token, data.refresh_token);
    currentUser = data.user;
    $("userLabel").textContent = `${data.user.email} · ${data.user.role}`;
    $("loginView").hidden = true;
    const mfaEl = $("mfaView");
    if (mfaEl) mfaEl.hidden = true;
    await loadHome();
  }

  async function login() {
    const email = $("loginEmail").value.trim();
    const password = $("loginPassword").value;
    const err = $("loginErr");
    err.hidden = true;
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Sign in failed");
      const data = await res.json();
      if (data.mfa_required) { promptMfa(data.challenge); return; }
      await finishLogin(data);
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    }
  }

  // Second factor: show the code prompt, then exchange challenge + code.
  let mfaChallenge = null;
  function promptMfa(challenge) {
    mfaChallenge = challenge;
    const view = $("mfaView");
    if (!view) { toast("MFA required but this build has no code prompt."); return; }
    $("loginView").hidden = true;
    view.hidden = false;
    const codeEl = $("mfaCode");
    if (codeEl) { codeEl.value = ""; codeEl.focus(); }
  }

  async function submitMfa() {
    const err = $("mfaErr");
    if (err) err.hidden = true;
    try {
      const res = await fetch("/api/auth/login/mfa", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge: mfaChallenge, code: $("mfaCode").value.trim() }),
      });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Invalid code");
      await finishLogin(await res.json());
    } catch (e) {
      if (err) { err.textContent = e.message; err.hidden = false; } else { toast(e.message); }
    }
  }

  async function logout() {
    const rt = getRefresh();
    if (rt) { try { await fetch("/api/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: rt }) }); } catch (e) { /* noop */ } }
    clearTokens();
    showLogin();
  }

  // If we arrived back from an SSO redirect, tokens are in the URL fragment.
  function consumeSsoFragment() {
    if (!location.hash || location.hash.indexOf("sso_access=") === -1) return false;
    const p = new URLSearchParams(location.hash.slice(1));
    const access = p.get("sso_access");
    if (!access) return false;
    setTokens(access, p.get("sso_refresh") || "");
    // Scrub the tokens from the address bar / history.
    history.replaceState(null, "", location.pathname + location.search);
    return true;
  }

  // Show the "Sign in with SSO" button only when the server has OIDC configured.
  async function initSso() {
    const btn = $("btnSso");
    if (!btn) return;
    try {
      const cfg = await (await fetch("/api/auth/oidc/config")).json();
      btn.hidden = !cfg.enabled;
    } catch (e) { btn.hidden = true; }
    btn.addEventListener("click", () => { location.href = "/api/auth/oidc/login"; });
  }

  async function ensureAuthed() {
    if (!getToken()) { showLogin(); return false; }
    try {
      const me = await api("/api/auth/me");
      currentUser = me;
      $("userLabel").textContent = `${me.email} · ${me.role}`;
      return true;
    } catch (e) { showLogin(); return false; }
  }

  // ---- empty / setup ----------------------------------------------------- //
  async function loadHome() {
    currentSid = null;
    closeSocket();
    $("loginView").hidden = true;
    $("console").hidden = true;
    $("emptyState").hidden = false;
    $("sessionMeta").hidden = true;
    $("userChip").hidden = false;
    $("btnNew").hidden = false;
    $("btnGuided").hidden = false;
    $("btnEditor").hidden = false;
    $("btnMembers").hidden = !(currentUser && currentUser.role === "admin");  // U-1: admins manage members
    $("btnTour").hidden = false;
    ["btnPause", "btnResume", "btnVerify", "btnCertificate", "btnHotwash", "btnRunday"].forEach((id) => ($(id).hidden = true));

    const showArchived = $("showArchived") && $("showArchived").checked;
    const [scenarios, sessions] = await Promise.all([
      api("/api/scenarios"),
      api(`/api/sessions${showArchived ? "?include_archived=1" : ""}`),
    ]);
    $("archivedToggle").hidden = false;

    const sel = $("scenarioSel");
    sel.innerHTML = "";
    scenarios.forEach((s) => {
      const o = document.createElement("option");
      o.value = s.id;
      o.textContent = `${s.name} · ${s.exercise_type}`;
      sel.appendChild(o);
    });

    if (scenarios.length) {
      $("emptySub").textContent = "Choose a scenario and start, or pick up a recent exercise.";
      $("setupForm").hidden = false;
    } else {
      $("emptySub").textContent = "No scenarios yet. Build one on the right, or import a pack.";
    }

    const list = $("sessList");
    list.innerHTML = "";
    sessions.slice(0, showArchived ? 40 : 8).forEach((s) => {
      const li = document.createElement("li");
      const archived = !!s.archived_at;
      li.innerHTML = `<span><b>${escapeHtml(s.name)}</b> · <span class="pill ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span>${archived ? ' <span class="pill">archived</span>' : ""}</span>`;
      const acts = document.createElement("span");
      acts.className = "sess-acts";
      const btn = document.createElement("button");
      btn.className = "btn ghost";
      btn.textContent = s.status === "complete" ? "Review" : "Resume";
      btn.onclick = () => openSession(s.id);
      acts.appendChild(btn);
      // U-3: finished (or never started) exercises can be archived; archived ones restored.
      if (archived || s.status === "complete" || s.status === "setup") {
        const arc = document.createElement("button");
        arc.className = "btn ghost";
        arc.textContent = archived ? "Restore" : "Archive";
        arc.title = archived ? "Show it in lists again" : "Hide it from lists; nothing is deleted";
        arc.onclick = async () => {
          try { await api(`/api/sessions/${s.id}/${archived ? "unarchive" : "archive"}`, "POST"); toast(archived ? "Restored." : "Archived."); await loadHome(); }
          catch (e) { toast(e.message); }
        };
        acts.appendChild(arc);
      }
      li.appendChild(acts);
      list.appendChild(li);
    });

    await populateGenerator();
    if (window.GauntletTour) window.GauntletTour.maybeAuto();
  }

  async function populateGenerator() {
    try {
      const [envs, actors, templates] = await Promise.all([
        api("/api/environments"),
        api("/api/catalog/actors"),
        api("/api/catalog/templates"),
      ]);
      $("genBlock").hidden = false;
      // E1: with no environment yet the picker says so and the New button is the way in.
      $("genEnv").innerHTML = envs.length
        ? envs.map((e) => `<option value="${e.id}">${escapeHtml(e.name)}${e.sector ? " · " + escapeHtml(e.sector) : ""}</option>`).join("")
        : '<option value="">No environments yet — create one</option>';
      $("btnGenerate").disabled = !envs.length;

      const tOpts = templates.map((t) =>
        `<option value="tpl:${t.key}">Template · ${escapeHtml(t.name)}</option>`).join("");
      const aOpts = actors.map((a) =>
        `<option value="act:${a.key}">Actor · ${escapeHtml(a.name)} (${a.kill_chain.length} phases)</option>`).join("");
      $("genActor").innerHTML = tOpts + aOpts;

      try {
        const packs = await api("/api/catalog/ctep-packs");
        // M2: the pack library, grouped by sector.
        if ($("ctepSel")) {
          const bySector = {};
          packs.forEach((p) => { (bySector[p.sector || "Other"] = bySector[p.sector || "Other"] || []).push(p); });
          $("ctepSel").innerHTML = Object.keys(bySector).sort().map((sec) =>
            `<optgroup label="${escapeHtml(sec)}">` + bySector[sec].map((p) =>
              `<option value="${escapeHtml(p.key)}" data-env="${escapeHtml(p.environment_name || "")}" title="${escapeHtml(p.description || "")}">${escapeHtml(p.title)} (${p.modules} modules)</option>`).join("") +
            `</optgroup>`).join("");
          const hint = $("ctepHint");
          const showHint = () => {
            const o = $("ctepSel").selectedOptions[0];
            if (hint) hint.textContent = o && o.dataset.env ? `Written for “${o.dataset.env}” — import it there, or into the environment picked above.` : "";
          };
          $("ctepSel").onchange = showHint; showHint();
        }
      } catch (e) { /* noop */ }
    } catch (e) { /* generator is optional */ }
  }

  async function generateScenario() {
    const envId = Number($("genEnv").value);
    const pick = $("genActor").value;
    const name = $("genName").value.trim() || null;
    const body = { environment_id: envId, name };
    if (pick.startsWith("tpl:")) body.template_key = pick.slice(4);
    else body.actor_key = pick.slice(4);
    try {
      const scn = await api("/api/scenarios/generate", "POST", body);
      toast(`Generated "${scn.name}" — ${scn.injects.length} injects.`);
      await loadHome();
      // Preselect the freshly generated scenario for launch.
      $("scenarioSel").value = String(scn.id);
      $("sessInput").focus();
    } catch (e) { toast("Generate failed: " + e.message); }
  }

  // own=true (M2): import the pack into the library environment it was written
  // for, stamping that environment into the org if it is not there yet.
  async function importCtep(own) {
    const envId = own === true ? null : Number($("genEnv").value);
    const pack_key = $("ctepSel") ? $("ctepSel").value : "";
    if (!pack_key || (own !== true && !envId)) { toast("Pick an environment and a CTEP pack."); return; }
    try {
      const scn = await api("/api/scenarios/import-ctep", "POST", { environment_id: envId, pack_key });
      if (own === true) await populateGenerator();
      toast(`Imported "${scn.name}" — ${scn.injects.length} injects.`);
      await loadHome();
      $("scenarioSel").value = String(scn.id);
      $("sessInput").focus();
    } catch (e) { toast("CTEP import failed: " + e.message); }
  }

  async function startNew() {
    const scenarioId = Number($("scenarioSel").value);
    const name = $("sessInput").value.trim() || "Untitled exercise";
    const realtime = $("rtToggle").checked;
    try {
      const sess = await api("/api/sessions", "POST", {
        scenario_id: scenarioId, name,
        mode: realtime ? "real_time" : "tabletop", auto_advance: realtime,
      });
      await api(`/api/sessions/${sess.id}/start`, "POST");
      openSession(sess.id);
    } catch (e) { toast("Could not start: " + e.message); }
  }

  // ---- realtime ---------------------------------------------------------- //
  let socket = null;
  function closeSocket() { if (socket) { try { socket.onclose = null; socket.close(); } catch (e) { /* noop */ } socket = null; } }
  async function subscribeSocket(sid) {
    closeSocket();
    let ticket;
    try { ticket = (await api(`/api/sessions/${sid}/ws-ticket`, "POST")).ticket; }
    catch (e) { return; }  // realtime is best-effort; polling paths still work
    if (currentSid !== sid) return;  // moved on while awaiting
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const url = `${scheme}://${location.host}/ws/sessions/${sid}?ticket=${encodeURIComponent(ticket)}`;
    try {
      socket = new WebSocket(url);
      socket.onmessage = (ev) => {
        try { if (JSON.parse(ev.data).type === "changed") loadState(); } catch (e) { /* noop */ }
      };
      // Reconnect if the socket drops while the same session is open.
      socket.onclose = () => { if (currentSid === sid) setTimeout(() => { if (currentSid === sid) subscribeSocket(sid); }, 2000); };
    } catch (e) { /* realtime is best-effort */ }
  }

  async function openSession(sid) {
    currentSid = sid;
    $("emptyState").hidden = true;
    $("console").hidden = false;
    $("sessionMeta").hidden = false;
    subscribeSocket(sid);
    await loadState();
  }

  // ---- render running state ---------------------------------------------- //
  async function loadState() {
    const state = await api(`/api/sessions/${currentSid}`);
    render(state);
  }

  function render(state) {
    const { session, scenario, current_inject, available_branches, timeline, observations, terminal } = state;

    // top bar
    $("statusPill").textContent = session.status;
    $("statusPill").className = "pill " + session.status;
    $("sessName").textContent = session.name;
    $("clock").textContent = current_inject ? current_inject.clock || "T+00:00" : "—";
    $("btnPause").hidden = session.status !== "running";
    $("btnResume").hidden = session.status !== "paused";
    $("btnVerify").hidden = false;
    // M1: a completed exercise can be certified — the number, signed.
    $("btnCertificate").hidden = session.status !== "complete";
    // M3: run-day second screen, and the hotwash once play has started.
    $("btnRunday").hidden = false;
    $("btnRunday").href = `/runday.html?session=${currentSid}&view=${session.status === "setup" ? "brief" : "projector"}`;
    $("btnHotwash").hidden = session.status === "setup";
    lastState = state;

    // left rail
    $("scnName").textContent = scenario.name;
    $("scnActor").textContent = scenario.threat_actor;

    // scene
    if (current_inject) {
      currentInjectId = current_inject.id;
      $("scenePanel").hidden = false;
      $("injChannel").textContent = current_inject.channel;
      $("injCode").textContent = current_inject.code;
      $("injClock").textContent = current_inject.clock;
      $("injTitle").textContent = current_inject.title;
      $("injNarrative").textContent = current_inject.narrative;
      $("injActions").innerHTML = (current_inject.expected_actions || [])
        .map((a) => `<li>${escapeHtml(a)}</li>`).join("");
      const maps = (current_inject.attack_techniques || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("");
      const obj = current_inject.objective_code ? `<span class="tag obj">${escapeHtml(current_inject.objective_code)}</span>` : "";
      $("injMaps").innerHTML = maps + obj || '<span class="hint">—</span>';
    }

    // branches
    const branchWrap = $("branches");
    branchWrap.innerHTML = "";
    (available_branches || []).forEach((b) => {
      const el = document.createElement("button");
      el.className = "branch";
      el.innerHTML =
        `<span class="when ${escapeHtml(b.when)}">${escapeHtml((b.when || "").replace("_", " "))}</span>` +
        `<span class="lab">${escapeHtml(b.label || b.goto)}</span>` +
        `<span class="goto">${escapeHtml(b.goto)} →</span>`;
      el.onclick = () => advance(b.when, b.trigger || null, null);
      branchWrap.appendChild(el);
    });
    $("branchPanel").hidden = terminal || session.status === "complete";
    $("terminalNote").hidden = !terminal || session.status === "complete";

    // kill-chain progress map (how far along the exercise is)
    updateKillChain(scenario.id, current_inject, timeline);
    // P1: what the room answered, live
    updateResponses(current_inject);

    // live blue-vs-red scoreboard (detections vs adjudicated red moves)
    updateScoreboard(currentSid);

    // objectives (rail) + observation selector
    objectives = scenario_objectives_cache[scenario.id] || [];
    if (!objectives.length) fetchObjectives(scenario.id);
    else renderObjectives(observations);

    // environment summary (rail)
    fetchEnvOnce(scenario.id);

    // join lobby (rail)
    updateLobby(currentSid);

    // timeline
    const tl = $("timeline");
    tl.innerHTML = "";
    (timeline || []).slice().reverse().forEach((e) => {
      const li = document.createElement("li");
      li.className = "k-" + e.kind;
      li.innerHTML = `<span class="tclock">${escapeHtml(e.game_clock || "--:--")}</span>${describeEvent(e)}`;
      tl.appendChild(li);
    });
  }

  const scenario_objectives_cache = {};
  const scenario_injects_cache = {};
  const env_cache = {};
  let injectBank = null;

  // P1: the proctor's tally for the live decision card.
  async function updateResponses(currentInject) {
    const box = $("responses");
    if (!box) return;
    if (!currentInject) { box.hidden = true; return; }
    try {
      const t = await api(`/api/sessions/${currentSid}/responses?inject=${encodeURIComponent(currentInject.code)}`);
      if (!t.spec) { box.hidden = true; return; }
      const max = Math.max(1, ...t.options.map((o) => o.count));
      const bars = t.options.map((o) =>
        `<div class="rs-row"><span class="rs-lbl"><b>${escapeHtml(o.key.toUpperCase())}</b> ${escapeHtml(o.label)} <span class="hint">${Math.round(o.score * 100)}%</span></span>` +
        `<span class="rs-bar"><span style="width:${Math.round(o.count / max * 100)}%"></span></span><span class="rs-n">${o.count}</span></div>`).join("");
      const texts = t.free_text.map((f) => `<li><b>${escapeHtml(f.display_name || "")}</b>: ${escapeHtml(f.text)}</li>`).join("");
      box.hidden = false;
      box.innerHTML = `<p class="eyebrow">Decision <span class="hint">— ${t.responses} of ${t.expected} answered` +
        (t.mean_score != null ? ` · score ${Math.round(t.mean_score * 100)}%` : "") +
        (t.median_latency_sec != null ? ` · median ${t.median_latency_sec} s` : "") + `</span></p>` +
        `<p class="rs-prompt">${escapeHtml(t.spec.prompt)}${t.spec.derived ? ' <span class="hint">(derived from expected actions)</span>' : ""}</p>` +
        bars + (texts ? `<ul class="rs-texts">${texts}</ul>` : "");
    } catch (e) { box.hidden = true; }
  }

  async function ensureBank() {
    if (injectBank) return injectBank;
    try { injectBank = await api("/api/catalog/injects"); } catch (e) { injectBank = []; }
    return injectBank;
  }

  // The kill-chain journey map: how far along a running exercise is.
  async function updateKillChain(scenarioId, currentInject, timeline) {
    const box = $("killChain");
    if (!box || !window.KillChain) return;
    try {
      if (!scenario_injects_cache[scenarioId]) {
        const scn = await api(`/api/scenarios/${scenarioId}`);
        scenario_injects_cache[scenarioId] = scn.injects || [];
      }
      const fired = new Set((timeline || []).filter((e) => e.kind === "inject_fired").map((e) => e.ref));
      if (currentInject) fired.add(currentInject.code);
      window.KillChain.render(box, {
        injects: scenario_injects_cache[scenarioId], bank: await ensureBank(),
        mode: "live", currentCode: currentInject ? currentInject.code : null, firedCodes: fired,
      });
    } catch (e) { box.hidden = true; }
  }

  async function fetchObjectives(scenarioId) {
    const scn = await api(`/api/scenarios/${scenarioId}`);
    scenario_objectives_cache[scenarioId] = scn.objectives;
    objectives = scn.objectives;
    $("scnRoe").textContent = scn.rules_of_engagement;
    renderObjectives();
  }

  // Live blue-vs-red scoreboard, tallied from every adjudicated red move.
  async function updateScoreboard(sid) {
    const panel = $("scorePanel");
    if (!panel || !sid) return;
    let sb;
    try { sb = await api(`/api/sessions/${sid}/scoreboard`); } catch (e) { panel.hidden = true; return; }
    if (!sb || !sb.red_actions) { panel.hidden = true; return; }  // nothing adjudicated yet
    panel.hidden = false;
    const rate = sb.detection_rate != null ? Math.round(sb.detection_rate * 100) + "%" : "—";
    const mttd = sb.mean_time_to_detect_min != null ? sb.mean_time_to_detect_min + "′" : "—";
    const tiles = [
      { k: "Detection rate", v: rate, tone: "good" },
      { k: "Detected", v: `${sb.detected}/${sb.red_actions}`, tone: "info" },
      { k: "Mean TTD", v: mttd, tone: "info" },
      { k: "Missed", v: sb.missed, tone: sb.missed ? "crit" : "good" },
      { k: "Deceptions tripped", v: sb.deceptions_tripped, tone: "warn" },
    ];
    $("scoreTiles").innerHTML = tiles.map((t) =>
      `<div class="stile ${t.tone}"><span class="v">${escapeHtml(String(t.v))}</span><span class="k">${escapeHtml(t.k)}</span></div>`).join("");
    // Compact ATT&CK technique coverage bars (detected / attempts).
    const tech = (sb.by_technique || []).filter((r) => r.technique && r.technique !== "(unspecified)");
    $("scoreTech").innerHTML = !tech.length ? "" :
      `<p class="score-lbl">Technique coverage</p>` + tech.map((r) => {
        const pct = r.attempts ? Math.round((r.detected / r.attempts) * 100) : 0;
        return `<div class="tcov"><span class="tt">${escapeHtml(r.technique)}</span>` +
          `<span class="bar"><span class="fill" style="width:${pct}%"></span></span>` +
          `<span class="n">${r.detected}/${r.attempts}</span></div>`;
      }).join("");
    if (detectStreak >= 2) {
      $("scoreTech").innerHTML += `<p class="score-streak">🔥 ${detectStreak} detections in a row</p>`;
    }
  }

  function renderObjectives(observations = []) {
    const ratingByObj = {};
    observations.forEach((o) => {
      const rank = { missed: 3, partial: 2, met: 1, note: 0 };
      if ((rank[o.rating] || 0) >= (rank[ratingByObj[o.objective_code]] || 0)) {
        ratingByObj[o.objective_code] = o.rating;
      }
    });
    $("objList").innerHTML = objectives.map((o) => {
      const r = ratingByObj[o.code];
      const badge = r && r !== "note" ? ` <span class="tag">${escapeHtml(r)}</span>` : "";
      return `<li><b>${escapeHtml(o.code)}</b>${escapeHtml(o.title)}${badge}</li>`;
    }).join("");

    const sel = $("obsObj");
    sel.innerHTML = '<option value="">— general —</option>' +
      objectives.map((o) => `<option value="${escapeHtml(o.code)}">${escapeHtml(o.code)} · ${escapeHtml(o.title)}</option>`).join("");
  }

  // Join-code lobby: show the code + who's joined; refreshed each render.
  async function updateLobby(sid) {
    if (!sid || !$("lobbyPanel")) return;
    try {
      const roster = await api(`/api/sessions/${sid}/lobby`);
      $("lobbyList").innerHTML = roster.map((m) =>
        `<li><span class="lb-cell lb-${escapeHtml(m.cell)}">${escapeHtml((m.cell || "").replace("_cell", ""))}</span>${escapeHtml(m.display_name)}</li>`).join("")
        || '<li class="muted">No one has joined yet.</li>';
    } catch (e) { /* noop */ }
  }
  async function generateJoinCode() {
    if (!currentSid) return;
    try {
      const { join_code } = await api(`/api/sessions/${currentSid}/join-code`, "POST");
      const url = `${location.origin}/join.html?code=${join_code}`;
      $("joinCodeBox").innerHTML =
        `<code class="jc">${escapeHtml(join_code)}</code><button class="btn ghost small" id="btnCopyJoin" title="Copy join link">Copy link</button>`;
      const c = $("btnCopyJoin");
      if (c) c.addEventListener("click", () => { try { navigator.clipboard.writeText(url); toast("Join link copied"); } catch (e) { toast(url); } });
    } catch (e) { toast(e.message); }
  }

  async function fetchEnvOnce(scenarioId) {
    if (env_cache[scenarioId]) return renderEnv(env_cache[scenarioId]);
    const scn = await api(`/api/scenarios/${scenarioId}`);
    const env = await api(`/api/environments/${scn.environment_id}`);
    env_cache[scenarioId] = env;
    renderEnv(env);
  }

  function renderEnv(env) {
    const rows = [
      ["Name", env.name],
      ["Sector", env.sector],
      ["Box", env.box_type],
      ["Assets", (env.assets || []).length],
      ["Controls", (env.controls || []).length + (env.detections || []).length],
      ["Deception", (env.deception_assets || []).length],
    ];
    $("envSummary").innerHTML =
      rows.map(([k, v]) => `<div class="row"><span>${k}</span><span>${escapeHtml(String(v))}</span></div>`).join("") +
      `<div class="cj">Crown jewels: ${escapeHtml((env.crown_jewels || []).join(", "))}</div>`;
  }

  // ---- proctor actions --------------------------------------------------- //
  async function advance(when, trigger, goto) {
    try {
      await api(`/api/sessions/${currentSid}/advance`, "POST", { when, trigger, goto });
      await loadState();
    } catch (e) { toast(e.message); }
  }

  async function adjudicate() {
    const techniques = $("adjTech").value.split(",").map((t) => t.trim()).filter(Boolean);
    const target_asset = $("adjAsset").value.trim();
    try {
      const out = await api(`/api/sessions/${currentSid}/adjudicate`, "POST", { techniques, target_asset });
      renderRuling(out.ruling);
      if (out.ruling && out.ruling.detected) { detectStreak += 1; detectedMoment(detectStreak); }
      else detectStreak = 0;
      await loadState();
    } catch (e) { toast(e.message); }
  }

  function renderRuling(r) {
    const box = $("rulingOut");
    box.hidden = false;
    box.className = "ruling " + (r.detected ? "detected" : "missed");
    const controls = (r.controls_hit || []).map((c) =>
      `<div class="c"><span>${escapeHtml(c.name)}${c.deception ? " ⚑" : ""}</span><span>p·eff ${c.efficacy}</span></div>`).join("");
    box.innerHTML =
      `<div class="verdict"><span class="${r.detected ? "v-detected" : "v-missed"}">${r.detected ? "DETECTED" : "MISSED"}</span>` +
      `<span>${r.time_to_detect_min != null ? r.time_to_detect_min + " min" : "—"}</span></div>` +
      `<div class="rationale">${escapeHtml(r.rationale)}</div>` +
      (controls ? `<div class="controls">${controls}</div>` : "");
  }

  async function observe() {
    const note = $("obsNote").value.trim();
    if (!note) return toast("Add a note first.");
    try {
      await api(`/api/sessions/${currentSid}/observe`, "POST", {
        objective_code: $("obsObj").value,
        rating: selectedRating,
        note,
      });
      $("obsNote").value = "";
      toast("Observation logged.");
      await loadState();
    } catch (e) { toast(e.message); }
  }

  async function setStatus(action) {
    try { await api(`/api/sessions/${currentSid}/${action}`, "POST"); await loadState(); }
    catch (e) { toast(e.message); }
  }

  async function verify() {
    const v = await api(`/api/sessions/${currentSid}/verify`);
    $("chainState").innerHTML = v.chain_valid
      ? `<span class="chainok">✓ chain intact · ${v.events} events</span>`
      : `<span class="chainbad">✗ chain broken</span>`;
    toast(v.chain_valid ? "Timeline verified — hash-chain intact." : "Timeline verification FAILED.");
  }

  let lastState = null;

  // M3: the hotwash — every objective gets a rating, and what the room agreed
  // to fix becomes an improvement item, before anyone leaves.
  async function hotwash() {
    if (!lastState) return;
    const obs = lastState.observations || [];
    const rated = {};
    obs.forEach((o) => { if (["met", "partial", "missed"].includes(o.rating)) rated[o.objective_code] = o.rating; });
    const rows = objectives.map((o) => {
      const r = rated[o.code];
      const btn = (v, label) => `<button class="btn ghost small hw-rate ${r === v ? "on" : ""}" data-obj="${escapeHtml(o.code)}" data-rate="${v}">${label}</button>`;
      return `<tr><td><b>${escapeHtml(o.code)}</b> ${escapeHtml(o.title)}<br><span class="hint">${escapeHtml(o.success_criteria || "")}</span></td>` +
        `<td class="hw-btns">${btn("met", "Met")}${btn("partial", "Partial")}${btn("missed", "Missed")}</td></tr>`;
    }).join("");
    let items = [];
    try { items = (await api("/api/improvements")).filter((i) => i.session_id === currentSid); } catch (e) { /* noop */ }
    let scores = null;
    try { scores = await api(`/api/sessions/${currentSid}/participants/scores`); } catch (e) { /* noop */ }
    const scoreRows = scores && scores.participants.length
      ? `<h2>Participants</h2><table class="dfields"><thead><tr><th>Who</th><th>Cell</th><th>Answers</th><th>Score</th><th>Median time</th></tr></thead><tbody>` +
        scores.participants.map((r) => `<tr><td>${escapeHtml(r.display_name || "")}</td><td>${escapeHtml((r.cell || "").replace("_cell", ""))}</td><td>${r.responses}</td><td>${r.mean_score == null ? "—" : Math.round(r.mean_score * 100) + "%"}</td><td>${r.median_latency_sec == null ? "—" : r.median_latency_sec + " s"}</td></tr>`).join("") +
        `</tbody></table>` : "";
    $("modalBody").innerHTML =
      `<p class="eyebrow">Hotwash · ${escapeHtml(lastState.session.name)}</p><h1>What did we learn?</h1>` +
      `<p class="sub">Rate each objective while the room is still here. Anything the room agrees to fix goes on the improvement list now, with an owner later.</p>` +
      `<h2>Objectives</h2><table class="dfields hw-table"><tbody>${rows || '<tr><td class="muted">No objectives declared.</td></tr>'}</tbody></table>` +
      scoreRows +
      `<h2>Improvement items</h2><ul class="hw-items" id="hwItems">${items.map((i) => `<li><span class="pill">${escapeHtml(i.severity)}</span> ${escapeHtml(i.title)}</li>`).join("") || '<li class="muted">Nothing logged yet.</li>'}</ul>` +
      `<div class="row"><input id="hwTitle" placeholder="e.g. Enforce MFA on the VPN for all contractors" style="flex:1"><select id="hwSev"><option>high</option><option selected>medium</option><option>low</option></select><button class="btn" id="hwAdd">Log item</button></div>` +
      `<p class="hint">Three questions to ask the room: What went well? What surprised us? What one control would have changed the outcome?</p>` +
      (lastState.session.status !== "complete" ? `<div class="modal-actions"><button class="btn primary" id="hwComplete">Complete exercise</button></div>` : "");
    $("modal").hidden = false;
    $("modalBody").querySelectorAll(".hw-rate").forEach((b) => b.addEventListener("click", async () => {
      try {
        await api(`/api/sessions/${currentSid}/observe`, "POST", { objective_code: b.dataset.obj, rating: b.dataset.rate, note: "hotwash rating" });
        b.parentElement.querySelectorAll(".hw-rate").forEach((x) => x.classList.remove("on")); b.classList.add("on");
        await loadState();
      } catch (e) { toast(e.message); }
    }));
    $("hwAdd").addEventListener("click", async () => {
      const title = $("hwTitle").value.trim();
      if (!title) return;
      try {
        const it = await api("/api/improvements", "POST", { title, severity: $("hwSev").value, session_id: currentSid, description: "Raised at the hotwash." });
        const li = document.createElement("li"); li.innerHTML = `<span class="pill">${escapeHtml(it.severity)}</span> ${escapeHtml(it.title)}`;
        const ul = $("hwItems"); if (ul.querySelector(".muted")) ul.innerHTML = ""; ul.appendChild(li); $("hwTitle").value = "";
        toast("Improvement item logged.");
      } catch (e) { toast(e.message); }
    });
    const done = $("hwComplete");
    if (done) done.addEventListener("click", async () => { closeModal(); await setStatus("complete"); toast("Exercise complete — issue the certificate when ready."); });
  }

  // M3: keyboard for the facilitator. Space / → takes the first proctor choice,
  // P pauses or resumes, A focuses the adjudication box, H opens the hotwash.
  function keys(e) {
    if (!currentSid || ($("modal") && !$("modal").hidden)) return;
    if (e.target && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
    if (e.key === " " || e.key === "ArrowRight") {
      const avail = (lastState && lastState.available_branches) || [];
      const b = avail.find((x) => x.when === "proctor_choice") || avail[0];
      if (b) { e.preventDefault(); advance(b.when, b.trigger || null, null); }
    } else if (e.key === "p" || e.key === "P") {
      if (!$("btnPause").hidden) setStatus("pause"); else if (!$("btnResume").hidden) setStatus("resume");
    } else if (e.key === "a" || e.key === "A") { e.preventDefault(); $("adjTech").focus(); }
    else if (e.key === "h" || e.key === "H") { if (!$("btnHotwash").hidden) hotwash(); }
  }

  // M1: issue (idempotent) and show the signed certificate for a completed exercise.
  async function certificate() {
    try {
      const cert = await api(`/api/sessions/${currentSid}/certificate`, "POST");
      const p = cert.payload || {};
      const pct = (v) => (v == null ? "n/a" : Math.round(v * 100) + "%");
      const obj = p.objectives || {};
      const verifyUrl = `${location.origin}/verify.html?serial=${encodeURIComponent(cert.serial)}`;
      const tiles = [
        ["Detection rate", pct(p.detection_rate)],
        ["Mean time to detect", p.mean_time_to_detect_min == null ? "n/a" : p.mean_time_to_detect_min + " min"],
        ["Objectives met", pct(obj.met_rate)],
        ["Techniques exercised", String((p.techniques_exercised || []).length)],
      ].map(([k, v]) => `<div class="stile info"><span class="v">${escapeHtml(v)}</span><span class="k">${escapeHtml(k)}</span></div>`).join("");
      modalWithDownloads(
        `<p class="eyebrow">Exercise certificate · ${escapeHtml(cert.serial)}</p>` +
        `<h1>${escapeHtml(p.organization || "")}</h1>` +
        `<p class="sub">completed <b>${escapeHtml(p.exercise || "")}</b> (${escapeHtml(p.scenario || "")}) against ${escapeHtml(p.environment || "")}.</p>` +
        `<div class="score cert-tiles">${tiles}</div>` +
        `<table class="dfields"><tbody>` +
        `<tr><td>Adversary actions</td><td>${p.adversary_actions} adjudicated · ${p.detected} detected · ${p.missed} missed</td></tr>` +
        `<tr><td>Objectives</td><td>${obj.met || 0} met · ${obj.partial || 0} partial · ${obj.missed || 0} not met · of ${obj.total || 0}</td></tr>` +
        `<tr><td>Undetected techniques</td><td>${escapeHtml((p.coverage_gaps || []).join(", ") || "none")}</td></tr>` +
        `<tr><td>Timeline</td><td>${p.timeline_events} signed events · chain ${p.chain_verified ? "verified intact at issue" : "NOT verified"}</td></tr>` +
        `<tr><td>Issued</td><td>${escapeHtml(new Date(cert.issued_at).toLocaleString())} by ${escapeHtml(cert.issued_by || "")}</td></tr>` +
        `<tr><td>Signature</td><td><code class="cert-sig">${escapeHtml(cert.signature)}</code></td></tr>` +
        `<tr><td>Verify</td><td><a href="${escapeHtml(verifyUrl)}" target="_blank" rel="noopener">${escapeHtml(verifyUrl)}</a><br><span class="hint">Anyone with the serial can check these figures without an account.</span></td></tr>` +
        `</tbody></table>` +
        `<blockquote>An exercise record, not a compliance attestation. The figures were frozen and signed at issue; the verify link recomputes the signature.</blockquote>`,
        [{ label: "Download certificate PDF", path: `/api/sessions/${currentSid}/certificate.pdf`, filename: `certificate-${cert.serial}.pdf` }]);
    } catch (e) { toast(e.message); }
  }

  async function downloadBlob(path, filename) {
    try {
      const token = getToken();
      const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) throw new Error("Download failed");
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url; a.download = filename; document.body.appendChild(a); a.click();
      a.remove(); setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (e) { toast(e.message); }
  }

  // actions: [{label, path, filename}] — each becomes a download button.
  function modalWithDownloads(html, actions) {
    const btns = actions.map((a, i) =>
      `<button class="btn ${i === 0 ? "primary" : "ghost"}" data-dl="${i}">${a.label}</button>`).join("");
    $("modalBody").innerHTML = `<div class="modal-actions">${btns}</div>` + html;
    $("modal").hidden = false;
    $("modalBody").querySelectorAll("[data-dl]").forEach((b) => {
      const a = actions[Number(b.dataset.dl)];
      b.addEventListener("click", () => downloadBlob(a.path, a.filename));
    });
  }

  async function generateReport(audience) {
    try {
      const rep = await api(`/api/sessions/${currentSid}/reports`, "POST", { audience });
      const base = `/api/sessions/${currentSid}/reports/${rep.id}`;
      modalWithDownloads(renderMarkdown(rep.content), [
        { label: "Download PDF", path: `${base}.pdf`, filename: `report-${audience}.pdf` },
        { label: "Download DOCX", path: `${base}.docx`, filename: `report-${audience}.docx` },
      ]);
    } catch (e) { toast(e.message); }
  }

  // M4: what the tools actually saw, against what the ruling expected.
  async function telemetry() {
    if (!currentSid) return;
    let cmp;
    try { cmp = await api(`/api/sessions/${currentSid}/telemetry/compare`); } catch (e) { toast(e.message); return; }
    const pct = (v) => (v == null ? "n/a" : Math.round(v * 100) + "%");
    const label = { confirmed: "Confirmed", silent_gap: "Silent gap", surprise: "Surprise", missed: "Missed" };
    const rows = cmp.rows.map((r) =>
      `<tr><td class="mono">${escapeHtml(r.game_clock || "--:--")}</td><td>${escapeHtml((r.techniques || []).join(", ") || "action")}${r.target_asset ? ` <span class="hint">on ${escapeHtml(r.target_asset)}</span>` : ""}</td>` +
      `<td>${r.expected ? "detected" : "missed"}${r.expected_ttd_min != null ? ` <span class="hint">${r.expected_ttd_min} min</span>` : ""}</td>` +
      `<td>${r.observed ? "alert" : "—"}${r.observed_latency_min != null ? ` <span class="hint">${r.observed_latency_min} min</span>` : ""}</td>` +
      `<td><span class="tl-out ${r.outcome}">${label[r.outcome]}</span></td></tr>`).join("");
    const tiles = [
      ["Modelled", pct(cmp.expected_rate)], ["Observed", pct(cmp.observed_rate)], ["Agreement", pct(cmp.model_agreement)], ["Alerts", String(cmp.alerts)],
    ].map(([k, v]) => `<div class="stile info"><span class="v">${escapeHtml(v)}</span><span class="k">${escapeHtml(k)}</span></div>`).join("");
    $("modalBody").innerHTML =
      `<p class="eyebrow">Telemetry · expected vs observed</p><h1>What did the tools see?</h1>` +
      `<p class="sub">The ruling says what the modelled controls should have caught. Record the alerts the SOC's tools actually raised and every action becomes confirmed, a silent gap, a surprise, or missed.</p>` +
      `<div class="score cert-tiles">${tiles}</div>` +
      `<div class="row"><span class="pill">${cmp.counts.confirmed} confirmed</span><span class="pill">${cmp.counts.silent_gap} silent gap</span><span class="pill">${cmp.counts.surprise} surprise</span><span class="pill">${cmp.counts.missed} missed</span></div>` +
      `<table class="dfields tl-table"><thead><tr><th>Clock</th><th>Action</th><th>Expected</th><th>Observed</th><th>Outcome</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="muted">No adjudicated actions yet.</td></tr>'}</tbody></table>` +
      (cmp.unmatched_alerts.length ? `<p class="hint">${cmp.unmatched_alerts.length} alert(s) matched no action: ${cmp.unmatched_alerts.map((u) => escapeHtml(u.alert)).join(", ")}.</p>` : "") +
      `<h2>Record an alert</h2>` +
      `<div class="setup tl-form"><label>Alert<input id="tlAlert" placeholder="e.g. Credential dumping via LSASS"></label>` +
      `<label>Techniques<input id="tlTech" placeholder="T1003.001, T1078"></label>` +
      `<label>Asset<input id="tlAsset" placeholder="SRV-01 (blank = any)"></label>` +
      `<label>Source<select id="tlSource"><option>siem</option><option>edr</option><option>ndr</option><option>email</option><option>identity</option><option>cloud</option><option selected>manual</option></select></label>` +
      `<label>Observed at<input id="tlWhen" placeholder="2026-09-02T10:15:00Z (blank = now)"></label>` +
      `<button class="btn" id="tlAdd">Record alert</button></div>` +
      `<h2>Import an export</h2><p class="hint">JSON or CSV from the SIEM/EDR: columns such as alert/rule_name, technique(s), host, source, time are recognised.</p>` +
      `<div class="row"><select id="tlFmt"><option value="json">JSON</option><option value="csv">CSV</option></select><input type="file" id="tlFile" accept=".json,.csv,.txt"><button class="btn ghost" id="tlImport">Import</button></div>`;
    $("modal").hidden = false;
    $("tlAdd").addEventListener("click", async () => {
      const alert = $("tlAlert").value.trim();
      if (!alert) { toast("Name the alert."); return; }
      try {
        await api(`/api/sessions/${currentSid}/telemetry`, "POST", {
          alert, techniques: $("tlTech").value.split(",").map((x) => x.trim()).filter(Boolean),
          asset: $("tlAsset").value.trim(), source: $("tlSource").value, observed_at: $("tlWhen").value.trim() });
        toast("Alert recorded."); await telemetry();
      } catch (e) { toast(e.message); }
    });
    $("tlImport").addEventListener("click", async () => {
      const f = $("tlFile").files[0];
      if (!f) { toast("Choose an export file."); return; }
      try {
        const out = await api(`/api/sessions/${currentSid}/telemetry/import`, "POST", { format: $("tlFmt").value, data: await f.text() });
        toast(`${out.recorded} alert(s) recorded, ${out.skipped} row(s) skipped.`); await telemetry();
      } catch (e) { toast(e.message); }
    });
  }

  function exportTimeline(fmt) {
    if (!currentSid) return;
    downloadBlob(`/api/sessions/${currentSid}/timeline.${fmt}`, `timeline-${currentSid}.${fmt}`);
  }

  async function previewCompliance() {
    try {
      const ev = await api(`/api/sessions/${currentSid}/evidence`);
      const blocks = ev.frameworks.map((f) => {
        const rows = f.controls.map((c) =>
          `<tr><td><code>${escapeHtml(c.id)}</code></td><td>${escapeHtml(c.title)}</td>` +
          `<td><span class="evid ${c.status}">${c.status.replace("_", " ")}</span></td></tr>`).join("");
        return `<h2>${escapeHtml(f.name)}</h2>` +
          `<p class="hint">${f.summary.demonstrated} demonstrated · ${f.summary.gaps} gap(s) · ${f.summary.controls} control(s)</p>` +
          `<table class="dfields"><tbody>${rows || '<tr><td colspan="3" class="muted">No mapped controls.</td></tr>'}</tbody></table>`;
      }).join("");
      modalWithDownloads(
        `<h1>Compliance evidence</h1><blockquote>${escapeHtml(ev.disclaimer)}</blockquote>${blocks}`, [
          { label: "Download evidence PDF", path: `/api/sessions/${currentSid}/evidence.pdf`, filename: "compliance-evidence.pdf" },
          { label: "Download DOCX", path: `/api/sessions/${currentSid}/evidence.docx`, filename: "compliance-evidence.docx" },
        ]);
    } catch (e) { toast(e.message); }
  }

  async function importYaml() {
    const file = $("yamlFile").files[0];
    if (!file) return toast("Choose a YAML file first.");
    const envId = Number($("genEnv").value);
    try {
      const yaml = await file.text();
      const scn = await api("/api/scenarios/import", "POST", { environment_id: envId, yaml });
      toast(`Imported "${scn.name}" — ${scn.injects.length} injects.`);
      await loadHome();
      $("scenarioSel").value = String(scn.id);
    } catch (e) { toast("Import failed: " + e.message); }
  }

  async function previewDelivery() {
    if (!currentInjectId) return;
    try {
      const d = await api(`/api/injects/${currentInjectId}/delivery`);
      $("modalBody").innerHTML = renderDelivery(d);
      $("modal").hidden = false;
    } catch (e) { toast(e.message); }
  }

  function renderDelivery(d) {
    const rows = Object.entries(d.fields || {})
      .map(([k, v]) => `<tr><td class="dk">${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join("");
    const actions = (d.expected_actions || [])
      .map((a) => `<li>${escapeHtml(a)}</li>`).join("");
    return (
      `<div class="delivery ch-${escapeHtml(d.channel)}">` +
      `<span class="chan">${escapeHtml(d.channel.replace("_", " "))}</span>` +
      `<h1>${escapeHtml(d.headline)}</h1>` +
      `<table class="dfields"><tbody>${rows}</tbody></table>` +
      `<p class="dbody">${escapeHtml(d.body)}</p>` +
      (actions ? `<h2>Expected actions</h2><ul>${actions}</ul>` : "") +
      `</div>`
    );
  }

  // ---- helpers ----------------------------------------------------------- //
  function describeEvent(e) {
    const p = e.payload || {};
    switch (e.kind) {
      case "inject_fired": return `<b>${escapeHtml(e.ref)}</b> ${escapeHtml(p.title || "")}`;
      case "decision": return `Decision → ${escapeHtml(p.label || p.goto || "")}`;
      case "adjudication": return `Adjudication [<b>${p.detected ? "detected" : "missed"}</b>] ${escapeHtml(truncate(p.rationale, 90))}`;
      case "observation": return `Observation [${escapeHtml(p.rating)}] ${escapeHtml(truncate(p.note, 80))}`;
      case "note": return `Note — ${escapeHtml(truncate(p.text, 90))}`;
      case "status": return `Status → ${escapeHtml(p.status)}`;
      case "response": return `Decision by <b>${escapeHtml(p.display_name || "")}</b> (${escapeHtml((p.cell || "").replace("_cell", ""))}) — ${escapeHtml(truncate(p.label || p.text || "", 70))}${p.latency_sec != null ? ` <span class="hint">${p.latency_sec} s</span>` : ""}`;
      case "telemetry": return `Alert [${escapeHtml(p.source || "tool")}] ${escapeHtml(truncate(p.alert, 70))}${(p.techniques || []).length ? " · " + escapeHtml(p.techniques.join(", ")) : ""}`;
      default: return e.kind;
    }
  }

  // A brief, professional "Detected!" micro-moment — momentum for retention,
  // never confetti spam. Reduced-motion is handled in CSS.
  function detectedMoment(streak) {
    const el = document.createElement("div");
    el.className = "detected-pop";
    el.textContent = streak >= 2 ? `Detected! ×${streak}` : "Detected!";
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 1300);
  }
  function truncate(s, n) { s = s || ""; return s.length > n ? s.slice(0, n) + "…" : s; }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // Minimal, safe markdown renderer for the report viewer.
  function renderMarkdown(md) {
    const lines = md.split("\n");
    let html = "", inTable = false, inList = false;
    const inline = (t) => escapeHtml(t)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+?)`/g, "<code>$1</code>")
      .replace(/_(.+?)_/g, "<em>$1</em>");
    const closeList = () => { if (inList) { html += "</ul>"; inList = false; } };
    const closeTable = () => { if (inTable) { html += "</tbody></table>"; inTable = false; } };

    for (const raw of lines) {
      const line = raw.trimEnd();
      if (/^\|.*\|$/.test(line)) {
        const cells = line.split("|").slice(1, -1).map((c) => c.trim());
        if (/^[-:\s|]+$/.test(line.replace(/\|/g, ""))) continue; // separator row
        if (!inTable) { closeList(); html += "<table><tbody>"; inTable = true; }
        const tag = "td";
        html += "<tr>" + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join("") + "</tr>";
        continue;
      }
      closeTable();
      if (/^#{1,3}\s/.test(line)) {
        closeList();
        const level = line.match(/^#+/)[0].length;
        html += `<h${level}>${inline(line.replace(/^#+\s/, ""))}</h${level}>`;
      } else if (/^>\s?/.test(line)) {
        closeList(); html += `<blockquote>${inline(line.replace(/^>\s?/, ""))}</blockquote>`;
      } else if (/^[-*]\s/.test(line)) {
        if (!inList) { html += "<ul>"; inList = true; }
        html += `<li>${inline(line.replace(/^[-*]\s/, ""))}</li>`;
      } else if (line === "") {
        closeList();
      } else {
        closeList(); html += `<p>${inline(line)}</p>`;
      }
    }
    closeList(); closeTable();
    return html;
  }

  // ---- security settings (change password, MFA) -------------------------- //
  function closeModal() { $("modal").hidden = true; }

  // ---- E1: new environment (library / blank / import) ------------------------- //
  async function openNewEnvironment() {
    let templates = [];
    try { templates = await api("/api/environments/templates"); } catch (e) { /* noop */ }
    $("modal").hidden = false;
    $("modalBody").innerHTML =
      '<p class="eyebrow">New environment</p>' +
      '<h1>The system under test</h1>' +
      '<p class="sub">Every ruling is made against an environment: its assets, the controls that cover them, and where the deception is. Start from a sector template and edit, start blank, or import an export from a tool you already have.</p>' +
      '<div class="env-sources">' +
      '<div class="source"><h3>From the library</h3>' +
      '<div class="env-tpls">' + templates.map((t) =>
        `<label class="env-tpl"><input type="radio" name="envTpl" value="${escapeHtml(t.key)}">` +
        `<span class="env-tpl-name">${escapeHtml(t.name)}</span><span class="env-tpl-meta">${escapeHtml(t.sector)} · ${escapeHtml(t.box_type)} box · ${t.assets} assets · ${t.controls} controls · ${t.deception} canary</span>` +
        `<span class="env-tpl-desc">${escapeHtml(t.description)}</span></label>`).join("") + '</div>' +
      '<div class="row" style="margin-top:.6rem"><input id="envTplName" type="text" placeholder="Name (optional — defaults to the template name)"><button class="btn primary" id="btnEnvFromTpl">Create from template</button></div></div>' +
      '<div class="source"><h3>Blank</h3><div class="row"><input id="envBlankName" type="text" placeholder="Name, e.g. Acme Retail — Stores"><input id="envBlankSector" type="text" placeholder="Sector"><select id="envBlankBox"><option value="grey">Grey box</option><option value="white">White box</option><option value="black">Black box</option></select><button class="btn" id="btnEnvBlank">Create blank</button></div>' +
      '<p class="hint">Add assets and controls afterwards through the API or an import; a blank environment adjudicates every action as a detection gap until it has controls.</p></div>' +
      '<div class="source"><h3>Import an export</h3><div class="row"><select id="envImpSource"><option value="cmdb">CMDB</option><option value="edr">EDR</option><option value="siem">SIEM</option><option value="asm">Attack-surface scan</option><option value="generic">Generic</option></select><select id="envImpFormat"><option value="json">JSON</option><option value="csv">CSV</option></select><input id="envImpName" type="text" placeholder="Name (optional)"><input id="envImpFile" type="file" accept=".json,.csv,.txt"><button class="btn" id="btnEnvImport">Import</button></div></div>' +
      '</div><p class="loginerr" id="envErr" hidden></p>';
    const fail = (e) => { const el = $("envErr"); el.textContent = e.message; el.hidden = false; };
    const done = async (env) => { closeModal(); toast(`Environment “${env.name}” created.`); await populateGenerator(); $("genEnv").value = String(env.id); };
    $("btnEnvFromTpl").addEventListener("click", async () => {
      const pick = $("modalBody").querySelector('input[name="envTpl"]:checked');
      if (!pick) { fail(new Error("Choose a template first.")); return; }
      try { done(await api("/api/environments/from-template", "POST", { key: pick.value, name: $("envTplName").value.trim() || null })); } catch (e) { fail(e); }
    });
    $("btnEnvBlank").addEventListener("click", async () => {
      const name = $("envBlankName").value.trim();
      if (!name) { fail(new Error("Give the environment a name.")); return; }
      try { done(await api("/api/environments", "POST", { name, sector: $("envBlankSector").value.trim(), box_type: $("envBlankBox").value })); } catch (e) { fail(e); }
    });
    $("btnEnvImport").addEventListener("click", async () => {
      const f = $("envImpFile").files[0];
      if (!f) { fail(new Error("Choose a file to import.")); return; }
      try {
        const data = await f.text();
        const out = await api("/api/environments/import", "POST", { source: $("envImpSource").value, format: $("envImpFormat").value, data, name: $("envImpName").value.trim() || null });
        done(out.environment);
      } catch (e) { fail(e); }
    });
  }

  async function openSecurity() {
    let me;
    try { me = await api("/api/auth/me"); } catch (e) { return; }
    $("modalBody").innerHTML =
      '<h2 style="margin-top:0">Account security</h2>' +
      '<div class="setup" style="margin-bottom:1rem">' +
      '<h3 style="margin:.2rem 0">Change password</h3>' +
      '<label>Current <input id="secOld" type="password" autocomplete="current-password"></label>' +
      '<label>New <input id="secNew" type="password" autocomplete="new-password"></label>' +
      '<button class="btn primary" id="secChangePw">Update password</button>' +
      '<p class="loginerr" id="secPwMsg" hidden></p></div>' +
      '<div class="setup"><h3 style="margin:.2rem 0">Two-factor (TOTP)</h3>' +
      `<p class="sub" id="secMfaState">${me.mfa_enabled ? "Enabled." : "Not enabled."}</p>` +
      '<div id="secMfaBox"></div></div>';
    $("modal").hidden = false;
    $("secChangePw").addEventListener("click", changePassword);
    renderMfaBox(me.mfa_enabled);
  }

  function renderMfaBox(enabled) {
    const box = $("secMfaBox");
    if (enabled) {
      box.innerHTML =
        '<label>Code to disable <input id="mfaDisableCode" inputmode="numeric" maxlength="6" placeholder="000000"></label>' +
        '<button class="btn ghost" id="btnMfaDisable">Disable 2FA</button><p class="loginerr" id="mfaMsg" hidden></p>';
      $("btnMfaDisable").addEventListener("click", disableMfa);
    } else {
      box.innerHTML = '<button class="btn primary" id="btnMfaStart">Set up 2FA</button><p class="loginerr" id="mfaMsg" hidden></p>';
      $("btnMfaStart").addEventListener("click", startMfa);
    }
  }

  function secMsg(id, text, ok) {
    const el = $(id);
    if (!el) { toast(text); return; }
    el.textContent = text; el.hidden = false;
    el.style.color = ok ? "var(--good, #3ba55d)" : "";
  }

  async function changePassword() {
    try {
      await api("/api/auth/change-password", "POST",
        { old_password: $("secOld").value, new_password: $("secNew").value });
      // Password change revokes refresh tokens server-side; grab a fresh pair.
      secMsg("secPwMsg", "Password updated.", true);
      $("secOld").value = ""; $("secNew").value = "";
    } catch (e) { secMsg("secPwMsg", e.message, false); }
  }

  async function startMfa() {
    try {
      const s = await api("/api/auth/mfa/setup", "POST");
      $("secMfaBox").innerHTML =
        '<p class="sub">Add this secret to your authenticator, then confirm with a code.</p>' +
        `<p><code style="word-break:break-all">${s.secret}</code></p>` +
        '<label>Code <input id="mfaEnableCode" inputmode="numeric" maxlength="6" placeholder="000000"></label>' +
        '<button class="btn primary" id="btnMfaEnable">Enable 2FA</button><p class="loginerr" id="mfaMsg" hidden></p>';
      $("btnMfaEnable").addEventListener("click", enableMfa);
    } catch (e) { secMsg("mfaMsg", e.message, false); }
  }

  async function enableMfa() {
    try {
      await api("/api/auth/mfa/enable", "POST", { code: $("mfaEnableCode").value.trim() });
      $("secMfaState").textContent = "Enabled.";
      renderMfaBox(true);
      secMsg("mfaMsg", "Two-factor enabled.", true);
    } catch (e) { secMsg("mfaMsg", e.message, false); }
  }

  async function disableMfa() {
    try {
      await api("/api/auth/mfa/disable", "POST", { code: $("mfaDisableCode").value.trim() });
      $("secMfaState").textContent = "Not enabled.";
      renderMfaBox(false);
    } catch (e) { secMsg("mfaMsg", e.message, false); }
  }

  // ---- wire up ----------------------------------------------------------- //
  // Show the AIR-GAPPED badge when the server reports it (no outbound egress).
  async function checkAirgap() {
    try {
      const h = await (await fetch("/api/health")).json();
      const pill = $("airgapPill");
      if (pill && h && h.airgapped) pill.hidden = false;
      // U-5: only advertise the seeded demo credentials when they actually exist.
      const hint = $("demoHint");
      if (hint) hint.hidden = !(h && h.demo);
    } catch (e) { /* noop */ }
  }

  function init() {
    initTheme();
    checkAirgap();
    $("btnNew").addEventListener("click", loadHome);
    $("btnStart").addEventListener("click", startNew);
    $("btnGenerate").addEventListener("click", generateScenario);
    $("btnImportYaml").addEventListener("click", importYaml);
    { const b = $("btnImportCtep"); if (b) b.addEventListener("click", () => importCtep(false)); }
    { const b = $("btnImportCtepOwn"); if (b) b.addEventListener("click", () => importCtep(true)); }
    $("btnCompliance").addEventListener("click", previewCompliance);
    $("btnTelemetry").addEventListener("click", telemetry);
    $("btnExportCsv").addEventListener("click", () => exportTimeline("csv"));
    $("btnExportJson").addEventListener("click", () => exportTimeline("json"));
    $("btnAttackLayer").addEventListener("click", () => {
      if (currentSid) downloadBlob(`/api/sessions/${currentSid}/attack-layer.json`, `attack-session-${currentSid}.json`);
    });
    $("btnDelivery").addEventListener("click", previewDelivery);
    $("btnAdjudicate").addEventListener("click", adjudicate);
    { const b = $("btnJoinCode"); if (b) b.addEventListener("click", generateJoinCode); }
    $("btnObserve").addEventListener("click", observe);
    $("btnOverride").addEventListener("click", () => {
      const goto = $("overrideGoto").value.trim();
      if (goto) advance("proctor_choice", null, goto);
    });
    $("btnPause").addEventListener("click", () => setStatus("pause"));
    $("btnResume").addEventListener("click", () => setStatus("resume"));
    $("btnComplete").addEventListener("click", () => setStatus("complete"));
    $("btnVerify").addEventListener("click", verify);
    $("btnCertificate").addEventListener("click", certificate);
    $("btnHotwash").addEventListener("click", hotwash);
    $("btnTour").addEventListener("click", () => { if (window.GauntletTour) window.GauntletTour.start(); });
    document.addEventListener("keydown", keys);
    $("modalX").addEventListener("click", () => ($("modal").hidden = true));
    $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) $("modal").hidden = true; });

    $("obsRatings").querySelectorAll(".rating").forEach((b) => {
      b.addEventListener("click", () => {
        $("obsRatings").querySelectorAll(".rating").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        selectedRating = b.dataset.r;
      });
    });
    document.querySelectorAll(".report-btns .btn").forEach((b) =>
      b.addEventListener("click", () => generateReport(b.dataset.aud)));

    $("btnLogin").addEventListener("click", login);
    $("loginPassword").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
    $("btnLogout").addEventListener("click", logout);
    $("btnSecurity").addEventListener("click", openSecurity);
    $("showArchived").addEventListener("change", () => loadHome());
    $("btnNewEnv").addEventListener("click", openNewEnvironment);
    $("btnMfa").addEventListener("click", submitMfa);
    $("mfaCode").addEventListener("keydown", (e) => { if (e.key === "Enter") submitMfa(); });
    initSso();

    consumeSsoFragment();  // pull SSO tokens off the URL before we check auth
    ensureAuthed().then((ok) => { if (ok) loadHome(); });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
