/* Solo learning mode (S1): pick a side, play against the engine, get a debrief. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let me = null, cat = null, side = null, difficulty = "standard", run = null, clock = null, pickedTech = new Set(), pickedAsset = null;
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  function setTokens(a, r) { try { localStorage.setItem("gauntlet-token", a); if (r) localStorage.setItem("gauntlet-refresh", r); } catch (e) { /* noop */ } }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function toast(m) { const el = $("toast"); el.textContent = m; el.hidden = false; clearTimeout(el._t); el._t = setTimeout(() => (el.hidden = true), 3000); }
  function initTheme() {
    let t = "light"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  async function api(path, method = "GET", body, raw = false) {
    const t = token(); const headers = t ? { Authorization: `Bearer ${t}` } : {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (!res.ok) {
      let d = res.statusText;
      try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : (j.detail && j.detail.password ? j.detail.password.join("; ") : JSON.stringify(j.detail)); } catch (e) { /* noop */ }
      const err = new Error(d); err.status = res.status; throw err;
    }
    if (raw) return res;
    return res.status === 204 ? null : res.json();
  }
  function show(id) {
    ["authView", "pickView", "playView", "debriefView"].forEach((v) => { $(v).hidden = v !== id; });
    $("runMeta").hidden = id !== "playView";
    $("btnQuit").hidden = id !== "playView";
    $("btnRuns").hidden = !me || id === "authView";
    window.scrollTo(0, 0);
  }

  // ---- account ----
  // Sign-up confirmation (G): a deployment with mail configured answers 202 to
  // a registration and sends a link; the link lands here with ?confirm=<token>.
  function showConfirmNotice(el, email) {
    el.innerHTML = `<b>Check your inbox.</b> We sent a confirmation link to ${esc(email)}. Follow it to finish creating your account; it works for a day. ` +
      `<a href="#" id="lnkResend">Send it again</a>`;
    el.hidden = false;
    $("lnkResend").addEventListener("click", async (ev) => {
      ev.preventDefault();
      try { await api("/api/auth/confirm/resend", "POST", { email }); toast("Sent again, if the address is registered and unconfirmed."); }
      catch (e) { toast(e.message); }
    });
  }
  async function login() {
    $("liErr").hidden = true;
    const email = $("liEmail").value.trim();
    try {
      const out = await api("/api/auth/login", "POST", { email, password: $("liPass").value });
      if (out.mfa_required) { $("liErr").textContent = "This account uses two-factor sign-in; sign in on the console first."; $("liErr").hidden = false; return; }
      setTokens(out.access_token, out.refresh_token); await boot();
    } catch (e) {
      if (e.status === 403 && /confirm your email/i.test(e.message)) { showConfirmNotice($("liErr"), email); return; }
      $("liErr").textContent = e.message; $("liErr").hidden = false;
    }
  }
  async function register() {
    $("rgErr").hidden = true;
    const name = $("rgName").value.trim();
    const email = $("rgEmail").value.trim();
    try {
      const out = await api("/api/auth/register", "POST", { org_name: `${name || "My"} lab`, email, password: $("rgPass").value, name });
      if (out && out.confirmation_required) { showConfirmNotice($("rgErr"), out.email || email); return; }
      setTokens(out.access_token, out.refresh_token); toast("Welcome. Your workspace is ready."); await boot();
    } catch (e) { $("rgErr").textContent = e.message; $("rgErr").hidden = false; }
  }
  async function confirmFromLink(token) {
    // Scrub the token from the address bar whatever happens; it is single-use.
    try { history.replaceState(null, "", location.pathname); } catch (e) { /* noop */ }
    try {
      const out = await api("/api/auth/confirm", "POST", { token });
      setTokens(out.access_token, out.refresh_token); toast("Email confirmed. Welcome — your workspace is ready.");
    } catch (e) {
      if (e.status === 409) toast("That address is already confirmed. Sign in.");
      else { $("rgErr").textContent = e.message + " Sign up again or ask for a new link from the sign-in card."; $("rgErr").hidden = false; }
    }
  }

  // ---- pick ----
  const SIDE_BLURB = { blue: "Respond to what the adversary does. Every scene is a call: contain, escalate, wait.",
    exec: "Run the business side: who to tell, what to say, when to pay.", red: "Attack the environment and stay unseen. Reach a crown jewel." };
  async function loadPick() {
    cat = await api("/api/solo/scenarios");
    $("sides").innerHTML = cat.sides.map((s) => `<button class="side ${side === s.key ? "on" : ""}" data-side="${s.key}"><span class="door-k">${esc(s.key)}</span><b>${esc(s.label.split(" — ")[0])}</b><span class="hint">${esc(SIDE_BLURB[s.key] || "")}</span></button>`).join("");
    $("sides").querySelectorAll("[data-side]").forEach((b) => b.addEventListener("click", () => { side = b.dataset.side; loadPick(); }));
    $("difficulties").innerHTML = cat.difficulties.map((d) => `<button class="chip ${difficulty === d.key ? "on" : ""}" data-diff="${d.key}" style="font-family:var(--body);font-size:.85rem;padding:.35rem .7rem">${esc(d.label)}</button>`).join("");
    $("difficulties").querySelectorAll("[data-diff]").forEach((b) => b.addEventListener("click", () => { difficulty = b.dataset.diff; loadPick(); }));
    const lv = cat.difficulties.find((d) => d.key === difficulty) || {};
    $("diffHint").textContent = side === "red"
      ? `Red on ${difficulty}: ${lv.alert} detections evict you, ${lv.moves} moves, ${lv.foothold ? "a foothold before any crown jewel" : "no foothold needed"}, ${lv.deception ? "canaries live (a touch costs two alert points)" : "no canaries"}, ${lv.hints ? "technique hints on" : "no hints"}${lv.zones ? "" : ", zones hidden"}. Score weight ×${lv.weight}.`
      : side ? `${side === "exec" ? "Executive" : "Blue"} on ${difficulty}: ${lv.clock} s per decision, ${lv.shuffle ? "options shuffled" : "options in authored order (worked examples always shuffle)"}, ${lv.distractors ? lv.distractors + " distractor" + (lv.distractors > 1 ? "s" : "") + " mixed in" : "no distractors"}, ${lv.hints ? "hints shown" : "no hints"}, impact ×${lv.impact}. Score weight ×${lv.weight}.`
      : "Pick a side to see what the difficulty changes.";
    const types = side ? (cat.types[side] || []) : [];
    $("pickHint").textContent = side ? "The engine assembles a fresh run from the library each time: a sector environment, an adversary from the pool, the attack that fits." : "Choose a side first.";
    $("types").innerHTML = types.map((t) => `<button class="door" data-type="${esc(t.key)}"><span class="door-k">${esc(side)} · ${esc(difficulty)}</span><b>${esc(t.label)}</b><span>${esc(t.blurb)}${t.win ? " " + esc(t.win) : ""}</span></button>`).join("");
    $("types").querySelectorAll("[data-type]").forEach((b) => b.addEventListener("click", () => startEngagement(b.dataset.type)));
    const list = side ? cat.scenarios.filter((s) => s.sides.includes(side)) : [];
    $("scenarios").innerHTML = list.map((s) => `<button class="scn" data-scn="${s.id}"><span><b>${esc(s.name)}</b><br><span class="hint">${esc(s.threat_actor || "")}${s.sector ? " · " + esc(s.sector) : ""} · ${s.scenes} scenes</span></span><span>${s.best[side] != null ? `<span class="pill">best ${s.best[side]}</span> ` : ""}<span class="btn small">Play</span></span></button>`).join("") || (side ? "" : '<p class="hint">Choose a side first.</p>');
    $("scenarios").querySelectorAll("[data-scn]").forEach((b) => b.addEventListener("click", () => start(Number(b.dataset.scn))));
    show("pickView");
  }
  async function loadRuns() {
    try {
      const rows = await api("/api/solo/runs");
      $("runsPanel").hidden = false;
      $("runs").innerHTML = rows.length ? `<table class="grade"><thead><tr><th>When</th><th>Scenario</th><th>Side</th><th>Difficulty</th><th class="n">Score</th><th></th></tr></thead><tbody>` +
        rows.map((r) => `<tr><td>${esc(r.started_at ? new Date(r.started_at).toLocaleDateString() : "")}</td><td>${esc(r.scenario)}</td><td>${esc(r.side)}</td><td>${esc(r.difficulty || "standard")}</td><td class="n">${r.score == null ? "—" : `<span class="g">${r.score}</span> ${esc(r.badge || "")}`}</td><td>${r.status === "complete" ? `<button class="btn ghost small" data-db="${r.id}">Debrief</button>` : `<button class="btn small" data-resume="${r.id}">Resume</button>`}</td></tr>`).join("") + `</tbody></table>` : '<p class="hint">No runs yet.</p>';
      $("runs").querySelectorAll("[data-db]").forEach((b) => b.addEventListener("click", () => showDebrief(Number(b.dataset.db))));
      $("runs").querySelectorAll("[data-resume]").forEach((b) => b.addEventListener("click", async () => { run = await api(`/api/solo/${b.dataset.resume}`); side = run.side; render(); }));
    } catch (e) { toast(e.message); }
  }

  // ---- play ----
  async function start(scenarioId) {
    try { run = await api("/api/solo/start", "POST", { scenario_id: scenarioId, side, difficulty }); render(); }
    catch (e) { toast(e.message); }
  }
  async function startEngagement(type) {
    toast("Assembling your engagement…");
    try { run = await api("/api/solo/start", "POST", { side, type, difficulty }); render(); }
    catch (e) { toast(e.message); }
  }
  function render() {
    if (!run) return;
    if (run.status === "complete") { showDebrief(run.id); return; }
    show("playView");
    $("sidePill").textContent = `${run.side} · ${run.difficulty || "standard"}`; $("runName").textContent = run.scenario.name;
    $("bar").style.width = `${run.scenes_total ? Math.round(100 * run.scene_index / run.scenes_total) : 0}%`;
    $("sideLabel").textContent = run.side_label;
    $("roe").textContent = run.scenario.rules_of_engagement || "Facilitated simulation. No production access. Every action is simulated.";
    const sc = run.scene;
    $("scene").className = "solo-scene reveal";
    $("scene").innerHTML = sc ? `<p class="eyebrow"><span class="tag">${esc(sc.channel || "briefing")}</span> ${esc(sc.code)} · ${esc(sc.clock || "")} · scene ${run.scene_index} of ${run.scenes_total}</p><h2>${esc(sc.title)}</h2><p>${esc(sc.narrative)}</p>` +
      (run.side !== "red" && sc.expected_actions.length ? `<p class="eyebrow">Consider</p><ul>${sc.expected_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>` : "") +
      (run.side === "red" && sc.attack_techniques.length ? `<p class="hint">Intel: this scene's adversary used ${esc(sc.attack_techniques.join(", "))}${sc.target_asset ? " on " + esc(sc.target_asset) : ""}.</p>` : "") : "<p class=\"muted\">Loading…</p>";
    const imp = run.impact || {};
    $("stats").innerHTML = run.side === "red"
      ? `<div class="stat"><div class="stat-v">${run.red.moves}/${run.red.max_moves}</div><div class="stat-l">Moves used</div></div><div class="stat"><div class="stat-v">${run.red.used.length}</div><div class="stat-l">Techniques tried</div></div>`
      : `<div class="stat"><div class="stat-v">${run.scene_index}/${run.scenes_total}</div><div class="stat-l">Scenes</div></div><div class="stat"><div class="stat-v">${imp.cost ? "$" + Math.round(imp.cost / 1000) + "k" : "—"}</div><div class="stat-l">Cost so far</div></div>`;
    $("feed").innerHTML = (run.feed || []).slice().reverse().map((f) => `<li class="${esc(f.kind)}"><span class="mono">${esc(f.clock || "")}</span><span>${esc(f.text)}</span></li>`).join("");
    if (run.side === "red") renderRed(); else renderDecision();
  }
  function renderDecision() {
    $("redPanel").hidden = true; $("alertBox").hidden = true;
    clearInterval(clock);
    const box = $("decision"); const d = run.decision;
    if (!d) {
      box.hidden = false;
      box.innerHTML = run.terminal ? `<p class="eyebrow">The story ends here</p><p>${esc(run.reason || "There is nothing more to decide.")}</p><button class="btn primary" id="btnFinishNow">See my debrief</button>`
        : run.addressed === false && run.scene
          ? `<p class="eyebrow">Another cell's call</p><p class="hint">This scene is addressed to a different cell. Read it, then continue; the engine plays that cell.</p><button class="btn primary" id="btnContinue">Continue</button>`
          : `<p class="eyebrow">No decision in this scene</p><p class="hint">Read it, then continue.</p><button class="btn primary" id="btnContinue">Continue</button>`;
      const f = $("btnFinishNow"); if (f) f.addEventListener("click", finish);
      const c = $("btnContinue"); if (c) c.addEventListener("click", skip);
      return;
    }
    box.hidden = false;
    box.innerHTML = `<p class="eyebrow">${d.kind === "comms" ? "Communications decision" : "Your call"} <span class="solo-clock" id="dcClock"></span></p><p class="dc-prompt">${esc(d.prompt)}</p>` +
      `<div class="dc-opts">${d.options.map((o) => `<button class="dc-opt" data-k="${esc(o.key)}"><span class="dc-key">${esc(o.key.toUpperCase())}</span>${esc(o.label)}</button>`).join("")}</div>` +
      (d.free_text ? `<textarea id="dcText" rows="3" placeholder="${d.kind === "comms" ? "Draft the statement you would issue…" : "Or write what you would do…"}"></textarea><button class="btn primary" id="dcSend">Submit</button>` : "") +
      `<p class="loginerr" id="dcErr" hidden></p>`;
    let picked = null;
    box.querySelectorAll(".dc-opt").forEach((b) => b.addEventListener("click", () => {
      if (d.kind !== "comms") { respond(b.dataset.k, ""); return; }
      picked = b.dataset.k; box.querySelectorAll(".dc-opt").forEach((x) => x.classList.toggle("on", x === b));
    }));
    const sendBtn = $("dcSend"); if (sendBtn) sendBtn.addEventListener("click", () => respond(picked, $("dcText").value.trim()));
    const limit = run.time_limit_sec || 120;
    const t0 = run.scene_started_at ? new Date(run.scene_started_at).getTime() : Date.now();
    const tick = () => {
      const left = Math.max(0, Math.round(limit - (Date.now() - t0) / 1000));
      const el = $("dcClock"); if (el) { el.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left`; el.classList.toggle("low", left <= 15); }
      if (left <= 0) { clearInterval(clock); skip(true); }
    };
    tick(); clock = setInterval(tick, 1000);
  }
  async function respond(option, text) {
    clearInterval(clock);
    try { const out = await api(`/api/solo/${run.id}/respond`, "POST", { option: option || null, text: text || "" }); run = out.view; render(); }
    catch (e) { const el = $("dcErr"); if (el) { el.textContent = e.message; el.hidden = false; } else toast(e.message); }
  }
  async function skip(timedOut) {
    clearInterval(clock);
    if (timedOut) toast("Time ran out — that counts as a decision too.");
    try { const out = await api(`/api/solo/${run.id}/skip`, "POST"); run = out.view; render(); } catch (e) { toast(e.message); }
  }
  async function finish() {
    clearInterval(clock);
    try { await api(`/api/solo/${run.id}/finish`, "POST"); showDebrief(run.id); } catch (e) { toast(e.message); }
  }
  function renderRed() {
    $("decision").hidden = true; $("redPanel").hidden = false; $("alertBox").hidden = false;
    const r = run.red;
    $("alert").innerHTML = Array.from({ length: r.max_alert }, (_, i) => `<i class="${i < r.alert ? "on" : ""}"></i>`).join("");
    $("moveCount").textContent = `— ${r.max_moves - r.moves} left${r.needs_foothold ? (r.foothold ? " · foothold gained" : " · no foothold yet") : ""}`;
    $("redRules").textContent = `Pick the techniques and the asset. Every move is ruled against the controls in place. ${r.max_alert} detections and you are evicted; reach a crown jewel (double border) unseen and you win.` +
      (r.needs_foothold ? " A crown jewel needs an unseen move on an outer asset first." : "") + (r.deception_live ? " Canaries are live: touching one costs two alert points." : "");
    $("techChips").innerHTML = r.techniques.map((t) => `<button class="chip ${pickedTech.has(t) ? "on" : ""}" data-t="${esc(t)}">${esc(t)}</button>`).join("") || '<span class="hint">No hints from this scenario; type technique ids below.</span>';
    $("techChips").querySelectorAll("[data-t]").forEach((b) => b.addEventListener("click", () => { pickedTech.has(b.dataset.t) ? pickedTech.delete(b.dataset.t) : pickedTech.add(b.dataset.t); b.classList.toggle("on"); }));
    $("assets").innerHTML = r.assets.map((a) => `<button class="asset ${a.crown_jewel ? "jewel" : ""} ${pickedAsset === a.code ? "on" : ""}" data-a="${esc(a.code)}" title="${a.crown_jewel ? "Crown jewel" : esc(a.zone)}">${esc(a.name)}<span class="mono">${esc(a.code)} · ${esc(a.zone || "")}${a.crown_jewel ? " · crown jewel" : ""}</span></button>`).join("");
    $("assets").querySelectorAll("[data-a]").forEach((b) => b.addEventListener("click", () => { pickedAsset = b.dataset.a; $("assets").querySelectorAll(".asset").forEach((x) => x.classList.toggle("on", x === b)); }));
  }
  async function move() {
    const typed = $("techFree").value.split(",").map((t) => t.trim()).filter(Boolean);
    const techniques = [...pickedTech, ...typed];
    if (!techniques.length) { $("moveErr").textContent = "Pick at least one technique."; return; }
    if (!pickedAsset) { $("moveErr").textContent = "Pick a target."; return; }
    $("moveErr").textContent = "";
    try {
      const out = await api(`/api/solo/${run.id}/move`, "POST", { techniques, target: pickedAsset, action: `${techniques.join(", ")} against ${pickedAsset}` });
      const ru = out.ruling;
      $("ruling").hidden = false;
      $("ruling").innerHTML = (window.GauntletGame ? window.GauntletGame.diceHtml(ru) : "") + `<p><b class="${ru.detected ? "verdict-poor" : "verdict-best"}">${ru.detected ? "DETECTED" : "Unseen"}</b> <span class="hint">(${Math.round((ru.probability || 0) * 100)}% detection odds)</span>${out.captured ? " <b>· crown jewel captured</b>" : ""}</p><p class="hint">${esc(ru.rationale || "")}</p>`;
      pickedTech = new Set(); $("techFree").value = ""; pickedAsset = null;
      run = out.view;
      if (out.status === "complete") { toast(out.outcome); setTimeout(() => showDebrief(run.id), 1800); } else render();
    } catch (e) { $("moveErr").textContent = e.message; }
  }

  // ---- debrief ----
  async function showDebrief(id) {
    clearInterval(clock);
    let d;
    try { d = await api(`/api/solo/${id}/debrief`); } catch (e) { toast(e.message); return; }
    run = { id, side: d.side, status: "complete" }; side = d.side;
    show("debriefView");
    $("dbScore").innerHTML = `${d.score}<small> / 100</small>`;
    $("dbTitle").textContent = `${d.badge} — ${d.scenario}`;
    $("dbHead").textContent = `${d.side_label} · ${d.difficulty_label || d.difficulty}${d.weight && d.weight !== 1 ? ` (raw ${d.raw_score} × ${d.weight})` : ""}. ${d.headline}`;
    const s = d.summary;
    $("dbStats").innerHTML = d.side === "red"
      ? `<div class="stat"><div class="stat-v">${s.moves}</div><div class="stat-l">Moves</div></div><div class="stat"><div class="stat-v">${s.unseen}</div><div class="stat-l">Unseen</div></div><div class="stat"><div class="stat-v">${s.detected}</div><div class="stat-l">Detected</div></div><div class="stat"><div class="stat-v">${s.captured ? "Yes" : "No"}</div><div class="stat-l">Crown jewel</div></div>`
      : `<div class="stat"><div class="stat-v">${s.decisions}</div><div class="stat-l">Decisions</div></div><div class="stat"><div class="stat-v">${s.best}</div><div class="stat-l">Best choice made</div></div><div class="stat"><div class="stat-v">${s.median_latency_sec == null ? "—" : s.median_latency_sec + "s"}</div><div class="stat-l">Median time</div></div><div class="stat"><div class="stat-v">${s.impact && s.impact.cost ? "$" + Math.round(s.impact.cost / 1000) + "k" : "—"}</div><div class="stat-l">Cost of the path</div></div>`;
    $("dbRows").innerHTML = d.side === "red"
      ? `<table class="grade"><thead><tr><th>#</th><th>Techniques</th><th>Target</th><th>Outcome</th><th>Why</th></tr></thead><tbody>${d.rows.map((r) => `<tr><td>${r.n}</td><td class="mono">${esc(r.techniques.join(", "))}</td><td>${esc(r.target)}</td><td class="${r.detected ? "verdict-poor" : "verdict-best"}">${r.detected ? "Detected" : "Unseen"}${r.captured ? " · captured" : ""}</td><td class="hint">${esc(r.rationale)}</td></tr>`).join("")}</tbody></table>`
      : `<table class="grade"><thead><tr><th>Scene</th><th>You chose</th><th>Best choice</th><th class="n">Score</th><th class="n">Time</th></tr></thead><tbody>${d.rows.map((r) => `<tr><td><b>${esc(r.code)}</b> ${esc(r.title)}<br><span class="hint">${esc(r.prompt)}</span></td><td class="verdict-${esc(r.verdict)}">${esc(r.chosen)}${r.timed_out ? " (timed out)" : ""}${r.chosen_note && r.verdict !== "best" ? `<br><span class="hint">${esc(r.chosen_note)}</span>` : ""}</td><td>${esc(r.best)}${r.best_note ? `<br><span class="hint">${esc(r.best_note)}</span>` : ""}</td><td class="n g">${r.score == null ? "—" : Math.round(r.score * 100)}</td><td class="n">${r.latency_sec == null ? "—" : r.latency_sec + "s"}</td></tr>`).join("")}</tbody></table>`;
    $("dbWork").innerHTML = d.work_on.length ? d.work_on.map((w) => `<li>${esc(w)}</li>`).join("") : "<li>Nothing stands out. Try the other side.</li>";
    $("btnPdf").onclick = async () => {
      try { const res = await api(`/api/solo/${id}/debrief.pdf`, "GET", undefined, true); const blob = await res.blob(); const u = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = u; a.download = `solo-debrief-${id}.pdf`; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 2000); }
      catch (e) { toast(e.message); }
    };
  }

  async function boot() {
    const confirmTok = new URLSearchParams(location.search).get("confirm");
    if (confirmTok) await confirmFromLink(confirmTok);
    try { me = await api("/api/auth/me"); } catch (e) { me = null; }
    if (!me) { show("authView"); return; }
    $("userChip").hidden = false; $("userLabel").textContent = me.email;
    const q = new URLSearchParams(location.search);
    if (q.get("debrief")) { showDebrief(Number(q.get("debrief"))); return; }
    await loadPick();
  }
  function init() {
    initTheme();
    $("btnLogin").addEventListener("click", login);
    $("btnRegister").addEventListener("click", register);
    $("btnLogout").addEventListener("click", () => { try { localStorage.removeItem("gauntlet-token"); localStorage.removeItem("gauntlet-refresh"); } catch (e) { /* noop */ } location.reload(); });
    $("btnRuns").addEventListener("click", async () => { await loadPick(); await loadRuns(); $("runsPanel").scrollIntoView({ behavior: "smooth" }); });
    $("btnQuit").addEventListener("click", async () => { if (!run || !confirm("End this run now? You get the debrief for what you have done so far.")) return; finish(); });
    $("btnMove").addEventListener("click", move);
    $("btnAgain").addEventListener("click", () => loadPick());
    $("btnOther").addEventListener("click", () => { side = null; loadPick(); });
    boot();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
