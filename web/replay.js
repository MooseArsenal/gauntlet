/* Session replay (L4): scenes at a pace, the roads not taken, rewind to a branch. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const STAFF = ["admin", "facilitator"];
  let rep = null, shown = 0, timer = null, canRewind = false, sid = null;
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
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
  async function api(path, method = "GET", body) {
    const t = token(); const headers = t ? { Authorization: `Bearer ${t}` } : {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in first."); }
    if (!res.ok) { let d = res.statusText; try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : d; } catch (e) { /* noop */ } const err = new Error(d); err.status = res.status; throw err; }
    return res.status === 204 ? null : res.json();
  }
  function dur(sec) { if (sec == null) return "—"; const m = Math.floor(sec / 60); return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m ${sec % 60}s`; }
  function money(v) { return v == null ? "" : "$" + Math.round(v).toLocaleString(); }
  function impactLine(im) {
    if (!im) return "";
    const bits = [];
    if (im.cost) bits.push(`cost ${money(im.cost)}`);
    if (im.downtime_hours) bits.push(`${im.downtime_hours} h downtime`);
    if (im.records) bits.push(`${Number(im.records).toLocaleString()} records`);
    if (im.reputation) bits.push(`reputation ${im.reputation}`);
    return bits.length ? ` — ${bits.join(", ")}` : "";
  }
  function sceneHtml(sc, i) {
    const dec = sc.decision;
    const blocks = [];
    if (sc.responses.length) blocks.push(`<div class="rp-block"><b>The room</b><ul>${sc.responses.map((r) => `<li>${esc(r.display_name || "?")}${r.cell ? ` <span class="hint">(${esc(r.cell)})</span>` : ""}: ${esc(r.label || r.text || "")}${r.score != null ? ` <span class="hint">score ${r.score}, ${r.latency_sec}s</span>` : ""}</li>`).join("")}</ul></div>`);
    if (sc.rulings.length) blocks.push(`<div class="rp-block"><b>The engine ruled</b><ul>${sc.rulings.map((r) => `<li><b>${esc(r.outcome || "")}</b>${r.probability != null ? ` <span class="hint">(${Math.round(r.probability * 100)}%)</span>` : ""}${r.techniques && r.techniques.length ? ` ${esc(r.techniques.join(", "))}` : ""}${r.target ? ` on ${esc(r.target)}` : ""}${r.rationale ? `<div class="hint">${esc(r.rationale)}</div>` : ""}</li>`).join("")}</ul></div>`);
    if (sc.red_actions.length) blocks.push(`<div class="rp-block"><b>Red cell</b><ul>${sc.red_actions.map((r) => `<li>${esc(r.action || (r.techniques || []).join(", "))} → <b>${esc(r.outcome || "")}</b></li>`).join("")}</ul></div>`);
    if (sc.telemetry.length || sc.evidence.length) blocks.push(`<div class="rp-block"><b>Evidence</b><ul>${sc.telemetry.map((t) => `<li>telemetry ${esc(t.technique || "")}: ${t.matched ? "matched" : "unmatched"}${t.latency_sec != null ? ` after ${t.latency_sec}s` : ""}</li>`).join("")}${sc.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`);
    if (sc.notes.length) blocks.push(`<div class="rp-block"><b>Proctor notes</b><ul>${sc.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div>`);
    const roads = sc.branches.length ? `<div class="rp-block" style="grid-column:1/-1"><b>${sc.branches.length > 1 ? "The roads" : "Onward"}</b>` +
      sc.branches.map((b) => `<div class="rp-road ${b.taken ? "taken" : ""}"><span>${b.taken ? "✔ " : "○ "}${esc(b.label || b.goto)} <span class="hint">→ ${esc(b.goto)}${b.when === "timeout" ? " (on timeout)" : ""}</span></span>` +
        (canRewind && !b.taken && dec ? `<button class="btn ghost small" data-rewind="${sc.seq}" data-goto="${esc(b.goto)}" title="Fork a new run that begins at this scene, with the state as it was">Rewind here</button>` : "") + `</div>`).join("") + `</div>` : "";
    return `<article class="rp-scene" data-i="${i}"><p class="eyebrow">${esc(sc.clock || "T+?")} · ${esc(sc.code)} · ${esc(sc.channel || "briefing")}${sc.visible_to.length ? ` · to ${esc(sc.visible_to.join(", "))}` : ""}${sc.elapsed_sec ? ` · ${dur(sc.elapsed_sec)} after the last scene` : ""}</p>` +
      `<h3 style="margin:.1rem 0 .3rem">${esc(sc.title)}</h3><p>${esc(sc.narrative)}</p>` +
      (dec ? `<p><b>The room took “${esc(dec.label || dec.goto)}”</b>${impactLine(dec.impact)}${dec.note ? ` <span class="hint">— ${esc(dec.note)}</span>` : ""}</p>` : sc.ended ? "<p><b>The exercise ended here.</b></p>" : (i === rep.scenes.length - 1 && rep.session.status !== "complete" ? '<p class="hint">Live — this is where the exercise is now.</p>' : "")) +
      `<div class="rp-blocks">${blocks.join("")}${roads}</div></article>`;
  }
  function render() {
    const total = rep.scenes.length;
    $("scenes").innerHTML = rep.scenes.slice(0, shown).map((sc, i) => sceneHtml(sc, i)).join("");
    $("progress").textContent = `Scene ${Math.min(shown, total)} of ${total}`;
    $("bar").style.width = `${total ? (shown / total) * 100 : 0}%`;
    $("scenes").querySelectorAll("[data-rewind]").forEach((b) => b.addEventListener("click", () => rewind(Number(b.dataset.rewind), b.dataset.goto)));
    const last = $("scenes").lastElementChild; if (last && timer) last.scrollIntoView({ behavior: "smooth", block: "end" });
    if (shown >= total) stop();
  }
  function step() { if (!rep) return; if (shown < rep.scenes.length) { shown += 1; render(); } }
  function play() { if (timer) return stop(); if (shown >= rep.scenes.length) shown = 0; step(); timer = setInterval(step, Number($("pace").value)); $("btnPlay").textContent = "⏸ Pause"; }
  function stop() { clearInterval(timer); timer = null; $("btnPlay").textContent = "▶ Play"; }
  async function rewind(seq, goto) {
    const sc = rep.scenes.find((s) => s.seq === seq);
    if (!confirm(`Rewind to ${sc.code} “${sc.title}”? A new running exercise starts there with the state as it was; this record is not changed. You then choose the road (${goto}) from the console.`)) return;
    try {
      const s = await api(`/api/sessions/${sid}/rewind`, "POST", { seq });
      $("forkPanel").hidden = false; $("forkMsg").textContent = `Exercise #${s.id} “${s.name}” is running from ${sc.code}. Open it in the console and take the other road.`;
      $("forkPanel").scrollIntoView({ behavior: "smooth" });
      toast("Rewound.");
    } catch (e) { toast(e.message); }
  }
  async function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    sid = new URLSearchParams(location.search).get("session");
    if (!sid) { $("lead").textContent = "Open a replay from the console: pick an exercise, then Replay."; return; }
    let me = null;
    try { me = await api("/api/auth/me"); } catch (e) { return; }
    canRewind = STAFF.includes(me.role);
    if (!canRewind) { $("lnkConsole").href = "/participant.html"; $("lnkConsole").textContent = "Play"; }
    try { rep = await api(`/api/sessions/${sid}/replay`); }
    catch (e) { if (e.status === 402) { $("gatePanel").hidden = false; $("gateMsg").textContent = e.message; $("lead").textContent = "Session replay"; } else $("lead").textContent = e.message; return; }
    $("title").textContent = rep.session.name;
    $("lead").textContent = `${rep.scenario.name}${rep.scenario.threat_actor ? ` · ${rep.scenario.threat_actor}` : ""} · ${rep.session.status}`;
    $("stats").innerHTML = `<div class="stat"><div class="stat-v">${rep.scenes.length}</div><div class="stat-l">Scenes</div></div><div class="stat"><div class="stat-v">${rep.branch_points}</div><div class="stat-l">Branch points</div></div>` +
      `<div class="stat"><div class="stat-v">${dur(rep.duration_sec)}</div><div class="stat-l">Duration</div></div><div class="stat"><div class="stat-v">${rep.scenes.reduce((n, s) => n + s.responses.length, 0)}</div><div class="stat-l">Decisions made</div></div>`;
    if (rep.rewound_from) { $("rewound").hidden = false; $("rewound").textContent = `This run was rewound from exercise #${rep.rewound_from.session_id} at ${rep.rewound_from.code}.`; }
    $("player").hidden = false;
    $("btnPlay").addEventListener("click", play);
    $("btnStep").addEventListener("click", () => { stop(); step(); });
    $("btnAll").addEventListener("click", () => { stop(); shown = rep.scenes.length; render(); });
    $("btnRestart").addEventListener("click", () => { stop(); shown = 0; render(); });
    $("pace").addEventListener("change", () => { if (timer) { stop(); play(); } });
    shown = 1; render();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
