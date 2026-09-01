/* Gauntlet guided wizards (Q3) — mouse-first flows over the existing API.
 * Build an exercise / Run a session / Report & evidence. Every flow is a thin
 * orchestration of endpoints the console/editor already use; "Console" and
 * "Editor" links in the header are the always-available granular escape hatch.
 */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);

  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  async function api(path, method = "GET", body) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    const t = token();
    if (t) headers["Authorization"] = `Bearer ${t}`;
    const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/index.html"; throw new Error("Sign in first."); }
    if (!res.ok) {
      let d = res.statusText; try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail || j); } catch (e) { /* noop */ }
      throw new Error(d);
    }
    return res.status === 204 ? null : res.json();
  }
  async function downloadBlob(path, filename) {
    try {
      const res = await fetch(path, { headers: token() ? { Authorization: `Bearer ${token()}` } : {} });
      if (!res.ok) throw new Error("Download failed");
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a"); a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (e) { toast(e.message); }
  }
  function toast(m) { const el = $("toast"); el.textContent = m; el.hidden = false; clearTimeout(el._t); el._t = setTimeout(() => (el.hidden = true), 2600); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

  // ---- controller -------------------------------------------------------- //
  let flow = null, idx = 0, data = {};
  const FLOWS = {};   // name -> [step,...]
  const LABEL = { build: "Build an exercise", run: "Run a session", report: "Report & evidence" };

  function start(name) { flow = name; idx = 0; data = {}; $("launcher").hidden = true; $("stepHost").hidden = false; renderStep(); }
  function home() { flow = null; $("stepHost").hidden = true; $("launcher").hidden = false; $("crumbs").innerHTML = ""; }

  function renderStep() {
    const steps = FLOWS[flow]; const step = steps[idx];
    $("crumbs").innerHTML = `${esc(LABEL[flow])} · <b>${esc(step.title)}</b>`;
    $("dots").innerHTML = steps.map((s, i) => `<span class="d ${i === idx ? "on" : i < idx ? "done" : ""}"></span>`).join("");
    $("stepBody").innerHTML = `<h2>${esc(step.title)}</h2><p class="wz-lead">${esc(step.lead || "")}</p><div id="stepInner"></div>`;
    step.render($("stepInner"));
    $("btnBack").textContent = idx === 0 ? "Cancel" : "Back";
    $("btnNext").textContent = step.nextLabel || "Next";
    $("btnNext").hidden = !!step.terminal;
    const adv = $("advLink");
    if (step.advance) { adv.hidden = false; adv.textContent = step.advance.label; adv.href = step.advance.href; }
    else adv.hidden = true;
  }
  async function next() {
    const step = FLOWS[flow][idx];
    try {
      if (step.onNext) { const ok = await step.onNext(); if (ok === false) return; }
      if (idx < FLOWS[flow].length - 1) { idx += 1; renderStep(); }
    } catch (e) { toast(e.message); }
  }
  function back() { if (idx === 0) home(); else { idx -= 1; renderStep(); } }

  // ---- reusable renderers ------------------------------------------------ //
  function tiles(el, items, key) {
    el.innerHTML = `<div class="wz-tiles">${items.map((it) => `
      <button class="wz-tile ${data[key] === it.value ? "sel" : ""}" data-v="${esc(it.value)}">
        ${it.meta ? `<span class="m">${esc(it.meta)}</span>` : ""}
        <span class="t">${esc(it.title)}</span>
        ${it.desc ? `<span class="d">${esc(it.desc)}</span>` : ""}
      </button>`).join("")}</div>`;
    el.querySelectorAll(".wz-tile").forEach((t) => t.addEventListener("click", () => {
      data[key] = t.getAttribute("data-v"); el.querySelectorAll(".wz-tile").forEach((x) => x.classList.remove("sel")); t.classList.add("sel");
    }));
  }
  function choice(el, opts, key, def) {
    if (data[key] == null) data[key] = def;
    el.innerHTML = `<div class="wz-choice">${opts.map((o) => `<button class="opt ${data[key] === o.value ? "sel" : ""}" data-v="${esc(o.value)}">${esc(o.label)}</button>`).join("")}</div>`;
    el.querySelectorAll(".opt").forEach((o) => o.addEventListener("click", () => { data[key] = o.getAttribute("data-v"); el.querySelectorAll(".opt").forEach((x) => x.classList.remove("sel")); o.classList.add("sel"); }));
  }

  // ---- BUILD flow -------------------------------------------------------- //
  // Step 1 is a three-mode "choose your adversary" picker: by scenario type
  // (template_key), by real ATT&CK group (actor_key), or by industry (sector →
  // the groups that target it → actor_key). Each mode offers a Random pick.
  const PICK_MODES = [
    { value: "type", label: "By scenario type" },
    { value: "actor", label: "By threat actor" },
    { value: "sector", label: "By industry" },
  ];
  function clearPick() { data.template_key = null; data.actor_key = null; data.actorName = null; }

  function actorTile(g) {
    return {
      value: g.key, title: g.name,
      meta: `${g.attack_id}${g.aliases && g.aliases.length ? " · " + g.aliases[0] : ""}`,
      desc: g.description,
    };
  }

  async function renderTypeMode(host) {
    host.innerHTML = '<p class="hint">Loading library…</p>';
    const tmpls = await api("/api/catalog/templates");
    host.innerHTML = `<div class="wz-pickhead"><span></span><button class="btn ghost small" id="wzRand">🎲 Random</button></div><div id="wzGrid"></div>`;
    tiles($("wzGrid"), tmpls.map((t) => ({ value: t.key, title: t.name, desc: t.narrative })), "template_key");
    $("wzRand").addEventListener("click", () => {
      const pick = tmpls[Math.floor(Math.random() * tmpls.length)];
      clearPick(); data.template_key = pick.key; renderTypeMode(host);
    });
  }

  async function renderActorMode(host, sector) {
    host.innerHTML = '<p class="hint">Loading adversaries…</p>';
    const groups = await api("/api/catalog/attack-groups" + (sector ? `?sector=${encodeURIComponent(sector)}` : ""));
    if (!groups.length) { host.innerHTML = '<p class="hint">No adversaries match — try another industry.</p>'; return; }
    host.innerHTML = `<div class="wz-pickhead"><span class="wz-count">${groups.length} real ATT&CK group${groups.length === 1 ? "" : "s"}</span><button class="btn ghost small" id="wzRand">🎲 Surprise me</button></div><div id="wzGrid"></div>`;
    tiles($("wzGrid"), groups.map(actorTile), "actor_key");
    // remember chosen group's display name for the summary
    $("wzGrid").querySelectorAll(".wz-tile").forEach((t) => t.addEventListener("click", () => {
      const g = groups.find((x) => x.key === t.getAttribute("data-v")); data.actorName = g ? g.name : null; data.template_key = null;
    }));
    $("wzRand").addEventListener("click", async () => {
      const g = await api("/api/catalog/attack-groups/random" + (sector ? `?sector=${encodeURIComponent(sector)}` : ""));
      clearPick(); data.actor_key = g.key; data.actorName = g.name;
      renderActorMode(host, sector);
    });
  }

  async function renderSectorMode(host) {
    // Data-driven industry list: the union of sectors the catalog's groups target.
    if (!data._sectors) {
      const all = await api("/api/catalog/attack-groups");
      data._sectors = [...new Set(all.flatMap((g) => g.sectors))].sort();
    }
    if (data.sector == null) data.sector = data._sectors[0];
    host.innerHTML =
      `<div class="wz-field"><label>Your industry / org type</label>
         <select id="wzSector">${data._sectors.map((s) => `<option value="${esc(s)}" ${s === data.sector ? "selected" : ""}>${esc(s.replace(/-/g, " "))}</option>`).join("")}</select></div>
       <p class="wz-lead" style="margin:.2rem 0 .8rem">Adversaries publicly reported to target this industry:</p>
       <div id="wzSectorGroups"></div>`;
    $("wzSector").addEventListener("change", (e) => { data.sector = e.target.value; clearPick(); renderSectorMode(host); });
    renderActorMode($("wzSectorGroups"), data.sector);
  }

  FLOWS.build = [
    {
      title: "Choose your adversary", lead: "Emulate a real ATT&CK group, start from a scenario type, or find who targets your industry — you can tune everything afterwards.",
      async render(el) {
        if (!data.pickMode) data.pickMode = "type";
        el.innerHTML =
          `<div class="wz-seg" id="wzSeg">${PICK_MODES.map((m) => `<button class="seg ${data.pickMode === m.value ? "on" : ""}" data-m="${m.value}">${m.label}</button>`).join("")}</div>
           <div id="wzPick"></div>`;
        const host = $("wzPick");
        const renderMode = () => {
          if (data.pickMode === "type") return renderTypeMode(host);
          if (data.pickMode === "actor") return renderActorMode(host, null);
          return renderSectorMode(host);
        };
        $("wzSeg").querySelectorAll(".seg").forEach((b) => b.addEventListener("click", () => {
          data.pickMode = b.getAttribute("data-m"); clearPick();
          $("wzSeg").querySelectorAll(".seg").forEach((x) => x.classList.remove("on")); b.classList.add("on");
          renderMode();
        }));
        await renderMode();
      },
      onNext() {
        if (!data.template_key && !data.actor_key) { toast("Pick a scenario type or an adversary."); return false; }
      },
    },
    {
      title: "Ground it in your environment", lead: "Scenes are filled with real assets from the environment you choose.",
      async render(el) {
        const envs = await api("/api/environments");
        if (!envs.length) { el.innerHTML = '<p class="hint">No environments yet — create one in the <a href="/index.html">console</a> first.</p>'; return; }
        if (data.environment_id == null) data.environment_id = envs[0].id;
        const pick = data.actor_key ? `Emulating <b>${esc(data.actorName || data.actor_key)}</b>` : `Scenario type <b>${esc(data.template_key)}</b>`;
        el.innerHTML =
          `<p class="wz-pickchip">${pick}${data.actor_key && data.template_key ? ` · framed as <b>${esc(data.template_key)}</b>` : ""}</p>` +
          `<div class="wz-field"><label>Environment</label><select id="wzEnv">${envs.map((e) => `<option value="${e.id}" ${e.id === data.environment_id ? "selected" : ""}>${esc(e.name)} · ${esc(e.sector || "")}</option>`).join("")}</select></div>` +
          `<div class="wz-field"><label>Name (optional)</label><input id="wzName" placeholder="e.g. Q3 phishing drill" value="${esc(data.name || "")}"></div>`;
        $("wzEnv").addEventListener("change", (e) => (data.environment_id = Number(e.target.value)));
        $("wzName").addEventListener("input", (e) => (data.name = e.target.value));
      },
      nextLabel: "Generate ✨",
      async onNext() {
        if (data.environment_id == null) { toast("Pick an environment."); return false; }
        data.scenario = await api("/api/scenarios/generate", "POST", {
          environment_id: data.environment_id,
          actor_key: data.actor_key || null,
          template_key: data.template_key || null,
          name: data.name || null,
        });
        toast(`Generated "${data.scenario.name}"`);
      },
    },
    {
      title: "Ready", lead: "", terminal: true,
      render(el) {
        const s = data.scenario;
        el.innerHTML = `<div class="wz-done"><div class="big">🎯</div><h2>${esc(s.name)}</h2>
          <p class="wz-lead">${s.injects.length} scenes · ${s.objectives.length} objectives, grounded and ready.</p>
          <div class="row">
            <a class="btn primary" href="/editor.html">Open in editor</a>
            <button class="btn" id="wzStart">Start exercise now</button>
            <button class="btn ghost" id="wzAgain">Build another</button>
          </div></div>`;
        $("wzStart").addEventListener("click", async () => {
          try { const sess = await api("/api/sessions", "POST", { scenario_id: s.id, name: s.name }); await api(`/api/sessions/${sess.id}/start`, "POST"); location.href = "/index.html"; }
          catch (e) { toast(e.message); }
        });
        $("wzAgain").addEventListener("click", () => start("build"));
      },
    },
  ];

  // ---- RUN flow ---------------------------------------------------------- //
  FLOWS.run = [
    {
      title: "Pick a scenario", lead: "Choose a scenario to take live.",
      async render(el) {
        const scns = await api("/api/scenarios");
        if (!scns.length) { el.innerHTML = '<p class="hint">No scenarios yet — build one first.</p>'; return; }
        tiles(el, scns.map((s) => ({ value: String(s.id), title: s.name, meta: s.exercise_type, desc: s.threat_actor })), "scenario_id");
      },
      onNext() { if (!data.scenario_id) { toast("Pick a scenario."); return false; } },
    },
    {
      title: "How should it run?", lead: "Tabletop is discussion-based; functional and real-time drive live timers.",
      render(el) {
        el.innerHTML = `<div class="wz-field"><label>Mode</label><div id="wzMode"></div></div>
          <div class="wz-field"><label>Session name</label><input id="wzSn" placeholder="e.g. October drill" value="${esc(data.sname || "")}"></div>`;
        choice($("wzMode"), [
          { value: "tabletop", label: "Tabletop" }, { value: "sandbox", label: "Functional (sandbox)" }, { value: "real_time", label: "Real-time" },
        ], "mode", "tabletop");
        $("wzSn").addEventListener("input", (e) => (data.sname = e.target.value));
      },
      nextLabel: "Start ▶", terminal: false,
      async onNext() {
        const sess = await api("/api/sessions", "POST", { scenario_id: Number(data.scenario_id), name: data.sname || "Guided run", mode: data.mode });
        await api(`/api/sessions/${sess.id}/start`, "POST");
        data.session = sess;
      },
    },
    {
      title: "Running", lead: "", terminal: true,
      render(el) {
        el.innerHTML = `<div class="wz-done"><div class="big">🚀</div><h2>Exercise started</h2>
          <p class="wz-lead">Drive it from the facilitator console.</p>
          <div class="row"><a class="btn primary" href="/index.html">Open the console</a>
          <button class="btn ghost" id="wzAgain">Run another</button></div></div>`;
        $("wzAgain").addEventListener("click", () => start("run"));
      },
    },
  ];

  // ---- REPORT flow ------------------------------------------------------- //
  FLOWS.report = [
    {
      title: "Pick an exercise", lead: "Choose a session to report on.",
      async render(el) {
        const sess = await api("/api/sessions");
        if (!sess.length) { el.innerHTML = '<p class="hint">No sessions yet — run one first.</p>'; return; }
        tiles(el, sess.map((s) => ({ value: String(s.id), title: s.name, meta: s.status, desc: `session #${s.id}` })), "rsession");
      },
      onNext() { if (!data.rsession) { toast("Pick a session."); return false; } },
    },
    {
      title: "Choose outputs", lead: "Generate an audience report, or export evidence and the timeline.", terminal: true,
      render(el) {
        const sid = data.rsession;
        el.innerHTML = `<p class="lbl">Audience report (PDF)</p><div class="wz-choice" id="wzAud"></div>
          <p class="lbl" style="margin-top:1rem">Evidence &amp; exports</p>
          <div class="row" style="justify-content:flex-start;gap:.5rem;flex-wrap:wrap">
            <button class="btn" data-dl="evidence.pdf" data-fn="evidence.pdf">Compliance evidence PDF</button>
            <button class="btn ghost" data-dl="timeline.csv" data-fn="timeline.csv">Timeline CSV</button>
            <button class="btn ghost" data-dl="timeline.json" data-fn="timeline.json">Timeline JSON</button>
          </div>
          <div class="row" style="justify-content:flex-start;margin-top:1.3rem"><button class="btn ghost" id="wzAgain">Report on another</button></div>`;
        const auds = [["executive", "Executive"], ["technical", "Technical"], ["grc", "GRC"], ["training", "Training"]];
        $("wzAud").innerHTML = auds.map(([v, l]) => `<button class="opt" data-aud="${v}">${l}</button>`).join("");
        $("wzAud").querySelectorAll("[data-aud]").forEach((b) => b.addEventListener("click", async () => {
          try { const rep = await api(`/api/sessions/${sid}/reports`, "POST", { audience: b.getAttribute("data-aud") });
            await downloadBlob(`/api/sessions/${sid}/reports/${rep.id}.pdf`, `report-${b.getAttribute("data-aud")}.pdf`); }
          catch (e) { toast(e.message); }
        }));
        el.querySelectorAll("[data-dl]").forEach((b) => b.addEventListener("click", () =>
          downloadBlob(`/api/sessions/${sid}/${b.getAttribute("data-dl")}`, `${b.getAttribute("data-fn")}`)));
        $("wzAgain").addEventListener("click", () => start("report"));
      },
    },
  ];

  // ---- init -------------------------------------------------------------- //
  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "dark"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  function init() {
    initTheme();
    if (!token()) { location.href = "/index.html"; return; }
    document.querySelectorAll(".wz-card").forEach((c) => c.addEventListener("click", () => start(c.getAttribute("data-flow"))));
    $("btnNext").addEventListener("click", next);
    $("btnBack").addEventListener("click", back);
  }
  document.addEventListener("DOMContentLoaded", init);
})();
