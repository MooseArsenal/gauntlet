/* Gauntlet visual scenario editor (Q2) — vanilla SVG, no framework.
 *
 * Model: a graph of inject nodes and branch edges, loaded from a scenario and
 * saved back through PUT /api/scenarios/{id}/graph. Node positions ride in each
 * inject's meta.pos so a layout survives a round-trip.
 */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const SVGNS = "http://www.w3.org/2000/svg";

  // Kill-chain phase order → the same colour tokens editor.css defines.
  const PHASES = ["initial-access", "execution", "persistence", "command-and-control",
    "lateral-movement", "collection", "exfiltration", "impact"];
  const phaseColor = (p) => `var(--ph-${(p || "default").replace(/[^a-z-]/g, "") || "default"})`;

  // ---- auth / api -------------------------------------------------------- //
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  async function api(path, method = "GET", body) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    const t = token();
    if (t) headers["Authorization"] = `Bearer ${t}`;
    const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (res.status === 401) { location.href = "/index.html"; throw new Error("Sign in first."); }
    if (!res.ok) {
      let d = res.statusText;
      try { const j = await res.json(); d = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail || j); } catch (e) { /* noop */ }
      throw new Error(d);
    }
    return res.status === 204 ? null : (res.headers.get("content-type") || "").includes("json") ? res.json() : res.text();
  }
  function toast(m) { const el = $("toast"); el.textContent = m; el.hidden = false; clearTimeout(el._t); el._t = setTimeout(() => (el.hidden = true), 2600); }

  // ---- state ------------------------------------------------------------- //
  let scenarioId = null;
  let nodes = [];   // {code,title,channel,narrative,techniques,target,is_start,objective_code,branches,x,y,seq}
  let bank = [];    // inject-bank palette entries
  let selected = null;   // {kind:'node'|'edge', ...}
  let view = { x: 0, y: 0, k: 1 };  // pan/zoom
  const undoStack = [], redoStack = [];

  const NODE_W = 168, NODE_H = 66;

  // ---- model helpers ----------------------------------------------------- //
  function snapshot() { return JSON.stringify(nodes); }
  function pushUndo() { undoStack.push(snapshot()); if (undoStack.length > 100) undoStack.shift(); redoStack.length = 0; }
  function restore(s) { nodes = JSON.parse(s); selected = null; render(); }
  function undo() { if (!undoStack.length) return; redoStack.push(snapshot()); restore(undoStack.pop()); }
  function redo() { if (!redoStack.length) return; undoStack.push(snapshot()); restore(redoStack.pop()); }

  function nodeByCode(code) { return nodes.find((n) => n.code === code); }

  function fromScenario(scn) {
    const injects = (scn.injects || []).slice().sort((a, b) => (a.sequence || 0) - (b.sequence || 0));
    nodes = injects.map((inj, i) => {
      const pos = (inj.meta && inj.meta.pos) || null;
      return {
        code: inj.code, title: inj.title || inj.code, channel: inj.channel || "briefing",
        narrative: inj.narrative || "", techniques: inj.attack_techniques || [],
        target: inj.target_asset || "", is_start: !!inj.is_start,
        objective_code: inj.objective_code || "", act: inj.act || "",
        branches: (inj.branches || []).map((b) => ({ ...b })),
        seq: inj.sequence != null ? inj.sequence : i,
        meta: inj.meta || {},
        x: pos ? pos.x : 0, y: pos ? pos.y : 0, _placed: !!pos,
      };
    });
    if (nodes.some((n) => !n._placed)) autoLayout();
  }

  function toInjects() {
    return nodes.map((n, i) => ({
      code: n.code, sequence: i, title: n.title, channel: n.channel, narrative: n.narrative,
      attack_techniques: n.techniques, target_asset: n.target, is_start: n.is_start,
      objective_code: n.objective_code, act: n.act, branches: n.branches,
      meta: { ...(n.meta || {}), pos: { x: Math.round(n.x), y: Math.round(n.y) } },
    }));
  }

  // Simple layered layout: BFS from the start node, column = depth, row = order.
  function autoLayout() {
    const start = nodes.find((n) => n.is_start) || nodes[0];
    const depth = new Map();
    if (start) {
      const q = [[start.code, 0]]; depth.set(start.code, 0);
      while (q.length) {
        const [code, d] = q.shift();
        const n = nodeByCode(code);
        for (const b of (n ? n.branches : [])) {
          if (b.goto && !depth.has(b.goto)) { depth.set(b.goto, d + 1); q.push([b.goto, d + 1]); }
        }
      }
    }
    let orphan = Math.max(0, ...[...depth.values()]) + 1;
    const rows = {};
    nodes.forEach((n) => {
      const d = depth.has(n.code) ? depth.get(n.code) : orphan;
      rows[d] = (rows[d] || 0);
      n.x = 60 + d * (NODE_W + 70);
      n.y = 40 + rows[d] * (NODE_H + 40);
      n._placed = true;
      rows[d] += 1;
    });
  }

  // ---- validation (mirrors the server's graph check) --------------------- //
  function validate() {
    const issues = [];
    const codes = nodes.map((n) => n.code);
    if (new Set(codes).size !== codes.length) issues.push("Inject codes must be unique.");
    const starts = nodes.filter((n) => n.is_start);
    if (nodes.length && starts.length !== 1) issues.push(`Exactly one start inject (found ${starts.length}).`);
    const known = new Set(codes);
    const reachable = new Set();
    if (starts[0]) {
      const q = [starts[0].code]; reachable.add(starts[0].code);
      while (q.length) {
        const n = nodeByCode(q.shift());
        for (const b of (n ? n.branches : [])) if (b.goto && known.has(b.goto) && !reachable.has(b.goto)) { reachable.add(b.goto); q.push(b.goto); }
      }
    }
    const bad = new Set();
    nodes.forEach((n) => {
      (n.branches || []).forEach((b) => {
        if (b.goto && !known.has(b.goto)) { issues.push(`Branch from ${n.code} → unknown ${b.goto}.`); bad.add(n.code); }
      });
      if (nodes.length > 1 && !reachable.has(n.code)) { issues.push(`${n.code} is unreachable.`); bad.add(n.code); }
    });
    return { ok: issues.length === 0, issues, bad };
  }

  // ---- rendering --------------------------------------------------------- //
  const svg = () => $("canvas");
  function applyViewBox() {
    const s = svg(); const w = s.clientWidth || 1000, h = s.clientHeight || 700;
    s.setAttribute("viewBox", `${view.x} ${view.y} ${w / view.k} ${h / view.k}`);
  }
  function el(tag, attrs, parent) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function anchor(n, side) {
    return side === "out" ? { x: n.x + NODE_W, y: n.y + NODE_H / 2 } : { x: n.x, y: n.y + NODE_H / 2 };
  }

  function render() {
    const v = validate();
    $("validity").className = "ed-validity " + (v.ok ? "ok" : "bad");
    $("validity").title = v.ok ? "Valid" : v.issues.join(" ");
    $("edEmpty").hidden = nodes.length > 0;
    applyViewBox();

    const edgesG = $("edges"), nodesG = $("nodes");
    edgesG.innerHTML = ""; nodesG.innerHTML = "";

    // edges
    nodes.forEach((n) => {
      (n.branches || []).forEach((b, bi) => {
        const to = b.goto && nodeByCode(b.goto);
        if (!to) return;
        const a = anchor(n, "out"), z = anchor(to, "in");
        const midx = (a.x + z.x) / 2;
        const d = `M${a.x},${a.y} C${midx},${a.y} ${midx},${z.y} ${z.x},${z.y}`;
        const isSel = selected && selected.kind === "edge" && selected.code === n.code && selected.bi === bi;
        el("path", { d, class: "edge-hit", "data-edge": `${n.code}|${bi}` }, edgesG);
        el("path", { d, class: "edge" + (b.when === "timeout" ? " timeout" : "") + (isSel ? " sel" : "") }, edgesG);
        const lg = el("g", { class: "edge-label", transform: `translate(${midx},${(a.y + z.y) / 2})` }, edgesG);
        const label = b.trigger || b.when || "→";
        const tw = label.length * 5.4 + 8;
        el("rect", { x: -tw / 2, y: -8, width: tw, height: 14, rx: 4 }, lg);
        const t = el("text", { x: 0, y: 2, "text-anchor": "middle" }, lg); t.textContent = label;
      });
    });

    // nodes
    nodes.forEach((n) => {
      const g = el("g", { class: "node" + (n.is_start ? " start" : "") + (selected && selected.kind === "node" && selected.code === n.code ? " sel" : ""), transform: `translate(${n.x},${n.y})`, "data-code": n.code }, nodesG);
      el("rect", { class: "phase", x: 0, y: 0, width: 5, height: NODE_H, rx: 2, fill: phaseColor(phaseOf(n)) }, g);
      el("rect", { class: "box", x: 0, y: 0, width: NODE_W, height: NODE_H, rx: 10 }, g);
      const title = el("text", { class: "title", x: 12, y: 22 }, g);
      title.textContent = clip(n.title, 22);
      const code = el("text", { class: "code", x: 12, y: 40 }, g); code.textContent = n.code;
      const ch = el("text", { class: "chan", x: 12, y: 56 }, g); ch.textContent = n.channel;
      if (n.is_start) { const sb = el("text", { class: "startbadge", x: NODE_W - 10, y: 15, "text-anchor": "end" }, g); sb.textContent = "▶ START"; }
      if (v.bad.has(n.code)) { const iv = el("circle", { class: "invalid", cx: NODE_W - 9, cy: NODE_H - 9, r: 4 }, g); iv.setAttribute("title", "Validation issue"); }
      // out handle for connecting
      el("circle", { class: "handle", cx: NODE_W, cy: NODE_H / 2, r: 6, "data-handle": n.code }, g);
    });
  }

  function phaseOf(n) {
    // Infer a phase from the node's act, or from its first technique's bank entry.
    if (n.act && PHASES.includes(n.act)) return n.act;
    const be = bank.find((b) => (b.techniques || []).some((t) => (n.techniques || []).includes(t)));
    return be ? be.phase : "default";
  }
  function clip(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  // ---- pointer interactions (drag nodes, connect, pan) ------------------- //
  let drag = null;   // {code, dx, dy} node drag
  let link = null;   // {from, x, y} connect drag
  let pan = null;    // {x,y}
  function toWorld(evt) {
    const s = svg(), r = s.getBoundingClientRect();
    return { x: view.x + (evt.clientX - r.left) / view.k, y: view.y + (evt.clientY - r.top) / view.k };
  }

  function onPointerDown(evt) {
    const handle = evt.target.closest("[data-handle]");
    const nodeEl = evt.target.closest(".node");
    const edgeHit = evt.target.closest("[data-edge]");
    if (handle) {
      const from = handle.getAttribute("data-handle");
      const w = toWorld(evt); link = { from, x: w.x, y: w.y };
      evt.preventDefault(); return;
    }
    if (nodeEl) {
      const code = nodeEl.getAttribute("data-code"); const n = nodeByCode(code);
      selectNode(code);
      const w = toWorld(evt); drag = { code, dx: w.x - n.x, dy: w.y - n.y, moved: false };
      pushUndo();
      evt.preventDefault(); return;
    }
    if (edgeHit) { const [code, bi] = edgeHit.getAttribute("data-edge").split("|"); selectEdge(code, Number(bi)); return; }
    // empty → pan (or deselect)
    pan = { sx: evt.clientX, sy: evt.clientY, vx: view.x, vy: view.y, moved: false };
  }
  function onPointerMove(evt) {
    if (drag) {
      const w = toWorld(evt); const n = nodeByCode(drag.code);
      n.x = w.x - drag.dx; n.y = w.y - drag.dy; drag.moved = true; render();
    } else if (link) {
      const w = toWorld(evt); link.x = w.x; link.y = w.y; drawLinkPreview();
    } else if (pan) {
      view.x = pan.vx - (evt.clientX - pan.sx) / view.k;
      view.y = pan.vy - (evt.clientY - pan.sy) / view.k;
      if (Math.abs(evt.clientX - pan.sx) + Math.abs(evt.clientY - pan.sy) > 3) pan.moved = true;
      applyViewBox();
    }
  }
  function onPointerUp(evt) {
    if (link) {
      const nodeEl = evt.target.closest(".node");
      if (nodeEl) {
        const to = nodeEl.getAttribute("data-code");
        if (to !== link.from) addBranch(link.from, to);
      }
      const p = $("linkPreview"); if (p) p.remove(); link = null; render();
    }
    if (pan && !pan.moved) { selected = null; renderProps(); render(); }
    drag = null; pan = null;
  }
  function drawLinkPreview() {
    let p = $("linkPreview");
    if (!p) { p = el("path", { id: "linkPreview", class: "link-preview" }, $("edges")); }
    const n = nodeByCode(link.from); const a = anchor(n, "out");
    p.setAttribute("d", `M${a.x},${a.y} L${link.x},${link.y}`);
  }

  function onWheel(evt) {
    evt.preventDefault();
    const w = toWorld(evt);
    const factor = evt.deltaY < 0 ? 1.1 : 1 / 1.1;
    view.k = Math.min(2.5, Math.max(0.3, view.k * factor));
    // keep the cursor point stable
    const s = svg(), r = s.getBoundingClientRect();
    view.x = w.x - (evt.clientX - r.left) / view.k;
    view.y = w.y - (evt.clientY - r.top) / view.k;
    applyViewBox();
  }

  // ---- editing ----------------------------------------------------------- //
  function selectNode(code) { selected = { kind: "node", code }; render(); renderProps(); }
  function selectEdge(code, bi) { selected = { kind: "edge", code, bi }; render(); renderProps(); }

  function addBranch(from, to) {
    pushUndo();
    const n = nodeByCode(from);
    n.branches = n.branches || [];
    if (!n.branches.some((b) => b.goto === to)) n.branches.push({ when: "proctor_choice", goto: to });
    render();
  }

  function uniqueCode(base) {
    let i = 1, code = base;
    while (nodeByCode(code)) { i += 1; code = `${base}-${i}`; }
    return code;
  }

  function addNode(entry, at) {
    pushUndo();
    const code = uniqueCode(entry ? (entry.key || "INJ").toUpperCase().replace(/[^A-Z0-9]+/g, "-").slice(0, 10) : `INJ-${nodes.length + 1}`);
    const n = {
      code, title: entry ? entry.title : "New inject", channel: entry ? entry.channel : "briefing",
      narrative: "", techniques: entry ? (entry.techniques || []) : [], target: "",
      is_start: nodes.length === 0, objective_code: "", act: entry ? entry.phase : "",
      branches: [], seq: nodes.length, meta: {},
      x: at ? at.x - NODE_W / 2 : 80, y: at ? at.y - NODE_H / 2 : 80, _placed: true,
    };
    nodes.push(n);
    selectNode(code);
  }

  function deleteNode(code) {
    pushUndo();
    nodes = nodes.filter((n) => n.code !== code);
    nodes.forEach((n) => { n.branches = (n.branches || []).filter((b) => b.goto !== code); });
    selected = null; render(); renderProps();
  }

  // ---- properties panel -------------------------------------------------- //
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

  function renderProps() {
    const empty = $("propsEmpty"), form = $("propsForm");
    if (!selected) { empty.hidden = false; form.hidden = true; return; }
    empty.hidden = true; form.hidden = false;

    if (selected.kind === "node") return renderNodeProps(nodeByCode(selected.code), form);
    return renderEdgeProps(form);
  }

  function renderNodeProps(n, form) {
    if (!n) { selected = null; return renderProps(); }
    const v = validate();
    const issues = v.issues.filter((s) => s.includes(n.code));
    form.innerHTML =
      `<p class="eyebrow">Inject</p>` +
      (issues.length ? `<div class="pf-issues">Issues<ul>${issues.map((i) => `<li>${esc(i)}</li>`).join("")}</ul></div>` : "") +
      grp("Code", `<input id="pfCode" value="${esc(n.code)}">`) +
      grp("Title", `<input id="pfTitle" value="${esc(n.title)}">`) +
      grp("Channel", chanSelect(n.channel)) +
      grp("Narrative", `<textarea id="pfNarr">${esc(n.narrative)}</textarea>`) +
      `<label class="pf-group" style="flex-direction:row;align-items:center;gap:.5rem">
         <input type="checkbox" id="pfStart" ${n.is_start ? "checked" : ""} style="width:auto"> Start inject</label>` +
      `<details class="pf-adv"><summary>Advanced</summary>` +
        grp("ATT&CK techniques (comma)", `<input id="pfTech" value="${esc((n.techniques || []).join(", "))}">`) +
        grp("Target asset", `<input id="pfTarget" value="${esc(n.target)}">`) +
        grp("Objective code", `<input id="pfObj" value="${esc(n.objective_code)}">`) +
        `<p class="lbl">Branches</p><div id="pfBranches">${(n.branches || []).map((b, i) => branchRow(b, i)).join("")}</div>` +
        `<button class="btn ghost small" id="pfAddBranch">+ Branch</button>` +
      `</details>` +
      `<button class="btn ghost small pf-danger" id="pfDelete" style="margin-top:.7rem;width:100%">Delete inject</button>`;

    const on = (id, ev, fn) => { const e = $(id); if (e) e.addEventListener(ev, fn); };
    const commit = () => { render(); };
    on("pfCode", "change", (e) => { const nc = e.target.value.trim(); if (nc && !nodeByCode(nc)) { pushUndo(); const old = n.code; nodes.forEach((m) => (m.branches || []).forEach((b) => { if (b.goto === old) b.goto = nc; })); n.code = nc; selected.code = nc; commit(); } });
    on("pfTitle", "input", (e) => { n.title = e.target.value; commit(); });
    on("pfNarr", "input", (e) => { n.narrative = e.target.value; });
    on("pfChan", "change", (e) => { n.channel = e.target.value; commit(); });
    on("pfStart", "change", (e) => { pushUndo(); if (e.target.checked) nodes.forEach((m) => (m.is_start = m.code === n.code)); else n.is_start = false; commit(); });
    on("pfTech", "change", (e) => { n.techniques = e.target.value.split(",").map((s) => s.trim()).filter(Boolean); commit(); });
    on("pfTarget", "change", (e) => { n.target = e.target.value; });
    on("pfObj", "change", (e) => { n.objective_code = e.target.value; });
    on("pfAddBranch", "click", () => { pushUndo(); n.branches = n.branches || []; n.branches.push({ when: "proctor_choice", goto: "" }); renderProps(); render(); });
    on("pfDelete", "click", () => deleteNode(n.code));
    (n.branches || []).forEach((b, i) => bindBranchRow(n, b, i));
  }

  function branchRow(b, i) {
    return `<div class="pf-branch" data-bi="${i}">
      <div class="row">
        <select class="bWhen">${["proctor_choice", "action_taken", "timeout"].map((w) => `<option ${b.when === w ? "selected" : ""}>${w}</option>`).join("")}</select>
        <select class="bGoto">${nodes.map((m) => `<option value="${esc(m.code)}" ${b.goto === m.code ? "selected" : ""}>${esc(m.code)}</option>`).join("")}<option value="" ${!b.goto ? "selected" : ""}>—</option></select>
      </div>
      <input class="bTrigger" placeholder="trigger (optional)" value="${esc(b.trigger || "")}" style="margin-top:.35rem">
      <input class="bCond" placeholder="condition e.g. state.contained == false" value="${esc(b.condition || "")}" style="margin-top:.35rem">
      <button class="btn ghost small bDel" style="margin-top:.35rem">Remove branch</button>
    </div>`;
  }
  function bindBranchRow(n, b, i) {
    const root = document.querySelector(`#pfBranches .pf-branch[data-bi="${i}"]`);
    if (!root) return;
    root.querySelector(".bWhen").addEventListener("change", (e) => { b.when = e.target.value; render(); });
    root.querySelector(".bGoto").addEventListener("change", (e) => { b.goto = e.target.value; render(); });
    root.querySelector(".bTrigger").addEventListener("change", (e) => { b.trigger = e.target.value; render(); });
    root.querySelector(".bCond").addEventListener("change", (e) => { b.condition = e.target.value; });
    root.querySelector(".bDel").addEventListener("click", () => { pushUndo(); n.branches.splice(i, 1); renderProps(); render(); });
  }

  function renderEdgeProps(form) {
    const n = nodeByCode(selected.code); const b = n && n.branches[selected.bi];
    if (!b) { selected = null; return renderProps(); }
    form.innerHTML = `<p class="eyebrow">Branch</p><p class="hint">${esc(n.code)} → ${esc(b.goto || "?")}</p>` +
      `<div class="pf-branch">${branchRow(b, selected.bi)}</div>`;
    bindBranchRow(n, b, selected.bi);
    const del = form.querySelector(".bDel");
    if (del) del.onclick = () => { pushUndo(); n.branches.splice(selected.bi, 1); selected = null; renderProps(); render(); };
  }

  function grp(label, inner) { return `<label class="pf-group">${esc(label)}${inner}</label>`; }
  function chanSelect(cur) {
    const chans = ["briefing", "email", "edr_alert", "siem_alert", "phone", "chat", "news", "intel"];
    return `<select id="pfChan">${chans.map((c) => `<option ${c === cur ? "selected" : ""}>${c}</option>`).join("")}</select>`;
  }

  // ---- palette ----------------------------------------------------------- //
  function renderPalette() {
    const wrap = $("paletteList");
    wrap.innerHTML = bank.map((b) => `
      <div class="pal-item" draggable="true" data-key="${esc(b.key)}" style="--phase:${phaseColor(b.phase)}">
        <div><div class="pal-ch">${esc(b.channel || "")}</div><div class="pal-t">${esc(b.title || b.key)}</div></div>
      </div>`).join("") || '<p class="hint">No bank entries.</p>';
    wrap.querySelectorAll(".pal-item").forEach((it) => {
      it.addEventListener("dragstart", (e) => e.dataTransfer.setData("text/key", it.getAttribute("data-key")));
      it.addEventListener("click", () => addNode(bank.find((b) => b.key === it.getAttribute("data-key"))));
    });
  }
  function renderLegend() {
    $("legend").innerHTML = PHASES.map((p) => `<li><span class="sw" style="background:${phaseColor(p)}"></span>${p}</li>`).join("");
  }

  // ---- YAML view --------------------------------------------------------- //
  async function showYaml() {
    try {
      const yaml = await api(`/api/scenarios/${scenarioId}/export`);
      $("yamlText").value = typeof yaml === "string" ? yaml : JSON.stringify(yaml, null, 2);
    } catch (e) { $("yamlText").value = "# Save the scenario first to export YAML.\n# " + e.message; }
  }
  async function validateYaml() {
    try {
      const out = await api("/api/scenarios/validate", "POST", { yaml: $("yamlText").value });
      const errs = out.errors || [], warns = out.warnings || [];
      $("yamlMsg").textContent = errs.length ? `${errs.length} error(s): ${errs[0]}` : (warns.length ? `Valid · ${warns.length} warning(s)` : "Valid ✓");
    } catch (e) { $("yamlMsg").textContent = e.message; }
  }

  // ---- save / load ------------------------------------------------------- //
  async function loadScenarios() {
    const list = await api("/api/scenarios");
    $("scenarioSel").innerHTML = list.length
      ? list.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("")
      : '<option value="">No scenarios — create one in the console</option>';
    if (list.length) { scenarioId = list[0].id; await openScenario(scenarioId); }
  }
  async function openScenario(id) {
    scenarioId = Number(id);
    const scn = await api(`/api/scenarios/${scenarioId}`);
    fromScenario(scn);
    undoStack.length = 0; redoStack.length = 0; selected = null;
    view = { x: 0, y: 0, k: 1 };
    render(); renderProps();
  }
  async function save() {
    const v = validate();
    if (!v.ok) { toast("Fix validation issues before saving: " + v.issues[0]); return; }
    try {
      await api(`/api/scenarios/${scenarioId}/graph`, "PUT", { injects: toInjects() });
      toast("Saved ✓");
    } catch (e) { toast("Save failed: " + e.message); }
  }

  // ---- tabs / theme ------------------------------------------------------ //
  function showTab(which) {
    const yaml = which === "yaml";
    $("yamlView").hidden = !yaml;
    ["palette", "canvasWrap", "props"].forEach((id) => ($(id).style.display = yaml ? "none" : ""));
    $("tabDesign").setAttribute("aria-pressed", String(!yaml));
    $("tabYaml").setAttribute("aria-pressed", String(yaml));
    if (yaml) showYaml();
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

  // ---- init -------------------------------------------------------------- //
  async function init() {
    initTheme(); renderLegend();
    if (!token()) { location.href = "/index.html"; return; }
    try { bank = await api("/api/catalog/injects"); } catch (e) { bank = []; }
    renderPalette();

    const s = svg();
    s.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    s.addEventListener("wheel", onWheel, { passive: false });
    // drop from palette
    s.addEventListener("dragover", (e) => e.preventDefault());
    s.addEventListener("drop", (e) => {
      e.preventDefault();
      const key = e.dataTransfer.getData("text/key");
      addNode(bank.find((b) => b.key === key), toWorld(e));
    });

    $("scenarioSel").addEventListener("change", (e) => openScenario(e.target.value));
    $("btnSave").addEventListener("click", save);
    $("btnBlank").addEventListener("click", () => addNode(null));
    $("btnTidy").addEventListener("click", () => { pushUndo(); autoLayout(); render(); });
    $("btnUndo").addEventListener("click", undo);
    $("btnRedo").addEventListener("click", redo);
    $("tabDesign").addEventListener("click", () => showTab("design"));
    $("tabYaml").addEventListener("click", () => showTab("yaml"));
    $("btnYamlValidate").addEventListener("click", validateYaml);
    $("btnYamlCopy").addEventListener("click", () => { navigator.clipboard && navigator.clipboard.writeText($("yamlText").value); toast("Copied"); });
    window.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "z") { e.preventDefault(); undo(); }
      else if ((e.ctrlKey || e.metaKey) && (e.key === "y" || (e.shiftKey && e.key === "Z"))) { e.preventDefault(); redo(); }
      else if ((e.key === "Delete" || e.key === "Backspace") && selected && selected.kind === "node" && document.activeElement === svg()) { deleteNode(selected.code); }
    });
    window.addEventListener("resize", applyViewBox);

    await loadScenarios();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
