/* Gauntlet kill-chain progress map (Q2b) — a shared, dependency-free component.
 *
 * A branching MSEL has no single linear length, so "how far along" is expressed
 * as a journey along the cyber kill chain: the ordered phases the scenario
 * touches light up as the exercise advances. Professional (real security
 * vocabulary), a little fun, never dungeon-crawly.
 *
 * Two modes:
 *   live     — a running exercise: done / current / upcoming phases + a % .
 *   coverage — design time: which phases the scenario spans (all "planned").
 *
 * Global: window.KillChain = { phaseOfInject, build, render }.
 */
(() => {
  "use strict";
  const PHASES = ["initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "command-and-control", "collection", "exfiltration", "impact", "recovery"];
  const LABEL = {
    "initial-access": "Initial access", "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Priv-esc", "defense-evasion": "Evasion",
    "credential-access": "Cred access", "discovery": "Discovery",
    "lateral-movement": "Lateral move", "command-and-control": "C2",
    "collection": "Collection", "exfiltration": "Exfiltration", "impact": "Impact",
    "recovery": "Recovery", "other": "Other",
  };
  const order = (p) => { const i = PHASES.indexOf(p); return i === -1 ? PHASES.length : i; };
  const color = (p) => `var(--ph-${(p || "default").replace(/[^a-z-]/g, "") || "default"}, var(--muted))`;

  // Build a technique → phase lookup from the inject bank (authoritative), so we
  // never hard-code an ATT&CK table.
  function techniqueIndex(bank) {
    const idx = {};
    (bank || []).forEach((b) => (b.techniques || []).forEach((t) => { if (!idx[t]) idx[t] = b.phase; }));
    return idx;
  }

  function phaseOfInject(inj, techIdx) {
    if (inj.act && PHASES.includes(inj.act)) return inj.act;
    for (const t of (inj.attack_techniques || inj.techniques || [])) {
      if (techIdx[t]) return techIdx[t];
    }
    return inj.act && inj.act !== "" ? inj.act : "other";
  }

  // Reduce injects to the ordered set of phases they span, with per-phase counts.
  function build(injects, bank) {
    const techIdx = techniqueIndex(bank);
    const byPhase = {};
    (injects || []).forEach((inj) => {
      const p = phaseOfInject(inj, techIdx);
      (byPhase[p] = byPhase[p] || { phase: p, codes: [] }).codes.push(inj.code);
    });
    const stages = Object.values(byPhase).sort((a, b) => order(a.phase) - order(b.phase));
    return { stages, techIdx, phaseOf: (inj) => phaseOfInject(inj, techIdx) };
  }

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

  /* opts: { injects, bank, mode: 'live'|'coverage', currentCode, firedCodes:Set } */
  function render(container, opts) {
    if (!container) return;
    const { stages, phaseOf } = build(opts.injects || [], opts.bank || []);
    if (!stages.length) { container.hidden = true; container.innerHTML = ""; return; }
    container.hidden = false;

    const mode = opts.mode || "coverage";
    const fired = opts.firedCodes || new Set();
    const injByCode = {};
    (opts.injects || []).forEach((i) => (injByCode[i.code] = i));
    const currentPhase = opts.currentCode && injByCode[opts.currentCode]
      ? phaseOf(injByCode[opts.currentCode]) : null;
    const curIdx = stages.findIndex((s) => s.phase === currentPhase);

    // A phase lights up once any of its injects has fired; the current inject's
    // phase is the "current" stop. Progression % is measured by scenes actually
    // played (fired / total), not phase order — phases aren't monotonic with the
    // story (containment/recovery scenes map to late attack phases).
    const total = (opts.injects || []).length;
    const firedCount = (opts.injects || []).filter((i) => fired.has(i.code)).length;
    stages.forEach((s, i) => {
      if (mode === "coverage") { s.state = "plan"; return; }
      const anyFired = s.codes.some((c) => fired.has(c));
      if (i === curIdx) s.state = "current";
      else if (anyFired) s.state = "done";
      else s.state = "upcoming";
    });

    const pct = mode === "coverage" ? 100 : Math.round(firedCount / Math.max(1, total) * 100);
    const right = mode === "coverage"
      ? `${stages.length} phase${stages.length === 1 ? "" : "s"} covered`
      : `${firedCount} / ${total} scenes · ${pct}%`;

    const nodes = stages.map((s) => {
      const c = color(s.phase);
      return `<li class="kc-stop kc-${s.state}" style="--ph:${c}" title="${esc(LABEL[s.phase] || s.phase)} · ${s.codes.length} inject(s)">
        <span class="kc-dot">${s.state === "done" ? "✓" : ""}</span>
        <span class="kc-lbl">${esc(LABEL[s.phase] || s.phase)}</span>
        <span class="kc-ct">${s.codes.length}</span>
      </li>`;
    }).join("");

    // Track fill follows real progression (scenes played), not stage index.
    const fillPct = mode === "coverage" ? 100 : pct;

    container.innerHTML =
      `<div class="kc-head"><span class="kc-title">Kill chain</span><span class="kc-meta">${esc(right)}</span></div>
       <div class="kc-rail" role="list">
         <div class="kc-track"></div>
         <div class="kc-fill" style="width:${mode === "coverage" ? 100 : fillPct}%"></div>
         <ul class="kc-stops">${nodes}</ul>
       </div>`;
    container.classList.toggle("kc-coverage", mode === "coverage");
  }

  window.KillChain = { PHASES, phaseOfInject, build, render };
})();
