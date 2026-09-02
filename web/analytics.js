/* Gauntlet maturity dashboard (D3) — trends readiness across exercises.
 * Inline-SVG charts, no library (keeps the offline/air-gapped promise). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
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
  async function api(path) {
    const t = token();
    const res = await fetch(path, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    if (res.status === 401) { location.href = "/"; throw new Error("Sign in via the console."); }
    if (res.status === 403) throw new Error("Maturity analytics need an evaluator+ account.");
    if (!res.ok) throw new Error(res.statusText);
    return res.json();
  }

  const pct = (v) => (v == null ? "—" : Math.round(v * 100) + "%");
  const mins = (v) => (v == null ? "—" : v + "′");
  // A trend arrow — direction is "good" per metric (up good, or down good for MTTD).
  function delta(v, goodWhen) {
    if (v == null) return "";
    const up = v > 0, flat = v === 0;
    const good = flat ? true : (goodWhen === "up" ? up : !up);
    const arrow = flat ? "→" : up ? "▲" : "▼";
    const cls = flat ? "muted" : good ? "d-good" : "d-bad";
    return ` <span class="mat-delta ${cls}">${arrow}</span>`;
  }

  function renderTiles(m) {
    const s = m.summary, t = m.trend;
    const tiles = [
      { k: "Exercises run", v: m.exercises, tone: "info" },
      { k: "Detection rate", v: pct(s.detection_rate) + delta(t.detection_rate, "up"), tone: "good" },
      { k: "Mean TTD", v: mins(s.mean_time_to_detect_min) + delta(t.mean_time_to_detect_min, "down"), tone: "info" },
      { k: "Objectives met", v: pct(s.objectives_met_rate) + delta(t.objectives_met_rate, "up"), tone: "good" },
      { k: "ATT&CK techniques", v: s.unique_techniques, tone: "warn" },
    ];
    $("matTiles").innerHTML = tiles.map((x) =>
      `<div class="stile ${x.tone}"><span class="v">${x.v}</span><span class="k">${esc(x.k)}</span></div>`).join("");
  }

  // A minimal inline-SVG line chart of detection rate across exercises.
  function renderChart(active) {
    if (active.length < 2) { $("chartPanel").hidden = true; return; }
    $("chartPanel").hidden = false;
    const W = 640, H = 180, P = 24;
    const xs = (i) => P + (W - 2 * P) * (i / (active.length - 1));
    const ys = (v) => H - P - (H - 2 * P) * v;
    const pts = active.map((m, i) => `${xs(i).toFixed(1)},${ys(m.detection_rate || 0).toFixed(1)}`).join(" ");
    const dots = active.map((m, i) =>
      `<circle cx="${xs(i).toFixed(1)}" cy="${ys(m.detection_rate || 0).toFixed(1)}" r="3.5" fill="var(--accent)"><title>${esc(m.name)}: ${pct(m.detection_rate)}</title></circle>`).join("");
    $("chart").innerHTML =
      `<svg viewBox="0 0 ${W} ${H}" class="mat-svg" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Detection rate over exercises">
        <line x1="${P}" y1="${ys(0.5)}" x2="${W - P}" y2="${ys(0.5)}" class="mat-grid"/>
        <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2"/>
        ${dots}
      </svg>
      <div class="mat-axis"><span>oldest</span><span>50%</span><span>latest</span></div>`;
  }

  function renderTable(series) {
    if (!series.length) { $("tablePanel").hidden = true; return; }
    $("tablePanel").hidden = false;
    $("matTable").innerHTML =
      `<div class="mat-row mat-head"><span>Exercise</span><span>Detect</span><span>MTTD</span><span>Obj met</span><span>Moves</span></div>` +
      series.slice().reverse().map((m) =>
        `<div class="mat-row"><span class="mat-name">${esc(m.name)}</span>` +
        `<span>${pct(m.detection_rate)}</span><span>${mins(m.mean_time_to_detect_min)}</span>` +
        `<span>${pct(m.objectives_met_rate)}</span><span>${m.red_actions}</span></div>`).join("");
  }

  async function load() {
    try {
      const m = await api("/api/analytics/maturity");
      if (!m.exercises) { $("matLead").textContent = "No exercises yet — run a session to start trending your readiness."; return; }
      const active = m.series.filter((s) => s.red_actions);
      $("matLead").textContent = `${m.exercises} exercise${m.exercises === 1 ? "" : "s"}, ${m.exercises_with_activity} with adjudicated activity.`;
      renderTiles(m);
      renderChart(active);
      renderTable(m.series);
    } catch (e) { $("matLead").textContent = e.message; }
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    load();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
