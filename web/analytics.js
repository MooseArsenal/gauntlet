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
  function toast(m) { const el = $("toast"); if (!el) return; el.textContent = m; el.hidden = false; clearTimeout(el._t); el._t = setTimeout(() => (el.hidden = true), 2600); }
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

  // M7: the org's figures against the library's modelled expectation and, when
  // opted in, the k-anonymous cohort of other organisations on this instance.
  function fmtDelta(v, unit, goodWhen) {
    if (v == null) return "";
    const good = goodWhen === "up" ? v >= 0 : v <= 0;
    const sign = v > 0 ? "+" : "";
    return ` <span class="mat-delta ${v === 0 ? "muted" : good ? "d-good" : "d-bad"}">${sign}${unit === "%" ? Math.round(v * 100) + "%" : v + " min"}</span>`;
  }
  async function loadBenchmark(me) {
    let b;
    try { b = await api("/api/analytics/benchmark"); } catch (e) { return; }
    const rows = b.sectors.filter((r) => r.own || r.cohort);
    $("benchPanel").hidden = false;
    $("benchNote").textContent = b.note;
    const cell = (x, key, unit) => {
      if (!x) return "—";
      if (x.suppressed) return `<span class="muted">${x.organisations}/${x.needed} orgs</span>`;
      const v = x[key]; if (v == null) return "—";
      return unit === "%" ? pct(v) : mins(v);
    };
    $("benchTable").innerHTML = rows.length
      ? `<table class="dfields"><thead><tr><th>Sector</th><th>You</th><th>Modelled expectation</th><th>Instance cohort</th></tr></thead><tbody>` +
        rows.map((r) => `<tr><td>${esc(r.sector)}</td>` +
          `<td>${cell(r.own, "detection_rate", "%")} · ${cell(r.own, "mean_time_to_detect_min", "min")}</td>` +
          `<td>${cell(r.reference, "detection_rate", "%")}${r.vs_reference ? fmtDelta(r.vs_reference.detection_rate, "%", "up") : ""} · ${cell(r.reference, "mean_time_to_detect_min", "min")}${r.vs_reference ? fmtDelta(r.vs_reference.mean_time_to_detect_min, "min", "down") : ""}</td>` +
          `<td>${b.opt_in ? cell(r.cohort, "detection_rate", "%") + (r.vs_cohort ? fmtDelta(r.vs_cohort.detection_rate, "%", "up") : "") + " · " + cell(r.cohort, "mean_time_to_detect_min", "min") : '<span class="muted">opt in to see</span>'}</td></tr>`).join("") +
        `</tbody></table><p class="hint">Detection rate · mean time-to-detect. Deltas are yours minus the comparison.</p>`
      : '<p class="muted">Complete an exercise with adjudicated moves to see how it compares.</p>';
    if (me && me.role === "admin") {
      $("benchOpt").hidden = false; $("benchOptIn").checked = !!b.opt_in;
      $("benchOptIn").onchange = async () => {
        try {
          const t = token();
          const res = await fetch("/api/analytics/benchmark/opt-in", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${t}` }, body: JSON.stringify({ opt_in: $("benchOptIn").checked }) });
          if (!res.ok) throw new Error("could not update");
          toast($("benchOptIn").checked ? "Opted in — cohort figures appear once enough organisations contribute." : "Opted out.");
          loadBenchmark(me);
        } catch (e) { toast(e.message); }
      };
    }
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
      let me = null; try { me = await api("/api/auth/me"); } catch (e) { /* noop */ }
      loadBenchmark(me);
    } catch (e) { $("matLead").textContent = e.message; }
  }

  function init() {
    initTheme();
    if (!token()) { location.href = "/"; return; }
    load();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
