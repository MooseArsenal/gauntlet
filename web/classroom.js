/* Education edition (L4): cohorts, enrolment, seating, gradebook. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const STAFF = ["admin", "facilitator"];
  let me = null, cohorts = [], current = null, sessions = [];
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
  function gate(e) { $("gatePanel").hidden = false; $("gateMsg").textContent = e.message; $("lead").textContent = "Education edition"; }
  function fmtScore(v) { return v == null ? "—" : Math.round(v * 100); }
  function gradeCell(v) { if (v == null) return '<span class="g">—</span>'; const g = Math.round(v * 100); return `<span class="g ${g >= 80 ? "hi" : g < 50 ? "lo" : ""}">${g}</span>`; }

  // ---- signed out: enrol ----
  async function enrol() {
    const code = $("enCode").value.trim().toUpperCase();
    if (!code) return toast("Enter your class code.");
    try {
      const out = await api("/api/cohorts/enrol", "POST", { code, email: $("enEmail").value.trim(), password: $("enPass").value, name: $("enName").value.trim() });
      try { localStorage.setItem("gauntlet-token", out.access_token); if (out.refresh_token) localStorage.setItem("gauntlet-refresh", out.refresh_token); } catch (e) { /* noop */ }
      toast("Welcome. Taking you to your class…");
      setTimeout(() => { location.href = "/classroom.html"; }, 600);
    } catch (e) { toast(e.message); }
  }

  // ---- student ----
  async function loadMine() {
    try {
      const rows = await api("/api/cohorts/mine");
      $("lead").textContent = rows.length ? `You are in ${rows.length} class${rows.length === 1 ? "" : "es"}.` : "Join a class with the code your instructor gave you.";
      $("mine").innerHTML = rows.length ? rows.map((r) => {
        const m = r.me || {};
        return `<div class="panel scene" style="margin:.5rem 0"><p class="eyebrow">${esc(r.cohort.name)} <span class="hint">— you are ${esc(r.alias)}${r.cohort.anonymous ? " (graded anonymously)" : ""}</span></p>` +
          `<div class="stats"><div class="stat"><div class="stat-v">${m.grade == null ? "—" : m.grade}</div><div class="stat-l">Your grade</div></div>` +
          `<div class="stat"><div class="stat-v">${m.answered || 0}/${m.possible || 0}</div><div class="stat-l">Decisions answered</div></div>` +
          `<div class="stat"><div class="stat-v">${m.median_latency_sec == null ? "—" : m.median_latency_sec + "s"}</div><div class="stat-l">Median time to decide</div></div>` +
          `<div class="stat"><div class="stat-v">${fmtScore(r.class_mean_score)}</div><div class="stat-l">Class mean</div></div></div>` +
          (r.sessions.length ? `<table class="grade" style="margin-top:.6rem"><thead><tr><th>Run</th><th>Status</th><th class="n">Your score</th><th class="n">Answered</th></tr></thead><tbody>` +
            r.sessions.map((s) => { const c = (m.sessions || []).find((x) => x.session_id === s.id) || {}; return `<tr><td>${esc(s.name)}</td><td><span class="pill ${esc(s.status)}">${esc(s.status)}</span></td><td class="n">${gradeCell(c.mean_score)}</td><td class="n">${c.answered || 0}/${c.possible || 0}</td></tr>`; }).join("") + `</tbody></table>` : '<p class="hint">No runs yet.</p>') + `</div>`;
      }).join("") : '<p class="muted">Not in a class yet.</p>';
    } catch (e) { if (e.status === 402) gate(e); else toast(e.message); }
  }
  async function join() {
    const code = $("joinCode").value.trim().toUpperCase(); if (!code) return;
    try { const out = await api("/api/cohorts/join", "POST", { code }); toast(`Joined ${out.cohort.name} as ${out.alias}.`); $("joinCode").value = ""; loadMine(); } catch (e) { toast(e.message); }
  }

  // ---- instructor ----
  async function loadCohorts() {
    try {
      cohorts = await api("/api/cohorts");
      $("lead").textContent = `${cohorts.length} cohort${cohorts.length === 1 ? "" : "s"}. Students enrol themselves with a class code; you seat them into runs and grade from the decisions they make.`;
      $("count").textContent = `— ${cohorts.length}`;
      $("cohorts").innerHTML = cohorts.length ? `<table class="dfields"><thead><tr><th>Class</th><th>Code</th><th>Students</th><th>Runs</th><th></th></tr></thead><tbody>` +
        cohorts.map((c) => `<tr><td><b>${esc(c.name)}</b>${c.anonymous ? ' <span class="pill">anon</span>' : ""}${c.open ? "" : ' <span class="pill">closed</span>'}</td><td class="mono">${esc(c.code)}</td><td>${c.students}</td><td>${c.sessions.length}</td><td><button class="btn small" data-open="${c.id}">Open</button></td></tr>`).join("") + `</tbody></table>` : '<p class="muted">No cohorts yet.</p>';
      $("cohorts").querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => openCohort(Number(b.dataset.open))));
      if (current) { const still = cohorts.find((c) => c.id === current.id); if (still) openCohort(current.id); else { current = null; $("detail").hidden = true; } }
    } catch (e) { if (e.status === 402) gate(e); else toast(e.message); }
  }
  async function openCohort(id) {
    try {
      current = await api(`/api/cohorts/${id}`);
      $("detail").hidden = false;
      $("dCode").textContent = current.code;
      $("dEnrolUrl").textContent = `${location.origin}/classroom.html?code=${current.code}`;
      $("btnOpen").textContent = current.open ? "Close enrolment" : "Reopen enrolment";
      $("btnAnon").textContent = current.anonymous ? "Anonymous grading: on" : "Anonymous grading: off";
      $("dCount").textContent = `— ${current.members.length}`;
      $("members").innerHTML = current.members.length ? `<table class="dfields"><thead><tr><th>Alias</th><th>Name</th><th>Email</th><th>Joined</th><th></th></tr></thead><tbody>` +
        current.members.map((m) => `<tr><td class="mono">${esc(m.alias)}</td><td>${esc(m.name)}</td><td>${esc(m.email)}</td><td>${esc(new Date(m.joined_at).toLocaleDateString())}</td><td><button class="btn ghost small" data-rm="${m.user_id}">Remove</button></td></tr>`).join("") + `</tbody></table>` : '<p class="muted">No students yet — share the code.</p>';
      $("members").querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", async () => {
        if (!confirm("Remove this student from the cohort? Their answers stay on the record.")) return;
        try { await api(`/api/cohorts/${current.id}/members/${b.dataset.rm}`, "DELETE"); openCohort(current.id); } catch (e) { toast(e.message); }
      }));
      sessions = await api("/api/sessions?limit=200");
      const attached = new Set(current.sessions.map((s) => s.id));
      $("attachSel").innerHTML = sessions.filter((s) => !attached.has(s.id) && s.status !== "complete").map((s) => `<option value="${s.id}">#${s.id} ${esc(s.name)} (${esc(s.status)})</option>`).join("") || '<option value="">No unattached exercises — create one in the console</option>';
      $("runs").innerHTML = current.sessions.length ? `<table class="dfields"><thead><tr><th>Run</th><th>Status</th><th>Seat the class</th></tr></thead><tbody>` +
        current.sessions.map((s) => `<tr><td><b>#${s.id} ${esc(s.name)}</b></td><td><span class="pill ${esc(s.status)}">${esc(s.status)}</span></td><td>` +
          (s.status === "complete" ? '<span class="hint">finished</span>' : `<select data-cell="${s.id}"><option value="auto">auto (round-robin)</option></select> <button class="btn small" data-seat="${s.id}">Seat</button>`) +
          ` <a class="btn ghost small" href="/replay.html?session=${s.id}" target="_blank" rel="noopener">Replay</a></td></tr>`).join("") + `</tbody></table>` : '<p class="muted">No runs attached.</p>';
      for (const s of current.sessions) {
        const sel = $("runs").querySelector(`[data-cell="${s.id}"]`); if (!sel) continue;
        try { const scn = await api(`/api/scenarios/${s.scenario_id}`); (scn.cells || []).filter((c) => c.kind !== "control").forEach((c) => { const o = document.createElement("option"); o.value = c.key; o.textContent = c.name || c.key; sel.appendChild(o); }); } catch (e) { /* noop */ }
      }
      $("runs").querySelectorAll("[data-seat]").forEach((b) => b.addEventListener("click", async () => {
        const cell = $("runs").querySelector(`[data-cell="${b.dataset.seat}"]`).value;
        try { const out = await api(`/api/cohorts/${current.id}/sessions/${b.dataset.seat}/seat`, "POST", { cell }); toast(`Seated ${out.seated} student${out.seated === 1 ? "" : "s"}: ${Object.entries(out.cells).map(([k, v]) => `${k} ${v}`).join(", ")}.`); } catch (e) { toast(e.message); }
      }));
      loadGradebook();
    } catch (e) { toast(e.message); }
  }
  async function loadGradebook() {
    if (!current) return;
    try {
      const book = await api(`/api/cohorts/${current.id}/gradebook?reveal=${$("gbReveal").checked}`);
      $("gbNote").textContent = book.cohort.anonymous && !book.cohort.revealed ? "— aliases only (anonymous grading)" : "";
      if (!book.students.length) { $("gradebook").innerHTML = '<p class="muted">No students yet.</p>'; return; }
      $("gradebook").innerHTML = `<table class="grade"><thead><tr><th>Student</th><th class="n">Grade</th><th class="n">Answered</th><th class="n">Median time</th>` +
        book.sessions.map((s) => `<th class="n" title="${esc(s.name)}">#${s.id}</th>`).join("") + `</tr></thead><tbody>` +
        book.students.map((r) => `<tr><td><span class="mono">${esc(r.alias)}</span>${r.name !== r.alias ? ` ${esc(r.name)}` : ""}${r.email ? ` <span class="hint">${esc(r.email)}</span>` : ""}</td><td class="n">${gradeCell(r.mean_score)}</td><td class="n">${r.answered}/${r.possible}</td><td class="n">${r.median_latency_sec == null ? "—" : r.median_latency_sec + "s"}</td>` +
          r.sessions.map((c) => `<td class="n">${gradeCell(c.mean_score)} <span class="hint">${c.answered}/${c.possible}</span></td>`).join("") + `</tr>`).join("") +
        `</tbody><tfoot><tr><th>Class mean</th><th class="n">${fmtScore(book.class_mean_score)}</th><th></th><th></th>${book.sessions.map((s) => `<th class="n">${fmtScore(s.mean_score)}</th>`).join("")}</tr></tfoot></table>`;
    } catch (e) { toast(e.message); }
  }
  async function csv() {
    if (!current) return;
    try {
      const res = await api(`/api/cohorts/${current.id}/gradebook.csv?reveal=${$("gbReveal").checked}`, "GET", undefined, true);
      const blob = await res.blob(); const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `gradebook-${current.id}.csv`; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) { toast(e.message); }
  }

  async function init() {
    initTheme();
    const q = new URLSearchParams(location.search);
    if (!token()) {
      $("enrolPanel").hidden = false; $("lead").textContent = "Create your account with the class code your instructor gave you.";
      $("enCode").value = (q.get("code") || "").toUpperCase();
      $("btnEnrol").addEventListener("click", enrol);
      return;
    }
    try { me = await api("/api/auth/me"); } catch (e) { location.href = "/"; return; }
    if (STAFF.includes(me.role)) {
      $("instructorView").hidden = false;
      $("btnCreate").addEventListener("click", async () => {
        const name = $("newName").value.trim(); if (!name) return;
        try { const c = await api("/api/cohorts", "POST", { name, anonymous: $("newAnon").checked }); $("newName").value = ""; toast(`Created — class code ${c.code}.`); current = c; loadCohorts(); } catch (e) { if (e.status === 402) gate(e); else toast(e.message); }
      });
      $("btnRotate").addEventListener("click", async () => { try { await api(`/api/cohorts/${current.id}/rotate-code`, "POST"); loadCohorts(); } catch (e) { toast(e.message); } });
      $("btnOpen").addEventListener("click", async () => { try { await api(`/api/cohorts/${current.id}`, "PATCH", { open: !current.open }); loadCohorts(); } catch (e) { toast(e.message); } });
      $("btnAnon").addEventListener("click", async () => { try { await api(`/api/cohorts/${current.id}`, "PATCH", { anonymous: !current.anonymous }); loadCohorts(); } catch (e) { toast(e.message); } });
      $("btnArchive").addEventListener("click", async () => {
        if (!confirm("Archive this cohort? Students keep their accounts and the runs keep their records.")) return;
        try { await api(`/api/cohorts/${current.id}`, "DELETE"); current = null; $("detail").hidden = true; loadCohorts(); } catch (e) { toast(e.message); }
      });
      $("btnAttach").addEventListener("click", async () => {
        const sid = $("attachSel").value; if (!sid) return;
        try { await api(`/api/cohorts/${current.id}/sessions/${sid}`, "PUT"); toast("Attached."); loadCohorts(); } catch (e) { toast(e.message); }
      });
      $("gbReveal").addEventListener("change", loadGradebook);
      $("btnCsv").addEventListener("click", csv);
      loadCohorts();
    } else {
      $("studentView").hidden = false; $("lnkPlay").hidden = false; $("lnkConsole").hidden = true;
      $("joinCode").value = (q.get("code") || "").toUpperCase();
      $("btnJoin").addEventListener("click", join);
      loadMine();
    }
  }
  document.addEventListener("DOMContentLoaded", init);
})();
