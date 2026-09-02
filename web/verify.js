/* Gauntlet certificate verification — public, no account. Recomputes the
 * signature server-side and shows the signed record; never the session. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function initTheme() {
    let t = "light"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }
  const pct = (v) => (v == null ? "n/a" : Math.round(v * 100) + "%");
  const date = (iso) => (iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "n/a");

  async function check() {
    const serial = $("serial").value.trim().toUpperCase();
    $("err").hidden = true; $("result").hidden = true;
    if (!serial) { $("err").textContent = "Enter a serial."; $("err").hidden = false; return; }
    let v;
    try {
      const res = await fetch(`/api/certificates/${encodeURIComponent(serial)}/verify`);
      if (!res.ok) throw new Error(res.status === 429 ? "Too many checks — try again in a minute." : "Verification service unavailable.");
      v = await res.json();
    } catch (e) { $("err").textContent = e.message; $("err").hidden = false; return; }
    const r = v.record || {};
    const obj = r.objectives || {};
    if (!v.valid) {
      $("result").innerHTML =
        `<div class="cert-verdict bad"><span class="rc-vtag">NOT VERIFIED</span><span>${esc(v.reason)}</span></div>` +
        `<p class="hint">Serial <code>${esc(v.serial)}</code>. A certificate that was revoked, edited, or issued by another instance does not verify here.</p>`;
      $("result").hidden = false; return;
    }
    const tiles = [
      ["Detection rate", pct(r.detection_rate)],
      ["Mean time to detect", r.mean_time_to_detect_min == null ? "n/a" : r.mean_time_to_detect_min + " min"],
      ["Objectives met", pct(obj.met_rate)],
      ["Techniques exercised", String((r.techniques_exercised || []).length)],
    ].map(([k, x]) => `<div class="stile info"><span class="v">${esc(x)}</span><span class="k">${esc(k)}</span></div>`).join("");
    $("result").innerHTML =
      `<div class="cert-verdict good"><span class="rc-vtag">VERIFIED</span><span>signature recomputed · issued ${esc(date(v.issued_at))}</span></div>` +
      `<h2 class="cert-org">${esc(r.organization)}</h2>` +
      `<p class="sub">completed <b>${esc(r.exercise)}</b> (${esc(r.scenario)}) against ${esc(r.environment)}${r.sector ? " · " + esc(r.sector) : ""} on ${esc(date(r.completed_at))}.</p>` +
      `<div class="score cert-tiles">${tiles}</div>` +
      `<table class="dfields"><tbody>` +
      `<tr><td>Cells</td><td>${esc((r.cells || []).join(", ") || "n/a")} · ${r.participants || 0} joined by code</td></tr>` +
      `<tr><td>Adversary actions</td><td>${r.adversary_actions} adjudicated · ${r.detected} detected · ${r.missed} missed</td></tr>` +
      `<tr><td>Objectives</td><td>${obj.met || 0} met · ${obj.partial || 0} partial · ${obj.missed || 0} not met · of ${obj.total || 0}</td></tr>` +
      `<tr><td>Techniques</td><td>${esc((r.techniques_exercised || []).join(", ") || "none")}</td></tr>` +
      `<tr><td>Timeline</td><td>${r.timeline_events} signed events · head #${(r.timeline_head || {}).seq || "—"} · chain ${r.chain_verified ? "verified intact at issue" : "not verified"}</td></tr>` +
      `</tbody></table>` +
      `<blockquote>These figures describe one facilitated exercise against a modelled environment. They are an exercise record, not a compliance attestation and not a measure of production security.</blockquote>`;
    $("result").hidden = false;
  }

  function init() {
    initTheme();
    const want = new URLSearchParams(location.search).get("serial");
    if (want) { $("serial").value = want.toUpperCase(); check(); }
    $("btnCheck").addEventListener("click", check);
    $("serial").addEventListener("keydown", (e) => { if (e.key === "Enter") check(); });
  }
  document.addEventListener("DOMContentLoaded", init);
})();
