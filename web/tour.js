/* Gauntlet guided tour (M6): eight stops through the console for a first-time
 * facilitator. Pure DOM, no library; each stop names an element id, a title
 * and a line of copy. Stops whose element is not on screen are skipped, so
 * the same tour works on the home screen and inside an exercise. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const KEY = "gauntlet-tour-done";
  const STOPS = [
    { id: "scenarioSel", title: "Run an exercise", text: "Pick a scenario and start. Three ship with the demo: a banking ransomware tabletop, a hospital espionage intrusion and a water-utility CTEP." },
    { id: "genEnv", title: "The system under test", text: "Every ruling is made against an environment: its assets, the controls that cover them, and where the deception is. New stamps one from the library." },
    { id: "genActor", title: "Emulate an adversary", text: "A real ATT&CK group or an attack type, grounded in the environment you chose. Generate writes the scenes for you." },
    { id: "ctepSel", title: "Start from a CTEP pack", text: "Eleven packs across sectors, each runnable and adjudicated. Import one into its own environment in one click." },
    { id: "scenePanel", title: "The scene", text: "What the room is looking at right now. The projector view (Run day) shows only what the blue cell may see." },
    { id: "branches", title: "Next move", text: "The proctor decides. Space or → takes the first proctor choice; timers can advance on their own in real-time mode." },
    { id: "adjTech", title: "Adjudicate", text: "Type what the adversary did (ATT&CK ids and a target). The engine rules against the environment's controls and writes it to the signed timeline." },
    { id: "scorePanel", title: "The number", text: "Detection rate, time-to-detect, deception tripped — live. At the end: the hotwash, the reports, and a signed certificate anyone can verify." },
  ];
  let i = 0, box = null, ring = null;

  function visible(el) { return el && !el.hidden && el.offsetParent !== null; }
  function stops() { return STOPS.filter((s) => visible($(s.id))); }
  function end() {
    if (box) box.remove(); if (ring) ring.remove(); box = ring = null;
    try { localStorage.setItem(KEY, "1"); } catch (e) { /* noop */ }
    document.removeEventListener("keydown", keys);
  }
  function keys(e) {
    if (e.key === "Escape") end();
    else if (e.key === "ArrowRight" || e.key === "Enter") { e.stopPropagation(); e.preventDefault(); step(1); }
    else if (e.key === "ArrowLeft") { e.stopPropagation(); e.preventDefault(); step(-1); }
  }
  function step(d) { i += d; show(); }
  function show() {
    const list = stops();
    if (!list.length) { end(); return; }
    if (i < 0) i = 0;
    if (i >= list.length) { end(); return; }
    const s = list[i]; const el = $(s.id);
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    const r = el.getBoundingClientRect();
    if (!ring) { ring = document.createElement("div"); ring.className = "tour-ring"; document.body.appendChild(ring); }
    Object.assign(ring.style, { top: (r.top + window.scrollY - 6) + "px", left: (r.left + window.scrollX - 6) + "px", width: (r.width + 12) + "px", height: (r.height + 12) + "px" });
    if (!box) { box = document.createElement("div"); box.className = "tour-box"; document.body.appendChild(box); }
    box.innerHTML = `<p class="eyebrow">Tour · ${i + 1} of ${list.length}</p><h3>${s.title}</h3><p>${s.text}</p>` +
      `<div class="tour-btns"><button class="btn ghost small" data-t="skip">Skip</button>` +
      `${i > 0 ? '<button class="btn ghost small" data-t="back">Back</button>' : ""}` +
      `<button class="btn primary small" data-t="next">${i === list.length - 1 ? "Done" : "Next"}</button></div>`;
    const below = r.bottom + 12 + 180 < window.innerHeight;
    Object.assign(box.style, { top: (below ? r.bottom + window.scrollY + 12 : r.top + window.scrollY - 12) + "px",
      left: Math.max(12, Math.min(r.left + window.scrollX, window.innerWidth - 360)) + "px", transform: below ? "" : "translateY(-100%)" });
    box.querySelector('[data-t="skip"]').onclick = end;
    box.querySelector('[data-t="next"]').onclick = () => step(1);
    const b = box.querySelector('[data-t="back"]'); if (b) b.onclick = () => step(-1);
  }
  function start() { i = 0; document.addEventListener("keydown", keys, true); show(); }
  function maybeAuto() {
    let done = "1"; try { done = localStorage.getItem(KEY) || ""; } catch (e) { /* noop */ }
    const want = new URLSearchParams(location.search).get("tour") === "1";
    if (want || !done) setTimeout(() => { if (stops().length) start(); }, 900);
  }
  window.GauntletTour = { start, end, maybeAuto };
})();
