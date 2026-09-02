/* Game mode (L3): a skin and a vocabulary over the same engine.
 * Encounter and action cards, a d20 that always lands consistent with the
 * engine's ruling, XP from decision scores, HP from the impact of the path,
 * quests from objectives. Toggle with the 🎲 button or ?mode=game. The record,
 * the certificate and the reports underneath are unchanged. */
(() => {
  "use strict";
  const KEY = "gauntlet-mode";
  const VOCAB = [
    ["What you've been told", "Encounter"], ["Decision", "Your move"], ["Communications decision", "Your words"],
    ["Submit decision", "Play card"], ["Issue statement", "Speak"], ["Your decision", "Card played"],
    ["Your feed", "Chronicle"], ["updates live", "the tale unfolds"], ["Consider", "Options on the table"],
    ["Record", "Chronicle"], ["Objectives", "Quests"], ["Adjudicate an action", "Roll for the adversary"],
    ["Next move", "Next turn"], ["the proctor decides", "the dungeon master decides"], ["Adjudicate", "Roll"],
    ["Blue vs Red", "Party vs Adversary"], ["live scoreboard", "the tally"], ["Run an exercise, or build one.", "Begin a campaign, or write one."],
    ["Start exercise", "Begin campaign"], ["Exercise name", "Campaign name"], ["Hotwash", "Rest & recount"],
    ["Certificate", "Scroll of completion"], ["Your participation", "Your legend"], ["Join the exercise", "Join the party"],
    ["Join exercise", "Join the party"], ["Your side", "Your role"], ["Blue cell — defenders", "The Party — defenders"],
    ["Red cell — adversary", "The Adversary"], ["White cell — control and observers", "Dungeon master and watchers"],
    ["Detected", "Hit"], ["Missed", "Miss"], ["DETECTED", "HIT"], ["MISSED", "MISS"], ["CAUGHT", "CAUGHT!"], ["UNDETECTED", "SLIPPED PAST"],
    ["Evasion rate", "Stealth"], ["Got through", "Slipped past"], ["Caught", "Caught"], ["Moves", "Turns"],
    ["Facilitator Console", "Dungeon Master's Table"], ["Participant view", "Adventurer's view"], ["Red-cell view", "Adversary's view"],
  ];
  const on = () => document.documentElement.getAttribute("data-mode") === "game";
  function set(mode) {
    document.documentElement.setAttribute("data-mode", mode ? "game" : "");
    try { localStorage.setItem(KEY, mode ? "game" : ""); } catch (e) { /* noop */ }
    if (mode) loadFonts();
    translate();
    document.querySelectorAll("#btnGame").forEach((b) => { b.classList.toggle("on", mode); b.title = mode ? "Back to exercise control" : "Game mode"; });
  }
  function loadFonts() {
    if (document.getElementById("gameFonts")) return;
    const l = document.createElement("link"); l.id = "gameFonts"; l.rel = "stylesheet";
    l.href = "https://fonts.googleapis.com/css2?family=Cinzel:wght@600;800&family=Spectral:ital,wght@0,400;0,600;1,400&display=swap";
    document.head.appendChild(l);
  }
  // Exact-text replacement on labels; the original is kept on the node so it can be undone.
  function translate() {
    const game = on();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((n) => {
      const parent = n.parentElement; if (!parent || ["SCRIPT", "STYLE", "TEXTAREA", "INPUT"].includes(parent.tagName)) return;
      const raw = n.nodeValue; const key = raw.trim(); if (!key) return;
      if (game) {
        const hit = VOCAB.find(([a]) => a === key);
        if (hit) { if (!parent.dataset.gameOrig) parent.dataset.gameOrig = raw; n.nodeValue = raw.replace(key, hit[1]); }
      } else if (parent.dataset.gameOrig) { n.nodeValue = parent.dataset.gameOrig; delete parent.dataset.gameOrig; }
    });
  }
  // A d20 that lands consistent with the ruling: DC from the modelled odds, roll on the right side of it.
  function dice(ruling) {
    const p = typeof ruling.probability === "number" ? ruling.probability : (ruling.detected ? 0.8 : 0.2);
    const tripped = (ruling.controls_hit || []).some((c) => c.deception);
    const dc = Math.max(2, Math.min(20, Math.round((1 - p) * 20) + 1));
    let roll;
    if (tripped) roll = 20;
    else if (ruling.detected) roll = dc + Math.floor(Math.random() * (21 - dc));
    else roll = 1 + Math.floor(Math.random() * (dc - 1));
    return { dc, roll, tripped };
  }
  function diceHtml(ruling) {
    if (!on()) return "";
    const d = dice(ruling);
    return `<div class="d20 ${ruling.detected ? "hit" : "miss"}"><span class="d20-face"><span class="d20-n">${d.roll}</span></span>` +
      `<span class="d20-txt">${d.tripped ? "Natural 20 — the trap springs!" : ruling.detected ? `Rolled ${d.roll} against DC ${d.dc}: the defenders notice.` : `Rolled ${d.roll} against DC ${d.dc}: the adversary slips past.`}</span></div>`;
  }
  const xpFor = (score) => Math.round((score == null ? 0.5 : score) * 100);
  function progress(view) {
    // XP from this player's cards, HP from the party's impact budget.
    const mine = (view.timeline || []).filter((e) => e.kind === "response");
    const xp = mine.reduce((a, e) => a + xpFor(e.payload && e.payload.score), 0);
    const level = Math.floor(xp / 300) + 1;
    const imp = view.impact || {};
    const cost = Number(imp.cost || 0);
    const hp = Math.max(0, 100 - Math.min(100, Math.round(cost / 20000)));  // $2M ≈ the whole bar
    return { xp, level, hp, next: 300 - (xp % 300) };
  }
  function progressHtml(view) {
    if (!on()) return "";
    const p = progress(view);
    const quests = (view.objectives || []).map((o) => `<li>◈ ${o.title}</li>`).join("");
    return `<div class="gm-sheet"><div class="gm-stat"><span class="k">Level</span><span class="v">${p.level}</span></div>` +
      `<div class="gm-stat wide"><span class="k">XP ${p.xp} · ${p.next} to next</span><span class="gm-bar"><span style="width:${Math.round((p.xp % 300) / 3)}%"></span></span></div>` +
      `<div class="gm-stat wide"><span class="k">Party HP ${p.hp}/100</span><span class="gm-bar hp"><span style="width:${p.hp}%"></span></span></div>` +
      (quests ? `<div class="gm-quests"><span class="k">Quests</span><ul>${quests}</ul></div>` : "") + `</div>`;
  }
  function init() {
    let want = ""; try { want = localStorage.getItem(KEY) || ""; } catch (e) { /* noop */ }
    if (new URLSearchParams(location.search).get("mode") === "game") want = "game";
    // the toggle sits next to the theme button on every page that has one
    document.querySelectorAll("#btnTheme").forEach((t) => {
      if (document.getElementById("btnGame")) return;
      const b = document.createElement("button"); b.id = "btnGame"; b.className = "btn toggle"; b.type = "button"; b.textContent = "🎲"; b.setAttribute("aria-label", "Game mode");
      b.addEventListener("click", () => set(!on())); t.parentElement.insertBefore(b, t);
    });
    set(want === "game");
    new MutationObserver(() => { if (on()) translate(); }).observe(document.body, { childList: true, subtree: true });
  }
  window.GauntletGame = { on, set, dice, diceHtml, progressHtml, translate };
  document.addEventListener("DOMContentLoaded", init);
})();
