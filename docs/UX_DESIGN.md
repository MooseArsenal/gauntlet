# Gauntlet — QoL & UX design

_The plan for making Gauntlet operable without technical knowledge: mouse-first,
visually engaging, and gently gamified for retention — while staying professional
and letting power users go as granular as they like._

This document is the design brief for the **QoL arc** (Q1 this doc → Q2 the
visual scenario editor → Q3 the wizards, then the gamified blue-vs-red room).
It is deliberately implementation-light: it fixes the vision, principles, screens,
and interaction model so the build PRs have a north star.

---

## 1. Vision

Today Gauntlet is powerful but expert-facing: you author branching MSELs, hand-
edit YAML, and drive a facilitator console that assumes you know the vocabulary.
The QoL arc keeps every bit of that power and puts a **friendly, visual surface**
in front of it, so:

- a **proctor** builds an exercise by dragging scenes onto a canvas and wiring
  them together — no YAML, no jargon required;
- **two teams learn by playing** — blue (defenders) versus red (the proctor
  driving the adversary) — in a shared, fog-of-war room that turns an exercise
  into a memorable, repeatable teaching moment;
- the experience is **visually fun and rewarding** (progress, streaks, a live
  scoreboard, tasteful celebration of good defensive moves) **without feeling
  like a video game** — it reads as a polished professional tool that happens to
  be enjoyable to use;
- a power user can always **drop into the granular controls** (raw branch
  conditions, YAML import/export, the full API) — the visual layer is an
  on-ramp, never a ceiling.

> Design tension to hold throughout: **playful but professional.** When a choice
> trades one against the other, prefer the reading that a CISO would screenshot
> into a board deck — polish first, delight second, gimmicks never.

## 2. Principles

1. **Mouse-first, keyboard-fast.** Every core task is completable by pointing and
   clicking. Power users get keyboard shortcuts and inline text for speed, never
   as the only path.
2. **Show, don't spell.** A branching scenario is a picture, not a YAML tree.
   State, coverage, and detection gaps are visible at a glance.
3. **Progressive disclosure.** Start simple (a wizard, a few nodes); reveal depth
   (conditions, set-mutations, techniques, RoE) only when asked. "Go granular" is
   a button, not a different product.
4. **Always recoverable.** Undo/redo everywhere, autosave drafts, non-destructive
   edits, and a live validator that warns before you can break a scenario.
5. **Earned momentum.** Gamification serves *retention and learning*, not vanity:
   it rewards the behaviours a good exercise wants (fast triage, full coverage,
   clean containment) and is quiet when it would distract.
6. **One system, two themes.** Everything is theme-aware (light/dark), accessible
   (WCAG AA contrast, keyboard-navigable, reduced-motion honoured), and consistent
   with the existing console's visual language.

## 3. People & modes

| Persona | Wants | Primary surface |
|---|---|---|
| **Proctor / facilitator** | Build and run an exercise quickly; drive the adversary live | Visual editor + live room (control view) |
| **Blue team (defender)** | Understand what's happening; respond; learn | Live room (blue view, fog-of-war) |
| **Red team** (often the proctor) | Submit adversary actions; see what was detected | Live room (red view) + scoreboard |
| **Observer / evaluator** | Watch, score objectives, take notes | Live room (observer view) |
| **Educator / student** | Learn by doing; retain through repetition & feedback | Guided mode + gamified feedback |

**Two headline modes**, both built on the existing engine:

- **Design mode** — the visual scenario editor and the build wizard. Output is a
  normal Gauntlet scenario (same models, same API).
- **Play mode** — the live blue-vs-red room. A dressed-up, role-aware view over
  the existing session/WebSocket/purple-team endpoints, with fog-of-war and a
  scoreboard already shipped in F5.

## 4. Information architecture

```
Home / Dashboard
├── Build            → Wizard (guided)  ┐
│                     └ Visual editor ──┤ both produce a Scenario
├── Run              → Session wizard → Live room (role views)
│                        ├── Proctor / control
│                        ├── Blue view (fog-of-war)
│                        ├── Red view (+ submit actions)
│                        └── Observer / evaluator
├── Programme        → Schedules, rollups, improvement plan (existing APIs)
├── Reports & evidence
└── Account / Security (existing)
```

The current console (`web/index.html` + `app.js`) remains the "granular" home;
the new surfaces are additive routes that lean on the same API and can hand off
to the console at any point ("Open in advanced view").

## 5. The visual scenario editor (Q2)

The centrepiece. A branching MSEL is a **directed graph**; we let people draw it.

**Canvas.** A pan/zoom board of **inject nodes** connected by **branch edges**.
- **Node** = one inject (a scene). Shows title, channel icon (email / EDR alert /
  SIEM / briefing…), the kill-chain phase as a colour band, and small chips for
  ATT&CK techniques and the target asset. A "start" node is badged.
- **Edge** = a branch. Labelled by its trigger (`action_taken` / `timeout` /
  `proctor_choice`) and, if present, a condition (e.g. `state.contained == false`).
  A timeout edge shows its clock.
- **Palette** (left rail): the **inject bank** (F2/M2 catalog) grouped by phase,
  plus a blank node. Drag an entry onto the canvas to instantiate a pre-filled,
  best-practice scene; it auto-fills `{org}`/`{asset}` from the chosen environment.
- **Properties panel** (right rail): click a node/edge to edit everything in
  plain fields — narrative, expected actions, techniques, visibility per cell,
  branch trigger/goto/condition/`set`-mutations. This is where "granular" lives,
  progressively disclosed under an **Advanced** twist-down.
- **Live validation:** the F-series validator runs continuously; unreachable
  nodes, dangling `goto`s, missing start, or a branch to nowhere are flagged
  inline (a red dot on the node + a fixable message), never a wall of text.
- **Escape hatch:** a **YAML** tab shows the exact import/export the engine uses,
  editable, round-tripping with the canvas. Power users can paste a scenario in
  and see it laid out.

**Interactions**
- Drag from a node's edge-handle to another node to create a branch; drop on empty
  canvas to create-and-connect a new node.
- Multi-select, box-select, align/distribute, auto-layout ("tidy") that runs a
  simple layered graph layout so an imported YAML looks sensible instantly.
- Undo/redo, copy/paste nodes, duplicate a subtree.
- Autosave to a draft; explicit **Save** commits via the scenario API. Nothing is
  persisted server-side until save, so experimentation is free.

**Tech approach.** Inline **SVG** canvas rendered by vanilla JS in the existing
SPA style (no heavy framework, consistent with `app.js`). Graph model in memory,
serialised to the existing scenario/inject JSON on save; the YAML tab reuses the
shipped import/export endpoints. Theme-aware tokens; `prefers-reduced-motion`
disables the springy edge animations.

_Wireframe (schematic):_

```
┌───────────────────────────────────────────────────────────────┐
│  Ransomware — Finance      [Design] [YAML]      ⟲ ⟳   Validate ●│
├───────┬───────────────────────────────────────────┬───────────┤
│ BANK  │                CANVAS                      │ PROPERTIES │
│ ┌───┐ │      ┌─────────┐        ┌─────────┐        │ Title …    │
│ │📧 │ │  ▶── │ Phish   │──act──▶│ EDR:PS  │──to──▶ │ Channel …  │
│ │phish│ │      └─────────┘  \timeout      └─────────┘        │ Narrative…│
│ ├───┤ │                     ▼                       │ Techniques │
│ │🖥 │ │                 ┌─────────┐                  │ ▸ Advanced │
│ │edr │ │                 │ Missed  │                 │   condition│
│ └───┘ │                 └─────────┘                 │   set{…}   │
└───────┴───────────────────────────────────────────┴───────────┘
```

## 6. Wizards (Q3)

For people who want to be led. Each wizard is a short, friendly, mouse-driven
flow that produces the same artifacts as the expert path — and every step has a
**"skip to advanced"** link.

- **Build an exercise** — pick a sector → pick a threat (actor/template card) →
  confirm the environment (or import one via F6) → name it → **Generate**. Lands
  you in the visual editor with a ready-to-tune scenario.
- **Run a session** — pick a scenario → choose tabletop / functional / real-time
  → invite/assign cells (blue, red, observers) → **Start**, dropping into the
  live room.
- **Report & evidence** — pick a completed session → choose audience(s) and
  frameworks → get PDF/DOCX/CSV (F1) and compliance evidence (F2) in a click.

Wizards are a *view*, not a fork: they call the same generate/session/report APIs
the console does.

## 7. Play mode — the blue-vs-red educational room

Where the gamification and the teaching value live. One session, role-aware views
over the existing session + WebSocket + purple-team (F5) endpoints.

- **Proctor / control:** the full picture — timeline, current inject, branch
  choices, adjudication, and the red/blue scoreboard. Advances the story, rules
  actions, injects live (F7 range or simulation).
- **Blue view (fog-of-war):** only what defenders would see — the current scene,
  their feed, and an action tray ("Contain host", "Block sender", "Escalate")
  that maps to observations/decisions. Clear, calm, focused.
- **Red view:** submit adversary actions (F5 red-actions) and immediately see
  whether the blue team's controls detected them — the core learning loop.
- **Observer/evaluator:** score objectives, drop notes on the timeline.

**Live scoreboard** (built on F5): detections, mean time-to-detect, coverage vs.
the ATT&CK matrix, deceptions tripped — shown as clean stat tiles and a small
technique heatmap, not arcade HUD.

## 8. Gamification — for retention, not spectacle

The bar: a professional would leave it turned on. Mechanics, all opt-in per org:

- **Progress & momentum** — a per-exercise progress rail (phases cleared),
  streaks for consecutive fast triages, and a tasteful "detected!" micro-moment
  (a brief, mutable, reduced-motion-respecting highlight — never confetti spam).
- **Team score & MTTD** — the F5 scoreboard, framed as friendly blue-vs-red
  competition with a post-game "how you did" summary that doubles as a debrief.
- **Skill badges** — earned for demonstrated capabilities (e.g. "Clean
  containment", "Full kill-chain coverage", "Sub-10-min MTTD"), mapped to the
  same capability taxonomy the compliance crosswalk uses — so a badge is also
  evidence.
- **Learning reinforcement** — after each inject, an optional "why this matters"
  card and, in educator mode, a quick recap that aids retention.

Everything here is cosmetic over data we already compute; none of it changes
adjudication or the record.

## 9. Visual language

- **Tone:** clean, confident, a little playful. Generous spacing, rounded cards,
  soft depth. Motion is purposeful and quick (120–200ms), always
  `prefers-reduced-motion`-aware.
- **Colour:** a professional neutral base with a small, meaningful accent set —
  kill-chain phases get a consistent ordered palette (initial-access → actions-
  on-objective), reused on nodes, the phase rail, and the scoreboard so colour
  *means* the same thing everywhere. Blue-team / red-team get their two team
  colours, used sparingly. All defined as theme tokens on `:root`, redefined for
  dark.
- **Type:** the existing system stack; a clear type scale; numerals tabular in
  the scoreboard.
- **Iconography:** channel and technique icons as simple line glyphs (inline
  SVG), never emoji-as-UI.
- **Accessibility:** WCAG AA contrast in both themes; full keyboard operation of
  the canvas and wizards; visible focus; colour never the sole signal (icons +
  labels back it up).

## 10. Delivery roadmap (small, rolling PRs)

| Step | Scope | Deliverable |
|---|---|---|
| **Q1** | This design doc | `docs/UX_DESIGN.md` (+ optional visual mock) |
| **Q2** | Visual scenario editor | Drag-and-drop canvas, palette, properties, live validation, YAML escape hatch; saves via existing APIs |
| **Q3** | Wizards | Build / Run / Report guided flows over existing APIs |
| **Q4** | Play-mode polish + gamification | Role-aware live room styling, scoreboard tiles, progress/badges (opt-in) |
| **Q5** | Educator mode | Two-team classroom flow, recaps, retention aids |

Each step ships as its own reviewed PR with tests where there's logic (graph
model, validation, wizard state), and screenshots/interaction notes where it's
visual. The granular console and API remain first-class throughout — the QoL
layer is the friendly front door, not a replacement.

---

_Next: Q2 — the visual scenario editor. This doc is the reference it builds to;
it will evolve as real screens land._
