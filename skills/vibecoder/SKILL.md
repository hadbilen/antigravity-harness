---
name: vibecoder
description: >
  Product-first and vibe-oriented rapid prototyping skill for non-coders and exploratory builders.
  Flips the specification burden onto the agent, conducts a structured 3-step UX/aesthetic interview,
  and delivers zero-friction, immediately runnable single-file HTML application, game, and creative studio / interactive sandbox prototypes with click-by-click instructions.
  Triggers: /vibecode, /vibecoder, vibecoder, vibercoder, "fikrim var", "oyun prototipi", "etkileşimli kum havuzu", "ses sentezleyici", "vibe coding", "I want [outcome] for [audience]".
  Not for multi-file production engineering or Tier 2/3 architecture (use 'harness', 'game-engineering', or 'marathon').
---

# Vibe Coder (Product & Experience-First Builder)

> [!IMPORTANT]
> Internal instructions are canonical English (GEMINI.md Rule 6). Talk to the user in the language
> they use; Turkish trigger phrases such as "fikrim var" are intentional.

Jargon-free, vision- and feeling-driven rapid prototyping. The agent takes over the burden of writing
the technical specification: it listens to what the user wants, distils the real need behind it, and
produces interfaces that run with zero setup.

## Mutual Exclusion

- **Activation:** only when the user explicitly triggers `/vibecode` or `/vibecoder` (or a trigger phrase above) for
  rapid prototyping or product discovery.
- **Relationship with `harness`, `marathon`, `unlazy`, and `procoder`:** `vibecoder` runs EXCLUSIVELY in single-file prototype mode (1 HTML file) and is mutually
  exclusive with the architectural `harness` Tier 2/3 workflow, `marathon`, `unlazy`, and `procoder`: no `implementation_plan.md`, `tasks.md`, `GATES.md`, `.procoder/`, or `ADR` files while it
  is active. Standard day-to-day engineering stays with the core `harness` skill.
- **Deactivation:** ends when the user says "stop vibecode" / "normal mode", or when they ask to turn
  the prototype into a real product via `/marathon` (see Section 5), at which point `marathon` and `harness` Tier 3 apply.

---

## 1. Core Philosophy

### A. Take Over the Specification Burden (Inversion of Specification)
* Never ask the user **how** to build it (framework, database type, architecture patterns).
* Focus on what the user is an expert in: **what** they want, **who** it is for, **how it should feel**,
  and which **constraints** they have.
* The agent makes the technical decisions itself (utility CSS, browser storage, modular vanilla JS or a
  CDN-loaded React build). Every CDN asset must be pinned to an exact version and loaded with a
  Subresource Integrity hash (`integrity="sha384-…" crossorigin="anonymous"`) per GEMINI.md Rule 12;
  prefer inlining small libraries over remote scripts.

### B. Read Between the Lines
* Do not interpret the first sentence literally and stop there.
* When a user asks for an "invoice tracker", anticipate that they will need a print/PDF view, local
  persistence (`localStorage`), a clean empty state and search/filtering. Include what is essential for
  the first job and **list** optional extras (PDF export, search) in the delivery message instead of
  silently expanding scope.

### C. Prevent Decision Fatigue (Anti-Paralysis Gate)
* Never ask open-ended, sprawling questions.
* **Hard limit:** at most **3 questions** via `ask_question`.
* Present each question with Antigravity's interactive modal tool `ask_question`. In exported runtimes lacking `ask_question`, emit at most `3` numbered plain-text questions (`2–3` options and `1` `(Recommended)` default per question) and stop for user input.
* Give 2 or 3 concrete options per question, explain the reasoning behind each, and mark exactly one
  as `(Recommended)`.

### D. Zero-Friction Delivery (Applications, Games & Creative Sandboxes)
* Do not put technical friction such as `npm install` or `docker-compose up` in front of the user.
* Primary output: a **single rich HTML file** that runs by double-clicking it in the browser (`file://`-safe with zero external CORS asset dependencies), or an in-chat **Generative UI** component.
* **Game Prototype Mode (`Game Vibe Mode`):** When the user wants a game or interactive simulation prototype, deliver a self-contained **single-file rich HTML** game (`<canvas>` 2D/WebGL + inline procedural rendering + WebAudio synthesized sound effects) that runs immediately on double-click without external `.png`/`.mp3` files or a local dev server.
* **Creative Studio & Sandbox Mode (`Creative & Sandbox Vibe Mode`):** When the user wants an audio/visual synthesizer, drum sequencer, generative art or shader studio, vector/pixel canvas tool, or an interactive algorithm/physics/finance sandbox (distinct from static architecture diagrams owned by `skills/visualizer/SKILL.md` and multi-section marketing sites owned by `skills/silk-design/SKILL.md`), deliver a self-contained **single-file rich HTML** studio with real-time tactile controls, live `<canvas>` / Scalable Vector Graphics (`SVG`) / `WebAudio` synthesis, built-in starter presets, and one-click client-side file export (`.json`, `.svg`, `.png`, or `.wav` via `Blob` URLs).
* On delivery, give a step-by-step **"Where do I click / what keys do I press now?"** guide instead of terminal commands.

### E. Aesthetic and Quality Shield (`antislop` & `game-engineering` compliance)
* Fast does not mean low quality. Every prototype must meet the constitution's `antislop` standards:
  * **Application / Utility Prototypes (`MODE: UTILITY` / `MODE: EDITORIAL`):**
    * WCAG AA color contrast (washed-out light-gray text is forbidden).
    * Five component states: default, hover, focus, active, disabled.
    * Mobile: zero horizontal scrolling, using flexible flex/grid layouts (not an `overflow-x: hidden` trap).
    * Realistic micro-copy: `Download quote as PDF` or `Add invoice` instead of `Lorem ipsum` or `Submit`.
    * Pass `python3 skills/antislop/scripts/check_ui_slop.py <path.html> --mode utility` (or `~/.gemini/config/skills/antislop/scripts/check_ui_slop.py`).
  * **Game & Interactive Prototypes (`MODE: GAME & INTERACTIVE`, bridged with `skills/game-engineering/SKILL.md`):**
    * **Viewport & Diegetic HUD:** The `<canvas>` playfield owns at least `85%` of the viewport; HUD indicators (score, health, cooldowns, wave) anchor to screen edges (`8px–16px` safe inset) on dark translucent plates (`var(--surface-hud-scrim)` per `DESIGN.md` §3), never inside white SaaS `.card` boxes.
    * **Fixed-Timestep & Seeded Loop:** Separate fixed simulation ticks (`FIXED_DT = 1 / 60` s with clamped frame accumulator) from `render(alpha)`, use an explicit seeded PRNG (`mulberry32`), and expose `globalThis.__stepTick = globalThis.stepTick = stepTick` (`stepTick(state, input)`) for deterministic headless inspection.
    * **Cohesive World Palette & Offline Display Typography (`UI-4` & `DESIGN.md` §2.1):** Use a 5–7 color world palette with distinct luminance and shape silhouettes; raw uncalibrated hex primaries (`#FF0000`, `#00FF00`, `#0000FF`, `#FFFF00`, `#FF00FF`, `#00FFFF`) are forbidden. Avoid `system-ui` on game title screens, combat callouts, and diegetic HUD banners using offline-compliant single-file typography: an inline `data:font/woff2;base64` subset (`<= 32 KB`), procedural `<canvas>`/`<svg>` display glyphs, or named local non-`system-ui` stacks (such as `'Trebuchet MS', Georgia, serif`).
    * **Input Feedback Triad ("Juice"):** Every primary player action triggers at least two synchronous channels inside the single HTML file: visual squash-stretch/hit-flash/pooled particles, decaying trauma screen shake (disabled under `prefers-reduced-motion: reduce`), and synthesized WebAudio SFX (`AudioContext` + `OscillatorNode`/noise burst envelope with a visible mute button).
    * Pass `python3 skills/antislop/scripts/check_ui_slop.py <path.html> --mode game` (or `~/.gemini/config/skills/antislop/scripts/check_ui_slop.py`) with zero `UI-1`–`UI-5` findings.
  * **Creative Studios, Synthesizers & Interactive Sandboxes (`3C`):**
    * **Zero-Latency Parameter Coupling (`<= 16.6ms` Frame Budget):** Sliders, rotary dials, XY pads, and step-grid toggles update the `<canvas>`, `SVG`, or `WebAudio` graph within a single `requestAnimationFrame` tick (`<= 16.6ms` at 60Hz) on `input`/`pointermove` without requiring a "Submit" button, displaying live numeric readouts in `tabular-nums`.
    * **Audio & Motion Safety Guards:** Audio synthesizers must initialize or resume `AudioContext` strictly on an explicit user gesture, clamp master output gain (`GainNode` `<= 0.8` or `DynamicsCompressorNode` limiter), and expose a visible **Mute / Panic** button; high-frequency visual shaders and particle emitters must honor `@media (prefers-reduced-motion: reduce)` and `window.matchMedia('(prefers-reduced-motion: reduce)')`.
    * **Curated Starter Presets & Reset:** Include 3–4 contrasting built-in presets (plus a "Randomize / Mutate" or "Reset" trigger) so the user experiences rich output on the very first click before tweaking individual parameters.
    * **Zero-CORS Client-Side Export:** Provide one-click browser export using native APIs (`canvas.toDataURL("image/png")`, serialized `SVG` / `JSON` `Blob` download, or `OfflineAudioContext` PCM `.wav` encoding), plus `localStorage` preset slots whenever persistence is selected in Question 3 of Section 3C.
    * Pass `python3 skills/antislop/scripts/check_ui_slop.py <path.html> --mode utility` (or `--mode game` when the primary `<canvas>` stage occupies `>= 85%` of the viewport).
* A single HTML file is not automatically low-risk: never embed secrets, and tell the user where data
  is stored (for example "only in this browser").

### F. Experience Goal & Acceptance Criteria
* At the start, capture the prototype's goal in one line (audience, feel, the primary one-click outcome) and 2–3 observable acceptance criteria (e.g. "a record can be added and appears in the list", "it still shows after a page reload").
* The criteria are the prototype's definition of done: they stop endless aesthetic drift, and progress is reported as criteria met ("2/3"), never as a percentage.
* **Embedded Single-File Promotion Metadata:** Persist Section 1F inside the generated single `.html` file as `<script type="application/json" id="vibecoder-promotion-spec">{"goal": "...", "audience": "...", "mode": "...", "acceptance_criteria": [...], "implicit_assumptions": [...]}</script>` so zero extra files are created while `/marathon` (`skills/marathon/SKILL.md` §1) and `skills/harness/SKILL.md` §6 can deterministically read Section 1F in a fresh window.

---

## 2. Four-Step Workflow

```
[User idea]
       ↓
[Step 1: Capture intent & infer needs]
       ↓
[Step 2: Vibe-Grill (3 targeted questions via ask_question)]
       ├─ Question 1: Core user flow (first job-to-be-done)
       ├─ Question 2: Visual texture and atmosphere (aesthetic / vibe)
       └─ Question 3: Data and usage constraints (persistence)
       ↓
[Step 3: Smart build (single-file / Generative UI)]
       ↓
[Step 4: Hand-off ("double-click, open, press here")]
```

---

## 3. Questioning Discipline (`Vibe-Grill`)

Questions target the user experience and the feeling of the product, never technology. Choose **3A** for applications/tools, **3B** for games/interactive simulations, or **3C** for creative studios, audio/visual synthesizers, and interactive sandboxes.

### 3A. Application / Utility Prototype Questions

#### Example Question 1: Core Flow
* *Wrong:* "Should CRUD go through REST or GraphQL?"
* *Right:* "When someone opens this page, what is the first and most satisfying thing they should do?"
  * `(Recommended)` Quick form, instant result: enter data and create a visual card/document in one click.
  * Status board: drag and drop work items across columns (To do, In progress, Done).

#### Example Question 2: Visual Vibe
* *Wrong:* "Which primary color should the design tokens use?"
* *Right:* "How should the app feel visually?"
  * `(Recommended)` Minimal dark studio: charcoal background, one vivid accent, refined `system-ui` typography.
  * Clean & structured: crisp light background, slate details, airy trustworthy tables.
  * Warm & tactile: cream/paper background, monospace (`ui-monospace`) numeric accents, classic ledger feel (conforming to `DESIGN.md` two-font discipline: `system-ui` + `ui-monospace`).

#### Example Question 3: Keeping Information (Persistence)
* *Wrong:* "SQLite or IndexedDB?"
* *Right:* "How should the information you enter be kept?"
  * `(Recommended)` Browser memory: no setup or account; everything stays saved in this browser.
  * Private / per session: everything resets when the page is closed.

### 3B. Game Prototype Questions (`Game Vibe-Grill`)

#### Example Question 1: Core Gameplay Loop & Controls
* *Wrong:* "Should we use a 2D AABB physics step or a grid state array?"
* *Right:* "In the first 10 seconds after pressing Play, what is the main action that hooks the player?"
  * `(Recommended)` Fast arcade reflex (`WASD` / arrows / mouse): dodge hazards, aim, and chain combos in real time.
  * Tactical / turn-based puzzle: plan moves on a board or grid where every step changes the field.
  * Physics & timing challenge: launch, balance, or deflect objects with one-click or drag controls.

#### Example Question 2: World Atmosphere & Game Feel ("Juice")
* *Wrong:* "What particle pool size and WebAudio oscillator waveform should we configure?"
* *Right:* "How should the game world look, sound, and react when you hit or score?"
  * `(Recommended)` High-impact dark arcade: obsidian arena, luminous cyan/amber silhouettes, screen shake, and synthesized retro sound effects.
  * Crisp geometric minimal: high-contrast slate board, tactile squash-stretch motion, and soft percussive audio cues.
  * Warm nostalgic cabinet: CRT-style amber/emerald palette, chunky pixel-inspired shapes, and classic arcade bleeps.

#### Example Question 3: Progression & High-Score Persistence
* *Wrong:* "Should we serialize the PRNG seed and leaderboard to `localStorage`?"
* *Right:* "How should player progress and high scores work between runs?"
  * `(Recommended)` Arcade cabinet memory: save best score, unlocked perks, and daily seed automatically in this browser.
  * Pure single-run session: every reload starts fresh from zero with no saved state.

### 3C. Creative Studio, Synthesizer & Interactive Sandbox Questions (`Creative & Sandbox Vibe-Grill`)

#### Example Question 1: Primary Creative / Simulation Surface
* *Wrong:* "Should we wire an `AudioWorkletNode`, a 2D `<canvas>` buffer, or an `SVG` DOM tree?"
* *Right:* "When you open the studio or sandbox, how do you want to shape and play with the output?"
  * `(Recommended)` Live tactile parameter deck + real-time stage: tweak sliders, XY pads, or step grids and watch/hear the canvas or synthesizer respond immediately.
  * Direct canvas manipulation: draw, drag nodes, place emitters/forces directly on the stage, and play/pause the simulation.
  * Side-by-side scenario explorer: compare presets or input curves against live visual charts and simulated outcomes.

#### Example Question 2: Studio Aesthetic & Tactile Feel
* *Wrong:* "Which CSS custom properties and oscilloscope FFT bin size should we use?"
* *Right:* "What kind of instrument or lab atmosphere should the workspace have?"
  * `(Recommended)` Hardware synth & dark lab: matte graphite surface, amber/cyan LED meters, tactile rotary/slider controls, and live waveform/spectrum feedback.
  * Swiss precision Drafting Table: crisp light/slate grid, high-contrast vector geometry, and clean numeric readouts.
  * Expressive generative stage: full-bleed visual canvas with a floating translucent control dock.

#### Example Question 3: Presets, Saving & Artifact Export
* *Wrong:* "Should we encode a `Blob` URL with `canvas.toDataURL` or serialize JSON state to `localStorage`?"
* *Right:* "What should you be able to keep or take away after creating something you like?"
  * `(Recommended)` Built-in presets + one-click file export: start from curated presets, save custom patches in this browser, and download the result (`.png` / `.svg` / `.wav` / `.json`).
  * Live ephemeral playground: focus purely on real-time exploration with a quick "Randomize / Reset" button.

---

## 4. Delivery Format

The final message after the code is written must contain these blocks in order, placing the Delivery Block strictly at the end (`GEMINI.md` Rules 5 & 8):

1. **Summary & file path:** where the single `.html` file was saved (e.g. `workspace/invoice-tracker.html`, including embedded `#vibecoder-promotion-spec` metadata).
2. **How to run it (zero technical language):**
   * "Double-click the file, or drag and drop it onto an open Chrome tab."
3. **First-experience guide:**
   * "Step 1: Click the green button at the top right."
   * "Step 2: Enter a sample record and press 'Save'."
   * "Step 3: Look at the result in the preview card."
4. **Delivery Block (`GEMINI.md` Rules 5 & 8 — Closing Block Only):**
   * **Progress:** each acceptance criterion from Section 1F marked met or not met (e.g. `"3/3 acceptance criteria met"`, never a percentage).
   * **Verification Gap Declaration:** list what was verified (`check_ui_slop.py`, HTML/JavaScript syntax check, deterministic headless `stepTick` check where applicable) and what was *not* verified (e.g. live browser visual/WebAudio rendering or physical mobile touch).
   * **Falsification Gate (Popper's Invariant):** state what discriminating edge or falsifying check was executed (or whether any available check was not run).
   * **Next Step (`marathon` promotion bridge):** end with a single concise line offering `/marathon` (`skills/marathon/SKILL.md`) in a fresh window (reading `#vibecoder-promotion-spec` from the `.html` file) if the user wants to evolve the prototype into a full production build or multi-window architecture plan (with `tasks.md`, `HANDOFF.md`, and per-window model/effort routing).

---

## 5. Constitutional Balance (Harness Isolation)

* `vibecoder` operates as an **explicit single-file prototype-mode exemption** (1 HTML file; Tier 2/3 multi-file planning artifacts are deferred until promotion, though single-file prototypes may exceed 20 lines while still passing `check_ui_slop.py` and syntax/tick verification).
* During exploratory prototyping, do not burden the user with formal architecture plans
  (`implementation_plan.md`), test-suite scaffolding or `ADR` documents; however, never weaken or modify any existing repository tests (`GEMINI.md` Rule 9).
* **When to promote:** when all acceptance criteria are met and the user says "let's connect this to
  a real backend and ship it" (or invokes `/marathon`), stop prototyping and switch to `marathon`
  (`skills/marathon/SKILL.md`) and `harness` Tier 3 standards; the goal and criteria carry over into
  `tasks.md` and the exit criteria of `HANDOFF.md`.
