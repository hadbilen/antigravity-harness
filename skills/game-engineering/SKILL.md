---
name: game-engineering
description: >-
  Deterministic game loop architecture, real-time simulation discipline, entity state machines, seeded procedural
  generation, and game feel ("juice") engineering for 2D/3D web, canvas, and engine-based games. Enforces fixed-timestep
  simulation decoupling, zero per-frame allocation, headless tick verification, and MODE: GAME & INTERACTIVE UI vitality.
  Invoke with /game-engineering or when building, refactoring, or debugging games, interactive simulations, physics
  loops, or canvas/WebGL applications ("oyun geliştir", "oyun motoru", "game loop", "canvas oyun", "fizik döngüsü").
  Not for zero-spec single-file UX discovery interviews (use 'vibecoder') or post-hoc profiling of non-game software (use 'sweetspot').
---

# Game Engineering & Real-Time Interactive Simulation Discipline

Standard web CRUD habits break real-time games. Coupling physics to display refresh rates, allocating objects inside 60–120 Hz loops, scattering boolean flags (`isJumping && !isDead && isDashing`) across update handlers, and wrapping game HUDs in SaaS admin cards produce jittery, buggy, lifeless prototypes. This skill enforces deterministic simulation architecture, compile-time entity safety, and tactile game feel ("juice").

---

## 1. Fixed-Timestep Simulation & Render Decoupling

Never advance physics, movement, cooldowns, or AI directly by variable frame delta (`requestAnimationFrame` delta or unguarded engine frame time) without an accumulator. Variable frame steps make collision tunneling and jump heights depend on monitor refresh rate (60 Hz vs. 144 Hz) and tab-switch lag spikes.

### Required Architecture
1. **Fixed Simulation Tick (`update(dt)`):** Advance all game rules, physics, collisions, and AI in discrete fixed steps (for example, `FIXED_DT = 1 / 60` seconds = `16.6667 ms`).
2. **Clamped Frame Accumulator:** Clamp incoming frame deltas (for example, `Math.min(frameDelta, 0.25)`) before accumulating so background tab pauses never trigger a spiral-of-death freeze.
3. **Pure Render Pass (`render(alpha)`):** Rendering reads world state and interpolates visual positions using `alpha = accumulator / FIXED_DT`. Rendering must never mutate simulation state, decrement timers, or resolve collisions.
4. **Headless Step Seam (`stepTick(state, input)`):** Expose the fixed tick function (and alias `globalThis.__stepTick = globalThis.stepTick = stepTick` in browser/single-file HTML builds) so tests can run 1,000+ ticks synchronously in milliseconds without a browser, DOM, or GPU context.

### Architectural Seam Carve-Out (Efficiency Ladder Rung 7)
Single-call-site phase functions inside the hot loop (`readInput`, `stepPhysics`, `resolveCollisions`, `evaluateAi`, `stepCombat`, `renderWorld`, `renderHud`) are **architectural verification seams**, not speculative abstraction bloat. Do **not** inline them into a monolithic 800-line `tick()` function under `skills/harness/SKILL.md` Efficiency Ladder Rung 7.

---

## 2. Hot-Path Memory & Frame-Budget Discipline (`16.6 ms` at 60 FPS)

Inside `update(dt)`, `render(alpha)`, and collision broad/narrow phases:

* **Zero Per-Frame Heap Allocation:** Do not allocate new arrays (`.map()`, `.filter()`, spread `[...entities]`), temporary vector objects (`new Vec2()`), closures, or DOM nodes inside per-frame loops. Mutate pre-allocated scratch vectors or iterate index-based over contiguous arrays/typed buffers.
* **Object Pooling for Transient Entities:** Projectiles, particles, floating damage numbers, and hit sparks must use fixed-capacity ring buffers or object pools (`acquire()` / `release()`), never per-shot instantiation and garbage collection.
* **DOM vs. Canvas Boundary:** Never synchronize high-frequency per-frame state (entity coordinates, particle positions, smooth health drain) through React/Vue state re-renders or per-frame `element.style.transform` mutations on dozens of nodes. Keep 60 Hz visual updates inside `<canvas>` / WebGL / engine layers, and bridge to DOM HUD overlays only on discrete state transitions (score change, inventory toggle, wave clear, game over).

---

## 3. Entity State Machines & Mistake-Proofing (`skills/mistake-proofing/SKILL.md`)

Boolean flag soup (`isGrounded`, `isDashing`, `isAttacking`, `isStunned`, `isDead`) creates $2^N$ implicit states where illegal combinations (attacking while dead, dashing while stunned) inevitably occur.

* **Discriminated State Unions:** Represent entity lifecycle and action states as explicit closed unions or state tables (`type ActorState = { kind: "idle" } | { kind: "dash"; remainingTicks: number } | { kind: "stunned"; recoveryTicks: number } | { kind: "dead" }`).
* **Exhaustive Transition Table:** Centralize state transitions in a single pure transition function (`transitionActor(state, event)`). Every state transition must explicitly define which events are legal and which are ignored.
* **Branded Coordinate & Unit Types:** When mixing coordinate spaces, distinguish `WorldPos`, `ScreenPos`, and `TileCoord` (or `Seconds` vs. `Ticks`) so passing tile indices into pixel-space collision functions is prevented or immediately announced.

---

## 4. Seeded Determinism & Economy Balance

Unseeded `Math.random()` makes procedural maps, loot drops, and enemy spawns impossible to reproduce when a bug occurs on tick 4,200.

* **Explicit Seeded PRNG:** Route all gameplay randomness (map generation, spawn tables, critical hit rolls, AI tie-breaking) through an explicit seeded pseudo-random number generator (`mulberry32`, `sfc32`, or `PCG`) stored in the simulation state (`state.rngSeed`).
* **Reproducible Replay Contract:** Given `(initialSeed, frameInputLog)`, running `stepTick` for $N$ ticks must produce bit-identical entity states, scores, and health values across runs.
* **Closed-Form Economy Bounds:** Express damage, XP curves, wave scaling, and resource costs as named table constants or pure functions (`xpForLevel(level)`, `enemyHpForWave(wave)`), never magic numbers buried inside collision branches.

---

## 5. Game Feel ("Juice") & `MODE: GAME & INTERACTIVE` Vitality

A mechanically working game still feels like AI programmer art if inputs have no physical weight and the HUD looks like a SaaS dashboard. Apply `DESIGN.md` §2.1 (`MODE: GAME & INTERACTIVE`), `skills/antislop/SKILL.md` (`Game & Interactive Canvas Vitality`), and the following rules:

1. **Viewport Budget (`>= 85%` Canvas):** The interactive playfield owns at least 85% of the viewport. Never wrap a `<canvas>` inside a padded marketing page with a 3-card feature grid below it unless explicitly requested.
2. **Diegetic HUD Over SaaS Cards:** Anchor HUD indicators (health, ammo, score, minimap, cooldowns) to screen edges (`8px–16px` safe inset) using translucent dark plates (`var(--surface-hud-scrim)`, defined as `--surface-hud-scrim: rgba(10, 14, 23, 0.78)` in `DESIGN.md` §3), crisp `1px` specular borders, or angled/chamfered bars. Never use white SaaS `.card` boxes or `Inter` admin tables over the playfield.
3. **Cohesive Palette Over Raw Primaries (`UI-4`):** Never render entities or bars with uncalibrated RGB/CMY hex primaries (`#FF0000`, `#00FF00`, `#0000FF`, `#FFFF00`, `#FF00FF`, `#00FFFF`). Define a cohesive 5–7 color world palette (background depth layers, player focal hue, hazard hue, collectible hue, neutral structure) with distinct luminance AND shape silhouettes so colorblind players can read every threat by silhouette alone.
4. **Input Feedback Triad:** Every primary player action (jump, fire, hit, dash, collect, take damage) must trigger at least **two** synchronous feedback channels:
   * **Visual:** `80ms–140ms` transform/squash-stretch tween, 2–4 frame hit-flash, directional knockback impulse, or pooled particle burst.
   * **Spatial / Camera:** Decaying trauma-based screen shake (bounded amplitude, immediately disabled when `prefers-reduced-motion: reduce` is active) or brief hit-stop (`2–4` simulation freeze frames on heavy impact).
   * **Audio / Tactile Cue:** Synthesized WebAudio procedural SFX (`OscillatorNode` / noise burst envelope) or explicit audio/haptic hook with mute toggle.

---

## 6. Headless Verification & Delivery Gate

Before declaring any game or interactive simulation task complete, run all four verification checks:

1. **Headless Tick Invariant Test (`1,000+` Ticks):** Write and run a unit/simulation test that steps the headless loop for at least `1,000` ticks across seeded scenarios (`idle`, `continuous movement`, `combat/collision saturation`, `boundary edges`) and asserts:
   * Zero `NaN` or `Infinity` values in any entity position, velocity, health, or score field.
   * All bounded entities remain within legal world/arena bounds (no collision tunneling out of bounds).
   * Deterministic replay: running the same seed and input sequence twice yields identical state snapshots.
   * Pool/entity cap holds: active entity count never exceeds the configured pool ceiling.
2. **State Machine Transition Coverage:** Verify every legal transition and confirm illegal transitions (for example, moving or attacking while in `"dead"` or `"gameover"` state) are rejected.
3. **Structural UI Slop Gate (`check_ui_slop.py`):** Run the deterministic UI slop scanner in game mode on all HTML/JSX/TSX/CSS files:
   ```bash
   python3 skills/antislop/scripts/check_ui_slop.py <paths> --mode game
   # Or from installed global config:
   python3 ~/.gemini/config/skills/antislop/scripts/check_ui_slop.py <paths> --mode game
   ```
   Zero `UI-1`–`UI-5` findings are permitted on delivery.
4. **Type, Lint & Test Suite:** Pass the project's standard typecheck, lint, and unit test gates with zero errors (`skills/harness/SKILL.md` §3B).
   * **Single-File Prototype Mode (`vibecoder`) Carve-Out:** When building a single-file HTML game prototype under `skills/vibecoder/SKILL.md`, execute the `1,000+` tick invariant and state-transition checks via an ephemeral CLI one-liner or `<appDataDir>/brain/<conversation-id>/scratch/` probe against `globalThis.__stepTick` / `globalThis.stepTick` and run `check_ui_slop.py --mode game` without creating persisted unit test files or requiring multi-file `harness` §3B test suites.
