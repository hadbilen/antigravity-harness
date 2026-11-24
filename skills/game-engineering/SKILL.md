---
name: game-engineering
description: >-
  Deterministic fixed-timestep game loop architecture, entity state machines, zero per-frame allocation, seeded
  procedural generation, and game feel ("juice") for 2D/3D web, canvas, and engine games. Invoke with /game-engineering
  or on "oyun geliştir", "oyun motoru", "game loop", "canvas oyun", "fizik döngüsü". Not for zero-spec single-file UX
  discovery interviews (use 'vibecoder') or profiling non-game software (use 'sweetspot').
---

# Game Engineering & Real-Time Interactive Simulation Discipline

Standard web CRUD habits break real-time games. Coupling physics to display refresh rates, allocating objects inside 60–120 Hz loops, scattering boolean flags (`isJumping && !isDead && isDashing`) across update handlers, leaking GPU/audio handles on scene transitions, and wrapping game HUDs in SaaS admin cards produce jittery, buggy prototypes. This skill enforces deterministic simulation architecture across two execution profiles, compile-time entity safety, asset verification, and tactile game feel ("juice").

### Execution Profiles (Select Before Implementation)
* **Profile A — Web / `<canvas>` / WebGL / WebGPU:** Browser single-page apps, modular TypeScript games, or promoted `vibecoder` (`"mode": "game"`) builds. Enforces fixed-step `requestAnimationFrame` accumulators, `globalThis.__stepTick`, DOM/canvas separation, offline display fonts, and `check_ui_slop.py --mode game` on HTML/JSX/TSX/CSS layers.
* **Profile B — 3D & Native / Compiled Game Engines (Godot, Unity, Unreal, Bevy, SDL2/Raylib):** Map simulation determinism onto the engine's fixed tick hook (`_physics_process`, `FixedUpdate`, `FixedUpdate` schedule in Bevy, or explicit sub-stepping) while keeping core rules/math pure so headless simulation tests run without spawning a GPU window. HTML-only `check_ui_slop.py` does **not** scan native engine scripts (`.gd`, `.cs`, `.cpp`, `.rs`); verify engine UI legibility, input remapping, and explicit GPU/native resource disposal (`queue_free`, `Destroy`/`Dispose`, manual mesh/texture/shader/audio-buffer release on scene unload) directly in engine gates.

---

## 1. Fixed-Timestep Simulation, Input Buffering & Render Decoupling

Never advance physics, movement, cooldowns, or AI directly by variable frame delta (`requestAnimationFrame` delta or unguarded engine frame time) without an accumulator. Variable frame steps make collision tunneling and jump heights depend on monitor refresh rate (60 Hz vs. 144 Hz) and tab-switch lag spikes.

### Required Architecture
1. **Fixed Simulation Tick (`update(dt)`):** Advance all game rules, physics, collisions, and AI in discrete fixed steps (for example, `FIXED_DT = 1 / 60` seconds = `16.6667 ms`).
2. **Clamped Frame Accumulator:** Clamp incoming frame deltas (for example, `Math.min(frameDelta, 0.25)`) before accumulating so background tab pauses never trigger a spiral-of-death freeze.
3. **Pure Render Pass (`render(alpha)`):** Rendering reads world state and interpolates visual positions using `alpha = accumulator / FIXED_DT`. Rendering must never mutate simulation state, decrement timers, or resolve collisions.
4. **Headless Step Seam (`stepTick(state, input)`):** Expose the fixed tick function (and alias `globalThis.__stepTick = globalThis.stepTick = stepTick` in browser/single-file HTML builds) so tests can run 1,000+ ticks synchronously in milliseconds without a browser, DOM, or GPU context.
5. **Input Buffering & Forgiveness Windows:** Latch transient player actions (jump, dodge, attack, parry) inside fixed-duration tick buffers (for example, `5–7` ticks of jump coyote time and `4–6` ticks of pre-land input buffering) consumed inside `readInput` / `stepTick` rather than sampling raw key-down edges inside `render()`. Never allow variable frame rate spikes to drop buffered actions or grant double triggers.

### Architectural Seam Carve-Out (Efficiency Ladder Rung 7)
Single-call-site phase functions inside the hot loop (`readInput`, `stepPhysics`, `resolveCollisions`, `evaluateAi`, `stepCombat`, `renderWorld`, `renderHud`) are **architectural verification seams**, not speculative abstraction bloat. Do **not** inline them into a monolithic 800-line `tick()` function under `~/.gemini/config/skills/harness/SKILL.md` Efficiency Ladder Rung 7.

---

## 2. Hot-Path Memory & Frame-Budget Discipline (`16.6 ms` at 60 FPS)

Inside `update(dt)`, `render(alpha)`, and collision broad/narrow phases:

* **Zero Per-Frame Heap Allocation:** Do not allocate new arrays (`.map()`, `.filter()`, spread `[...entities]`), temporary vector objects (`new Vec2()`), closures, or DOM nodes inside per-frame loops. Mutate pre-allocated scratch vectors or iterate index-based over contiguous arrays/typed buffers.
* **Object Pooling for Transient Entities:** Projectiles, particles, floating damage numbers, and hit sparks must use fixed-capacity ring buffers or object pools (`acquire()` / `release()`), never per-shot instantiation and garbage collection.
* **DOM vs. Canvas Boundary (Profile A) & GPU/Native Disposal (Profile B):** Under Profile A, keep 60 Hz visual updates inside `<canvas>` / WebGL layers and bridge to DOM HUD overlays only on discrete state transitions (score change, inventory toggle, wave clear, game over). Under both profiles—especially Profile B (`WebGL`/`WebGPU` buffers, shaders, textures, native scenes, or audio voices)—keep total frame compute + draw submission within the `16.67 ms` (`60 FPS`) frame budget, explicitly release/dispose allocated GPU, physics, and audio resources on level unload or entity pool teardown, cap active shaders/render passes, and maintain Profile B text/UI legibility floors (`>= 4.5:1` contrast, `>= 14px` UI baseline).
* **Asset Preload & Initialization Gate:** Never block mid-gameplay ticks on lazy image/mesh decoding or audio fetching. Preload, decode, and verify all external assets in an explicit loading state before transitioning into the active play loop, exposing a bounded retry path (`<= 3` decode/fetch retries before entering an explicit terminal error state).

---

## 3. Entity State Machines & Mistake-Proofing (`~/.gemini/config/skills/harness/references/mistake-proofing.md`)

Boolean flag soup (`isGrounded`, `isDashing`, `isAttacking`, `isStunned`, `isDead`) creates $2^N$ implicit states where illegal combinations (attacking while dead, dashing while stunned) inevitably occur.

* **Discriminated State Unions:** Represent entity lifecycle and action states as explicit closed unions or state tables (`type ActorState = { kind: "idle" } | { kind: "dash"; remainingTicks: number } | { kind: "stunned"; recoveryTicks: number } | { kind: "dead" }`).
* **Exhaustive Transition Table:** Centralize state transitions in a single pure transition function (`transitionActor(state, event)`). Every state transition must explicitly define which events are legal and which are ignored.
* **Branded Coordinate & Unit Types:** When mixing coordinate spaces, distinguish `WorldPos`, `ScreenPos`, and `TileCoord` (or `Seconds` vs. `Ticks`) so passing tile indices into pixel-space collision functions is prevented or immediately announced.

---

## 4. Seeded Determinism & Economy Balance

Unseeded `Math.random()` makes procedural maps, loot drops, and enemy spawns impossible to reproduce when a bug occurs on tick 4,200.

* **Explicit Seeded PRNG:** Route all gameplay randomness (map generation, spawn tables, critical hit rolls, AI tie-breaking) through an explicit seeded pseudo-random number generator (`mulberry32`, `sfc32`, or `PCG`) stored in the simulation state (`state.rngSeed`).
* **Reproducible Replay & Save Schema Contract:** Given `(initialSeed, frameInputLog)`, running `stepTick` for $N$ ticks must produce bit-identical entity states, scores, and health values across runs. Persist every saved game or replay payload with an explicit integer `schemaVersion` field plus a deterministic migration or explicit corrupt/incompatible quarantine handler (rotating corrupted files non-destructively to `.corrupt.<timestamp>` before resetting or surface-prompting recovery) before deserializing into world state.
* **Closed-Form Economy Bounds:** Express damage, XP curves, wave scaling, and resource costs as named table constants or pure functions (`xpForLevel(level)`, `enemyHpForWave(wave)`), never magic numbers buried inside collision branches.

---

## 5. Game Feel ("Juice") & `MODE: GAME & INTERACTIVE` Vitality

A mechanically working game still feels like AI programmer art if inputs have no physical weight and the HUD looks like a SaaS dashboard. Apply `DESIGN.md` §2.1 (`MODE: GAME & INTERACTIVE`), `~/.gemini/config/skills/ui-refinery/SKILL.md` (`Game & Interactive Canvas Vitality`), and the following rules:

1. **Viewport Budget (`>= 85%` Canvas):** The interactive playfield owns at least 85% of the viewport. Never wrap a `<canvas>` inside a padded marketing page with a 3-card feature grid below it unless explicitly requested.
2. **Diegetic HUD Over SaaS Cards:** Anchor HUD indicators (health, ammo, score, minimap, cooldowns) to screen edges (`8px–16px` safe inset) using translucent dark plates (`var(--surface-hud-scrim)`, defined as `--surface-hud-scrim: rgba(10, 14, 23, 0.78)` in `DESIGN.md` §3), crisp `1px` specular borders, or angled/chamfered bars. Never use white SaaS `.card` boxes or `Inter` admin tables over the playfield.
3. **Cohesive Palette Over Raw Primaries (`UI-4`):** Never render entities or bars with uncalibrated RGB/CMY hex primaries (`#FF0000`, `#00FF00`, `#0000FF`, `#FFFF00`, `#FF00FF`, `#00FFFF`). Define a cohesive 5–7 color world palette (background depth layers, player focal hue, hazard hue, collectible hue, neutral structure) with distinct luminance AND shape silhouettes so colorblind players can read every threat by silhouette alone.
4. **Input Feedback Triad:** Every primary player action (jump, fire, hit, dash, collect, take damage) must trigger at least **two** synchronous feedback channels:
   * **Visual:** `80ms–140ms` transform/squash-stretch tween, 2–4 frame hit-flash, directional knockback impulse, or pooled particle burst.
   * **Spatial / Camera:** Decaying trauma-based screen shake (bounded amplitude, immediately disabled when `prefers-reduced-motion: reduce` is active) or brief hit-stop (`2–4` simulation freeze frames on heavy impact).
   * **Audio / Tactile Cue & External Asset Co-Load:** Synthesized WebAudio procedural SFX (`OscillatorNode` / noise burst envelope with a visible mute button) suffices for inline prototypes; whenever the game ships external audio clips, looping music stems, spritesheets, pixel art, textures, or cutscenes, **co-load** `~/.gemini/config/skills/media-studio/SKILL.md` and pass `media_qc.py` (`--game-sfx`, `--ogg-codec vorbis|opus`, `--check-loop`, `--pixel-art`, `--sprite-atlas`) before delivery.

---

## 6. Headless Verification & Delivery Gate

Before declaring any game or interactive simulation task complete, run all four verification checks:

1. **Headless Tick Invariant Test (`1,000+` Ticks):** Write and run a unit/simulation test that steps the headless loop for at least `1,000` ticks across seeded scenarios (`idle`, `continuous movement`, `combat/collision saturation`, `boundary edges`) and asserts:
   * Zero `NaN` or `Infinity` values in any entity position, velocity, health, or score field.
   * All bounded entities remain within legal world/arena bounds (no collision tunneling out of bounds).
   * Deterministic replay: running the same seed and input sequence twice yields identical state snapshots.
   * Pool/entity cap holds: active entity count never exceeds the configured pool ceiling.
2. **State Machine Transition Coverage:** Verify every legal transition and confirm illegal transitions (for example, moving or attacking while in `"dead"` or `"gameover"` state) are rejected.
3. **Structural UI Slop Gate (`check_ui_slop.py` — Profile A / Web Overlays Only):** For HTML/JSX/TSX/CSS game builds and DOM overlays, run the deterministic UI slop scanner in game mode (native C#/GDScript/C++/Rust engine projects without web markup skip this step):
   ```bash
   plumb-guard ui-slop <paths> --mode game
   # Or from installed global config:
   python3 ~/.gemini/config/skills/ui-refinery/scripts/check_ui_slop.py <paths> --mode game
   ```
   Zero `UI-1`–`UI-5` findings are permitted on delivery.
4. **Type, Lint, Asset QC & Test Suite:** Pass the project's standard typecheck, lint, `media_qc.py` external asset checks (when applicable), and unit/headless simulation test gates with zero errors (`~/.gemini/config/skills/harness/SKILL.md` §3B).
   * **Single-File Prototype Mode (`vibecoder`) Carve-Out:** When building a single-file HTML game prototype under `~/.gemini/config/skills/vibecoder/SKILL.md`, execute the `1,000+` tick invariant and state-transition checks via an ephemeral CLI one-liner or `<appDataDir>/brain/<conversation-id>/scratch/` probe against `globalThis.__stepTick` / `globalThis.stepTick` and run `check_ui_slop.py --mode game` without creating persisted unit test files or requiring multi-file `harness` §3B test suites.

---

## 7. Clean-Room Reference Extraction (`rea` Bridge) & Brownfield Modification Workflow

* **Clean-Room Behavior & Timing Reference (`reverse-engineer-anything` / `rea_rea`):** When analyzing an existing game binary, packaged archive (`.apk`, `.asar`, `.pak`, WebAssembly/JavaScript bundle), or binary save format to reconstruct deterministic mechanics or inspect timing/UI behavior, **co-load** `reverse-engineer-anything` (routing shipped artifact analysis through the `rea_rea` Model Context Protocol (`MCP`) tools such as `open_binary`, `inspect_artifact`, `analyze_javascript_application`, or `inspect_wasm_artifact`) strictly for **clean-room behavioral specification**, never copyright-protected asset redistribution. Pair extracted or recreated external game assets with `~/.gemini/config/skills/media-studio/SKILL.md` (`media_qc.py`).
* **Brownfield Game Modification Triage (`GEMINI.md` Rule 18 Surgical Scope):** Do not apply greenfield templates or rewrite whole scenes in an existing game repository. Route brownfield tasks cleanly by signal:
  * **Broken physics, state desync, softlock, or crash** -> `~/.gemini/config/skills/diagnosing-bugs/SKILL.md` (capture a deterministic `(initialSeed, frameInputLog)` reproducer first).
  * **Frame-time spikes, Garbage Collection (`GC`) stalls, shader/draw-call overhead, asset bundle bloat, or multiplayer netcode latency in a working game** -> `~/.gemini/config/skills/sweetspot/SKILL.md` (`--time`, `--memory`, `--disk`, `--net` with real frame/heap benchmarks).
  * **15+ year obsolete runtime/Flash/encoding revival or full cross-engine remake** -> `~/.gemini/config/skills/renew/SKILL.md` paired with `game-engineering` (`renew` classic-game rules).
