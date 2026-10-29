---
name: renew
description: >-
  Generational legacy software and classic game modernization, platform/runtime porting, and unbuildable codebase
  revival while preserving domain behavior, historical file/save compatibility, and simulation feel. Enforces a 5-stage
  Silent Autopsy -> Renewal Contract -> Golden Master or Equivalence Ledger -> Layered Strangler Cutover & Security
  Sanitization -> Parity Gate pipeline. Invoke with /renew or when modernizing, porting, remastering, or reviving legacy
  programs, dead UI toolkits, obsolete encodings, or classic games ("eski programı yenile", "eski oyunu yenile",
  "eski yazılımı modernize et", "güncel sisteme taşı", "oyunu remaster yap", "port legacy app"). Not for routine
  single-package version bumps on an active stack (use 'dependency-upgrade'), internal code cleanup with zero
  runtime/platform or contract shift (use 'refactoring'), resource optimization on an already-working stack (use
  'sweetspot'), promoting a recent single-file discovery prototype into production (use 'marathon' + 'harness'),
  migrating/bridging active C, C++, Go, or Python code into Rust (use 'rustify'), or porting AI agent rules across IDEs
  (use 'porter').
---

# Renew — Legacy Software & Classic Game Modernization Discipline

Treating a 15-year-old unbuildable application or classic game like a greenfield rewrite discards undocumented domain edge cases, breaks existing user files or save states, and alters physics timing—while treating it like a pure in-place refactor fails when the original compiler, toolkit, or operating-system layer no longer runs. `renew` bridges the exact generational gap where `skills/dependency-upgrade/SKILL.md` halts ("migration rewrite rather than a version bump") and where `skills/refactoring/SKILL.md` cannot start because the host runtime, encoding, or user interface layer must intentionally evolve.

---

## 1. Adjacent-Skill Boundaries & Co-Loading Map

* **vs. `skills/dependency-upgrade/SKILL.md`:** Use `dependency-upgrade` when bumping packages or sequential runtime versions on an already-building stack. Switch to `renew` when `dependency-upgrade` §2 hits a generational rewrite boundary, dead UI toolkit (Flash, Visual Basic 6, legacy Win32/MFC, WinForms, Python 2 Tkinter, SDL1, jQuery 1.x, Java Applets), or obsolete language dialect.
* **vs. `skills/refactoring/SKILL.md` & `skills/sweetspot/SKILL.md`:** Use `refactoring` for internal structure cleanup and `sweetspot` for speed, memory, disk, or network optimization when code already runs on an active stack with zero runtime/platform or public-contract shift. Use `renew` when reviving dead build toolchains, migrating character encodings (`Windows-1254` / `ISO-8859-9` / `CP437` -> `UTF-8`), porting across languages/platforms, or replacing obsolete interfaces while pinning core domain rules.
* **vs. `skills/vibecoder/SKILL.md`:** Single-file rapid discovery prototypes (`vibecoder`) promote to production via `skills/marathon/SKILL.md` + `skills/harness/SKILL.md` §6 rather than `renew`.
* **vs. `skills/rustify/SKILL.md` (Handoff vs. Co-Load):** Direct C, C++, Go, or Python -> Rust migrations and Foreign Function Interface (`FFI`) bridges on active codebases follow `skills/rustify/SKILL.md`. When reviving an obsolete or unbuildable legacy application or classic game into a Rust target stack, co-load `renew` with `rustify`: combine both Stage 1 autopsies and a single merged Stage 2 contract gate (`<= 4` questions), pin once in Stage 3, apply `renew` Stage 4.2 legacy vulnerability sanitization (plus Section 6 for classic games) alongside `rustify` Stage 4 Application Binary Interface (`ABI`) and `unsafe` purification rules, and pass both Stage 5 gates.
* **Co-Loaded Capabilities When Applicable:**
  * *Missing or compiled-only source (`.exe`, `.dll`, `.swf`, `.jar`, `.apk`):* Use `reverse-engineer-anything` (`rea_rea` MCP server when available) to extract decompiled procedures and a reconstruction obligation ledger before coding.
  * *Classic games & real-time simulations:* Co-load `skills/game-engineering/SKILL.md` and `DESIGN.md` (`MODE: GAME & INTERACTIVE`) alongside Section 6 below.
  * *Legacy database schemas & character-set migrations:* Co-load `skills/database-migrations/SKILL.md`.
  * *Corrupt or obsolete embedded audio, video, or bitmap assets:* Co-load `skills/media-studio/SKILL.md`.
  * *Multi-window (`>8` files) legacy overhauls:* Partition execution via `skills/marathon/SKILL.md` (`W1: Autopsy, Oracle & Core Domain`, `W2: Platform/Interface Cutover`, `W3: Parity & Security Audit`) and record stack/compatibility trade-offs via `skills/architecture-decision-records/SKILL.md`.

---

## 2. Stage 1 — Silent Archaeology & Codebase Autopsy (Before Asking Any Question)

Never ask the user technical facts that the repository or shipped binary already answers (`skills/deep-grill/SKILL.md` §3). Perform a **static safety pre-check first** (`read_file` on `Makefile`, `configure`, `setup.py`, `.bat`/`.sh`, and entrypoints per `GEMINI.md` Rule 12: never execute legacy build scripts or binaries that fetch unpinned remote code or mutate host paths outside a disposable temporary directory) to assemble a concise **Legacy Autopsy Snapshot**:

1. **Runtime, Build & Operating-System Coupling:** Language standard/version, 16/32-bit word-size or pointer assumptions, case-insensitive or hardcoded filesystem paths (`C:\...`, `/usr/local/...`), registry or OS-specific system calls, and dead UI/plugin dependencies.
2. **Data, Encoding & Wire Formats:** Legacy single-byte encodings (`Windows-1254`, `ISO-8859-9`, `Latin-1`, `CP437`), binary struct endianness/packing, `.ini`/XML/SQLite schemas, CLI flags, and custom project or save-file formats.
3. **Oracle Executability State:**
   * *State A (Runs Locally in Temp Sandbox):* Builds or executes cleanly against a disposable temporary directory with zero unpinned fetches or host mutations.
   * *State B (Isolated Oracle):* Executes inside an available local interpreter, emulator, or container confined to a temporary working directory.
   * *State C (Static / Binary Oracle Only):* Cannot execute safely on modern hosts; truth is extracted statically from source `file:line` (or `reverse-engineer-anything` binary analysis).
   * *State D (Incomplete / Unrecoverable Oracle):* Missing source modules, stripped/packed binaries without symbol recovery, or external server/stored-procedure logic leaves domain rules unprovable. Log every unprovable rule as `[ORACLE GAP]` and halt in `BLOCKED` status until the user supplies sample I/O fixtures or approves an explicit specification rule in Stage 2.
4. **Legacy Security & Reliability Hazards:** Unparameterized SQL or shell string concatenation, unchecked buffer/path operations, broken cryptography (`MD5`, `SHA-1`, custom XOR ciphers), swallowed error codes, and hardcoded credentials (`GEMINI.md` Rule 12).

---

## 3. Stage 2 — The Renewal Contract Gate (`ask_question`, Max 3–4 Decisions)

Legacy code proves *what the old program did*, never *how conservative or transformative the user wants the modernized version to be*. Unless the user's prompt already specifies every axis below, ask **at most 3–4 pointed questions** one at a time via `ask_question` (or a single numbered plain-text list of `<= 4` questions with `(Recommended)` defaults when `ask_question` is unavailable in headless/subagent contexts) derived from the Stage 1 autopsy:

1. **Fidelity Tier (Modernization Depth):**
   * *Tier A — Compatibility Revival:* Keep the original language, architecture, and interface; update only broken build/OS seams, `UTF-8` handling, and security hazards so it runs cleanly today.
   * *Tier B — Faithful Modernization / Remaster (Recommended when the legacy UI or runtime is dead):* Preserve 100% of core domain formulas, workflows, and file/save formats while replacing dead frameworks or UI toolkits with modern equivalents and adding non-breaking ergonomics (high-DPI layout, keyboard accessibility, dark/light theme).
   * *Tier C — Generational Reimagining:* Extract core domain rules and rebuild workflows and architecture cleanly for modern usage, retiring obsolete historical workarounds.
2. **Target Runtime & Stack:** Present 2–3 concrete target stacks grounded in the codebase (for example, modernizing within the native language ecosystem vs. porting to a modern cross-platform desktop or web stack).
3. **Backward Data Compatibility & Legacy Bug Policy:** Confirm whether existing config, database, project, or save files must open directly (or via a non-destructive import/migration tool), and whether obvious historical bugs discovered in Stage 1 should be fixed or gated behind a compatibility flag for external callers.
4. **Game Feel & Viewport Policy *(ask only when the target is a game or simulation)*:** Confirm whether to lock original aspect ratio and simulation mechanics strictly or enable widescreen framing and opt-in Quality-of-Life (`QoL`) controls (input remapping, gamepad support, autosave alongside classic saves).

Lock the confirmed choices into `AC-1..N` acceptance criteria (`skills/harness/SKILL.md` §4.E) before editing production files. Adopt `(Recommended)` defaults labeled `[USER-DELEGATED DEFAULT]` only when the user explicitly delegates selection; if backward-compatibility or `[ORACLE GAP]` questions are skipped without delegation, remain `BLOCKED` rather than guessing.

---

## 4. Stage 3 — Behavior Pinning (Golden Master vs. Equivalence Ledger)

Partition pinned behavior explicitly into **Preserved Parity Suites** (unchanged domain behavior) versus **Authorized Sanitization & Bug-Fix Transitions** (approved in Stage 2.3 and Stage 4.2):

1. **Runnable Oracle (`State A` or `State B`):** Capture deterministic input -> output characterization fixtures from the untouched legacy program (CLI arguments/stdout/exit codes, sample legacy input files -> parsed/exported outputs, edge-case rounding, Turkish/non-ASCII locale strings, or seeded game tick traces) inside a disposable temporary directory and wrap them as public-seam tests (`skills/refactoring/SKILL.md` §3 & `skills/test-design/SKILL.md`).
2. **Unrunnable Source or Binary Oracle (`State C`):** Write a structured **Behavior & Format Equivalence Ledger** (in `scratch/equivalence_ledger.md` or the plan artifact) mapping every domain formula, state transition, boundary constant, character-encoding conversion, and binary byte offset/endianness rule to its exact `legacy_file:line` (or decompiled symbol address). Convert each ledger row into an executable failing seam test before implementing the target module (Red -> Green).
3. **Immutable Test & Cross-Language Retirement Discipline (`GEMINI.md` Rule 9):** Never weaken or silently delete existing legacy tests. Record approved bug-fix/security behavior shifts and cross-language test transitions under `## Authorized Test Modifications` in `tasks.md` (`[Legacy Test Transition Request]`), and keep superseded legacy test files on disk until replacement public-seam tests are green and the human operator seals a fresh `agy-guard test-boundary snapshot`.

---

## 5. Stage 4 — Layered Strangler Cutover & Security Sanitization

Execute modernization in narrow vertical slices (`<= 3` tightly coupled production files or `1` domain workflow per planned forward Strangler slice — an explicit `GEMINI.md` Rule 13 forward-slice carve-out, while unverified bug-fix retry loops after a failing gate remain strictly capped at `GEMINI.md` Rule 13's `max(1 file, ~10%)`) rather than a single unverified rewrite:

1. **Pure Domain & Legacy Format Adapter First:** Implement calculation logic, explicit state unions (`skills/mistake-proofing/SKILL.md`), strict fail-fast character-encoding bridges (decoding legacy `Windows-1254` / `ISO-8859-9` / `CP437` inputs into internal `UTF-8` with explicit error reporting rather than silent `U+FFFD` replacement corruption, or `surrogateescape` when round-tripping raw binary-embedded strings, and never overwriting user files in place), and legacy file/save parsers with zero UI framework dependencies. Prove green against Stage 3 Preserved Parity Suites first.
2. **Mandatory Security & Resilience Sanitization (Never Port Vulnerabilities as "Fidelity"):**
   * Replace string-concatenated SQL/shell commands with parameterized queries and argument-array `subprocess` execution (`shell=False`).
   * Canonicalize and bounds-check untrusted paths and binary struct lengths read from legacy files so malformed archival inputs raise explicit parse errors instead of crashing or traversing directories.
   * Replace broken cryptographic primitives (`MD5`, `SHA-1`, `DES`, custom obfuscation) with modern standards; if legacy encrypted/hashed records must still be read, isolate the legacy algorithm strictly inside a read-only import/upgrade verifier that re-persists in the modern format.
3. **Modern Interface & Platform Binding:** For **Tier B** and **Tier C** modernizations, attach the target CLI, desktop, or web shell last, conforming to `DESIGN.md` and `skills/antislop/SKILL.md` (`check_ui_slop.py`) so modernized interfaces gain genuine domain clarity rather than generic SaaS card-grid templates. Under **Tier A (Compatibility Revival)**, preserve the original interface and authentic hardware palette without forced restyling.

---

## 6. Legacy Game & Interactive Simulation Profile (Co-load `skills/game-engineering/SKILL.md`)

When renewing, porting, or remastering a classic game (DOS, Win32, Flash/ActionScript, Java/J2ME, SDL1, Python 2 Pygame, or early browser Canvas):

1. **Preserve Original Simulation Cadence (`FIXED_DT`):** Extract the legacy loop's exact simulation tick frequency (such as `30 Hz`, `35 Hz`, `60 Hz`, or `70 Hz`) and advance physics, gravity, cooldowns, and AI strictly at that fixed `FIXED_DT` while decoupling high-refresh rendering via `render(alpha)` interpolation (`skills/game-engineering/SKILL.md` §1). Never replace frame-counted legacy timers with raw variable `requestAnimationFrame` deltas, which accelerate gameplay or alter jump heights on `120–240 Hz` monitors.
2. **Pixel Aspect Ratio & Camera Boundary Fidelity:** Honor non-square CRT pixel geometry (for example `320x200` `4:3` displays requiring a `6:5` (`1.2x`) vertical pixel stretch, Sample Aspect Ratio `5:6`) and crisp integer or texel-snapped scaling (`image-rendering: pixelated`) rather than blurry bilinear stretching. Do not widen the gameplay camera from `4:3` to `16:9` when level spawn triggers, tile culling, or boss arenas assume fixed screen edges; on widescreen monitors, the outer game stage (active `4:3` playfield plus clean pillarbox or diegetic bezel) satisfies `skills/game-engineering/SKILL.md` §5's `>= 85%` viewport budget without stretching the inner `4:3` camera.
3. **Non-Destructive Legacy Asset & Audio Revival:** Convert color-keyed bitmaps (such as `#FF00FF` magenta transparency palettes), low-sample-rate PCM clips with DC offset/clicks, and obsolete cutscene codecs non-destructively via `skills/media-studio/SKILL.md` (`media_qc.py salvage` / `master-audio` / `check`), and honor `prefers-reduced-motion: reduce` on camera shake and flash effects.
4. **Headless Replay & UI Slop Gate:** Expose `stepTick(state, input)` with an explicit seeded PRNG (`skills/game-engineering/SKILL.md` §4 & §6) and execute a `1,000+` tick headless deterministic simulation test requiring zero `NaN`/`Infinity` state values and identical end-state hashes across `>= 2` identically seeded runs (plus `<= 1e-6` oracle state delta when a `State A`/`B` reference trace exists). Run `check_ui_slop.py --mode game` on newly authored Tier B/C HUDs (documenting a Tier A hardware-palette carve-out when preserving original 16-color/EGA/VGA palettes).

---

## 7. Stage 5 — Parity Verification & Delivery Gate

Require `100%` pass across all Preserved Parity Suites (`<= 1e-6` tolerance permitted solely on documented cross-architecture floating-point operations); if any preserved parity case fails after 3 fix rounds (`GEMINI.md` Rule 13), halt in `BLOCKED` status rather than relaxing assertions. Before declaring completion, run the full `skills/harness/SKILL.md` §3B verification pipeline (plus `contract-change-auditor`, `test-adequacy-auditor`, `security-boundary-verifier`, and `silent-failure-hunter` when legacy file contracts, security boundaries, or >8 files are touched). In the `GEMINI.md` Rule 5/8 Delivery Block, report: the Stage 1 Autopsy -> Target parity summary, exact Preserved Parity and Sanitization Transition test counts, legacy file/save compatibility status, legacy security hazards eliminated during porting, and any hardware/OS peripherals or `[ORACLE GAP]` paths that could not be verified locally.
