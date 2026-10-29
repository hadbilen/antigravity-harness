# Architecture Decision Record 0003: Canonical `rustify` Skill Package with On-Demand Interop References and C/C++/Rust `code_map.py` Indexing

**Date**: 2026-10-24
**Status**: accepted
**Deciders**: Human Operator (hadbilen), Antigravity Primary Engineering Session

## Context

An external single-file `rustify` Markdown draft was evaluated via `porter.py inspect` (`100/100` constitutional score, `90/100` ecosystem adaptability) to fill a gap in the 33-skill catalog: migrating active C, C++, Go, or Python modules into idiomatic, memory-safe Rust. While `skills/renew/SKILL.md` governs generational revival of obsolete or unbuildable applications and `skills/refactoring/SKILL.md` governs intra-language behavior-preserving restructuring, neither defines Rust ownership and lifetime redesign or Foreign Function Interface (`FFI`) safety. They also omit Application Binary Interface (`ABI`) layout preservation (`#[repr(C)]`), C unsigned-wrapping vs. signed-overflow semantics, two-stage `unsafe` purification, and Rust verification ladders (`clippy`, `miri`, C/Rust sanitizers, and `cargo kani`).

In addition, inspecting `scripts/code_map.py` revealed two mechanical gaps affecting C/C++ -> Rust migrations:
1. `CODE_EXTENSIONS` and `_index_non_python_file` omitted C/C++ source/header extensions (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx`) and C-style typed function definitions.
2. `_COMMENT_STRING_RE` matched `'...'` across multi-character spans on non-Python files, causing Rust lifetime annotations (`<'a>`, `&'a [u8]`, `&'static str`) to erase intermediate Rust functions and call sites from the structural index.

## Decision

1. **Create `skills/rustify/` as a canonical 3-file skill package (`34` skills total):**
   - `skills/rustify/SKILL.md` holds the core 5-stage workflow (`Silent Build & Layout Autopsy -> Migration Contract via ask_question -> Behavior Pinning & Leaf-to-Root Decomposition -> Two-Stage Unsafe Purification & 6 Red Lines -> 3-Tier Verification Ladder`), explicit negative frontmatter boundaries (`Pass 7`), `GEMINI.md` Rule 9 cross-language test retirement rules (`[Legacy Test Transition Request]` plus human-sealed `agy-guard test-boundary snapshot`), and Tier-3 auditor dispatch rules.
   - `skills/rustify/references/c-cpp-abi-and-embedded.md` holds on-demand C/C++ layout (`#[repr(C)]`, bitfields, foreign enum safety), integer promotion/wrapping, `Send`/`Sync` foreign-handle classification, `bindgen`/`cbindgen` (C `ABI`) vs. `cxx` (C++ bridge) selection rules, `#![no_std]` / `volatile` / interrupt safety, and CMake/Cargo co-build sanitizer gates.
   - `skills/rustify/references/managed-go-python.md` holds on-demand Go (`tokio::task::JoinSet`/`rayon`, bounded channels, `cgo` pointer rules) and Python (`PyO3` + `maturin`, Global Interpreter Lock (`GIL`) release, signal polling, and `1`-to-`1` exception mapping) migration rules so C/C++ tasks incur zero managed-language context overhead while avoiding future skill proliferation.
2. **Adopt a sensor-aware 3-tier Rust verification ladder (including conditional `cargo kani`, excluding `Prusti`):** Enforce `cargo check`, strict `cargo clippy` (with `safety-critical` panic bans scoped to `--lib --bins`), and differential `cargo test` universally; require `cargo +nightly miri test` on pure-Rust `unsafe` and AddressSanitizer/UndefinedBehaviorSanitizer on mixed C/Rust `FFI` binaries; run `cargo kani` bounded proofs on `safety-critical` targets when installed (halting in `BLOCKED` status under `GEMINI.md` Rule 8 when mandatory sensors on critical `unsafe` or `safety-critical` seams cannot run locally) while excluding `Prusti` due to pinned legacy nightly/Viper fragility.
3. **Wire ecosystem seams and harden `scripts/code_map.py` with linear `O(N)` lexers:** Register bilingual path-safe `rustify` triggers in `guard/agy_hooks.py` (`SKILL_HINTS` and `_DISTINCTIVE_SKILL_SLUGS`), add native `cargo` pipeline commands and `rustify` routing to `skills/harness/SKILL.md`, define `renew` + `rustify` co-loading in `skills/renew/SKILL.md`, emit all Rust and C/C++ globs in `porter/emitters/cursor.py`, and extend `scripts/code_map.py` with single-pass `O(N)` C/C++ and Rust scrubbers and brace-aware indexers.

## Alternatives Considered

### Alternative 1: Import the External Single-File Draft Verbatim
- **Pros**: Zero authoring effort beyond `porter.py import`.
- **Cons**: Fails `meta_audit.py --strict` Pass 7 (missing negative trigger boundary and `SKILL_HINTS` registration), omits `GEMINI.md` Rule 9 legacy-test preservation, and uses a non-functional configuration snippet instead of `ask_question`. It also misses critical C/C++ `ABI` and `FFI` hazards (`#[repr(C)]` field reordering, bitfields, bidirectional unwinding, C unsigned modular wrapping vs. checked math, non-UTF-8 `CStr` inputs, and mixed-binary sanitizer limits where `miri` halts at external C calls).
- **Why not**: Rejected because mechanical self-audit compliance and C/C++ binary/memory soundness are non-negotiable invariants.

### Alternative 2: Restrict `rustify` Strictly to C/C++ and Drop Go/Python Coverage
- **Pros**: Slightly narrower frontmatter scope.
- **Cons**: Forces either ad-hoc unguided rewrites or creation of a second `rustify-python`/`pyo3` skill whenever hot Python/Go components are ported to Rust, violating the Efficiency Ladder (`GEMINI.md` Rule 18).
- **Why not**: Moving Go/Python matrices into `references/managed-go-python.md` achieves zero token cost during C/C++ work while keeping all Rust target-language migrations under one coherent skill owner.

### Alternative 3: Fold Rust Migration Rules into `renew` or `refactoring`
- **Pros**: Keeps the skill count at `33`.
- **Cons**: `refactoring` prohibits cross-language rewrites and platform shifts, while `renew` targets dead toolchains and generational application/game revival rather than active C/C++ `FFI` strangler bridges, `#![no_std]` embedded firmware, or `PyO3` extensions.
- **Why not**: Rejected to keep `refactoring` and `renew` sharp, using explicit co-loading (`renew` + `rustify`) only when an unbuildable legacy application is simultaneously revived into Rust.

## Consequences

### Positive
- Provides a complete, mechanically audited C/C++ (and on-demand Go/Python) -> Rust engineering workflow integrated with `harness`, `renew`, `mistake-proofing`, `sweetspot`, and all 7 read-only governance/security auditors.
- Upgrades `skills/harness/SKILL.md` with first-class `cargo check` / `cargo clippy` / `cargo test` pipeline gates for every Rust repository.
- Eliminates C/C++ file blindness, `#ifdef` / C++11 brace-initializer scope drift, and Rust `'lifetime` code-erasure bugs in `scripts/code_map.py`.

### Negative
- Increases the canonical skill count from `33` to `34`, requiring synchronized updates to `README.md`, `CHANGELOG.md`, and `.harness/manifest.json`.

### Risks
- **Risk**: Generic Rust prompts (`"fix borrow checker error in main.rs"`, `"bump pyo3 in Cargo.toml"`, `"migrate crate to Rust edition 2024"`, `"rewrite this unsafe helper into safe Rust"`) or file paths (`src/rustify/lib.rs`, `rustify.rs`) could false-trigger `rustify`.
  **Mitigation**: Anchor `SKILL_HINTS` strictly on `/rustify`, explicit cross-language migration phrases (`to/into Rust` excluding edition/version upgrades and intra-Rust `unsafe` helpers, `Rust'a çevir/taşı/dönüştür`), and version-bump-guarded `FFI` bridge tool names (`cbindgen`, `cxx::bridge`, `PyO3`), verified with positive and negative seam tests in `tests/test_rustify_and_codemap.py`.
- **Risk**: Single-quote lexing changes for `.rs` and C/C++ files in `scripts/code_map.py` could affect single-quoted string stripping in JavaScript and TypeScript files (`'hello world'`).
  **Mitigation**: Route `.rs` and C/C++ files through dedicated linear `O(N)` single-pass scrubbers (`_scrub_rust_source` and `_scrub_c_cpp_source`), keeping `_COMMENT_STRING_RE` completely untouched for `.js`/`.jsx`/`.ts`/`.tsx`/`.go`.
