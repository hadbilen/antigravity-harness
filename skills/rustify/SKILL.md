---
name: rustify
description: >-
  Architectural migration, porting, and FFI bridging (`cbindgen`, `cxx`, `PyO3`, `napi-rs`) of C, C++, Go, Python,
  TS/JS, Ruby, or Java into memory-safe, compiler-verified Rust (`rustc`, `clippy`, `miri`, sanitizers). Invoke with
  /rustify or on "rust'a çevir", "rust'a taşı", "c/c++'dan rust'a". Not for intra-Rust hardening (use 'rust-harden' or
  'refactoring'), Rust tuning (use 'sweetspot'), Cargo bumps (use 'harness' dependency-upgrade), or non-Rust legacy
  revival (use 'renew').
---

# Rustify: Architectural Migration & Memory-Safe Interop Discipline

Translating source files line-by-line from C, C++, Go, Python, TypeScript/JavaScript, Ruby, or Java/Kotlin into Rust produces "source-language code in Rust syntax": ubiquitous `Arc<Mutex<T>>` wrappers, raw `*mut T` pointer arithmetic, `.unwrap()` panic landmines, silent `as` integer truncations, FFI marshaling regressions, and broken Application Binary Interface (`ABI`) layouts. `rustify` governs cross-language transformation so ownership, lifetimes, semantic parity, binary layout invariants, and zero-panic guarantees are locked in incrementally with compiler and runtime proof.

---

## 1. Adjacent-Skill Boundaries & Co-Loading Map

* **vs. `~/.gemini/config/skills/rust-harden/SKILL.md`, `~/.gemini/config/skills/refactoring/SKILL.md` & `~/.gemini/config/skills/sweetspot/SKILL.md`:** `rustify` governs cross-language porting and Foreign Function Interface (`FFI`) bridges from C, C++, Go, Python, TypeScript/JavaScript, Ruby, or Java/Kotlin into Rust. Once a crate is already in Rust, use `rust-harden` (`--internal`, `--contract`, or `--greenfield`) to eliminate intra-Rust `.clone()` / `Arc<Mutex<T>>` ownership debt, remove production `.unwrap()` / `.expect()` panics, harden `tokio::select!` cancellation, POSIX privilege drop, or real-time game loops, scaffold greenfield Rust workspaces, and narrow `#![no_std]` / kernel `unsafe` blocks; use `refactoring` for language-agnostic structural moves with zero contract shift; and use `sweetspot` when profiling/optimizing an already-working Rust crate (`--time`, `--memory`, `--disk`, `--net`). Never mix premature Single Instruction, Multiple Data (`SIMD`) or custom-allocator micro-tuning into the initial cross-language migration pass.
* **Sequential Post-Parity Handoff to `rust-harden` (`Anti-Mixing Sequencing Rule`):** Preserve `~/.gemini/config/skills/harness/references/context-and-artifacts.md` §1's `Anti-Mixing Sequencing Rule`: complete `rustify` Stage 5 differential parity to `100%` green first (and drive strangler-fig fallback to `0%` on whole-app cutovers) before applying intra-Rust hardening or structural redesign. Once parity is green, hand off sequentially to `~/.gemini/config/skills/rust-harden/SKILL.md` (`--internal` by default to keep ported `pub`/ABI/golden-vector contracts intact, or explicitly user-authorized `--contract` for controlled public Rust API tightening) paired with the matching runtime reference (`async-and-userspace.md`, `kernel-and-unsafe.md`, or `game-and-realtime.md`); if a standalone new workspace skeleton is needed for a lifted crate, run `rust-harden --greenfield` (`greenfield-architecture.md`) as a separate sequential pass rather than mixing it into `--internal`/`--contract`.
* **vs. `~/.gemini/config/skills/harness/references/dependency-upgrade.md`:** Use `dependency-upgrade` when bumping crate versions in `Cargo.toml` / `Cargo.lock` or upgrading the Rust toolchain edition (`2021` -> `2024`) within an existing Rust project.
* **vs. `~/.gemini/config/skills/renew/SKILL.md` (Handoff vs. Co-Load):**
  * *Active/buildable C, C++, Go, Python, TS/JS, Ruby, or Java/Kotlin module -> Rust:* Use `rustify` directly.
  * *Obsolete/unbuildable 15+ year legacy software or classic game revived into a Rust target stack:* **Co-load** `~/.gemini/config/skills/renew/SKILL.md` with `rustify`: combine both Stage 1 autopsies and a single merged Stage 2 contract gate (`<= 4` questions), pin once in Stage 3, apply `renew` Stage 4.2 legacy vulnerability sanitization (plus `renew` Section 6 for classic games) alongside `rustify` Stage 4, and pass both Stage 5 gates.
* **On-Demand Reference Modules (Load Only What Matches the Source Language):**
  * *C, C++, `#![no_std]` firmware, hardware registers, or Foreign Function Interface (`FFI`) bridges:* Read [references/c-cpp-abi-and-embedded.md](./references/c-cpp-abi-and-embedded.md).
  * *Go, Python (`PyO3`/`maturin`), TypeScript/JavaScript (`napi-rs`/`wasm`), Ruby, Java/Kotlin bridges, batching (`--batch`/`FnIndex`), semantic traps, oracle noise taxonomy, or strangler-fig whole-app cutover:* Read [references/managed-go-python.md](./references/managed-go-python.md).
* **Co-Loaded Capabilities When Applicable:**
  * *Optional Pinned `rust-anything` CLI / MCP Backend:* For TS/JS, Python, C, Go, Ruby, or Java/Kotlin ports, an existing pinned `rust-anything` (`=2.1.0 --locked`, version-verified) CLI/MCP server may automate Stages 1–5 per [references/managed-go-python.md](./references/managed-go-python.md) §6; when absent, mismatched, failing mid-run, or targeting C++, `#![no_std]`, embedded, or `safety-critical` crates, execute all five `rustify` stages manually with native `bindgen`/`cbindgen`/`cxx`/`PyO3`, golden-vector harnesses, `clippy`, `miri`, sanitizers, and `cargo kani` with zero loss of rigor.
  * *Compiled-only `.so` / `.dll` / `.a` / firmware binaries lacking source:* Co-load `reverse-engineer-anything` (`rea_rea` Model Context Protocol (`MCP`) server when available) to extract symbol graphs and calling conventions first.
  * *Domain type & typestate design:* Apply `~/.gemini/config/skills/harness/references/mistake-proofing.md` and `~/.gemini/config/skills/harness/references/mistake-proofing-languages.md` (`Rust` section: `Prevented` vs. `Announced`).
  * *Multi-window (`>8` files) migrations:* Partition via `~/.gemini/config/skills/harness/references/marathon.md` (`W1: Characterization & Leaf Types`, `W2: Interop Seam & Intermediate Logic`, `W3: Unsafe Purification & Audit`). Record target profile and binary layout decisions via `~/.gemini/config/skills/harness/references/adr.md`.

---

## 2. Stage 1: Silent Build, Layout & Dependency Autopsy (Before Asking Questions)

Never ask the user technical facts already visible in the repository (`GEMINI.md` Rule 11). First audit `Makefile`, `CMakeLists.txt`, `meson.build`, `compile_commands.json`, `setup.py`, `pyproject.toml`, `go.mod`, `package.json`, `tsconfig.json`, `Gemfile`, `pom.xml`, `build.gradle*`, `Cargo.toml`, and any `build.rs` via `read_file` before executing `make`, `cmake`, `pytest`, `maturin`, `npm`, `gradle`, or `cargo check` (because `cargo check` compiles and runs `build.rs` and procedural macros with full user privileges; `GEMINI.md` Rule 12). Map symbol dependencies via `agy-guard code-map profile <symbol>` / `blast-radius <symbol>` (noting that `code_map.py` performs single-pass `#` directive blanking without macro expansion and linear template masking on C/C++, so always cross-check C/C++ results against `compile_commands.json` / `clangd` or `nm -gC` per `references/c-cpp-abi-and-embedded.md` §5) to establish:

1. **Source Language Dialect & Build Seam:** Compiler flags (`-fno-strict-aliasing`, `-fwrapv`, `-ffast-math` / `-ffp-contract`, C/C++ standard, target triple/endianness), runtime/VM ABI (Node `napi-rs`/WebAssembly, Python `CPython`, Ruby, JVM/ART), `setjmp`/`longjmp` or C++ exception paths, static vs. shared linkage, and existing test runners (`ctest`, `gtest`, `pytest`, `go test`, `vitest`/`jest`, `rspec`, `gradle`/`mvn`).
2. **Binary & Hardware Coupling:** Structs crossing wire, file, shared-memory, or Memory-Mapped Input/Output (`MMIO`) boundaries; interrupt service routines; thread/lock topology; and global mutable state.
3. **Dependency Graph (`Leaf -> Intermediate -> Root`):**
   * *Leaf Nodes:* Constants, binary/math kernels, checksums, and stateless data types with zero external calls.
   * *Intermediate Nodes:* Parsers, state machines, codecs, and domain validators.
   * *Root Nodes:* Input/Output (`I/O`) loops, thread/async orchestrators, and hardware interrupt handlers. External `FFI` entry points also sit at the root boundary.
4. **Bridge-Overhead Profiling Before Unit Selection:** Measure caller-inclusive hot paths (including FFI marshaling overhead via native profilers or `rust-anything profile`) before selecting bridge units. Never port a tiny hot-loop helper whose per-call bridge crossing costs more than the compute saved; expand the boundary to include its callers or batch calls across a prepared index (`--batch` / `FnIndex` in [references/managed-go-python.md](./references/managed-go-python.md)).

---

## 3. Stage 2: The Migration Contract Gate (`ask_question`, Max 3 Decisions)

Unless the user's prompt already specifies every axis below, ask **at most 3 pointed questions** via `ask_question` (with `(Recommended)` defaults grounded in Stage 1; in exported runtimes lacking `ask_question`, emit at most `3` numbered plain-text questions with `2–3` options and `1` `(Recommended)` default per question, then stop for user input):

1. **Target Profile:**
   * *`standard-service`:* Full `std`, structured errors (`thiserror` at library seams, `anyhow` at application roots), and bounded concurrency (`tokio` / `rayon` where needed).
   * *`embedded-no-std`:* `#![no_std]` (decoupled as `#![cfg_attr(not(test), no_std)]` on pure domain crates for host testing, with `alloc` only if authorized), deterministic fixed-capacity buffers (`heapless`), `embedded-hal` traits, and `critical-section` interrupt synchronization.
   * *`safety-critical` (automotive ISO 26262 / avionics DO-178C / MISRA-aligned):* Strict `#![no_std]`, zero dynamic heap allocation after initialization, **Zero-Panic Guarantee** on production targets (no `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or unchecked `slice[i]`), and bounded formal proof harnesses.
2. **Cutover & Interop Strategy:**
   * *`idiomatic-rewrite`:* Replace the target module or binary end-to-end in pure safe Rust while preserving external command-line, wire, or file contracts.
   * *`incremental-ffi` (Strangler Bridge):* Keep the host application running and replace one module at a time behind a verified `ABI` seam. Split pure C bridges into a 3-crate workspace (`*-sys` raw bindings, `*-core` pure safe Rust, `*-ffi` C ABI exports), or wrap modern C++ classes/templates behind a dedicated `cxx` bridge crate (`#[cxx::bridge]`). Use `bindgen` + `cbindgen` for C headers, `cxx` for C++, `PyO3` + `maturin` for Python, `napi-rs` or `wasm` for TypeScript/JavaScript, Magnus/C ABI for Ruby, JNI for Java/Kotlin, or a C static/shared seam for Go `cgo`. For whole-app strangler-fig migrations, drive the **fallback rate** monotonically to `0%` behind per-unit runtime kill switches and isolated shadow checks before lifting to standalone Rust and offering a post-lift reshape pass (see [references/managed-go-python.md](./references/managed-go-python.md) §6).
3. **Legacy Defect, Overflow & Float Policy:** Confirm whether silent source-language quirks (C unsigned wraparound, sentinel error codes, loose input acceptance, insertion-ordered maps, ASCII-only regex `\w`, or fused floating-point contraction drift vs. `0` Units in the Last Place (`ULP`) with `-ffp-contract=off`) must be preserved bit-for-bit or tightened into explicit `Authorized Sanitization Transitions`.

Default new or migrated crates to **Rust `2024` Edition** targeting **Rust `1.100.0`+** unless the host workspace pins an older Minimum Supported Rust Version (`MSRV`): note Edition 2024 `#[unsafe(no_mangle)]` / `#[unsafe(export_name)]` / `#[unsafe(link_section)]`, `unsafe extern "C" { pub safe / pub unsafe ... }` blocks, `static_mut_refs` denial (`&raw const`/`&raw mut` or atomics), `unsafe_op_in_unsafe_fn` warnings, plus Rust `1.100.0`'s stabilized `core::mem::DropGuard`, `core::alloc::Allocator` (`Vec::new_in` / `Box::new_in`), and stable `!` never type (beware the `1.100.0` pre-2024 never-type fallback change from `()` to `!` when upgrading older callback/FFI code). Pin every added Cargo crate (`=x.y.z` + `Cargo.lock`, `--locked`, noting `cargo install` defaults to `--locked`), configure registry publish-age cooldowns in `.cargo/config.toml` when pulling public crates (`[registry] global-min-publish-age = 259200` / `[registries.crates-io] min-publish-age = 259200`, a `3`-day default cooldown with explicit documented per-version exemption only for pinned zero-day security advisories, plus `[resolver] incompatible-publish-age = "deny"`), enable `[lints.cargo] unused_dependencies = "warn"` (`rust-version >= "1.79.0"`), and lock confirmed choices into `AC-1..N` acceptance criteria (`~/.gemini/config/skills/harness/SKILL.md` §4.E) before writing production code.

---

## 4. Stage 3: Differential Pinning & Leaf-to-Root Redesign

1. **Pin Source Oracle First (`~/.gemini/config/skills/refactoring/SKILL.md` §3 & `~/.gemini/config/skills/harness/references/test-design.md`):**
   * Capture golden edge-case vectors from the untouched source implementation (empty/zero-length buffers, boundary integers `0`, `INT_MIN`, `INT_MAX`, `UINT_MAX`, malformed frames, non-UTF-8 byte sequences, and cross-language semantic traps in [references/managed-go-python.md](./references/managed-go-python.md)) or record a `file:line` **Equivalence Ledger** in `scratch/equivalence_ledger.md` when the source target cannot execute locally.
   * **Two-Run Oracle Noise Taxonomy & `known-diffs.jsonl`:** Run the untouched source oracle twice on identical inputs to classify nondeterminism (`values` / `order` / `lines`) and record only explicitly user-approved behavioral deltas in `<crate>/known-diffs.jsonl` (carrying `expected` and `approved_in` provenance; never self-authored during Stage 5 retries per `GEMINI.md` Rule 9) following [references/managed-go-python.md](./references/managed-go-python.md) §6.
   * **Immutable Cross-Language Test Discipline (`GEMINI.md` Rule 9):** Never delete, comment out, or weaken existing C, C++, Go, Python, TS/JS, Ruby, or Java/Kotlin test suites to pass a gate. Keep superseded legacy test files on disk and running across `incremental-ffi` seams until replacement Rust public-seam and differential tests are green, the user authorizes `## Authorized Test Modifications` in `tasks.md` (`[Legacy Test Transition Request]`), and the human operator seals a fresh `agy-guard test-boundary snapshot`.
2. **Redesign Data Models Before Function Bodies (`~/.gemini/config/skills/harness/references/mistake-proofing-languages.md`):**
   * Replace nullable pointers and magic sentinels (`NULL`, `-1`, `nil`, `None`) with `Option<T>` (`Option<&T>` / `Option<&mut T>` / `NonNull<T>` inside low-level wrappers).
   * Replace `errno`, out-parameters, and unchecked exceptions with `#[must_use]` `Result<T, DomainError>` enums, using `Vec::try_reserve_exact` plus explicit byte-cap bounds on untrusted wire lengths so corrupt lengths return `Err(...)` instead of aborting on allocation failure.
   * Replace invalid flag combinations and closed `virtual` Object-Oriented Programming (`OOP`) hierarchies with algebraic `enum` variants (`Prevented` at compile time), using `trait` + `dyn Trait` only for genuinely open extension seams. Map templates/`SFINAE` to generics with `where` bounds, Standard Template Library (`STL`) views (`std::string_view`, `std::span`, `std::expected`) to `&str`/`&[T]`/`Result`, non-destructive `std::move` patterns to destructive Rust moves (`core::mem::take`/`replace`), scoped C `goto cleanup` blocks to `core::mem::DropGuard` (`DropGuard::new` / `dismiss`), custom arenas to `core::alloc::Allocator` (`references/c-cpp-abi-and-embedded.md`), and insertion-ordered dynamic objects/dicts to `indexmap` (`references/managed-go-python.md`).
3. **Execute Strictly Leaf-to-Root in Narrow Vertical Slices:** Port and verify leaf types and pure kernels first (`<= 3` tightly coupled files, such as header/implementation/bridge, per planned forward migration slice: an explicit `GEMINI.md` Rule 13 forward-slice carve-out, while unverified bug-fix retry loops after a failing gate remain strictly capped at `GEMINI.md` Rule 13's `max(1 file, ~10%)`). Next port intermediate state machines and parsers, and wire root `I/O` loops or external `FFI` glue last so ownership and lifetime shapes stabilize from the inside out.

---

## 5. Stage 4: Two-Stage `unsafe` Purification & Six Red Lines

When porting pointer-heavy C/C++ or hardware code, never combine behavioral translation and `unsafe` refactoring in one unverified leap:

1. **Stage A (Behavioral Parity Seam):** Establish a compiling, test-pinned slice behind a narrow private `unsafe` boundary and prove parity against Stage 3 golden vectors.
2. **Stage B (Safe Purification):** Systematically shrink and eliminate `unsafe` blocks by replacing raw pointer + length pairs (`const T* ptr, size_t len`) with borrowed slices (`&[T]`, `&mut [T]`), iterators, checked slice splits (`split_at_mut`), or arena indices (`Vec<Node>` + typed index newtypes instead of cyclic/intrusive pointer graphs).
3. **Mandatory Invariant Documentation:** Every remaining unavoidable `unsafe` block (foreign call, `read_volatile`/`write_volatile` register access, or zero-copy layout cast not covered by `bytemuck`/`zerocopy`) must sit inside a minimal private safe wrapper. Each `unsafe` block and `unsafe impl` must carry an explicit `// SAFETY:` comment stating the exact preconditions verified at the boundary.

### Six Strictly Prohibited Anti-Patterns (Red Lines)
1. **The `Arc<Mutex<T>>` / `Rc<RefCell<T>>` Reflex:** Never wrap every ported struct in shared interior mutability to silence the borrow checker. Assign a single owner, pass `&T` / `&mut T` down the call tree, or transfer ownership over bounded channels.
2. **Hidden Panics as Error Handling:** Never translate C error codes, Go `err != nil`, or JS/Python/Ruby/Java exceptions into `.unwrap()`, `.expect()`, or unchecked `buf[idx]`, because a Rust panic never matches a recorded source error. Use `.get(idx).ok_or(...)?` and explicit `Err(...)` variants; reserve `// INFALLIBLE: <why>` strictly for non-`safety-critical` states outside `extern "C"` / FFI unwind seams proven impossible in both the original and Rust, paired with `#[expect(clippy::expect_used, reason = "...")]` on `.expect(...)` (banning bare `.unwrap()`; under `safety-critical` profiles, zero production panics remain mandatory).
3. **Silent Narrowing `as` Casts & Blind Overflow Rules:** Never narrow integers with `val as u16`; use `u16::try_from(val)?`. Distinguish intentional C `unsigned` modular arithmetic (`wrapping_add`, `Wrapping<u32>`) from bug-prone arithmetic (`checked_add`, `saturating_sub`); blindly converting intentional checksum/crypto wraparound to `checked_add` breaks parity.
4. **Unannotated Cross-Boundary Struct Layouts:** Never pass a default `repr(Rust)` struct across `FFI`, shared memory, or binary wire/register maps because `rustc` reorders fields freely. Enforce explicit `#[repr(C)]` or `#[repr(transparent)]` plus compile-time size/offset assertions (see [references/c-cpp-abi-and-embedded.md](./references/c-cpp-abi-and-embedded.md)).
5. **Bidirectional Unwinding Across Foreign Boundaries:** Panicking from Rust across `extern "C"` (or letting C `longjmp` or uncaught C++ exceptions jump across Rust frames holding `Drop` destructors) triggers immediate Undefined Behavior (`UB`). Guard `std` Rust exports with `std::panic::catch_unwind` (`#![no_std]` exports enforce `panic = "abort"` plus static panic-freedom lints, while `PyO3` extension wheels keep `panic = "unwind"`), and trap C `setjmp`/`longjmp` or C++ `try-catch` strictly inside thin C/C++ shims before returning error codes to Rust.
6. **Premature Lifetime Proliferation & Blind UTF-8 Assumptions:** Prefer owned fields in domain structs and borrowed slices (`&[u8]`, `&str`) in parameters unless measured zero-copy parsing requires `'a`; never call `.to_str()?` on raw C `CStr` / OS path bytes unless strict UTF-8 validity is part of the proven contract, and translate UTF-16 code-unit offsets explicitly at JS/Java seams.

---

## 6. Stage 5: Three-Tier Verification Ladder & Independent Auditor Gate

Treat deterministic Rust and native toolchains as mandatory co-verifiers (routing `>500`-line or twice-failing borrow-checker/trait traces to the `build-error-resolver` subagent per `~/.gemini/config/skills/harness/SKILL.md` §3.B):

### Tier V1: Mandatory Universal Compiler, Lint & Differential Parity Gate
Run on every slice and before delivery (for `#![no_std]` hardware crates, scope `--target <embedded-triple>` to `--lib --bins` and run unit tests on the `#![cfg_attr(not(test), no_std)]` domain crate with `--target <host-triple>`):
```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::undocumented_unsafe_blocks
cargo test
```
* Under `safety-critical` profiles, enforce panic/truncation bans on **production targets** (`cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing -D clippy::ptr_as_ptr -D clippy::cast_possible_truncation`) so `assert!` / `assert_eq!` macros inside `#[test]` targets remain valid.
* Execute all Stage 3 golden-vector and cross-language differential parity suites within the agreed integer/float tolerance (and user-approved `<crate>/known-diffs.jsonl` records with `approved_in` provenance, never self-authored during Stage 5 retries) to `100%` pass.
* **Error-Path Reachability, `3x + 50` Line-Bloat Check, `#[expect]` & Caller-Inclusive Benchmark:**
  * Verify every deliberate original failure path (`throw`, `raise`, returned `error`) is reached by a recorded failing test case returning Rust `Err(...)`.
  * Audit any ported unit whose non-test production source lines of code (`SLOC`, excluding `#[cfg(test)]` modules and `// SAFETY:` comments) exceed `3x` the original source line count plus `50` lines (for imports and signatures); fold repeated logic or reuse pinned crates instead of carrying verbose translations (`GEMINI.md` Rules 4 & 18).
  * Silence justified local lints strictly with `#[expect(lint, reason = "...")]` on Rust `1.81+` (falling back to `#[allow(lint)] // MSRV < 1.81: <reason>` only when the workspace pins MSRV `< 1.81.0`) so stale suppressions warn automatically once resolved.
  * For `incremental-ffi` bridges, benchmark original vs. Rust *including bridge overhead* over `>= 30` post-warmup iterations and do not ship a unit that regresses median or p95 caller latency by `> 5%` without batching (`--batch` / `FnIndex`) or widening the boundary.

### Tier V2: Mandatory Memory & Boundary Sanitizer Gate (Whenever `unsafe` or Foreign Interop Exists)
* **Pure-Rust `unsafe` blocks:** Run `cargo +nightly miri test` to catch aliasing (`Stacked` / `Tree Borrows`), uninitialized memory reads, alignment violations, and out-of-bounds pointer arithmetic.
* **Mixed C/C++ <-> Rust binaries:** Because `miri` cannot execute external C/C++ functions, compile and run the linked integration test binary with `AddressSanitizer` and `UndefinedBehaviorSanitizer` enabled on the C/C++ toolchain alongside `>= 1,000` `proptest` cases or `>= 10,000` `cargo fuzz` runs (`>= 30 s`) over boundary inputs.
* **Managed-Runtime FFI Bridges (`JNI`, `napi-rs`, `PyO3`, `magnus`, `wasm`):** Execute runtime-specific boundary checks on native interop layers (JVM `-Xcheck:jni` plus explicit `.close()` handle-leak tests; Node `--expose-gc` plus ASan/Valgrind native addon smoke tests; `PyO3` reference-count and GIL-release concurrency tests; `wasm` out-of-bounds and memory-growth tests) alongside `cargo +nightly miri test` on pure-Rust `unsafe` helpers.

### Tier V3: Safety-Critical Bounded Formal Verification Gate (`cargo kani`)
* For `safety-critical` and `embedded-no-std` kernels/wrappers, check `command -v cargo-kani`: when installed, author `#[kani::proof]` harnesses proving panic-freedom, bounds safety, and invariant preservation across bounded symbolic inputs (`cargo kani`).
* **Fail-Closed Verification Gap Rule (`GEMINI.md` Rule 8):** When `miri` or sanitizers on newly introduced `unsafe` / interop seams (or `cargo-kani` under a `safety-critical` profile) cannot execute on the host, declare the exact unrun sensor and seam in the `Verification Gap Declaration` and halt delivery in `BLOCKED` status pending user review (never claim formal proof from `cargo test` alone; avoid fragile `Prusti` gates unless already pinned by the repository).

### Pre-Delivery Auditor Dispatch & Delivery Block
Before declaring completion on `FFI`, `unsafe`, public binary or programming interface changes, `safety-critical` profiles, or `>8`-file migrations (`GEMINI.md` §3 Critical Exceptions), dispatch the read-only `security-boundary-verifier`, `silent-failure-hunter`, `contract-change-auditor`, and `test-adequacy-auditor` subagents (plus `consistency-auditor` and `specification-gap-auditor` on `safety-critical` specifications). In the `GEMINI.md` Rule 5/8 Delivery Block, report: the active Target Profile & Interop Strategy (plus current strangler fallback rate when applicable), differential parity test counts, remaining `unsafe` block count with `file:line` `// SAFETY:` coordinates, executed verification tiers (`V1` / `V2` / `V3`), and any host-unavailable formal or hardware checks.
