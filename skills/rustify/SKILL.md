---
name: rustify
description: >-
  Architectural migration, porting, and Foreign Function Interface (FFI) bridging of C, C++, Go, or Python codebases
  into idiomatic, memory-safe, compiler-verified Rust. Enforces a 5-stage Silent Build & Layout Autopsy -> Migration
  Contract -> Behavior Pinning & Leaf-to-Root Decomposition -> Two-Stage Unsafe Purification -> 3-Tier Verification
  Ladder (rustc, clippy, miri, C/Rust sanitizers, and conditional Kani proofs). Invoke with /rustify or when porting,
  migrating, rewriting, or bridging code into Rust ("rustify", "rust'a çevir", "rust'a taşı", "rust'a dönüştür",
  "c/c++'dan rust'a", "cbindgen", "cxx bridge", "PyO3"). Not for intra-Rust behavior-preserving restructuring (use
  'refactoring'), post-hoc optimization of already-working Rust code (use 'sweetspot'), single-package Cargo.toml
  version bumps (use 'dependency-upgrade'), or reviving legacy software to non-Rust stacks (use 'renew').
---

# Rustify — Architectural Migration & Memory-Safe Interop Discipline

Translating source files line-by-line from C, C++, Go, or Python into Rust produces "C/Go in Rust syntax": ubiquitous `Arc<Mutex<T>>` wrappers, raw `*mut T` pointer arithmetic, `.unwrap()` panic landmines, silent `as` integer truncations, and broken Application Binary Interface (`ABI`) layouts. `rustify` governs cross-language transformation so ownership, lifetimes, binary layout invariants, and zero-panic guarantees are locked in incrementally with compiler and runtime proof.

---

## 1. Adjacent-Skill Boundaries & Co-Loading Map

* **vs. `skills/refactoring/SKILL.md` & `skills/sweetspot/SKILL.md`:** Use `refactoring` when restructuring code that is *already* in Rust with zero contract shift, and use `sweetspot` when profiling/optimizing an already-working Rust crate (`--time`, `--memory`, `--disk`, `--net`). Never mix premature Single Instruction, Multiple Data (`SIMD`) or custom-allocator micro-tuning into the initial cross-language migration pass.
* **vs. `skills/dependency-upgrade/SKILL.md`:** Use `dependency-upgrade` when bumping crate versions in `Cargo.toml` / `Cargo.lock` or upgrading the Rust toolchain edition (`2021` -> `2024`) within an existing Rust project.
* **vs. `skills/renew/SKILL.md` (Handoff vs. Co-Load):**
  * *Active/buildable C, C++, Go, or Python module -> Rust:* Use `rustify` directly.
  * *Obsolete/unbuildable 15+ year legacy software or classic game revived into a Rust target stack:* **Co-load** `skills/renew/SKILL.md` with `rustify`: combine both Stage 1 autopsies and a single merged Stage 2 contract gate (`<= 4` questions), pin once in Stage 3, apply `renew` Stage 4.2 legacy vulnerability sanitization (plus `renew` Section 6 for classic games) alongside `rustify` Stage 4, and pass both Stage 5 gates.
* **On-Demand Reference Modules (Load Only What Matches the Source Language):**
  * *C, C++, `#![no_std]` firmware, hardware registers, or Foreign Function Interface (`FFI`) bridges:* Read [references/c-cpp-abi-and-embedded.md](./references/c-cpp-abi-and-embedded.md).
  * *Go services/concurrency or Python `PyO3` / `maturin` extensions:* Read [references/managed-go-python.md](./references/managed-go-python.md).
* **Co-Loaded Capabilities When Applicable:**
  * *Compiled-only `.so` / `.dll` / `.a` / firmware binaries lacking source:* Co-load `reverse-engineer-anything` (`rea_rea` Model Context Protocol (`MCP`) server when available) to extract symbol graphs and calling conventions first.
  * *Domain type & typestate design:* Apply `skills/mistake-proofing/SKILL.md` and `skills/mistake-proofing/languages.md` (`Rust` section: `Prevented` vs. `Announced`).
  * *Multi-window (`>8` files) migrations:* Partition via `skills/marathon/SKILL.md` (`W1: Characterization & Leaf Types`, `W2: Interop Seam & Intermediate Logic`, `W3: Unsafe Purification & Audit`). Record target profile and binary layout decisions via `skills/architecture-decision-records/SKILL.md`.

---

## 2. Stage 1 — Silent Build, Layout & Dependency Autopsy (Before Asking Questions)

Never ask the user technical facts already visible in the repository (`GEMINI.md` Rule 11). First audit `Makefile`, `CMakeLists.txt`, `meson.build`, `compile_commands.json`, `setup.py`, `pyproject.toml`, `go.mod`, `Cargo.toml`, and any `build.rs` via `read_file` before executing `make`, `cmake`, `pytest`, `maturin`, or `cargo check` (because `cargo check` compiles and runs `build.rs` and procedural macros with full user privileges; `GEMINI.md` Rule 12). Map symbol dependencies via `python3 scripts/code_map.py profile <symbol>` / `blast-radius <symbol>` to establish:

1. **Source Language Dialect & Build Seam:** Compiler flags (`-fno-strict-aliasing`, `-fwrapv`, `-ffast-math` / `-ffp-contract`, C/C++ standard, target triple/endianness), `setjmp`/`longjmp` or C++ exception paths, static vs. shared linkage, and existing test runners (`ctest`, `gtest`, `pytest`, `go test`).
2. **Binary & Hardware Coupling:** Structs crossing wire, file, shared-memory, or Memory-Mapped Input/Output (`MMIO`) boundaries; interrupt service routines; thread/lock topology; and global mutable state.
3. **Dependency Graph (`Leaf -> Intermediate -> Root`):**
   * *Leaf Nodes:* Constants, binary/math kernels, checksums, and stateless data types with zero external calls.
   * *Intermediate Nodes:* Parsers, state machines, codecs, and domain validators.
   * *Root Nodes:* Input/Output (`I/O`) loops, thread/async orchestrators, and hardware interrupt handlers. External `FFI` entry points also sit at the root boundary.

---

## 3. Stage 2 — The Migration Contract Gate (`ask_question`, Max 3 Decisions)

Unless the user's prompt already specifies every axis below, ask **at most 3 pointed questions** via `ask_question` (with `(Recommended)` defaults grounded in Stage 1; in exported runtimes lacking `ask_question`, emit at most `3` numbered plain-text questions with `2–3` options and `1` `(Recommended)` default per question, then stop for user input):

1. **Target Profile:**
   * *`standard-service`:* Full `std`, structured errors (`thiserror` at library seams, `anyhow` at application roots), and bounded concurrency (`tokio` / `rayon` where needed).
   * *`embedded-no-std`:* `#![no_std]` (decoupled as `#![cfg_attr(not(test), no_std)]` on pure domain crates for host testing, with `alloc` only if authorized), deterministic fixed-capacity buffers (`heapless`), `embedded-hal` traits, and `critical-section` interrupt synchronization.
   * *`safety-critical` (automotive ISO 26262 / avionics DO-178C / MISRA-aligned):* Strict `#![no_std]`, zero dynamic heap allocation after initialization, **Zero-Panic Guarantee** on production targets (no `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or unchecked `slice[i]`), and bounded formal proof harnesses.
2. **Cutover & Interop Strategy:**
   * *`idiomatic-rewrite`:* Replace the target module or binary end-to-end in pure safe Rust while preserving external command-line, wire, or file contracts.
   * *`incremental-ffi` (Strangler Bridge):* Keep the host application running and replace one module at a time behind a verified `ABI` seam. Use `bindgen` + `cbindgen` for C headers, `cxx` for C++ classes/templates, `PyO3` + `maturin` for Python, or a C static/shared seam for Go `cgo`.
3. **Legacy Defect, Overflow & Float Policy:** Confirm whether silent source-language quirks (C unsigned wraparound, sentinel error codes, loose input acceptance, or fused floating-point contraction drift vs. `0` Units in the Last Place (`ULP`) with `-ffp-contract=off`) must be preserved bit-for-bit or tightened into explicit `Authorized Sanitization Transitions`.

Pin every added Cargo crate (`=x.y.z` + `Cargo.lock`, `--locked`) or external build dependency to an exact version or 40-character commit hash (`GEMINI.md` Rule 12), and lock confirmed choices into `AC-1..N` acceptance criteria (`skills/harness/SKILL.md` §4.E) before writing production code.

---

## 4. Stage 3 — Differential Pinning & Leaf-to-Root Redesign

1. **Pin Source Oracle First (`skills/refactoring/SKILL.md` §3 & `skills/test-design/SKILL.md`):**
   * Capture golden edge-case vectors from the untouched source implementation (empty/zero-length buffers, boundary integers `0`, `INT_MIN`, `INT_MAX`, `UINT_MAX`, malformed frames, non-UTF-8 byte sequences) or record a `file:line` **Equivalence Ledger** in `scratch/equivalence_ledger.md` when the source target cannot execute locally.
   * **Immutable Cross-Language Test Discipline (`GEMINI.md` Rule 9):** Never delete, comment out, or weaken existing C, C++, Go, or Python test suites to pass a gate. Keep superseded legacy test files on disk and running across `incremental-ffi` seams until replacement Rust public-seam and differential tests are green, the user authorizes `## Authorized Test Modifications` in `tasks.md` (`[Legacy Test Transition Request]`), and the human operator seals a fresh `agy-guard test-boundary snapshot`.
2. **Redesign Data Models Before Function Bodies (`skills/mistake-proofing/languages.md`):**
   * Replace nullable pointers and magic sentinels (`NULL`, `-1`, `nil`, `None`) with `Option<T>` (`Option<&T>` / `Option<&mut T>` / `NonNull<T>` inside low-level wrappers).
   * Replace `errno`, out-parameters, and unchecked exceptions with `#[must_use]` `Result<T, DomainError>` enums, using `Vec::try_reserve_exact` plus explicit byte-cap bounds on untrusted wire lengths so corrupt lengths return `Err(...)` instead of aborting on allocation failure.
   * Replace invalid flag combinations and deep Object-Oriented Programming (`OOP`) inheritance hierarchies with closed algebraic `enum` variants, flat structs, composition, and focused traits (`Prevented` at compile time).
3. **Execute Strictly Leaf-to-Root in Narrow Vertical Slices:** Port and verify leaf types and pure kernels first (`<= 3` tightly coupled files, such as header/implementation/bridge, per planned forward migration slice — an explicit `GEMINI.md` Rule 13 forward-slice carve-out, while unverified bug-fix retry loops after a failing gate remain strictly capped at `GEMINI.md` Rule 13's `max(1 file, ~10%)`). Next port intermediate state machines and parsers, and wire root `I/O` loops or external `FFI` glue last so ownership and lifetime shapes stabilize from the inside out.

---

## 5. Stage 4 — Two-Stage `unsafe` Purification & Six Red Lines

When porting pointer-heavy C/C++ or hardware code, never combine behavioral translation and `unsafe` refactoring in one unverified leap:

1. **Stage A (Behavioral Parity Seam):** Establish a compiling, test-pinned slice behind a narrow private `unsafe` boundary and prove parity against Stage 3 golden vectors.
2. **Stage B (Safe Purification):** Systematically shrink and eliminate `unsafe` blocks by replacing raw pointer + length pairs (`const T* ptr, size_t len`) with borrowed slices (`&[T]`, `&mut [T]`), iterators, checked slice splits (`split_at_mut`), or arena indices (`Vec<Node>` + typed index newtypes instead of cyclic/intrusive pointer graphs).
3. **Mandatory Invariant Documentation:** Every remaining unavoidable `unsafe` block (foreign call, `read_volatile`/`write_volatile` register access, or zero-copy layout cast not covered by `bytemuck`/`zerocopy`) must sit inside a minimal private safe wrapper. Each `unsafe` block and `unsafe impl` must carry an explicit `// SAFETY:` comment stating the exact preconditions verified at the boundary.

### Six Strictly Prohibited Anti-Patterns (Red Lines)
1. **The `Arc<Mutex<T>>` / `Rc<RefCell<T>>` Reflex:** Never wrap every ported struct in shared interior mutability to silence the borrow checker. Assign a single owner, pass `&T` / `&mut T` down the call tree, or transfer ownership over bounded channels.
2. **Hidden Panics as Error Handling:** Never translate C error codes, Go `err != nil`, or Python exceptions into `.unwrap()`, `.expect()`, or unchecked `buf[idx]`. Use `.get(idx).ok_or(...)?` and explicit error variants.
3. **Silent Narrowing `as` Casts & Blind Overflow Rules:** Never narrow integers with `val as u16`; use `u16::try_from(val)?`. Distinguish intentional C `unsigned` modular arithmetic (`wrapping_add`, `Wrapping<u32>`) from bug-prone arithmetic (`checked_add`, `saturating_sub`)—blindly converting intentional checksum/crypto wraparound to `checked_add` breaks parity.
4. **Unannotated Cross-Boundary Struct Layouts:** Never pass a default `repr(Rust)` struct across `FFI`, shared memory, or binary wire/register maps because `rustc` reorders fields freely. Enforce explicit `#[repr(C)]` or `#[repr(transparent)]` plus compile-time size/offset assertions (see [references/c-cpp-abi-and-embedded.md](./references/c-cpp-abi-and-embedded.md)).
5. **Bidirectional Unwinding Across Foreign Boundaries:** Panicking from Rust across `extern "C"`—or letting C `longjmp` or uncaught C++ exceptions jump across Rust frames holding `Drop` destructors—triggers immediate Undefined Behavior (`UB`). Guard `std` Rust exports with `std::panic::catch_unwind` (`#![no_std]` exports enforce `panic = "abort"` plus static panic-freedom lints, while `PyO3` extension wheels keep `panic = "unwind"`), and trap C `setjmp`/`longjmp` or C++ `try-catch` strictly inside thin C/C++ shims before returning error codes to Rust.
6. **Premature Lifetime Proliferation & Blind UTF-8 Assumptions:** Prefer owned fields in domain structs and borrowed slices (`&[u8]`, `&str`) in parameters unless measured zero-copy parsing requires `'a`; never call `.to_str()?` on raw C `CStr` / OS path bytes unless strict UTF-8 validity is part of the proven contract.

---

## 6. Stage 5 — Three-Tier Verification Ladder & Independent Auditor Gate

Treat deterministic Rust and native toolchains as mandatory co-verifiers (routing `>500`-line or twice-failing borrow-checker/trait traces to the `build-error-resolver` subagent per `skills/harness/SKILL.md` §3.B):

### Tier V1 — Mandatory Universal Compiler, Lint & Differential Parity Gate
Run on every slice and before delivery (for `#![no_std]` hardware crates, scope `--target <embedded-triple>` to `--lib --bins` and run unit tests on the `#![cfg_attr(not(test), no_std)]` domain crate with `--target <host-triple>`):
```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::undocumented_unsafe_blocks
cargo test
```
* Under `safety-critical` profiles, enforce panic/truncation bans on **production targets** (`cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing -D clippy::ptr_as_ptr -D clippy::cast_possible_truncation`) so `assert!` / `assert_eq!` macros inside `#[test]` targets remain valid.
* Execute all Stage 3 golden-vector and cross-language differential parity suites within the agreed integer/float tolerance to `100%` pass.

### Tier V2 — Mandatory Memory & Boundary Sanitizer Gate (Whenever `unsafe` or Foreign Interop Exists)
* **Pure-Rust `unsafe` blocks:** Run `cargo +nightly miri test` to catch aliasing (`Stacked` / `Tree Borrows`), uninitialized memory reads, alignment violations, and out-of-bounds pointer arithmetic.
* **Mixed C/C++ <-> Rust binaries:** Because `miri` cannot execute external C/C++ functions, compile and run the linked integration test binary with `AddressSanitizer` and `UndefinedBehaviorSanitizer` enabled on the C/C++ toolchain alongside `>= 1,000` `proptest` cases or `>= 10,000` `cargo fuzz` runs (`>= 30 s`) over boundary inputs.

### Tier V3 — Safety-Critical Bounded Formal Verification Gate (`cargo kani`)
* For `safety-critical` and `embedded-no-std` kernels/wrappers, check `command -v cargo-kani`: when installed, author `#[kani::proof]` harnesses proving panic-freedom, bounds safety, and invariant preservation across bounded symbolic inputs (`cargo kani`).
* **Fail-Closed Verification Gap Rule (`GEMINI.md` Rule 8):** When `miri` or sanitizers on newly introduced `unsafe` / interop seams—or `cargo-kani` under a `safety-critical` profile—cannot execute on the host, declare the exact unrun sensor and seam in the `Verification Gap Declaration` and halt delivery in `BLOCKED` status pending user review (never claim formal proof from `cargo test` alone; avoid fragile `Prusti` gates unless already pinned by the repository).

### Pre-Delivery Auditor Dispatch & Delivery Block
Before declaring completion on `FFI`, `unsafe`, public binary or programming interface changes, `safety-critical` profiles, or `>8`-file migrations (`GEMINI.md` §3 Critical Exceptions), dispatch the read-only `security-boundary-verifier`, `silent-failure-hunter`, `contract-change-auditor`, and `test-adequacy-auditor` subagents (plus `consistency-auditor` and `specification-gap-auditor` on `safety-critical` specifications). In the `GEMINI.md` Rule 5/8 Delivery Block, report: the active Target Profile & Interop Strategy, differential parity test counts, remaining `unsafe` block count with `file:line` `// SAFETY:` coordinates, executed verification tiers (`V1` / `V2` / `V3`), and any host-unavailable formal or hardware checks.
