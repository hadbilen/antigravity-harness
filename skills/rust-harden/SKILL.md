---
name: rust-harden
description: >-
  Intra-Rust hardening, ownership debt cleanup, panic removal, async cancellation, and #![no_std] or kernel unsafe
  narrowing. Invoke with /rust-harden or on "harden rust", "rust kodunu sertleştir", "idiomatic rust yap", "sahiplik
  borcunu temizle", "unsafe arındır". Not for cross-language ports (use 'rustify'), generic moves (use 'refactoring'),
  speed/RAM tuning (use 'sweetspot'), Cargo bumps (use 'harness' dependency-upgrade), or bugs (use 'diagnosing-bugs').
---

# Rust Harden: Intra-Rust Ownership, Panic-Freedom & Unsafe Narrowing Discipline

Existing Rust crates frequently accumulate borrow-checker workarounds and latent runtime traps: defensive `.clone()` chains, single-owner state wrapped in `Arc<Mutex<T>>` or `Rc<RefCell<T>>`, production `.unwrap()` and `.expect()` panic paths, cancellation-unsafe `tokio::select!` branches, and oversized `unsafe` blocks lacking verified preconditions. `rust-harden` eliminates intra-Rust ownership, panic, concurrency, and memory-safety debt under compiler, linter, sanitizer, and formal proof gates.

---

## 1. Adjacent-Skill Boundaries & Mode Selection

* **vs. `skills/rustify/SKILL.md`:** `rustify` ports C, C++, Go, Python, TS/JS, Ruby, or Java/Kotlin codebases into Rust and builds initial Foreign Function Interface (`FFI`) bridges against cross-language golden vectors. Once code compiles and runs as a Rust crate, hand off intra-Rust ownership cleanup, panic removal, async cancellation hardening, and `unsafe` narrowing to `rust-harden`.
* **vs. `skills/refactoring/SKILL.md` & `skills/sweetspot/SKILL.md`:** Use `refactoring` for language-agnostic module splits or renames without Rust-specific ownership/lint/soundness goals, and use `sweetspot` when profiling and reducing measured wall-clock time, memory (`RAM`), binary size, or network bandwidth under the 3-Zone Gate.
* **vs. `skills/harness/references/dependency-upgrade.md` & `skills/diagnosing-bugs/SKILL.md`:** Use `dependency-upgrade` for `Cargo.toml` version or Rust edition bumps (`2021 -> 2024`), and use `diagnosing-bugs` first when reproducing an active crash, deadlock, or failing test before hardening surrounding code.

### Two Mutually Exclusive Operational Modes (Never Mix in One Changeset)

Bare `/rust-harden` invocations default to **Mode 1 (`--internal`)** unless the user explicitly passes `--contract` or confirms contract tightening via `ask_question`:

1. **Mode 1 (`--internal`, Default): Behavior- & Signature-Preserving Hardening**
   * **Contract Invariant:** `100%` preservation of all `pub` function/type/trait signatures, wire formats, CLI flags, exit codes, and existing test suites (`GEMINI.md` Rule 9).
   * **Allowed Scope:** Replace reflexive `.clone()` and single-owner-solvable `Arc<Mutex<T>>` / `Rc<RefCell<T>>` wrappers with owned moves, `&T` / `&mut T` borrows, or bounded channels; shrink lock guard scopes before `.await` or slow I/O; replace internal `.unwrap()`, `.expect()`, and `slice[i]` panics inside functions whose return type already carries `Result` or `Option`; and purify private `unsafe` blocks into safe slices (`&[T]`, `&mut [T]`), `split_at_mut`, iterators, or typed arena indices.
2. **Mode 2 (`--contract`): Controlled Public Contract Tightening**
   * **Contract Invariant:** Deliberately upgrades `pub`-reachable panics, unchecked `as` integer casts, infallible OOM allocations, or primitive stringly-typed parameters into `#[must_use] Result<T, DomainError>`, `TryFrom` conversions, `Vec::try_reserve` / `try_reserve_exact`, and invariant-enforcing `newtype` or `typestate` wrappers (`skills/harness/references/mistake-proofing-languages.md`).
   * **Mandatory Protocol:** Execute `Expand -> Migrate -> Contract` across workspace callers (`skills/refactoring/SKILL.md` §5, mapping blast radius first via `agy-guard code-map callers <symbol>` and `agy-guard code-map blast-radius <symbol>`), obtain explicit user approval under `## Authorized Test Modifications` in `tasks.md` (`GEMINI.md` Rule 9) before updating any existing test call signature, and dispatch both `contract-change-auditor` and `test-adequacy-auditor` prior to delivery.

---

## 2. Crate-Tiered `rustc` & `clippy` Lint Architecture

Never apply a naive workspace-wide `unsafe_code = "deny"` paired with `allow_attributes = "deny"`: that combination deadlocks legitimate hardware/HAL/FFI boundary crates and breaks external procedural macros expanding attributes inside downstream crates. Partition lints cleanly between `[lints.rust]` (`rustc`) and `[lints.clippy]` (`clippy`) by crate role:

1. **Safe Domain, Protocol & Application Crates (`app-cli` Default):**
   * Enforce `#![forbid(unsafe_code)]` at the crate root (or `unsafe_code = "forbid"` in crate `Cargo.toml` `[lints.rust]`).
2. **Isolated Hardware, Kernel Framework, HAL & FFI Boundary Crates:**
   * Keep `unsafe` confined to the smallest private boundary module and enforce in `Cargo.toml`:
   ```toml
   [lints.rust]
   unsafe_op_in_unsafe_fn = "deny"
   static_mut_refs = "deny"

   [lints.clippy]
   undocumented_unsafe_blocks = "deny"
   multiple_unsafe_ops_per_block = "deny"
   let_underscore_must_use = "deny"
   await_holding_lock = "deny"
   ```
   * Every remaining `unsafe` block and `unsafe impl` carries a dedicated `// SAFETY:` comment proving the exact aliasing, alignment, lifetime, initialization, and thread-safety preconditions verified at that call site.
3. **Production Panic & Truncation Gate (`--lib --bins` vs. `#[test]`):**
   * Enforcing `clippy::unwrap_used = "deny"` globally across `--all-targets` without test configuration breaks idiomatic `#[test]` assertions (`GEMINI.md` Rule 9). Either configure `clippy.toml` at the workspace root:
   ```toml
   allow-unwrap-in-tests = true
   allow-expect-in-tests = true
   ```
   * Or run the strict panic and truncation lint pass specifically against production targets (`cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing -D clippy::cast_possible_truncation`) so existing unit and integration tests remain untouched under Mode 1 (`--internal`).
4. **Self-Expiring Lint Suppressions (`#[expect]`):** On Rust `1.81+` / Edition `2024`, prefer `#[expect(lint, reason = "...")]` over `#[allow(...)]` for justified local lint overrides so `rustc` flags the suppression automatically once the condition no longer triggers (on crates pinned to MSRV `< 1.81.0`, use `#[allow(lint)] // MSRV < 1.81: <reason>`).

---

## 3. Default `app-cli` Hardening Rules (Rust `2024` Edition Baseline)

1. **Single Owner First (`Zero Arc<Mutex<T>> Reflex`):** Before keeping or adding `Arc<Mutex<T>>`, `RwLock<T>`, or `Rc<RefCell<T>>`, prove that `>= 2` concurrent tasks or callbacks genuinely mutate shared state. Otherwise pass `&mut State` down the call stack or isolate state inside one actor task fed by a bounded `mpsc::channel(cap)`.
2. **Eliminate Unnecessary `.clone()` Allocations:** Audit `.clone()` calls on `String`, `Vec<T>`, `PathBuf`, `Bytes`, and domain structs: accept `&str`, `&[T]`, or `&Path` in read-only parameters, return `Cow<'_, str>` when allocation is conditional, and move owned values on terminal call sites.
3. **Structured Error Propagation, `// INFALLIBLE:` & Zero Silent Drops:** Use typed `#[derive(Debug)]` domain error enums (`thiserror` at library seams, contextual `anyhow::Context` only at binary entrypoints). Never discard `Result` or channel outcomes via `let _ = ...`, `.ok()`, or failure-masking `.unwrap_or_default()`. Never use `.unwrap()`, `.expect()`, or `panic!()` on recoverable error paths; reserve an explicit `// INFALLIBLE: <why>` comment strictly for provably impossible states in non-`safety-critical` crates outside `extern "C"` / FFI unwind seams, paired with `#[expect(clippy::expect_used, reason = "...")]` on `.expect(...)` (banning bare `.unwrap()` and keeping zero production panics on `#![no_std]` / kernel / `safety-critical` paths).
4. **Bounded Deserialization & Fallible Reservation:** Enforce explicit byte-size and element-count caps at untrusted file, IPC, and network edges before allocating; reserve dynamic buffers with `Vec::try_reserve` / `Vec::try_reserve_exact` and checked integer conversions (`usize::try_from(len)?`, `checked_mul`).
5. **Rust `2024` Edition Hygiene:** Respect Edition `2024` `unsafe extern "C"` blocks, `#[unsafe(no_mangle)]`, `&raw const` / `&raw mut` instead of mutable static references (`static_mut_refs`), explicit `unsafe {}` blocks inside `unsafe fn` (`unsafe_op_in_unsafe_fn`), and `core::mem::DropGuard` for rollback-on-unwind cleanup.

---

## 4. Progressive Disclosure: Specialized Domain Profiles

Load only the reference document matching the target crate's runtime layer:

* **Async Services, Tokio Daemons & Privileged POSIX Processes:** Read [references/async-and-userspace.md](./references/async-and-userspace.md) for `tokio::select!` cancellation safety, zero locks across `.await`, bounded backpressure, `spawn_blocking` isolation, `OwnedFd` / `BorrowedFd` RAII descriptors, and synchronous pre-runtime `setgroups(&[]) -> setresgid -> setresuid` privilege drop with negative `setuid(0) -> EPERM` verification.
* **`#![no_std]`, Embedded, OS Kernel & Low-Level `unsafe` Subsystems:** Read [references/kernel-and-unsafe.md](./references/kernel-and-unsafe.md) for fallible `alloc` (`ENOMEM`), Framekernel safe/unsafe crate partitioning, IRQ-safe spinlock ordering, `UserSlice` / `UserPtr` SMAP/PAN/TOCTOU boundaries, DMA `Pin` and hardware-quiesced/quarantined `Drop` safety, `8-16 KB` kernel stack limits (`large_stack_frames` / `large_stack_arrays`), and paired `Atomic*` ordering proofs (`loom`, `cargo kani`).
* **Games, Vulkan/GPU Renderers & Real-Time Audio Engines:** Read [references/game-and-realtime.md](./references/game-and-realtime.md) for per-frame heap/cache hygiene (`clippy::large_enum_variant` + `1,000`-tick zero-allocation check), generational arenas vs. `Rc<RefCell<T>>` / `Arc<Mutex<T>>`, deterministic non-`HashMap` simulation, `f32`/`f64` `NaN`/`total_cmp`/clamp guards, reverse-order GPU/Vulkan `Drop`, swapchain `Outdated`/`Lost` handling, lock-free `SPSC` audio threads, and bounded binary packet/save deserialization.

---

## 5. Verification Ladder & Independent Auditor Gate

Execute deterministic Rust sensors sequentially after every hardening slice (routing `>500`-line or twice-failing borrow-checker and trait traces immediately to `build-error-resolver` per `skills/harness/SKILL.md` §3.B):

1. **Compiler & Workspace Lint Gate (Mandatory for All Crates):**
   ```bash
   cargo check --all-targets
   cargo clippy --all-targets -- -D warnings
   cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::let_underscore_must_use -D clippy::await_holding_lock
   cargo test
   ```
2. **Undefined Behavior & Property Gate (Mandatory When `unsafe` or Complex Parsers Exist):**
   * Run `cargo +nightly miri test` over every pure-Rust `unsafe` wrapper, custom collection, or pointer/slice manipulation seam to catch Stacked/Tree Borrows aliasing, alignment, uninitialized memory, and out-of-bounds defects.
   * Run `proptest` state/input property suites when `proptest` is already pinned in `Cargo.lock` (or after obtaining user confirmation to pin an exact `=x.y.z` dev-dependency per `GEMINI.md` Rule 12).
3. **Concurrency Schedule & Bounded Model-Checking Gate (`loom` / `cargo kani`):**
   * Run `loom` permutation tests on lock-free `Atomic*` primitives and `cargo kani` (`#[kani::proof]`) harnesses on `unsafe`, FFI, and `#![no_std]`/kernel invariant boundaries when installed.
   * **Conditional Fail-Closed Rule (`GEMINI.md` Rule 8):** When the hardened target contains `unsafe`, FFI, lock-free atomics, or `#![no_std]`/kernel seams and required `miri` or `cargo kani` verification cannot run on the host, list the unverified seam in the `Verification Gap Declaration` and stop in `BLOCKED` status for user review. Pure `#![forbid(unsafe_code)]` safe crates do **not** block when optional nightly `miri` or `cargo kani` toolchains are absent; report them cleanly as skipped non-applicable sensors.
4. **Pre-Flight Subagent Dispatch:**
   * Dispatch `silent-failure-hunter`, `security-boundary-verifier`, and `simplicity-auditor` on Tier 2/3 hardening passes (plus `contract-change-auditor` and `test-adequacy-auditor` whenever Mode 2 `--contract` alters `pub` signatures or error contracts).

---

## 6. Triggers & Reference Modules

* **Slash Command:** `/rust-harden` (defaults to `--internal`; pass `--contract` for `pub` signature tightening).
* **Natural Language Triggers:** `harden rust`, `idiomatic rust cleanup`, `remove rust unwrap and clone debt`, `rust kodunu sertleştir`, `idiomatic rust yap`, `sahiplik borcunu temizle`, `unsafe arındır`.
* **Reference Modules (`skills/rust-harden/references/`):**
  * **Async & Privileged Userspace Hardening:** [references/async-and-userspace.md](./references/async-and-userspace.md)
  * **Kernel, `#![no_std]` & `unsafe` Soundness Hardening:** [references/kernel-and-unsafe.md](./references/kernel-and-unsafe.md)
  * **Game Loops, Graphics (Vulkan/GPU) & Real-Time Audio Hardening:** [references/game-and-realtime.md](./references/game-and-realtime.md)
