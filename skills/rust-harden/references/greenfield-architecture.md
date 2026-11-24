# Greenfield Rust Crate & Workspace Architecture (`--greenfield`)

For `~/.gemini/config/skills/rust-harden/SKILL.md`. Load this module when designing or scaffolding a new Rust crate, service, Command-Line Interface (`CLI`), library, or Cargo workspace from scratch so ownership boundaries, lint gates, supply-chain cooldowns, and structured error seams are established on day 1 without accruing borrow-checker or panic debt.

## 1. Workspace & Crate Partitioning (`core` / `domain` / `bin` / `ffi`)

Do not create speculative micro-crates for small tools (`GEMINI.md` Rule 4): start with a single crate (`src/domain/` + `src/lib.rs` + `src/main.rs`) for Tier 1/2 utilities, and promote to a multi-crate Cargo workspace once isolated `unsafe`/Foreign Function Interface (`FFI`) seams, reusable library boundaries, or separate target triples (`#![no_std]` vs. host) justify distinct compilation units:

1. **Pure Domain & Core Crates (`crates/<app>-core` / `crates/<app>-domain`):**
   * Enforce `#![forbid(unsafe_code)]` at the crate root (`lib.rs`) and keep zero transport, CLI, database, or filesystem imports inside domain logic.
   * For portable or embedded targets, declare `#![cfg_attr(not(test), no_std)]` so deterministic unit tests run directly on the host triple while production builds target `#![no_std]`.
2. **Thin Binary Entrypoint Crates (`crates/<app>-cli` / `crates/<app>-bin` / `crates/<app>-server`):**
   * Own CLI argument parsing, environment/config loading, dependency wiring, runtime construction (e.g., synchronous privilege drop before `tokio` runtime startup per [async-and-userspace.md](./async-and-userspace.md)), and structured exit-code or status translation.
3. **Isolated Boundary & Adapter Crates (`crates/<app>-sys` / `crates/<app>-ffi` / `crates/<app>-hal` / `crates/<app>-storage`):**
   * Confine every unavoidable `unsafe` block, raw FFI call, or Hardware Abstraction Layer (`HAL`) register access inside minimal private safe wrappers exposing safe domain types upward.
   * Keep dependency edges strictly acyclic and inward (`bin -> adapters/ffi -> core/domain`); forbid reverse edges (`core/domain -> bin`, `core/domain -> storage/transport`) and cyclic crates.
   * For workspaces with `>= 5` member crates, verify acyclic inward layer boundaries mechanically in CI with `cargo metadata --no-deps --format-version 1` (asserting core/domain crates never depend on adapter/bin crates) and optionally check portable pure cores with `cargo check -p <app>-core --target wasm32-unknown-unknown` to prove zero accidental OS/filesystem/network leakage.

## 2. Edition `2024`, MSRV, `[workspace.lints]`, `clippy.toml` & Publish-Age Cooldowns

Pin toolchain baselines, lint policies, and registry cooldowns at the workspace root before adding application crates:

1. **Workspace `Cargo.toml` (`resolver = "3"`, Edition `2024`, Explicit MSRV & Partitioned Lints):**
   * Set `edition = "2024"` and an explicit Minimum Supported Rust Version (`MSRV`): pin `rust-version = "1.100.0"` when enabling `[workspace.lints.cargo]` (`cargo::unused_dependencies`, stabilized in Rust `1.100.0`), Cargo RFC 3923 publish-age cooldowns, or stabilized `core::mem::DropGuard` / `core::alloc::Allocator` (use `rust-version = "1.85.0"` for the Edition `2024` baseline when omitting `[workspace.lints.cargo]` and publish-age settings).
   * Enforce `#![forbid(unsafe_code)]` per safe crate rather than pairing workspace-wide `unsafe_code = "forbid"` with `allow_attributes = "deny"` when an isolated `*-ffi` or `*-hal` member exists:
   ```toml
   [workspace]
   resolver = "3"
   members = [
     "crates/app-core",
     "crates/app-cli",
     "crates/app-ffi",
   ]

   [workspace.package]
   edition = "2024"
   rust-version = "1.100.0"

   [workspace.lints.rust]
   unsafe_op_in_unsafe_fn = "deny"
   static_mut_refs = "deny"
   unused_must_use = "deny"

   [workspace.lints.clippy]
   undocumented_unsafe_blocks = "deny"
   multiple_unsafe_ops_per_block = "deny"
   let_underscore_must_use = "deny"
   await_holding_lock = "deny"
   unwrap_used = "deny"
   expect_used = "deny"
   panic = "deny"
   indexing_slicing = "deny"

   # Requires Rust >= 1.100.0 (omit this table when pinning rust-version = "1.85.0")
   [workspace.lints.cargo]
   unused_dependencies = "warn"
   ```
   * Inherit package metadata and lints cleanly in every member crate `Cargo.toml`:
   ```toml
   [package]
   name = "app-core"
   version = "0.1.0"
   edition.workspace = true
   rust-version.workspace = true

   [lints]
   workspace = true
   ```
2. **Test-Friendly `clippy.toml` (`GEMINI.md` Rule 9):**
   * Keep production targets panic-free and bounds-checked without breaking idiomatic `#[test]` assertions or fixture indexing by placing `clippy.toml` at the workspace root (and enforcing `clippy::cast_possible_truncation` against production targets via `--lib --bins` in §6):
   ```toml
   allow-unwrap-in-tests = true
   allow-expect-in-tests = true
   allow-panic-in-tests = true
   allow-indexing-slicing-in-tests = true
   ```
3. **Supply-Chain Publish-Age Cooldown (`.cargo/config.toml`, Rust/Cargo `>= 1.100.0`) & Pinning:**
   * On Cargo `>= 1.100.0` (RFC 3923), configure a `"3 days"` duration-string registry publish-age cooldown in `.cargo/config.toml` when resolving public `crates.io` packages, pin dependencies explicitly (`=x.y.z`), commit `Cargo.lock` for binaries and services, and enforce `--locked` in CI. For documented zero-day security advisories requiring an immediate patched crate release, run a scoped one-shot override (`CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow cargo update -p <crate> --precise <x.y.z>`) and record the advisory ID in the commit message:
   ```toml
   [registry]
   global-min-publish-age = "3 days"

   [registries.crates-io]
   min-publish-age = "3 days"

   [resolver]
   incompatible-publish-age = "deny"
   ```
4. **Optional Large-Workspace Dev Build Profile:**
   * In larger workspaces with heavy third-party crates, reduce incremental link time and debug-info disk footprint while keeping readable backtraces and fast dependency execution (omit on small single-crate utilities):
   ```toml
   [profile.dev]
   debug = "line-tables-only"

   [profile.dev.package."*"]
   opt-level = 2
   debug = false
   ```

## 3. Error Boundaries: `thiserror` Libraries vs. `anyhow` Binaries

Separate typed library error contracts from operator-facing application diagnostics from the first commit:

1. **Library, Domain & Protocol Crates (`thiserror`):**
   * Define focused, typed `#[derive(Debug, thiserror::Error)]` enums (adding `#[non_exhaustive]` on public semver-governed error enums) and return `#[must_use]` `Result<T, DomainError>`.
   * Never expose `anyhow::Error` in library public signatures, and never discard failures silently with `let _ = ...`, `.ok()`, or `.unwrap_or_default()`.
2. **Binary, CLI & Daemon Entrypoints (`anyhow`):**
   * Use `anyhow::Result` with `.with_context(|| ...)` only at top-level application edges (`main.rs`, command dispatchers) to attach operational context and map typed domain failures cleanly onto documented exit codes or transport error responses.
3. **Zero Recoverable Panics:**
   * Never use `.unwrap()`, `.expect()`, or `panic!()` on recoverable I/O, parsing, or state errors. Reserve an explicit `// INFALLIBLE: <why>` comment paired with `#[expect(clippy::expect_used, reason = "...")]` strictly for provably impossible states in non-`safety-critical` crates outside `extern "C"` unwind seams.

## 4. Day-1 Single Ownership, `newtype`, `enum` & `typestate` APIs

Model invariants in types and ownership graphs before implementing function bodies (`~/.gemini/config/skills/harness/references/mistake-proofing-languages.md`):

1. **Single Owner First (`Zero Arc<Mutex<T>> Reflex`):**
   * Assign every mutable resource a single authoritative owner. Pass `&mut State` down synchronous call stacks, accept read-only borrowed views (`&str`, `&[T]`, `&Path`) in function parameters, return `Cow<'_, str>` only when allocation is conditional, and isolate shared concurrent state inside one owner task fed by a bounded `mpsc::channel(cap)`.
2. **Parse at Edges into `newtype` Wrappers & Exhaustive `enum`s:**
   * Replace primitive strings, raw integers, and boolean flags at domain boundaries with `newtype` structs carrying a private inner field and fallible `TryFrom` / `new() -> Result<Self, DomainError>` constructors so holding the value is compile-time proof of validity.
   * Model finite domain states as algebraic `enum`s where each variant owns only its valid payload; avoid catch-all `_ =>` arms in domain `match` expressions so newly added states fail compilation until handled.
3. **Targeted `typestate` for High-Hazard Lifecycles:**
   * Apply ownership-consuming `typestate` transitions (`self -> NextState` with zero-sized marker types) strictly on dangerous sequences where out-of-order execution breaks safety or security (authentication handshakes, privilege drop, transactional commits, hardware initialization); omit `typestate` ceremony on plain data records (`GEMINI.md` Rule 4).
4. **Bounded Ingress & Fallible Allocation:**
   * Validate untrusted byte sizes, collection lengths, and nesting depth before allocating; use `usize::try_from`, `checked_mul`, and `Vec::try_reserve_exact` so corrupt inputs return `Err(...)` instead of aborting on Out-Of-Memory (`OOM`).

## 5. Self-Expiring Lint Suppression Hygiene (`#[expect]`)

1. **Prefer `#[expect(lint, reason = "...")]` Over `#[allow(...)]`:** On Rust `1.81+` and Edition `2024`, annotate every justified local suppression with `#[expect(lint, reason = "...")]` so `rustc` automatically flags `unfulfilled_lint_expectations` the moment refactoring removes the underlying condition.
2. **Narrow Scope Only:** Attach suppressions to the smallest expression, statement, or item; forbid crate-wide `#![allow(warnings)]` or `#![allow(clippy::all)]` attributes.
3. **Older MSRV Fallback:** Only when a workspace explicitly pins `rust-version < "1.81.0"`, fall back to item-scoped `#[allow(lint)] // MSRV < 1.81: <reason>`.

## 6. Greenfield Verification Gate & Domain Co-Loading

Run deterministic verification on the initial skeleton and every subsequent vertical slice (alongside `~/.gemini/config/skills/rust-harden/SKILL.md` §5):

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo clippy --lib --bins -- -D clippy::cast_possible_truncation
cargo test
```

* If the workspace includes an isolated `*-ffi` or `*-hal` crate with `unsafe` blocks, run `cargo +nightly miri test` over pure-Rust `unsafe` helpers and obey the conditional fail-closed rule (`~/.gemini/config/skills/rust-harden/SKILL.md` §5).
* Co-load the matching runtime reference module when the new workspace targets specialized layers: [async-and-userspace.md](./async-and-userspace.md) (Tokio services/daemons/POSIX privileges), [kernel-and-unsafe.md](./kernel-and-unsafe.md) (`#![no_std]`/embedded/kernel), or [game-and-realtime.md](./game-and-realtime.md) (fixed-timestep games/Vulkan/GPU/real-time audio).
