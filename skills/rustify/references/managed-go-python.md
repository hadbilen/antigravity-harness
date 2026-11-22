# Managed & Dynamic Languages -> Rust Migration and Interop Reference

On-demand companion to `skills/rustify/SKILL.md` for migrating or bridging garbage-collected and dynamic runtimes (Go `cgo`, Python `PyO3` + `maturin`, TypeScript/JavaScript `napi-rs` / `wasm`, Ruby Magnus / C ABI, and Java/Kotlin `JNI`) into idiomatic Rust.

---

## 1. Go -> Idiomatic Rust Architectural Matrix

| Go Pattern | Idiomatic Rust Replacement | Soundness & Architectural Rationale |
| :--- | :--- | :--- |
| Returning heap pointers (`return &Config{...}`) | Return owned value (`-> Config`) | Avoids heap allocation pressure; Rust moves values on the stack and applies Return Value Optimization (`RVO`). |
| Shared struct pointers mutated across goroutines | Single task owner + message passing (or scoped `Arc<RwLock<T>>` / atomics) | Prevents deadlocks, data races (`go test -race` gaps), and wrapping every field in `Arc<Mutex<T>>`. |
| `go func()` for network / Input-Output (`I/O`) work | `tokio::task::JoinSet` (draining `.join_next().await`) or awaited `JoinHandle` | Structured cooperative concurrency; never drop an unawaited `tokio::spawn` `JoinHandle` because detached tasks silently swallow `Result::Err` values and panics. |
| `go func()` for compute-heavy loops | `rayon::par_iter()` or `tokio::task::spawn_blocking` | Keeps processor-bound work off async executor worker threads so tail latency does not stall. |
| Unbounded or `chan T` pipelines | `tokio::sync::mpsc::channel(cap)` (bounded) / `oneshot` | Bounded capacity enforces explicit backpressure and prevents Out-Of-Memory (`OOM`) spikes under load. |
| `context.Context` cancellation & deadlines | Future drop cancellation, `tokio::time::timeout`, or `CancellationToken` | Dropping a Rust `Future` cancels work deterministically at `.await` points; use `CancellationToken` when graceful drain/flush is required before drop. |
| Implicit `interface{}` / `any` & type switches | Closed `enum` variants or generic `<T: Trait>` bounds | Moves dispatch and exhaustiveness checking to compile time (`dyn Trait` only for open plugin registries). |
| `if err != nil` + `defer f.Close()` | `#[must_use]` `Result<T, E>` with `?` + automatic `Drop` | Eliminates forgotten `defer` leaks, early-return nil-pointer bugs, and zero-value uninitialized structs (`Go` structs allow missing fields silently; Rust structs require every field at construction). |

### Key Go -> Rust Migration & `cgo` Interop Traps
* **Zero-Value Assumptions:** Go code frequently relies on zero-initialized structs (`var mu sync.Mutex`, nil slices behaving like empty slices on `len`/`append`, reading from a nil map returning zero). In Rust, model optional state explicitly (`Option<T>` / `Default` only where an empty default is domain-valid per `skills/harness/references/mistake-proofing.md`).
* **Blocking Inside `async fn`:** Never call `std::fs`, synchronous `reqwest::blocking`, `std::thread::sleep`, or `std::sync::Mutex` across `.await` points inside an async runtime (`clippy::await_holding_lock`); use `tokio::time::sleep` and async `I/O` or `spawn_blocking`.
* **Go `cgo` Bridge Constraints:** When bridging Go to a Rust `cdylib`/`staticlib` via `cgo`, never retain a Go pointer (`*T` or slice backing buffer) inside Rust after the `cgo` call returns (Go stacks move and Go's garbage collector forbids foreign retention of unpinned Go pointers), and batch records into contiguous byte buffers so `~100 ns` per-call `cgo` stack-switch overhead does not dominate hot loops.

---

## 2. Python -> Idiomatic Rust & `PyO3` Interop Matrix

| Python Pattern | Idiomatic Rust Replacement | Soundness & Architectural Rationale |
| :--- | :--- | :--- |
| Untyped `dict[str, Any]` payloads | Typed `struct` + `#[derive(Serialize, Deserialize)]` (`#[serde(deny_unknown_fields)]` at strict edges) | Parses unstructured boundary data once (`skills/harness/references/mistake-proofing.md` §3), eliminating downstream `KeyError` and `AttributeError` failures. |
| `T \| S \| None` (`Union` / `isinstance` chains) | `Option<DomainEnum>` with exhaustive `match` | Compiler rejects unhandled variants whenever the schema evolves. |
| Exception-driven flow control (`try / except`) | `Option<T>` / `Result<T, DomainError>` combinators | Makes recoverable failure modes explicit in signatures; map each `DomainError` variant `1`-to-`1` to the expected Python exception subclass (`PyKeyError`, `PyIndexError`, `PyTypeError`, `PyOSError`, `PyValueError`) at the outer `#[pyfunction]` / `#[pymethods]` seam. |
| List/dict comprehensions over large arrays | Chained iterators `.iter().filter(...).map(...).collect()` | Fuses transformations into a single pass without intermediate Python object allocations. |
| Compute-bound Python / NumPy hot loops | `PyO3` (`#[pyfunction]`) + `maturin` + Global Interpreter Lock (`GIL`) release (`py.allow_threads` / `py.detach`) | Releases the Python interpreter lock over pure-Rust slices (`&[f64]`, `numpy::PyReadonlyArray`) for true multi-core execution via `rayon`. |

### `PyO3` & `maturin` Hybrid Migration Rules
1. **Separate Pure Rust Core from Python Glue:** Place pure domain types, algorithms, and unit tests in a Rust core module (zero `pyo3` imports in core domain structs!) and keep a thin `py_bindings` adapter module converting `PyObject` / `Bound<'py, PyAny>` <-> domain Rust types once per call. Keep `panic = "unwind"` on `PyO3` extension wheels (`panic = "abort"` terminates the host Python interpreter instead of raising `PanicException`), and mark thread-affine `#[pyclass]` wrappers `#[pyclass(unsendable)]`.
2. **Release the `GIL` Safely & Respect Signals:** Before calling `py.allow_threads(|| ...)` (or `py.detach(|| ...)` in newer `PyO3` releases), extract owned data or borrowed raw slices that do not touch Python heap objects while unlocked, then re-acquire the `GIL` only to construct the final Python return object. In long loops that must hold the `GIL`, poll `py.check_signals()?` periodically so `Ctrl-C` (`KeyboardInterrupt`) is never blocked.
3. **Differential Equivalence Pinning (`pytest` + `cargo test`):** Keep the existing `pytest` suite running against the compiled `maturin develop` wheel alongside `cargo test` (`GEMINI.md` Rule 9). Pay special attention to Python arbitrary-precision `int` (which never overflows in Python but overflows `i64`/`u64` in Rust; use `i128`, `num-bigint`, or explicit overflow `PyOverflowError` checks), passthrough integer-vs-float preservation, negative slice indexing (`arr[-1]`), and `NaN` equality semantics. Note that automated synthetic unit fuzzers cannot reliably generate arbitrary `numpy::PyReadonlyArray` shapes; record application-level integration cases for NumPy array entry points.

---

## 3. TypeScript / JavaScript (`napi-rs` / `wasm`), Ruby & Java / Kotlin Bridges

| Source Runtime | Bridge Seam | Boundary Invariants & Operational Caveats |
| :--- | :--- | :--- |
| **TypeScript / JavaScript** (Node, Bun, Deno, Browser) | `napi-rs` (native server addon) or `wasm-bindgen` / `wasm` (browser or sandboxed target) | `napi` `String` rejects lone UTF-16 surrogates; convert JS UTF-16 code-unit offsets to Rust UTF-8 byte offsets explicitly at the seam. Avoid allocating per-item JS wrapper arrays (`Array.from(order, fn)` can cost `20x` more than a plain `for` loop mapping returned Rust indices back to source items). |
| **Ruby** (`CRuby` / native extension) | `magnus` / C ABI extension | Preserve `Integer` vs. `Float` return types for passthrough values (`Ruby` callers check type identity and integer division semantics). Map Rust `Err("TypeName: message")` deterministically to the expected Ruby exception class without unwinding across the C ABI. |
| **Java / Kotlin** (`JVM` & Android `ART`) | `JNI` (`jni` crate / C ABI, Android NDK `jniLibs/` for `ART`) | Disambiguate overloaded Java method names explicitly (reflection drivers keyed by method name collide on overloads); keep Kotlin top-level and `@JvmStatic` bindings behind explicit wrappers, and require deterministic `.close()` (`AutoCloseable` / `try-with-resources`) on Rust-backed handles instead of relying on garbage-collector finalizers. |

---

## 4. FFI Bridge-Overhead Profiling & Hot-Loop Batching (`--batch` / `FnIndex`)

Crossing any foreign runtime seam (`cgo`, `PyO3`, `napi-rs`, `JNI`, `wasm`) pays fixed argument-marshaling and stack/GC transition costs:

1. **Profile Caller-Inclusive Hot Paths First:** Benchmark the original workload end-to-end (including caller loop and bridge crossing) before choosing a unit. If a single call runs for nanoseconds inside a tight host loop, porting the leaf function alone makes callers slower. Either widen the unit to absorb the outer loop or batch calls across the seam.
2. **Persistent Batch Handle (`--batch fn:param` / `FnBatch`):** Pass the dataset once into Rust (`new FnBatch(items)` in TS/Python/Java, `Mod::FnBatch.new(items)` in Ruby, `NewFnBatch(items)` in Go) and reuse the handle across queries instead of re-marshaling inputs on every iteration. Always close handles explicitly in Go (`defer batch.Close()`) and Java (`try (var batch = ...)`).
3. **Precomputed `pub struct FnIndex`:** Inside the Rust batch handle, define a prepared `pub struct FnIndex` holding one-time preprocessing (lowercased buffers, ASCII fast-path flags, character bitmasks, position tables) so each query scans compact Rust slices without per-call Unicode table lookups or intermediate allocations, returning ranked item indices (`Vec<u32>`) mapped back in a plain host loop.

---

## 5. Cross-Language Semantic Trap Checklist

Audit every ported unit against these recurring cross-language divergence traps before running Stage 5 differential suites:

1. **UTF-16 vs. UTF-8 String Offsets:** JavaScript/TypeScript and Java/Kotlin index UTF-16 code units while Rust `&str` indexes UTF-8 bytes. Whenever indices, slice bounds, or regex match spans cross the seam, translate between UTF-16 code units and UTF-8 byte offsets explicitly (e.g., via a dedicated `utf16` index helper) and document lone-surrogate handling.
2. **Regex Engine & Character Class Semantics (`fancy-regex` vs. `regex`):**
   * Use `fancy-regex` (not `regex`) whenever the source pattern requires lookahead, lookbehind, or backreferences, and always configure an explicit `.backtrack_limit(...)` ceiling via `RegexBuilder` on untrusted inputs to prevent Regular Expression Denial of Service (`ReDoS`).
   * Rust's `regex` crate enables Unicode character classes (`\w`, `\b`, `\d`, `\s`) by default, whereas JavaScript (without the Unicode `u` flag) and Java match ASCII-only `\w`/`\d` by default. Replace `\w` with explicit ASCII classes (`[A-Za-z0-9_]`) when matching ASCII-only originals.
   * Test Unicode case-folding and boundary traps explicitly: **Turkish dotted/dotless `i`/`İ`/`ı`**, **Kelvin sign (`K`, U+212A)**, zero-width joiners, and non-ASCII Unicode digits and whitespace.
3. **Character Classification (`char::is_alphanumeric`):** Rust's `char::is_alphanumeric` matches broader Unicode categories than Java's `Character.isLetterOrDigit` (which operates per UTF-16 code unit on Basic Multilingual Plane letters and decimal digits). Implement an explicit matching predicate when parity with Java character classification is contractual.
4. **Insertion-Ordered Maps & Objects (`indexmap`):** JavaScript objects, Python `dict` (`3.7+`), and Ruby `Hash` preserve insertion order, whereas `std::collections::HashMap` randomizes iteration order per run. Use `indexmap::IndexMap` / `IndexSet` wherever key order reaches serialized JSON, logs, or caller-visible output.
5. **Python & Ruby Numeric & Exception Fidelity:** Preserve `int` vs. `float` types on passthrough numeric values in Python and Ruby instead of widening integers silently to `f64`. Translate Rust `Result::Err(...)` into the source runtime's exact exception subclass; a Rust `panic!` never satisfies a recorded source error.

---

## 6. Two-Run Oracle Noise Taxonomy, `known-diffs.jsonl` & Strangler-Fig Cutover

1. **Two-Run Oracle Noise Taxonomy (`values` / `order` / `lines`):** Run the untouched original application or unit twice on identical inputs before locking golden fixtures and classify any variance explicitly:
   * `values`: inline substrings changed between runs (timestamps, request IDs, temp paths) -> mask explicitly with `[..]` wildcards confined strictly to the exact byte spans that differed between Run 1 and Run 2 of the untouched oracle.
   * `order`: identical output lines emitted in varying order (hash maps, concurrent workers) -> confirm with the user whether ordering is contractual before comparing unordered or sorting deterministically (`BTreeMap` / `indexmap`).
   * `lines`: differing line counts across identical runs (`...` wildcard matching arbitrary stretches) -> **never accept silently**; narrow the wildcard manually or stabilize the fixture input so regressions cannot hide behind `...`.
2. **Explicit Delta Ledger (`known-diffs.jsonl`):** When the user approves a narrow behavioral delta (such as accepted floating-point operation order / FMA tolerance or an `Authorized Sanitization Transition`), record one JSON object per case in `<crate>/known-diffs.jsonl` carrying the original oracle's `expected` value and explicit `approved_in` provenance:
   ```json
   {"fn": "normalize_score", "args": [0.1, 0.2], "expected": 0.3, "actual": 0.30000000000000004, "reason": "IEEE-754 FMA tolerance", "approved_in": "Stage 2 contract / tasks.md ## Authorized Test Modifications"}
   ```
   Keep every original differential assertion intact (`GEMINI.md` Rule 9). Never append entries to `known-diffs.jsonl` during Stage 5 retry loops without explicit user confirmation.
3. **Whole-App Strangler-Fig Progression (`Fallback Rate % -> 0%`):**
   * Start with a shadow front-door (`RUST_ANYTHING_MODE=shadow` returning original results while logging Rust mismatches; `new` switching traffic to Rust; `old` disabling Rust). Restrict `shadow` execution strictly to pure, idempotent, or sandboxed calls (never double-execute mutating writes, external side-effects, or financial charges), bound shadow execution with an explicit timeout (`<= 2x` original p95) and `catch_unwind` isolation, and fail-safe any unknown `RUST_ANYTHING_MODE` or `RUST_ANYTHING_UNIT_<NAME>` environment value to `old` / `original`.
   * Track the **fallback rate** over `100%` of public endpoints and recorded app cases still executing in the original runtime, driving it monotonically toward `0%` while preserving a per-unit runtime **kill switch** (`RUST_ANYTHING_UNIT_<NAME>=original` or build-time toggle for C libraries).
   * Refuse final cutover/lift until fallback rate reaches `0%` and every unit clears all Stage 5 gates (`skills/rustify/SKILL.md` §6, including `#[expect(lint, reason = "...")]` with MSRV `< 1.81.0` fallback). Before deleting fallback glue and kill switches, verify a post-lift artifact or blue-green rollback plan; after lift, replay all recorded app cases against the standalone pure-Rust binary, verify runtime asset embedding, and offer an optional **post-lift reshape** pass (`skills/rust-harden/SKILL.md` or `skills/refactoring/SKILL.md`) to unify legacy file splits into idiomatic Rust modules.
4. **Optional Pinned `rust-anything` CLI / MCP Workflow (`=2.1.0 --locked`):**
   * When available locally (`command -v rust-anything`, verifying `rust-anything --version` matches `2.1.0`, or installed only after explicit user approval via `cargo install rust-anything --version =2.1.0 --locked` per `GEMINI.md` Rule 12) or exposed via `rust-anything mcp`, the subcommands `profile`, `analyze --json`, `bridge [--batch fn:param]`, `record`, `diff`, `bench`, `shadow`, `gate`, and `app {record,replay,front-door,wire,lift}` automate Steps 1–5 for TS/JS, Python, C, Go, Ruby, Java, and Kotlin.
   * When `rust-anything` is absent, reports a mismatched version, errors mid-run, or targets C++/`#![no_std]`/embedded/`safety-critical` crates, fall back immediately to executing the identical discipline manually with native toolchains, golden-vector fixtures, `miri`, sanitizers, and `cargo kani`.
