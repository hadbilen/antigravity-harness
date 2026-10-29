# Go & Python -> Rust Migration and Interop Reference

On-demand companion to `skills/rustify/SKILL.md` for migrating or bridging garbage-collected Go services and dynamic Python modules (`PyO3` + `maturin`) into idiomatic Rust.

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
* **Zero-Value Assumptions:** Go code frequently relies on zero-initialized structs (`var mu sync.Mutex`, nil slices behaving like empty slices on `len`/`append`, reading from a nil map returning zero). In Rust, model optional state explicitly (`Option<T>` / `Default` only where an empty default is domain-valid per `skills/mistake-proofing/SKILL.md`).
* **Blocking Inside `async fn`:** Never call `std::fs`, synchronous `reqwest::blocking`, `std::thread::sleep`, or `std::sync::Mutex` across `.await` points inside an async runtime (`clippy::await_holding_lock`); use `tokio::time::sleep` and async `I/O` or `spawn_blocking`.
* **Go `cgo` Bridge Constraints:** When bridging Go to a Rust `cdylib`/`staticlib` via `cgo`, never retain a Go pointer (`*T` or slice backing buffer) inside Rust after the `cgo` call returns (Go stacks move and Go's garbage collector forbids foreign retention of unpinned Go pointers), and batch records into contiguous byte buffers so `~100 ns` per-call `cgo` stack-switch overhead does not dominate hot loops.

---

## 2. Python -> Idiomatic Rust & `PyO3` Interop Matrix

| Python Pattern | Idiomatic Rust Replacement | Soundness & Architectural Rationale |
| :--- | :--- | :--- |
| Untyped `dict[str, Any]` payloads | Typed `struct` + `#[derive(Serialize, Deserialize)]` (`#[serde(deny_unknown_fields)]` at strict edges) | Parses unstructured boundary data once (`skills/mistake-proofing/SKILL.md` §3), eliminating downstream `KeyError` and `AttributeError` failures. |
| `T \| S \| None` (`Union` / `isinstance` chains) | `Option<DomainEnum>` with exhaustive `match` | Compiler rejects unhandled variants whenever the schema evolves. |
| Exception-driven flow control (`try / except`) | `Option<T>` / `Result<T, DomainError>` combinators | Makes recoverable failure modes explicit in signatures; map each `DomainError` variant `1`-to-`1` to the expected Python exception subclass (`PyKeyError`, `PyIndexError`, `PyTypeError`, `PyOSError`, `PyValueError`) at the outer `#[pyfunction]` / `#[pymethods]` seam. |
| List/dict comprehensions over large arrays | Chained iterators `.iter().filter(...).map(...).collect()` | Fuses transformations into a single pass without intermediate Python object allocations. |
| Compute-bound Python / NumPy hot loops | `PyO3` (`#[pyfunction]`) + `maturin` + Global Interpreter Lock (`GIL`) release (`py.allow_threads` / `py.detach`) | Releases the Python interpreter lock over pure-Rust slices (`&[f64]`, `numpy::PyReadonlyArray`) for true multi-core execution via `rayon`. |

### `PyO3` & `maturin` Hybrid Migration Rules
1. **Separate Pure Rust Core from Python Glue:** Place pure domain types, algorithms, and unit tests in a Rust core module (zero `pyo3` imports in core domain structs!) and keep a thin `py_bindings` adapter module converting `PyObject` / `Bound<'py, PyAny>` <-> domain Rust types once per call. Keep `panic = "unwind"` on `PyO3` extension wheels (`panic = "abort"` terminates the host Python interpreter instead of raising `PanicException`), and mark thread-affine `#[pyclass]` wrappers `#[pyclass(unsendable)]`.
2. **Release the `GIL` Safely & Respect Signals:** Before calling `py.allow_threads(|| ...)` (or `py.detach(|| ...)` in newer `PyO3` releases), extract owned data or borrowed raw slices that do not touch Python heap objects while unlocked, then re-acquire the `GIL` only to construct the final Python return object. In long loops that must hold the `GIL`, poll `py.check_signals()?` periodically so `Ctrl-C` (`KeyboardInterrupt`) is never blocked.
3. **Differential Equivalence Pinning (`pytest` + `cargo test`):** Keep the existing `pytest` suite running against the compiled `maturin develop` wheel alongside `cargo test` (`GEMINI.md` Rule 9). Pay special attention to Python arbitrary-precision `int` (which never overflows in Python but overflows `i64`/`u64` in Rust—use `i128`, `num-bigint`, or explicit overflow `PyOverflowError` checks!), negative slice indexing (`arr[-1]`), and `NaN` equality semantics.
