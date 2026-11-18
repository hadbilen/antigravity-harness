# Async Tokio Services & Privileged POSIX Userspace Hardening

For `skills/rust-harden/SKILL.md`. Load this module when hardening asynchronous Rust services (`tokio`, `futures`), network daemons, IPC workers, file-descriptor boundaries, or privileged Linux/POSIX processes.

## 1. `tokio::select!` Cancellation Safety

Dropping an unfinished future at a `tokio::select!` loser branch aborts that future at its current `.await` suspension point, discarding any partial local buffers or half-executed multi-step writes inside the dropped future:

1. **Use Only Cancel-Safe Arms Directly Inside `select!`:** `mpsc::Receiver::recv`, `oneshot::Receiver` (`&mut rx`), `tokio::time::Sleep` (`tokio::pin!(sleep)`), and `TcpListener::accept` are cancel-safe. Multi-read stream helpers such as `AsyncReadExt::read_exact`, `BufReader::read_line`, and multi-step request/response futures are **not** cancel-safe and lose partial bytes on cancellation.
2. **Pin Stateful Futures Outside the Loop:** When polling a single in-flight operation across loop iterations against a shutdown or heartbeat signal, bind and `tokio::pin!(op)` outside the `loop` and poll `&mut op` inside `tokio::select!` with a completion flag so partial progress is preserved across wakeups.
3. **Commit Domain State Only After `.await` Succeeds:** Never mutate shared counters, sequence numbers, or protocol state *before* an `.await` inside a cancellable branch; compute inputs first, await the cancel-safe I/O primitive, and apply state transitions synchronously after completion.

## 2. Zero Locks Held Across `.await` (`clippy::await_holding_lock`)

1. **Never Hold `std::sync::MutexGuard` or `RwLock*Guard` Across `.await`:** Suspending a task while holding an OS mutex stalls the worker thread when another task on the same thread attempts to lock it, causing deterministic executor deadlocks under load. Enforce `clippy::await_holding_lock = "deny"` on all library and binary targets.
2. **Scope Guards to Tight Synchronous Blocks:** Extract or clone the minimal required command/snapshot inside a dedicated `{ let guard = state.lock()...; ... }` block so `guard` drops deterministically before the next `.await` statement. Prefer `std::sync::Mutex` (or `parking_lot::Mutex`) for short synchronous state mutations and `tokio::sync::Mutex` only when a single serialized resource handle itself must be awaited exclusively.

## 3. Bounded Channels & Explicit Backpressure

1. **Ban `unbounded_channel` on Untrusted or Network-Driven Paths:** `tokio::sync::mpsc::unbounded_channel` disables producer backpressure and converts traffic bursts or slow downstream consumers into process Out-Of-Memory (`OOM`) aborts.
2. **Enforce Fixed Capacities & Admission Limits:** Use `tokio::sync::mpsc::channel(capacity)` with explicit queue bounds, pair listener loops with `tokio::sync::Semaphore` concurrency permits (`acquire_owned().await?`), and apply bounded `tokio::time::timeout(deadline, ...)` wrappers around every external socket read, write, connect, and DNS resolution step.
3. **Explicit Full-Queue Semantics:** Decide and test whether backpressure blocks the producer (`send().await`), sheds load immediately (`try_send()` returning `TrySendError::Full` mapped to HTTP `429` / `503`), or coalesces latest state (`tokio::sync::watch`).

## 4. Blocking I/O & CPU-Bound Isolation (`spawn_blocking`)

1. **Keep Tokio Worker Threads Non-Blocking:** Synchronous filesystem traversal (`std::fs`), SQLite queries, synchronous compression/hashing (`zstd`, `Argon2id`, large `SHA-256`), and blocking FFI calls starve sibling tasks on cooperative async worker threads when they exceed `~100 us`.
2. **Offload Deterministically:** Dispatch blocking syscalls and FFI operations via `tokio::task::spawn_blocking` (propagating `JoinError` panics/cancellations explicitly via `Result`, never `let _ = spawn_blocking(...)`), and route sustained CPU-bound parallel workloads to a dedicated bounded `rayon::ThreadPool`.

## 5. RAII File-Descriptor Ownership (`OwnedFd` / `BorrowedFd`)

1. **Ban Raw `RawFd` (`i32`) Ownership Across Functions:** Storing bare `RawFd` integers risks double-close UB (closing an FD already recycled by another thread onto a socket or database file) and descriptor leaks on early `?` error returns.
2. **Enforce Typed Lifetime-Checked Descriptors:** Represent owned descriptors exclusively with `std::os::fd::OwnedFd` (closing once in `Drop`) and temporary borrows with `BorrowedFd<'a>` via `AsFd::as_fd`. Convert from raw FFI integers via `unsafe { OwnedFd::from_raw_fd(fd) }` immediately after verifying `fd >= 0` inside a single private wrapper.
3. **Mandatory Descriptor Flags:** Open files, pipes, and sockets atomically with `O_CLOEXEC` (`SOCK_CLOEXEC`) so child processes never inherit internal descriptors, and combine `openat` / `O_NOFOLLOW` when operating inside untrusted filesystem directories (avoiding `/proc/self/fd/` race exposures).

## 6. Synchronous Pre-Runtime POSIX Privilege Drop

Linux `setuid`, `setgid`, `setresuid`, `setresgid`, and `setgroups` syscalls operate per-thread at the kernel `cred` level unless coordinated via `nptl` libc wrappers; dropping privileges *after* `#[tokio::main]` spawns background worker threads risks leaving sibling threads running with `root` (`UID 0`) credentials or supplementary groups:

1. **Drop Privileges Before Constructing the Async Runtime:** Write a synchronous `fn main() -> Result<(), AppError>` without `#[tokio::main]`. Bind privileged ports (`< 1024`) or load root-only TLS keys into zeroizing memory first, drop privileges on the single initial OS thread, and only then construct `tokio::runtime::Builder::new_multi_thread().enable_all().build()?`.
2. **Strict Irreversible Ordering (`groups -> gid -> uid`):**
   * Clear supplementary groups first (`nix::unistd::setgroups(&[])?` or verified `libc::setgroups(0, core::ptr::null())`), because `setgroups` requires `CAP_SETGID` before UID drop.
   * Drop real, effective, and saved group IDs (`setresgid(gid, gid, gid)?`).
   * Drop real, effective, and saved user IDs last (`setresuid(uid, uid, uid)?`), and apply `PR_SET_NO_NEW_PRIVS` (`prctl`) plus `seccomp` / `landlock` filters where supported.
3. **Mandatory Return-Code & Negative Escalation Check:** Check every privilege syscall return value via `Result` without `.unwrap()`. Immediately after `setresuid`, execute a negative verification probe attempting `setuid(Uid::from_raw(0))` and `seteuid(Uid::from_raw(0))`: both calls **must** fail with `Errno::EPERM` (aborting startup immediately if regaining `UID 0` succeeds).
