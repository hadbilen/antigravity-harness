# C, C++, Application Binary Interface & Embedded Rust Migration Reference

On-demand companion to `skills/rustify/SKILL.md` for C, C++, `#![no_std]` firmware, hardware drivers, Application Binary Interface (`ABI`) contracts, and mixed-binary Foreign Function Interface (`FFI`) migrations.

---

## 1. C and C++ -> Idiomatic Rust Architectural Matrix

| C / C++ Pattern | Idiomatic Rust Replacement | Soundness & Architectural Rationale |
| :--- | :--- | :--- |
| `const T*` / `T*` (non-null single item) | `&T` / `&mut T` | Enforces shared read-only or exclusive mutable aliasing at compile time. |
| `T*` (nullable pointer) | `Option<&T>`, `Option<&mut T>`, or `Option<NonNull<T>>` | Niche optimization gives `Option<&T>` and `Option<fn(...)>` the exact pointer size of C `T*` with zero null-dereference hazard. |
| `const T* buf, size_t len` | `&[T]` (or `&mut [T]` for mutable buffers) | Fat slice bundles base pointer and element count; construct at `FFI` entry only after verifying non-null, alignment, initialized elements, and `len * size_of::<T>() <= isize::MAX` (`std::slice::from_raw_parts` preconditions). |
| `char*` (`NUL`-terminated string) | `&CStr` / `CString` -> `&[u8]` (or `&str` only if UTF-8 is guaranteed) | C strings have no UTF-8 invariant; calling `.to_str()?` blindly rejects valid binary/Latin-1 C inputs. Parse bytes via `CStr::to_bytes()` first. |
| `malloc` / `free` / `std::unique_ptr<T>` | Stack `T` or `Box<T>` (`Drop`) | Deterministic Resource Acquisition Is Initialization (`RAII`). Never call `Box::from_raw`, `CString::from_raw`, `Vec::from_raw_parts`, or cross-module `libc::free` on a foreign heap pointer—allocator mismatch triggers immediate Undefined Behavior (`UB`), so wrap the foreign module's own destructor function inside a custom `Drop` newtype instead. |
| `std::shared_ptr<T>` | Single owner + `&T` borrows, or `Arc<T>` across threads | Refactor ownership hierarchy first; reach for `Arc<T>` only for genuine concurrent shared lifetime. |
| `void* user_data` callback context | Generic `<F: FnMut(...)>` or `Box<Box<dyn Trait>>` thin pointer | Passing `Box<dyn Trait>` directly as `*mut c_void` corrupts pointers because `dyn Trait` is a 2-word fat pointer! Double-box (`Box::into_raw(Box::new(boxed_trait))`) or monomorphize a generic trampoline `extern "C" fn<T>`. |
| Intrusive / cyclic doubly linked lists | `Vec<Node>` + typed index handle (`SlotKey` / `usize`) | Eliminates self-referential lifetimes and dangling node pointers while improving cache locality. |
| C `goto cleanup;` / C++ `try-catch` | `Result<T, E>`, `?`, and scoped `Drop` guards (`scopeguard` if needed) | Makes every cleanup path deterministic without forgotten label jumps or unwinding across C frames. |
| `#define` constants, bitmasks & function macros | Typed `const`, `bitflags`-style newtypes, and `#[inline]` generics | Type-checked at compile time without double-evaluation macro bugs. |

### Foreign Handle Thread-Safety Classification (`Send` / `Sync`)
Raw pointers (`*const T`, `*mut T`, `NonNull<T>`) are `!Send` and `!Sync` in Rust for a reason. Never slap `unsafe impl Send` or `unsafe impl Sync` onto a foreign handle wrapper merely to appease `tokio::spawn` or `PyO3`:
1. **Thread-Affine Foreign Handle (`!Send + !Sync`):** Default when C state uses thread-local storage, single-threaded contexts, or undocumented locking; retain `PhantomData<*const ()>` (`#[pyclass(unsendable)]` in `PyO3`).
2. **Externally Synchronized / Movable Handle (`unsafe impl Send`, `!Sync`):** Permitted only when upstream C documentation guarantees the handle may transfer across OS threads so long as access is exclusive (`&mut self` or wrapped in a `Mutex`).
3. **Concurrently Thread-Safe Handle (`unsafe impl Send + unsafe impl Sync`):** Permitted only when upstream C documentation guarantees internal atomic/mutex synchronization across concurrent callers; cite the exact C contract inside each `// SAFETY:` block.

---

## 2. Binary Layout, Alignment, Bitfields & Integer Semantics

1. **Struct Layout & Padding (`#[repr(C)]`):**
   * Rust's default `repr(Rust)` has unspecified field order and padding. Any struct crossing `FFI`, `mmap`, network headers, or binary file records **must** declare `#[repr(C)]` (or `#[repr(transparent)]` for single-field newtypes), including Direct Memory Access (`DMA`) descriptors.
   * Add compile-time layout assertions (`const _: () = assert!(core::mem::size_of::<Frame>() == 16);` and `core::mem::offset_of!`) matching C `sizeof` / `offsetof`.
   * **Packed Struct Hazard (`#[repr(C, packed)]`):** Never take a reference (`&packed.field`) to an unaligned field inside a `packed` struct—creating an unaligned `&T` is immediate `UB` even without dereferencing it! Copy scalar fields out by value (`let v = packed.field;`) or use `core::ptr::addr_of!(packed.field).read_unaligned()`.
   * **C Bitfields & Foreign `enum` Discriminants:** Rust has no C-compatible bitfield syntax because C bitfield bit-ordering and container straddling are compiler/target ABI-specific; model bitfields as explicit fixed-width integers (`u8` / `u16` / `u32` or audited `bitflags` wrappers) with shift/mask accessors verified by cross-language `sizeof` and bit-pattern differential tests. Never accept a bare `#[repr(C)] enum` directly as an `extern "C"` input parameter from untrusted C callers: C `enum` width varies under `-fshort-enums` and passing an out-of-range integer bit pattern into a Rust `enum` causes instant `UB`—accept the raw fixed-width integer (`c_int` / `u32`) or a `#[repr(transparent)]` integer newtype and convert via `TryFrom`.
   * **Zero-Copy Byte Casting:** Prefer `zerocopy` or `bytemuck` (`Pod`, `Zeroable`, `FromBytes`) over raw `transmute` / `*const Header` casts so padding-byte and invalid-bit-pattern `UB` are rejected at compile time.
2. **C Integer Promotion & Signed vs. Unsigned Overflow:**
   * In C, `uint8_t` and `uint16_t` promote implicitly to signed `int` before arithmetic (`(uint16_t)a * (uint16_t)b` can trigger signed 32-bit overflow `UB` in C!). Make intermediate widths explicit in Rust (`u32::from(a) * u32::from(b)`).
   * C `unsigned` overflow is defined modulo $2^N$ (`a.wrapping_add(b)`), whereas C `signed` overflow is `UB`. Audit hashes, ring-buffer indices, timers, and Cyclic Redundancy Checks (`CRC`) carefully: use `wrapping_*` where modular wraparound is the algorithm, `checked_*` where overflow indicates corrupt input, and `saturating_*` for clamped control loops.

---

## 3. Interop Toolchain Selection (`bindgen` / `cbindgen` vs. `cxx`)

Choose the interop layer from the actual `ABI` boundary discovered in Stage 1:

* **Pure C Boundary (`.h` headers, C hosts, dynamic plugins, or Real-Time Operating System (`RTOS`) kernels):**
  * *Calling C from Rust:* Generate raw bindings in a dedicated `*-sys` module/crate via `bindgen` (allowlisting specific functions/types), capture OS thread-local error state (`std::io::Error::last_os_error()` for `errno` / Windows `GetLastError`) immediately on the calling thread before any allocation, `Drop`, or `.await`, and expose **only** a safe Rust wrapper seam above `*-sys`. If the C library uses `setjmp`/`longjmp`, trap `setjmp` inside a thin C wrapper function before returning an error code to Rust—never allow `longjmp` to jump across Rust stack frames.
  * *Calling Rust from C:* Expose `#[no_mangle] pub unsafe extern "C" fn ...` taking opaque handle pointers or `#[repr(C)]` structs, guard unwinding (`std::panic::catch_unwind` on `std` or `panic = "abort"` on `#![no_std]`), preserve expected `errno` contracts when shimming legacy C functions, pair every `*_new` allocator export with a matching Rust `*_free` export, and generate the C header deterministically via `cbindgen`.
* **Modern C++ Boundary (classes, namespaces, `std::unique_ptr`, `std::vector`, `std::string`, `rust::Slice`):**
  * Prefer **`cxx`** (`#[cxx::bridge]`) over raw `extern "C"` glue: `cxx` statically verifies both the Rust and C++ signatures at build time, catches C++ exceptions into `Result<T, cxx::Exception>` without unwinding across Rust `Drop` frames, and prevents mismatched struct layouts without manual `*mut c_void` casts. Evaluate `autocxx` only when ingesting large existing C++ header surfaces that cannot be wrapped behind a narrow `#[cxx::bridge]` facade.
* **Mixed Build & Sanitizer Wiring (`CMake` / `Meson` / `Cargo`):**
  * Integrate Cargo crates into CMake builds via `Corrosion` pinned to an exact release tag + 40-character Git commit hash (`GEMINI.md` Rule 12), or compile C/C++ shims via the pinned `cc` crate inside `build.rs`.
  * In `incremental-ffi` projects, run the combined C/C++ + Rust test binary with `-fsanitize=address,undefined` (matching compiler sanitizer runtimes when testing cross-language memory ownership).

---

## 4. `#![no_std]`, Embedded Hardware & Safety-Critical Rules

When `target_profile` is `embedded-no-std` or `safety-critical`:

1. **Host-Testable Crate Split & Deterministic Allocation:** Structure pure protocol/math/state-machine logic in a `#![cfg_attr(not(test), no_std)]` core crate so `cargo test`, `miri`, and `cargo kani` execute cleanly on the host, keeping board/register glue in a thin `#![no_std]` hardware crate (`cargo check --lib --bins --target <triple>`). Forbid unbounded recursion and dynamic `alloc` after boot unless authorized in Stage 2; use `heapless::Vec<T, N>` / `heapless::Deque<T, N>` or caller-supplied `&mut [u8]` arenas returning `Error::CapacityExceeded`.
2. **Hardware Register & `volatile` Semantics:** Never model Memory-Mapped Input/Output (`MMIO`) registers as `&mut RegBlock` references—the Rust compiler may insert spurious reads or elide repeated writes on `&mut T`! Access hardware registers exclusively via `svd2rust` / `ral` Peripheral Access Crates (`PAC`), `volatile-register`, or raw pointer `core::ptr::read_volatile` / `core::ptr::write_volatile` (`addr_of_mut!`).
3. **Interrupt & Concurrency Soundness:** Never use raw `static mut` (instant aliasing hazard on re-entrant interrupts). Share state between Interrupt Service Routines (`ISR`) and main loops via `core::sync::atomic::Atomic*` (with explicit `Ordering` rationale) or `critical_section::Mutex<RefCell<Option<T>>>`.
4. **Panic Handler & Binary Footprint:** Configure an explicit deterministic `#[panic_handler]` in the binary/hardware crate (safe hardware fault state + halt/reset, avoiding multi-kilobyte `core::fmt` formatting on constrained microcontrollers; `defmt` when telemetry is used) and verify zero `core::panicking` symbols remain on hot safety-critical paths when required (`cargo bloat` / `llvm-objdump` or `cargo kani` bounded proofs).
