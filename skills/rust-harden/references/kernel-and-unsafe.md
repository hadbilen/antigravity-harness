# `#![no_std]`, Embedded, OS Kernel & Low-Level `unsafe` Hardening

For `skills/rust-harden/SKILL.md`. Load this module when hardening `#![no_std]` crates, OS kernel modules, hypervisors, device drivers, interrupt handlers, syscall boundaries, DMA engines, or lock-free `unsafe` data structures.

## 1. `#![no_std]` & Fallible Allocation Discipline (`ENOMEM`)

Default `alloc::vec::Vec::push`, `vec![]`, `Box::new`, and `String::from` abort or invoke the global `#[alloc_error_handler]` on allocation failure, enabling unprivileged callers to panic a kernel or embedded controller via heap exhaustion:

1. **Fallible Heap Growth Only:** On every untrusted or runtime-sized `#![no_std]` + `alloc` path, enforce `Vec::try_reserve` / `Vec::try_reserve_exact` before pushing elements and `Box::try_new` (or allocator-aware `Vec::new_in` / `Box::new_in` via `core::alloc::Allocator`) mapped explicitly to `Err(KernelError::OutOfMemory)` (`ENOMEM`).
2. **Host-Testable Pure Cores:** Use `#![cfg_attr(not(test), no_std)]` on hardware-independent ring buffers, allocators, page-table walkers, and parsers so `cargo test` and `cargo +nightly miri test` execute deterministically on the host target alongside cross-compiled `--target <triple> --lib --bins` checks.

## 2. Framekernel Safe / `unsafe` Crate Split

Porting C kernel patterns file-by-file scatters `unsafe` raw pointers across schedulers, filesystems, and network stacks. Enforce a strict **Framekernel** boundary:

1. **Minimal Trusted Computing Base (`TCB`) Framework Crate:** Isolate CPU control registers, MMU page tables, trap frames, interrupt controllers, raw MMIO (`read_volatile` / `write_volatile`), and DMA primitives inside a dedicated low-level framework crate enforcing `unsafe_op_in_unsafe_fn = "deny"`, `static_mut_refs = "deny"`, `undocumented_unsafe_blocks = "deny"`, and `multiple_unsafe_ops_per_block = "deny"`.
2. **`#![forbid(unsafe_code)]` Subsystem Crates:** Export safe capability tokens (`PhysFrame`, `VmIo`, `IrqLine`, `DmaStreamSlice`, `UserSlice`) from the framework crate so upper OS subsystems (VFS, TCP/IP, process table, drivers) compile under crate-root `#![forbid(unsafe_code)]`.

## 3. Interrupt-Safe Spinlock Ordering (`SpinLockIrqSave`)

1. **Never Acquire an Interrupt-Shared Spinlock With Local IRQs Enabled:** If thread context acquires a plain `SpinLock` and a hardware interrupt fires on the same CPU core whose handler attempts to acquire that same lock, the core spins forever in an unrecoverable single-CPU deadlock. Use `SpinLockIrqSave` wrappers that save IRQ flags and disable local interrupts *before* atomic lock acquisition and restore the saved IRQ state in `Drop`.
2. **Strict Lock-Level Hierarchy & Non-Sleeping Critical Sections:** Assign compile-time or documented lock ranks (`Rank 1 -> Rank 2`) so locks are never acquired out of order across cores. Never sleep, yield, trigger demand page faults, or invoke blocking allocators while holding any spinlock or IRQ-disabled guard.

## 4. Syscall Boundary Opacity (`UserSlice` / `UserPtr`, SMAP/PAN & TOCTOU)

1. **Never Dereference User-Space Addresses as Rust References (`&T` / `&[u8]`):** User virtual addresses may be unmapped, misaligned, pointing into kernel space, or concurrently mutated by another user thread; forming `&[u8]` over user memory causes immediate Rust aliasing Undefined Behavior (`UB`) even before a page fault occurs.
2. **Opaque `UserPtr` / `UserSlice` Copy-In Semantics:** Represent syscall pointer arguments as opaque `UserSliceRead` / `UserSliceWrite` handles backed by architecture fault-table `copy_from_user` / `copy_to_user` routines:
   * Validate `[addr, addr.checked_add(len))` lies strictly below `USER_SPACE_MAX` and enforce explicit byte-count ceilings before reserving kernel buffers (`Vec::try_reserve_exact`).
   * Scope x86 `SMAP` (`STAC` / `CLAC`) and ARM64 `PAN` hardware user-access windows strictly around the low-level copy instructions, never leaving user-memory access enabled across general Rust code.
   * **Single-Fetch Invariant (`Zero Double-Fetch TOCTOU`):** Copy user headers and payloads into kernel-owned memory **once**, then validate lengths, offsets, and discriminants exclusively against the private kernel copy so racing user threads cannot swap values between check and use.

## 5. DMA Buffer `Pin` & Hardware-Quiesced `Drop` Safety

1. **Physical Address Stability & Memory Barriers:** Buffers handed to Bus-Mastering Direct Memory Access (`DMA`) devices must reside in physically contiguous or IOMMU-pinned frames wrapped in `Pin` (or non-movable `DmaBuffer` handles) so Rust moves never relocate backing memory mid-transfer. Issue explicit architecture/bus memory barriers (`Ordering::Release` + MMIO write fence) between descriptor writes and device doorbell register pokes, and `Ordering::Acquire` / cache invalidation before reading device-written descriptors.
2. **Active-DMA `Drop` Hazard & Quarantine Rule:** If a future or driver handle owning a `DmaBuffer` is cancelled or dropped while the PCIe/SoC device is still transferring into that physical address, freeing the frames back to the page allocator causes silent cross-process memory corruption (`Use-After-Free by Hardware`):
   * `Drop` must synchronously abort/reset the hardware DMA channel and poll the hardware status register until transfer quiescence is confirmed (or IOMMU-unmap and flush IOTLB entries synchronously).
   * If hardware quiescence times out on faulted silicon, **quarantine (intentionally leak) the physical frames** into a poisoned zombie list and log a hardware fault; never return non-quiesced DMA frames to the general allocator.

## 6. `8-16 KB` Kernel Stack Ceiling

Kernel threads execute on fixed, non-expanding `8 KB` or `16 KB` stacks without guard-page growth:

1. **Zero Unbounded Recursion:** Convert recursive parsers, tree traversals, and release chains into iterative loops backed by fallible `Vec::try_reserve` worklists or intrusive links.
2. **Mechanical Stack-Frame Lints:** Enforce `[lints.clippy]` `large_stack_frames = "deny"` and `large_stack_arrays = "deny"` in `Cargo.toml` paired with `clippy.toml` thresholds (`stack-size-threshold = 2048`, `array-size-threshold = 512`), constructing large structs directly in pre-allocated heap/slab slots (`Box::try_new_uninit` + field initialization) instead of materializing multi-kilobyte rvalues on the stack first.

## 7. `Atomic*` Memory Ordering & Formal Proof Harnesses (`loom` & `kani`)

1. **Paired Ordering Documentation:** Never guess `Ordering::Relaxed` on synchronization variables or sprinkle `Ordering::SeqCst` without naming the invariant. Every `Acquire`, `Release`, `AcqRel`, or `fence` call site must document in an inline comment the exact paired atomic operation and the non-atomic memory accesses synchronized across the happens-before edge.
2. **Exhaustive Interleaving & Symbolic Verification:**
   * Verify lock-free queues, reference counts, seqlocks, and state flags under `#[cfg(loom)]` (`loom::model`) to explore weak-memory thread schedules deterministically.
   * Author bounded `#[kani::proof]` (`cargo kani`) harnesses with `kani::any()` symbolic inputs and `kani::assume(...)` preconditions over `unsafe` index calculations, bitfield packers, ring-buffer wraparound math, and `UserSlice` range checks to prove absence of panics, arithmetic overflow, and out-of-bounds pointer offsets.
