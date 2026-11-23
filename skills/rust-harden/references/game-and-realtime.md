# Game Loops, Graphics (Vulkan/GPU) & Real-Time Audio Hardening

For `~/.gemini/config/skills/rust-harden/SKILL.md`. Load this module when hardening Rust games, fixed-timestep simulations, Vulkan / `wgpu` / graphics renderers, real-time audio digital signal processing (`DSP`) callbacks, or latency-sensitive interactive engines. Co-load `~/.gemini/config/skills/game-engineering/SKILL.md` for loop architecture and `~/.gemini/config/templates/vulkan.SKILL.template.md` (copied to `.agents/skills/vulkan/SKILL.md`) for Vulkan `1.3`/`1.4` pipelines.

## 1. Per-Frame Heap Allocation & Cache Hygiene (`1,000`-Tick Allocation Check)

Per-frame heap allocations (`Vec::push` growth, `String` formatting, `Box::new`, transient `HashMap` creation) trigger allocator lock contention and frame-time spikes across `16.67 ms` (`60 Hz`) and `8.33 ms` (`120 Hz`) frame budgets:

1. **Zero Steady-State Frame Allocations:** Pre-allocate entity pools, command queues, collision scratch vectors, and vertex/index staging buffers during level or scene initialization, calling `.clear()` (preserving heap capacity) at frame boundaries. Use stack-backed or fixed-capacity buffers for transient HUD text and per-tick scratch lists.
2. **Enum Footprint & Cache Locality (`clippy::large_enum_variant`):** Enforce `clippy::large_enum_variant = "deny"` on library and binary targets (`Box` rare oversized variants so entity/event enums stay cache-line compact), and store hot simulation components in contiguous `Vec<T>` / Structure-of-Arrays (`SoA`) tables instead of pointer-chasing trees.
3. **Deterministic `1,000`-Tick Allocation Check:** Add a dedicated integration test binary (`harness = false` or executed with `--test-threads=1` so parallel `cargo test` sibling threads and `libtest` cannot pollute counts) backed by a lock-free `GlobalAlloc` wrapper (guarded by a `thread_local` / atomic active flag and counting `alloc`, `alloc_zeroed`, and `realloc`) that runs warm-up initialization followed by `1,000` consecutive simulation ticks (`step_tick`) and asserts `0` steady-state heap allocations across all `1,000` ticks.

## 2. Generational Arenas vs. `Rc<RefCell<T>>` / `Arc<Mutex<T>>`

Modeling scene graphs, parent-child transforms, AI targets, or projectile owners with `Rc<RefCell<Entity>>` or `Arc<Mutex<Entity>>` introduces reference-count cycles (silent memory leaks), runtime `BorrowMutError` panics, and cache misses:

1. **Flat Generational Arena Storage:** Store entities in contiguous `Vec<Slot<T>>` arenas (or pinned crates such as `slotmap` / Entity Component System (`ECS`) registries) addressed by opaque `Copy` handles (`struct EntityId { index: u32, generation: u32 }`).
2. **Stale-Handle Safety:** Increment the slot generation on removal so stale handles resolve safely to `None` instead of aliasing a recycled slot or panicking at runtime. Pass `&mut World` or disjoint component slice borrows down simulation phases (`step_physics`, `resolve_collisions`, `evaluate_ai`) with zero interior-mutability locks.

## 3. Deterministic Simulation Ordering (Non-`HashMap` Iteration)

`std::collections::HashMap` and `std::collections::HashSet` seed `RandomState` from OS entropy on every process launch, causing non-deterministic entity updates, physics resolution divergence, and broken lockstep/replay tests:

1. **Ban `HashMap` Iteration in Simulation State:** Never iterate `std::collections::HashMap` or `HashSet` when order affects physics impulses, damage tie-breaking, AI targeting, spawn order, or serialized state hashes. Use dense arena indices (`Vec`), `BTreeMap` / `BTreeSet`, or `indexmap::IndexMap` backed by a fixed-seed hasher (and sort keys explicitly before crossing simulation or network outputs).
2. **Explicit Seeded Pseudo-Random Number Generation (`PRNG`):** Store an explicitly seeded deterministic PRNG (`ChaCha8Rng` / `SmallRng` / `SplitMix64`) inside the simulation state struct and pass `&mut rng` explicitly; forbid `rand::thread_rng()` or wall-clock `SystemTime::now()` inside simulation ticks.

## 4. Floating-Point Determinism & `NaN` / `total_cmp` / Clamp Guards (`f32` / `f64`)

A single `NaN` or `Inf` entering physics transforms, camera matrices, spatial hashes, or audio filters poisons downstream state or panics unchecked comparators:

1. **Ban `.partial_cmp(...).unwrap()`:** Never sort render keys, depth buffers, or AI scores with `a.partial_cmp(b).unwrap()` (which panics immediately on `NaN`). Use `f32::total_cmp` / `f64::total_cmp` for total ordering without panics.
2. **Boundary Sanitization & Finite Clamps:** Validate external inputs, deserialized transforms, and physics deltas with `.is_finite()` and `.clamp(min, max)`. Guard vector normalization (`len_sq > EPSILON` before dividing by `len_sq.sqrt()`) and clamp frame `dt` (`max_frame_dt`) before fixed-timestep accumulation (`FIXED_DT`) to prevent spiral-of-death stalls.

## 5. GPU / Vulkan / Audio Resource Lifetime (`Drop`, Swapchain & Lock-Free SPSC)

1. **Reverse-Order GPU / Vulkan `Drop` Discipline:** Rust drops struct fields in **top-to-bottom declaration order**, and raw `ash::vk::*` handles are `Copy` with no built-in `Drop` implementation. Wrap raw GPU handles in explicit RAII structs, declare child resources (pipelines, descriptor pools, image views, buffers/images, GPU allocator, swapchain, command pools, fences/semaphores) **above** logical `Device`, `Surface`, OS `Window` (dropping `Surface` before `Window` per `VUID-vkDestroySurfaceKHR-surface-01266`), and `Instance` handles, and wait for GPU quiescence (`vkDeviceWaitIdle` or bounded timeline wait, logging and continuing without `.unwrap()` on `DEVICE_LOST` so `Drop` never double-panics during unwind) so validation layers report `0` destroyed-while-in-use or leaked handles.
2. **Swapchain `Outdated` / `Lost` & Minimized-Window Resilience:** Never `.unwrap()` swapchain acquire or present outcomes. Handle `VK_ERROR_OUT_OF_DATE_KHR`, `VK_SUBOPTIMAL_KHR`, `VK_ERROR_SURFACE_LOST_KHR` (recreate surface and swapchain), `VK_ERROR_DEVICE_LOST`, `wgpu::SurfaceError::Outdated`, `wgpu::SurfaceError::Lost`, `wgpu::SurfaceError::Timeout` (skip frame cleanly), `wgpu::SurfaceError::OutOfMemory` (fail cleanly without a spin-retry loop), and zero-extent minimized windows explicitly by pausing submission and recreating swapchain images and dependent attachments idempotently.
3. **Hard Real-Time Audio Thread Isolation (Lock-Free `SPSC`):** OS audio render callbacks execute on real-time priority threads where priority inversion causes immediate audio glitches/dropouts. Inside audio callbacks, strictly forbid mutex locks (`std::sync::Mutex`, `RwLock`), heap allocation, **heap deallocation (`Drop` of owned `Vec`/`Box`/`Arc` payloads)**, blocking I/O, logging syscalls, and panics. Bridge control messages and sample blocks between the game/UI thread and audio thread exclusively over bounded lock-free Single-Producer Single-Consumer (`SPSC`) ring buffers (`rtrb` / `ringbuf` or verified `Atomic*` SPSC queues using paired `Acquire`/`Release` ordering validated under `loom` / `miri`) carrying `Copy`/pre-allocated payloads (or returning retired heap buffers to the UI thread over a dedicated drop SPSC queue), with explicit underrun policy (output silence `0.0` with zero spin-wait) and overrun policy (drop or coalesce oldest/newest control updates cleanly).

## 6. Bounded Binary Packet, Replay & Save Deserialization

Untrusted multiplayer packets, community mods, replays, and local save files must never trigger panics or Out-Of-Memory (`OOM`) aborts via forged length prefixes:

1. **Header & Ceiling Validation Before Allocation:** Require an explicit magic tag, fixed endianness (e.g., little-endian), `schema_version` (`~/.gemini/config/skills/game-engineering/SKILL.md`), and payload integrity checksum (`CRC32` / `BLAKE3`). Enforce hard ceilings on packet bytes, entity/chunk counts (`MAX_PACKET_BYTES`, `MAX_ENTITIES`), recursion depth (`MAX_NESTING_DEPTH`, e.g. `<= 32`), and decompressed payload size (`MAX_DECOMPRESSED_BYTES`), verify `count.checked_mul(min_elem_bytes) <= remaining_bytes` before allocation (blocking small-packet allocation amplification), validate counts with `usize::try_from` / `checked_mul`, and allocate via `Vec::try_reserve_exact` (or bounded codec limits such as `bincode` `with_limit`).
2. **Fail-Closed Quarantine & Atomic Save Commits:** Return typed `Err(DecodeError::...)` on truncated, checksum-mismatched, unknown-version, or non-finite (`NaN`/`Inf`) payloads; write saves via atomic temp file + `fsync` + rename so power loss or crashes leave prior backups intact, and quarantine corrupt save slots cleanly without crashing the engine.

## 7. Verification Gate for Game & Real-Time Crates

Run deterministic checks alongside `~/.gemini/config/skills/rust-harden/SKILL.md` §5:
```bash
cargo check --all-targets
cargo clippy --lib --bins -- -D warnings -D clippy::large_enum_variant -D clippy::unwrap_used -D clippy::expect_used -D clippy::indexing_slicing
cargo test
```
* Execute the headless `1,000`-tick zero-allocation test and fixed-seed replay determinism test (two runs from identical seed and input stream produce byte-identical state hashes).
* Run `cargo +nightly miri test` over custom generational arenas, `unsafe` FFI/render wrappers, and lock-free `SPSC` ring buffers (`loom` for custom atomic SPSC primitives), and execute `~/.gemini/config/templates/vulkan.SKILL.template.md` Stage 3 (`spirv-val`, `VK_LAYER_KHRONOS_validation` with Sync Validation, and headless Lavapipe) for Vulkan targets.
