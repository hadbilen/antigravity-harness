---
name: sweetspot
description: >-
  Controlled, behavior-preserving performance, memory (RAM), disk/artifact footprint, and network I/O (download/upload
  bandwidth and round-trip latency) optimization with holistic Pareto sweet-spot analysis and multi-file hot-path
  discovery for working software (scripts, backends, real-time game frame rates, command-line cold-start latency,
  web/app bundles, networked services, and compiled executables across formats and operating systems). Supports axis
  flags: --all (alias --holistic, default: 3-axis local or 4-axis when network boundaries exist), --time (alias
  --speed), --memory (alias --ram), --disk (alias --size), and --net (alias --network). Profiles first across all active
  axes, classifies opportunities into 3 zones (In-Scope Controlled, Trade-Off / Identity-Shifting Approval Required, or
  Already at Sweet Spot), and refuses placebo edits. Invoke with /sweetspot or /optimize, or when the user says
  "sweetspot", "optimize et", "bu oyunu optimize et", "bu yazılımı optimize et", "hızlandır", "performans
  optimizasyonu", "kare hızını artır", "bellek kullanımını düşür", "RAM optimizasyonu", "disk alanını küçült",
  "boyutunu küçült", "ağ optimizasyonu", "indirme/yükleme hızlandır", or "gecikmeyi düşür". Not for broken code or
  unexpected regressions (use 'diagnosing-bugs') or pure structural cleanup without speed, memory, size, or network
  goals (use 'refactoring').
---

# Sweetspot — Controlled Performance, Memory, Footprint & Network Optimization Gate

Optimizing an already working, stable system requires stricter discipline than fixing a broken one. Unconstrained optimization prompts across execution speed, Random-Access Memory (`RAM`), disk footprint, or network Input/Output (`I/O`) often trigger three failure modes in language models: inventing unmeasured micro-optimizations that degrade readability, silently breaking edge-case behavior or data fidelity, or mutating a project's architecture and purpose without asking. `sweetspot` enforces **controlled, behavior-preserving optimization** across three universal local resource axes—**Time (Speed/Latency)**, **Memory (`RAM` Footprint)**, and **Disk (Binary, Bundle & Storage Footprint)**—plus a **Conditional 4th Axis for networked systems—Network (`I/O` Download/Upload Bandwidth & Round-Trip Time (`RTT`) Latency)**, backed by multi-file hot-path discovery, repeatable measurements, explicit **Cross-Axis Trade-off** governance, and an honest stop condition when a system reaches its **Pareto Frontier** (the holistic sweet spot where all active axes meet without structural compromise).

---

## 1. Core Invariants

1. **Working Baseline Prerequisite:** Apply `sweetspot` only to systems whose functional behavior is currently working and stable. If tests are failing or the system crashes, route to `skills/diagnosing-bugs/SKILL.md` first.
2. **Behavior & Data Preservation (`GEMINI.md` Rule 9):** A controlled optimization leaves every observable contract identical: return values, output formatting, error boundaries, determinism, side effects, wire protocol compatibility, and stored data fidelity. Never delete user data, audit logs, or required assets to claim a memory, disk, or network reduction.
3. **Measure Before and After (`GEMINI.md` Rule 8):** Intuition about where time, memory, disk space, or network bandwidth is spent holds zero evidentiary weight. Every optimization claim requires a repeatable before-and-after measurement on the target machine (using deterministic loopback harnesses or exact payload/request counters for network boundaries, never noisy external internet jitter).
4. **Holistic Multi-Axis Default, Explicit Axis Flags & Trade-Off Discipline:**
   * **Holistic Intersection Mode (`--all` / `--holistic`, or No Flag — Default):** When the user requests general optimization without restricting to a single axis (such as *"optimize this game"*, *"bu oyunu/yazılımı optimize et"*, `/sweetspot`, or `/sweetspot --all`), target the **Holistic Multi-Axis Intersection** simultaneously:
     * **3-Axis Local Intersection (`Time + Memory + Disk`):** Applied automatically when Step 1 detects a purely local/offline codebase with no network boundaries.
     * **4-Axis Networked Intersection (`Time + Memory + Disk + Network`):** Activated automatically inside Holistic Mode whenever Step 1 detects network boundaries (Hypertext Transfer Protocol (`HTTP`), WebSocket, Remote Procedure Call (`gRPC`), socket clients/servers, remote database/service queries, multiplayer netcode, or web bundle/asset delivery).
     * First eliminate **joint slack**—dead work, per-frame allocation churn, duplicate in-memory buffers, unstreamed full-file reads, redundant `N+1` network round trips, uncompressed wire payloads, and unused dependencies or assets—that improves all active axes together (or improves at least one axis by `>= 1%` with `0%` regression beyond `< 1%` noise on all other active axes) until the software reaches its **Pareto Frontier**.
   * **Single-Axis Mode (`--time`, `--memory`, `--disk`, `--net` or Natural Language) & Cross-Axis Trade-Off Gate:** When the user passes an explicit single-axis flag or names a specific primary axis in natural language, focus on that primary axis and treat all remaining active axes as non-regressing guardrails (`< 1%` noise floor). Once the Pareto Frontier is reached in either mode, any further gain that requires trading away another resource axis beyond `< 1%` noise (such as caching in memory or disk to cut network round trips, spending extra processor time on high-ratio compression to shrink upload/download bandwidth, or adding cold-start decompression latency to shrink disk size) is classified as **Zone 2** and requires explicit user approval before editing code.

| Flag | Alias | Mode & Primary Target Axis | Non-Regressing Guardrail Axes (`< 1%` Noise) |
| :--- | :--- | :--- | :--- |
| *(none)* or `--all` | `--holistic` | **Holistic Intersection (Default):** `Time + Memory + Disk` (plus **Conditional Axis 4: `Network`** whenever the target structure has network boundaries) | All active axes must remain `<= 0%` regression (`< 1%` noise) while at least one improves `>= 1%` |
| `--time` | `--speed` | **Axis 1 — Execution Speed & Latency** (wall time, frame rate, cold start) | `Memory`, `Disk`, and (if networked) `Network` |
| `--memory` | `--ram` | **Axis 2 — Memory Footprint** (peak Resident Set Size (`RSS`), retained heap, allocation churn) | `Time`, `Disk`, and (if networked) `Network` |
| `--disk` | `--size` | **Axis 3 — Disk, Bundle & Storage Footprint** (binary, bundle, database size) | `Time`, `Memory`, and (if networked) `Network` |
| `--net` | `--network` | **Axis 4 — Network I/O** (download/upload payload bytes, request count, `RTT` latency) | `Time`, `Memory`, and `Disk` |
5. **Domain Co-Loading & White-Box vs. Black-Box Tool Routing:**
   * **Real-Time Game & Simulation Co-Loading:** When the target is a game, interactive canvas application, or real-time simulation loop, co-load `skills/game-engineering/SKILL.md` before Step 1 profiling so fixed-timestep determinism, zero per-frame allocation, and headless tick verification govern every measurement and edit.
   * **Source Code (`code_map.py`) vs. Shipped Artifact (`reverse-engineer-anything`) Boundary:** When source code is available (white-box analysis), map multi-file call graphs and dataflow using `scripts/code_map.py` and native language profilers; never invoke the `reverse-engineer-anything` plugin for ordinary source-repository analysis. Route to `reverse-engineer-anything` (`inspect_artifact`, `inspect_binary_layout`, `analyze_javascript_application`, or `analyze_web_bundle`) **only** when inspecting a shipped binary, compiled executable without source, mobile package, Electron archive, or stripped bundle where standard source tools and `stat`/`size` cannot explain internal section or payload bloat.
6. **Honest Sweet-Spot Declaration:** Finding that no meaningful optimization is possible within the current scope—or that further gain requires changing the system's identity or trading away another resource—is a first-class, successful engineering outcome, never a failure to hide.

---

## 2. Step 1: Map Multi-File Architecture, Pin Behavior & Measure the Active-Axis Baseline

Before proposing or writing any optimization edit:

1. **Map the Multi-File Hot-Path, Network Boundaries & Dependency Graph (`scripts/code_map.py`):**
   * Never optimize the first inspected file in isolation when a software project or game spans multiple connected files and modules (such as entrypoint, game loop, physics, entity management, rendering, network transport, data loaders, and asset pipelines).
   * Starting from the application entrypoint or main update loop, map the connected call graph, dataflow, and blast radius across all participating files using `python3 scripts/code_map.py profile <symbol>`, `callers <symbol>`, `flow <symbol>`, and `blast-radius <symbol>` (or `python3 ~/.local/share/antigravity-harness/runtime/scripts/code_map.py`). Identify cross-file bottlenecks—such as producer modules allocating transient objects consumed by downstream loop modules, redundant serialization across module boundaries, or sequential network call chains—before choosing optimization targets.
2. **Pin Observable Behavior (`skills/refactoring/SKILL.md` §3):**
   * Run the existing test suite covering the target path across all coupled modules.
   * If the hot path lacks seam tests, write characterization tests that lock exact current outputs across representative and boundary inputs before touching production code.
3. **Establish a Repeatable Multi-Axis Benchmark Sensor (Holistic 3/4-Axis Default or Primary + Guardrail Axes):**
   * Construct a deterministic measurement command capturing all active axes in **Holistic Mode** (`Time + Memory + Disk`, plus **Axis 4: `Network`** whenever network boundaries exist) or the primary axis plus guardrail checks in **Single-Axis Mode**:
     * **Axis 1 — Execution Speed & Latency (Time):**
       * *Scripts, Functions & Backends:* Wall-clock execution time (`p50` median and `p95` tail latency across `N >= 5` runs after warm-up) using `hyperfine`, `time`, or `go test -bench`, plus query execution plans (`EXPLAIN ANALYZE`).
       * *Real-Time Games & Interactive Loops:* Frame-step execution time in milliseconds (`stepTick` / `update` + `render` budget against `16.67 ms` for 60 frames per second (`FPS`) or `8.33 ms` for 120 frames per second).
       * *Command-Line Interface (`CLI`) Tools & Executables:* Cold-start versus warm-start launch latency (`time`, `hyperfine`, `python3 -X importtime`) and dynamic library load count.
     * **Axis 2 — Memory Footprint (`RAM`):**
       * *Peak & Retained Memory:* Peak Resident Set Size (`RSS` via `/usr/bin/time -v` or `ps`) and peak heap allocation (`tracemalloc`, `go test -benchmem`, `valgrind --tool=massif`, or runtime heap snapshots).
       * *Hot-Loop & Per-Request Allocation Churn:* Allocation count and bytes allocated per frame, tick, or request (`skills/game-engineering/SKILL.md`), verifying that retained heap plateaus across repeated iterations rather than growing unboundedly.
     * **Axis 3 — Disk, Bundle & Storage Footprint (Space):**
       * *Compiled Executables & Libraries:* On-disk binary size (`stat`, `size`, `bloaty`) and section breakdown (`.text`, `.rodata`, `.data`, debug symbols) across the target Operating System (`OS`); if inspecting a stripped or packaged binary artifact whose internal bloat cannot be resolved from source or `size`, use `reverse-engineer-anything` (`inspect_binary_layout` or `inspect_artifact`).
       * *Application Bundles, Packages & Containers:* Bundled asset and script/stylesheet payload sizes (uncompressed and compressed via `gzip` or `brotli`), dependency tree weight, and container image layer sizes (or `analyze_web_bundle` / `analyze_javascript_application` when analyzing packaged web or Electron artifacts).
       * *Runtime Persistent Storage:* On-disk database, cache, and state file footprint (`du -b`, SQLite page count and freelist ratio) under a deterministic workload.
     * **Axis 4 — Network I/O: Download/Upload Bandwidth & Round-Trip Latency (Conditional in `--all` Holistic Mode; Primary in `--net` Mode):**
       * *Download & Upload Payload Volume (Ingress / Egress Bytes):* Total uncompressed and wire-compressed (`gzip`, `brotli`, `zstd`) download and upload bytes transferred per user journey, request cycle, or state sync, plus payload schema bloat (over-fetching unused fields or duplicate metadata).
       * *Round-Trip Time (`RTT`) & Request Waterfall Depth:* Sequential round-trip depth, connection and Transport Layer Security (`TLS`) handshake count, `N+1` request waterfalls, and local loopback `p50` median and `p95` tail latency (or `inspect_web_network_capture` / `inspect_packet_capture` when inspecting captured browser or packet traces).
       * *Real-Time Netcode & Streaming Throughput:* Packet or message frequency (tick/snapshot rate), header-to-payload ratio, and stream backpressure under a deterministic workload.
       * *Deterministic Loopback & Counter Rule (`GEMINI.md` Rule 8):* Never benchmark against live external internet jitter; measure against a deterministic local loopback server, recorded replay fixture, or exact wire-byte, request-count, and waterfall-depth counters so the `< 1%` noise floor holds.
   * Record the exact baseline numbers across all active axes (`Time`, `Memory`, `Disk`, and `Network` when applicable), and locate the actual hot spots or bloat sources across the connected module graph using a profiler, runtime call-edge tracer (`python3 scripts/code_map.py trace <script.py>` or `python3 ~/.local/share/antigravity-harness/runtime/scripts/code_map.py trace <script.py>`), heap/section analyzer, network trace inspector, query plan (`EXPLAIN ANALYZE`), or startup import timer (`python3 -X importtime`).

---

## 3. Step 2: The 3-Zone Sweet-Spot Classification Gate

Once the baseline profile is captured, classify every identified optimization opportunity into one of three explicit zones **before editing production code**:

| Zone | Classification | Defining Criteria | Required Agent Action |
| :--- | :--- | :--- | :--- |
| **Zone 1** | **Controlled Optimization (In-Scope / Pareto Sweet Spot)** | Preserves exact observable behavior, public interfaces, wire contracts, data fidelity, portability, and the system's core architecture while eliminating joint slack across all active axes or targeting a measured bottleneck above the noise floor (`>= 1%` improvement on at least one active axis—Time, Memory, Disk, or Network—with `0%` regression beyond `< 1%` noise on all remaining active axes). | Present the bottleneck proof and expected gain (or execute directly if the user already authorized in-scope optimization) and verify via Step 4 (Section 5) until the **Pareto Frontier** is reached. |
| **Zone 2** | **Trade-Off or Identity-Shifting Optimization** | Further Time, Memory, Disk, or Network improvement beyond the Pareto Frontier is achievable, **but** requires either: (a) a **cross-axis resource trade-off** beyond `< 1%` noise (e.g., increasing peak memory or disk usage via caching to cut network downloads/round trips, spending extra processor time on heavy compression to shrink upload/download bandwidth, batching uploads at the cost of higher per-message latency, or adding cold-start decompression latency to shrink disk size); or (b) altering the software's purpose, problem domain, feature contract, numerical precision, lossy asset compression, cache eviction semantics, public file/wire format, or deployment layout. | **STOP.** Do not modify code. Explain the exact trade-off (`Target Axis | Proposed Shift | Cross-Axis or Feature Cost | Expected Gain`) and ask for explicit user approval via `ask_question` or direct confirmation. |
| **Zone 3** | **Already at the Sweet Spot (Pareto Frontier) / Out of Scope** | (a) All joint Zone 1 opportunities are exhausted and the software stands on its **Multi-Axis Pareto Frontier**, bounded by hardware, `OS` syscall floors, minimum runtime footprint, network protocol headers, or information-theoretic entropy (Amdahl's Law or compression ceiling); (b) the only remaining hotspots or bloat sources lie outside the user's permitted scope; or (c) remaining micro-optimizations yield `< 1%` gain while reducing code clarity. | **STOP (`GEMINI.md` Rule 8 Null-Action Invariant).** Modify zero further files. Deliver an honest **Sweet-Spot Report** with the multi-axis profiling numbers proving why the structure is at its optimal Pareto sweet spot. |

---

## 4. Step 3: Domain Playbooks for Zone 1 Controlled Optimizations

When Zone 1 opportunities exist, prefer structural, readable wins in this order:

### A. Execution Speed: Scripts, Data Pipelines & Backend Services
* **Algorithmic & Lookup Complexity:** Replace repeated linear scans ($O(N \times M)$) inside loops with pre-indexed sets or hash maps ($O(N + M)$) when the index allocation stays within `< 1%` of peak memory (otherwise request Zone 2 trade-off approval).
* **Loop-Invariant Hoisting & Compilation:** Hoist regular expression compilation, configuration parsing, filesystem checks, and constant object construction out of inner loops.
* **Batching & Streaming:** Replace `N+1` sequential queries or network/disk calls with batched reads/writes; use iterators or streaming buffers instead of materializing multi-megabyte intermediate lists in memory when only aggregates are needed.
* **Cold-Start Import Hygiene (Python / Node.js):** Defer heavy, non-essential module imports (`pandas`, plotting libraries, cloud software development kits, optional subcommands) inside the specific functions that use them so `CLI` startup and `--help` remain instantaneous.

### B. Execution Speed & Allocation Churn: Real-Time Games & Interactive Simulations (`skills/game-engineering/SKILL.md`)
* **Zero Per-Frame Heap Allocation:** Eliminate `.map()`, `.filter()`, object spreads, and temporary vector instantiations inside 60–120 Hz `update` and `render` loops; reuse pre-allocated scratch buffers across coupled loop modules.
* **Object Pooling & Broad-Phase Culling:** Pool transient entities (particles, projectiles, damage text) across entity producer and consumer modules, and apply spatial grid / bounding-box culling before narrow-phase collision math.
* **Render State Batching:** Group draw calls by texture/material/fillStyle and bridge state to Document Object Model (`DOM`) overlays only on discrete events rather than every animation frame.

### C. Execution Speed: Compiled Executables, Packaging & Cross-`OS` Responsiveness
* **Startup Critical-Path Trimming:** Defer non-critical disk scans, telemetry hooks, font/asset preloading, and background worker spawning until after the initial window render or first command response.
* **Semantics-Preserving Compiler & Linker Flags:** Enable release optimization levels (`-O2` / `-O3`, Rust `codegen-units = 1` with Link-Time Optimization (`LTO`) `lto = "thin"`, Go `-ldflags="-s -w"`, dead-section elimination `--gc-sections`) while strictly forbidding unsafe floating-point flags (`-ffast-math`) unless explicitly approved under Zone 2.
* **Packaging & Extraction Overhead:** Identify when slow executable launch on Linux, macOS, or Windows is caused by self-extracting archive decompression to a temporary directory on every cold start (such as single-file bundled runtimes). Report the measured extraction cost vs. actual application startup time, and seek Zone 2 approval before changing the distribution format.

### D. Memory Footprint (`RAM`) & Allocation Hygiene
* **Data Layout & Object Overhead Compaction:** Replace heavyweight dynamic dictionaries or boxed object wrappers on high-cardinality records with `__slots__`, `namedtuple`, compact `dataclass(slots=True)`, typed arrays (`array`, `Float64Array`), or flat parallel buffers.
* **Streaming & Generator Pipelines:** Replace full-file reads (`.read()`, `.readlines()`) and multi-pass list comprehensions with single-pass generators, chunked stream readers, or database cursors so peak memory stays $O(1)$ or $O(\text{chunk})$ instead of $O(N)$.
* **Reference Release & Duplicate Buffer Elimination:** Clear dead references to large intermediate buffers as soon as their scope ends, and avoid retaining duplicate raw, parsed, and serialized copies of the same payload in memory simultaneously. (Changing an unbounded cache to evict entries that callers rely on for state requires Zone 2 approval; bounding a pure memoization cache must preserve exact outputs.)
* **Lazy Asset & Module Materialization:** Load heavy lookup tables, localization bundles, or optional submodules only when the code path that requires them is actually invoked.

### E. Disk, Bundle & Persistent Storage Footprint
* **Binary Symbol & Dead-Section Pruning:** Strip non-essential symbol tables and debug sections in release builds (`strip`, Go `-ldflags="-s -w"`, Rust `strip = "symbols"`), enable `--gc-sections` with `-fdata-sections -ffunction-sections`, and avoid statically linking unused subsystems.
* **Bundle Tree-Shaking & Dependency Diet:** Replace monolithic barrel imports with direct submodule imports so bundlers can tree-shake dead code, and remove unused static assets, duplicate font weights, or orphaned lockfile dependencies verified to have zero callers via `python3 scripts/code_map.py callers <symbol>`.
* **Lossless Storage & Database Compaction:** Reclaim fragmented freelist pages (`VACUUM` on SQLite when safe offline), deduplicate identical stored blobs via content-addressed references where the schema already supports it, and apply deterministic lossless compression to internal caches without altering public file formats. (Switching public file formats, applying lossy media compression, or truncating logs/history requires Zone 2 approval.)

### F. Network I/O: Download/Upload Bandwidth & Round-Trip Latency
* **Request Waterfall Flattening & Coalescing:** Collapse sequential `N+1` network round trips into batched queries, parallel independent fetches (`Promise.all`, `asyncio.gather`, `errgroup`), or single-trip bulk reads/writes, and deduplicate identical in-flight requests triggered simultaneously across components.
* **Connection Reuse & Multiplexing:** Reuse persistent client sessions (`HTTP Keep-Alive` connection pools, multiplexed `HTTP/2` or `HTTP/3` streams, persistent `gRPC` channels, or pooled database sockets) instead of paying fresh connection and handshake latency on every request.
* **Download & Upload Payload Diet (Zero-Semantic-Loss):** Enable standard lossless transport compression (`brotli`, `gzip`, `zstd`) when processor and memory overhead stays within `< 1%` guardrails, omit unused fields in internal queries (over-fetching elimination), and stream chunked uploads/downloads instead of buffering multi-megabyte request/response bodies in memory. (Mutating public wire schemas, introducing lossy payload quantization, or delaying real-time uploads via aggressive batching windows requires Zone 2 approval.)
* **Conditional Fetching & Delta Sync:** Leverage protocol-level cache revalidation (`ETag` / `If-None-Match` returning `304 Not Modified`) and send incremental state deltas rather than full-state snapshots across real-time WebSocket or multiplayer loops when wire compatibility is preserved.

---

## 5. Step 4: Single-Hypothesis Atomic Slices & Append-Only Experiment Ledger

Execute approved optimizations under strict experimental control (`skills/diagnosing-bugs/SKILL.md` alignment):

1. **Single-Hypothesis Isolation (Including Coupled Cross-File Atomic Slices):** Apply one optimization hypothesis at a time. When a single bottleneck spans multiple coupled files (for example, introducing an object pool across loop modules or coalescing sequential client fetches with a shared connection pool), update the **minimal coupled cross-file atomic slice** required by that single hypothesis in one measured attempt, and record all touched `file:line` coordinates in the ledger. Never bundle unrelated performance, memory, size, or network hypotheses into a single unmeasured diff.
2. **Re-Run Pinning Tests & Multi-Axis Benchmark:** Immediately run the characterization/unit test suite (must exit `0` with zero modified assertions per `GEMINI.md` Rule 9) and re-run the exact Step 1 benchmark command under identical load conditions to verify both primary gain and guardrail axes.
3. **Append-Only Experiment Ledger & Simplicity Criterion:** Record every attempt in the canonical 7-column ledger shared with `skills/diagnosing-bugs/SKILL.md`:

```markdown
| Attempt | Zone | Hypothesis & Target (`file:line`) | Diff Summary | Baseline | Measured | Status: KEEP/REVERT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `#1` | Zone 1 | Pool projectiles across loop (`entities.js:42`, `physics.js:118`) | Reuse pre-allocated pool instead of per-tick instantiation | `14.2 ms/tick, 96 MB` | `8.9 ms/tick (-37.3%), 54 MB (-43.8%)` | `KEEP` |
| `#2` | Zone 1 | Stream CSV rows (`loader.py:84`) | Replace `readlines()` list with generator | `312 MB RSS` | `28 MB RSS (-91.0%)` | `KEEP` |
| `#3` | Zone 1 | Strip release symbols (`Makefile:19`) | Add `-ldflags="-s -w"` to build target | `18.4 MB bin` | `12.1 MB bin (-34.2%)` | `KEEP` |
| `#4` | Zone 1 | Coalesce `N+1` user-item fetches & reuse session (`sync.py:61`, `api.py:29`) | Batch item IDs into single request over pooled `HTTP` session | `14 RTTs, 480 KB dl, 62 ms` | `2 RTTs (-85.7%), 112 KB dl (-76.7%), 11 ms (-82.3%)` | `KEEP` |
| `#5` | Zone 1 | Unroll 4-element matrix loop (`sim.py:188`) | Inline 4 multiply-add expressions | `3.8 ms/tick` | `3.78 ms/tick (-0.5%)` | `REVERT (Noise < 1%)` |
```

* **The Simplicity Criterion & Termination Cap (`GEMINI.md` Rule 13):**
  * Any change that adds code complexity for noise-level gain (`< 1%` across active Time, Memory, Disk, and Network axes, or that regresses any non-target guardrail axis beyond `< 1%` noise without Zone 2 approval) is immediately reverted (`REVERT`).
  * Any change that simplifies code or deletes dead work/bloat while achieving equal or better measured metrics (`>= 0%`) is kept (`KEEP`).
  * Never stack a subsequent attempt on top of a reverted or unmeasured edit.
  * **3-Strike Sweet-Spot Circuit Breaker:** After 3 consecutive `REVERT` attempts (or when all profiled Zone 1 hotspots/bloat sources `>= 1%` are exhausted and the software reaches its Pareto Frontier), halt code edits immediately and transition to **Zone 3** (`Sweet-Spot Report`).

---

## 6. Triggers and Invocations

* **Slash Commands & Axis Flags:**
  * `/sweetspot`, `/optimize`, `/sweetspot --all`, `/sweetspot --holistic` *(Holistic Default: 3-axis `Time + Memory + Disk` on local software; automatically expands to 4-axis `Time + Memory + Disk + Network` when network boundaries exist)*
  * `/sweetspot --time` (alias `--speed`), `/sweetspot --memory` (alias `--ram`), `/sweetspot --disk` (alias `--size`), `/sweetspot --net` (alias `--network`)
* **Natural Language Triggers:** *"sweetspot analizi yap"*, *"bu oyunu optimize et"*, *"bu yazılımı/projeyi optimize et"*, *"bunu yapıyı bozmadan hızlandır"*, *"performans optimizasyonu yap"*, *"kare hızını artır"*, *"daha hızlı açılsın"*, *"bellek kullanımını düşür"*, *"RAM optimizasyonu yap"*, *"disk alanını küçült"*, *"dosya/paket boyutunu küçült"*, *"ağ optimizasyonu yap"*, *"indirme ve yükleme boyutunu küçült"*, *"indirme/yükleme hızını optimize et"*, *"ağ gecikmesini (latency) düşür"*, *"bant genişliği optimizasyonu"*, *"optimize this game/app/project"*, *"optimize this for speed, memory, disk size, or network bandwidth/latency without breaking behavior"*.
