# System Architecture (`ARCHITECTURE.md`)

**System / Repository:** `{{project-slug}}`
**Last Verified Commit:** `{{commit-sha}}`
**Authoritative Scope:** Current-state structural topology and non-negotiable boundaries only (`<= 150` lines total).

> [!IMPORTANT]
> **Anti-Rot Authoring Rules:**
> 1. Document **current-state topology only**. Move historical context, rejected designs, and migration narratives into `docs/adr/{{NNNN}}-{{decision-slug}}.md`.
> 2. **Zero directory tree dumps and zero volatile line numbers:** Never paste `tree` output or `:L<n>` coordinates that go stale on routine edits; cite stable module/crate/package paths (`{{crates/core}}`, `{{src/domain}}`) and public entry symbols.
> 3. Keep this file at or below `150` lines (`wc -l ARCHITECTURE.md <= 150`). Split subsystem internals into `ADR` records when detail outgrows a table row.

## 1. System Backbone & Entrypoints

State the system's operational purpose in two sentences, then list every executable, daemon, library root, or network entrypoint and the primary request or data path connecting them:

`{{Client / Caller}} -> {{Ingress / CLI Entrypoint}} -> {{Domain Core}} -> {{Storage / External Adapter}}`

| Entrypoint / Binary | Source Root | Runtime / Process Boundary | Primary Responsibility & Protocol |
| :--- | :--- | :--- | :--- |
| `{{bin-or-service-name}}` | `{{crates/server/src/main.rs}}` | {{Async multi-thread / CLI process / Kernel module}} | {{Terminates TLS 1.3 HTTP/2 API requests and dispatches validated commands}} |
| `{{worker-or-lib-name}}` | `{{crates/core/src/lib.rs}}` | {{In-process pure library (`#![forbid(unsafe_code)]`)}} | {{Executes deterministic domain state transitions with zero I/O}} |

## 2. Module Responsibilities & Forbidden Dependency Directions

Every top-level module owns a single bounded responsibility. Dependencies flow strictly inward toward pure domain types; reverse or cyclic edges fail review and architecture gates.

| Module / Crate | Owned Responsibility | Allowed Outbound Dependencies (`A -> B`) |
| :--- | :--- | :--- |
| `{{api / transport}}` | `{{Wire parsing, auth extraction, status serialization}}` | `{{api -> domain}}, {{api -> telemetry}}` |
| `{{domain / core}}` | `{{Business invariants, typestates, pure state transitions}}` | `{{domain -> std/core only (zero transport or DB imports)}}` |
| `{{storage / hal}}` | `{{Persistence transactions, SQL/KV codecs, or hardware MMIO}}` | `{{storage -> domain}}` |

**Forbidden Dependency Directions (Hard Blocks):**
- `{{domain}} -> {{api}}` is **FORBIDDEN** (`domain` never imports HTTP, gRPC, CLI flag, or presentation types).
- `{{domain}} -> {{storage}}` is **FORBIDDEN** (`domain` defines repository/port traits or pure data inputs; `storage` implements them).
- `{{api}} -> {{storage}}` direct bypass is **FORBIDDEN** unless explicitly exempted in `docs/adr/{{NNNN}}-{{decision-slug}}.md`.

## 3. State & Data Ownership

Each mutable state store, cache, queue, or shared-memory region has exactly one authoritative writer boundary:

| State / Dataset | Authoritative Owner Module | Backing Store & Isolation | Concurrency, Lock Ordering & Cache Invalidation Rule |
| :--- | :--- | :--- | :--- |
| `{{accounts / ledger}}` | `{{crates/ledger}}` | {{PostgreSQL 17 `SERIALIZABLE`}} | {{Single writer via `ledger::commit_entry`; zero direct SQL mutations from other modules}} |
| `{{session_cache}}` | `{{crates/auth}}` | {{In-memory bounded LRU (`max_entries = 10_000`)}} | {{Read-through cache; invalidated synchronously on password reset or token revocation}} |

## 4. Non-Negotiable System Invariants

Every invariant below is enforced mechanically by types, lints, database constraints, or seam tests (never prose promises alone):

| Invariant ID | Architectural Guarantee | Enforcing Boundary / Check | Governing ADR |
| :--- | :--- | :--- | :--- |
| `INV-01` | {{Zero `unsafe` blocks outside the isolated HAL/FFI crate; all upper crates enforce `#![forbid(unsafe_code)]`}} | {{Workspace `Cargo.toml` lints + CI `cargo clippy --all-targets -- -D warnings`}} | [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md) |
| `INV-02` | {{All external wire payloads pass bounded byte-length caps (`<= 1 MiB`) and schema parsing before allocation}} | {{Ingress middleware + negative boundary test in `{{tests/test_ingress_bounds.rs}}`}} | [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md) |
| `INV-03` | {{Idempotency keys deduplicate retried mutations atomically within a `24h` retention window}} | {{Composite `UNIQUE (tenant_id, idempotency_key)` constraint + `{{tests/test_idempotency.rs}}`}} | [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md) |
