# ADR-0011: Governance Templates (`ARCHITECTURE.md`, `SECURITY_POSTURE.md`), `rust-harden` Skill Package, and `simplicity-auditor` Subagent

**Date**: 2026-11-18
**Status**: accepted
**Amends**: [ADR-0003](0003-rustify-skill-and-codemap-c-rust-indexing.md) (partial: intra-Rust vs. cross-language boundary), [ADR-0009](0009-cognitive-slimming-skill-consolidation-and-midturn-hook-silence.md) (partial: 21st top-level skill within the 10,800-byte frontmatter ceiling)
**Deciders**: Human Operator (`tugay`), Antigravity Harness Maintainers

## Context

Three structural gaps surfaced across production Rust and multi-module engineering sessions governed by Antigravity Harness: (1) projects lacked a bounded current-state structural topology artifact (`ARCHITECTURE.md`) and a non-public, evidence-backed security control ledger (`SECURITY_POSTURE.md` separated from root `SECURITY.md`, which GitHub and GitLab automatically publish in the public repository Security Policy tab); (2) intra-Rust ownership debt (`Arc<Mutex<T>>` and reflexive `.clone()` proliferation), production `.unwrap()` / `.expect()` elimination, `tokio::select!` cancellation safety, pre-runtime POSIX privilege drop, and `#![no_std]` / kernel `unsafe` narrowing fell between cross-language `rustify` (`ADR-0003`) and language-agnostic `refactoring`; and (3) Tier 2 and Tier 3 Pre-flight Gates (`skills/harness/SKILL.md` §5.A) lacked a dedicated read-only auditor verifying `GEMINI.md` Rule 4 (`YAGNI`), Rule 18 (`Surgical Changes & Reuse`), and the 7-Rung Efficiency Ladder. The decision-driving constraint is **closing all three governance and verification gaps without exceeding `ADR-0009`'s `10,800`-byte aggregate skill frontmatter budget, without exposing unverified security gaps in public `SECURITY.md` tabs, and without breaking existing Rust/C++ routing or test-boundary invariants**.

## Decision

We adopt four coordinated additions across the harness and its Porter/Guard ecosystem:
1. **Opt-In Portable Governance Templates (`templates/ARCHITECTURE.template.md`, `templates/SECURITY_POSTURE.template.md`):** Ship a `<= 150`-line current-state `ARCHITECTURE.template.md` with four fixed sections (`System Backbone & Entrypoints`, `Module Responsibilities & Forbidden Dependency Directions`, `State & Data Ownership`, `Non-Negotiable System Invariants`) banning volatile directory trees and `:L<n>` line numbers, alongside `SECURITY_POSTURE.template.md` splitting `[ENFORCED]` controls (requiring both code and passing test paths) from `` `[REQUIRED — UNVERIFIED]` `` controls (carrying an explicit `Release Blocker` `YES | NO` gate and banning subjective adjectives per `audit` Pass 2). Both files are read when present during `harness` planning and `audit` Phase 0.B grounding, and created in user repositories only on explicit user request (`GEMINI.md` Rule 4).
2. **`skills/rust-harden/` Capability Package (`SKILL.md` + `async-and-userspace.md` + `kernel-and-unsafe.md`):** Add `rust-harden` (`<= 520`-byte YAML frontmatter keeping the 21-skill aggregate under `10,700 / 10,800` UTF-8 bytes) with two mutually exclusive modes: Mode 1 (`--internal`, default on bare `/rust-harden`, preserving `100%` of `pub` signatures and existing tests) and Mode 2 (`--contract`, tightening `pub` signatures into `#[must_use] Result<T, E>`, `newtype`, and `typestate` contracts via `Expand -> Migrate -> Contract`, `contract-change-auditor`, `test-adequacy-auditor`, and `GEMINI.md` Rule 9 test authorization). Split crate-tiered `[lints.rust]` (`unsafe_code = "forbid"` on safe crates; `unsafe_op_in_unsafe_fn = "deny"` and `static_mut_refs = "deny"` on HAL/FFI crates) from `[lints.clippy]` (`undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `let_underscore_must_use`, `await_holding_lock`, and production `--lib --bins` / `clippy.toml` `unwrap_used` and `expect_used`).
3. **Read-Only `agents/simplicity-auditor.md` & Rust Security/Silent-Failure Vectors:** Add `simplicity-auditor` (`access: read-only`, exported to Claude Code with `tools: Read, Grep, Glob`) enforcing `GEMINI.md` Rules 4 and 18 plus Rung 7 verbatim (`>= 3` call sites or `<= +5` caller lines eliminating real duplication, with explicit carve-outs for `game-engineering` hot-loop seams and minimal safe `unsafe`/FFI/`newtype`/`typestate` wrappers). Extend `silent-failure-hunter.md` and `security-boundary-verifier.md` with Rust error-discarding and systems-memory boundary checks.
4. **Hook, Exporter, Meta-Audit & Manifest Synchronization:** Guard `SKILL_HINTS["rustify"]` against intra-Rust prompts, register `rust-harden` (`SKILL_HINTS` and Cursor `**/*.rs, **/Cargo.toml` globs above the `rustify` branch) without bare `Cargo.toml` workspace auto-injection, register `simplicity-auditor` in `ECOSYSTEM_ROUTING_HINTS`, `_ROUTE_EXPLICIT_SLUGS`, and `_READONLY_SUBAGENT_TYPES`, add `ARCHITECTURE.md` and `SECURITY_POSTURE.md` to `KNOWN_EXTERNAL_MD`, and refresh `.harness/manifest.json`.

## Alternatives Considered

### Alternative 1: Track Security Controls Inside Root `SECURITY.md`
- **Pros**: Reuses a filename already recognized by hosting platforms.
- **Cons**: Critical disclosure hazard: GitHub and GitLab automatically render root `SECURITY.md` in the public repository Security Policy tab, publishing any `` `[REQUIRED — UNVERIFIED]` `` control table directly to external attackers before mitigation lands.
- **Why not**: Rejected on security-boundary grounds; root `SECURITY.md` remains exclusively for vulnerability reporting instructions while `SECURITY_POSTURE.md` holds internal control verification state.

### Alternative 2: Enforce Workspace-Wide `unsafe_code = "deny"` Paired With `allow_attributes = "deny"`
- **Pros**: Single workspace-root lint block in `Cargo.toml`.
- **Cons**: Deadlocks isolated hardware/HAL/FFI crates that legitimately require narrow `#[allow(unsafe_code)]` wrappers and breaks external procedural macros expanding attributes inside workspace crates.
- **Why not**: Crate-tiered `#![forbid(unsafe_code)]` on safe crates paired with `unsafe_op_in_unsafe_fn = "deny"` and `undocumented_unsafe_blocks = "deny"` on isolated HAL/FFI crates achieves strict containment without macro or FFI deadlocks.

### Alternative 3: Fold Intra-Rust Hardening Into `skills/rustify/SKILL.md`
- **Pros**: Keeps the top-level skill count at `20`.
- **Cons**: Bloats C/C++/Go/Python migration context with `tokio` cancellation, POSIX privilege-drop, and kernel DMA/SMAP/IRQ rules while conflating cross-language differential-oracle gates with intra-Rust signature-preserving (`--internal`) vs. signature-tightening (`--contract`) workflows.
- **Why not**: Separate top-level routing with progressive-disclosure `references/` preserves clean mutual boundaries while staying `> 100` bytes under the `10,800`-byte frontmatter ceiling.

## Consequences

### Positive
- Repositories gain deterministic, non-public control tracking (`SECURITY_POSTURE.md`) and zero-rot architecture maps (`ARCHITECTURE.md`) audited automatically by `audit` Phase 0.B.
- Intra-Rust crates gain explicit `--internal` vs. `--contract` hardening discipline, host-verified `rustc`/`clippy` lint separation, and deep async/userspace and `#![no_std]`/kernel reference playbooks without colliding with `rustify` or generic `Cargo.toml` prompts.
- Tier 2 (`> +150` net lines or new abstractions) and Tier 3 Pre-flight Gates gain mechanical `YAGNI` and Rung 7 verification via `simplicity-auditor`.

### Negative
- Aggregate `skills/*/SKILL.md` frontmatter grows from `10,138` bytes to `~10,670` bytes (`<= 10,800`-byte cap), leaving `~130` bytes of headroom before future top-level skills require consolidating or trimming existing descriptions.
- Adding a `21`st skill, `10`th subagent, and `2` portable templates requires synchronized updates in `README.md`, `.harness/manifest.json`, and authorized exporter inventory tests.

### Risks
- **False-positive `rust-harden` hints on routine greenfield Rust prompts**: Mitigated by omitting bare `Cargo.toml` workspace auto-injection and restricting `SKILL_HINTS["rust-harden"]` to explicit hardening, ownership-debt, panic-removal, async-cancellation, and `unsafe`-narrowing intents verified by negative control tests.
- **Over-zealous abstraction removal on soundness wrappers**: Mitigated by baking explicit `game-engineering` seam and `unsafe`/FFI/`newtype`/`typestate` soundness-wrapper carve-outs directly into `agents/simplicity-auditor.md`.
