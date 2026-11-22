# Repository State Snapshot (`REPOSTATE.md`)

**System / Repository:** `{{project-slug}}`
**Last Verified Commit:** `{{commit-sha}}` <!-- Latest verified `git rev-parse --short HEAD` recorded post-commit (or `{{commit-sha}} (+ working tree)` if updated pre-commit) -->
**Authoritative Scope:** Opt-in compact state snapshot, roadmap, and milestone ledger (`<= 150` lines total).

> [!IMPORTANT]
> **Anti-Rot Authoring Rules:**
> 1. **Point to files; copy nothing:** Record high-level status and link to authoritative source files, `ARCHITECTURE.md`, `SECURITY_POSTURE.md`, `docs/adr/{{NNNN}}-{{decision-slug}}.md`, or test suites. Never duplicate schemas, API specs, config tables, or command logs here.
> 2. **Zero volatile line numbers and zero directory dumps:** Never cite `:L<n>` coordinates or paste `tree` listings that break on routine edits. Reference stable file paths, module names, and ADR numbers only.
> 3. **Hard ceiling (`<= 150` lines):** Keep `wc -l REPOSTATE.md <= 150` by capping tables (`<= 20` snapshot rows, `<= 15` roadmap rows, `<= 10` ledger rows). Archive pruned ledger rows into `CHANGELOG.md` when `CHANGELOG.md` exists (otherwise drop the oldest rows) and keep detailed history in `docs/adr/`.
> 4. **Concrete milestone cadence only:** Update `REPOSTATE.md` exclusively at completed Tier 2/3 milestones or when a `marathon` campaign seals `[COMPLETE]`. Never rewrite it on Tier 1 edits or mid-window drafts; if a campaign halts `[!] BLOCKED` or is aborted, leave `REPOSTATE.md` unchanged except an optional open-risk note, keeping active task tracking in `tasks.md` and `HANDOFF.md`.

## 1. Current State Snapshot

Summarize operational readiness across core subsystems in one table. Every status entry must point to its verifying artifact or source root:

| Subsystem / Capability | Operational Status | Authoritative Pointer | Active Constraint / Open Risk |
| :--- | :--- | :--- | :--- |
| `{{core-domain}}` | `[SHIPPED]` | `{{src/domain/}}`, [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md) | {{Zero external I/O; covered by unit test suite}} |
| `{{api-ingress}}` | `[IN-PROGRESS]` | `{{src/api/}}`, `SECURITY_POSTURE.md` | {{Rate-limit middleware verified; webhook SSRF test pending}} |
| `{{cli-tooling}}` | `[STABLE]` | `{{src/cli/}}`, `ARCHITECTURE.md` | {{Backward-compatible flags locked for v1.x}} |

## 2. Planned Roadmap

List only committed near-term initiatives and consciously parked items in priority order. Move detailed requirements and acceptance criteria into `docs/plans/` or `tasks.md` once execution begins:

| Priority | Initiative / Milestone | Scope Boundary & Exit Gate | Governing Spec / ADR | Status |
| :--- | :--- | :--- | :--- | :--- |
| `P0` | {{Finish outbound webhook IP pinning}} | {{Pass negative IPv6-mapped loopback boundary tests}} | [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md) | `[NEXT]` |
| `P1` | {{Migrate job queue to transactional outbox}} | {{Zero message loss under worker crash replay test}} | `{{docs/plans/YYYY-MM-DD-outbox.md}}` | `[PLANNED]` |
| `P2` | {{Multi-region read replicas}} | {{Deferred until single-region read latency exceeds 50 ms p99}} | `{{None (V2 backlog)}}` | `[PARKED]` |

## 3. Compact Milestone Ledger

Append one single-line row per completed Tier 2/3 milestone or sealed `[COMPLETE]` campaign. Keep the newest entry at the top and prune rows older than the last 10 milestones (archiving into `CHANGELOG.md` when present, else dropping oldest entries) so the file stays within `150` lines:

| Date | Commit / Campaign | Milestone Delivered | Verification Proof & Pointer |
| :--- | :--- | :--- | :--- |
| `{{YYYY-MM-DD}}` | `{{commit-sha}}` / `{{campaign-id}}` | {{Shipped v1.2 schema migration and idempotent billing ledger}} | {{`pytest` + `alembic upgrade/downgrade` green; [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md)}} |
| `{{YYYY-MM-DD}}` | `{{commit-sha}}` / `{{campaign-id}}` | {{Completed security boundary hardening for tenant isolation}} | {{Negative IDOR suite green; `SECURITY_POSTURE.md` updated}} |
