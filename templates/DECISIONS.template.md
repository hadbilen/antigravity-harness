# Decision Provenance Ledger (`DECISIONS.md`)

**System / Repository:** `{{project-slug}}`
**Authoritative Scope:** Opt-in compact Tier-2 design decision and provenance ledger (`<= 150` lines total).

> [!IMPORTANT]
> **Opt-In & Anti-Rot Authoring Rules:**
> 1. **Strictly opt-in (never auto-created):** Create `DECISIONS.md` at the project root **only** when explicitly requested by the user (`GEMINI.md` Rule 4). Never initialize it automatically in repositories that have not opted in.
> 2. **Single-Source-of-Truth boundary vs. `docs/adr/` (zero dual-ledger drift):** Record lightweight Tier-2 design decisions directly as single-line rows with a concise rationale. Record Tier-3 architectural decisions in `docs/adr/{{NNNN}}-{{decision-slug}}.md` and keep **only** a single-line pointer row here (`[ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md)`); never duplicate ADR context, rejected alternatives, or consequences into `DECISIONS.md`.
> 3. **Structured provenance (`Origin` & `Authority`):** Record `User` (`User Constraint`) or `Model (<Model Display Name & Effort>)` (`Model Recommendation`) alongside explicit human sign-off (`Approved By: User`) so `/retro` can separate model calibration patterns from intentional operator constraints.
> 4. **Hard ceiling (`<= 150` lines), zero `:L<n>` coordinates & supersession hygiene:** Keep `wc -l DECISIONS.md <= 150` (`<= 40` rows) and cite stable file/module paths or ADR links rather than volatile `:L<n>` line numbers. When a decision is reversed or replaced, update `Status` to `[SUPERSEDED by {{YYYY-MM-DD / ADR-NNNN}}]` (tagging `Rationale` with `defect:` vs. `pivot:` so `/retro` separates model defects from requirement shifts) or `[REVERTED]` with the reason instead of silently deleting it during the active cycle. Prune whenever the file reaches `>= 135` lines or `>= 35` rows: remove the oldest `[SUPERSEDED]`, `[REVERTED]`, or `[ARCHIVED]` rows after `/retro` review (moving durable history to `CHANGELOG.md` or `docs/adr/` when present), and if `[ACTIVE]` rows alone exceed `35`, graduate durable subsystem invariants into `ARCHITECTURE.md` or a consolidated `docs/adr/` entry.

## 1. Active & Recent Decisions

Keep the newest entry at the top. Each row must remain one line and link to its governing ADR whenever a Tier-3 record exists:

| Date | Decision | Scope | Origin (User / Model + Effort) | Approved By | Rationale / ADR Link | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `{{YYYY-MM-DD}}` | {{Use PostgreSQL advisory locks for job lease acquisition}} | `{{src/scheduler/}}` | `User` (`User Constraint`) | `User` | {{Avoids external Redis dependency on single-region V1 deployment}} | `[ACTIVE]` |
| `{{YYYY-MM-DD}}` | {{Expose typed `DomainError` enum at library seam and `anyhow` only in CLI}} | `{{crates/core/}}`, `{{crates/cli/}}` | `Model ({{Model Display Name}}, {{Effort}})` (`Model Recommendation`) | `User` | {{Preserves exhaustive caller matching while keeping operator errors readable}} | `[ACTIVE]` |
| `{{YYYY-MM-DD}}` | {{Adopt transactional outbox for webhook dispatch}} | `{{src/webhooks/}}` | `Model ({{Model Display Name}}, {{Effort}})` (`Model Recommendation`) | `User` | [ADR-{{NNNN}}](docs/adr/{{NNNN}}-{{decision-slug}}.md) | `[ACTIVE]` |
| `{{YYYY-MM-DD}}` | {{Cache auth sessions in process memory without TTL eviction}} | `{{src/auth/}}` | `Model ({{Model Display Name}}, {{Effort}})` (`Model Recommendation`) | `User` | {{defect: replaced with bounded TTL cache after multi-worker staleness defect}} | `[SUPERSEDED by {{YYYY-MM-DD}}]` |

## 2. Status Tokens & Update Cadence

- **`[ACTIVE]`:** Current governing choice for the referenced scope.
- **`[SUPERSEDED by <YYYY-MM-DD / ADR-NNNN>]`:** Replaced by a newer row or ADR; prefix `Rationale` with `defect:` (faulty assumption or regression) or `pivot:` (intentional requirement change) and keep visible until the next `/retro` pass or `>= 135`-line / `>= 35`-row prune cycle.
- **`[REVERTED]`:** Rolled back due to a defect or invalidated assumption; include the concrete failure reason so `/retro` can group reversals by `Origin`.
- **`[ARCHIVED]`:** Historical entry slated for removal on the next pruning pass once its scope is retired.
- **Cadence:** Append or supersede rows only when a Tier-2 design choice is confirmed or a Tier-3 ADR is accepted. Never rewrite `DECISIONS.md` on routine Tier-1 edits.
