# Architecture Decision Records

Capture architectural decisions as they happen during coding sessions. Instead of decisions living only in Slack threads, PR comments, or someone's memory, this skill produces structured ADR documents that live alongside the code.

## When to Activate

- User explicitly invokes `/adr`, or says "let's record this decision", "record adr", or "ADR this"
- Tier 3 architectural decisions (`>8` files, database selection, schema redesigns, protocol changes, or authentication model shifts per `GEMINI.md` §3)
- User chooses between significant alternatives (framework, library, pattern, database, API design)
- User says "we decided to..." or "the reason we're doing X instead of Y is..."
- User asks "why did we choose X?" (read existing ADRs)
- During planning phases when architectural trade-offs are discussed

## ADR Format

Use the lightweight ADR format proposed by Michael Nygard, adapted for AI-assisted development:

```markdown
# ADR-NNNN: [Decision Title]

**Date**: YYYY-MM-DD
**Status**: proposed | accepted | deprecated | superseded by ADR-NNNN
**Deciders**: [who was involved]
**Proposed By**: User | Model (<Model Display Name & Effort>)
**Approved By**: User | pending
**Authority**: User Constraint | Model Recommendation

## Context

What is the issue that we're seeing that is motivating this decision or change?

[2-5 sentences describing the situation, constraints, and forces at play]

## Decision

What is the change that we're proposing and/or doing?

[1-3 sentences stating the decision clearly]

## Alternatives Considered

### Alternative 1: [Name]
- **Pros**: [benefits]
- **Cons**: [drawbacks]
- **Why not**: [specific reason this was rejected]

### Alternative 2: [Name]
- **Pros**: [benefits]
- **Cons**: [drawbacks]
- **Why not**: [specific reason this was rejected]

## Consequences

What becomes easier or more difficult to do because of this change?

### Positive
- [benefit 1]
- [benefit 2]

### Negative
- [trade-off 1]
- [trade-off 2]

### Risks
- [risk and mitigation]
```

### Decision Provenance & Backward Compatibility

Record explicit provenance on every newly authored ADR so future maintainers and `/retro` passes can distinguish operator mandates from model-proposed architecture:

- **`Proposed By`:** `User` when the human operator originated the option or constraint, or `Model (<Model Display Name & Effort>)` (for example, `Model (Gemini 4 Neon, XHigh)`) when an AI model proposed the design.
- **`Approved By`:** `User` once the human operator explicitly accepts the ADR (use `pending` while `Status` is `proposed`).
- **`Authority`:** `User Constraint` for binding operator requirements versus `Model Recommendation` for model-proposed architectural choices eligible for later `/retro` calibration review.
- **Backward Compatibility (`docs/adr/0001..0013`):** Historical ADRs authored before structured provenance fields were adopted remain valid without mandatory backfill; apply the three fields to all newly created ADRs going forward.
- **Single-Source-of-Truth Boundary vs. Opt-In `DECISIONS.md` (`~/.gemini/config/templates/DECISIONS.template.md`):** Keep deep Tier-3 architectural context, rejected alternatives, and consequences exclusively in `docs/adr/NNNN-*.md`. When a repository opts into a root `DECISIONS.md` ledger (`<= 150` lines, created only on explicit user request), record Tier-2 design choices there directly and add only a 1-line summary pointer to any Tier-3 ADR without duplicating ADR prose.

## Workflow

### Capturing a New ADR

When a decision moment is detected:

1. **Initialize (first time only):** If `docs/adr/` does not exist and an ADR is already required (Tier 3 planning) or explicitly requested (`/adr`), create `docs/adr/`, a `README.md` seeded with the index table header (see ADR Index Format below), and a blank `template.md` for manual use directly under the Reversible-First default (`~/.gemini/config/skills/harness/SKILL.md` §1) without pausing for a low-stakes confirmation. Ask before initializing `docs/adr/` only when proposing an unsolicited ADR from implicit conversation signals.
2. **Identify the decision:** Extract the core architectural choice being made.
3. **Gather context:** State the problem that prompted this decision and the active constraints.
4. **Document alternatives with weighted criteria:** Record the other options considered and why each was rejected. Do not treat criteria as equally weighted: name the decision-driving constraint and whether a single critical failure mode outweighed several minor advantages.
5. **State consequences:** List the concrete trade-offs and what becomes easier or harder.
6. **Assign a number:** Scan existing ADRs in `docs/adr/` and increment.
7. **Write and review:** When an ADR was explicitly requested (`/adr`) or already scoped as a Tier 3 / `tasks.md` deliverable, write `docs/adr/NNNN-decision-title.md` directly and summarize the recorded decision in the response so the user can adjust or revert it. Require explicit upfront draft approval only when proposing an unsolicited ADR from implicit conversation signals; if the user declines, discard the draft without writing any files.
8. **Update the index:** Append the new row to `docs/adr/README.md`.

### Reading Existing ADRs

When a user asks "why did we choose X?":

1. Check if `docs/adr/` exists; if not, respond: "No ADRs found in this project. Would you like to start recording architectural decisions?"
2. If it exists, scan `docs/adr/README.md` index for relevant entries
3. Read matching ADR files and present the Context and Decision sections
4. If no match is found, respond: "No ADR found for that decision. Would you like to record one now?"

### ADR Directory Structure

```
docs/
└── adr/
    ├── README.md              ← index of all ADRs
    ├── 0001-use-nextjs.md
    ├── 0002-postgres-over-mongo.md
    ├── 0003-rest-over-graphql.md
    └── template.md            ← blank template for manual use
```

### ADR Index Format

```markdown
# Architecture Decision Records

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [0001](0001-use-nextjs.md) | Use Next.js as frontend framework | accepted | 2026-01-15 |
| [0002](0002-postgres-over-mongo.md) | PostgreSQL over MongoDB for primary datastore | accepted | 2026-01-20 |
| [0003](0003-rest-over-graphql.md) | REST API over GraphQL | accepted | 2026-02-01 |
```

## Decision Detection Signals

Watch for these patterns in conversation that indicate an architectural decision:

**Explicit signals**
- "Let's go with X"
- "We should use X instead of Y"
- "The trade-off is worth it because..."
- "Record this as an ADR"

**Implicit signals** (suggest recording an ADR; do not auto-create without user confirmation)
- Comparing two frameworks or libraries and reaching a conclusion
- Making a database schema design choice with stated rationale
- Choosing between architectural patterns (monolith vs microservices, REST vs GraphQL)
- Deciding on authentication/authorization strategy
- Selecting deployment infrastructure after evaluating alternatives

## What Makes a Good ADR

### Do
- **Be specific:** "Use Prisma ORM" instead of "use an ORM"
- **Record the why:** the rationale matters more than the what
- **Include rejected alternatives:** future developers need to know what was considered
- **State consequences honestly:** every decision has trade-offs
- **Keep it short:** an ADR should be readable in 2 minutes
- **Use present tense:** "We use X" instead of "We will use X"

### Don't
- Record trivial decisions: variable naming or formatting choices do not need ADRs
- Write essays: if the context section exceeds 10 lines, shorten it
- Omit alternatives: "we just picked it" is not a valid rationale
- Backfill without marking it: if recording a past decision, note the original date
- Let ADRs go stale: superseded decisions should reference their replacement

## ADR Lifecycle

```
proposed → accepted → [deprecated | superseded by ADR-NNNN]
```

- **proposed**: decision is under discussion, not yet committed
- **accepted**: decision is in effect and being followed
- **deprecated**: decision is no longer relevant (e.g., feature removed)
- **superseded**: a newer ADR replaces this one (always link the replacement)

## Categories of Decisions Worth Recording

| Category | Examples |
|----------|---------|
| **Technology choices** | Framework, language, database, cloud provider |
| **Architecture patterns** | Monolith vs microservices, event-driven, CQRS |
| **API design** | REST vs GraphQL, versioning strategy, auth mechanism |
| **Data modeling** | Schema design, normalization decisions, caching strategy |
| **Infrastructure** | Deployment model, CI/CD pipeline, monitoring stack |
| **Security** | Auth strategy, encryption approach, secret management |
| **Testing** | Test framework, coverage targets, E2E vs integration balance |
| **Process** | Branching strategy, review process, release cadence |

## Integration with Other Skills and Subagents

- **`harness` & `deep-grill` (Tier 3 Planning)**: when a Tier 3 architectural change (`>8 files`, schema, authentication, or cross-system protocol shift) is planned, record the decision in `docs/adr/` alongside `implementation_plan.md`.
- **`consistency-auditor` & `specification-gap-auditor`**: verify that newly proposed specifications and architectural changes conform to accepted ADRs or explicitly supersede them.
- **`retro` (`~/.gemini/config/skills/retro/SKILL.md`)**: inspects `Proposed By`, `Approved By`, and `Authority` across `docs/adr/` and opt-in `DECISIONS.md` to separate reversed `Model Recommendation` calibration patterns from intentional `User Constraint` pivots.
