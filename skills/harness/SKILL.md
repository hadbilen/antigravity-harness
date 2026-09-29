---
name: harness
description: >-
  Autonomous engineering harness for AI coding agents. Enforces strict computational verification gates (typecheck,
  lint, test), artifact-driven task lifecycle (spec/plan/tasks), multi-agent verifier handoffs, and entropy/drift management.
  Invoke with /harness, /verify, /gate, or when enforcing production-grade execution discipline.
---

# Harness — Autonomous Software Engineering Scaffolding & Verification Gate

An engineering harness designed around the principle: **Agent = Model + Harness**.
While the model provides raw reasoning, the harness enforces the execution environment, computational sensors, context hygiene, and deterministic verification gates that prevent flawed code from reaching production.

---

## 1. The 3-Tier Execution Ladder

To eliminate over-engineering, latency, and context bloat, tasks are partitioned into three operational tiers:

*   **Tier 1 (Trivial / Fast Path):**
    *   *Scope:* 1–2 files, <20 lines of changes, typos, minor CSS/copy updates, or localized single-function tweaks.
    *   *Procedure:* Heavy `tasks.md` or multi-agent pipelines are bypassed. Execute relevant syntax/type checks (`tsc`, `mypy`) and targeted unit tests directly before delivery.
*   **Tier 2 (Standard Production - Default Harness Engine):**
    *   *Scope:* 3–8 files, feature additions, bug fixes, API endpoint development, database queries, and UI components.
    *   *Procedure:* Implementation plan artifact (Section 4A) and `tasks.md`, Blast Radius Mapping on symbol/type modifications (more than 8 affected files escalates to Tier 3), the sequential Verification Pipeline (Section 3), and auditor subagents (`silent-failure-hunter`, `security-boundary-verifier`) on critical data/security boundaries.
*   **Tier 3 (High-Volume / Architectural Refactoring):**
    *   *Scope:* >8 files, cross-system architectural migrations, schema redesigns, or authentication protocol overhauls.
    *   *Procedure:* Everything in Tier 2 plus the `deep-grill` trade-off interview, an ADR, call-graph reachability verification and independent auditor subagents before delivery; large efforts are decomposed with `unlazy` (Depth Tree) or `procoder` (Sprint / Backlog).
*   **Vertical Slices Discipline:**
    *   Construct narrow, end-to-end, demoable vertical paths cutting through all affected architectural layers (schema -> API -> UI) within a single context window. Avoid wide, half-broken horizontal refactors that cannot be validated incrementally.

---

## 2. Zero-Trust Computational Gate Principle & Immutable Test Invariant

Language models exhibit natural optimism regarding code they produce (inferential bias). Therefore:
* **Inferential Trust is Prohibited:** The model's claim that "code is complete and should work" holds zero evidentiary weight.
* **Computational Sensors are Mandatory:** Task completion is proven exclusively when deterministic terminal tools (compiler, type checker, linter, unit test suites) exit with zero errors (`exit code 0`).
* **Strict Gate Rule:** An agent cannot complete a delivery while compiler or test errors remain active. The feedback loop continues until resolved or escalated.
* **Immutable Test Invariant:** Constitution Rule 9 governs tests (no weakening, fix the source, test at seams, legacy transition requests). The procedural parts live here:
  * **Test diff inspection** before declaring completion: `git diff HEAD -- ':(glob)**/tests/**' ':(glob)**/__tests__/**' ':(glob)**/spec/**' ':(glob)**/*test*' ':(glob)**/*spec*'`. Any unauthorized change to an existing assertion trips the gate (`BLOCKED: Unconfirmed Test Mutation Detected`).
  * **Authorized contract changes** are recorded in `tasks.md` as `## Authorized Test Modifications: [<file_path>: <reason>]`.
  * Deterministic backstop: `agy-guard test-boundary verify` / `python3 scripts/verify_invariants.py --test-boundary`.

---

## 3. Verification Pipeline

Upon writing or editing code, the agent sequentially executes and evaluates outputs from these gates:

```
[Code Implementation / Modification]
          │
          ▼
   1. Type & Syntax Gate  (TypeScript: `npx tsc --noEmit` | Python: `mypy` | Go: `go vet`)
          │  (On error -> invoke `build-error-resolver`)
          ▼
   2. Formatting & Lint Gate (`eslint`, `prettier --check`, `ruff`, `golangci-lint`)
          │  (On error -> auto-correct)
          ▼
   3. Call-Graph Reachability (Grep or file-based routing patterns)
          │  (Error: 0 callers -> Wire to entry point or mark with @entrypoint)
          ▼
   4. Deterministic Unit Tests (`npm test`, `pytest`, `go test ./...`) - At contract seams
          │  (Failing tests -> blocked from exit until green)
          ▼
   4a. Test Integrity & Mutation Guard (`git diff HEAD -- ':(glob)**/tests/**' '**/*test*' '**/*spec*'`)
          │  (Existing assertions modified/deleted without user consent -> BLOCKED)
          │  (New tests added or authorized in tasks.md -> PASSED)
          ▼
   5. Silent Failures & Security (`silent-failure-hunter` and `security-boundary-verifier`)
          │  (Mandatory for Tier 3 or Security/Core exceptions; bypassed for Tier 1-2)
          ▼
    6. Verification Gap Declaration (Gap-Round: explicit declaration of unverified boundaries)
          │  (Critical unverified gap blocks delivery; requests user review)
          ▼
    7. Delivery Block (Rule 5: verified / not verified, next step only at phase ends or handoffs)
          │
          ▼
[User Delivery]
```

---

## 4. Artifact-Driven Context Hygiene

As conversation trajectories grow, models suffer context rot and instruction loss. Operational state is therefore managed in persistent disk artifacts rather than transient model memory:

### A. Standard Artifact Hierarchy
For medium and large tasks, maintain aligned platform artifacts and disk tracking:
1. **`implementation_plan.md` (Design Document & Review Gate):** Created in the Antigravity artifact directory (`<appDataDir>/brain/<conversation-id>/implementation_plan.md`) with `ArtifactMetadata` (`request_feedback: true`, `user_facing: true`) to trigger the platform's interactive "Proceed" review UI.
2. **`tasks.md` (Execution Checklist):** Checkable milestones (`[ ]` / `[x]`) maintained at the workspace root as a persistent ledger.
3. **`walkthrough.md` (Delivery Walkthrough):** Summary of verified changes, automated gate outputs, and verification gap declarations upon task completion.
4. **`HANDOFF.md` (Session Handoff):** The single handoff mechanism for multi-session work, written from `~/.gemini/config/templates/HANDOFF.template.md` when a Rule 13 handoff trigger fires. It carries the authoritative goal and exit criteria; `tasks.md` stays the execution checklist and is not a second handoff ledger.

### B. Context Preservation Discipline
* Update `tasks.md` on disk immediately upon completing each sub-step.
* Even if conversation history undergoes compaction, read `tasks.md` from disk to resume execution deterministically.

### C. Think in Code (Constitution Rule 11)
* Avoid using the model as a raw data processor; generate code to let the operating system compute.
* When scanning more than 3 files, run targeted shell one-liners (`grep`, `jq`, `awk`) via `run_command` instead of dumping whole files into context.
* **Bulk Inspection Barrier:** when analyzing 5+ files or a dataset, write a one-off script in `<appDataDir>/brain/<conversation-id>/scratch/` that prints only the aggregated result. Read-only auditor subagents without execution tools use bounded search primitives (`grep_search`, bounded `view_file`).
* **No raw stream dumps:** pipe `curl`/`wget`/log output through filters or into `scratch/stream_<name>.tmp`, inspect the slice, then delete the temp file. Never silently truncate failing compiler/test traces.
* **Subagent sandbox for heavy ingestion:** documentation over 50 KB goes to the `research` subagent; traces over 500 lines go to `build-error-resolver` or an isolated diagnostic subagent. For broad codebase exploration, dispatch the read-only `research` subagent.

### D. Work Scope Quad-Classification (Anti-Scope-Explosion)
During decomposition and execution (`tasks.md`), every discovered item goes into exactly one class:
- **`REQUIRED`**: directly needed for the user's explicit objective.
- **`NECESSARY FOR SAFETY/CORRECTNESS`**: discovered during the work; needed to prevent a regression or boundary break.
- **`VALUABLE`**: an improvement not needed now: parked for later, never implemented in-band.
- **`OUT OF SCOPE`**: unrelated observations or speculative refactors: not included.

---

## 5. Multi-Agent Orchestration (Actor-Verifier Topology & Pre-flight Gate)

Having a single agent persona assume all roles degrades output quality. However, dispatching subagents on every minor edit introduces unacceptable latency. The **Pre-flight Gate** topology solves this:

### A. Trigger Timing
1. **On-Demand Escalation:** If the primary agent fails to resolve a compiler or type error after two consecutive attempts, invoke `build-error-resolver`.
2. **Pre-flight Gate:** Immediately following code completion and local test passes, run auditor subagents (`silent-failure-hunter`, `security-boundary-verifier`) in parallel before final user delivery.

### B. Contract Injection Model
Do not dump the full conversation transcript to subagents. Pass only:
* **Task Objective:** Single-sentence summary of the modification.
* **Diff / Modified Files:** The exact code difference to review.
* **Audit Focus:** The specific vulnerability or invariant to evaluate (e.g. unhandled error propagation or unauthorized data access).

### C. Subagent Roles
1. **Actor (Primary Developer Agent):** Designs architecture, writes production code, and builds primary test suites.
2. **Build Error Specialist (`build-error-resolver`):** Resolves compiler/type errors with minimal diffs without modifying core architecture.
3. **Silent Failure Hunter (`silent-failure-hunter`):** Flags swallowed exceptions (`catch {}`), missing logs, and dangerous fallback returns.
4. **Security Boundary Verifier (`security-boundary-verifier`):** Audits authorization boundaries, injection risks, and race conditions (TOCTOU) using negative test cases.
5. **Specification Gap & Consistency Auditors (`specification-gap-auditor`, `consistency-auditor`):** Evaluates specifications, architectures, and rules for omissions, axiomatic contradictions, and logical cycles.
6. **Research & Heavy Ingestion Specialist (`research`):** Ingests large external documentation (>50 KB) and explores broad codebases in an isolated sandbox, returning distilled contracts to the primary session.

### D. Staged Artifact Passing & Partial Stage Re-Execution
For sequential multi-subagent pipelines (`Agent 1 -> Agent 2 -> Agent 3`):
1. **Numbered stage contracts:** persist each stage's output as a file (`<appDataDir>/brain/<conversation-id>/scratch/stage_01_<role>.md`, `stage_02_<role>.md`, ...) instead of relaying large prose through the parent conversation.
2. **Partial re-execution:** when a follow-up or a failed verification requires revising stage *k*, keep the validated outputs of stages 1..k-1 and re-run only from stage *k*, passing the upstream artifact paths in the subagent invocation contract.

---

## 6. Entropy and Drift Management

As codebases evolve, documentation, decision records (`ADR`), and rules diverge from implementation. Harness enforces periodic audits:
* **MISTAKES.md Rule Promotion:** A failure pattern recurring three times in `MISTAKES.md` is promoted to a mechanical check (script, hook, test) or a skill rule first; it enters `GEMINI.md` only when no mechanical or skill-level home exists (Constitution Rule 10).
* **Broken Contract Audits:** When API schemas or shared types change, update dependent documentation and contract tests in the same session.

---

## 7. Triggers and Invocations

* **Slash Commands:** `/harness`, `/verify`, `/gate`, `/run-gate`.
* **Natural Language Triggers:** *"Run the verification gate"*, *"Apply harness discipline"*, *"Verify tests and types before completing"*.
