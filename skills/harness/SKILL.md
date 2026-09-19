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
    *   *Procedure:* Full harness lifecycle: Artifact tracking (`tasks.md` / `plan.md`), Blast Radius Mapping on symbol/type modifications, the sequential Verification Pipeline (Section 3), and approval from auditor subagents (`silent-failure-hunter`, `security-boundary-verifier`) on critical data/security boundaries.
*   **Tier 3 (High-Volume / Architectural Refactoring):**
    *   *Scope:* >8 files, cross-system architectural migrations, schema redesigns, or authentication protocol overhauls.
    *   *Procedure:* Automatically transitions beyond standard harness boundaries to `unlazy` (Depth Tree) or `procoder` (Sprint / Backlog) scaffolding.

---

## 2. Zero-Trust Computational Gate Principle & Immutable Test Invariant

Language models exhibit natural optimism regarding code they produce (inferential bias). Therefore:
* **Inferential Trust is Prohibited:** The model's claim that "code is complete and should work" holds zero evidentiary weight.
* **Computational Sensors are Mandatory:** Task completion is proven exclusively when deterministic terminal tools (compiler, type checker, linter, unit test suites) exit with zero errors (`exit code 0`).
* **Strict Gate Rule:** An agent cannot complete a delivery while compiler or test errors remain active. The feedback loop continues until resolved or escalated.
* **Immutable Test Invariant (Goodhart & Seams Protection):** Weakening test assertions, skipping checks (`skip`), commenting out assertions, or loosening validation boundaries solely to pass verification gates is strictly forbidden. When a test fails, the source code must be corrected. Modifying existing test files requires explicit user authorization.
* **Test at Seams:** Tests target public interfaces, exported functions, and API boundaries—never internal volatile private methods. Exported pure logic functions represent contract seams and are testable. Refactoring internal implementation must leave seam tests green and unmodified.
* **Legacy Test Transition Exception:** If a test breaks because it is tightly bound to superseded private implementation details rather than a public contract, test weakening remains prohibited. Present an explicit `[Legacy Test Transition Request]` to elevate the test to an interface seam or retire it upon user approval.

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
   5. Silent Failures & Security (`silent-failure-hunter` and `security-boundary-verifier`)
          │  (Mandatory for Tier 3 or Security/Core exceptions; bypassed for Tier 1-2)
          ▼
   6. Verification Gap Declaration (Gap-Round: explicit declaration of unverified boundaries)
          │  (Critical unverified gap blocks delivery; requests user review)
          ▼
[User Delivery]
```

---

## 4. Artifact-Driven Context Hygiene

As conversation trajectories grow, models suffer context rot and instruction loss. Operational state is therefore managed in persistent disk artifacts rather than transient model memory:

### A. Standard Artifact Hierarchy
For medium and large tasks, maintain three artifacts at the workspace root:
1. **`spec.md` (Specification):** Requirements, acceptance criteria, and system invariants.
2. **`plan.md` (Architectural Plan):** Impacted components, dependency sequence, Blast Radius Mapping (direct consumers at `depth=1`, core schemas at `depth=2`), and risk analysis.
3. **`tasks.md` (Task Tree):** Granular checkable milestones (`[ ]` / `[x]`).

### B. Context Preservation Discipline
* Update `tasks.md` on disk immediately upon completing each sub-step.
* Even if conversation history undergoes compaction, read `tasks.md` from disk to resume execution deterministically.

### C. Think in Code
* Avoid using the model as a raw data processor; generate code to let the operating system compute.
* When scanning more than 3 files, run targeted shell one-liners (`grep`, `jq`, `awk`) via `run_command` instead of dumping whole files into context.
* For broad codebase exploration, dispatch the read-only `research` subagent to return synthesized summaries without polluting main conversation context.

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

---

## 6. Entropy and Drift Management

As codebases evolve, documentation, decision records (`ADR`), and rules diverge from implementation. Harness enforces periodic audits:
* **MISTAKES.md Rule Promotion:** Failure patterns occurring three times in `MISTAKES.md` are graduated into permanent constitutional rules in `GEMINI.md` or `AGENTS.md`.
* **Broken Contract Audits:** When API schemas or shared types change, update dependent documentation and contract tests in the same session.

---

## 7. Triggers and Invocations

* **Slash Commands:** `/harness`, `/verify`, `/gate`, `/run-gate`.
* **Natural Language Triggers:** *"Run the verification gate"*, *"Apply harness discipline"*, *"Verify tests and types before completing"*.
