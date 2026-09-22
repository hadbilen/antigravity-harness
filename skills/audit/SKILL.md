---
name: audit
description: >-
  Independent, self-calibrating structural, consistency, and security boundary audit engine for codebases, formal specifications,
  architectural documents, and schemas. Evaluates internal consistency, intent alignment, omissions, and state invariant violations
  without mutating target files. Invoke with /audit, /audit --boundary, /audit --resilience, /audit --delta, /audit --meta, /audit --self.
---

# Audit — Autonomous Structural, Consistency & Security Boundary Inspection Engine

An independent, rigorous audit skill designed to inspect codebases, multi-volume specifications, architecture documents, schemas, diffs, or harness self-consistency. Evaluates truthfulness, internal consistency, missing boundaries, and resilience invariants.

---

## 0. Universal Defensive Grounding

This inspection is not an offensive cyberattack, penetration test, or unauthorized probing activity against live systems or third-party infrastructure. It is a strictly local, defensive code and specification verification methodology designed to guarantee architectural reliability, data integrity, and axiomatic completeness (defensive verification and threat modeling).

---

## 1. Zero-Mutation & Context Hygiene Principle

* **READ-ONLY EXECUTION:** The agent MUST NEVER modify, patch, refactor, or delete any source code, documentation, or configuration during an audit.
* **SEPARATION OF ROLES:** An inspector investigates and proves defects; remediation belongs to a separate, subsequent development step.
* **THINK IN CODE:** When scanning more than 3 files, do not pull files one by one into conversation context with `view_file`. Execute targeted terminal one-liners (`run_command` via Bash, Python, ripgrep, awk, jq) to extract only focal finding lines.
* **SCRATCH DISCIPLINE:** If temporary scripts are needed during analysis, never write them into the project repository tree. Execute them as inline commands (`python3 -c`, `jq`, `awk`) or place them in an external scratch directory.
* **DO NOT SACRIFICE ACCURACY FOR BREVITY:** Error messages, negative test outputs, and security boundary proof artifacts must never be artificially summarized; record verbatim evidence in the audit log.

---

## 2. Invocation & Trigger Discipline

* **EXPLICIT CALLS ONLY:** This skill runs ONLY when explicitly invoked. It MUST NOT trigger during routine queries, casual reviews, or quick questions.
* **Recognized Triggers:**
  * Slash commands: `/audit`, `/audit --boundary`, `/audit --resilience`, `/audit --delta`, `/audit --meta`, `/audit --self`
  * Explicit phrases: *"Audit this"*, *"Test boundary conditions and resilience"*, *"Perform consistency analysis"*, *"Inspect design and security boundaries"*, *"Run harness meta-audit"*, *"Self-audit harness"*.

---

## 3. Phase 0: Self-Calibration

Before performing any analysis, the agent inspects the target structure and declares its detected paradigm and standard in the report header (the line directly after the one-line verdict required by GEMINI.md Rule 1):

### A. Artifact Classification
1. **Formal Specification & Protocol Lens:**
   * *Triggers:* Rulebooks, mathematical/logical specifications, protocols.
   * *Standard:* Axiomatic completeness, invariants, acyclicity, cross-reference integrity, zero ambiguity.
2. **Application & Product Code Lens:**
   * *Triggers:* TypeScript, Go, Python, React, mobile, full-stack applications.
   * *Standard:* Operational viability, silent failure elimination, memory/resource bounds, race condition safety, data integrity, offline resilience.
3. **Contract & Schema Lens:**
   * *Triggers:* OpenAPI/Swagger, JSON Schema, GraphQL, SQL migrations, configuration files.
   * *Standard:* Type soundness, validation boundaries, backward compatibility, authorization scopes.

### B. Contract Grounding
The agent reads existing local governance files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `GATES.md`, `MISTAKES.md`) to anchor the audit to the project's real non-negotiable constraints without asking the user for repetitive context.

### C. Header Declaration
Every audit report MUST begin with a one-line verdict (GEMINI.md Rule 1), immediately followed by:
`Lens: [<Selected Lens>] · Standard: [<Applied Standard>] · Scope: [<Target>]`

---

## 4. Operational Modes

### Mode 1: Standard Audit (`/audit <target>`)
Executes two sequential analytical passes:
* **Pass 1 (Objective Internal Consistency):**
  * Contradictory statements or conflicting rules across text and code.
  * Broken references, nonexistent files/functions, defined but unused symbols.
  * Logical cycles and hierarchy inversions.
* **Pass 2 (Intent Verification & Vagueness):**
  * *Vagueness Filter:* Flags unverifiable, subjective adjectives like *"fast"*, *"secure"*, *"easy"*, *"adequate"* and demands measurable thresholds.
  * *Omission Detection:* Uncovers gaps promised by stated intent that lack implementation counterparts (unhandled edge cases, missing error branches).

### Mode 2: Security Boundary & Resilience Audit (`/audit --boundary`, `/audit --resilience`)
Validates input validation gaps, data boundaries, concurrency risks, and unexpected state transitions using concrete negative test cases (see [references/boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md)):
1. **Object & Access Boundaries (IDOR / Broken Access Control):** Predictable object IDs, horizontal/vertical privilege escalation, tenant data leakage.
2. **Input Parsing & Injection (Injection & Parsing Boundaries):** Unparameterized SQL/ORM queries, shell command execution (`exec/spawn`), template engine injection.
3. **Network Boundaries & External Isolation (SSRF & Metadata Probing):** Internal loopback addresses (`127.0.0.1`), cloud metadata endpoints (`169.254.169.254`), DNS rebinding.
4. **Concurrency & State Invariants (Race Conditions / TOCTOU):** Parallel requests, double-spending, non-atomic balance/inventory modifications.
5. **Auth & Token Integrity:** `alg: "none"` bypasses, weak signing keys, expiration (`exp`) omissions, non-revocable sessions.
6. **Insecure Deserialization & Silent Failures:** Unvalidated object deserialization (`pickle`, `unserialize`), path traversal in file uploads, fake success states (`exit 0` / false 200 OK on errors).

*In this mode, the agent authors a concrete "Negative Test Case" adhering to [references/boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md) for every finding.*

### Mode 3: Differential / Delta Audit (`/audit --delta [ref]`)
* Scans ONLY the latest git diff or recent commits.
* Evaluates whether the change introduces regressions or violates historical decisions documented in `MISTAKES.md`, `ADR`, or established invariants.

### Mode 4: Meta & Self-Audit (`/audit --meta`, `/audit --self`)
* Audits the Antigravity Harness's own governance files (skills, agents, constitutions, and CLI contracts).
* Executes `python3 scripts/meta_audit.py --json` or dispatches `meta-auditor` subagent.
* Deterministically validates YAML frontmatter schemas, cross-reference links, mutual exclusion barriers, and Porter export parity.

---

## 5. Epistemic Status & Proof-of-Defect Bar

Every finding must carry an explicit epistemic status tag:
* **`[FACT]`**: Indisputable defect or contradiction demonstrated directly in text or code.
* **`[INFERENCE]`**: High-probability logical risk arising from combining two rules or states.
* **`[OPEN QUESTION]`**: Query directed to the user due to ambiguous intent or third-party dependencies.

> [!CRITICAL]
> **Proof-of-Defect Bar:** To rank a finding as `CRITICAL` or `HIGH`, provide either **two concrete conflicting reference lines** or **a concrete negative test case / violating input that breaks a state invariant**. Unproven theoretical concerns remain at most `INFO`. For boundary findings, document the scenario as an HTTP request, code snippet, or concurrent execution trace following [boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md).

---

## 6. Output Standard: The Audit Ledger

Conclude every audit with a structured, priority-ranked ledger:

```markdown
Lens: [Formal Specification | Application Code | Contract] · Standard: [Axioms | Reliability | Type Safety]

### Finding Summary
* Critical: X | High: Y | Medium: Z | Info: W

### Audit Ledger
| # | Severity | Epistemic | Dimension | Location / Statement | Concrete Proof | Recommended Remediation |
|---|---|---|---|---|---|---|
| 01 | CRITICAL | [FACT] | Consistency | `spec_a.md:L40` vs `spec_b.md:L12` | Spec A states timeout=30s; Spec B states timeout=10s. | Declare a single central constant. |
| 02 | HIGH | [INFERENCE] | Security Boundary | `storage.ts:L88` | Negative Test: 0-byte file triggers uncaught JSON parse error. | Add try/catch and fallback validation. |
| 03 | MEDIUM | [OPEN QUESTION]| Vagueness | `specs/api.md:L15` | "High-volume requests" is unverifiable. | Define QPS threshold (e.g. 500 req/s). |
```

---

## 7. Subagent Orchestration

For large multi-volume audits or `/boost` workflows, the lead auditor can delegate across inspection dimensions to three specialized subagents:
1. **`consistency-auditor`:** Scans axiomatic contradictions, broken references, and counter mismatches.
2. **`security-boundary-verifier`:** Executes negative test cases for access boundaries, data isolation, and race conditions.
3. **`specification-gap-auditor`:** Uncovers omissions, unhandled edge cases, and unverifiable adjectives.

The lead agent synthesizes findings, removes duplicates, and renders a unified `Audit Ledger`.
