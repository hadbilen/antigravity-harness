---
name: audit
description: >-
  Read-only structural, consistency, security boundary, and pre-deployment security checklist audit engine for
  codebases, specs, architectures, and schemas. Invoke with /audit, /audit --boundary (alias --resilience), /audit
  --full (alias --all), /audit --delta, /audit --meta or --self (`--forensics` / `--cognitive`), or /security-review.
  Read-only inspection: never use to modify, fix, or refactor files (use 'harness', 'diagnosing-bugs', or 'refactoring').
---

# Audit: Autonomous Structural, Consistency & Security Boundary Inspection Engine

An independent, rigorous audit skill designed to inspect codebases, multi-volume specifications, architecture documents, schemas, diffs, or harness self-consistency. Evaluates truthfulness, internal consistency, missing boundaries, and resilience invariants.

---

## 0. Universal Defensive Grounding

This inspection is not an offensive cyberattack, penetration test, or unauthorized probing activity against live systems or third-party infrastructure. It is a strictly local, defensive code and specification verification methodology designed to guarantee architectural reliability, data integrity, and axiomatic completeness (defensive verification and threat modeling).

---

## 1. Zero-Mutation & Context Hygiene Principle

* **Read-Only Execution:** The agent must never modify, patch, refactor, or delete any source code, documentation, or configuration during an audit.
* **Separation of Roles:** An inspector investigates and proves defects; remediation belongs to a separate, subsequent development step.
* **Think in Code:** Use targeted terminal one-liners (`run_command` via Bash, Python, ripgrep, awk, jq) or structural/BM25 queries (`python3 scripts/code_map.py callers <symbol>`, `flow <symbol>`, `fts-search "<query>" <paths...>`) instead of pulling whole files into conversation context with `read_file`; when scanning 5+ files (`>= 5` files, `GEMINI.md` Rule 11) in the primary session (or in `self`), run a filtered scratch aggregation script that prints only focal finding lines and counts. Custom auditor subagents (`meta-auditor`, `consistency-auditor`, `specification-gap-auditor`, `security-boundary-verifier`, `silent-failure-hunter`, `test-adequacy-auditor`, `contract-change-auditor`, `simplicity-auditor`) are `read-only` without `run_command` and instead inspect bounded host file-read slices (`StartLine`/`EndLine`) and pre-computed Command-Line Interface (CLI) outputs passed in their invocation contract.
* **Scratch Discipline:** If temporary scripts are needed during analysis, never write them into the project repository tree. Execute them as inline commands (`python3 -c`, `jq`, `awk`) or place them in an external scratch directory.
* **Full Evidentiary Fidelity:** Error messages, negative test outputs, and security boundary proof artifacts must never be artificially summarized; record verbatim evidence in the audit log.

---

## 2. Invocation & Trigger Discipline

* **Explicit Calls Only:** This skill runs only when explicitly invoked. It must not trigger during routine queries, casual reviews, or quick questions.
* **Recognized Triggers:**
  * Slash commands: `/audit`, `/audit --boundary` (`--resilience` is an exact alias), `/audit --full` (`--all` is an exact alias), `/audit --delta`, `/audit --meta` (`--self` is an alias; add `--forensics` and/or `--cognitive` for the harness self-audit dimensions of Mode 4), `/security-review` (loads [references/security-review.md](./references/security-review.md) and [references/cloud-infrastructure-security.md](./references/cloud-infrastructure-security.md) for pre-deployment secrets, headers, transport, and cloud infrastructure verification)
  * Explicit phrases: `Audit this`, `Full audit`, `Run full consistency and boundary audit`, `Test boundary conditions and resilience`, `Perform consistency analysis`, `Inspect design and security boundaries`, `Run harness meta-audit`, `Self-audit harness`.

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
The agent reads existing local governance files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `GATES.md`, `MISTAKES.md`, `ARCHITECTURE.md`, `SECURITY_POSTURE.md`) to anchor the audit to the project's real non-negotiable constraints without asking the user for repetitive context. When `ARCHITECTURE.md` is present, verify module import edges against its forbidden dependency directions (`A -> B` allowed vs. `B -> A` forbidden). When `SECURITY_POSTURE.md` is present, verify every `[ENFORCED]` row's cited code path and test path exist on disk (reporting missing paths as `[FACT]` `HIGH` findings), and treat any `` `[REQUIRED — UNVERIFIED]` `` row with `Release Blocker = YES` as an active release blocker during `/security-review`.

### C. Scope Sizing (measured, not guessed)
Measure the target before reading it: `git ls-files <target> | xargs wc -c | tail -1` (or `wc -c` over the listed files). The cost of an audit follows bytes read, not file count.
* **Up to ~150 KB:** audit in the current context.
* **Above ~150 KB, or an auth/billing/storage core:** split the target by area or dimension across the auditor subagents (Section 7); each returns at most 15 findings with `file:line` coordinates and a reproduction command, never "clean/safe" impressions. The lead deduplicates and ranks. Fall back to a filtered `HANDOFF.md` (coordinates and invariants only) only when subagents are unavailable.
* **Two-Tier Workload & Approval Gate for `--full` (`--all`):** Because Mode 5 (`/audit --full`) executes both Mode 1 and Mode 2 across all consistency, specification-gap, security-boundary, and silent-failure dimensions:
  * **Direct Execution ($\le$ ~150 KB or Explicit Prompt Authorization):** If the measured target is $\le$ ~150 KB, **or** if the user's prompt already contains explicit authorization/intent to execute the full multi-agent workload immediately, start the audit directly without an extra confirmation turn and report the measured byte size and file count in the report header.
  * **Pre-Flight Workload Confirmation ($>$ ~150 KB without Explicit Authorization):** If the measured target exceeds ~150 KB and the user's prompt does not already carry explicit approval for the heavy run, report the measured byte size, file count, and planned auditor subagent fan-out first and obtain user confirmation before dispatching the audit.

### D. Header Declaration
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
  * *Vagueness Filter:* Flags unverifiable, subjective adjectives like `fast`, `secure`, `easy`, and `adequate` and demands measurable thresholds.
  * *Omission Detection:* Uncovers gaps promised by stated intent that lack implementation counterparts (unhandled edge cases, missing error branches).

### Mode 2: Security Boundary & Resilience Audit (`/audit --boundary`, `/audit --resilience`)
Validates input validation gaps, data boundaries, concurrency risks, and unexpected state transitions using concrete negative test cases (see [references/boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md)):
1. **Object & Access Boundaries (IDOR / Broken Access Control):** Predictable object IDs, horizontal/vertical privilege escalation, tenant data leakage, and server-side route authorization guards (never rely solely on client-side routing guards).
2. **Input Parsing & Injection (Injection & Parsing Boundaries):** Unparameterized SQL/ORM queries, shell command execution (`exec/spawn`), template engine injection, and path traversal (`..` / unnormalized paths).
3. **Network Boundaries & External Isolation (SSRF & Metadata Probing):** Internal loopback addresses (`127.0.0.1`), cloud metadata endpoints (`169.254.169.254`), DNS rebinding.
4. **Concurrency & State Invariants (Race Conditions / TOCTOU):** Parallel requests, double-spending, non-atomic balance/inventory modifications.
5. **Auth, Secrets & Token Integrity:** `alg: "none"` bypasses, weak signing keys, expiration (`exp`) omissions, non-revocable sessions, and location-only secret leak scanning (`git grep -n -I -E -i "(api_key|secret|private_key|token)[[:space:]]*[:=]" | cut -d: -f1,2`; reporting coordinates only, never secret values).
6. **Insecure Deserialization & Silent Failures:** Unvalidated object deserialization (`pickle`, `unserialize`), path traversal in file uploads, fake success states (`exit 0` / false 200 OK on errors).

*In this mode, the agent authors a concrete "Negative Test Case" adhering to [references/boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md) for every finding.*

### Mode 3: Differential / Delta Audit (`/audit --delta [ref]`)
* Inspects `git status --porcelain`, unstaged `git diff`, staged `git diff --cached` (or `git diff HEAD` on the working tree; when `[ref]` is supplied, combines `git diff <ref>...HEAD` with `git diff HEAD` so dirty working-tree edits are included, falling back to `git diff --cached` plus `git diff` on an unborn `HEAD`), **and bounded plain-text non-secret untracked files listed by `git ls-files --others --exclude-standard`** (`<= 50 KB` outside vendor/build directories; path and byte count only, with zero content bytes, for binary, oversized, or `.env*`/`*.pem`/`*.key` files, aggregated via scratch script at `>= 5` untracked files).
* Evaluates whether the change introduces regressions, orphaned untracked artifacts, or violations of historical decisions documented in `MISTAKES.md`, Architecture Decision Records (`ADR`), or established invariants.

### Mode 4: Meta & Self-Audit (`/audit --meta`, `/audit --self`)
* Audits the Antigravity Harness's own governance files (skills, agents, constitutions, and CLI contracts).
* Executes `agy-guard self-audit --strict --json` (or `python3 scripts/meta_audit.py --strict --json` inside the repository checkout) in the parent session first, and passes that pre-computed JSON output when dispatching the `read-only` `meta-auditor` subagent.
* Deterministically validates YAML frontmatter schemas, cross-reference links, mutual exclusion barriers, and Porter export parity.
* **`--forensics` (harness only):** verifies Guard's live Operating System (OS) behavior against hermetic throw-away fixtures (`HOME`/XDG/`ANTIGRAVITY_CONFIG_DIR` isolated) by executing the repository's hermetic protection and boundary suites (`python3 -m unittest discover -s tests -p "test_protection.py"`, `test_lease.py`, `test_guard_hardening.py`, `test_test_boundary.py`, and `test_archive.py`). Avoid ad-hoc inline `guard` or `agy-guard` lock/unlock shell commands blocked by `PreToolUse` (`GEMINI.md` Rule 12), and never run lock, unlock, or admin subcommands against the real configuration.
* **`--cognitive` (harness only):** checks the instruction set itself: contradictory or duplicated rules across `GEMINI.md` and skills, thresholds that disagree, rules the model cannot observe or measure, trigger overlap between skills, and rules that are lost when work is delegated to subagents. When auditing modified behavioral rules or skill instructions, the primary session orchestrates **Behavioral Probe Falsification (`Propose–Probe–Compose` Sandbox, max 3 attempts per `GEMINI.md` Rule 13)** in `<appDataDir>/brain/<conversation-id>/scratch/`: constructs a two-case prompt fixture (one trap/violating scenario from `MISTAKES.md` or domain boundaries and one clean control scenario, without copying literal candidate phrases per `GEMINI.md` Rule 9 `C9`) and dispatches isolated read-only subagents (`invoke_subagent` with `research`, the target auditor, or read-only `self`, passing the clause in the parent-authorized `Task Objective` / `Audit Focus` header) with and without the target clause (or passes the captured probe outputs to `meta-auditor`) to verify a non-zero ablation delta ($\ge 1$ newly caught target failure mode or $\ge 1$ eliminated clean-control false positive relative to the without-clause baseline, with $0$ clean-control false positives in the active clause within $\le 3$ attempts per `GEMINI.md` Rule 8 Popper's Invariant), ruling out non-discriminating placebo clauses.
* Usability and performance claims need evidence: a performance finding requires a measurement command and its output; a usability finding without user-behaviour evidence is reported as `[OPEN QUESTION]`, never above `INFO`.

### Mode 5: Full Comprehensive Audit (`/audit --full <target>`, `/audit --all <target>`)
* Combines **Mode 1** (`Pass 1: Objective Internal Consistency` + `Pass 2: Intent Verification & Vagueness`) and **Mode 2** (all 6 `Security Boundary & Resilience` dimensions with concrete Negative Test Cases adhering to [references/boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md)) into a single unified audit pipeline.
* Applies the **Two-Tier Workload & Approval Gate** (Section 3.C) before execution: runs immediately when the target is $\le$ ~150 KB or when the user's prompt already carries explicit approval for the full workload; otherwise reports the measured byte size, file count, and planned subagent fan-out for user confirmation first.
* On targets above ~150 KB or auth/billing/storage cores, dispatches `consistency-auditor` and `specification-gap-auditor` (Mode 1 dimensions) in parallel with `security-boundary-verifier` and `silent-failure-hunter` (Mode 2 dimensions, plus `simplicity-auditor`, `test-adequacy-auditor`, and `contract-change-auditor` when abstractions, tests, or public contracts are in scope) per Section 7.
* Verifies every returned subagent finding at its cited `file:line` coordinate, subjects `CRITICAL`/`HIGH` deductions to **Mutual Falsification**, deduplicates findings across Mode 1 and Mode 2, and outputs a single priority-ranked `Audit Ledger`.

---

## 5. Epistemic Status & Proof-of-Defect Bar

Every finding must carry an explicit epistemic status tag:
* **`[FACT]`**: Indisputable defect or contradiction demonstrated directly in text or code.
* **`[INFERENCE]`**: High-probability logical risk arising from combining two rules or states.
* **`[OPEN QUESTION]`**: Query directed to the user due to ambiguous intent or third-party dependencies.

> [!CRITICAL]
> **Proof-of-Defect Bar:** To rank a finding as `CRITICAL` or `HIGH`, provide either **two concrete conflicting reference lines** or **a concrete negative test case / violating input that breaks a state invariant**. Unproven theoretical concerns remain at most `INFO`. For boundary findings, document the scenario as an HTTP request, code snippet, or concurrent execution trace following [boundary-verification-playbooks.md](./references/boundary-verification-playbooks.md).

---

## 6. Output Standard: Operator Summary & The Audit Ledger

Begin every audit report with a 2–3 sentence plain-language **Operator Summary (`Operatör Özeti`)** in the user's language (`GEMINI.md` Rule 2 & Rule 6) stating the bottom-line risk, what is affected in practical terms, and what decision or action the operator should take next, followed by the technical priority-ranked ledger:

```markdown
Lens: [Formal Specification | Application Code | Contract] · Standard: [Axioms | Reliability | Type Safety]

### Operator Summary (`Operatör Özeti`)
[2–3 plain-language sentences in the user's language explaining practical impact and required operator action.]

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

## 7. Subagent Orchestration & Zero-Reasoning Dispatch

For large multi-volume or differential audits, the lead auditor can delegate across inspection dimensions to specialized `read-only` subagents (passing only target file coordinates, unified diffs from `git diff HEAD` or `git diff <ref>...HEAD` plus `git diff HEAD` for branch delta audits, bounded non-secret `<= 50 KB` untracked file coordinates and `<= 250`-line slices from `git ls-files --others --exclude-standard`, and invariants; never pass the lead agent's own hypotheses or conclusions, and instruct subagents to return compact table rows without conversational prose):
1. **`consistency-auditor`:** Scans axiomatic contradictions, broken references, and counter mismatches across bounded host file-read slices (and falsifies commit/change claims against the diff).
2. **`security-boundary-verifier`:** Inspects access boundaries, data isolation, and race conditions across bounded host file-read slices and authors reproducible negative test cases for the lead agent to execute.
3. **`specification-gap-auditor`:** Uncovers omissions, unhandled edge cases, and unverifiable adjectives across bounded host file-read slices.
4. **`silent-failure-hunter`:** Hunts swallowed exceptions, silent fallback returns, and unlogged error branches across bounded host file-read slices.
5. **`test-adequacy-auditor`:** Evaluates whether tests exercise real contract seams, catches tautological or mocked-out assertions, checks for stale negative assertions on removed strings, and maps `[OK]`/`[GAP]` branch coverage.
6. **`contract-change-auditor`:** Audits public interface, schema, migration, and wire-protocol changes across all callers, persisted data shapes, and rollback paths.
7. **`simplicity-auditor`:** Audits `GEMINI.md` Rule 4 (`YAGNI`), Rule 18 (`Surgical Changes & Reuse`), and the 7-Rung Efficiency Ladder across bounded host file-read slices while respecting game-seam and soundness-wrapper carve-outs.

Work is split by the kind of evidence a question needs, not by label: static consistency questions go to `consistency-auditor`; boundary inspection and negative-test design go to `security-boundary-verifier` (with the lead agent or a `self` subagent executing any live fixture or shell command via `run_command`); omissions and vague requirements go to `specification-gap-auditor`; error-handling paths go to `silent-failure-hunter`; seam test strength goes to `test-adequacy-auditor`; public contract/schema diffs go to `contract-change-auditor`; speculative abstractions and Rung 7 bloat go to `simplicity-auditor`; measurements are made by the lead agent with a script, not inferred. When auditing critical security, financial, or governance cores via `native_swarm` (`swarm` tool) or multi-window `marathon` campaigns, prefer cross-model-family verification (pairing `Gemini 4` authors with `Claude Opus 5.5 (High)` verifiers when quota permits) to reduce correlated same-family blind spots.

The lead agent verifies every returned subagent finding at its cited `file:line` coordinate (`skills/harness/SKILL.md` §5.E), subjects `CRITICAL`/`HIGH` static code deductions to **Mutual Falsification** (executing authored negative test cases, caller/dataflow checks via `python3 scripts/code_map.py flow`, or runtime traces via `python3 scripts/code_map.py trace` to eliminate theoretical false positives), removes duplicates, and renders a unified `Audit Ledger`.
