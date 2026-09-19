---
name: diagnosing-bugs
description: Systematic seven-phase root-cause analysis for bugs, test failures, and regressions. Prohibits speculative code edits until a reproducible feedback loop is established. Enforces Think in Code context hygiene and MISTAKES.md logging. Invoke when debugging, fixing failing tests, investigating crashes, or troubleshooting regressions.
---

# Diagnosing Bugs & Root-Cause Analysis

Use this skill whenever investigating, reproducing, or fixing defects, regressions, or failing tests in any codebase.

## Zero-Speculation Rule
NEVER propose speculative fixes, wrap code in superficial try/catch blocks, or modify code based on guessing before establishing a deterministic feedback loop that proves the defect.

## Context Hygiene & Think in Code
* **Computational Scanning:** When debugging across multiple logs or source files, do not read entire files one by one into conversation context. Execute targeted shell one-liners (`run_command` via Bash, Python, `grep`, `awk`, `jq`) to filter and pull only focal defect lines.
* **Output Filtering:** For test and build invocations, use `--silent`, `-q`, `grep`, `head`, or `tail` rather than flooding context with raw standard output.
* **Accuracy Priority:** Failing test logs, stack traces, and compiler error output must never be artificially synthesized or truncated; preserve exact failure text.

## The Seven-Phase Investigation Discipline

### Phase 1: Establish a Reproducible Feedback Loop
* Formulate a single, deterministic command, script, or test case that triggers the failure reliably.
* Run the command and verify that it consistently fails (RED).
* If the defect is interactive or non-deterministic, capture the exact inputs, environment, and state progression before touching code.

### Phase 2: Minimize & Isolate
* Strip away extraneous variables to find the smallest reproducible example (minimal payload, minimal state, minimal file).
* Identify the exact boundary where expected behavior diverges from actual behavior.
* Distinguish between the **trigger** (what initiated the error), the **fault** (the defective logic or state), and the **symptom** (the visible failure or crash).

### Phase 3: Formulate & Rank Hypotheses
* Formulate 2–3 concrete hypotheses for the root cause, ranked by likelihood.
* For each hypothesis, define a specific **falsification test** (what evidence would prove this hypothesis wrong?).

### Phase 4: Instrument & Verify Hypothesis
* Add minimal, targeted diagnostic logging or assertions to test the top hypothesis.
* Observe the actual state against expectations. Do not modify business logic yet.
* Confirm which hypothesis matches reality with empirical proof.

### Phase 5: Fix Root Cause & Prove Green
* Apply the minimal, cleanest fix addressing the true root cause, not merely suppressing the symptom.
* Run the feedback loop from Phase 1 and prove that it passes (GREEN).
* Add a regression test so this specific defect cannot recur unnoticed.

### Phase 6: Clean Up & Verify Entire Scope
* Remove all temporary debug logging, scratch files, and instrumentation.
* Run the project's full test suite, linter, and build gate to verify no unintended side effects were introduced.

### Phase 7: Incident Logging (`MISTAKES.md`) and Rule Graduation
* For every resolved defect, prepend an entry to `MISTAKES.md` in the project root with these four mandatory fields:
  * **Date & Incident:** Summary of the defect.
  * **Root Cause:** What flawed assumption or missing validation triggered it?
  * **Impact:** What regressed or failed?
  * **Preventive Rule:** Concrete rule to prevent recurrence.
* **Rule Graduation:** When the same error pattern recurs 3 or more times, propose graduating it from `MISTAKES.md` into permanent rules in `AGENTS.md` or `GEMINI.md`.
