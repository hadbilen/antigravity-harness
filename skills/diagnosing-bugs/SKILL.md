---
name: diagnosing-bugs
description: Systematic seven-phase root-cause analysis for bugs, test failures, regressions and measured performance problems. Classifies each failure (code, environment, tool, external) before any edit and prohibits speculative code edits until a reproducible feedback loop is established. Invoke when debugging, fixing failing tests, investigating crashes, troubleshooting regressions, or when something measured is too slow.
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

### Phase 0: Classify the Failure (before touching any source)
Label the failure with one or more of: **`CODE`** (application logic is wrong), **`ENVIRONMENT`** (tool/runtime/path/dependency/configuration), **`TOOL`** (an agent tool call failed, timed out or was rejected), **`EXTERNAL`** (a remote service or network endpoint), **`UNKNOWN`** (evidence is insufficient: reproduce and gather traces before changing anything). A failure can carry several labels (code that relies on an API the installed runtime lacks is `CODE` + `ENVIRONMENT`): fix each part where it lives. Never modify working application code to get around an environment, tool or external failure.

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
* **Hypothesis-bound scripts:** every diagnostic scratch script tests a stated hypothesis. When a script does not confirm it, revise the hypothesis from the evidence before writing the next script; open-ended trial-and-error scripting is progress theater. (Inventory/aggregation scripts required by Constitution Rule 11 are not diagnostic scripts.)

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
* **Rule Graduation:** When the same error pattern recurs 3 or more times, propose graduating it into a mechanical check (script, hook, test) or a skill rule first; only when neither is possible, into `AGENTS.md` or `GEMINI.md` (Constitution Rule 10).

## Performance Problems (Measured Optimization Path)
Optimization is a defect fix with a measurement instead of a failing test:
1. **Measure first:** a repeatable command and its number (time, memory, I/O calls, query count). No measurement, no optimization: without a measured problem the answer is Constitution Rule 8's null action.
2. **Change one thing** at the measured hot spot; keep public signatures and behaviour identical. Seam tests must pass unchanged (Rule 9); changing an API for ergonomics is a separate, user-approved design change, not an optimization.
3. **Re-measure with the same command** and report before/after numbers. Keep the change only if the gain is real and outside run-to-run noise.
