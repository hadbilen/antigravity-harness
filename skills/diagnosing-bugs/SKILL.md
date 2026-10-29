---
name: diagnosing-bugs
description: Systematic seven-phase root-cause analysis for bugs, failing or flaky tests, regressions and unexpected performance regressions. Classifies each failure (code, environment, tool, external) before any edit and prohibits speculative code edits until a reproducible feedback loop is established. Invoke when debugging, fixing failing tests, investigating crashes, or troubleshooting regressions. Not for proactive performance optimization of working code (use 'sweetspot').
---

# Diagnosing Bugs & Root-Cause Analysis

Use this skill whenever investigating, reproducing, or fixing defects, regressions, or failing or flaky tests in any codebase.

**Proportion (Tier 1 Fast Path):** A defect already reproduced by a failing command with an obvious single-line root cause (Tier 1) may merge Phases 2 through 4 into one stated hypothesis and its verification check; Phases 0, 1, 5, 6, and (when triggered by Rule 10) 7 always run.

## Zero-Speculation Rule
NEVER propose speculative fixes, wrap code in superficial try/catch blocks, or modify code based on guessing before establishing a deterministic feedback loop that proves the defect.

## Context Hygiene & Think in Code
* **Computational Scanning:** When debugging across multiple logs or source files, do not read entire files one by one into conversation context. Execute targeted shell one-liners (`run_command` via Bash, Python, `grep`, `awk`, `jq`), structural dataflow queries (`python3 scripts/code_map.py callers <symbol>`, `flow <symbol>`; or `~/.local/share/antigravity-harness/runtime/scripts/code_map.py` when running outside the harness checkout), or ranked log searches (`python3 scripts/code_map.py fts-search "<query>" <paths...>`) to filter and pull only focal defect lines.
* **Output Filtering:** Use runner flags (`--silent`, `-q`, `--tb=short`) to suppress passing test chatter, but never pipe failing test or compiler output through `head` or `tail` (if a failure trace exceeds 500 lines, route it to `build-error-resolver` per `GEMINI.md` Rule 11, or redirect to a scratch file and read the complete failing block).
* **Accuracy Priority:** Failing test logs, stack traces, and compiler error output must never be artificially synthesized or truncated; preserve exact failure text.

## The Seven-Phase Investigation Discipline

### Phase 0: Classify the Failure (before touching any source)
Label the failure with one or more of: **`CODE`** (application logic is wrong), **`ENVIRONMENT`** (tool/runtime/path/dependency/configuration), **`TOOL`** (an agent tool call failed, timed out or was rejected), **`EXTERNAL`** (a remote service or network endpoint), **`UNKNOWN`** (evidence is insufficient: reproduce and gather traces before changing anything). A failure can carry several labels (code that relies on an Application Programming Interface (API) the installed runtime lacks is `CODE` + `ENVIRONMENT`): fix each part where it lives. Never modify working application code to get around an environment, tool or external failure.

### Phase 1: Establish a Reproducible Feedback Loop
* Formulate a single, deterministic command, script, or test case that triggers the failure reliably. Where a test can express the defect, that test is the loop: it becomes the regression test of Phase 5, failing (RED) now and following `test-design`.
* Run the command and verify that it consistently fails (RED).
* If the defect is interactive or non-deterministic, capture the exact inputs, environment, and state progression before touching code. For a test that passes and fails on the same code, follow **Flaky and Non-Deterministic Tests** below.

### Phase 2: Minimize & Isolate
* Strip away extraneous variables to find the smallest reproducible example (minimal payload, minimal state, minimal file).
* Identify the exact boundary where expected behavior diverges from actual behavior. Use `python3 scripts/code_map.py flow <symbol>` (or `python3 ~/.local/share/antigravity-harness/runtime/scripts/code_map.py flow <symbol>`) to trace backward argument origins (`backflow`) and forward return-value consumers (`forwardflow`) without reading every intermediate file manually.
* Distinguish between the **trigger** (what initiated the error), the **fault** (the defective logic or state), and the **symptom** (the visible failure or crash).
* **Regressions (worked previously):** Identify the last known good commit and bisect between it and the failing commit using the Phase 1 reproduction command (`git bisect run <command>`) rather than reading commit history manually.

### Phase 3: Formulate & Rank Hypotheses
* Formulate 2–3 concrete hypotheses for the root cause, ranked by likelihood.
* For each hypothesis, define a specific **falsification test** (what evidence would prove this hypothesis wrong?).
* **Hypothesis-bound scripts:** every diagnostic scratch script tests a stated hypothesis. When a script does not confirm it, revise the hypothesis from the evidence before writing the next script; open-ended trial-and-error scripting is progress theater. (Inventory/aggregation scripts required by Constitution Rule 11 are not diagnostic scripts.)

### Phase 4: Instrument & Verify Hypothesis
* Add minimal, targeted diagnostic logging, assertions, or run the reproduction script under the structural runtime tracer (`python3 scripts/code_map.py trace <repro.py> --json` or `python3 ~/.local/share/antigravity-harness/runtime/scripts/code_map.py trace <repro.py> --json`) to capture actual call edges, concrete argument values, and return values across polymorphic dispatch, comprehensions, and lambdas.
* Observe the actual state against expectations. Do not modify business logic yet.
* Confirm which hypothesis matches reality with empirical proof.

### Phase 5: Fix Root Cause & Prove Green
* Apply the minimal, cleanest fix addressing the true root cause, not merely suppressing the symptom.
* Run the feedback loop from Phase 1 and prove that it passes (GREEN).
* Add a regression test at the contract seam (`test-design`) and watch it fail before or without the fix (if you forced the RED state by mutating code or a fixture, run `diff` against a pristine copy to prove the mutation landed before trusting the failure), then watch it pass with the fix.
* When a defect of the same shape has recurred, or the root cause is a hazard the code makes easy to repeat, apply `mistake-proofing`: close the structural hazard and grep the codebase for sibling occurrences of the same pattern.

### Phase 6: Clean Up & Verify Entire Scope
* Remove all temporary debug logging, scratch files, and instrumentation.
* Run the project's full test suite, linter, and build gate to verify no unintended side effects were introduced.

### Phase 7: Failure Log (`MISTAKES.md`) and Rule Graduation (`GEMINI.md` Rule 10)
* When the defect was an **unexpected failure of the agent's own work, a broken contract, or a user correction**, prepend an entry to `MISTAKES.md` in the project root (initialized from `~/.gemini/config/templates/MISTAKES.template.md`) with these four mandatory fields:
  * **Date & Incident:** Summary of the incident.
  * **Root Cause:** What flawed assumption or missing validation triggered it?
  * **Impact:** What regressed or failed?
  * **Preventive Invariant:** Concrete rule or mechanical check to prevent recurrence.
  * *(Note: An ordinary application bug fixed at the user's request is not an agent failure-log entry.)*
* **Rule Graduation:** When the same error pattern recurs 3 or more times (audited via `retro`), propose graduating it into a mechanical check (script, hook, test) or a skill rule first; only when neither is possible, into `AGENTS.md` or `GEMINI.md` (Constitution Rule 10).

---

## Flaky and Non-Deterministic Tests

A test that passes and fails on the same code has a concrete cause; it is a defect, not noise. Use this workflow when Phase 1 cannot make a failure deterministic:

1. **Establish the failure pattern with measured counts:** If the same commit fails every time, the test is deterministic—return to Phase 1. Otherwise run the test in isolation multiple times and record pass/fail counts; then run it inside the full suite; then run with test order reversed or randomized. Passing in isolation while failing in the suite points to order dependency or leaked shared state.
2. **Read the trace from the innermost error outward** and name the exact source of non-determinism before proposing any edit. Chained exceptions hide the root cause; the outer error line is rarely the fault.
3. **Classify, then fix by root-cause class:**

| Class | Root-Cause Fix |
|---|---|
| **Timeout** | Locate the slow or blocked operation and make it deterministic; never simply raise the timeout limit. |
| **Concurrency** | Add deterministic synchronization (barriers, locks, explicit joins); eliminate mutable state shared across concurrent tests. |
| **Asynchronous wait** | Poll the exact condition the test requires with a bounded timeout and state re-read inside the loop (Step 5). |
| **Wall-clock time** | Inject a controllable clock or compare relative/monotonic deltas rather than wall-clock timestamps. |
| **Randomness** | Pin the random seed or pass deterministic fixture inputs. |
| **Order dependency** | Isolate state in setup and teardown; no test may depend on side effects of a previously executed test. |
| **Environment** | Use hermetic test-local fixtures and explicit environment variables; eliminate shared temp paths or process-wide singletons. |
| **Resource leak** | Close every file, socket, or child process in a teardown block that executes even when the test fails. |
| **External network/service** | Stub at the seam boundary or run against a local ephemeral test server. |
| **Filesystem residue** | Create temporary directories per test and remove them in teardown. |

4. **Isolating state leaked across tests:** Run test files individually or bisect the test list until you find the earliest test that leaves behind the polluting file, database row, or global state.
5. **Wait for the condition, never a guessed duration:** Replace fixed `sleep` delays with a condition poll that re-reads state on each iteration, enforces an explicit timeout, and raises an error naming the exact condition that failed to settle. A fixed delay is valid only when timer behavior itself is under test.
6. **Prohibited pseudo-fixes (`GEMINI.md` Rule 9):** Never mask flakiness by raising timeouts, adding arbitrary `sleep` calls, wrapping tests in retry/rerun decorators, widening assertion tolerances, or skipping/quarantining tests without explicit user authorization.
7. **Infrastructure or external outages:** When evidence proves the failure is caused by an external service or runner infrastructure outside the repository, propose no application code change and report the classification (`ENVIRONMENT`, `EXTERNAL`, or `UNKNOWN`) with the logs.
8. **Existing test freeze (`GEMINI.md` Rule 9):** When fixing a flaky test requires editing an existing test file, present the exact diff to the user and record approval under `## Authorized Test Modifications` in `tasks.md` before mutating assertions.
9. **Prove resolution with repeated counts:** Execute the repaired test repeatedly in the exact suite order that previously failed and report the pass count (e.g., `20/20 passes`). A single passing run after a failing run is evidence of flakiness, not proof of a fix.

---

## Performance Problems (Measured Optimization Path)
Unexpected performance regressions and measured slowdowns follow this defect path; for **proactive, controlled optimization of an already working system** across execution speed, memory (`RAM`) footprint, disk/artifact size, or network download/upload bandwidth and round-trip latency (frame rates, scripts, startup latency, bundles, networked services, or compiled executables across operating systems) and the 3-Zone Sweet-Spot Honesty Gate, load `skills/sweetspot/SKILL.md` (`/sweetspot`, `/optimize`, `--all`, `--time`, `--memory`, `--disk`, `--net`). Optimization is governed by a repeatable measurement rather than a binary assertion:
1. **Measure first:** Establish a repeatable benchmark command and record its baseline metric (wall time, memory allocation, Input/Output (I/O) calls, or query count). Without a measured bottleneck, apply Constitution Rule 8's Null-Action Invariant.
2. **Locate, then change one variable at a time:** Profile to locate the hot spot (language profiler, query plan, allocation trace) and change a single variable at that hot spot while keeping public signatures and seam behavior identical (Rule 9). If an optimization would alter the system's domain, feature contract, or architecture, stop and request explicit user approval (`skills/sweetspot/SKILL.md` Zone 2).
3. **Simplicity Criterion & Append-Only Experiment Ledger:** Track every optimization attempt in an append-only table (`Attempt | Zone | Hypothesis & Target (file:line) | Diff Summary | Baseline | Measured | Status: KEEP/REVERT`). Apply the **Simplicity Criterion**:
   * A change that adds complexity for zero or noise-level gain (`< 1%`) is immediately reverted (`REVERT`).
   * A change that achieves equal or better performance while deleting code or simplifying state is kept (`KEEP`).
   * Never stack unverified optimization changes on top of a reverted or unmeasured attempt.
