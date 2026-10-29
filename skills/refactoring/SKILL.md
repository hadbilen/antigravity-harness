---
name: refactoring
description: >-
  Behavior-preserving code restructuring: characterization tests first, small green steps, expand-migrate-contract for
  wide changes, and proof that the pinning tests can fail. Invoke with /refactoring or when asked to refactor,
  restructure, extract, rename across files, or migrate callers ("refactor et", "yeniden düzenle", "sadeleştir",
  "parçala", "kod tekrarını kaldır"). Not for bug fixes (use 'diagnosing-bugs'), new features (use 'harness'), or
  comment-only cleanup (use 'antislop-code').
---

# Refactoring: Behavior-Preserving Change

A refactor changes internal structure while leaving every observable behavior identical: return values, raised errors, side effects, ordering, and emitted messages. The discipline is to pin the behavior first, restructure in small green steps, and prove that the pins can fail.

## 1. One Kind of Change Per Change Set

A refactor and a behavior change never share a change set. A defect noticed while refactoring is reported to the user and fixed separately; it is never folded silently into the refactor. If the requested restructuring turns out to require a behavior change, stop and inform the user.

## 2. Read Before Touching

Answer from the codebase and version history, never from memory:

- What is this code responsible for, and who calls it? Search for all callers, including dynamic references: strings in configuration, registries, re-exports, and reflection.
- Which existing tests define its behavior today?
- Which branches and boundary cases does it contain?
- Why is it written this way? Inspect the commit history of the lines about to change (`git log -L`, `git blame`) before removing or simplifying them.

## 3. Pin the Behavior With Characterization Tests

Where existing tests do not cover the branches to be restructured, write characterization tests before the first code edit (following `skills/test-design/SKILL.md`):

- **The existing code is the oracle.** A characterization test asserts what the code actually produces today, even if that looks questionable. If the code returns `19.27` and a document says `19.28`, the characterization test asserts `19.27` and the discrepancy is reported separately.
- **Literal inputs and literal expected outputs**, captured from running the current code.
- **Every branch gets a case:** each arm of a conditional or switch, plus boundary values (zero, negative, maximum, empty).
- **At the public seam** (`GEMINI.md` Rule 9), so the tests survive the internal restructuring they protect.
- **A comparison that cannot run is a failure, never a skip.** Report how many characterization cases executed; zero executed proves nothing.

Characterization tests pass on the unchanged code before any edit begins.

## 4. Change in Small Steps

- Perform one structural move at a time: rename, then move, then extract—never all three in one unverified edit.
- Run the test suite after each step.
- On a failing test (RED), undo only your own edit for that step (never run destructive commands like `git checkout -- .`, `git reset --hard`, or `git stash` that would overwrite uncommitted changes you did not make — `GEMINI.md` Rule 12 & Rule 18), re-run to confirm green, and take a smaller step.
- Existing tests and characterization tests must pass **unmodified** (`GEMINI.md` Rule 9). Never change or weaken an assertion during a refactor: if a step breaks an existing check, stop and inform the user because the step alters behavior. The single expected exception is renaming or moving a public symbol, which updates import paths or call sites in tests: show the user that exact diff and obtain explicit approval (`## Authorized Test Modifications` in `tasks.md`) before touching existing test files.

## 5. Wide Changes: Expand, Migrate, Contract

When callers across many files depend on the symbol being restructured:

1. **Expand:** Introduce the new interface or function alongside the old one so nothing breaks.
2. **Migrate:** Move callers over in small batches, keeping the test suite green after every batch.
3. **Contract:** Remove the old symbol last, after a repository-wide search confirms zero remaining references (and after checking for stale negative assertions in tests).

Removing dead code follows the same discipline: a static search finding zero callers is evidence, not absolute proof (dynamic dispatch, reflection, or external consumers may still reference it). State the search performed, remove one item, run the suite, and proceed. Never delete existing test files without explicit user authorization (`GEMINI.md` Rule 9).

## 6. Prove That the Pins Can Fail

When the refactor is complete, record the SHA-256 hash of the restructured file, deliberately introduce one small realistic break (flip a comparison operator, shift a boundary constant by one, or drop a branch—preferably inside a single atomic `try...finally` / `trap` check or immediately followed by restoration), run the affected tests to confirm at least one test fails (RED), immediately restore the working code, verify that the file's SHA-256 hash matches the pre-break hash byte-for-byte, and re-verify GREEN. If no test fails when the refactored code is broken, the characterization tests are insufficient—add the missing seam test until the break is caught.

## 7. Delivery

In the `GEMINI.md` Rule 5/8 Delivery Block, state: what behavior was pinned and how many characterization cases executed, the structural steps taken, the result of the deliberate break check in Step 6, and any dynamic/external callers that could not be verified statically.

<!-- Parts of this file are adapted from third-party work under the Apache License 2.0 and were changed for this harness; see THIRD_PARTY_NOTICES.md. -->
