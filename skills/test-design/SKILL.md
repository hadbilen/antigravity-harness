---
name: test-design
description: >-
  Writing tests that fail for the right reason: one failing test at a public seam, independent expected values, and
  mocks only at system boundaries. Invoke with /test-design or when writing a new unit, integration, or regression
  test ("test yaz", "test ekle", "regresyon testi"). Not for auditing an already-finished diff (use
  'test-adequacy-auditor').
---

# Test Design

A test exists to catch a specific break. This skill is the reference for writing one that does: what a good test is, where it goes, how the expected value is obtained, when a mock is allowed, and the rules of the red → green loop. Worked examples are in [examples.md](./examples.md).

## 1. Scope and the Immutable Test Invariant

These rules govern the tests you write now. Existing tests are frozen (`GEMINI.md` Rule 9, enforced by `agy-guard test-boundary verify` / `python3 scripts/verify_invariants.py --test-boundary`): a weak existing test is reported to the user, never edited, relaxed, or deleted without explicit user authorization; a new assertion goes into a new test (in `--mode bugfix`, existing test files must remain 100% byte-identical and new regression tests go into a new test file; in `--mode tdd`, existing test files may be extended with pure line additions that never mutate or remove existing lines).

## 2. The Loop: Red, Then Green

1. **Find the project's own test command** before running anything (`GEMINI.md`, `AGENTS.md`, `package.json`, `pyproject.toml`, `Makefile`).
2. **Write one failing test** at a public seam for one behavior.
3. **Run it and confirm the red.** All three must hold:
   - the test *fails*; it does not error on an import, a syntax typo, or a missing fixture;
   - the failure message is the expected assertion failure;
   - it fails because the behavior is missing or wrong, which is what the test is about.

   A test that passes immediately tests behavior that already exists: it does not protect this change. State that explicitly and rework it.
4. **Write the minimum production code** that makes it pass (`GEMINI.md` Rule 9 & Rule 18: general logic only, never hardcoded test return literals or test-runner detection). No speculative features and no code for tests you have not written yet.
5. **Run the whole suite** and inspect the output.
6. Repeat, one vertical slice at a time. Do not write all tests first and all implementation afterwards: bulk pre-written tests describe imagined behavior and lock in internal structure before the implementation has taught you anything.

A regression test for a bug fix reproduces the reported symptom and fails on the unfixed code (`skills/diagnosing-bugs/SKILL.md` Phase 1 & Phase 5). Restructuring belongs after green, as a separate step (`skills/refactoring/SKILL.md`).

## 3. Seams: Where Tests Go

A seam is the public boundary where behavior is observed without reaching inside. Tests live at seams, never against volatile private internals (`GEMINI.md` Rule 9): internal helpers may change completely while the seam test remains untouched. A test that breaks during a behavior-preserving refactor was coupled to private implementation details.

Put testing effort on critical paths, state transitions, and complex branching logic. For Tier 2 and Tier 3 changes, list the target seams under test in the implementation plan (`skills/harness/SKILL.md` §4.A & §4.E).

## 4. Name the Break Before Writing the Body

Answer first: **which production defect should make this test fail, and is that change a bug or an intentional design decision?** A test earns its place by catching a wrong branch, a missing side effect, a swapped argument, a boundary violation, or a broken contract.

| Your answer | What to do |
|---|---|
| "I cannot name one" | Redesign the test around an observable behavior at the public seam |
| "The source text changed" | Execute the code and assert its return value, side effects, or exit code; never assert by grepping production source text |
| "Only an intentional decision" (a constant's value, exact prose wording, private structure) | That is a brittle change detector: it fires on deliberate redesign and sleeps through real bugs. Test the behavior that depends on the decision |

Test the contract your own code establishes at its boundaries (the route registered, the query emitted, the payload produced), not the framework's own documented mechanics. Constructors, getters, constants, and plain pass-through functions earn a test only when they validate, normalize, default, derive, enforce an invariant, or cause a side effect.

## 5. Expected Values Come From Outside the Code Under Test

Use concrete literals and hand-verified fixtures; a table of cases with literal inputs and literal expected outputs is the preferred shape. Never compute the expected value inside the test by calling the function under test, calling its internal helpers, or copying its formula into the assertion—doing so creates a tautology that passes even when the formula is wrong.

## 6. Mocks at System Boundaries Only

Mock at **system boundaries only**: external network services, wall-clock time, randomness, and where necessary out-of-process databases or filesystems. Never mock your own domain modules, internal collaborators, or the function under test.

- **Understand the real method's side effects first**; replace only the slow or external transport layer below the state transitions the test depends on.
- **The mock earns zero assertions.** Asserting that a mock was called or returned its configured literal proves nothing about the system's observable outcome. Assert the real component's output or state transition.
- **Mirror real payload shapes completely:** a partial mock fixture passes unit tests while downstream code that reads an omitted field crashes in production.
- **Give each boundary branch its own fixture:** separate explicit fixtures for success, error, timeout, and malformed response cases.
- **Deterministic wall-clock & time-to-live anchors:** never compare live `datetime.now()`, `time.time()`, or `Date.now()` against hardcoded calendar dates or fixed International Organization for Standardization (ISO) timestamps. Inject an explicit `now` clock anchor into the function under test or compute fixture timestamps relative to a deterministic anchor via `timedelta`.
- **No test-only methods in production code:** cleanup or reset helpers needed only by tests belong in `tests/` utilities, never on production classes.
- When mock setup exceeds half the test body, switch to a real in-memory or local integration fixture.

## 7. The Mental Mutation Pass

Before finishing, mentally apply five realistic mutations to the production code you wrote; at least one test must fail for each:

- a wrong constant or swapped argument;
- an inverted conditional branch (`<` vs `<=`, `if` vs `unless`);
- a skipped state transition or side effect;
- an empty, `null`, or default return;
- missing boundary validation for zero, empty, negative, unauthorized, or malformed input.

If a mutation would leave the test suite green, the behavior is unprotected or the new assertion is tautological.

## 8. Warning Signs (Anti-Patterns)

- Setup and assertion reference the exact same mutated object reference, guaranteeing equality.
- The test can fail only via an unhandled crash or syntax error (`assert result is not None` without checking value).
- The test fails on every intentional refactor and never on accidental logic regressions.
- Expected values are computed by loops, builders, or the production helper itself.
- The test reads production source files as strings or asserts only that a symbol name is absent.
- The test would still pass if the business logic were deleted and only the mock/framework remained.
- The test compares live wall-clock time (`datetime.now()`, `time.time()`, `Date.now()`) against a hardcoded calendar date or fixed ISO timestamp ("time-bomb" test that flips outcome as real calendar dates advance).
- A production method or environment branch exists solely to detect or serve the test suite (`GEMINI.md` Rule 9).
