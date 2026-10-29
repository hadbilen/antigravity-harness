---
name: dependency-upgrade
description: >-
  Upgrades a dependency, framework, or runtime without changing behavior: exact version pair, intersection delta
  catalog of breaking changes this codebase actually meets, baseline suite measured before the bump, and one dependency
  per change set. Invoke with /dependency-upgrade or when asked to upgrade or bump package/runtime versions ("sürümü
  yükselt", "bağımlılıkları güncelle", "version bump"). Not for adding a brand-new dependency to a feature, or
  generational modernization and dead-runtime porting of unbuildable legacy software (use 'renew').
---

# Dependency Upgrade: One Version Pair at a Time

An upgrade changes the versions underneath the code while preserving observable behavior. It succeeds when the project builds and behaves on the target version exactly as it did on the prior version, and every difference is explicitly accounted for. The method is to pin the exact version pair, catalog where this codebase intersects upstream changes, measure the baseline suite before touching the manifest, and upgrade one dependency at a time.

## 1. Pin the Exact Version Pair

- State the exact version installed today and the exact target version to reach. Read the current version from the lockfile (`package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `poetry.lock`, `Cargo.lock`, `go.mod`) or installed package metadata, never from memory (`skills/harness/SKILL.md` §2). Never target an unpinned `@latest` tag (`GEMINI.md` Rule 12); resolve the target to a concrete version number first.
- A jump across multiple major versions, or upgrading a runtime and a framework simultaneously, must be split into sequential hops. Each hop must build and pass verification before the next hop starts. List the hops and their order in the plan.
- Use the package manager that owns the repository's existing lockfile.
- Upgrading multiple packages or crossing a major version boundary is at least Tier 2 (`skills/harness/SKILL.md` §1): write the plan with `AC-1..N` acceptance criteria before modifying manifests.

## 2. Build the Intersection Delta Catalog

The delta catalog lists only the upstream changes between the old and new versions **that this codebase actually touches**:

1. **What changed upstream between the two versions:** Read the release notes, changelog, and migration guide for every intermediate version from installed package docs or via the `research` subagent (`skills/harness/SKILL.md` §2 — never from training memory). Remember that minor or patch releases can also introduce behavioral shifts.
2. **What this codebase uses:** Search the repository (`run_command` via `git grep -n`, `ripgrep`, or `scripts/code_map.py`) for all imports, function calls, configuration keys, and command-line flags from the package.

For every intersection entry, record:
- **Location:** `file:line` and total call-site count;
- **Contract delta:** old signature/behavior vs. new signature/behavior;
- **Class:**
  - *Removed or changed interface* (fails loudly at compile or call time),
  - *Silent behavior change* (compiles and runs, but alters defaults, sort order, encoding, timezone/date handling, rounding, serialization shape, or exception types),
  - *Build or configuration pin* (`.nvmrc`, `.python-version`, `.tool-versions`, `engines`, `Dockerfile` base image, Continuous Integration (CI) workflow matrix),
  - *Peer/transitive dependency conflict*;
- **Remediation type:** mechanical (rename/codemod) vs. design judgment requiring user confirmation;
- **Pre-bump characterization test** required for any silent behavior change (Section 4).

If an official upstream codemod or migration tool exists, state which of three states holds: *exists*, *can run in this environment*, or *executed*. If the catalog reveals that most of the application must be rewritten, halt and report that the request is a migration rewrite rather than a version bump, and route generational modernization or dead-runtime porting to `skills/renew/SKILL.md`.

## 3. Measure Baseline Verification Before the Bump

Run the project's full verification pipeline (test suite, type checker, linter, build) on the **current version** before editing any manifest or lockfile. Record the exact number of executed tests and any pre-existing failures. That baseline measurement is the oracle the upgraded environment must match.

## 4. Pin Silent Behavior Changes Before Touching Versions

Where the delta catalog identifies a silent behavior change at a call site not covered by existing assertions, write a characterization test at that seam before bumping the version (`skills/test-design/SKILL.md` and `skills/refactoring/SKILL.md` §3): literal input and literal output captured on the old version. It must pass before the bump and will immediately reveal whether behavior shifted after the bump.

## 5. Upgrade One Dependency Per Change Set

- Upgrade one package (or one tightly coupled package family that must move in lockstep) per change set so any regression is immediately attributable and cleanly revertible.
- Apply mechanical call-site updates first, then approved judgment changes. Adopt new library idioms only where old ones were removed; park optional modernizations under `VALUABLE` (`skills/harness/SKILL.md` §4.D).
- Re-run the full verification pipeline after each hop and compare test counts and outcomes against the Section 3 baseline:
  - A previously passing test that now fails is a regression to fix.
  - A previously failing test that now passes is an unexplained behavior change to investigate, not an automatic win.
- Never weaken or edit existing test assertions to make the new version pass (`GEMINI.md` Rule 9). If an upstream breaking change invalidates an existing test's contract, raise a `[Legacy Test Transition Request]` for explicit user approval.

## 6. Audit the Lockfile Diff

- Regenerate the lockfile using the project's package manager (never hand-edit lockfiles).
- Inspect the lockfile diff, not just the manifest diff: list any transitive dependencies that crossed a major version boundary or were newly introduced.
- Verify any newly added or renamed transitive package name before accepting it (`GEMINI.md` Rule 12 supply-chain discipline).

## 7. Delivery

In the `GEMINI.md` Rule 5/8 Delivery Block, report: the exact version pair and hops executed, the intersection delta catalog with each item's resolution, the before/after test count comparison from Section 3, notable transitive lockfile shifts, deprecated APIs intentionally left untouched, and any runtime or codemod checks that could not be executed locally.

<!-- Parts of this file are adapted from third-party work under the Apache License 2.0 and the MIT License and were changed for this harness; see THIRD_PARTY_NOTICES.md. -->
