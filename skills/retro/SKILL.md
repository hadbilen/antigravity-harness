---
name: retro
description: >-
  Read-only engineering retrospective that analyzes repository records (MISTAKES.md, plan outcomes, tasks.md,
  HANDOFF.md, ADRs, and guard ledgers) to count recurring failure patterns and propose ranked improvements to product,
  process, and mechanical checks (Rule 10 3-strike promotion). Invoke EXCLUSIVELY when the user explicitly requests
  /retro or a retrospective. Never edits files.
---

# Retrospective: From Recorded Evidence to Ranked Proposals

When the user requests a retrospective (`/retro`), inspect the recorded history of the session or project and produce a ranked list of actionable proposals across Product, Process, and Environment (mechanical checks, hooks, skills, project instructions), alongside practices that proved effective. This skill is strictly **read-only**: it never mutates project code, `MISTAKES.md`, or governance files (`GEMINI.md` Rule 12).

## 1. Scope Selection

The user specifies the scope; when omitted, default to the current session and active workspace:

- **Session:** The current conversation trajectory and the artifacts it produced (`implementation_plan.md`, `tasks.md`, `walkthrough.md`, `MISTAKES.md`).
- **Project:** All historical records in the active workspace repository.

When analyzing a multi-directory or large project history (5+ files, `GEMINI.md` Rule 11), use a filtered aggregation script or dispatch the read-only `research` subagent with a fixed extraction contract (returning pattern counts, dates, and `file:line` coordinates) so raw historical logs do not flood primary context.

## 2. Records to Inspect

Inspect the existing artifacts on disk without re-reading raw past transcripts:
- **`MISTAKES.md`** at the project root (Date & Incident, Root Cause, Impact, Preventive Invariant).
- **Plan files and `walkthrough.md` / `implementation_plan.md`**, specifically checking the four Outcome labels (`skills/harness/SKILL.md` §4.A): **Deviations**, **Not verified**, **Surprises**, and **Follow-ups**.
- **`PRODUCT.md`** (if the project originated from a `vibecoder` prototype) and **Architecture Decision Records (`docs/adr/*.md`)**.
- **`tasks.md` and `HANDOFF.md`**, plus the project's verification scripts (`package.json`, `pyproject.toml`, `Makefile`, Continuous Integration (CI) workflows, `agy-guard status`).

## 3. Project Phase & Observable Trajectory

- **Identify the current project phase** from `tasks.md`, `docs/adr/`, and `PRODUCT.md`: *prototype*, *active build*, *stabilization*, *release*, or *maintenance*. Rank proposals that apply to the active phase first; park out-of-phase proposals with the reason.
- **Reconstruct the trajectory from observable events only:** user corrections, circuit-breaker halts (`GEMINI.md` Rule 13), reversed decisions, plans that deviated, or verification steps that were skipped. Cite `file:line` for each event; omit flattery or subjective commentary (`GEMINI.md` Rule 3 & Rule 7).

## 4. Group by Root Cause, Count Occurrences, and Check Current State

- Group incidents that share an underlying root cause and count exact occurrences, citing the date and `file:line` of each, plus the command/search used to count them.
- **Three-Strike Promotion Threshold (`GEMINI.md` Rule 10):** A pattern with **3 or more occurrences** is due for promotion. Patterns with 1 or 2 occurrences are listed at the bottom under *Noted (Below Threshold)*, not proposed as new rules.
- **Recency and Current Codebase Check:** The most recent recorded decision supersedes older habits. Before proposing a fix for a historical pattern, check the current codebase, linter config, and hooks—if a mechanical check or code change already closed the pattern, report it under *Already Resolved*, never as a new proposal.
- **Commit- and Date-Anchored Claims:** State every historical code or behavior claim with the date and commit SHA (or `file:line` record) at which it held rather than timeless present-tense ("currently", "now") assertions, and mark older claims as superseded when newer evidence overtakes them.
- **Classify each proposal by Kind:**
  - **Product:** A requirement that repeatedly shifts, an acceptance criterion that repeatedly fails, or a `PRODUCT.md` assumption that implementation keeps hitting.
  - **Process:** Planning omissions, missing pre-bump baselines, or skipped verification steps.
  - **Environment:** Linter rules, tests, `agy-guard` checks, `hooks.json` handlers, skills, or project instructions.
- **What Worked:** Highlight practices whose recorded outcomes show measurable value (e.g., zero regressions after characterization pinning, defects caught early by a specific auditor or hook), citing the records.

## 5. Choose the Lowest-Friction Durable Home (`GEMINI.md` Rule 10)

Classify the target failure mode before choosing where the proposal lives:

- **Mechanical** (a deterministic syntactic/textual pattern, a banned command or Application Programming Interface (API), a file path rule, a required command sequence, or a missing environment variable): propose a **deterministic check** at the cheapest layer—a project linter rule, a seam test, a `hooks.json` check (`guard/agy_hooks.py`), or a CI step. Build the check rather than adding prose. First check whether an existing linter/hook rule already exists but is disabled or unwired.
- **Judgment** (cross-file design trade-offs, domain modeling, seam adequacy): propose a targeted clause in the relevant on-demand `skills/<name>/SKILL.md` or an inspection bullet in the relevant `agents/<name>.md` auditor.
- **Always-on Constitution (`GEMINI.md` / `AGENTS.md`):** propose adding to always-on instructions **only** when no mechanical check, skill, or subagent home can carry it, and phrase it as a single compact sentence.

When the user accepts a mechanical check proposal, implement it in a subsequent `harness` task using the recorded historical incidents as positive test cases (which the new check must flag) alongside a clean control case (which the new check must allow).

When the user accepts a **Judgment** (`skills/<name>/SKILL.md` or `agents/<name>.md`) or **Always-on Constitution** proposal, verify it in a subsequent `harness` task via the **Propose–Probe–Compose Sandbox Loop** (bounded to at most 3 total probe attempts per `GEMINI.md` Rule 13) before committing:
1. **Propose:** Draft the candidate clause (or 2 concise candidate phrasings) in `<appDataDir>/brain/<conversation-id>/scratch/` without mutating live `~/.gemini/config/` files (`GEMINI.md` Rules 12 & 15a).
2. **Probe (Isolated Sandbox Evaluation):** Extract the recorded historical incident from `MISTAKES.md` or plan outcome records as a self-contained prompt fixture paired with a clean control case (without copying literal phrases from the candidate clause per `GEMINI.md` Rule 9 `C9`). Dispatch two isolated read-only subagent runs (`invoke_subagent` using `research`, the target auditor persona, or `self` under a read-only contract, passing the baseline vs. candidate clause inside the parent-authorized `Task Objective` / `Audit Focus` header per `skills/harness/SKILL.md` §5.B so `Prompt Defense Baseline` is respected).
3. **Compose:** Retain only the shortest candidate clause that produces a verified **behavioral contrast** (catching $\ge 1$ failure mode missed by baseline with $0$ new false positives on the clean control and zero collateral constitutional regressions); if no candidate achieves behavioral contrast within 3 attempts, discard the prose candidate and either reclassify the proposal as a deterministic **Mechanical** check or escalate to the user as `[OPEN QUESTION]`.

## 6. Report Format

Output the retrospective directly in chat (never write or mutate repository files during `/retro`):

```markdown
### <Pattern Title in One Line>

* **Occurrences:** <count> (<dates and file:line coordinates>, counted via `<search command>`)
* **Kind:** [Product | Process | Environment]
* **Class:** [Mechanical | Judgment]
* **Proposed Home:** [Linter Rule | Seam Test | Hook / Gate | CI Job | Skill Clause | Auditor Focus | Project Instructions]
* **Proposed Check or Change:** One concrete, directly implementable sentence.
* **Probe Fixture:** One-sentence historical scenario from `MISTAKES.md` or session records that must diverge between baseline and candidate runs.
* **Timing:** [Act Now | Parked (<reason>)]
* **Boundary / Known Misses:** What this check or rule will not catch.
```

Follow the ranked proposals with:
1. **What Worked** (backed by recorded evidence),
2. **Noted Patterns (1–2 Occurrences, Below Rule 10 Threshold)**, and
3. **Verification Gap Declaration (`GEMINI.md` Rule 8):** any logs or records that were unavailable or unread.
