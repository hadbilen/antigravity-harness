---
name: marathon
description: >-
  Proactive multi-window goal planning, minimum-window task partitioning, per-window model/effort/skill routing,
  and deterministic session handoff orchestration via tasks.md and HANDOFF.md. Use for medium-to-large architectural
  builds, reworks, comprehensive revisions, multi-round audit/remediation campaigns, or promoting a vibecoder prototype
  into production. Invoke with /marathon or when the user says "maraton", "maraton başlat", "pencerelere böl", or
  "multi-window plan". Not for single-window Tier 1/2 tasks (use 'harness'), single-window autonomous subagent fan-out
  (use 'unlazy'), or .procoder/ sprint trees (use 'procoder').
---

# Marathon — Multi-Window Execution Planner & Handoff Orchestrator

Large architectural builds, deep reworks, and multi-round audit-and-remediation campaigns degrade when forced into a single exhausted context window—or when chopped into too many tiny, unverifiable fragments. `marathon` establishes a clear target upfront, packs the work into the **minimum viable number of self-contained context windows (`W1..Wn`)**, assigns the right **Model, Effort, and Skills** to each window, and drives execution through the repository's canonical `tasks.md` and `HANDOFF.md` files with zero unsolicited scope drift.

## Mutual Exclusion

- **Activation:** Triggered when the user invokes `/marathon` (or phrases such as `"maraton başlat"`, `"pencerelere böl"`), or when the user accepts the `/marathon` promotion offer at the end of a `vibecoder` prototype delivery.
- **Relationship with `harness`, `unlazy`, `procoder`, and `vibecoder`:** `marathon` is a multi-window session planner that operates directly on top of the `harness` verification pipeline (`skills/harness/SKILL.md`) using `tasks.md` and `HANDOFF.md` (`templates/HANDOFF.template.md`). It never creates a competing directory or ledger format:
  - When promoting a `vibecoder` prototype into a production system, `vibecoder` prototype mode ends and `marathon` + `harness` Tier 3 (`skills/harness/SKILL.md` §6) take over.
  - Repositories governed by `.procoder/` use the `procoder` sprint/backlog chain instead of `marathon`.
  - Single-window deep subagent fan-out uses `unlazy` (`.unlazy/`); `marathon` governs sequential human-in-the-loop context windows (`W1..Wn`).
- **Deactivation:** Ends when all Acceptance Criteria (`AC-1..N`) across `W1..Wn` are verified and `HANDOFF.md` is marked `[COMPLETE]`, or when the user says `"stop marathon"` (note: `"normal mode"` resets presentation styles like `chisle` first and only exits `marathon` when no presentation style is active or when the user explicitly says `"stop marathon"`), returning execution to standard single-window `harness` discipline.

---

## 1. Phase 1: Target & Scope Clarification (Before Planning Windows)

Never partition a vague goal into windows. Because `marathon` targets medium-to-large work (Tier 2 and Tier 3 `>8 files` architectural builds, reworks, revisions, and audit/remediation cycles), the agent must secure sufficient context before locking the window plan:

1. **Inspect Existing Artifacts First:** Read the repository structure, `PRODUCT.md` (if present, or the embedded `<script type="application/json" id="vibecoder-promotion-spec">` Section 1F metadata inside a `vibecoder` `.html` prototype), `MISTAKES.md`, and `docs/adr/` before asking the user anything the codebase already answers.
2. **Clarify Missing Boundaries (`skills/deep-grill/SKILL.md`):** If the target outcome, Version 1 (`V1`) scope boundary, technology constraint, or acceptance criteria remain ambiguous, ask pointed questions **one at a time** via `ask_question` with 2–3 concrete options and one `(Recommended)` choice (in exported runtimes lacking `ask_question`, emit at most `3` numbered plain-text questions with `2–3` options and `1` `(Recommended)` default per question, then stop for user input).
3. **Lock Authoritative Goal & Acceptance Criteria:** Define the authoritative goal in 1–2 sentences and 3–7 measurable `AC-1..N` items (`Scenario`, `Action`, `Expected`, `Must not`, `Verification` per `skills/harness/SKILL.md` §4.E). These criteria remain invariant from `W1` to the final window.

---

## 2. Phase 2: Minimum-Window Packing Rule (Anti-Fragmentation Gate)

Context windows are expensive to switch; excessively long windows suffer context rot. Partition work using the **Minimum-Window Packing Rule** (`2 <= N <= 4` windows for standard campaigns; `1–3` `AC-1..N` criteria and `<= 8` touched files per implementation window):

1. **Single-Window Refusal:** If the scoped work fits safely within a single context window (Tier 1 or a self-contained Tier 2 vertical slice of 3–5 files with straightforward verification), **do not split it across windows**. State that 1 window is sufficient and execute the task directly in the current window under `harness` discipline.
2. **Fewest Self-Contained Windows (`W1..Wn`):** Pack related work into the smallest number of windows where each window delivers a **complete, deterministic, and testable vertical slice or cognitive phase**:
   * **Pattern A — Prototype-to-Production / Architectural Build (2–3 Windows):**
     * `W1 (Architecture & Foundation Slice):` Target clarification, schema/contract design, and the primary end-to-end vertical slice passing unit/type gates.
     * `W2 (Feature Completion & User Interface / Integration Gate):` Remaining vertical slices, User Interface (`UI`) state handling, and `antislop` / integration verification.
     * `W3 (Adversarial Audit & Remediation Gate):` Mandatory for Tier 3 (`>8 files`) and `vibecoder` prototype-to-production promotions (`skills/harness/SKILL.md` §6); executes independent `audit` verification and remediates confirmed findings.
   * **Pattern B — Comprehensive Audit & Fix Campaign (2 Windows):**
     * `W1 (Deep Audit & Reproducible Defect Ledger):` Execute `audit` across the target scope, verify findings at `file:line`, and write the prioritized remediation plan into `tasks.md` and `HANDOFF.md`.
     * `W2 (Surgical Remediation & Regression Gate):` Fix confirmed findings under `GEMINI.md` Rule 13 blast caps and prove green across all gates.
   * **Pattern C — Observable Milestone Rule for In-Window `W1` Execution (`GEMINI.md` Rule 13):** Never guess subjective "context fullness". When Phase 1 clarification required `<= 3` `ask_question` turns and `W1` touches `<= 8` files, execute `W1`'s implementation slice in the **same** window immediately after user plan approval. Use a dedicated planning-and-specification `W1` exclusively on Tier 3 (`>8 files`) overhauls that require `> 3` `deep-grill` rounds and an Architecture Decision Record (`ADR` via `architecture-decision-records`) sign-off milestone before code edits begin.

---

## 3. Phase 3: Per-Window Model, Effort & Skill Routing

Different windows carry different cognitive loads. During initial planning (and when updating `HANDOFF.md` at the end of each window), assign an explicit **Model & Effort Tier** and **Required Skills** to every window `W1..Wn`:

| Window Archetype | Cognitive Profile | Recommended Host Model & Effort | Typical Required Skills |
| :--- | :--- | :--- | :--- |
| **Architecture, Deep-Grill, Complex Rework, or Security/Consistency Audit** | High ambiguity, multi-file invariant reasoning, adversarial falsification | **Top Reasoning Model (`Pro` / `Argon` / `Opus` tier) — High / Max Effort** | `marathon`, `deep-grill`, `harness`, `architecture-decision-records`, `audit`, `mistake-proofing` |
| **Standard Vertical-Slice Implementation, Refactoring, or Optimization** | Locked contract and clear `AC-1..N`; requires disciplined code generation and seam testing | **Balanced / Coding Model (`Pro` / `Sonnet` / `Flash` tier) — Medium / High Effort** | `marathon`, `harness`, `test-design`, `refactoring`, `sweetspot`, `game-engineering`, `antislop` |
| **Mechanical Polish, Doc/Changelog Sync, or Scoped Lint/Comment Cleanup** | Deterministic transformations with existing test coverage | **Fast Model (`Flash` / `Haiku` tier) — Low / Medium Effort** | `marathon`, `harness`, `antislop-code`, `technical-writing` |

* **Adaptive Re-Calibration:** If a window discovers unexpected structural complexity (or finishes simpler pieces early), the agent may adjust the recommended Model & Effort tier for the *upcoming* window `Wk+1` when writing `HANDOFF.md`, stating the one-line technical reason.

---

## 4. Phase 4: Disk Ledger Persistence (`tasks.md` & `HANDOFF.md`) & Cold-Start Handoff

All marathon state lives on disk in the target project root (`tasks.md` and `HANDOFF.md`), never in transient chat memory:

### A. `tasks.md` Window Table & Status States
At the top of `tasks.md`, maintain the window roadmap alongside the detailed `[ ]` / `[x]` task items using four deterministic status tokens (`[x] DONE`, `[ ] NEXT`, `[~] IN-PROGRESS (PARTIAL)` when a `GEMINI.md` Rule 13 handoff trigger fires mid-window, and `[!] BLOCKED` when a Phase 5 safety/correctness blocker awaits user decision):

```markdown
## Marathon Window Plan (`W1..Wn`)
| Window | Scope & Deliverable | Exit Gate | Recommended Model & Effort | Required Skills | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `W1` | Schema + Core Auth Slice | `AC-1`, `AC-2` | Top Reasoning — High Effort | `marathon`, `harness`, `mistake-proofing` | `[x] DONE` |
| `W2` | Interface Flows + Integration & Audit | `AC-3`, `AC-4` | Balanced — High Effort | `marathon`, `harness`, `antislop`, `audit` | `[ ] NEXT` |
```

### B. End-of-Window `HANDOFF.md` Update & Ready-to-Use Prompt
When window `Wk` ends (either by completing its scoped tasks and passing `skills/harness/SKILL.md` §3.B, or by hitting a `GEMINI.md` Rule 13 mid-window trigger):

1. **Intermediate Window (`k < N`) or Mid-Window Rule 13 Interruption (`[~] IN-PROGRESS (PARTIAL)` / `[!] BLOCKED`):**
   * Update `tasks.md` checkboxes and window status (`[x] DONE` if `Wk` passed all gates, else `[~] IN-PROGRESS (PARTIAL)` or `[!] BLOCKED`).
   * Write or update `HANDOFF.md` at the project root using `templates/HANDOFF.template.md` with `Status: [IN-PROGRESS]` and populate `## 4. Cold-Start Directive for the Incoming Agent`:
     * **Where:** `new window with this HANDOFF.md`
     * **Window Index:** `Window <k+1>/<N> — <Window Title>` (or `Window <k>/<N> (Resumed) — <Window Title>` on a mid-window Rule 13 handoff)
     * **Recommended Model & Effort:** `<Model Tier> (<Effort Level>) — <1-line reason>`
     * **Required Skills to Load:** `<comma-separated skill names and skills/<name>/SKILL.md paths>`
     * **Immediate Next Action:** Exact file, symbol, or command to run on Turn 1.
     * **Ready-to-Use Prompt:** A self-contained, copy-ready prompt in the user's language that instructs the next window to read `HANDOFF.md` and `tasks.md`, load the required skills, and execute the window under `marathon` scope lock.
   * In the user-facing response's **Delivery Block** (`GEMINI.md` Rule 5), output: what was verified and any verification gaps (`GEMINI.md` Rule 8), progress as criteria met (`e.g. 2/5 acceptance criteria met; Window 1/3 complete`), the **Recommended Model & Effort**, and the fenced **Ready-to-Use Prompt**.
2. **Terminal Window (`k == N` and all `AC-1..N` verified):**
   * Mark `Wn` as `[x] DONE` in `tasks.md`.
   * Update `HANDOFF.md` with `Status: [COMPLETE]` and `Progress: N/N exit criteria met`. Per `templates/HANDOFF.template.md` (`"When all are met the status is [COMPLETE] and no further handoff is issued"`), omit the next-window `Ready-to-Use Prompt` and deliver the final `GEMINI.md` Rule 5/8 completion block.

---

## 5. Phase 5: Strict Mid-Marathon Scope Lock (Anti-Drift Silence Rule)

While a marathon is in progress (`W1..Wn` prior to `[COMPLETE]`):

1. **Zero Unsolicited Feature or Plan-Change Proposals:** Unless the user explicitly asks for new ideas, scope expansion, or plan revisions, the agent **must not** propose out-of-plan features, bonus improvements (`VALUABLE`), architectural detours, or roadmap alterations in its chat responses or handoff prompts.
2. **Park Silently in `tasks.md` Only When Relevant:** If a useful non-essential observation arises, either omit it completely or—only if the user asked to track future ideas—park a single line under `## Parked (Out of Active Marathon Scope)` in `tasks.md` without discussing it in chat.
3. **Mandatory Safety & Blocker Carve-Out (`GEMINI.md` Rule 8):** Suppressing scope creep never means hiding defects. If the agent discovers a **`NECESSARY FOR SAFETY/CORRECTNESS`** issue (a breaking bug, security boundary violation, data-loss hazard, or a technical constraint that renders an `AC-1..N` criterion unsatisfiable per `skills/harness/SKILL.md` §4.E), mark the window `[!] BLOCKED` in `tasks.md` and surface the exact evidence and required adjustment immediately.

---

## 6. Triggers and Invocations

* **Slash Command:** `/marathon`.
* **Natural Language Triggers:** *"maraton başlat"*, *"bunu maraton ile pencerelere böl"*, *"start a marathon plan"*, *"plan this across windows"*.
