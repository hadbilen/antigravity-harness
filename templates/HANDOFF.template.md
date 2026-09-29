# Session Handoff Document

**Status:** {{[COMPLETE] | [IN-PROGRESS]}}
**Handoff Trigger:** {{milestone completed | circuit breaker | trace > 500 lines | repeated user correction}}
**Date & Time:** {{ISO_TIMESTAMP}}
**Previous Conversation / Session ID:** {{CONVERSATION_ID_OR_LABEL}}
**Git Branch / Commit:** {{BRANCH}} @ {{COMMIT_HASH}}

---

## 0. Authoritative Goal & Exit Criteria
- **Goal:** The user's objective for this line of work, in one or two sentences (inherited unchanged from the originating task).
- **Exit Criteria:** Verifiable conditions that end the work. If the user never stated them, write `[TBD: ask the user]`; do not invent them.
  - [ ] Criterion 1 (e.g. `pytest tests/test_x.py` passes)
  - [ ] Criterion 2
- **Progress:** {{N}}/{{M}} exit criteria met. When all are met the status is `[COMPLETE]` and no further handoff is issued.

## 1. Executive Summary & Active Constraints
- **Completed Milestone:** What the preceding session delivered.
- **Active Constraints:** Invariants, decisions (ADR references) and user instructions that still apply.

## 2. Completed Changes & Evidence
- **Modified / Created Files:** Key files, public types and production entry points touched.
- **Verified (with proof):** Commands, test suites and checks that passed.
- **Assumed / Not Verified:** Edge cases or boundaries that were not verified, and assumptions still unproven.

## 3. Active System State
- **Current Workspace State:** Working tree status (clean / dirty / untracked files).
- **Active Plan (`tasks.md`):** Remaining checkboxes, in order.
- **Known Blockers / Warnings:** Pending user reviews or external prerequisites.

## 4. Cold-Start Directive for the Incoming Agent
- **Where:** {{continue in this window | new window with this HANDOFF.md}}
- **Immediate Next Action:** The single next justified step: exact file, symbol or command to run on turn 1, and the skill to load if any.
- **Ready-to-Use Prompt:** A short task prompt that carries only the coordinates above (goal, exit criteria, next action). Task prompts never include harness maintenance commands.
