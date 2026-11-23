# Session Handoff Document

**Campaign ID:** {{YYYY-MM-DD-<topic-slug>}}
**Status:** {{[COMPLETE] | [IN-PROGRESS]}}
**Handoff Trigger:** {{milestone completed | marathon window boundary | predictive context headroom (user-accepted) | circuit breaker | trace > 500 lines | repeated user correction}}
**Date & Time:** {{ISO_TIMESTAMP}}
**Previous Conversation / Session ID:** {{CONVERSATION_ID_OR_LABEL}}
**Git Branch / Commit:** {{BRANCH}} @ {{COMMIT_HASH}}

> **Operator Summary (3 lines):**
> - **What changes:** {{1 concise sentence describing what changed or is pending in this campaign (<= 160 chars).}}
> - **If approved / resumed:** {{1 concise sentence stating what the next window delivers and whether it is safe to proceed (<= 160 chars).}}
> - **If denied / paused:** {{1 concise sentence stating current workspace safety and what stays unapplied if stopped now (<= 160 chars).}}

---

## 0. Authoritative Goal & Exit Criteria
- **Goal:** User objective in 1-2 sentences (inherited unchanged from the originating task).
- **Exit Criteria:** Verifiable conditions that end the work (write `[TBD: ask the user]` if unstated).
  - [ ] Criterion 1 (e.g. `pytest tests/test_x.py` passes)
  - [ ] Criterion 2
- **Progress:** {{N}}/{{M}} exit criteria met.
- **Closure Rule:** Mark `[COMPLETE]` only when all exit criteria pass (circuit-breaker or mid-window handoffs keep `Status: [IN-PROGRESS]`); start any later unrelated task with a fresh `Campaign ID` at `W1` (`AC-1`).

## Completed Windows Log
<!-- Multi-window marathon campaigns (`~/.gemini/config/skills/harness/references/marathon.md`); omit on single-handoff tasks. -->
| Window | Date | Status | Delivered Artifacts & Verified Gates | Exit Criteria Progress |
| :--- | :--- | :--- | :--- | :--- |
| `W1` | `{{YYYY-MM-DD}}` | `[x] DONE` | {{Key deliverables and verified exit-0 gates}} | `{{N}}/{{M}}` (`AC-1`) |

## 1. Executive Summary & Active Constraints
- **Completed Milestone:** What the preceding session delivered.
- **Active Constraints:** Invariants, ADR references, and user instructions that still apply.

## 2. Completed Changes & Evidence
- **Modified / Created Files:** Key files, public types, and production entry points touched.
- **Verified (with proof):** Commands, test suites, and deterministic checks that passed.
- **Assumed / Not Verified:** Unverified boundaries and unproven assumptions (`GEMINI.md` Rule 8).

## 3. Active System State
- **Current Workspace State:** Working tree status (clean / dirty / untracked files).
- **Active Plan (`tasks.md`):** Remaining checkboxes, in order.
- **Known Blockers / Warnings:** Pending user reviews or external prerequisites.

## 4. Cold-Start Directive for the Incoming Agent
- **Where:** {{continue in this window | new window with this HANDOFF.md}}
- **Window Index:** {{Single-Handoff | Window k/N: <Window Title> (Campaign: <YYYY-MM-DD-topic-slug>)}}
- **Recommended Model & Effort:** {{Top Reasoning / Balanced / Fast Model Tier (<Effort Level>): <1-line rationale>}}
- **Required Skills to Load:** {{e.g. `harness` (`~/.gemini/config/skills/harness/SKILL.md`, `~/.gemini/config/skills/harness/references/marathon.md`)}}
- **Immediate Next Action:** Exact file, symbol, or command to run on Turn 1, and required skill if any.
- **Ready-to-Use Prompt:** Start line 1 with `[Campaign: <YYYY-MM-DD-topic-slug> | Window <k>/<N>: <Window Title>]` and omit harness maintenance commands.
