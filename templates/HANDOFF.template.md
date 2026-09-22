# Session Handoff Document

**Status:** {{[COMPLETE] | [IN-PROGRESS / SATURATION-HALT]}}
**Date & Time:** {{ISO_TIMESTAMP}}
**Previous Conversation / Session ID:** {{CONVERSATION_ID_OR_LABEL}}
**Git Branch / Commit:** {{BRANCH}} @ {{COMMIT_HASH}}

---

## 1. Executive Summary & Objective
- **Completed Milestone:** Brief summary of the deliverable or task completed in the preceding session.
- **Architectural Context:** Pertinent design patterns, ADR references, or constraints established.

## 2. Completed Changes & Verified Seams
- **Modified / Created Files:** Key files, public types, and production entry points touched.
- **Verification Proof:** Specific deterministic commands, test suites, typecheck results (`tsc`, `mypy`), and seam tests that passed.
- **Verification Gaps Declared:** Explicit list of edge cases or boundaries *not verified* due to environment constraints.

## 3. Active System State & Working Directory
- **Current Workspace State:** Working tree status (clean / dirty / untracked files).
- **Pending Tasks (`tasks.md`):** Concrete checkboxes ready for immediate execution in the new session.
- **Known Blockers / Warnings:** Critical edge cases, pending user reviews, or external environment prerequisites.

## 4. Cold-Start Directive for Incoming Agent
- **Immediate Next Action:** Exact file path, function symbol, or test command the incoming agent must execute on Turn 1.
- **Key Invariants to Maintain:** Core constitutional rules or domain constraints that must not be broken or softened.
