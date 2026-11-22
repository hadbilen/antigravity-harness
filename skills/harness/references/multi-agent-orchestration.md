# Multi-Agent Orchestration, Pre-Flight Audits & Swarm Topology (`harness` §5 Reference)

Detailed contracts for Actor-Verifier dispatch, Zero-Reasoning Contract Injection, Mutual Falsification, and `native_swarm` coordination extracted from `skills/harness/SKILL.md`.

---

## 1. Trigger Timing & Pre-Code Plan Gate (`harness` §5.A)

1. **On-Demand Escalation:** Invoke `build-error-resolver` immediately when a compiler/type trace exceeds 500 lines, or if the primary agent fails to resolve a compiler/type error after two consecutive attempts.
2. **Pre-flight Gate:** Immediately following code completion and local test passes on Tier 3 tasks or `GEMINI.md` Critical Exceptions (and on Tier 2 when public contracts, observable caller behavior, or new abstractions / `> +150` net lines are introduced), run the relevant auditor subagents (`silent-failure-hunter`, `security-boundary-verifier`, `consistency-auditor`, `specification-gap-auditor`, `test-adequacy-auditor`, `contract-change-auditor`, `simplicity-auditor`, plus `meta-auditor` on harness governance changes) in parallel before final user delivery. Wait for every dispatched subagent report before delivering.
3. **Pre-Code Plan Gate (Tier 3 Fresh-Context Red-Teaming):** On Tier 3 tasks, prior to presenting `implementation_plan.md` for user sign-off or writing production code, dispatch `specification-gap-auditor` (and `consistency-auditor` when multiple documents or contracts interact) in a fresh context over the draft plan and target file coordinates. Apply an explicit **You Aren't Gonna Need It (`YAGNI`) Brake** in the audit focus: separate concrete architectural, concurrency, security, and data-integrity failure modes from low-probability hypothetical edge cases, and reject speculative abstractions that inflate scope. Require `0` unresolved confirmed `CRITICAL` or `HIGH` findings within at most `3` plan passes (`GEMINI.md` Rule 13) before proceeding.

---

## 2. Zero-Reasoning Contract Injection & Anonymized Evaluation (`harness` §5.B)

Never dump the full conversation transcript to subagents, and **never pass your own reasoning, root-cause narrative, or claims that "the tests already pass"**. A reviewer handed the author's conclusion suffers confirmation bias and rubber-stamps the diff. Pass only:

* **Task Objective:** Single-sentence summary of the modification.
* **Unified Diff, Untracked Files & Modified Coordinates:** The exact `git diff HEAD` (or `git diff <base_head>` when `HEAD` advanced during the session; `git diff --cached` plus `git diff` on an unborn `HEAD`), bounded plain-text non-secret untracked file slices (`<= 50 KB`, `<= 250` lines per slice; path and byte count only with zero content bytes for binary, oversized, vendor/build, or `.env*`/`*.pem`/`*.key` files) from `git ls-files --others --exclude-standard` (because `git diff` omits untracked files and read-only auditors cannot run `git` commands), and `file:line` slices to review, plus pre-computed `agy-guard code-map callers <symbol>` / `git grep -n` candidate caller and test file coordinates when dispatching `contract-change-auditor`, `test-adequacy-auditor`, or `simplicity-auditor`.
* **Audit Focus:** The specific invariant or boundary to evaluate.
* **Claims to Falsify (`consistency-auditor` only, explicitly labeled as a claim to disprove):** The commit message or change summary, passed strictly as a hypothesis to attempt to falsify, never as trusted context.
* **Zero-Prose Subagent Return Contract:** Instruct every subagent to return findings strictly as compact tables or `file:line | severity | proof | remediation` entries with zero conversational preamble, filler, or closing summary.
* **Model Policy & Cross-Model-Family Verification:**
  * In `native_swarm` (`swarm` tool), leave `model` unset by default for all workers (authors, verifiers, and auxiliary workers) so every member runs on the coordinator's chosen model; do not select a different model on your own initiative unless the user explicitly asks for another model or the current model is out of quota/capacity (`GEMINI.md` Rule 15f).
  * For multi-window `marathon` campaigns (`skills/harness/references/marathon.md`) or when the user explicitly requests cross-model-family verification on critical security, financial, or governance cores, pairing an approved flagship author (`Gemini 4 Neon (XHigh)` / `Gemini 4 Carbon (High)`) with a read-only verifier from a distinct flagship family (such as `Claude Opus 5.5 (High)`) reduces correlated same-family blind spots.
  * Customization and governance writes follow the `A1` Rule 17 policy enforced by `guard/agy_hooks.py`: `approved_customization_models` (`Gemini 4 Neon (XHigh)` and `Gemini 4 Carbon (High)`) receive `allow`, Pro-class Orchestrators (`gemini-pro-orchestrator-neon`) prompt `force_ask`, and Flash workers (`gemini-flash-worker-agy`, `*-flash-*`) receive `deny`. Single-session `invoke_subagent` calls continue to use `Model: "inherit"` per `GEMINI.md` Rule 17.
* **Anonymized Multi-Auditor Synthesis:** When multiple auditors return findings on the same change, evaluate and deduplicate their findings by the concrete `file:line` evidence and reproduction proof rather than the persona label.

---

## 3. Subagent Roles & Staged Artifact Passing (`harness` §5.C & §5.D)

### Subagent Roles (`harness` §5.C)
1. **Actor (Primary Developer Agent):** Designs architecture, writes production code, and builds primary test suites.
2. **Build Error Specialist (`build-error-resolver`):** Resolves compiler/type errors with minimal diffs without modifying core architecture.
3. **Silent Failure Hunter (`silent-failure-hunter`):** Flags swallowed exceptions (`catch {}`), missing logs, and dangerous fallback returns.
4. **Security Boundary Verifier (`security-boundary-verifier`):** Audits authorization boundaries, injection risks, and race conditions (Time-of-Check to Time-of-Use, TOCTOU) using negative test cases.
5. **Specification Gap & Consistency Auditors (`specification-gap-auditor`, `consistency-auditor`):** Evaluates specifications, architectures, and rules for omissions, axiomatic contradictions, and logical cycles.
6. **Test Adequacy Auditor (`test-adequacy-auditor`):** Verifies whether tests at the real seam would fail if the changed behavior broke, checks for stale negative assertions on renamed/removed strings, and maps untested code branches.
7. **Contract Change Auditor (`contract-change-auditor`):** Traces every consumer, serialized payload, and migration rollback path when a public interface, schema, or protocol changes.
8. **Meta-Consistency Auditor (`meta-auditor`):** Inspects the pre-computed 7-pass harness self-audit (`agy-guard self-audit --strict --json`, including Pass 7 trigger specificity checks) supplied by the parent session and audits governance files via bounded host file-read slices when the harness itself is modified (`GEMINI.md` Rule 17; `PreToolUse` in `guard/agy_hooks.py` enforces `A1` model/effort approval against `skills/upstream-auditor/upstream_state.seed.json`).
9. **Research & Heavy Ingestion Specialist (`research`):** Ingests large external documentation (>50 KB), verifies pinned third-party library interfaces, and explores broad codebases in an isolated sandbox, returning distilled contracts to the primary session.
10. **Simplicity & YAGNI Auditor (`simplicity-auditor`):** Audits Tier 2/3 diffs against `GEMINI.md` Rule 4 (`YAGNI`), Rule 18 (`Surgical Changes & Reuse`), and the 7-Rung Efficiency Ladder while honoring game-seam and soundness-wrapper carve-outs.

### Staged Artifact Passing & Partial Stage Re-Execution (`harness` §5.D)
For sequential multi-subagent pipelines (`Agent 1 -> Agent 2 -> Agent 3`):
1. **Numbered stage contracts:** Persist each stage's output as a file (`<appDataDir>/brain/<conversation-id>/scratch/stage_01_<role>.md`, `stage_02_<role>.md`, ...) instead of relaying large prose through the parent conversation.
2. **Partial re-execution:** When a follow-up or a failed verification requires revising stage *k*, keep the validated outputs of stages 1..k-1 and re-run only from stage *k*, passing the upstream artifact paths in the subagent invocation contract.

---

## 4. Verification of Findings: Mutual Falsification (`harness` §5.E)

Every finding returned by a subagent, linter, or external review is a **hypothesis until verified** in the primary session:
* **Verify at the cited `file:line` coordinate** before editing code: read the surrounding callers (`agy-guard code-map callers <symbol>` / `flow <symbol>`) and upstream guards to confirm whether the bad outcome can actually occur. Fixing a non-existent defect introduces real regressions.
* **Mutual Falsification (Static Theory vs. Dynamic Runtime Reproduction):** Read-only auditor subagents reason statically and can produce theoretical false positives. For every `CRITICAL` or `HIGH` code finding returned by a static auditor, the primary session (or an isolated `self` worker) attempts empirical falsification by executing a targeted reproduction command or tracing runtime values (`agy-guard code-map trace <repro.py>`) against the claim.
* **Assign an explicit verdict to every finding:**
  * `CONFIRMED` (real defect, with severity determined by actual impact and a reproduction test/command where applicable),
  * `REFUTED` (disproved, citing the exact `file:line` guard, invariant, or negative runtime trace that prevents it), or
  * `OPEN` (requires user clarification on business intent).
* **No silent drops:** Report the verdict for every auditor finding in the delivery summary. If a required fix would mutate an existing test assertion or governance file, stop and request explicit user authorization (`GEMINI.md` Rules 9 and 12).

---

## 5. Swarm Execution Topology & Role Alignment (`harness` §5.F)

When a task splits across `>= 2` genuinely independent writable workstreams within a single window, pair `native_swarm` (`swarm` tool, `~/.gemini/antigravity/builtin/skills/native_swarm/SKILL.md`) and `swarm_pane` (`~/.gemini/antigravity/builtin/skills/swarm_pane/SKILL.md`) with the harness verification gates (`GEMINI.md` Rule 15f & Rule 17) across four runtime roles:

1. **Coordinator / Orchestrator (`coordinator`):** Non-coding scope, message-board, Overview, and merge arbiter.
   * Splits work into disjoint `OWNS:` file slices, sets `swarm{action:"title"}`, loads `swarm_pane` before briefing and adding the first workers, and writes `<appDataDir>/brain/<conversation-id>/.system_generated/swarm/plan.json` (`goal`, `tasks`, `threads`) so the Swarm UI builds its live Overview directly (for visible UI/layout work, instruct workers to save screenshots in their own `<appDataDir>/brain/<conversation-id>/` and post `Screenshot: <absolute path> | <summary>`).
   * Briefs each cold-start worker completely inside `add` (or passes `fork:"<member>"` / `"coordinator"` only when warm context is needed), tracks board progress via `#seq` references without re-summarizing reports (`skills/harness/SKILL.md` §5.B), uses channels (`action:"channel"`, `@#channel`) for large swarms, integrates validated commits into the coordinator workspace, and runs final `skills/harness/SKILL.md` §3.B gates.
2. **Author Workers (`workspace:"share"` or `"branch"`):** Spawn parallel code or test writers with `workspace:"share"` (shared `.git`, separate working tree) or `"branch"` (isolated clone) and non-overlapping `OWNS:` boundaries (`GEMINI.md` Rule 15f). Authors commit inside their own workspace and post `#seq` diff summaries and test outputs. Leave `model` unset so every author runs on the coordinator's model unless user-requested or quota-exhausted; never downgrade `model` when editing customization or governance paths (`GEMINI.md` Rule 17).
3. **Verifier Workers (`workspace:"inherit"`) & Read-Only Pre-flight Auditors (`agents/*.md`):** Assign roughly one verifier worker per 2-4 authors on `workspace:"inherit"` to review `#seq` diffs and execute seam tests without editing author files (reporting failures directly to `@<author>`). Leave `model` unset by default for `native_swarm` verifiers unless the user explicitly asks for another model or the current model is out of quota. On Tier 3 (`>8 files`) tasks or `GEMINI.md` Critical Exceptions, the coordinator still executes the independent `read-only` `agents/*.md` Pre-flight Gate (`skills/harness/SKILL.md` §5.A & §5.C) with exact unified diffs and `skills/harness/SKILL.md` §5.E Mutual Falsification before delivery.
4. **Auxiliary Workers (`monitor`, opt-in `narrator`, `browser`):**
   * **Overview (`swarm_pane`, default):** Do not add a `narrator` by default because the `swarm_pane` Overview (`.system_generated/swarm/plan.json`) replaces it; add `narrator` (`swarm_narrator`) only when the user explicitly requests it by name.
   * **Stall Monitor (`monitor`):** When `swarm_monitor` is in the active skill list, add `monitor` during swarm initialization with `model` left unset (unless user-requested or quota-exhausted). The monitor schedules a daemon cron via `schedule{CronExpression: "*/3 * * * *", IsDaemon: true, Prompt: "[monitor] tick: check the swarm for a stall"}` (`IsDaemon: true` is required so the timer does not prevent the user's conversation from looking idle), posts at most one `@member [stall]` nudge per tick (stopping after 3 unacknowledged alerts per stall), and kills its cron via `manage_task{Action: "kill", TaskId: <cron>}` to go dormant once the coordinator posts `[done] <summary>` (without `@`) or the board stays idle for 5 ticks.
   * **Browser (`browser`):** Route live webview UI interactions exclusively to built-in `browser` (`Model: "flash"` unless overridden).

### Worktree Integration, `flight_recorder` & `Stop` Gate Interplay
* `swarm{action:"kill"}` permanently deletes `workspace:"share"` and `"branch"` directories; always verify a clean `0`-conflict `git merge` (or `git cherry-pick`) of validated author commits into the coordinator workspace *before* calling `kill` (push to a remote only when explicitly requested).
* Because `flight_recorder` (`skills/harness/SKILL.md` §4.B) keys pre-edit snapshots (`refs/harness/pre-edit` in the main checkout and `refs/harness/pre-edit-wt-<hash>` in linked worktrees) and per-conversation `touched_files` by resolved workspace root (`ws_resolved`) and `conversationId`, parallel writes inside `workspace:"share"` stay isolated from sibling conversations; after integrating share branches into the coordinator tree, run `TestBoundaryGuard` (`agy-guard verify-invariants --test-boundary` or `agy-guard test-boundary verify`) and inspect `git diff HEAD` (`skills/harness/SKILL.md` §3.B Step 4a) on the main workspace before finishing the turn so `handle_stop` evaluates a consistent, non-weakened baseline.
* `PreToolUse` (`guard/agy_hooks.py`) inspects orchestration tool calls (`swarm`, `invoke_subagent`, `run_workflow`, and board/subagent/schedule messages) to enforce `A1` customization delegation (`Rule 17`) and human-only Guard commands (`Rule 12`), tracking customization workers and channels across the workspace scope in `swarm_workers.json`.
