# Context Hygiene, Artifacts & Multi-Skill Recipes (`harness` §1, §4 Reference)

Detailed operational mechanics extracted from `~/.gemini/config/skills/harness/SKILL.md` via progressive disclosure so core workflow rules stay within a single bounded read while full procedures remain available on demand.

---

## 1. Multi-Skill Orchestration Recipes (`harness` §1)

Complex requests compose domain skills strictly in sequential phases; never mix incompatible gates inside a single unverified pass:

* **Compiled / Legacy Program -> Modern Port -> Optimization Pipeline:**
  1. *Artifact Recovery (`reverse-engineer-anything` / `rea_rea` MCP):* Decompile binaries, extract assets, and freeze a clean-room reconstruction obligation ledger before editing.
  2. *Deterministic Port (`renew` + domain adapter):* Capture offline oracle / `[HARDWARE/ENV SHIM]` replay fixtures first, then pair with `game-engineering` (classic games), `rustify` (C/C++/PyO3 native kernels), `database-migrations` (legacy schemas), and `media-studio` (corrupt audio/video/spritesheet assets) through the Stage 5 `100%` Parity Gate.
  3. *Post-Parity Tuning (`sweetspot` or `diagnosing-bugs`):* Hand off ONLY after parity is green: optimize hot paths/bundles via `sweetspot` or isolate newly surfaced runtime bugs via `diagnosing-bugs`.
* **New Game / Interactive Simulation Composition:**
  1. *Spec & Simulation Core (`deep-grill` -> `game-engineering`):* Lock core mechanics, fixed-timestep loop (`FIXED_DT`), zero per-frame allocations, and headless tick verification first.
  2. *Assets & HUD Polish (`media-studio` + `ui-refinery`):* Generate/normalize audio & sprite sheets via `media-studio` and enforce `DESIGN.md` (`MODE: GAME & INTERACTIVE`) + `ui-refinery-contrast` (`check_contrast`) on HUD overlays.
  3. *Frame-Pacing & Bundle Pass (`sweetspot`):* Profile and trim frame spikes or delivery size after gameplay behavior is verified.
* **Anti-Mixing Sequencing Rule:** Never apply `refactoring` or `sweetspot` micro-optimizations while a legacy parity port (`renew` / `rustify`) or active fault diagnosis (`diagnosing-bugs`) is still failing; restore a green oracle or bug-free baseline before crossing phases.

---

## 2. Standard Artifact Hierarchy (`harness` §4.A)

For medium and large tasks, maintain aligned platform artifacts and disk tracking:

1. **`implementation_plan.md` (Design Document & Review Gate):** Created in the Antigravity artifact directory (`<appDataDir>/brain/<conversation-id>/implementation_plan.md`) with `ArtifactMetadata` (`RequestFeedback: true`, `UserFacing: true`) for Tier 3 plans, ambiguous scopes, or Hard Ask classes 1 to 3, and `RequestFeedback: false` for clear Tier 2 plans with zero Hard Ask triggers (or persisted to `docs/plans/YYYY-MM-DD-<topic>.md` when the project tracks plans in version control).
   * Before writing the plan, check `MISTAKES.md`, `docs/adr/`, and any existing `REPOSTATE.md` (`~/.gemini/config/templates/REPOSTATE.template.md`), `DECISIONS.md` (`~/.gemini/config/templates/DECISIONS.template.md`), `ARCHITECTURE.md` (`~/.gemini/config/templates/ARCHITECTURE.template.md`), or `SECURITY_POSTURE.md` (`~/.gemini/config/templates/SECURITY_POSTURE.template.md`) for current milestone state, prior Tier-2 decision provenance (`User Constraint` vs. `Model Recommendation`), historical incidents, module dependency boundaries, and active security controls touching the same modules.
   * Create `REPOSTATE.md`, `DECISIONS.md`, `ARCHITECTURE.md`, or `SECURITY_POSTURE.md` in user repositories only when explicitly requested by the user (`GEMINI.md` Rule 4). Update `REPOSTATE.md` only at completed Tier 2/3 milestones or campaign `[COMPLETE]` when already present; update an existing `DECISIONS.md` only when a Tier-2 design choice is confirmed or a Tier-3 `docs/adr/NNNN-*.md` is accepted (appending a single-line pointer row without duplicating ADR prose, marking replaced choices `[SUPERSEDED]`/`[REVERTED]`, and keeping `wc -l DECISIONS.md <= 150`).
   * For specialized domain repositories such as Vulkan graphics/compute projects or `.procoder/`-governed repositories, opt-in portable templates (`~/.gemini/config/templates/vulkan.SKILL.template.md` -> `.agents/skills/vulkan/SKILL.md`, `~/.gemini/config/templates/procoder.SKILL.template.md` -> `.agents/skills/procoder/SKILL.md`) may be copied into project-local `.agents/skills/` so unrelated repositories incur zero global prompt overhead.
   * On Tier 3 tasks, challenge the draft plan via the fresh-context Pre-Code Plan Gate (`~/.gemini/config/skills/harness/SKILL.md` §5.A) prior to user sign-off or writing production code.
2. **`tasks.md` (Execution Checklist):** Checkable milestones (`[ ]` / `[x]`) maintained at the workspace root as a persistent ledger.
3. **`walkthrough.md` & Plan Outcome (Delivery Record):** Summary of verified changes, automated gate outputs, verification gap declarations, and four fixed outcome labels (`Deviations`, `Not verified`, `Surprises`, `Follow-ups`; used by `retro`).
4. **`HANDOFF.md` (Session Handoff):** The single handoff mechanism for multi-session work, written from `~/.gemini/config/templates/HANDOFF.template.md` when a Rule 13 handoff trigger fires, at a planned `marathon` window boundary (`~/.gemini/config/skills/harness/references/marathon.md`), or when the operator accepts a Tier-2 predictive context-headroom handoff choice (`Handoff Trigger: predictive context headroom (user-accepted)`). It carries the authoritative goal, exit criteria (`AC-1..N`), and per-window model/effort/skill directives; `tasks.md` stays the execution checklist and is not a second handoff ledger.

---

## 3. Context Preservation & Flight Recorder Mechanics (`harness` §4.B)

* Update `tasks.md` on disk immediately upon completing each sub-step.
* Even if conversation history undergoes compaction, read `tasks.md` from disk to resume execution deterministically.
* **In-Window Pre-Compaction Checkpoint (No Competing Ledger):** The agent cannot execute the host UI context-compaction command itself; only recommend it on observable volume triggers (`>= 30` tool calls in the active window or an explicit user request) when no `GEMINI.md` Rule 13 new-window `HANDOFF.md` trigger has fired. Before recommending context compaction (or when the user asks to prepare for compaction), flush verified `file:line` coordinates, ruled-out hypotheses, and immediate next actions into `tasks.md` on active Tier 2/3 tasks (or into `<appDataDir>/brain/<conversation-id>/scratch/compact_checkpoint.md` during read-only investigations), and never create a competing project-root state file alongside `tasks.md` and `HANDOFF.md`.
* **Automated Flight Recorder & Pre-Edit Git Checkpoint (`~/.local/share/plumbwork/runtime/guard/agy_hooks.py`):**
  * **Pre-Write Flight Record (`PreToolUse`):** Before any workspace file-mutating tool executes, `~/.local/share/plumbwork/runtime/guard/agy_hooks.py` atomically records the active `conversation_id`, `status: "in_flight"`, `last_tool`, `last_target`, bounded `touched_files`, `base_head` (`git rev-parse HEAD`), and (when pre-existing uncommitted tracked changes exist before the session's first write) a non-destructive git snapshot OID (`git stash create` pinned at `refs/harness/pre-edit` or `refs/harness/pre-edit-wt-<hash>` in linked worktrees) in `~/.local/state/plumbwork/flight_recorder.json`.
  * **Turn Reconciliation (`Stop`):** When a turn finishes normally, `handle_stop` transitions the conversation's flight record from `"in_flight"` to `"turn_complete"` (`0` findings) or `"in_progress_blocked"` (`>0` findings).
  * **Interrupted-Session & Pending-Handoff Gate (`PreInvocation`):** If a turn is cut off mid-flight by quota exhaustion, network disconnect, or power loss (leaving `status: "in_flight"` for the same conversation or past the `1800s` (`30 min`) stale-age threshold), or if a new conversation opens on a workspace with `HANDOFF.md` (`Status: [IN-PROGRESS]`) or unfinished `tasks.md` items (`[ ]`, `[~]`, `[!]`), `handle_pre_invocation` injects a `[Harness Recovery & Continuity Gate]` directive (silenced for read-only/auxiliary roles such as `monitor`, `narrator`, and `verifier`). Upon receiving this directive, inspect `git status`, `git diff`, `tasks.md`, and `HANDOFF.md` to reconcile half-finished modifications before writing new code.
  * **Predictive Context-Window Handoff Advisory (`PreInvocation`, No Fixed `%` Cutoff):** On fresh user turns (anchored via `transcript.jsonl` `USER_INPUT`, verified for both `invocationNum: 0` and `1`, silenced on mid-turn continuations and for auxiliary/read-only roles), `~/.local/share/plumbwork/runtime/guard/hooks/pre_invocation.py` tail-reads `transcript.jsonl` up to the newest `type: "CHECKPOINT"` compaction boundary, reads the latest post-checkpoint `PLANNER_RESPONSE` active total (`input_tokens + cache_read_tokens`, plus `cache_creation_input_tokens` when present), computes trailing per-step median `burn_rate`, and compares dynamic remaining headroom against estimated incoming job cost (derived from prompt weight, unchecked primary-workspace `tasks.md` items, and `burn_rate`) using model-specific empirical `model_compaction_ceilings` (recalibrated via `/audit-upstream --model` under `MC-01`). It suppresses trivial Tier-1 micro-edits and `1` small remaining `tasks.md` item whenever no heavy workflow signal is present, suppresses sessions with negligible reclaimable history, and never hard-denies:
    * *Tier 1 (Proactive / Yellow, `0` model tokens):* emits `systemMessage: ""` with a concise 1-line `[Context Advisory]` in `metadata.user_markdown` for the operator (throttled by `REHINT_TURN_GAP`) when projected job cost exceeds remaining headroom without crossing the critical squeeze floor.
    * *Tier 2 (Heavy-Job Critical / Red, one-time per-conversation latch):* injects a single terse `<= 60`-token `[Harness Context Handoff]` `systemMessage` (latched once per conversation in `hook_hints.json`, silencing further Tier-1 and Tier-2 advisories for the rest of that conversation) instructing the model to offer a 1-sentence continue-vs-clean-`HANDOFF.md` choice before heavy code edits.

### Parallel-Conversation & Worktree Ledger Hygiene (`tasks.md` & `HANDOFF.md`)

Because `tasks.md` and `HANDOFF.md` are workspace-root singletons carrying one active `Campaign ID` per checkout, running multiple writable conversations simultaneously against the same working tree creates ledger collisions and conflicting `## Authorized Test Modifications` entries. Follow four rules when operating parallel sessions on the same repository:

1. **Isolate Concurrent Writable Streams in Linked Worktrees:** Give each parallel writable task its own working directory via `git worktree add ../<branch-dir> -b <branch>` or `swarm` `workspace:"share"` / `"branch"`. `flight_recorder.json` keys state by resolved workspace root (`ws_resolved`) and pins linked worktree snapshots under `refs/harness/pre-edit-wt-<hash>` so sibling worktrees never clobber one another's baselines or ledgers. Keep `tasks.md` and `HANDOFF.md` uncommitted inside temporary linked worktrees (or reconcile any committed `## Authorized Test Modifications` entries explicitly during merge) so merging branches never overwrites the coordinator's active campaign ledger.
2. **Keep Read-Only Sibling Conversations Strictly Non-Mutating:** Parallel inspection, `/audit`, `research`, or Q&A sessions sharing an active checkout must never write or reset `tasks.md` or `HANDOFF.md`; persist temporary notes solely inside `<appDataDir>/brain/<conversation-id>/scratch/`.
3. **Never Overwrite Another Live Session's `[IN-PROGRESS]` Ledger:** If `HANDOFF.md` shows `Status: [IN-PROGRESS]` with a different `Campaign ID` or `flight_recorder.json` indicates another fresh active writer (`age < 1800s` / `30 min`), pause and confirm with the operator (or switch to a dedicated worktree) and leave `tasks.md` and `HANDOFF.md` untouched.
4. **Integrate Before Cleanup:** Record `<pre-merge-base-sha>` (`git rev-parse HEAD`) before merging validated commits from a linked worktree or `workspace:"share"` branch back into the main checkout, then run `plumb-guard verify-invariants --diff --base-ref <pre-merge-base-sha>` (covering multi-commit merges, not just `HEAD~1`) before removing the worktree or closing the campaign.

---

## 4. Think in Code, Arithmetic & Bulk Inspection (`harness` §4.C)

* Avoid using the model as a raw data processor; generate code to let the operating system compute.
* Run targeted shell one-liners (`grep`, `jq`, `awk`) or structural queries (`plumb-guard code-map callers <symbol>`) via `run_command` instead of dumping whole files into context with `read_file`.
* **Deterministic Arithmetic (Zero Mental Math):** Never compute financial amounts, taxes, currency conversions, fees, percentages, or statistical aggregates mentally in prose; execute deterministic code (using integer minor units or exact decimal types per `~/.gemini/config/skills/harness/references/mistake-proofing.md` and `~/.gemini/config/skills/harness/references/mistake-proofing-hazards.md`) and report verified outputs.
* **BM25 Passage Indexing for Large Logs & Docs (`fts-search`):** When searching across large log files, multi-volume specifications, or documentation directories locally, run `plumb-guard code-map fts-search "<query>" <paths...> --top 5` (which indexes chunks into an in-memory SQLite Full-Text Search 5 (`FTS5`) table and ranks slices with BM25) to pull only the top-scoring `file:line` passages into context. Bound in-memory `fts-search` indexing to plain-text files up to 50 megabytes (`<= 50 MB`), streaming larger logs with `grep` or `awk`.
* **Bulk Inspection Barrier (`5+` Files):** When scanning or analyzing 5+ files (`>= 5` files) or a dataset (`GEMINI.md` Rule 11), write a one-off script in `<appDataDir>/brain/<conversation-id>/scratch/` that prints only the aggregated result. Read-only auditor subagents without execution tools use bounded host file-read slices (`StartLine`/`EndLine`) and pre-computed `git grep -n` / CLI outputs passed by the parent session.
* **No raw stream dumps:** Pipe `curl`/`wget`/log output through filters or into `scratch/stream_<name>.tmp`, inspect the slice, then delete the temp file. Never silently truncate failing compiler/test traces.
* **Subagent sandbox for heavy ingestion:** Documentation over 50 KB goes to the `research` subagent; traces over 500 lines (or compiler/type errors persisting after 2 consecutive failed attempts) go to `build-error-resolver` or an isolated diagnostic subagent. For broad codebase exploration, dispatch the read-only `research` subagent.

---

## 5. Work Scope Quad-Classification & Structured Acceptance Criteria (`harness` §4.D & §4.E)

### Work Scope Quad-Classification (`harness` §4.D)
During decomposition and execution (`tasks.md`), every discovered item goes into exactly one class:
- **`REQUIRED`**: directly needed for the user's explicit objective.
- **`NECESSARY FOR SAFETY/CORRECTNESS`**: discovered during the work; needed to prevent a regression or boundary break.
- **`VALUABLE`**: an improvement not needed now: parked for later, never implemented in-band.
- **`OUT OF SCOPE`**: unrelated observations or speculative refactors: not included.

### Structured Acceptance Criteria (`AC-1..N`, `harness` §4.E)
For Tier 2 and Tier 3 tasks, the plan defines numbered acceptance criteria (`AC-1`, `AC-2`, ...; typically 3-7 criteria for a standard change). Progress is reported against them (`GEMINI.md` Rule 5) and they serve as the exit criteria in `HANDOFF.md` (`GEMINI.md` Rule 8). Each criterion states:
- **Scenario:** the starting state or precondition.
- **Action:** one concrete trigger or operation.
- **Expected:** the observable outcome.
- **Must not:** the prohibited side effect or regression boundary, where applicable.
- **Verification:** the exact command, test case, or inspection that proves it.

**Authoring & Anti-Gaming Rules for Acceptance Criteria:**
* Replace vague adjectives (`correctly`, `securely`, `fast`, `robust`) with measurable thresholds or concrete observable outputs.
* Describe observable behavior and public interfaces (avoid brittle volatile line numbers).
* Never infer business rules, pricing, compliance, or retention policies from existing code alone: mark uncertain product requirements as `[NEEDS CLARIFICATION: ...]` and ask the user only what is hard to undo, alters a public contract, or cannot be answered from the repository (`GEMINI.md`, `MISTAKES.md`, `docs/adr/`).
* **Lazy-Agent Reread Check:** Before starting implementation, reread `AC-1..N` from the perspective of an adversarial lazy agent looking for the cheapest shortcut to satisfy the letter of the criteria without doing the real work (e.g., stubbing, returning hardcoded test literals, passing on a subset, or claiming without running), and tighten the wording to close every shortcut.
* If a criterion proves unsatisfiable due to a discovered technical constraint, mark it `[revised]` with the proving evidence and surface it to the user; never drop or weaken an acceptance criterion silently.
