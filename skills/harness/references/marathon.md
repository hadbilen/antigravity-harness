# Marathon: Multi-Window Execution Planner & Handoff Orchestrator

Large architectural builds, deep reworks, and multi-round audit-and-remediation campaigns degrade when forced into a single exhausted context window, or when chopped into too many tiny, unverifiable fragments. `marathon` establishes a clear target upfront, packs the work into the **minimum viable number of self-contained context windows (`W1..Wn`)**, assigns the right **Model, Effort, and Skills** to each window, and drives execution through the repository's canonical `tasks.md` and `HANDOFF.md` files with zero unsolicited scope drift.

## Mutual Exclusion

- **Activation:** Triggered when the user invokes `/marathon` (or phrases such as `"maraton başlat"`, `"pencerelere böl"`), or when the user accepts the `/marathon` promotion offer at the end of a `vibecoder` prototype delivery.
- **Relationship with `harness`, `unlazy`, `vibecoder`, and opt-in `procoder`:** `marathon` is a multi-window session planner that operates directly on top of the `harness` verification pipeline (`~/.gemini/config/skills/harness/SKILL.md`) using `tasks.md` and `HANDOFF.md` (`~/.gemini/config/templates/HANDOFF.template.md`). It never creates a competing directory or ledger format:
  - When promoting a `vibecoder` prototype into a production system, `vibecoder` prototype mode ends and `marathon` + `harness` Tier 3 (`~/.gemini/config/skills/harness/SKILL.md` §6) take over.
  - Repositories governed by `.procoder/` may copy the opt-in `~/.gemini/config/templates/procoder.SKILL.template.md` template to `.agents/skills/procoder/SKILL.md` and use its sprint/backlog chain instead of `marathon`.
  - Single-window deep subagent fan-out uses `unlazy` (`.unlazy/`); `marathon` governs sequential human-in-the-loop context windows (`W1..Wn`).
- **Deactivation:** Ends when all Acceptance Criteria (`AC-1..N`) across `W1..Wn` are verified and `HANDOFF.md` is marked `[COMPLETE]`, or when the user says `"stop marathon"` (note: `"normal mode"` resets presentation styles like `chisle` first and only exits `marathon` when no presentation style is active or when the user explicitly says `"stop marathon"`), returning execution to standard single-window `harness` discipline. Once `HANDOFF.md` is `[COMPLETE]`, that campaign's `W1..Wn` and `AC-1..N` series is permanently closed: any later unrelated task starts a fresh `Campaign ID` at `W1` (`AC-1`) instead of appending `Wn+1` or `AC-(N+1)`.

---

## 1. Phase 1: Target & Scope Clarification (Before Planning Windows)

Never partition a vague goal into windows. Because `marathon` targets medium-to-large work (Tier 2 and Tier 3 `>8 files` architectural builds, reworks, revisions, and audit/remediation cycles), the agent must secure sufficient context before locking the window plan:

1. **Inspect Existing Artifacts & Enforce Campaign Isolation First:** Read the repository structure, `HANDOFF.md` and `tasks.md` (if present), `REPOSTATE.md` (if present), `PRODUCT.md` (if present, or the embedded `<script type="application/json" id="vibecoder-promotion-spec">` Section 1F metadata inside a `vibecoder` `.html` prototype), `MISTAKES.md`, and `docs/adr/` before asking the user anything the codebase already answers. **Hard Cross-Task Reset Rule:** If `HANDOFF.md` is `Status: [COMPLETE]` or its `Campaign ID` / goal belongs to a different completed or unrelated topic, **never** append `Wn+1` or `AC-(M+1)` onto the prior table; overwrite `tasks.md` from `W1` and `AC-1` (clearing the prior campaign's `## Completed Windows Log` rows in both `tasks.md` and `HANDOFF.md`) under a fresh `Campaign ID` (`YYYY-MM-DD-<topic-slug>`) **before** writing `Status: [IN-PROGRESS]` to the new `HANDOFF.md` when clearing all-clean prior `## Authorized Test Modifications`, and copy the **entire** `## Authorized Test Modifications` block verbatim whenever any listed test path still has uncommitted changes in `git status --porcelain` (partial pruning or resetting while `HANDOFF.md` is `[IN-PROGRESS]` triggers `force_ask` under `GEMINI.md` Rule 9).
2. **Clarify Missing Boundaries (`~/.gemini/config/skills/deep-grill/SKILL.md`):** If the target outcome, Version 1 (`V1`) scope boundary, technology constraint, or acceptance criteria remain ambiguous, batch all mutually independent unresolved frontier questions into a **single `ask_question` round** (`1–4` pointed questions per batch, each with `2–3` concrete options and one `(Recommended)` choice first) rather than serializing independent questions across multiple turns (in exported runtimes lacking `ask_question`, emit one numbered batch of at most `4` plain-text questions with `2–3` options and `1` `(Recommended)` default per question, then stop for user input). Reserve strict one-at-a-time questioning exclusively for explicit `/deep-grill` invocations.
3. **Lock Campaign ID, Authoritative Goal & Acceptance Criteria:** Assign an explicit `Campaign ID` (`YYYY-MM-DD-<topic-slug>`), define the authoritative goal in 1–2 sentences, and lock 3–7 measurable `AC-1..N` items (`Scenario`, `Action`, `Expected`, `Must not`, `Verification` per `~/.gemini/config/skills/harness/SKILL.md` §4.E). Both `Campaign ID` and `AC-1..N` remain invariant from `W1` to the final window.

---

## 2. Phase 2: Minimum-Window Packing Rule (Anti-Fragmentation Gate)

Context windows are expensive to switch; excessively long windows suffer context rot. Partition work using the **Minimum-Window Packing Rule** (`2 <= N <= 4` windows for standard campaigns; `1–3` `AC-1..N` criteria and `<= 8` touched files per implementation window):

1. **Single-Window Refusal & Post-Campaign Reset:** If the scoped work fits safely within a single context window (Tier 1 or a self-contained Tier 2 vertical slice of 3–5 files with straightforward verification), **do not split it across windows** and **never append it as `Wn+1` onto a prior `[COMPLETE]` marathon table**. State that 1 window is sufficient, reset any stale `[COMPLETE]` `tasks.md` under a fresh header if Tier 2 checklist tracking is needed (using `Window 1/1` with a standalone `Campaign ID` only when the user explicitly requests a cold-start `HANDOFF.md`), and execute the task directly in the current window under `harness` discipline.
2. **Fewest Self-Contained Windows (`W1..Wn`):** Pack related work into the smallest number of windows where each window delivers a **complete, deterministic, and testable vertical slice or cognitive phase**:
   * **Pattern A: Prototype-to-Production / Architectural Build (2–3 Windows):**
     * `W1 (Architecture & Foundation Slice):` Target clarification, schema/contract design, and the primary end-to-end vertical slice passing unit/type gates.
     * `W2 (Feature Completion & User Interface / Integration Gate):` Remaining vertical slices, User Interface (`UI`) state handling, and `ui-refinery` / integration verification.
     * `W3 (Adversarial Audit & Remediation Gate):` Mandatory for Tier 3 (`>8 files`) and `vibecoder` prototype-to-production promotions (`~/.gemini/config/skills/harness/SKILL.md` §6); executes independent `audit` verification and remediates confirmed findings.
   * **Pattern B: Comprehensive Audit & Fix Campaign (2 Windows):**
     * `W1 (Deep Audit & Reproducible Defect Ledger):` Execute `audit` across the target scope, verify findings at `file:line`, and write the prioritized remediation plan into `tasks.md` and `HANDOFF.md`.
     * `W2 (Surgical Remediation & Regression Gate):` Fix confirmed findings under `GEMINI.md` Rule 13 blast caps and prove green across all gates.
   * **Pattern C: Observable Milestone Rule for In-Window `W1` Execution (`GEMINI.md` Rule 13):** Never guess subjective "context fullness" or hardcode fixed `%` cutoffs. When Phase 1 clarification required `<= 3` `ask_question` turns and `W1` touches `<= 8` files, execute `W1`'s implementation slice in the **same** window immediately after user plan approval. Use a dedicated planning-and-specification `W1` exclusively on Tier 3 (`>8 files`) overhauls that require `> 3` `deep-grill` rounds and an Architecture Decision Record (`ADR` via `~/.gemini/config/skills/harness/references/adr.md`) sign-off milestone before code edits begin. During execution, `~/.local/share/antigravity-harness/runtime/guard/hooks/pre_invocation.py` monitors post-`CHECKPOINT` active tokens (`input_tokens + cache_read_tokens`) and trailing `burn_rate` against `model_compaction_ceilings` (`~/.gemini/config/skills/harness/references/context-and-artifacts.md` §3): Tier 1 notifies the operator via `0`-token `metadata.user_markdown`, and Tier 2 latches a single terse `systemMessage` offering a 1-sentence continue-vs-clean-`HANDOFF.md` choice before heavy edits when headroom is critically tight.

### Swarm (`native_swarm`) vs. Single-Window (`unlazy`) vs. Multi-Window (`marathon`) Decision Matrix

| Mode | Trigger Condition | Parallelism & Isolation | Ledger & Exit Governance |
| :--- | :--- | :--- | :--- |
| **Standard Single-Window (`harness`)** | `<= 8` files forming one cohesive vertical slice without parallel write contention | Serial execution + on-demand `invoke_subagent` (`research`, auditors) | `tasks.md` (Tier 2) or fast path (Tier 1); `harness` §3.B gate |
| **Parallel Swarm (`native_swarm` / `swarm` tool)** | `>= 2` independent writable modules runnable concurrently inside one coordinated swarm lifecycle | Disjoint `OWNS:` author workers in `workspace:"share"` / `"branch"` + `1` verifier per `2–4` authors on `workspace:"inherit"` (`harness` §5.F) | Board `#seq` + commits merged to coordinator tree before `kill`; may run *inside* a heavy `marathon` window `Wk` (`tasks.md` / `HANDOFF.md` remain sole window ledgers) |
| **Single-Window Fan-Out (`unlazy`)** | Tier 3 (`>8 files`) single-window dependency graph requiring formal leaf/branch checks | Rolling dispatch waves (`dispatch-check.mjs` + `invoke_subagent` or `swarm`) | `.unlazy/<scope>/PLAN.md` + `GATES.md` (`--reverify`); mutually exclusive with `marathon` |
| **Multi-Window Campaign (`marathon`)** | Tier 2/3 work exceeding safe single-window scope (`2 <= N <= 4` windows), requiring `deep-grill` / `ADR` milestone or sequential slice + Tier-3 audit gates | Sequential human-gated windows `W1..Wn` (`<= 8` touched files per implementation window) | Root `tasks.md` + `HANDOFF.md` (`Status: [COMPLETE]` when all `AC-1..N` pass) |

---

## 3. Phase 3: Per-Window Model, Effort & Skill Routing

Different windows carry different cognitive loads. During initial planning (and when updating `HANDOFF.md` at the end of each window), assign an explicit **Model & Effort Tier** and **Required Skills** to every window `W1..Wn`:

| Window Archetype | Cognitive Profile | Recommended Host Model & Effort | Typical Required Skills & References |
| :--- | :--- | :--- | :--- |
| **Architecture, Deep-Grill, Governance/Customization, or Security/Consistency Audit** | High ambiguity, multi-file invariant reasoning, adversarial falsification, or `.agents/rules/harness-maintainer.md` Rule 17 governance edits | **Top Reasoning Model (`Gemini 4 Neon (XHigh)` / `Gemini 4 Carbon (High)` for governance writes): Highest Effort** | `harness` (`references/marathon.md`, `references/adr.md`, `references/mistake-proofing.md`), `deep-grill`, `audit` |
| **Standard Vertical-Slice Implementation, Refactoring, or Optimization** | Locked contract and clear `AC-1..N`; requires disciplined code generation and seam testing | **Balanced / Coding Model (`Gemini 4 Carbon (High)` / `Pro` / `Sonnet` tier): Medium / High Effort** | `harness` (`references/marathon.md`, `references/test-design.md`), `refactoring`, `sweetspot`, `game-engineering`, `ui-refinery` |
| **Mechanical Polish, Doc/Changelog Sync, or Scoped Lint/Comment Cleanup** | Deterministic transformations with existing test coverage (non-governance paths only) | **Fast Model (`Flash` / `Haiku` tier): Low / Medium Effort** | `harness` (`references/marathon.md`), `ui-refinery` (`~/.gemini/config/skills/ui-refinery/references/code-comments.md`), `technical-writing` |

### Runtime Role & Rule 17 Calibration (Orchestrator, Flagships, Auditors & Auxiliary)

| Runtime Role | Primary Responsibility | Allowed Skills & Tools | `.agents/rules/harness-maintainer.md` Rules 15f & 17 Boundary |
| :--- | :--- | :--- | :--- |
| **1. Orchestrator / Coordinator (`Coordinator` role)** | Window planning (`tasks.md`/`HANDOFF.md`), `deep-grill`, swarm board control (`swarm`, `post_message`, `read_board`, `swarm_wait`), `swarm_pane` Overview (`.system_generated/swarm/plan.json`), branch integration, `harness` §5.E Mutual Falsification | `harness` (`references/marathon.md`, `references/adr.md`), `deep-grill`, `audit`, `upstream-auditor`, `swarm_pane`; `ask_question`, `invoke_subagent`, `run_workflow`, verification commands | Non-coding during active swarms; inside harness checkouts under `A1`, approved flagship models (`Gemini 4 Neon (XHigh)` / `Gemini 4 Carbon (High)` in `upstream_state.seed.json`) receive `allow`, Pro-class Orchestrators (`gemini-pro-orchestrator-neon`) prompt `force_ask`, and Flash workers receive `deny` on customization/governance writes (global `~/.gemini/config/` stays `deny` under Rule 12) |
| **2. Coding Flagships (`Author` workers)** | Vertical-slice production code, complex bug diagnosis, seam tests, and customization/governance edits | `harness` (`references/test-design.md`, `references/mistake-proofing.md`), `diagnosing-bugs`, `refactoring`, `sweetspot`, `game-engineering`, `rustify`, `rust-harden`, `renew`, `database-migrations`, `ui-refinery`; disjoint `workspace:"share"` / `"branch"` writes | Inside harness checkouts, governance/customization writes (`GEMINI.md`, `DESIGN.md`, `hooks.json`, `skills/`, `agents/`, `guard/`, `porter/`, etc.) are automatically allowed strictly for `Gemini 4 Neon (XHigh)` (`xhigh`) and `Gemini 4 Carbon (High)` (`high`/`xhigh`); Pro-class Orchestrators route to `force_ask` and Flash/downgraded tiers are denied by `PreToolUse` |
| **3. Auditors & Verifiers (`agents/*.md` + `Verifier` workers)** | Independent Pre-flight Gate (`consistency-auditor`, `specification-gap-auditor`, `security-boundary-verifier`, `silent-failure-hunter`, `test-adequacy-auditor`, `contract-change-auditor`, `simplicity-auditor`, `meta-auditor`, `research`) and swarm diff/test checks | `audit` (`~/.gemini/config/skills/audit/references/security-review.md`), `harness` (`references/test-design.md`), `ui-refinery`; `agents/*.md` stay strictly `access: read-only` (`harness` §5.B), swarm verifiers use `workspace:"inherit"` and report defects to `@<author>` | Never rubber-stamp; every `CRITICAL`/`HIGH` finding undergoes `harness` §5.E Mutual Falsification in the coordinator session; in `native_swarm`, leave `model` unset for verifiers by default unless user-requested or quota-exhausted (`Rule 15f`) |
| **4. Fast / Auxiliary (`Flash` / `Haiku` tier)** | Live webview UI flows (`browser`), stall timer checks (`monitor`), opt-in status narration (`narrator` only when requested by name; `swarm_pane` Overview replaces default `narrator`), or mechanical non-governance doc/comment polish | Built-in `browser` (`Model: "flash"` default), `swarm_monitor` (`schedule` with `CronExpression: "*/3 * * * *"` and `IsDaemon: true` + stall-only `post_message`), opt-in `swarm_narrator`, `ui-refinery` (`~/.gemini/config/skills/ui-refinery/references/code-comments.md`), `technical-writing` | Permanently denied on customization/governance writes (`A1` / `Rule 17`); in active `native_swarm` sessions leave `model` unset for `monitor` (and opt-in `narrator`) unless user-requested or quota-exhausted (`Rule 15f`) |

* **Adaptive Re-Calibration:** If a window discovers unexpected structural complexity (or finishes simpler pieces early), the agent may adjust the recommended Model & Effort tier for the *upcoming* window `Wk+1` when writing `HANDOFF.md`, stating the one-line technical reason.

---

## 4. Phase 4: Disk Ledger Persistence (`tasks.md` & `HANDOFF.md`) & Cold-Start Handoff

All marathon state lives on disk in the target project root (`tasks.md` and `HANDOFF.md`), never in transient chat memory:

### A. `tasks.md` Window Table & Status States
At the top of `tasks.md`, declare `**Campaign ID:** \`YYYY-MM-DD-<topic-slug>\`` and maintain the window roadmap alongside the detailed `[ ]` / `[x]` task items using four deterministic status tokens (`[x] DONE`, `[ ] NEXT`, `[~] IN-PROGRESS (PARTIAL)` when a `GEMINI.md` Rule 13 handoff trigger fires mid-window, and `[!] BLOCKED` when a Phase 5 safety/correctness blocker awaits user decision):

```markdown
**Campaign ID:** `2026-11-18-auth-service`

## Marathon Window Plan (`W1..Wn`)
| Window | Scope & Deliverable | Exit Gate | Recommended Model & Effort | Required Skills | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `W1` | Schema + Core Auth Slice | `AC-1`, `AC-2` | `Gemini 4 Neon (XHigh)` / `Gemini 4 Carbon (High)`: Highest Effort | `harness` (`references/marathon.md`, `references/mistake-proofing.md`) | `[x] DONE` |
| `W2` | Interface Flows + Integration & Audit | `AC-3`, `AC-4` | Balanced: High Effort | `harness` (`references/marathon.md`), `ui-refinery`, `audit` | `[ ] NEXT` |

## Completed Windows Log
| Window | Date | Status | Delivered Artifacts & Verified Gates | Exit Criteria Progress |
| :--- | :--- | :--- | :--- | :--- |
| `W1` | `2026-11-18` | `[x] DONE` | Auth schema + service slice; `pytest` + typecheck exit `0` | `2/4` (`AC-1`, `AC-2`) |
```

Append one compact row per finished or Rule 13 partial window execution to `## Completed Windows Log` in both `tasks.md` and `HANDOFF.md` (when resuming a partial window, append a separate `Wk (Resumed)` row rather than mutating earlier rows). Keep the table append-only for the active campaign (clearing it only on Hard Cross-Task Reset for a fresh `Campaign ID`); never spawn per-window subdirectories or competing per-window worklog or next-work files.

### B. End-of-Window `HANDOFF.md` Update & Ready-to-Use Prompt
When window `Wk` ends (either by completing its scoped tasks and passing `~/.gemini/config/skills/harness/SKILL.md` §3.B, or by hitting a `GEMINI.md` Rule 13 mid-window trigger):

1. **Intermediate Window (`k < N`) or Mid-Window Rule 13 Interruption (`[~] IN-PROGRESS (PARTIAL)` / `[!] BLOCKED`):**
   * Update `tasks.md` checkboxes, window status (`[x] DONE` if `Wk` passed all gates, else `[~] IN-PROGRESS (PARTIAL)` or `[!] BLOCKED`), and append one row for `Wk` under `## Completed Windows Log` in both `tasks.md` and `HANDOFF.md`.
   * Write or update `HANDOFF.md` at the project root using `~/.gemini/config/templates/HANDOFF.template.md` with `**Campaign ID:** \`<YYYY-MM-DD-topic-slug>\`` and `Status: [IN-PROGRESS]`, and populate `## 4. Cold-Start Directive for the Incoming Agent`:
     * **Where:** `new window with this HANDOFF.md`
     * **Window Index:** `Window <k+1>/<N>: <Window Title> (Campaign: <id>)` (or `Window <k>/<N> (Resumed): <Window Title> (Campaign: <id>)` on a mid-window Rule 13 handoff)
     * **Recommended Model & Effort:** `<Model Tier> (<Effort Level>): <1-line reason>`
     * **Required Skills to Load:** `<comma-separated skill names and ~/.gemini/config/skills/<name>/SKILL.md (plus ~/.gemini/config/skills/<name>/references/<subdoc>.md) paths>`
     * **Immediate Next Action:** Exact file, symbol, or command to run on Turn 1.
     * **Ready-to-Use Prompt:** A self-contained, copy-ready prompt in the user's language whose first line is `[Campaign: <id> | Window <k+1>/<N>: <Window Title>]` (or `[Campaign: <id> | Window <k>/<N>: <Window Title>]` for a cold-start `Window 1` or resumed window) and that instructs the next window to read `HANDOFF.md` and `tasks.md`, load the required skills, and execute the window under `marathon` scope lock without merging unrelated tasks.
   * In the user-facing response's **Delivery Block** (`GEMINI.md` Rule 5), output: what was verified and any verification gaps (`GEMINI.md` Rule 8), progress as criteria met (`e.g. 2/5 acceptance criteria met; Window 1/3 complete`), the **Recommended Model & Effort**, and the fenced **Ready-to-Use Prompt**.
2. **Terminal Window (`k == N` and all `AC-1..N` verified):**
   * Mark `Wn` as `[x] DONE` in `tasks.md` and append the final `Wn` row under `## Completed Windows Log` in both `tasks.md` and `HANDOFF.md`.
   * If opt-in `REPOSTATE.md` already exists at the project root, update its `Last Verified Commit` (`git rev-parse --short HEAD` post-commit, or tagged `<short-sha> (+ working tree)` when updated pre-commit), `Current State Snapshot`, `Planned Roadmap`, and `Compact Milestone Ledger` (preserving `<= 150` lines and zero volatile `:L<n>` coordinates). Do not create `REPOSTATE.md` unless the user explicitly requested it, and leave it unchanged (except an optional open-risk note) when a campaign halts `[!] BLOCKED` or ends via `"stop marathon"`.
   * Update `HANDOFF.md` with `Status: [COMPLETE]` and `Progress: N/N exit criteria met`. Per `~/.gemini/config/templates/HANDOFF.template.md` (`"When all are met the status is [COMPLETE] and no further handoff is issued"`), omit the next-window `Ready-to-Use Prompt`, seal the `Campaign ID` against any future `Wn+1` appends, and deliver the final `GEMINI.md` Rule 5/8 completion block.

---

## 5. Phase 5: Strict Mid-Marathon Scope Lock (Anti-Drift Silence Rule)

While a marathon is in progress (`W1..Wn` prior to `[COMPLETE]`):

1. **Zero Unsolicited Feature or Plan-Change Proposals:** Unless the user explicitly asks for new ideas, scope expansion, or plan revisions, the agent **must not** propose out-of-plan features, bonus improvements (`VALUABLE`), architectural detours, or roadmap alterations in its chat responses or handoff prompts.
2. **Park Silently in `tasks.md` Only When Relevant:** If a useful non-essential observation arises, either omit it completely or (only if the user asked to track future ideas) park a single line under `## Parked (Out of Active Marathon Scope)` in `tasks.md` without discussing it in chat.
3. **Mandatory Safety & Blocker Carve-Out (`GEMINI.md` Rule 8):** Suppressing scope creep never means hiding defects. If the agent discovers a **`NECESSARY FOR SAFETY/CORRECTNESS`** issue (a breaking bug, security boundary violation, data-loss hazard, or a technical constraint that renders an `AC-1..N` criterion unsatisfiable per `~/.gemini/config/skills/harness/SKILL.md` §4.E), mark the window `[!] BLOCKED` in `tasks.md` and surface the exact evidence and required adjustment immediately.

---

## 6. Triggers and Invocations

* **Slash Command:** `/marathon`.
* **Natural Language Triggers:** `maraton başlat`, `bunu maraton ile pencerelere böl`, `start a marathon plan`, `plan this across windows`.
