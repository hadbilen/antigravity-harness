# Antigravity Harness

[![Release](https://img.shields.io/badge/release-v2.4.0-blue.svg)](https://github.com/hadbilen/antigravity-harness/releases)
[![CI](https://github.com/hadbilen/antigravity-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/hadbilen/antigravity-harness/actions/workflows/ci.yml)
[![Runtime](https://img.shields.io/badge/core%20runtime-Python%20stdlib%20only-brightgreen.svg)](#dependencies)
[![Design Standard](https://img.shields.io/badge/UI-WCAG%20AA%20%7C%20antislop-orange.svg)](DESIGN.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **A behavioral constitution, auditor subagents, a rule transpiler, and a write-protection /
> integrity-monitoring companion (`agy-guard`) for AI coding agents.**

Autonomous coding agents suffer from **environment mutation drift**, **sycophancy**, **test weakening
(Goodhart's Curse)**, **context bloat**, and **ecosystem fragmentation**. Antigravity Harness counters
them with an engineering constitution (`GEMINI.md`), 20 modular skills, 10 independent auditor
subagents, Porter (a rule importer/exporter for Claude Code, Cursor, Aider and `AGENTS.md` tools),
and Antigravity Guard, which write-protects the governance files, detects drift, and gates changes
behind human confirmation.

---

## What Guard does and does not protect against (threat model)

Guard runs as **your own OS user**. Read this before relying on it:

| Protects against | Does NOT protect against |
|---|---|
| Accidental edits and tools that respect file permissions | A process running as your user that deliberately restores write bits (`chmod u+w`) |
| In-place edits of top-level files (`DESIGN.md`, `hooks.json`, …) and any change inside `rules/`, `skills/`, `agents/`, `templates/` | Deleting and recreating a top-level file: the config root stays writable for Antigravity's own saves, so this is only *detected* (FIM), not blocked |
| Headless / unattended agents: administration commands (`unlock`, `rebaseline`, `snapshot restore` / `prune`, lowering an environment policy, `notify disable`, `startup enable` / `disable`, `porter stage`, …) refuse without a human typing `yes` in a terminal or approving in the GUI | An agent that can drive an interactive terminal *and* chooses to ignore the constitution |
| Interactive approval prompts and native Antigravity `deny` rules (`command(agy-guard unlock)`, `command(regex:.*--no-verify.*)`) in standard App/CLI modes | Launching Antigravity CLI with `--dangerously-skip-permissions`, which auto-approves tool permission requests without prompting (native `deny` rules and OS-level read-only / `chattr +i` locks remain the backstop) |
| Silent drift: the SHA-256 baseline (outside the protected tree) reports modified, added, deleted and unreadable files | An attacker who can rewrite both the files **and** the per-user baseline (it is not signed) |
| Forgotten maintenance windows: leases relock automatically when they expire (failed relocks are retried and alerted), and changes made during an unattended window wait for review instead of being trusted | `root` / administrators, or kernel-level tampering |
| Untraceable decisions: approvals, refusals, locks, leases, rebaselines, restores, boot checks and every WARNING/CRITICAL alert are appended to an audit log (`~/.local/state/antigravity-harness/logs/guard.log`) | Rewriting that log: it lives in your user's state directory and is not signed |

For a real boundary, make the policy files immutable with root (`sudo chattr +i`), keep them root-owned,
or enforce policy on the host side (e.g. an Antigravity `PreToolUse` hook that denies writes to the
governance tree). `agy-guard status` shows which protection kind is active
(`USER-SPACE LOCK (advisory against the same OS user)` vs `IMMUTABLE (chattr +i, root)`).

---

## The Problem: Why This Exists

1. **Environment Mutation Drift & Rogue Writes:** agents, sub-processes or IDE extensions quietly overwrite prompt contracts or inject unverified skills into `~/.gemini/config/`.
2. **The Sycophancy Trap:** models reflexively agree with user premises and bury the diagnosis under polite filler.
3. **Test Weakening (Goodhart's Curse):** when a test fails, agents are tempted to edit assertions or skip tests to manufacture a green exit code.
4. **Context Bloat & Analysis Paralysis:** dumping megabytes of logs into the context window degrades attention and causes looping fixes.
5. **Ecosystem Fragmentation:** directives written for one tool are rewritten by hand for the next and decay along the way.

---

## Architectural Pillars

```
                     ┌───────────────────────────────────────────────┐
                     │          The Engineering Constitution         │
                     │  - Proportional Gate Escalation (Tier 1/2/3)  │
                     │  - The Immutable Test Invariant (No Weaken)   │
                     │  - Think in Code (Zero Context Bloat)         │
                     │  - External Rule Ingestion Invariant (Rule 16)│
                     └───────────────────────┬───────────────────────┘
                                             │
        ┌──────────────────┬──────────────────┼──────────────────┬──────────────────┐
        ▼                  ▼                  ▼                  ▼                  ▼
  ┌──────────────┐ ┌─────────────────┐ ┌──────────────┐ ┌──────────────────┐ ┌──────────────────┐
  │   Auditor    │ │  Modular Skill  │ │ Baseline UI  │ │  Porter bridge   │ │Antigravity Guard │
  │  Subagents   │ │     System      │ │   Contract   │ │ (verified export)│ │ (lock/FIM/lease) │
  └──────────────┘ └─────────────────┘ └──────────────┘ └──────────────────┘ └──────────────────┘
```

---

## 1. Antigravity Guard (`agy-guard` CLI & GUI)

### Governance write shield (`guard/os_adapter.py`, `guard/environment.py`)
Guard locks the **governance seams** of `~/.gemini/config/` (`rules/` including `rules/antigravity-constitution.md`,
`DESIGN.md`, `AGENTS.md`, `GEMINI.md` if present, `hooks.json`, `mcp_config.json`, `skills/`, `agents/`, `templates/`, `.harness/`,
plus the 4 harness plugin directories `plugins/antislop`, `plugins/rust-suite`, `plugins/media-studio`, and `plugins/game-engineering` when installed in opt-in `--plugins` Hybrid Layout)
together with the installed Guard runtime (`~/.local/share/antigravity-harness/runtime/`) and user launchers
(`~/.local/bin/agy-guard`, `agy-porter`, `porter`). Harness-internal `MISTAKES.md` stays in this source repository and is
not installed globally into `~/.gemini/config/`. Antigravity's
own runtime state (`config.json`, `projects/`, `sidecars/`, `plugins/` parent directory for Marketplace and third-party plugins, `cache`) stays writable, and so does
the root directory: Antigravity saves `config.json` by atomic replace (new file + rename), which a read-only
root would break. Top-level files therefore resist in-place edits, but a process that deletes and recreates
one is not stopped; the integrity baseline reports it.
* **Linux:** strips write bits (user-space lock); adds `chattr +i` only when run as root.
* **macOS:** BSD user-immutable flag (`chflags uchg` / `nouchg`) plus permission lockdown.
* **Windows:** NTFS deny ACEs `(WD,AD,DE,DC)` plus `attrib +R`; status is read from the ACL, not by writing probe files.
* Symlinks are **never followed**: a symlink pointing outside the tree is reported as *unprotected*
  (install in copy mode to protect it), and a config root that is itself a symlink is refused instead of
  locking the link target. Original permission modes are recorded (under a cross-process lock) and restored on
  unlock; a world-write bit is never restored from the record, and entries that were already read-only come
  back owner-writable.
* `lock` returns a non-zero exit code and lists the reasons whenever protection is only partial.

### Integrity baseline (`guard/integrity.py`)
* A flat `path -> SHA-256` map per environment, stored in `~/.local/state/antigravity-harness/integrity/`
  (outside the protected tree; `ANTIGRAVITY_INTEGRITY_FILE` overrides it for the global environment).
* Records symlinks as links (retargeting is detected), reports unreadable files, ignores installer backups and
  legacy Guard files **at the top level only** (a `backup_*` folder inside `skills/` is monitored), rejects
  malformed baselines as corrupt, and archives the previous baseline on every rebaseline. It detects drift; it
  is not a signature.
* Changes made during a lease that expired unattended are recorded as **pending review**: `status` and `verify`
  show `[REVIEW]` until an approved `agy-guard rebaseline` accepts them (anything changed afterwards is
  reported as ordinary drift).

### Snapshots & verified restore (`guard/snapshot.py`)
* Snapshots of the governance scope live in `~/.local/share/antigravity-harness/snapshots/` with a content manifest.
* Restore verifies the snapshot against its content manifest (snapshots without one are refused), refuses to
  write through destination symlinks, always takes a pre-restore backup first, swaps entries with a journal
  (rolled back on failure, with relock failures reported), and re-establishes the baseline.
* `prune` keeps N snapshots **per kind** (manual, pre-restore, pre-ingest, boot forensics) and requires human
  approval. `node_modules` is not copied into snapshots.

### Multi-environment registry (`guard/environment.py`)
* Discovers Claude Code, Codex / `AGENTS.md`, Cursor and Aider workspaces through their **rule files only**
  (`CLAUDE.md`, `.claude/agents|commands|skills`, `AGENTS.md`, `.cursorrules`, `.cursor/rules`, …), never the
  tools' own runtime state (sessions, memory, `settings.local.json`). The home directory is never treated as a
  workspace, and the GUI asks for a project folder. Ids include a path hash so two projects with the same folder
  name never collide; ambiguous ids are rejected. Whole-directory seams registered by 1.3.x are migrated.
* Policies: `enforced`, `monitored`, `disabled` (`agy-guard env policy <id> <policy>`). Other agents'
  environments start as `monitored` (integrity reports, no chmod); lowering a policy requires human approval,
  and a non-enforced environment is reported as NOT protected instead of "locked".
* The registry lives in the per-user state directory, so results never depend on the current directory.

### Human-approved, time-bounded leases (`guard/lease.py`)
* `agy-guard request-unlock --duration 60` asks a human to approve in the terminal (or the GUI); headless
  requests are rejected. There is no auto-approve flag.
* The record is persisted **before** unlocking and re-checked under the store lock, so two requests can never
  both be granted; a detached watcher (logging to `logs/lease-watcher.log`) relocks when the lease expires, and
  every Guard command also expires overdue leases. Several environments can hold leases at the same time.
* Closing relocks first and removes only the record of **that** lease. A successful close writes a change
  report (`~/.local/state/antigravity-harness/lease_reports/<id>.json`); the window's changes become pending
  review, or are accepted at once when a human closes the window with `agy-guard lock-complete` and confirms.
  A failed relock keeps the record, raises a CRITICAL notification and is retried (up to 5 times, 60 s apart).
  A corrupt lease store fails closed: it is set aside and every enforced environment is re-locked.

### Notifications (`guard/notifier.py`)
* `notify-send` (Linux), `osascript` (macOS), PowerShell balloon tips (Windows); message text is passed as
  data (argv / environment), never interpolated into code. Falls back to the terminal.
* Cooldowns: `CRITICAL` none, `WARNING` 30 minutes, `INFO` 24 hours. `agy-guard notify quiet` passes
  CRITICAL only; `agy-guard notify disable` silences everything (force never overrides it) and requires human
  approval; WARNING and CRITICAL events still reach the audit log. `agy-guard notify send` lets hooks reach the
  human instead of the agent's context.

### Audit trail (`guard/audit_log.py`)
* One JSON object per line in `~/.local/state/antigravity-harness/logs/guard.log` (1 MiB × 5 rotation, mode
  0600): approvals and refusals, locks and unlocks, policy changes, lease grants/closes/relock failures,
  baselines and pending reviews, snapshot create/restore/prune, boot checks, notification settings and every
  WARNING/CRITICAL notification (including suppressed ones). Logging never blocks an operation.

### Boot sentinel, doctor and GUI
* `agy-guard startup enable` (human approval) registers a systemd user unit / launchd agent / scheduled task
  (least privilege on Windows) that runs `boot-check`: it locks **first**, then verifies; on drift it captures a
  forensic snapshot (identical drift is not copied again; the newest 3 are kept), sends a CRITICAL notification
  and never rebaselines. Enabling reports failure when systemctl/launchctl fails. (Ordering before the
  graphical session is best-effort.)
* `agy-guard doctor [--fix]` (checks in `guard/doctor.py`) reports protection gaps, legacy baselines/snapshots
  inside the config tree, world-writable sources, symlink installs, dangling or external symlinks under `plugins/`
  and `.agents/skills/`, hybrid duplicate `skills/<slug>` + `plugins/<pack>/skills/<slug>` shadowing and stale global
  `contrast-mcp.py` entries alongside `plugins/antislop/mcp_config.json`, `hooks.json` schema/executable/script-path existence and `"enabled": false` states,
  dual `GEMINI.md` + `rules/antigravity-constitution.md` double-load warnings, workspace `.agents/hooks.json`
  collisions, `install_receipt.json` version alignment, relock-watcher errors, risky Antigravity permission grants
  (counts only), and native Antigravity `deny` rule recommendations (`agy-guard unlock`, `--no-verify`, plus optional `agy plugin` guidance when harness packs are installed).
* **Full CLI Workflow (25 subcommands):** `init`, `status`, `lock`, `unlock`, `verify`, `rebaseline`, `snapshot`, `porter`, `upstream`, `startup`, `boot-check`, `gui`, `doctor`, `test-boundary`, `provenance`, `env`, `request-unlock`, `lock-complete`, `drift`, `self-audit`, `notify`, `code-map`, `ui-slop`, `synthetic-markers`, `verify-invariants` (plus the internal `lease-tick` used by the lease watcher).
* **Desktop GUI (`guard/gui.py`):** Tkinter/ttk, `DESIGN.md` dark palette; long operations (verify,
  rebaseline, restore, drift analysis) run off the UI thread, tray callbacks are marshalled onto the Tk loop,
  administration actions go through the same approval gate (and audit log) as the CLI, snapshot files open as
  read-only `.txt` copies (never executed), and the window only hides to the tray while a tray icon is running.
* **Event-scoped lifecycle hooks (`hooks.json`, `guard/__init__.py`, `guard/agy_hooks.py`, `guard/hooks/`):** `guard/__init__.py` uses PEP 562 lazy `__getattr__` exports and `guard/agy_hooks.py` acts as a readable, byte-budgeted (`<= 32 KiB`, `<= 160` chars/line) lazy CLI router and compatibility facade (with a lightweight `invocationNum > 1` fast path) loading only the active lifecycle and tool-scoped submodule (`guard/hooks/pre_invocation.py`, `guard/hooks/pre_tool_use.py` with on-demand `_shell_guard.py`, `_swarm_guard.py`, `_mcp_guard.py`, `_write_guard.py`, and `_workflow_ast.py`, or `guard/hooks/stop_gate.py`, sharing `guard/hooks/common.py`) per invocation (`ADR-0008`, `ADR-0010`, `ADR-0013`, `ADR-0015`):
  * **`PreInvocation` (`pre_invocation.py`):** calibrated bilingual (`EN` / `TR`) skill, subagent, MCP server (`rea_rea`, `antislop-contrast` / `antislop_contrast`), and plugin auto-routing via native `systemMessage` (`ADR-0005`, `ADR-0006`, `ADR-0011`, `ADR-0015`, `ADR-0016`) emitting installed-layout-safe paths (`~/.gemini/config/...` or `~/.gemini/config/plugins/<pack>/...`), live `config.json["plugins"][<pack>]["enabled"]` toggle awareness suppressing disabled or removed harness packs, explicit `/slash` priority, pasted-review and read-only meta-question false-positive suppression, tiered hint saturation, bounded workspace & `transcriptPath` tail streaming, interrupted-session `[Harness Recovery & Continuity Gate]` (with `marathon` `Campaign ID` isolation and stale-ledger anti-merge guidance), dynamic predictive context-window handoff advisories (post-`CHECKPOINT` active token headroom vs. incoming job cost without fixed `%` cutoffs, delivering Tier-1 `0`-token `user_markdown` and one-time Tier-2 latched `systemMessage` per `ADR-0014`), and transcript-aware mid-turn / reactive-wakeup silence plus true-consecutive `build-error-resolver` filtering (`ADR-0009`, `ADR-0010`).
  * **`PreToolUse` (`pre_tool_use.py`, `_shell_guard.py`, `_swarm_guard.py`, `_mcp_guard.py`, `_write_guard.py`, `_workflow_ast.py`):** Governance Shield (unconditional `deny` on `~/.gemini/config` governance seams, `~/.gemini/{GEMINI,AGENTS}.md`, `plugins/` root/dot/glob patterns, and all paths inside harness plugin packs while preserving third-party plugins, including unified `ast.parse` pure read-only Python inline/heredoc verification per `ADR-0010` and `ADR-0016`), Top-Catalog Model & Highest-Effort Customization Gate (Rule 17, scoped strictly to `antigravity-harness` checkouts so external user projects can edit their own `AGENTS.md`/`GEMINI.md`/`SKILL.md` on any model, with `known_placeholder_models` diagnostics, fail-closed `MODEL_PLACEHOLDER_*` escalation, and `swarm`, `define_subagent`, `post_message`, `send_message`, `schedule`, and `run_workflow` AST checks per `ADR-0005`, `ADR-0007`, & `ADR-0010`), `GEMINI.md` Rule 9 `tasks.md` `## Authorized Test Modifications` gating (with standardized 3-sentence plain-language operator headers *What changes / If approved / If denied* across all `force_ask` prompts plus exact test path(s) and diff summaries per `ADR-0015`, while permitting clean `[COMPLETE]` stale-campaign resets once prior authorized tests are committed), `force_ask` gating on directory drops (`cp -r`, `rsync`, `git clone`, `mv`, cwd `tar -x`/`unzip`) into `~/.gemini/config/plugins/<any>`, all `agy plugin (install|import)` commands, and `agy plugin (disable|uninstall)` commands targeting harness packs (third-party `disable`/`uninstall` exempt), tiered MCP execution gating (`ADR-0004`), and command-boundary Bash Guard.
  * **`Stop` (`stop_gate.py`):** diff, untracked-file, and linked-worktree `TestBoundaryGuard` integrity verification (tautological assertions, operator/matcher relaxation, `C9` test-runner sniffing, unapproved test skips, malformed `.json`/`.toml`/`.svg` syntax, `UI-1`–`UI-5` slop, and broken local Markdown links) guarded by a 3-strike circuit breaker.
* **Upstream watchdog (`skills/upstream-auditor/scripts/upstream_watcher.py`):** the `SessionStart` hook monitors model drift, `builtin/skills` SHA-256, `~/.gemini/antigravity/builtin/.checksum` bundle drift (`ADR-0014`), and 8 tracked external repositories, sending an operator-only notice once per change (a desktop notification plus `metadata.user_markdown` on `systemMessage` with an empty `systemMessage` body so the operator sees it without injecting maintenance text into the agent prompt); `agy-guard upstream ack` (or `upstream_watcher.py --ack`) silences it until something changes again, and `agy-guard upstream status` (or `upstream_watcher.py --status`) shows the current reasons. Network checks have a hard deadline.

---

## 2. The Engineering Constitution (`GEMINI.md` + `.agents/rules/harness-maintainer.md`)

Slim universal always-on invariants live in `GEMINI.md` (Rules 1–14 & 18, installed globally to
`~/.gemini/config/rules/antigravity-constitution.md` with `trigger: always_on` so Antigravity App, CLI, and
IDE/Extensions all load a single copy while Antigravity's native rule deduplication prevents duplicate loading
inside this checkout); harness-repository-only maintainer rules (Rule 12 admin addendum and Rules 15–17) live
in `.agents/rules/harness-maintainer.md` (`trigger: always_on`). Procedures live in skills and mechanical checks
in Guard and `scripts/`.

* **Proportional Gate Escalation:** Tier 1 (`1–2` files, `<20` lines) direct edits; Tier 2 (`1–2` files `>=20` lines
  or `3–8` files) plans, blast-radius maps and checklists; Tier 3 (`>8` files or auth/schema changes) the full
  workflow with `deep-grill`, ADRs and auditor subagents.
* **The Immutable Test Invariant:** relaxing assertions, skipping tests, or branching on test-runner state in
  production code (`C9`) to pass gates is forbidden; new regression tests are always allowed.
* **Surgical Change & Reuse Discipline (Rule 18):** touch only lines required by the task, search existing
  utilities before introducing helpers, and never revert or overwrite uncommitted changes outside task scope.
* **Delivery Block:** one compact end-of-phase block (verified / not verified, the next step only at phase ends
  or handoffs, progress as criteria met, never percentages); maintenance notices never enter task prompts.
* **Handoffs carry a goal and exit criteria** and are triggered by observable events (milestone done, circuit
  breaker, >500-line trace, repeated user correction), not by a guessed "context saturation".
* **Circuit Breaker** (fix passes capped to `max(1 file, ~10% of affected files/symbols)` per fix pass),
  **Popper's Falsification Gate**, **Null-Action** (no change without a violated rule or a measured failure) and
  **Think in Code**.
* **Harness Maintainer Rules (`.agents/rules/harness-maintainer.md`):** Guard/installer/porter administration is
  human-only (Rule 12 addendum), global `~/.gemini/config` remains unconditionally `deny` under Governance Shield,
  governance/customization edits inside this repository checkout require an approved top-catalog model at highest
  effort plus `python3 scripts/meta_audit.py --all --strict` (Rule 17, aligned with `pre_tool_use.py` so external
  user projects are not gated), and upstream platform collisions (`(a)`–`(h)`: read-only `~/.gemini/config/`,
  `generative_ui`, `gh`, glue-only `run_workflow`, `native_swarm`, `migrate-agent-settings`, `mcp-app-development`)
  resolve in favor of the stricter safety rule (Rule 15).

---

## 3. Auditor Subagents (`/agents`)

Ten read-only role definitions setting `mainAgent: false`, `subagent: true`, `inheritMcp: false`, `access: read-only`,
and canary-verified Antigravity `tools:` (`read_file`, plus `search_web` for `research`; never unmapped legacy names
such as `view_file`/`grep_search`/`find_by_name`). Because Antigravity hosts still attach MCP and task wrappers alongside
`tools:`, `PreToolUse` Layer A remains active for MCP and `manage_task` enforcement; repeated constitutional prompt-defense
boilerplate is deduplicated across `agents/*.md` and injected standalone during Porter exports (`.claude/agents/*.md`,
`.cursor/rules/agent-*.mdc`, and index exports). `agents/research.md` deliberately overrides Antigravity's built-in
`research` subagent so harness callers receive bounded read-only decision matrices and Verification Gap blocks; see
`skills/harness/references/multi-agent-orchestration.md` for live canary evidence and the auditor model/cost guide
(`inherit` vs. `flash` for routine scans vs. top-catalog models for security, consistency, and meta audits):

* **`silent-failure-hunter`:** swallowed exceptions, discarded Rust `Result`/channel outcomes, missing logs, empty fallbacks, unhandled promises.
* **`security-boundary-verifier`:** authorization boundaries, IDOR, input validation, SSRF, TOCTOU, Rust `unsafe` / `UserSlice` / integer-narrowing boundaries.
* **`specification-gap-auditor`:** unhandled edge cases, missing error branches, vague adjectives.
* **`consistency-auditor`:** contradictions, circular dependencies, broken cross-references.
* **`test-adequacy-auditor`:** `[OK]`/`[GAP]` branch coverage tree, tautological assertions, negative error-path tests.
* **`contract-change-auditor`:** caller reachability and compatibility audit for changed signatures, schemas, and CLI flags.
* **`simplicity-auditor`:** `YAGNI` (`Rule 4`), surgical reuse (`Rule 18`), and 7-Rung Efficiency Ladder audit with game-seam and soundness-wrapper carve-outs.
* **`meta-auditor`:** inspects the pre-computed 7-pass harness self-audit (`scripts/meta_audit.py --strict --json`) and governance files.
* **`build-error-resolver`:** isolates compiler, type, and linker failures across TypeScript/JS, Rust/Cargo, Python, Go, Kotlin/Gradle, and QML/CMake and proposes minimal surgical diffs.
* **`research`:** digests large external documentation in an isolated context.

---

## 4. Porter: rule inspection, import and export (`porter.py`, `.harness/manifest.json`)

* **Pre-flight gate:** scores external rules (`.mdc`, `.cursorrules`, `CLAUDE.md`, …) 0–100 before anything is written (`porter/analyzer.py` maps the 20 top-level skills, the 14 consolidated reference module slugs, and archived opt-in skill templates such as `procoder`).
* **Negation-aware sanitizer (`porter/sanitizer.py`):** classifies every match as prohibited (kept), affirmative
  (neutralised, e.g. "skip the failing tests", "use --no-verify", "ignore previous instructions") or uncertain
  (kept and listed as `NEEDS_REVIEW`, never deleted). Negation is clause-scoped (including binary comma-free shared imperative prohibitions across `or`), so "Skipping tests is never OK" and "Never weaken assertions or delete tests"
  survive while "Don't hesitate to skip failing tests" does not.
* **Archive inspection (`porter/archive.py`):** `porter.py inspect bundle.zip` inspects a ZIP without
  extracting or installing anything: member count, total size and compression-ratio limits, path traversal,
  symlink, encrypted and nested-archive members, and a suitability report for each rule file.
* **SSRF-hardened fetcher (`porter/net.py`):** http/https only, globally routable destinations only
  (CGNAT, link-local, private, 6to4/NAT64, IPv4-mapped/-compatible/-translated loopback are rejected), DNS
  pinning against rebinding, per-redirect validation, proxies ignored, an overall deadline, 10 MB cap.
* **Canonical manifest:** all 20 skills with every support file, executable bit and in-skill symlink, all 10
  subagents, the templates, the constitution and the design contract. CI fails if the committed manifest is
  stale (`porter.py manifest --check`).
* **Verified export:** Claude Code (`CLAUDE.md`, `.claude/skills/`, `.claude/agents/` with `tools:`, verbatim
  copies in `.claude/harness/agents/`), Cursor (`.cursor/rules/*.mdc` with valid YAML + `.cursor/skills/`),
  Universal (`AGENTS.md` + `.agents/`), Aider (`CONVENTIONS.md`, `.aider.conf.yml`, `.aider/`), Generic
  (`RULES.md`, `skills/`, `agents/`). Skills, support files (with their executable bits), templates and agents
  are exported with LF line endings and checked for parity by the self-audit; `hooks.json` is Antigravity-only
  and is not exported. Existing files are only overwritten with `--force`.
* **Staging gate:** `agy-guard porter stage` binds the reviewed content hash to the written content, refuses
  destination symlinks, snapshots first and re-locks afterwards; `porter.py import` only writes into this
  source repository (review it with `git diff`).

---

## 5. Modular Skill Ecosystem (`/skills`)

20 capability packages (with 14 specialized reference modules consolidated on-demand under `harness`, `antislop`, `technical-writing`, and `audit` per `ADR-0009` and `ADR-0011`, `disable-model-invocation: true` applied to explicit-only skills `audit`, `retro`, `chisle`, and `upstream-auditor` plus installed-layout-safe paths verified by `meta_audit.py` per `ADR-0015`, and `procoder` archived as opt-in `templates/procoder.SKILL.template.md` per `ADR-0014`):

* **`harness`:** engineering harness, verification gates, Low-Friction Turbo UX (`Reversible-First` defaults and 3-Class Hard Ask Gate preserving `guard/` Layer A safety), Tier-3 Pre-Code Plan Gate (`YAGNI` Brake), Swarm vs. `unlazy` vs. `marathon` topology routing (`ADR-0007`, `ADR-0012`, `ADR-0013`), and task lifecycle (reading opt-in `REPOSTATE.md`, `DECISIONS.md`, `ARCHITECTURE.md`, and `SECURITY_POSTURE.md` when present, plus opt-in `templates/vulkan.SKILL.template.md` and `templates/procoder.SKILL.template.md`), with on-demand reference modules for `context-and-artifacts`, `multi-agent-orchestration`, `marathon` (`/marathon` multi-window goal planning, `Campaign ID` isolation, append-only `## Completed Windows Log`, and `HANDOFF.md` orchestration), `unlazy` (`/unlazy` Tier-3 `>8` files Depth Tree and ledger verification), `adr` (`/adr` with structured `Proposed By`/`Approved By`/`Authority` decision provenance), `mistake-proofing` (`/mistake-proofing`), `dependency-upgrade` (`/dependency-upgrade`), and `test-design` (`/test-design`).
* **`sweetspot`:** controlled, behavior-preserving performance, memory (`RAM`), disk/artifact footprint, and network download/upload bandwidth & round-trip latency optimization (`--all`, `--time`, `--memory`, `--disk`, `--net` with Controllable vs. Uncontrollable External Path classification) governed by the 3-Zone Sweet-Spot Honesty Gate (`Zone 1: Controlled`, `Zone 2: Trade-Off / Identity-Shifting [Approval Required]`, `Zone 3: Already at Sweet Spot [Null-Action]`).
* **`media-studio`:** high-fidelity audio, video, still-image (`JPG`, `PNG`, `TIFF`, `BMP`), and animated visual (`MP4`, `WebM`, `Animated WebP`, `GIF`, `APNG`, `WAV`, `FLAC`, `Opus`, `AAC`) synthesis, timeline editing, container/header salvage (`salvage`), signal restoration, two-tier fidelity-bounded quality enhancement, two-pass `EBU R128` loudness mastering, and the deterministic `media_qc.py` quality gate (`MEDIA-1..MEDIA-7`, `GAME-1..GAME-3`, `LUFS`, `dBTP`, aspect-locked `compare` `SSIM`/`PSNR`, `ab-sheet`, game SFX peak normalization, Ogg Vorbis/Opus, loop-seam, pixel-art, and sprite-atlas checks).
* **`renew`:** generational legacy software and classic game modernization, dead-runtime/toolkit porting, and unbuildable codebase revival via a 5-stage contract-first pipeline (`Silent Autopsy -> Renewal Contract -> Golden Master or Equivalence Ledger -> Layered Strangler Cutover -> Parity Gate`) with `[HARDWARE/ENV SHIM]` record/replay contracts, locale invariants, and a Legacy Game & Interactive Simulation Remaster profile.
* **`rustify`:** architectural C, C++, Go, Python, TypeScript/JavaScript, Ruby, and Java/Kotlin -> memory-safe Rust (`2024` Edition, `#[unsafe(no_mangle)]`, `unsafe extern "C"`, Cargo publish-age cooldowns) migration and Foreign Function Interface (`FFI`) bridging (`bindgen`/`cbindgen`, `cxx`, `PyO3`, `napi-rs`/`wasm`, Magnus, JNI) via a 5-stage contract-first pipeline (`Silent Build, ABI & Bridge-Overhead Autopsy -> Migration Contract & Strangler Cutover -> Differential Pinning, Noise Taxonomy & Leaf-to-Root Decomposition -> Two-Stage Unsafe Purification -> 3-Tier Verification Ladder` with `rustc`, `clippy`, `miri`, C/Rust sanitizers, conditional `cargo kani` formal proofs, `--batch`/`FnIndex` hot-loop batching, `known-diffs.jsonl`, and optional pinned `rust-anything` `=2.1.0 --locked` CLI/MCP acceleration with full manual fallback per `ADR-0012`).
* **`rust-harden`:** intra-Rust ownership and borrow-checker debt cleanup, production `.unwrap()` / `.expect()` elimination (`// INFALLIBLE: <why>` and `#[expect(lint, reason = "...")]`), crate-tiered `[lints.rust]` / `[lints.clippy]` enforcement, and `--internal` (signature-preserving default), `--contract` (`Expand -> Migrate -> Contract` `Result`/`newtype`/`typestate`), and `--greenfield` (day-1 crate/workspace architecture) modes, plus four on-demand playbooks: greenfield workspace partitioning, Edition `2024` `[workspace.lints]`/`clippy.toml`/publish-age cooldowns, and `thiserror`/`anyhow` error seams (`skills/rust-harden/references/greenfield-architecture.md`), `tokio::select!` cancellation and pre-runtime POSIX privilege drop (`skills/rust-harden/references/async-and-userspace.md`), `#![no_std]`, Framekernel, IRQ-spinlock, `UserSlice`, DMA `Drop`, and `loom`/`kani` proofs (`skills/rust-harden/references/kernel-and-unsafe.md`), and real-time game loops, Vulkan/GPU `Drop` & swapchain resilience, lock-free `SPSC` audio threads, and bounded binary saves (`skills/rust-harden/references/game-and-realtime.md`).
* **`game-engineering`:** deterministic fixed-timestep game loops (`Profile A` Web/Canvas `16.67 ms` budget and `Profile B` 3D/Native Engines), zero per-frame allocation, seeded PRNG, save `schemaVersion` quarantine, and clean-room `rea_rea` asset/binary recovery bridges.
* **`porter`:** ecosystem adapter, suitability analyzer, transpiler.
* **`vibecoder`:** product-first rapid prototyping with zero-friction single-file rich HTML application, game (`Game Vibe Mode`), and creative studio / interactive sandbox (`Creative & Sandbox Vibe Mode`) delivery.
* **`deep-grill`:** Socratic trade-off interviewer: product and business-rule boundaries first,
  `[NEEDS CLARIFICATION: ...]` parking, paraphrase check-ins, a decision ledger ending in exit criteria.
* **`chisle`:** terse, zero-fluff development mode with YAGNI/ladder-first code discipline (never bypasses verification gates or locked acceptance criteria).
* **`antislop`:** core 40-rule UI/copy filter + structural UI scanner (`check_ui_slop.py`), bundling on-demand reference modules and tools for UI geometry (`/antislop-ui`), code-comment hygiene (`/antislop-code`), prose scanning (`/antislop-copywriting` + `check_synthetic_markers.py` for English and Turkish), WCAG contrast (`/antislop-human` + `contrast-check.py` / `contrast-mcp.py`), mobile layout (`/antislop-layoutmobile`), and kinetic motion (`/silk-design`).
* **`technical-writing`:** Diataxis documentation, executable example verification, and `/visualizer` diagramming (`skills/technical-writing/references/visualizer.md`; Mermaid or built-in `generative_ui`).
* **`audit`:** read-only structural, consistency, and security boundary audit engine (with automatic `REPOSTATE.md`, `ARCHITECTURE.md`, and `SECURITY_POSTURE.md` Phase 0.B control grounding per `ADR-0011` and `ADR-0012`), bundling `/security-review` pre-deployment and cloud-infrastructure checklists (`skills/audit/references/security-review.md`).
* **`upstream-auditor`:** model catalog, built-in Antigravity runtime (`builtin/skills` + `builtin/.checksum`), and 8-repository upstream drift auditor (supporting branch commits, consolidated sub-reference targets, and `"track": "release"` tag tracking such as `morluto/rea` and `erkamyaman/rust-anything`).
* **`refactoring`**, **`retro`**, **`data-analysis`**, **`diagnosing-bugs`**, **`database-migrations`**.

Third-party origins and licenses are listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

### Bilingual Architecture (Canonical English + Native Turkish Intent Bridge)
While all core invariants, formal specifications, architectural decision records (`docs/adr/`), and agent contracts are canonical English (`GEMINI.md` Rule 6), Antigravity Harness provides **first-class bilingual intent recognition**:
* **Zero-Friction Prompt Matching:** Skill hint tables (`guard/agy_hooks.py` / `guard/hooks/pre_invocation.py`) and frontmatter triggers accept both standard English commands/phrases and native Turkish colloquial intents (`"hata var"`, `"sadeleştir"`, `"hızlandır"`, `"veri analizi"`).
* **Localized Anti-Slop Scanner:** `skills/antislop/scripts/check_synthetic_markers.py` features automatic language detection (`detect_language`) and dedicated Turkish LLM synthetic-marker detection rules (`TR-1` through `TR-7`) alongside universal English markers.
* **Extensibility:** The bilingual intent tables serve as a reference implementation for contributors wishing to bridge additional languages into Antigravity 2.0 lifecycle hooks.

---

## 6. Baseline Design Contract (`DESIGN.md`)

* Three domain-aware UI archetypes (`MODE: UTILITY`, `MODE: EDITORIAL`, and `MODE: GAME & INTERACTIVE`), backed by deterministic structural verification (`skills/antislop/scripts/check_ui_slop.py`, `UI-1`–`UI-5`, including HSL CSS gradient hue-range detection in `UI-3`).
* Every visual element passes a one-sentence functional justification test.
* WCAG AA: 4.5:1 text, 3:1 control borders and disabled text; the "Measured Contrast Pairs" table is
  recomputed by the self-audit, so stated ratios cannot drift from reality.
* Dials `ENERGY 2 / RHYTHM 2 / MOTION 2` (stepping down under `prefers-reduced-motion`) and five mandatory data states.

---

## Directory Structure

```text
antigravity-harness/
├── GEMINI.md / DESIGN.md / MISTAKES.md   # Universal constitution, design contract, repo-local incident log
├── .agents/
│   └── rules/harness-maintainer.md        # Harness-only maintainer rules (Rule 12 addendum, Rules 15-17)
├── CHANGELOG.md / CONTRIBUTING.md / THIRD_PARTY_NOTICES.md / LICENSE
├── hooks.json                             # Reference SessionStart, PreInvocation, PreToolUse & Stop hooks
├── install.py / install.sh                # Installer (install.sh is a POSIX wrapper around install.py)
├── guard.py / porter.py                   # CLI entry points
├── .github/workflows/ci.yml               # 3 OS x Python 3.10-3.14, lint, trusted-boundary, release
├── .harness/manifest.json                 # Canonical manifest (checked by CI)
├── docs/
│   ├── adr/                               # Architecture Decision Records (ADR-0001 through ADR-0016)
│   └── benchmark-protocol.md              # 10-task real-project A/B quality benchmark & PreInvocation evaluation record
├── bin/                                   # agy-guard launchers (POSIX, .bat, .ps1)
├── installers/                            # PyInstaller build, Linux packages (.deb/.rpm/Arch), desktop entry
├── guard/                                 # Guard: os_adapter, environment, integrity, snapshot, lease,
│   │                                      #   notifier, approval, audit_log, doctor, paths, startup,
│   │                                      #   test_boundary, provenance, porter_bridge, upstream, plugins, cli, gui, tray
│   ├── plugin_assets/                     #   4 dual-theme 128x128 SVG logos for standalone plugin packs
│   ├── agy_hooks.py                       #   lazy CLI router & PEP 562 compatibility facade (ADR-0008, ADR-0010, ADR-0013, ADR-0015)
│   └── hooks/                             #   event- & tool-scoped lifecycle hooks: common, pre_invocation, pre_tool_use, _shell_guard, _swarm_guard, _mcp_guard, _write_guard, _workflow_ast, stop_gate
├── porter/                                # analyzer, sanitizer, frontmatter, manifest, net, archive, emitters/
├── scripts/
│   ├── build_plugins.py                   # Standalone Antigravity plugin pack builder, archiver & validator
│   ├── code_map.py                        # AST caller/dataflow/blast-radius map, runtime tracer & FTS5 search
│   ├── meta_audit.py                      # 7-pass harness self-audit (Rule 17)
│   └── verify_invariants.py               # Deterministic invariant scan
├── agents/                                # 10 auditor subagent definitions
├── skills/                                # 20 top-level skills + on-demand references/ & scripts/
├── tests/                                 # Hermetic unittest suite (884 tests)
└── templates/                             # ARCHITECTURE, DECISIONS, HANDOFF, MISTAKES, REPOSTATE, SECURITY_POSTURE, procoder.SKILL, vulkan.SKILL & config templates
```

Runtime state never lives in the repository: registry, baselines, leases, lock-mode records and the
upstream ledger are in `~/.local/state/antigravity-harness/`; snapshots and the installed runtime in
`~/.local/share/antigravity-harness/` (`XDG_STATE_HOME` / `XDG_DATA_HOME` are honoured).

---

## Quickstart & Installation

### Recommended: install from a source checkout (all platforms)

```bash
git clone https://github.com/hadbilen/antigravity-harness.git
cd antigravity-harness
python3 install.py          # Windows: python install.py   |   POSIX alternative: ./install.sh
```

The default **copy mode** installs real files into `~/.gemini/config` (writing the universal constitution to
`~/.gemini/config/rules/antigravity-constitution.md` with `trigger: always_on` so App, CLI, and IDE/Extensions
load one shared copy while backing up and retiring legacy `~/.gemini/config/GEMINI.md` and receipt-tracked
`MISTAKES.md`), copies the
Guard runtime to `~/.local/share/antigravity-harness/runtime`, writes `agy-guard` / `agy-porter` launchers
to `~/.local/bin` (Windows: `%LOCALAPPDATA%\Programs\antigravity-guard\*.cmd`), merges the `upstream-watchdog`
and `harness-gate` lifecycle hooks into `hooks.json` without dropping other hooks, repoints relocated skill
scripts in `mcp_config.json` (`RELOCATED_SKILL_SCRIPTS`) while retiring superseded consolidated skill directories, backs replaced files up **outside** the config tree
(together with snapshots, baselines and backups left inside it by 1.3.0 and earlier),
establishes the integrity baseline and locks the governance scope. Re-running it over a locked scope asks
a human to confirm. Options: `--plugins` (opt-in Hybrid Layout: 14 core skills + 4 OS-locked Antigravity Plugin Packs under `plugins/`), `--flat-skills` (explicit Flat Layout or lossless revert from Hybrid back to 20 canonical skills and restored `mcp_config.json` entries), `--link` (developer symlink mode, cannot be locked), `--binary` (`python3 install.py --binary [--sha256 <64-hex>]`, also installing
the checksum-verified standalone binary), `--no-lock`, `--enable-startup`, `--dry-run`, `--uninstall`
(`python3 install.py --uninstall` unlocks, removes only receipt-tracked harness files, installed plugin packs, and merged hook keys while preserving user-authored customizations and third-party plugins, and archives a backup).

### Opt-in Hybrid Plugin Layout (`--plugins`) and standalone plugin packs

Default `v2.4.0` installs use Flat Layout (all 20 canonical skills under `~/.gemini/config/skills/`). To deploy the 4 domain bundles as UI-toggleable, OS-locked Antigravity Plugin Packs while keeping the 14 core governance skills, 10 auditor subagents, constitution, and `agy-guard` locks managed from this repository:

```bash
# Activate Hybrid Layout from a source checkout (or via Linux package: agy-guard init --plugins)
python3 install.py --plugins

# Verify OS locks, SHA-256 baseline, diagnostics, and hybrid self-audit
agy-guard status
agy-guard verify
agy-guard doctor
agy-guard self-audit --strict

# Losslessly revert Hybrid Layout back to Flat Layout (restores retired global mcp_config.json keys)
python3 install.py --flat-skills
```

#### Standalone plugin packs (GitHub Releases)

Each release publishes 4 standalone-clean plugin packs (`.zip` + `.zip.sha256`) on [GitHub Releases](https://github.com/hadbilen/antigravity-harness/releases) that work in Antigravity without `agy-guard` or the full harness (each archive bundles a strict `v1/plugin.json`, dual-theme `128x128` SVG logo, MIT `LICENSE`, pack-scoped `THIRD_PARTY_NOTICES.md`, and `README.md` linking back to this repository):

| Pack (`dir`) | Display Name | Bundled Skills & Extras |
| :--- | :--- | :--- |
| `antislop` | **AntiSlop UI** | `antislop`, `vibecoder`, `DESIGN.md`, `contrast-mcp.py` (`antislop_contrast` MCP) |
| `rust-suite` | **Rust Suite** | `rustify`, `rust-harden`, `vulkan.SKILL.template.md` |
| `media-studio` | **Media Studio** | `media-studio`, `media_qc.py` (requires `ffmpeg`/`ffprobe` on `PATH`) |
| `game-engineering` | **Game Engineering** | `game-engineering` |

To install a standalone pack from GitHub Releases (or build all 4 locally from source):

```bash
# Verify checksum and extract into global ~/.gemini/config/plugins/ (or project .agents/plugins/)
sha256sum -c antislop-v2.4.0.zip.sha256
unzip antislop-v2.4.0.zip -d ~/.gemini/config/plugins/

# Build, archive, and offline-validate all 4 standalone packs from a source checkout
python3 scripts/build_plugins.py --out dist/plugins --validate --zip
```

> **Canonical Home:** Antigravity plugins cannot install `agy-guard`/`agy-porter` PATH binaries, OS-level read-only locks, or global constitutional governance (`ADR-0016`). Use the standalone `.zip` packs when you only need a single domain toolkit; use `python3 install.py --plugins` (or `agy-guard init --plugins`) from this repository for the full constitutional harness and write-protection boundary.

**`agy plugin` security boundary (`ADR-0016`):**
- The 4 harness plugin directories (`plugins/antislop`, `plugins/rust-suite`, `plugins/media-studio`, `plugins/game-engineering`) are OS-locked and FIM-monitored inside the `antigravity` `enforced` scope, while `~/.gemini/config/plugins/` stays writable for Marketplace and third-party plugins (such as `rea`).
- Toggling a harness pack in the Antigravity UI writes only to `~/.gemini/config/config.json` (never modifying files inside `plugins/<pack>/`); `PreInvocation` reads that state to suppress disabled plugin skill hints and `antislop_contrast` MCP hints, while `Stop` (`stop_gate.py`) resolves `check_ui_slop.py` from OS-locked `runtime/` (or `/usr/share/antigravity-harness` on Linux packages) independent of `config.json`.
- `PreToolUse` denies direct writes, glob/dot/command-substitution escapes, `git clone` into protected roots, and explicit archive extraction targeting `~/.gemini/config/plugins/` root or harness packs; gates directory drops (`cp -r/-R/-a`, `rsync`, `git clone`, `mv`, cwd `tar -x`/`unzip`) targeting `~/.gemini/config/plugins/<any>`, all `agy plugin (install|import)` commands, and `agy plugin (disable|uninstall)` commands targeting harness packs behind 3-sentence `force_ask` confirmation (leaving third-party `disable`/`uninstall` exempt).
- **Downgrade & MCP backup note:** Before downgrading a `--plugins` install back to `v2.3.0`, run `python3 install.py --flat-skills` (or `agy-guard init --flat-skills`) first so plugin seams are pruned and flat skills/MCP entries are restored; any custom `env` or extra CLI flags on retired `contrast-mcp.py` entries are preserved in the external pre-migration backup (`~/.local/state/antigravity-harness/backups/`).

### Linux packages and standalone binaries

Release assets (see [GitHub Releases](https://github.com/hadbilen/antigravity-harness/releases)) ship with a
`.sha256` file each (including standalone plugin pack `.zip` archives); verify before installing:

```bash
sha256sum -c antigravity-guard_2.4.0_amd64.deb.sha256
sudo apt install ./antigravity-guard_2.4.0_amd64.deb
agy-guard init              # bootstrap ~/.gemini/config, hooks, FIM baseline & lock from /usr/share/antigravity-harness (add --plugins for Hybrid Layout)
```

Before removing a Linux `.deb`, `.rpm`, or Arch system package, run `agy-guard init --uninstall` per user account to unlock `~/.gemini/config`, remove receipt-tracked harness files and merged hook keys while preserving user-authored customizations, and archive a backup. Binaries are built for `linux-x86_64`, `macos-arm64` and `windows-x86_64`; `python3 install.py --binary` (optionally pinned with `--sha256 <64-hex>`) downloads the matching one only if its SHA-256 checksum matches. On other platforms (e.g. FreeBSD) the Python runtime is used.

---

## Antigravity Guard (`agy-guard`) Usage

```bash
# Health check (and re-lock / establish a missing baseline)
agy-guard doctor --fix

# Protection, integrity and lease status
agy-guard status

# Lock the governance seams; verify integrity
agy-guard lock
agy-guard verify

# Maintenance: prefer a time-bounded lease (human approval, automatic relock)
agy-guard request-unlock --duration 120 --reason "update skills"
agy-guard lock-complete            # relock now; offers to accept the window's changes

# Permanent unlock and accepting the current state require human confirmation
agy-guard unlock
agy-guard rebaseline

# Snapshots
agy-guard snapshot create --label pre_experiment
agy-guard snapshot list
agy-guard snapshot restore --id <snapshot_id>

# Porter gate
agy-guard porter inspect https://example.com/some_rule.md
agy-guard porter stage ./custom_rule.md

# Upstream repositories and model/runtime drift (zero LLM tokens)
agy-guard upstream check
agy-guard upstream status
agy-guard upstream ack

# Other environments
agy-guard env detect --path ~/projects/my-app
agy-guard env list
agy-guard env policy <env_id> monitored # built-in global 'antigravity' always reloads as 'enforced'
agy-guard drift

# Test trust boundary and reproducibility
agy-guard test-boundary snapshot
agy-guard test-boundary verify --mode tdd
agy-guard test-boundary verify --base-ref origin/main
agy-guard test-boundary run-reproducible --cmd "pytest tests/test_core.py" --passes 2
agy-guard provenance generate

# Portable workspace verification tools (work from any external project cwd)
agy-guard code-map callers handle_request src/
agy-guard ui-slop index.html --mode utility
agy-guard synthetic-markers --profile technical README.md
agy-guard verify-invariants --all

# Boot sentinel, notifications, self-audit, GUI
agy-guard startup enable
agy-guard boot-check
agy-guard notify quiet
agy-guard self-audit --strict
agy-guard gui

# Upstream watchdog notice: show the reasons, then silence it once reviewed
python3 ~/.gemini/config/skills/upstream-auditor/scripts/upstream_watcher.py --status
python3 ~/.gemini/config/skills/upstream-auditor/scripts/upstream_watcher.py --ack
```

Administration commands exit with code `3` when no human confirmation was given.

### Emergency Hook Disable & Fail-Open Caveat

If a misbehaving hook blocks urgent recovery work, disable only the affected group in `~/.gemini/config/hooks.json`
rather than deleting the file or leaving the config tree permanently unlocked:

1. Open a short human-approved lease: `agy-guard request-unlock --duration 15 --reason "emergency hook bypass"`.
2. Add `"enabled": false` inside the target hook group (`"harness-gate"` or `"upstream-watchdog"`) in `~/.gemini/config/hooks.json`.
3. Run `agy-guard doctor` to confirm the disabled hook state is visible as an explicit warning.
4. Once recovery finishes, remove `"enabled": false` (or re-run `python3 install.py`) and close the lease with `agy-guard lock-complete`.

> **Fail-Open Host Semantics:** Official Antigravity plugin documentation
> (`https://antigravity.google/docs/build-plugins`) specifies that
> non-zero hook exit codes are logged and ignored (**fail-open**), in contrast to third-party summaries that
> describe hooks as fail-closed. `guard/agy_hooks.py` therefore exits `0` and returns explicit JSON decisions
> (`deny`, `force_ask`, `allow`, `block`) on stdout. Run `agy-guard doctor` after Python or Antigravity upgrades
> to verify every hook executable and script path exists on disk so missing binaries cannot silently fall open.

---

## Porter CLI (`porter.py` / `agy-porter`) Usage

```bash
# Read-only suitability inspection (a .zip is inspected without extracting anything)
python3 porter.py inspect path/to/external-rule.mdc
python3 porter.py inspect path/to/rule-bundle.zip --json

# Import into THIS repository (review with git diff, then deploy with install.py)
python3 porter.py import path/to/rules.md --as-skill test-skill --dry-run
python3 porter.py import path/to/tailwind-rules.mdc --as-skill tailwind-v4

# Export (refuses to overwrite existing files unless --force)
python3 porter.py export --target claude --out ./export/claude
python3 porter.py export --target all --out ./export/

# Regenerate / check the canonical manifest
python3 porter.py manifest
python3 porter.py manifest --check
```

---

## Verification & Continuous Integration

CI runs on Linux, macOS and Windows with Python 3.10–3.14 (actions pinned to commit SHAs, Python build tools
pinned to exact versions; apt packages come from the runner image). Pull requests additionally run the
**candidate code against the base branch's own tests and graders** in a clean worktree, and verify that
existing tests were only extended, never weakened. Workflow runs for pull requests from forks wait for the
maintainer's approval, and their result is advisory (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

```bash
# Hermetic unit test suite (884 tests)
python3 -m unittest discover -s tests -v

# Harness self-audit (Rule 17); --strict also fails on warnings
python3 scripts/meta_audit.py --all --strict

# Deterministic invariant scan / diff check
python3 scripts/verify_invariants.py --all
python3 scripts/verify_invariants.py --diff --mode tdd --base-ref origin/main

# Standalone plugin pack build, archive & offline validation
python3 scripts/build_plugins.py --out /tmp/agy-plugins-smoke --validate --zip
```

---

## Dependencies

The Guard, Porter and grader code uses only the Python standard library (3.10+). Optional extras: `tkinter`
for the GUI, `pystray` + `Pillow` or PyGObject/AppIndicator for the tray icon, PyYAML (used alongside Porter's
frontmatter parser by the self-audit when present), `nodejs (>= 18)` (for `skills/harness/references/unlazy/scripts/*.mjs` gate and dispatch helpers),
and `ffmpeg` (`>= 5.1` recommended; automatic `-vsync` fallback on older builds) / `ffprobe` (for `media-studio` `media_qc.py` signal and container verification). The standalone binaries bundle `pystray` and `Pillow` via PyInstaller.

---

## Community Lineage & Acknowledgments

Grounded in prompt-failure post-mortems from [r/ChatGPTCoding](https://www.reddit.com/r/ChatGPTCoding/),
[r/ClaudeAI](https://www.reddit.com/r/ClaudeAI/) and [r/LocalLLaMA](https://www.reddit.com/r/LocalLLaMA/),
and on these open-source projects (licenses in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)):
`miqdadbadjuber/anti-slop`, `JayPokale/Chisle`, `Leonxlnx/unlazy`, `azrtydxb/procoder`,
`bendrape1-byte/silk-design`, `affaan-m/everything-claude-code`, `mattpocock/skills`, `erkamyaman/rust-anything`.

---

## Contributing & License

Suggestions and pull requests are welcome; the maintainer decides what is merged (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)). Every change must pass `python3 -m unittest discover -s tests`,
`python3 scripts/meta_audit.py --all --strict` and `python3 porter.py manifest --check`. Release tags are never
moved and release assets are never replaced. MIT licensed.

Licensed under the [MIT License](LICENSE).
