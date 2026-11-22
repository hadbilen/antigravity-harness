# ADR-0013: Multi-Agent Hook Isolation, Orchestrator Rule 17 Calibration, Lazy Hook Modularization, Portable Script Dispatch, and OS-Level Guard Hardening

**Date**: 2026-11-22
**Status**: accepted
**Amends**: [ADR-0005](0005-antigravity-v2-32-compatibility-and-hook-modernization.md) (partial: `SessionStart` watchdog & 15th builtin skill `swarm_pane`), [ADR-0007](0007-swarm-topology-hook-coverage-and-placeholder-hardening.md) (partial: workspace-scoped `swarm_workers.json`, `@#channel` tracking, `A1` Orchestrator Rule 17 policy & default-model verifiers), [ADR-0008](0008-agy-hooks-lazy-package-modularization.md) (partial: lazy tool-scoped submodules under `guard/hooks/pre_tool_use.py` & `inv > 1` fast path), [ADR-0009](0009-cognitive-slimming-skill-consolidation-and-midturn-hook-silence.md) (partial: `skills/harness/SKILL.md <= 28 KB` progressive disclosure & `meta_audit.py` `SKILL.md > 40 KB` check), [ADR-0010](0010-lazy-guard-init-ast-inline-shield-and-reactive-wakeup-continuity.md) (partial: `A2` `run_workflow` AST & `artifactDirectoryPath/scratch/` `ScriptPath` calibration)
**Deciders**: Human Operator (`tugay`), Antigravity Harness Maintainers

## Context

The 2026-11-21 full-stack technical evaluation of `antigravity-harness`, Antigravity Guard, and Antigravity Orchestrator/Swarm integration surfaced six operational defect clusters:

1. **Multi-agent hook contention and shell false positives:** Concurrent Swarm conversations tripped false circuit-breaker strikes in `stop_gate.py` on pre-existing dirty test files, clobbered each other's `flight_recorder.json` in-flight state in `pre_invocation.py`, injected recovery banners into auxiliary roles, and flagged benign file-descriptor or null-sink shell redirections (`2>/dev/null`, `>/dev/null`, `2>&1`) as file mutations.
2. **Orchestrator, Swarm, and `run_workflow` seam friction:** Pro-class Orchestrator models lacked a differentiated `force_ask` tier between approved flagship writers and Flash workers; Swarm atomic `mv` operations inside the active conversation's `artifactDirectoryPath` and `run_workflow` `ScriptPath` under `artifactDirectoryPath/scratch/` triggered false blocks; `swarm_workers.json` failed to share downgraded worker state across conversations; `@#channel` mentions were ignored; and `_workflow_ast.py` rejected dynamic `call_tool(...)` fan-out and helper functions returning `agent(...)`.
3. **Ecosystem drift and synchronous hook latency:** Antigravity's 15th builtin skill (`swarm_pane`), `swarm_monitor` (`IsDaemon: true`, `CronExpression: "*/3 * * * *"`), and default-model `native_swarm` policies drifted from harness docs; `upstream-watchdog` ran redundantly on every `PreInvocation` turn instead of once on `SessionStart`; `guard/hooks/pre_tool_use.py` loaded 7,838 lines synchronously on every tool call; and `skills/harness/SKILL.md` exceeded Antigravity's 46,080-byte single-read cap.
4. **External-project script portability:** Skill and agent instructions invoked repo-relative `./scripts/...` and `python3 skills/...` commands that fail in external user workspaces without an `antigravity-harness` checkout.
5. **OS-level `agy-guard` edge-case bugs:** `guard/startup.py` locked the root `~/.gemini/config` directory in fallback mode despite `protect_root=False` and relied solely on deprecated macOS `launchctl load`/`unload`; `guard/os_adapter.py` had an unreachable localized/SID fallback in `_windows_dir_denied()` and unhardened bare `USERNAME` formatting; `guard/lease.py` skipped process-identity verification before signaling watcher PIDs on macOS and Windows; and `guard/tray.py` plus `installers/build_binaries.py` lacked Linux GTK+Tk failure isolation and Wayland fallback diagnostics.

The decision-driving constraint is **eliminating all six defect clusters while preserving zero weakening of `GEMINI.md` Rules 1-18, 100% `guard/agy_hooks.py` facade parity, `21` top-level skills within the `10,800`-byte aggregate frontmatter cap, and full hermetic test isolation**.

## Decision

We adopt five coordinated architectural changes across hooks, skills, Guard CLI/installer, and OS adapters:

1. **Per-Conversation Hook Isolation, Benign Redirection Exclusion, `A1` Orchestrator Policy, and `A2` `run_workflow` Calibration (`W1`):**
   - Scope `stop_gate.py` dirty test checks by per-conversation write provenance (`has_session_writes` and touched paths) while keeping single-session unlogged or shell test edits fail-closed, and freeze circuit-breaker strikes once `tripped == True`.
   - Key `flight_recorder.json` per `(ws_key, conv_id)` with legacy migration, 1,800-second stale-age crash detection, and auxiliary-role recovery silence (`monitor`, `narrator`, `verifier`).
   - Strip quote-aware benign FD/null redirections (`2>/dev/null`, `>/dev/null`, `2>&1`, etc.) in `_shell_guard.py` before evaluating shell mutation indicators while keeping real file redirections and compound mutations blocked.
   - Enforce user-approved `A1` Rule 17 policy: `["gemini-4-neon-xhigh", "gemini-4-carbon-high"]` -> `allow`, Pro-class Orchestrator models -> `force_ask`, Flash workers -> `deny` with actionable guidance.
   - Permit same-conversation `artifactDirectoryPath` atomic `mv` (rejecting symlinks, `..`, and sibling conversations), scope `swarm_workers.json` by workspace/worktree, track `@#channel` / `action:"channel"`, and enforce `A2` in `_workflow_ast.py` (active `scratch/` `ScriptPath`, dynamic `call_tool` fan-out, and helper `agent()` passing/returns, while keeping `subprocess`, direct filesystem writes, network exfiltration, and dunder escapes strictly `deny`).
2. **Ecosystem Alignment, `SessionStart` Watchdog (`A3`), Lazy Tool-Scoped Hooks, and Progressive Disclosure (`W2`):**
   - Register `swarm_pane` as the 15th builtin skill across `upstream_state.seed.json`, `guard/upstream.py`, `upstream_watcher.py`, and `upstream-auditor/SKILL.md`; align `harness`, `marathon`, `dispatch`, and `model-calibration-matrix.md` with `swarm_pane`, `swarm_monitor` (`IsDaemon: true`, `*/3 * * * *`), `native_swarm` default-model verifiers, and `A1`.
   - Migrate `upstream-watchdog` from `PreInvocation` to `SessionStart` across `hooks.json`, `install.py`, `guard/doctor.py`, `guard/cli.py`, `scripts/meta_audit.py`, and `upstream_watcher.py`.
   - Add a sound `invocationNum > 1` fast path in `guard/agy_hooks.py` (`<= 350` lines) and decompose `guard/hooks/pre_tool_use.py` into four lazy tool-scoped submodules (`_shell_guard.py`, `_swarm_guard.py`, `_mcp_guard.py`, `_write_guard.py`) with PEP 562 `__getattr__` facade parity, cutting median cold-start latency below `100 ms` (`pre-invocation inv=2`) and `110 ms` (`pre-tool-use edit_file`).
   - Split `skills/harness/SKILL.md` (`<= 28 KB`) via progressive disclosure into `skills/harness/references/{context-and-artifacts,multi-agent-orchestration}.md` and enforce a `SKILL.md > 40 KB` warning in `scripts/meta_audit.py`.
3. **CWD-Independent Portable Script Dispatch (`W3`):**
   - Expose four passthrough `agy-guard` subcommands (`code-map`, `ui-slop`, `synthetic-markers`, `verify-invariants`) in `guard/cli.py` resolving scripts across repo root, canonical `~/.gemini/config/`, `data_dir()/runtime`, frozen PyInstaller `_MEIPASS`, and system package paths regardless of caller `cwd`.
   - Bundle `check_ui_slop.py` and `check_synthetic_markers.py` alongside `scripts/` in `install.py` runtime installs and `installers/build_binaries.py` standalone packages, enforce Rule 12 `--authorize` blocking for `agy-guard verify-invariants` and external-script AST shielding for `agy-guard code-map trace` in `_shell_guard.py`, and migrate repo-relative invocations across skills and agents to portable `agy-guard` / `~/.gemini/config/` commands.
4. **OS-Level Antigravity Guard Hardening (`W3`):**
   - `guard/startup.py`: honor `self.environment.protect_root` in `execute_boot_check()` fallback (never locking `~/.gemini/config` when `protect_root=False`) and use macOS `launchctl bootstrap`/`bootout` with graceful legacy `load`/`unload` fallback.
   - `guard/os_adapter.py`: harden `USERDOMAIN\USERNAME` principal formatting (with `*S-1-1-0` empty-user fallback), parse only post-`:(` ACE segments in `_windows_dir_denied()` to eliminate path-prefix spoofing, evaluate localized/SID deny and `(N)` ACEs when English `(DENY)` is absent, and keep the self-cleaning write-probe fallback reachable for unknown locales.
   - `guard/lease.py`: verify `"lease-tick"` process identity via `/proc` (Linux), `ps` (macOS/POSIX), and PowerShell `Get-CimInstance` / `wmic` fallback (Windows) in `_terminate_watcher_pid()` before sending `SIGTERM`.
   - `guard/tray.py` & `installers/build_binaries.py`: add Linux display-session classification (headless, Wayland, X11, frozen, `AGY_GUARD_NO_TRAY`), `Gtk.init_check()` preflight and exception isolation in `AyatanaAdapter`/`PystrayAdapter`, structured Wayland fallback diagnostics (`fallback_reason` + `tray.fallback` audit log), and `--exclude-module gi` in Linux onefile PyInstaller builds to avoid GTK+Tk library collisions.

## Alternatives Considered

### Alternative 1: Relax Rule 17 to Auto-Allow Pro-Class Orchestrators and Strip Static `run_workflow` AST Checks
- **Pros**: Eliminates all human prompts during Orchestrator governance runs and reduces AST maintenance in `_workflow_ast.py`.
- **Cons**: Weakens `GEMINI.md` Rule 17 by letting non-flagship orchestrator tiers rewrite governance files unattended, and opens direct `subprocess` / filesystem exfiltration channels inside `run_workflow` scripts.
- **Why not**: Rejected on security grounds; `A1` (`force_ask` for Pro-class Orchestrators, `deny` for Flash workers) and `A2` (targeted `scratch/` `ScriptPath` + dynamic `call_tool` + helper `agent()` while keeping `subprocess`/FS/dunder strictly `deny`) remove workflow friction without eroding safety boundaries.

### Alternative 2: Copy `scripts/` Directly Into `~/.gemini/config/scripts/` Instead of Exposing `agy-guard` Subcommands
- **Pros**: Allows `python3 ~/.gemini/config/scripts/code_map.py` without modifying `guard/cli.py`.
- **Cons**: Breaks `scripts/meta_audit.py`'s `is_split_layout` detection (`not (repo_root / "scripts").is_dir()`) and `install.py`'s `move_legacy_runtime_links()` boundary, mixes executable code into the user's governance config tree, and still fails when agents omit the home prefix.
- **Why not**: Rejected on architecture and split-layout invariants; exposing cwd-independent `agy-guard` subcommands (`code-map`, `ui-slop`, `synthetic-markers`, `verify-invariants`) plus canonical `~/.gemini/config/skills/antislop/scripts/` fallbacks keeps code isolated in `runtime` while working identically from any workspace.

### Alternative 3: Keep `guard/hooks/pre_tool_use.py` Monolithic and Move Only `upstream-watchdog`
- **Pros**: Zero module-splitting complexity and no PEP 562 facade proxy table in `pre_tool_use.py`.
- **Cons**: Every `edit_file`, `read_file`, or `swarm` hook invocation would still import and compile 7,800+ lines of shell and workflow AST scanners, leaving `pre-tool-use (edit_file)` above the `110 ms` target.
- **Why not**: Rejected on measured latency (`132.2 ms -> 86.7 ms` median after lazy split); tool-scoped lazy submodules achieve the latency target while maintaining 100% `ADR-0008`/`ADR-0010` facade compatibility.

## Consequences

### Positive
- Concurrent Swarm and multi-conversation sessions run without false circuit-breaker lockouts, `flight_recorder.json` collisions, or benign shell-redirection blocks.
- Hook cold-start latency drops sharply (`pre-invocation inv=2`: `209.5 -> 68.9 ms`; `pre-tool-use edit_file`: `132.2 -> 86.7 ms`; per-turn `upstream-watchdog` cost eliminated via `SessionStart`), and `skills/harness/SKILL.md` fits comfortably in a single bounded read (`<= 28 KB`).
- Agents working in any external repository invoke `agy-guard code-map`, `agy-guard ui-slop`, `agy-guard synthetic-markers`, and `agy-guard verify-invariants` reliably without checkout-relative paths, while `guard/hooks/_shell_guard.py` preserves Rule 12 `--authorize` and `code-map trace` protection.
- Linux, macOS, and Windows `agy-guard` installations avoid root-directory lockouts (`protect_root=False`), deprecated `launchctl` failures, localized Windows ACL false negatives, cross-platform PID-reuse termination hazards, and Linux GTK+Tk/Wayland tray crashes.

### Negative
- `agy-guard` public subcommands increase from `21` to `25`, requiring synced documentation in `guard.py`, `README.md`, and Linux shell completion scripts.
- Four additional lazy hook submodules (`_shell_guard.py`, `_swarm_guard.py`, `_mcp_guard.py`, `_write_guard.py`) must remain acyclic and synchronized with `guard/hooks/pre_tool_use.py`'s `__getattr__` facade map.

### Risks
- **New `agy-guard` subcommands bypassing `PreToolUse` shell rules:** Mitigated by extending `_GUARD_ADMIN_BODY` (`verify-invariants --authorize`) and `_inspect_external_script_command` (`agy-guard code-map trace <script>`) in `guard/hooks/_shell_guard.py` with dedicated negative tests.
- **Platform-specific OS calls untestable natively on a Linux-only CI runner:** Mitigated by strict hermetic unit and mock-boundary tests for macOS `launchctl`/`ps`, Windows `icacls`/`powershell`/`wmic`, and Linux Wayland/GTK failure paths in `tests/test_adr0013_swarm_orchestrator_guard_hardening.py`, alongside multi-OS GitHub Actions CI.
