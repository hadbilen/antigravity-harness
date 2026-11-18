# Changelog

All notable changes to Antigravity Harness are documented in this file.

## [Unreleased]
- **Windows CI (`CRLF` `512 KiB` Parity & `file:` URI Hardening) and Linux CI `ffmpeg` Fast-Path (`guard/hooks/common.py`, `guard/hooks/pre_tool_use.py`, `guard/hooks/_workflow_ast.py`, `guard/agy_hooks.py`, `.github/workflows/ci.yml`, `tests/test_windows_ci_v220_remediation.py`, `720` total tests):**
  - Aligned `_read_bounded_markdown_checked` and `_read_bounded_markdown` in `guard/hooks/common.py` from `256 KiB` to the `512 KiB` (`524,288`-byte) governance ledger ceiling enforced by `guard/hooks/pre_tool_use.py` (with `os.lstat`, `O_NONBLOCK`, and `stat.S_ISREG` FIFO/ELOOP safety), preventing Windows `CRLF` (`\r\n`) expansion on `200 KiB`-line `HANDOFF.md` files from truncating trailing `[IN-PROGRESS]` / `Campaign ID` headers during `PreInvocation`.
  - Extended `_parse_file_uri` (RFC 8089 `file:/...`, relative `file:...`, WHATWG `C|`, loopback/device `127.0.0.1/C$` & `\\.\C:`, and `wsl.localhost`) and `_canonicalize_check_path` across `guard/hooks/pre_tool_use.py` and `guard/hooks/_workflow_ast.py`, resolving Windows Python `3.12` `WinError 123` (`Path.resolve` on embedded `file:\C:\`) in `flight_recorder.json` updates and closing percent-encoded, single-slash, Win32 trailing-dot, MCP, and `run_workflow` `.agents/hooks.json` / `tasks.md` / Rule 17 gating seams (`tests/test_windows_ci_v220_remediation.py`; `713` -> `720` tests).
  - Guarded `Install ffmpeg (Linux)` in `.github/workflows/ci.yml` with the `ffmpeg`/`ffprobe` + `libvorbis`/`libwebp` precheck, `DEBIAN_FRONTEND=noninteractive`, `--no-install-recommends -o Acquire::Retries=3`, post-install encoder verification, and `SIGPIPE`-safe parameter-expansion banner printing, avoiding 20-minute timeouts on throttled Ubuntu archive mirrors.

## [2.2.0] - 2026-11-18
Opt-in governance templates (`ARCHITECTURE.md` and `SECURITY_POSTURE.md`), intra-Rust `rust-harden` capability package (`21` top-level skills), read-only `simplicity-auditor` subagent (`10` auditor subagents; `ADR-0011`), `marathon` `Campaign ID` session isolation with clean `[COMPLETE]` `tasks.md` stale-reset gating, and `713` hermetic unit tests.

- **Governance Templates (`ARCHITECTURE.md`, `SECURITY_POSTURE.md`), `rust-harden` Skill Package & `simplicity-auditor` Subagent (`ADR-0011`, `templates/`, `skills/rust-harden/`, `agents/`, `skills/{harness,audit,rustify}/`, `porter/emitters/cursor.py`, `scripts/meta_audit.py`, `guard/hooks/`, `tests/test_governance_rust_harden_and_simplicity.py`):**
  - Added portable opt-in templates `templates/ARCHITECTURE.template.md` (`<= 150`-line current-state topology map forbidding volatile directory trees and `:L<n>` line numbers) and `templates/SECURITY_POSTURE.template.md` (separating non-public `[ENFORCED]` code+test controls and `Release Blocker` `` `[REQUIRED — UNVERIFIED]` `` controls from public root `SECURITY.md` disclosure tabs), wired into `skills/harness/SKILL.md` planning, `skills/audit/SKILL.md` Phase 0.B grounding, `scripts/meta_audit.py` `KNOWN_EXTERNAL_MD`, and all Porter export targets.
  - Added `skills/rust-harden/` (`SKILL.md`, `references/async-and-userspace.md`, `references/kernel-and-unsafe.md`; `21`st top-level skill within the `10,800`-byte aggregate frontmatter ceiling) for intra-Rust ownership/`.clone()` debt cleanup, production `.unwrap()` / `.expect()` removal, crate-tiered `[lints.rust]` vs. `[lints.clippy]` separation, `--internal` (signature-preserving default) vs. `--contract` (`Expand -> Migrate -> Contract` `#[must_use] Result<T, E>` / `newtype` / `typestate`) modes, `tokio::select!` cancellation & pre-runtime POSIX privilege drop, and `#![no_std]` / Framekernel / IRQ-spinlock / `UserSlice` / DMA `Drop` / `loom` & `kani` verification, with mutual routing boundaries against `skills/rustify/SKILL.md` and Cursor `**/*.rs, **/Cargo.toml` glob parity.
  - Added read-only `agents/simplicity-auditor.md` (`10`th auditor subagent, exported to Claude Code with `tools: Read, Grep, Glob` and enforced in `_READONLY_SUBAGENT_TYPES`, `ECOSYSTEM_ROUTING_HINTS`, and Tier 2/3 Pre-flight Gates) auditing `GEMINI.md` Rule 4 (`YAGNI`), Rule 18 (`Surgical Changes & Reuse`), and the 7-Rung Efficiency Ladder (`>= 3` call sites or `<= +5` caller lines with explicit `game-engineering` hot-loop and `unsafe`/FFI/`newtype`/`typestate` soundness carve-outs), and extended `agents/silent-failure-hunter.md` and `agents/security-boundary-verifier.md` with Rust outcome-discarding and systems-memory boundary checks.
- **Marathon `Campaign ID` Isolation, Safe `PreToolUse` Stale-Reset Gate & `PreInvocation` Anti-Merge Continuity (`templates/HANDOFF.template.md`, `skills/harness/references/marathon.md`, `guard/hooks/{common,pre_invocation,pre_tool_use,_workflow_ast}.py`, `guard/agy_hooks.py`, `MISTAKES.md`, `tests/test_marathon_campaign_isolation.py`, `713` total tests):**
  - Added mandatory `Campaign ID` (`YYYY-MM-DD-<topic-slug>`), `[Campaign: <id> | Window <k>/<N>]` prompt headers, `tasks.md`-before-`HANDOFF.md` reset ordering, and the hard cross-task reset invariant in `templates/HANDOFF.template.md` and `skills/harness/references/marathon.md` prohibiting `Wn+1` / `AC-(M+1)` appends once `HANDOFF.md` reaches `Status: [COMPLETE]` or when an unrelated task begins.
  - Updated `_write_mutates_authorized_test_section` in `guard/hooks/pre_tool_use.py` (paired with Unicode-safe `_extract_normalized_auth_section` in `common.py` and multi-write workflow checks in `_workflow_ast.py`) to allow resetting `tasks.md` to an empty `## Authorized Test Modifications` section without `force_ask` strictly when `<workspace>/HANDOFF.md` is `[COMPLETE]` (or absent) and `git --literal-pathspecs status --porcelain`, `git ls-files -v`, bidirectional linked-worktree checks, and `TestBoundaryGuard` snapshots confirm zero uncommitted or un-rebaselined changes across prior authorized tests, while keeping all new test authorizations (`GEMINI.md` Rule 9), dual-key/cross-chunk/workflow-multi-write payloads, and dirty/`[IN-PROGRESS]` states fail-closed (`force_ask`).
  - Updated `_detect_workspace_recovery_hint` in `guard/hooks/pre_invocation.py` (`O(N)` BOM/bullet-safe `Campaign ID`, `Status`, `Commit`, and `[ ] NEXT` row parsing with superseding single-window `tasks.md` precedence) to surface active `Campaign ID` metadata and explicit new-task reset instructions on stale or `HEAD`-advanced ledgers while staying silent on clean `[COMPLETE]` workspaces, expanding the hermetic suite from `697` to `713` unit tests (`+16` tests across `tests/test_governance_rust_harden_and_simplicity.py` and `tests/test_marathon_campaign_isolation.py`).

## [2.1.2] - 2026-11-16
PEP 562 lazy `guard` package initialization (`-49.8%` `PreToolUse` and `-58.6%` `PreInvocation` subprocess cold-start latency), unified `ast.parse` pure read-only Python inline/heredoc Governance Shield with Windows `CommandLineToArgvW` / `8.3` drive-path parity (`ADR-0010`), reactive background-task and subagent wakeup continuity, static + runtime hermetic test isolation (`697` tests), and multi-model `MODEL_PLACEHOLDER_*` flagship mapping.

- **PEP 562 Lazy `guard` Init, Unified Read-Only Python AST Inline Shield, Reactive Wakeup Continuity, Hermetic Test Gate & Multi-Model Placeholder Mapping (`ADR-0010`, `guard/__init__.py`, `guard/agy_hooks.py`, `guard/hooks/`, `guard/upstream.py`, `guard/doctor.py`, `skills/upstream-auditor/`, `skills/harness/SKILL.md`, `scripts/meta_audit.py`, `tests/test_v212_evaluation_remediation.py`, `697` total tests):**
  - Converted `guard/__init__.py` to PEP 562 lazy `__getattr__` + `__dir__` exports (`0` eager non-hook `guard.*` loads on hook startup), converted non-Pass-7 module-level regexes in `guard/hooks/{common,pre_invocation,pre_tool_use}.py` into `_LazyRegex`, cached root-boundary regexes in `_command_mutates_governance` via `functools.lru_cache`, and extracted `run_workflow` AST verification into on-demand `guard/hooks/_workflow_ast.py` (`<= 350`-line facade and `52/52` `PINNED_EXTERNAL_ATTRIBUTES` preserved), reducing `N=5` median subprocess cold-start latency by `49.8%` (`pre-tool-use`) and `58.6%` (`pre-invocation`).
  - Replaced asymmetric inline/heredoc interpreter checks in `guard/hooks/pre_tool_use.py` with a unified `ast.parse` pure read-only Python subset allowlist permitting verified read-only `python3 -c` / `<<'EOF'` diagnostics without `"in_flight"` false positives while failing closed (`"deny"`) on `touch`, `truncate`, `FileIO`, `sqlite3`, `tarfile`, `zipfile`, `operator`, `functools`, `getattr`, dynamic imports, shell expansions, and non-Python `-e`/`<<` interpreters targeting protected governance roots.
  - Preserved `is_mid_turn = True` on `invocationNum == 1` reactive background-task/subagent wakeups (`has_tx and tx_mid_turn`) in `guard/hooks/pre_invocation.py` without regressing `ADR-0009` post-crash `USER_INPUT` recovery, and updated `_detect_transcript_tool_signals` to reset `consec_build_fails` on clean `exit 0` shell steps while excluding shell `126`/`127` exits and short (`<= 25`-line) non-compiler CLI statuses lacking compiler error markers.
  - Added pure-additive `import hermetic` headers and `TestPorterSanitizerNewPatterns` `setUp`/`tearDown` isolation across `tests/test_{agy_hooks,code_map,media_studio,rustify_and_codemap}.py` (`0` removed test lines), enforced top-level `hermetic` import presence and ordering statically in `scripts/meta_audit.py` Pass 1, wired backward-compatible `known_placeholder_models` (`MODEL_PLACEHOLDER_M417` -> `Gemini 4 Argon (High)`, `MODEL_PLACEHOLDER_M427` -> `Gemini 4 Carbon (High)`, `MODEL_PLACEHOLDER_M528` -> `Gemini 4 Hydrogen (XHigh)`) across `upstream_state.seed.json`, `upstream_watcher.py`, `guard/upstream.py`, `guard/doctor.py`, and `_seed_placeholder_diagnostic` (keeping unknown `MODEL_PLACEHOLDER_*` IDs fail-closed on `force_ask`), documented `agy-guard upstream status` / `ack` in `README.md`, and condensed duplicated domain summaries in `skills/harness/SKILL.md` §1 into compact pointer bullets.

## [2.1.1] - 2026-11-16
Cross-platform CI/release hardening (`ubuntu-24.04`, `macos-15`, `windows-2022`), Windows path / `file://` URI / `guard.log` handle & `8.3` short-path fixes, PyInstaller frozen `guard.hooks` package resolution, and `681` hermetic unit tests.

- **Cross-Platform CI Matrix & Release Pipeline (`ci.yml`, `skills/media-studio/scripts/media_qc.py`):**
  - Migrated macOS matrix runners (`test` and `build-binaries`) from retired `macos-14` to `macos-15` (`arm64`) and provisioned `ffmpeg`/`ffprobe` across Linux (`apt-get`), macOS (keg-only `ffmpeg-full` on `$GITHUB_PATH` for `libvorbis`/`libwebp` encoder parity under Homebrew FFmpeg 8+), Windows (`choco` + MSYS2 `pacman` fallback with explicit `$LASTEXITCODE` checks), and `trusted-boundary`.
  - Pinned UTF-8 (`errors="replace"`) subprocess stream decoding in `skills/media-studio/scripts/media_qc.py` (`_run_media_subprocess`) for Windows `cp1252` environments.
- **Windows Path, `file://` URI, Audit Handle & Init/MCP Hardening (`guard/audit_log.py`, `guard/hooks/pre_tool_use.py`, `guard/agy_hooks.py`, `guard/cli.py`, `guard/environment.py`, `guard/doctor.py`, `install.py`):**
  - Replaced persistent `RotatingFileHandler` descriptors in `guard/audit_log.py` with `_TransientRotatingFileHandler` (`RLock`-guarded, `0o600` rollover opener, immediate post-`emit` stream release, and transient recovery without latching `NullHandler`), eliminating Windows `PermissionError` (`WinError 32`) on temporary state cleanup.
  - Added token-anchored Windows drive normalization (`C:\...`), root-clamped `C:/..` path collapsing, shared `_parse_file_uri` (`file://C:\...`, `file://C:/...`, `file:///C:/...`, `%5c`/`%3A` unquoting, and `%00` null-byte rejection across `write_file` and MCP arguments), dual/escaped governance root spellings (`str`, `as_posix`, `\\`), Windows `%LOCALAPPDATA%\Programs\antigravity-guard` coverage, `.parent` / space-quoted `plugins` scrubbing guards, and backslash `rm`/`mv`/`.agents\hooks.json` shell checks in `guard/hooks/pre_tool_use.py` without weakening POSIX backslash/parameter-expansion obfuscation detection.
  - Preserved lexical `abspath` `--target` paths (Windows `8.3` short names & macOS `/var` symlinked ancestors) while rejecting symlinked `--target` roots and fixing `_uninstall_init_profile` template cleanup in `guard/cli.py`; added POSIX `/`-rooted `antigravity-harness` script repointing and `(OSError, RuntimeError, ValueError)` symlink-loop safety in `guard/environment.py`; kept `ensure_skill_script_permissions` directly unit-testable on Windows in `install.py`; normalized relative `.agents/hooks.json` collision warnings in `guard/doctor.py`; and added a PyInstaller `sys.frozen` PYZ fast-path in `guard/agy_hooks.py` (`_needs_synthetic_hooks_package`; `681` total tests).

## [2.1.0] - 2026-11-16
Constitutional slimming (`GEMINI.md` `< 6.5 KB`, `Rule 4: Simplicity First (YAGNI)`), `34 -> 20` top-level skill consolidation with automatic `mcp_config.json` script migration (`ADR-0009`), lazy event-scoped `guard/hooks/` modularization (`ADR-0008`), native Antigravity `v2.32.0` `systemMessage` and `swarm` / delegation hook coverage (`ADR-0005`, `ADR-0007`), linked-worktree `TestBoundaryGuard` support, and ecosystem routing + Rust `2024` / game / media / legacy modernization (`ADR-0006`; `680` hermetic tests).

- **Constitutional Slimming, `34 -> 20` Skill Consolidation, Automatic MCP Migration & Mid-Turn `PreInvocation` Silence (`ADR-0009`, `GEMINI.md`, `agents/*.md`, `skills/`, `guard/hooks/`, `install.py`, `guard/cli.py`, `guard/environment.py`, `scripts/meta_audit.py`, `680` total tests):**
  - Condensed always-on `GEMINI.md` below `6,500` UTF-8 bytes (`>= 63%` reduction) while preserving canonical `Rule 1..18` numbering and `Rule 15` `(a)`–`(h)` citations, elevated **`Rule 4: Simplicity First (YAGNI)`** across `GEMINI.md` and all `9` auditor subagents (`agents/*.md`), and removed the duplicate `Section 6` routing table.
  - Consolidated `14` sub-module and workflow-helper skills into on-demand `references/` and `scripts/` directories under `skills/antislop/`, `skills/harness/`, `skills/technical-writing/`, and `skills/audit/` (`20` top-level skills total), preserving 100% of scripts, assets, templates, `/slash` routing (`SKILL_HINTS` & `scripts/meta_audit.py` Pass 3 / Pass 7), and Porter suitability slugs (`porter/analyzer.py`).
  - Added shared `RELOCATED_SKILL_SCRIPTS` `mcp_config.json` repointing and stale consolidated skill-directory retirement across `install.py` (`migrate_mcp_config`) and `guard/cli.py` (`cmd_init`), preserving `0o600` secret file permissions and symlink/`..` traversal defenses.
  - Added bounded `transcriptPath` tail inspection in `guard/hooks/pre_invocation.py` so mid-turn tool continuations (even without `invocationNum`) stay silent without clearing `"in_flight"` recovery state—while still firing `[Harness Recovery & Continuity Gate]` after crashes on repeated short prompts—and prevented zero-match `grep`/`egrep`/`fgrep`/`rg`/`diff`/`cmp`/`test`/`[` exit codes `1`/`2` from escalating to `build-error-resolver`.
- **Event-Scoped Lazy Package Modularization of `guard/agy_hooks.py` into `guard/hooks/` & Fail-Closed Seam Hardening (`ADR-0008`, `guard/agy_hooks.py`, `guard/hooks/`, `scripts/meta_audit.py`, `scripts/verify_invariants.py`, `tests/test_agy_hooks_facade_parity.py`, `670` total tests):**
  - Split the `11,390`-line `guard/agy_hooks.py` monolith into a `347`-line lazy CLI dispatcher and uncached PEP 562 `__getattr__`/`__dir__`/`__all__` compatibility facade backed by an acyclic, event-scoped `guard/hooks/` package (`guard/hooks/__init__.py`, `guard/hooks/common.py`, `guard/hooks/pre_invocation.py`, `guard/hooks/pre_tool_use.py`, and `guard/hooks/stop_gate.py`) with per-instance `ContextVar` `_ACTIVE_FACADE` synthetic package bootstrap (including generator iteration binding and load-failure rollback) and dynamic `_facade_attr()` collaborator resolution, preserving `100%` observable behavior, top-level literal `PRE_TOOL_USE_MATCHER_TOOLS` AST parsing, Pass 7 `spec_from_file_location` routing checks, all `52` externally pinned attributes (`51` pre-existing plus `data_dir`), and all `17` facade-pinned seams with `0` edits to existing tests.
  - Hardened runtime fail-closed and contract boundaries surfaced by 7-auditor Mutual Falsification: preserved corrupt `flight_recorder.json` (`quarantine=False`) during `readOnly` `Stop` write-history checks (`_conversation_has_recorded_writes`), fixed intra-turn `invocationNum > 1` `PreInvocation` `transcriptPath` tuple unpacking for `build-error-resolver` routing, anchored `_SCANNER_EXEMPT_SUFFIXES` to exact root-relative harness-checkout paths in `guard/hooks/stop_gate.py` and `scripts/verify_invariants.py`, failed closed on corrupt `environments.json` (`deny`, non-quarantining) and `cmd_input_buffers.json` (`force_ask`) in `PreToolUse`, and added bounded `executionNum < 2` fail-closed `Stop` continuation if `stop_gate` fails to import at bootstrap.
  - Verified subprocess `sys.modules` lazy isolation (`PRE_TOOL_USE_MATCHER` loads `0` `guard.hooks.*` submodules; `pre-invocation`, `pre-tool-use`, and `stop` each load strictly `common` + their own lifecycle module), reducing paired `N=10` isolated `guard/agy_hooks.py` module import latency `236.10 ms -> 3.22 ms` (`-98.6%`), subprocess `python3 -c "import guard.agy_hooks"` `943.87 ms -> 244.33 ms` (`-74.1%`), and cold CLI wall time across `pre-tool-use` (`748.66 ms -> 462.80 ms`, `-38.2%`), `pre-invocation` (`703.10 ms -> 374.35 ms`, `-46.8%`), and `stop` (`733.71 ms -> 354.33 ms`, `-51.7%`).
  - Extended `scripts/meta_audit.py` Pass 2 (`pass2_cross_references`) `Subagent` reference and submodule presence verification across `guard/hooks/*.py` alongside `guard/agy_hooks.py`, hardened Pass 7 (`pass7_trigger_specificity`) against swallowed lazy `AttributeError`s, and added `tests/test_agy_hooks_facade_parity.py` (`18` tests).
- **REA (`morluto/rea` / `rea-agents`) `6.7.0` → `6.9.0` Synchronization (`skills/upstream-auditor/upstream_state.seed.json`, `guard/upstream.py`, `skills/upstream-auditor/SKILL.md`):**
  - Synchronized `morluto/rea` release tracking to `rea-agents-6.9.0` (`255` Model Context Protocol tools, verified on isolated SHA-256-pinned Node.js `v24.22.3` with `0` constitutional sanitizer findings across all `9` bundled `reverse-engineer-anything` skill files).
- **Pre-Code Plan Red-Teaming (You Aren't Gonna Need It — `YAGNI` Brake), Untracked Subagent Diff Contracts, Production Micro-Safeguards & Shared Imperative `or` Negation (`skills/harness/SKILL.md`, `skills/audit/SKILL.md`, `skills/security-review/SKILL.md`, `porter/sanitizer.py`, `tests/test_porter_shared_negation.py`, `652` total tests):**
  - Added the fresh-context Tier 3 **Pre-Code Plan Gate** (`specification-gap-auditor` / `consistency-auditor` with an explicit `YAGNI` Brake against scope inflation), multi-service/monorepo target verification, deterministic code arithmetic, and the standalone **Branch Finishing Decision Gate** in `skills/harness/SKILL.md`.
  - Paired `git diff HEAD` / `git diff <ref>...HEAD` with bounded non-secret `git ls-files --others --exclude-standard` inspection across `skills/harness/SKILL.md` (`§2`, `§3.B Step 4a`, `§5.B`) and `skills/audit/SKILL.md` (`§4 Mode 3`, `§7`) so newly created untracked files are never omitted from delta audits or `read-only` subagent review bundles, and added caller/tenant-scoped tool authorization and password-hashing cost floors in `skills/security-review/SKILL.md` (`§4`).
  - Refined `porter/sanitizer.py` (`_classify`) to classify binary comma-free shared imperative prohibitions across bare `or` (such as `"- Never weaken assertions or delete tests to make the suite pass."`) as `PROHIBITED` without relaxing comma-separated, `and`-joined, passive, modal-reset, interrogative, permissive, or quoted `UNCERTAIN` / `AFFIRMATIVE` safeguards (`tests/test_porter_shared_negation.py`; `650` -> `652` tests).
- **Swarm Role Alignment, `PreToolUse` Hook Coverage, Model Placeholder Gate & Linked-Worktree Hardening (`ADR-0007`):**
  - **Swarm & Role Calibration (`skills/harness/SKILL.md`, `skills/marathon/SKILL.md`, `skills/unlazy/references/dispatch.md`, `skills/upstream-auditor/`):** Standardized Swarm Execution Topology (`workspace:"share"`), Swarm vs. `unlazy` vs. `marathon` decision criteria, 3-adapter dispatch contracts (`invoke_subagent`, `swarm`, `run_workflow`), role-aware calibration (`Orchestrator` / `Author` / `Verifier` / `Fast` + `Target Role` ledger column), and retained root `GEMINI.md` at `17,920` bytes (`<= 20,000`-byte ceiling).
  - **Expanded `PreToolUse` & Workflow Swarm Ledger (`guard/agy_hooks.py`, `hooks.json`):** Added `post_message`, `send_message`, `define_subagent`, and `schedule` to `PRE_TOOL_USE_MATCHER_TOOLS` and `hooks.json`; added `_handle_post_message_pre_tool_use`, `_handle_send_message_pre_tool_use`, `_handle_define_subagent_pre_tool_use`, `_handle_schedule_pre_tool_use` (with strict boolean `IsDaemon`/`isDaemon`/`is_daemon` and `CronExpression` validation), sharded `fork:` downgrade inheritance, persistent `quarantine=False` `swarm_workers.json` context checks, and dry-run `_swarmOverlay` / `_pendingSwarmOps` transaction commit across `swarm`, `post_message`, and `send_message` in `_inspect_workflow_script` / `handle_pre_tool_use`.
  - **Model Placeholder & Upstream State Integrity (`guard/agy_hooks.py`, `guard/upstream.py`, `skills/upstream-auditor/scripts/upstream_watcher.py`):** Added canonical `MODEL_PLACEHOLDER_*` detection (`_is_model_placeholder` / `is_placeholder_model`) with in-session `<USER_SETTINGS_CHANGE>` transcript precedence (`"auto"` / concrete overrides without cross-block effort bleed), seed-based diagnostics (`_seed_placeholder_diagnostic` / `_resolve_placeholder_diagnostic`), fail-closed `force_ask` escalation on unresolved customization placeholders, and clean `upstream_state.json` persistence (`last_audited_model` concrete, `last_pbtxt_model` placeholder-aware) in `cmd_status` / `cmd_ack`.
  - **Linked-Worktree `TestBoundaryGuard`, `Stop` Accounting & Installer/Doctor Hardening (`guard/test_boundary.py`, `guard/agy_hooks.py`, `install.py`, `guard/doctor.py`):** Added `resolve_linked_worktree_root` (supporting standard and bare-repo linked worktrees while excluding git submodules, plus main-repo `tasks.md` authorization fallback), session-flight `_session_flight_base_head` tracking, `.git`-file per-worktree stash ref fallback, and dead-worktree `flight_recorder.json` pruning in `guard/agy_hooks.py`, `_is_within_lexically` / `_harness_skill_names` / `".."` traversal rejection + regular-file collision backups in `install.py`, and `_check_plugins_symlinks` (`os.walk` `onerror`, dangling vs external/resolved symlink classification across `plugins/` and `.agents/skills/`) in `guard/doctor.py`.
  - **Evaluation Report (`2026-11-15`) Runtime, Security-Seam & Latency Hardening (`guard/agy_hooks.py`, `guard/test_boundary.py`, `guard/doctor.py`, `skills/upstream-auditor/scripts/upstream_watcher.py`, `skills/*/SKILL.md`, `tests/test_w5_evaluation_remediation.py`):** Replaced `handle_stop` `"NO_TOOL_CALL"` whitelist with case-insensitive `_NON_NORMAL_STOP_REASONS` blacklist (`NO_TOOL_CALL`, `model_stop`, `TERMINAL_STEP_TYPE`, `INJECTED_RESPONSE` all run `Stop` gates while abnormal stops preserve `"in_flight"` state); added `lastUserInput` / `last_user_input` fast-path, opt-in `AGY_RECORD_HOST_FIXTURES=1` sanitized capture, and `tests/fixtures/host/` contract fixtures; added intra-turn `invocationNum > 1` `PreInvocation` fast-paths and `_LazyRegex` deferred compilation; shielded `~/.gemini/{GEMINI,AGENTS}.md` (`deny`), gated workspace `.agents/hooks.json` (`force_ask` + `doctor` `[WARN]`), anchored `_command_mutates_governance` `antigravity-(?:harness|guard)` matching to `.local/(?:state|share)/` and `/usr/(?:lib|share)/`, expanded `Bash Guard` (`force_ask` on out-of-workspace `rm -rf`/`mv`, DB `DROP`/`TRUNCATE`/`dropdb`/unconditional `DELETE FROM`, `find -delete`/`-exec rm`, `git branch -D` / `stash drop|clear`, `docker/podman ... prune -af`/`--volumes`, `chmod -R 777`), exempted non-harness `DESIGN.md` from universal Rule 17 gating while escalating unrecognized future flagships at verified high effort to `force_ask`, recorded `flight_recorder` baselines on mutating shell commands (`sed -i`, etc.), added diff + AST assertion operator/matcher relaxation detection (`==` -> `>=`, `!=`, `is not None`, `toBeTruthy`), compacted 18 `skills/*/SKILL.md` descriptions (`-27%` chars), and documented cross-model-family verification (`Claude Opus 5.5 (High)` vs `Gemini 4`) plus plain-language **Operator Summary (`Operatör Özeti`)** in `skills/harness/SKILL.md` and `skills/audit/SKILL.md`.
  - **Tier-3 7-Auditor Hardening & Regression Tests (`tests/test_guard_hardening.py`, `tests/test_w2_ac2_ac4_hardening.py`, `tests/test_w5_evaluation_remediation.py`, `650` total tests):** Executed all 7 independent Tier-3 auditors with Mutual Falsification (`0` unresolved `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` findings across `W3..W4`), applied the Rule-9-authorized `expected_tools` update in `tests/test_guard_hardening.py`, and added `37` hermetic regression tests across `tests/test_w2_ac2_ac4_hardening.py` (`28`) and `tests/test_w5_evaluation_remediation.py` (`9`; `613` -> `650`).
- **Ecosystem routing overhaul & five-skill modernization (`ADR-0006`, `Paket 1–4`):**
  - **Automatic ecosystem routing (`guard/agy_hooks.py`, `GEMINI.md`, `skills/harness/SKILL.md`):** Prioritized explicit slash/slug mentions before regex gating (`_has_explicit_slug_mention` / `_has_explicit_route_slug_mention` with `_ROUTE_EXPLICIT_SLUGS`, including single inline backticks and `p99 <= 250 ms` hook budget), introduced Tiered Hint Saturation (`MAX_HINTS = 2` generic, `MAX_EXPLICIT_HINTS = 4` explicit, `MAX_CONTEXT_SIGNALS = 2` per-bucket context), fixed `"sprite sheet"` routing to `media-studio`, added bilingual EN/TR routing triggers, added bounded `PreInvocation` workspace (`depth <= 2`, `<= 200` entries, `1,000`-entry capped sort) and `transcriptPath` tail streaming (`_iter_jsonl_tail_entries` with `O_NOFOLLOW | O_NONBLOCK`, `S_ISREG`, post-`USER_INPUT` `> 500`-line error traces, non-exec read tool filtering), added `GEMINI.md` Section 6 (`Always-On Domain Skill, Subagent & Server Routing`, `17,920` bytes), and documented multi-skill sequential orchestration recipes in `skills/harness/SKILL.md`.
  - **`rustify` Rust `2024` Edition, `1.100.0` & C++ depth (`skills/rustify/SKILL.md`, `references/c-cpp-abi-and-embedded.md`):** Updated FFI patterns to `#[unsafe(no_mangle)]`, `unsafe extern "C"` (`pub safe` / `pub unsafe`), `static_mut_refs` (`&raw const`/`&raw mut`), and `unsafe_op_in_unsafe_fn`; integrated `core::mem::DropGuard`, `core::alloc::Allocator`, stabilized `!` (with pre-2024 fallback warning), Cargo publish-age cooldowns (`global-min-publish-age` / `min-publish-age`, `259200`s default with zero-day exception) + single-crate `cxx` bridge facade carve-out alongside the 3-crate `*-sys`/`*-core`/`*-ffi` split, and `[lints.cargo] unused_dependencies`; added C++ `virtual`/template/`std::move` matrix and `scripts/code_map.py` C/C++ macro/template boundaries.
  - **Game + Media + `vibecoder` + `rea` integration (`skills/game-engineering/SKILL.md`, `skills/vibecoder/SKILL.md`, `skills/media-studio/SKILL.md`, `skills/media-studio/scripts/media_qc.py`):** Split Web/Canvas (`Profile A`, `16.67 ms` render budget) from 3D/Native Engines (`Profile B`, `>= 4.5:1` contrast / `>= 14px` readability floor), added input buffering, preload gate, save `schemaVersion` + `<= 3` retry / `.corrupt.<timestamp>` quarantine, clean-room `rea_rea` bridge, brownfield triage, and `"mode": "game"` promotion wiring; added opt-in `media_qc.py` game audio/pixel-art/atlas checks (`GAME-1..GAME-3`, `--game-sfx` `< 0.5 s` cutoff vs `400 ms` ITU gating, `--peak-db`, `--ogg-codec vorbis|opus` with `min(target_tp - 0.6, -1.6)` inter-sample headroom, `--check-loop`, per-channel `--trim-loop`, `--pixel-art` with `-fps_mode passthrough` multi-frame decode and `4:4:4` upsampled `< 8x8` SSIM/PSNR, `--sprite-atlas`, `--tile-size`, `--require-pot`, `--check-alpha-bleed`, `--allow-edge-touch`, `MAX_GAME_AUDIO_SR`/`MAX_GAME_AUDIO_BYTES`, `allow_nan=False` strict JSON, parameter finite/sign validation) preserving backwards-compatible defaults.
  - **`sweetspot --net` & `renew` boundary hardening (`skills/sweetspot/SKILL.md`, `skills/renew/SKILL.md`):** Defined the `--net` Controllable vs. Uncontrollable External Path boundary with Zone 3 Null-Action (`>= 85%` external path share and `< 1%` controllable gain on deterministic fixtures), and added `[HARDWARE/ENV SHIM]` record/replay contracts (`t_k >= t_{k-1}`, `<= 500 ms` timeouts, `ShimReplayMismatch`), non-blocking event-loop migration (`<= 1` bounded modal continuation queue), decimal/date/Turkish `İ/i`/`I/ı` locale invariants, and post-parity handoffs (`sweetspot` / `diagnosing-bugs`).
  - **Tier-3 7-auditor hardening (`Window 3/3`, `613` total tests):** Executed all 7 independent Tier-3 auditors (`0` CRITICAL), resolved confirmed `HIGH`/`MEDIUM` security, contract, specification, and test-adequacy gaps across `guard/agy_hooks.py`, `skills/media-studio/scripts/media_qc.py`, `GEMINI.md`, and 5 `SKILL.md`/reference docs, and added `12` additive hermetic regression tests (`601` -> `613`).
- **Antigravity `v2.32.0` compatibility & hook contract modernization (`ADR-0005`):**
  - Updated `skills/upstream-auditor/upstream_state.seed.json` and `guard/agy_hooks.py` for `Gemini 4 Hydrogen (XHigh)`, `Gemini 4 Carbon` (`High`/`XHigh`), `Orchestrator (Carbon/Argon)` comma-separated effort parsing, and the `14` built-in Antigravity skills (`sha256` synchronized) while preserving `"Gemini 4 Argon (High)"` backward compatibility and Rule 17 highest-effort enforcement.
  - Migrated `PreInvocation` hook output (`guard/agy_hooks.py`) and `skills/upstream-auditor/scripts/upstream_watcher.py` from deprecated `ephemeralMessage` to native `systemMessage` schema (`metadata.user_markdown` with empty `systemMessage` body for operator-only watchdog notices), updated `scripts/meta_audit.py` `_extract_pre_invocation_text`, and wired `Stop` `continuationActive` / `fullyIdle` awareness without suppressing diff/`TestBoundaryGuard` gates.
  - Added `swarm` to `PRE_TOOL_USE_MATCHER_TOOLS`, `hooks.json`, `guard/agy_hooks.py` (blocking two-step worker/coordinator customization model downgrades and gating `call_tool("swarm", ...)` in `run_workflow`), added `ECOSYSTEM_ROUTING_HINTS` entries for `native_swarm`, `migrate-agent-settings`, and `mcp-app-development`, and documented built-in resolutions in `GEMINI.md` Rule 15 `(f)–(h)`.
  - Tightened Knowledge Work hygiene in `guard/agy_hooks.py`: non-git workspaces receive file-based recovery hints without `git status`/`git diff`, non-harness `skills/`/`agents/` folders no longer trigger customization gates unless targeting `SKILL.md`/`.agents`/governance files, and `SKILL_HINTS` narrows `sweetspot`/`deep-grill` phrases cleanly.
- **Tracked upstream repository synchronization:** synced verified improvements from `miqdadbadjuber/anti-slop` (`R-39`, `R-40`, `Scaffold Sidebar`, copywriting tells; `40` rules total) and `mattpocock/skills` (fresh-context `research` subagent guidance in `deep-grill`), verified `JayPokale/Chisle`, `affaan-m/ECC`, and `azrtydxb/procoder` deltas, and noted `morluto/rea` `rea-agents-6.9.0` (retaining `rea-agents-6.7.0` in seed until human-unlocked plugin upgrade).

## [2.0.0] - 2026-10-19
Native Antigravity 2.0 lifecycle hooks (`PreInvocation`, `PreToolUse`, `Stop`), full ecosystem auto-routing (skills, auditor subagents, MCP servers, and plugins), AST/dataflow/FTS5 code mapping (`scripts/code_map.py`), domain-aware UI archetypes (`MODE: UTILITY`, `MODE: EDITORIAL`, `MODE: GAME & INTERACTIVE`), deterministic UI slop scanning (`check_ui_slop.py`), 13 new engineering skills (34 total), and 2 new auditor subagents (9 total).

### Breaking changes
- **Constitution expanded to 18 rules (`GEMINI.md`).** Added Rule 9 `C9` (prohibition on test-fitted production code and test-runner environment sniffing), Rule 17 top-catalog model and highest-effort requirement on customization/governance edits, and Rule 18 (`Surgical Change & Reuse Discipline`); codified built-in platform collision resolutions in Rule 15 (`a`–`e`).
- **Native Antigravity 2.0 `hooks.json` & `guard/agy_hooks.py` (`harness-gate`).** `PreToolUse` enforces an explicit `"decision"` contract (`"allow"`, `"force_ask"`, `"deny"`), blocks direct agent writes to `~/.gemini/config` governance seams (while permitting runtime subdirectories `plugins/`, `sidecars/`, `projects/`, `cache/`), blocks mutations to customization or governance files unless the active model and effort match the top catalog model (`skills/upstream-auditor/upstream_state.seed.json`), blocks agent execution of human-only `agy-guard` administration commands and `--no-verify` git bypasses, and prompts on destructive shell/git operations.
- **Domain-aware `DESIGN.md` archetypes.** Added `MODE: UTILITY`, `MODE: EDITORIAL`, and `MODE: GAME & INTERACTIVE` alongside the computed WCAG AA contrast table.

### Added
- `guard/agy_hooks.py`:
  - `PreInvocation`: bilingual (`EN` / `TR`) automatic skill suggestion across the skill catalog (`SKILL_HINTS`) plus automatic Subagent, MCP Server (`rea_rea`, `antislop-contrast`), and Plugin (`rea`) routing (`ECOSYSTEM_ROUTING_HINTS`) with per-conversation deduplication.
  - `PreToolUse`: Governance Shield, Top-Catalog Model & Effort Customization Gate (`GEMINI.md` Rule 17), and Bash Guard with command-boundary anchoring.
  - `Stop`: diff integrity gate catching tautological assertions, `C9` test-runner sniffing in production code, unapproved test skip markers, malformed `.json`/`.toml`/`.svg` syntax, structural UI/game slop (`UI-1`–`UI-5`), and broken workspace-local Markdown links, guarded by a 3-strike circuit breaker.
- `scripts/code_map.py`: zero-dependency Python AST `profile`, `callers`, `flow` (backflow/forwardflow), `blast-radius` (Tier 1/2/3 threshold check), `gate-syntax`, deterministic runtime `trace`, SQLite `FTS5` BM25 passage search (`fts-search`), plus brace-aware C/C++ (`.c`/`.h`/`.cpp`/`.cc`/`.cxx`/`.hpp`/`.hh`/`.hxx`) function/method indexing and lifetime-safe Rust (`.rs`) lexer scrubbing (`ADR-0003`).
- `skills/antislop/scripts/check_ui_slop.py`: deterministic structural scanner for UI/HTML/JSX/TSX/CSS files (`UI-1` cloned card grids, `UI-2` nested card-in-card boxification, `UI-3` unearned visual tells, `UI-4` raw RGB/CMY game primaries, `UI-5` dead interactive stubs).
- 13 new skills (`34` total): `test-design`, `mistake-proofing`, `refactoring`, `dependency-upgrade`, `retro`, `technical-writing`, `data-analysis`, `game-engineering`, `marathon`, `sweetspot`, `media-studio`, `renew`, and `rustify`.
- `skills/rustify`: 5-stage C/C++/Go/Python -> memory-safe Rust migration and FFI bridging package (`SKILL.md`, `references/c-cpp-abi-and-embedded.md`, `references/managed-go-python.md`) with two-stage unsafe purification and a 3-tier `rustc`/`clippy`/`miri`/sanitizer/conditional `cargo kani` verification ladder (`ADR-0003`).
- `skills/renew/SKILL.md`: 5-stage contract-first modernization pipeline (`Silent Autopsy -> Renewal Contract -> Golden Master or Equivalence Ledger -> Layered Strangler Cutover & Security Sanitization -> Parity Gate`) for generational legacy software and classic games (`ADR-0002`).
- `skills/media-studio`: container/header recovery (`media_qc.py salvage`), still-image restoration (`JPG`/`PNG`/`TIFF`/`BMP` with scanline decode verification), two-tier fidelity-bounded quality enhancement (`references/salvage-and-enhancement.md`), aspect-drift-locked `compare`, and side-by-side `ab-sheet` visual inspection (`ADR-0002`).
- 2 new read-only auditor subagents (`9` total): `test-adequacy-auditor` and `contract-change-auditor`.
- `skills/vibecoder/SKILL.md`: added **Game Prototype Mode (`Game Vibe Mode`)** bridged with `skills/game-engineering/SKILL.md` and `DESIGN.md` (`MODE: GAME & INTERACTIVE`) for zero-friction single-file rich HTML game prototypes (`<canvas>` + Diegetic HUD + fixed-timestep loop + seeded PRNG + WebAudio Input Feedback Triad) and a 3-question `Game Vibe-Grill`.
- `skills/antislop-copywriting`: added Turkish synthetic-marker rules (`TR-1`–`TR-7`) and monotonous sentence cadence (`6.7`) in `check_synthetic_markers.py`.
- `skills/upstream-auditor`: added release-tag (`"track": "release"`) and subpath tracking, registering `morluto/rea` (`reverse-engineer-anything`, 8 tracked repositories total).
- Guard CLI, GUI & Packaging synchronization: `.zip` archive inspection in `porter_bridge.py` and GUI, `tasks.md` `## Authorized Test Modifications` support in `test_boundary.py`, `hooks.json`/`install_receipt.json` checks in `doctor.py`, and updated PyInstaller/Linux packaging scripts.
- Architecture Decision Records: formal ADR process under `docs/adr/` (`ADR-0001` through `ADR-0004`) covering v2 remediation, renew/media-studio, rustify/codemap, and tiered MCP hook policy with dual-layer Linux package activation (`agy-guard init`).
- Bilingual Architecture: Full parity for English workflows with native, out-of-the-box Turkish intent detection in `PreInvocation` lifecycle hooks and Turkish AI-marker detection (`TR-1`–`TR-7`) in copywriting audits.
- Terminal & Process Hardening: Sealed terminal and process injection vectors against PTY spawns, multiplexer escapes (`tmux`, `screen`), and controlling-terminal prompt bypasses (`guard/approval.py`).

## [1.4.0] - 2026-09-30
Governance-quality release driven by a staged review of a master integration spec and a fresh
forensic audit of the code base. Fewer always-on rules, more mechanical enforcement.

### Breaking changes
- **Constitution pruned (GEMINI.md 18.5 KB -> 10.4 KB).** Rule numbers 1-17 are unchanged; procedures
  moved to `skills/harness` and `skills/diagnosing-bugs`, UI detail to `DESIGN.md`. The "~25 turns /
  noticeable context degradation" saturation guard is replaced by observable handoff triggers (Rule 13).
- **Lease changes are no longer trusted automatically.** An unattended expiry records the window's
  changes as *pending review* (`[REVIEW]` in `status`/`verify`) until an approved `rebaseline`;
  `agy-guard lock-complete` asks the human whether to accept them.
- **New approval gates:** lowering an environment policy, `notify disable`, `startup enable` and
  `snapshot prune` now require a human (exit code 3 otherwise), and Rule 12 lists them as human-only.
- **Other agents' environments** are discovered through rule files only (`CLAUDE.md`,
  `.claude/agents|commands|skills`, `.cursor/rules`, ...) and start as `monitored`; whole `.claude` /
  `.cursor` / `.codex` seams from 1.3.x are migrated on load. The home directory is never a workspace.
- **Locking one specific non-enforced environment returns failure** instead of reporting success.
- **Snapshots without a readable content manifest are no longer restored.**
- Canonical manifest schema 1.2.0 (executable bits, templates); the Claude export writes `tools:` from the
  new agent `access:` key and keeps verbatim agent copies in `.claude/harness/agents/`.

### Security & integrity
- Home-directory discovery no longer registers `~/.gemini`, `~/.claude` and `~/.cursor` wholesale (a
  launcher-started GUI ran there and "Lock All" froze those tools' runtime state).
- Leases: records are removed only by the close of the same lease id (a concurrent grant could be erased
  and leave the tree open with no record), grants re-check under the store lock, closes are claimed,
  failed relocks are retried (5 x 60 s), the watcher logs to `logs/lease-watcher.log` instead of
  `/dev/null`, and a corrupt lease store fails closed (set aside, every enforced environment re-locked).
- FIM: `backup_` / `.guard_` prefixes are excluded at the top level only (a `SKILL.md` inside a `skills/backup_*` folder
  used to be invisible); malformed baselines are reported as corrupt; the boot sentinel locks before it
  verifies, so a broken baseline can no longer skip the lock.
- Boot sentinel: forensic snapshots are deduplicated (newest 3 kept), systemctl/launchctl failures are
  reported, control characters are rejected in unit values (an injected `ExecStartPre=` line was
  accepted), `$` is escaped in `ExecStart=`, and the Windows task runs with `LIMITED` instead of `HIGHEST`.
- A symlinked config root is refused instead of locking the link target; the lock-mode store is
  serialised across processes and never restores a world-write bit; Windows `icacls` DENY parsing uses
  whole rights (`"de"` inside `"(deny)"` used to count as a write deny).
- Test boundary (TDD "extend only"): pure additions that disable tests (`skipTest`, early `return`,
  assert/TestCase monkeypatching, shadowing redefinitions, `os._exit`) are now weakening.
- Porter: the sanitizer classifies matches as prohibited / affirmative / uncertain with clause-scoped
  negation; uncertain lines are kept and flagged instead of deleted; `--no-verify` and "ignore previous
  instructions" are caught. The SSRF fetcher blocks IPv4-compatible/-translated IPv6, enforces an overall
  deadline and no longer registers file/ftp/data handlers.
- Upstream watchdog: the PreInvocation notice is operator-only (it used to tell the agent to "recommend
  running /audit-upstream" on every turn, and agents copied it into task prompts), shown once per change,
  silenced with `--ack`, with a hard network deadline, atomic state writes and re-seeding of a corrupt ledger.
- CI: the trusted-boundary job never falls back to the candidate's own verifier; supply-chain comment made
  accurate; fork pull-request runs require maintainer approval (see `CONTRIBUTING.md`).
- Installer: a corrupt `hooks.json` is left untouched instead of being overwritten; hook and launcher
  commands are shell-quoted.

### Added
- `guard/audit_log.py`: rotating JSON-lines audit log of approvals, locks, leases, baselines, snapshots,
  boot checks and every WARNING/CRITICAL notification.
- `agy-guard notify send` (used by hooks), `lock` shows unreviewed changes before sealing,
  `guard/doctor.py` (headless checks, watcher-log errors).
- `porter.py inspect <file.zip>`: read-only archive inspection (`porter/archive.py`).
- `skills/antislop-copywriting/scripts/check_synthetic_markers.py`: deterministic scanner for signs of
  AI-written prose (39 signs incl. Turkish, prose/technical profiles, R-02 em-dash policy).
- `skills/visualizer`: lens/abstraction/medium decisions for diagrams, rendering delegated to
  Mermaid or the built-in `generative_ui`.
- Skill updates: `deep-grill` (scope parking, paraphrase check-ins, product lens, decision ledger),
  `diagnosing-bugs` (multi-label failure classification, hypothesis-bound scripts, measured
  optimization path), `audit` (byte-based scope sizing, Mode 4 `--forensics` / `--cognitive`),
  `vibecoder` (goal + acceptance criteria), `harness` (quad classification, staged artifacts),
  agents `research`, `consistency-auditor`, `meta-auditor`; ADR weighted criteria.
- `HANDOFF.template.md`: authoritative goal, exit criteria, progress as criteria met, where to continue.
- `meta_audit`: slash commands referenced by the instruction set must be provided by a skill (found a
  dangling `/boost`); `.claude/` worktrees are skipped; agent `access:` values are validated.
- `CONTRIBUTING.md`.

### Fixed
- GUI: long operations off the Tk thread, lock failures shown as errors, lease-tick failures logged,
  approvals through the shared gate, snapshot files opened as read-only `.txt` copies (never executed),
  no hide-to-tray when the tray is not running.
- Porter export keeps executable bits, writes LF on every OS and exports `templates/`; the manifest now
  parses the constitution's rule list (the pattern never matched the `**Title:**` form).
- Windows: `porter.py` and `agy-guard` no longer crash on consoles that cannot encode a character
  (cp1252 pipes); a read cut short by the fetch deadline is reported as a deadline error even when the
  platform timer fires early.

### Known limitations
- New test files are always allowed by the test boundary, so a new file could still patch `TestCase` at
  import time; the maintainer review of external pull requests covers this.
- Entries that were already read-only before a lock come back owner-writable on unlock (recording them
  would make a lost mode store permanently freeze the tree).

## [1.3.1] - 2026-09-22
Remediation release for the five external audit reports (121 validated findings). Guard's claims now
match what it enforces; see the threat-model section of `README.md`.

### Breaking changes
- **`--auto-approve` removed** from `request-unlock`. `unlock`, `rebaseline`, `snapshot restore`,
  `porter stage`, `test-boundary snapshot` (overwrite), `startup disable` and `doctor --fix` (baseline)
  require a human to type `yes` in a TTY or confirm in the GUI; otherwise they exit with code `3`
  (`guard/approval.py`, GEMINI.md Rule 12).
- **State moved out of the protected tree and the repository:** registry, integrity baselines, leases,
  lock-mode records, notifier settings, lease reports and the upstream ledger live in
  `~/.local/state/antigravity-harness/`; snapshots and the runtime in `~/.local/share/antigravity-harness/`
  (`XDG_STATE_HOME` / `XDG_DATA_HOME` / `AGY_GUARD_STATE_DIR` honoured; same layout on every OS). Legacy
  `~/.gemini/.environments.json` and `.guard_integrity.json` are read once and reported by `doctor`.
- **Installer defaults to copy mode** (`--link` keeps the old symlink behaviour for development);
  backups go outside the config tree; `hooks.json` is merged instead of replaced; the `--full` flag
  mentioned in 1.2.7 never existed and is not needed.
- **Lock scope is the governance seams only** (`GEMINI.md`, `AGENTS.md`, `DESIGN.md`, `MISTAKES.md`,
  `hooks.json`, `mcp_config.json`, `skills/`, `agents/`, `templates/`, `.harness/`). Antigravity runtime
  state (`config.json`, `projects/`, `sidecars/`, …) and the root directory are no longer locked, because
  Antigravity saves `config.json` by atomic replace; replacing a top-level file is detected by FIM. When
  upgrading, the installer restores owner write access on runtime state frozen by the 1.3.0 lock.
- **Test boundary, bugfix mode:** new test files are allowed (Rule 9 regression tests); existing tests,
  runner configuration and fixtures must stay byte-identical. TDD mode allows pure appends only.
- The committed upstream ledger was renamed to `skills/upstream-auditor/upstream_state.seed.json` and is
  only read as a seed; the live ledger is written to the state directory.
- Porter's `porter/parsers/` package (unused) was removed.

### Security & integrity
- Locking never follows symlinks, reports external symlinks as unprotected, records and restores the
  original permission modes, returns failure on partial locks, and reads Windows directory state from the
  ACL instead of writing probe files.
- Leases: persisted before unlocking, detached `lease-tick` watcher relocks on expiry, several concurrent
  leases, relock before rebaseline, change report per lease, `close_failed` state + CRITICAL notification.
- FIM baseline records symlinks as links, reports unreadable files, archives history and no longer lives
  inside the tree it protects.
- Snapshots exclude `config.json` (no token copies), verify content before restore, refuse destination
  symlinks, always take a pre-restore backup, use a journaled swap and rebaseline afterwards; pruning is per kind.
- Boot sentinel quarantines drift (forensic snapshot, CRITICAL notification, no rebaseline); systemd and
  launchd files are quoted/escaped.
- Porter staging binds the reviewed content hash, refuses destination symlinks, writes with `O_NOFOLLOW`
  and always relocks. `porter.py import` refuses to write into the live config; `--force` needs a human.
- SSRF: DNS pinning against rebinding, `is_global` plus 6to4/NAT64/site-local blocks, proxies ignored.
- Notifier passes text as data (argv / environment) to `osascript` and PowerShell, `--` for `notify-send`;
  disable is absolute; cooldown cache pruned. Tray icon lives in a private runtime directory.
- Sanitizer is negation-aware (protective rules such as "never skip tests" are kept), matches across line
  breaks, covers Turkish phrasing and is applied on export as well as import.
- Provenance parses `git status -z` correctly and redacts secret-like environment values.
- A missing baseline is reported as `BASELINE MISSING` (not as a deleted file); the GUI's all-environment
  check uses each environment's own baseline; `startup disable` on Windows reports `schtasks` failures.

### Porter & self-audit
- Lossless export: every skill support file, in-skill symlink and all 7 agents for Claude, Cursor,
  Universal, Aider and Generic targets; valid Cursor `.mdc` YAML; no overwrite without `--force`.
- Strict standard-library YAML frontmatter parser/dumper (`porter/frontmatter.py`); manifest schema 1.1.0
  with content digest and `porter.py manifest --check`.
- `scripts/meta_audit.py` rewritten with six real passes (frontmatter, references, mutual exclusion and
  tier thresholds, export parity, CLI/README sync, measured contrast), `--strict`, `--pass`, `--json`, `--root`.
- `scripts/verify_invariants.py` detects `bash <(curl …)` / `source <(…)`, checks Markdown only inside
  code fences, supports `--base-ref` and exits `2` when a check cannot run.

### CI & packaging
- Actions pinned to commit SHAs, least-privilege permissions, Python 3.10–3.14 on Linux/macOS/Windows,
  lint job, `meta_audit --strict`, manifest freshness check.
- Trusted-boundary job runs the candidate code against the base branch's tests and graders in a clean worktree.
- Release assets get individual `.sha256` files and are never clobbered; PKGBUILD checksum is rendered by CI.
- Cross-platform: snapshots of a locked tree no longer inherit macOS immutable flags or read-only bits;
  in-skill directory symlinks are recreated with the right type on Windows; Windows lock detection reads
  the ACL instead of `os.access()`; state paths keep symlinked ancestors (`/var`, 8.3 names) as configured;
  `.gitattributes` checks text out with LF everywhere so the manifest is byte-identical on every OS.
- Snapshot ids stay unique when the clock does not advance between snapshots (Windows ~15 ms ticks);
  pruning only counts snapshots that were actually removed; `verify_invariants` output survives cp1252 consoles.
- Linux packages ship `LICENSE` and `THIRD_PARTY_NOTICES.md` and declare `MIT` and `Apache-2.0` (bundled
  `procoder` skill); build caches are no longer packaged.
- Upgrading from 1.3.0: the installer moves in-tree snapshots/baselines (`.guard_snapshots`,
  `.guard_integrity.json`), read-only `backup_*` folders and old runtime symlinks out of `~/.gemini/config`
  (to `~/.local/state/antigravity-harness/`, mode 0700); nothing is deleted and failures never abort the install.

### Content
- README rewritten with an explicit threat model and corrected commands, counts and policies.
- GEMINI.md Rules 8/10/12/13/15/17 clarified; DESIGN.md colours `#64748B` (light border / disabled text)
  and `#71717A` (dark border) with a measured contrast table.
- `vibecoder` translated to English with a mutual-exclusion section and SRI-pinned CDN assets; dead
  references fixed across skills; unified prompt-defence baseline for all agents; `THIRD_PARTY_NOTICES.md` added.

### Authorized test modifications
Existing tests were changed only where this release intentionally changed a contract:
- `test_guard.py`: hermetic HOME/state isolation (`tests/hermetic.py`) and `force_rmtree` clean-up;
  `test_status_command` now asserts the exact exit codes (1 → rebaseline → lock → 0) instead of `(0, 1)`;
  `test_upstream_check_cli` mocks the network; the Pillow test skips instead of passing vacuously;
  `test_gui_design_disabled_tokens` → `test_gui_tokens_meet_design_contract` (checks contrast, not hex
  literals); version tests assert single-sourcing instead of the literal `1.3.0`.
- `test_lease.py`: `auto_approve=` replaced by an explicit `approver=` and an injected scheduler (flag removed).
- `test_test_boundary.py`: `test_verify_bugfix_added_file_blocked` →
  `test_verify_bugfix_added_regression_test_permitted` (decision 7: new regression tests are allowed).
- `test_packaging.py`, `test_provenance.py`, `test_environment.py`, `test_meta_audit.py`,
  `test_notifier.py`: hermetic import, version via `__version__`, public packaging seams.
- New suites: `test_protection.py`, `test_porter.py`, `test_tooling.py` (plus 4 new tests in `test_guard.py`).
- `test_tooling.py::test_paths_with_spaces_are_quoted` (new in this release) expects systemd's backslash
  escaping, so the same assertion also holds for Windows paths.

## [1.3.0] - 2026-09-20
### Added & Hardened
- **Multi-Environment OS Write Protection & Governance Seams (`guard/environment.py`, `guard/os_adapter.py`, `guard/integrity.py`):** Extended OS protection adapter and cryptographic FIM tracking across multiple co-located agent runtimes (Antigravity, Claude Code, GPT Codex, Cursor, Aider). Protects discrete governance seam files (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `.aider.conf.yml`, `GEMINI.md`) without locking developer project code. Added auto-discovery and persistence in `.harness/environments.json`.
- **Architectural Boundary Enforcement:** Preserved absolute boundary between supervisor and model: Guard acts strictly as an immutable OS monitor, shield, and notification engine, while models and Porter manage their own rule transpilation and ingestion.
- **Multi-Environment Drift Analysis & CLI Matrix (`guard/cli.py`):** Added `agy-guard env (list|detect|add|remove|policy)`, `agy-guard drift`, and `--env` / `--all` flags across `lock`, `unlock`, and `verify`.
- **Low-Frequency Ergonomic Notification Engine (`guard/notifier.py`):** Implemented desktop and terminal notifications (`notify-send`, `osascript`, PowerShell, terminal bell) with persistent cooldown cache (`.notify_cache.json`), debouncing, and quiet mode.
- **Human-in-the-Loop Time-Bounded Lease Unlock (`guard/lease.py`):** Added `agy-guard request-unlock` and `agy-guard lock-complete` providing time-bounded maintenance leases with operator approval, automated relock upon expiry, and cryptographic rebaselining.
- **Autonomous Harness Self-Audit & Meta-Consistency Engine (`scripts/meta_audit.py`, `agents/meta-auditor.md`, `skills/audit/SKILL.md`):** Built 5-pass deterministic self-auditor verifying YAML frontmatter schemas, dead link/template cross-references, skill mutual exclusion barriers, Porter parity, and CLI sync. Integrated into `GEMINI.md` as **Rule 17**.
- **Native Linux Distribution Packaging (`installers/packaging/package_linux.py`, `PKGBUILD`):** Added native package generators for Debian/Ubuntu (`.deb` via pure Python `ar` builder), Red Hat/Fedora (`.rpm`), and Arch Linux (`.pkg.tar.zst`).
- **Comprehensive Unit Test Suite (`tests/test_*.py`):** Added 25 new unit tests across 5 new test files (`test_environment.py`, `test_notifier.py`, `test_lease.py`, `test_meta_audit.py`, `test_packaging.py`), bringing total passing unit tests to 77.

## [1.2.9] - 2026-09-20
### Added & Hardened
- **Test & Configuration Trust Boundary Shield (`guard/test_boundary.py`, `guard/cli.py`):** Established test suites and runner configurations as an external immutable trust boundary. Computes SHA-256 tree hashes across tests (`tests/`, `spec/`) and runner/compiler configurations (`pytest.ini`, `setup.cfg`, `tsconfig.json`, `package.json`, `jest.config.*`, etc.). Supports dual verification modes (`bugfix` and `tdd`) and explicitly flags subtle Goodhart gaming (fixture tampering, threshold loosening, mock alterations). Added CLI subcommands `agy-guard test-boundary snapshot` and `agy-guard test-boundary verify`.
- **Run Provenance & Execution Audit Trail Manifest (`guard/provenance.py`, `guard/cli.py`):** Implemented execution provenance tracking outputting `.harness/provenance.json`. Records base commit SHA, touched files, test boundary verification status, reproducibility confirmation, and environment variable overrides (`MOCK_*`, `SKIP_*`). Generates structured Markdown execution proofs for delivery gates. Added `agy-guard provenance generate` and `agy-guard provenance status`.
- **Targeted Reproducibility Gate (`guard/test_boundary.py`, `guard/cli.py`):** Added `agy-guard test-boundary run-reproducible --cmd "<command>"` executing target unit tests across consecutive isolated runs (default: 2x) to eliminate flaky passes, timing jitter, and race conditions.
- **Base-Commit CI Trust Boundary Split (`.github/workflows/ci.yml`):** Hardened CI matrix with a PR verification step that checks out test suites directly from the base branch (`git checkout origin/${{ github.base_ref }} -- tests/`), ensuring candidate pull requests are graded against trusted, unmodified tests.
- **Invariant Guard Integration (`scripts/verify_invariants.py`):** Added automatic test boundary verification to the repository invariant scanner.
- **Automated Unit Test Suite (`tests/test_test_boundary.py`, `tests/test_provenance.py`, `tests/test_guard.py`):** Added 14 unit tests validating snapshot creation, mode enforcement, fixture tampering detection, provenance generation, and version alignment across all modules.

## [1.2.8] - 2026-09-20
### Fixed
- **GUI Crash on Launch (`guard/gui.py`, `guard/upstream.py`):** Resolved fatal `KeyError: 'tracked_ecosystems'` during `AntigravityGuardApp` tab construction. `UpstreamAuditorBridge.get_model_drift_status()` now dynamically calculates and returns `"tracked_ecosystems"` count from state, and `_build_tab_upstream()` accesses dictionary keys defensively using safe fallbacks.
- **Upstream Auditor Contract Test (`tests/test_guard.py`):** Added `test_upstream_auditor_model_drift_status_keys` unit test ensuring drift status model and ecosystem contracts remain satisfied across releases.

## [1.2.7] - 2026-09-20
### Fixed & Hardened
- **Decoupled Control Plane & Policy Workspace (`install.py`, `install.sh`):** Separated standalone control plane binary (`agy-guard`) from config/policy workspace installation. Installers download or link compiled binary to `~/.local/bin/agy-guard` without altering underlying policy configuration. (Correction: no `--full` flag was ever implemented.)
- **Top-Level Regex Dependency Fix (`porter.py`):** Added top-level `import re` required by `clean_name = re.sub(...)` in `cmd_import()`, resolving `NameError` during CLI rule and skill import.
- **Upstream Auditor State Resolution (`guard/upstream.py`):** Synchronized state file resolution with `upstream_watcher.py`, prioritizing `UPSTREAM_STATE_FILE` and `$XDG_STATE_HOME/antigravity-harness/upstream_state.json` with fallback to legacy path, ensuring seamless watchdog status queries under lock.
- **Atomic Re-Lock Verification (`guard/porter_bridge.py`):** Captured return value of `self.os_adapter.lock()` during post-ingest relock; marks operation as failed if relock fails, eliminating unshielded exposure states.
- **Strict FIM Baseline Trust (`guard/integrity.py`):** Prevented automatic trust and silent baseline creation when `.guard_integrity.json` is missing; returns `is_intact=False` with `BASELINE MISSING` diagnostic.
- **Microsecond Precision Snapshot Identifiers (`guard/snapshot.py`):** Switched snapshot ID and emergency rollback timestamps to `%Y%m%d_%H%M%S_%f`, eliminating collisions during rapid consecutive snapshot creation.
- **Lossless Dynamic Canonical Manifest (`porter/manifest.py`, `.harness/manifest.json`):** Dynamic loader binding for `UniversalManifest` version alignment.

## [1.2.6] - 2026-09-20
### Added & Hardened
- **Pre-Session Boot Sentinel (`guard/startup.py`, `guard/cli.py`, `guard/gui.py`):** Cross-platform early-boot protection. On Linux, registers `systemd --user` unit (`agy-guard-boot.service`) running with `Before=graphical-session.target xdg-desktop-autostart.target` to lock and verify the environment before any desktop AI IDEs or models start. On macOS, configures a `launchd` LaunchAgent (`com.antigravity.guard.plist`). On Windows, registers a Task Scheduler task (`schtasks /SC ONLOGON /RL HIGHEST`). Added CLI commands `agy-guard startup enable|disable|status` and headless `agy-guard boot-check`, plus GUI settings toggle.
- **SSRF Immunity & Safe Redirects (`porter/net.py`, `guard/porter_bridge.py`, `porter.py`):** Centralized remote fetching into `porter/net.py` with `SafeRedirectHandler` preventing open-redirect SSRF bypasses to link-local/private metadata addresses. Enforced URL validation across `PorterBridge.inspect_source()`.
- **Path Traversal Guards (`guard/snapshot.py`, `porter.py`, `guard/porter_bridge.py`):** Enforced strict regex validation (`^[a-zA-Z0-9_-]+$`) on `snap_id` and verified `relative_to` containment for snapshot restoration, reading, and file indexing. Sanitized `--as-skill` and `--as-agent` identifiers in `porter.py` and `PorterBridge`.
- **Agent Import Routing Fix (`guard/porter_bridge.py`):** Corrected classification routing so imported persona and auditor files (`target_type in ("agent", "subagent")`) correctly target `agents/` instead of falling back to `rules/`.
- **FIM Symlink Traversal & Cycle Detection (`guard/integrity.py`):** Enabled `followlinks=True` with visited directory tracking in `scan_directory()`, ensuring modular skills installed as symlinks are fully monitored and protected by File Integrity Monitor.
- **Runtime State Separation (`skills/upstream-auditor/scripts/upstream_watcher.py`):** Relocated mutable `upstream_state.json` to user state directory (`~/.local/state/antigravity-harness/`), preventing write failures when `~/.gemini/config/` is locked by Guard.
- **Repository Hygiene & Portable Hooks (`hooks.json`):** Removed machine-specific absolute path from repository `hooks.json` and aligned all version definitions to `1.2.6`.

## [1.2.5] - 2026-09-20
### Added & Hardened
- **Design & Interactive State Governance (`DESIGN.md` & Rule 14):** Added explicit Interactive Component States (Default, Hover, Active/Pressed, Focus-Visible, Disabled) and prohibited bright accent retention on disabled controls; defined WCAG AA compliant disabled tokens (`#27272A` / `#A1A1AA`, 5.81:1 contrast).
- **GUI Disabled Button High Contrast (`guard/gui.py`):** Resolved low-contrast button styling in Tkinter/ttk by mapping explicit disabled states to dark neutral surfaces, eliminating unreadable text.
- **Cross-Platform System Tray & Minimize-to-Tray (`guard/tray.py`, `guard/gui.py`):** Added native system tray support via `AyatanaAppIndicator3` for Kubuntu/KDE Plasma, GNOME, XFCE and `pystray` across Linux, macOS, and Windows. Included configurable "Minimize to Tray on close/minimize" setting and dynamic shield status icons.
- **Snapshot Inspection & In-App Read-Only Viewer (`guard/snapshot.py`, `guard/gui.py`):** Added dual-pane snapshot file tree, in-app modal file viewer with path traversal guards, and external editor read-only launch.
- **Standalone Binary Packaging & CI Matrix (`installers/build_binaries.py`, `.github/workflows/ci.yml`):** Added PyInstaller packaging script and automated multi-OS build matrix for Linux, macOS, and Windows standalone executables.
- **Upstream Ecosystem Synchronization:** Synchronized `antislop` v3.2.10 (R-02 / R-37 em-dash scoping for user samples) and `everything-claude-code` (parameterized SQL injection fix), updating all tracked repositories to `Up-to-date`.

## [1.2.4] - 2026-09-19
### Fixed & Hardened
- **Windows NTFS Specific Rights:** Replaced broad `(W)` denial with `(WD,AD,DE,DC)` to preserve `READ_CONTROL` for binary reading and integrity verification under lock (`guard/os_adapter.py`).
- **Recursive Subdirectory Unlock:** Added `/t /c /q` to Windows `icacls` unlock routines to cleanly strip inherited deny ACEs across subdirectories (`guard/os_adapter.py`).
- **Directory Lock Detection:** Added probe file verification for directory locks on Windows (`guard/os_adapter.py`).
- **ASCII-Safe Console Output:** Replaced Unicode status characters with standardized `[OK]` and `[WARN]` markers for CP1252 / Windows terminal resilience (`guard/cli.py`, `guard/integrity.py`).
- **Repository Cleanliness:** Reorganized root directory bloat into `installers/` and consolidated release records into root `CHANGELOG.md`.

## [1.2.3] - 2026-09-19
### Added & Hardened
- **State-Synchronized Rollback:** Full-state snapshot restoration with extraneous file pruning (`guard/snapshot.py`).
- **Isolated Cryptographic Trust Anchor:** External baseline path support via `ANTIGRAVITY_INTEGRITY_FILE` (`guard/integrity.py`).
- **Stale Lock Recovery & Doctor:** Automatic recovery for crash-induced unshielded states and `agy-guard doctor [--fix]` diagnostic routine (`guard/os_adapter.py`, `guard/cli.py`).
- **Cross-Platform CI Matrix:** Automated GitHub Actions workflows for Linux, macOS, and Windows (`.github/workflows/ci.yml`).

## [1.2.2] - 2026-09-19
### Maintenance
- Synchronized upstream skill commits (chisle, everything-claude-code) and canonical manifest update.

## [1.2.1] - 2026-09-19
### Hardened
- Atomic lock-aware mutations for baseline and snapshot operations while write shield is engaged.

## [1.2.0] - 2026-09-19
### Added
- **Antigravity Guard Suite:** Cross-platform OS write protection, cryptographic FIM, lightweight snapshots, and Desktop GUI (`guard/`).

## [1.1.0] - 2026-09-19
### Added
- **Universal Bidirectional AI Agent Bridge (`porter.py`):** Lossless rule, skill, and agent transpiler supporting Claude Code, Cursor, Aider, Universal `AGENTS.md`, and generic platforms.
- **Pre-Flight Suitability & Adaptability Analyzer (`porter/analyzer.py`):** Scoring engine (0–100) evaluating constitutional alignment and platform compatibility prior to file creation or mutation.
- **Constitutional Sanitizer (`porter/sanitizer.py`):** Automated sanitization stripping sycophantic instructions, conversational fluff, and test-weakening directives from imported rules.
- **Lossless Universal Canonical Manifest Engine (`porter/manifest.py` & `.harness/manifest.json`):** Single-source compilation capturing the entire harness state.
- **SSRF Network Immunity:** Strict RFC-1918, link-local metadata (169.254.169.254), loopback, and IPv6 DNS resolution validation in remote rule fetching.
- **Rule 16 External Rule Ingestion Invariant:** Codified external rule ingestion gates in `GEMINI.md`.
- **`vibecoder` Skill:** Product-first, vibe-oriented rapid prototyping skill for non-coders and exploratory builders.
- **`research` Subagent:** Isolated read-only subagent for heavy documentation and external API schema ingestion without parent context pollution.

## [1.0.4] - 2026-09-19
### Added & Hardened
- **Universal Cross-Platform Installers:** Zero-dependency `install.py` supporting Windows, Linux, macOS, and FreeBSD with NTFS junction and copy fallbacks, alongside strict POSIX `install.sh`.
- **Popper's Falsification Gate (Rule 8):** Added deterministic baseline checks and edge verification requirement before concluding null-action or task completion.
- **Out-of-Band Meta-Diagnosis (Rule 13):** Added circuit breaker escalation dispatching isolated diagnostic subagents (`Model: 'pro'`) upon repeating failures.
- **Session Boundary & Handoff Protocol:** Standardized `HANDOFF.template.md` at project root for Tier 2/3 task continuity and context saturation freezes (>25 turns).

## [1.0.3] - 2026-09-19
### Added & Hardened
- **Circuit Breaker & Oscillation Guard (Rule 13):** Constrained modifications to ~10% blast cap per fix pass, added automatic detection for repeating tool loops and A/B oscillation, forcing immediate halt and hypothesis revision.
- **Session Boundary Protocol (Rule 8 & harness):** Codified session boundary recommendation after major deliveries to mitigate attention rot and token degradation.
- **Multi-Session Continuity & Handoff:** Standardized continuity sections in workspace `tasks.md` and enforced vertical slices discipline across architectural layers.

## [1.0.2] - 2026-09-19
### Hardened & Fixed
- **Subagent Safety Alignment:** Aligned `build-error-resolver` with read-only architecture and Rule 12 safety invariants.
- **Watchdog Concurrency & Timeouts:** Increased `hooks.json` timeout to 15s and parallelized `upstream_watcher.py` with ThreadPoolExecutor.
- **Platform Plan Gating:** Aligned `GEMINI.md` and `harness/SKILL.md` with Antigravity native `implementation_plan` artifacts and auto-scaffolded `MISTAKES.md`.
- **Symlink Normalization:** Decoupled nested circular symlinks across `antislop/skills/` and updated `deep-grill` tracking keys.

## [1.0.1] - 2026-09-19
### Changed & Hardened
- **User Interaction Language (Rule 6):** Refactored constitution to communicate in the user's prompt language while internal system directives, engineering rigor, computational gates, and invariants remain canonical in English.
- **Upstream & Platform Collision Invariant (Rule 15):** Enforced unconditional precedence of local constitutional rules and custom skills over upstream runtime prompts and directive drift.
- **Failure Logging Protocol (`MISTAKES.md`):** Automated structured logging for regressions, root-cause analyses, impacts, and preventive invariants.

## [1.0.0] - 2026-09-19
### Added
- **Initial Release of Antigravity Harness:** Production-grade engineering harness, behavioral constitution, and autonomous multi-agent ecosystem for Google Antigravity.
- **Global Behavioral Constitution (`GEMINI.md`):** Discourse & Communication Principles (Rule 1-6), Epistemic Objectivity & Anti-Sycophancy (Rule 7-8), Proportional Gate Escalation (Tier 1/2/3), Goodhart's Immutable Test Invariant (Rule 9), and Process & Context Hygiene (Rule 10-14).
- **Core Autonomous Subagents:** `consistency-auditor`, `specification-gap-auditor`, `security-boundary-verifier`, `silent-failure-hunter`, `build-error-resolver`.
- **Engineering Skill Ecosystem (17 Built-in Skills):**
  - `harness`: Autonomous engineering harness, computational verification gates, task lifecycle.
  - `audit`: Structural, consistency, and security boundary audit engine.
  - `deep-grill`: Relentless architectural trade-off and edge-case interview engine.
  - `diagnosing-bugs`: Seven-phase root-cause analysis and reproducible feedback loops.
  - `security-review`: Defensive security review, vulnerability scanners, and OWASP checklists.
  - `antislop` Suite: Comprehensive UI quality filter (38 rules, WCAG AA contrast, layout mobile, copywriting, and comment hygiene).
  - `procoder` & `unlazy`: Tier-3 depth completion engines, acceptance gates, and sprint chains.
  - `architecture-decision-records`: Automated architectural decision log.
  - `silk-design`: Kinetic motion, fluid typography, and design token toolbox.
  - `chisle`: Maximum-efficiency, minimal-fluff dev mode.
  - `database-migrations`: Schema change patterns, rollbacks, and zero-downtime deployments.
  - `upstream-auditor`: Staging and model drift auditor tracking 7 community skill repositories.
- **Design Contract (`DESIGN.md`):** Default engineering baseline (ENERGY 2 / RHYTHM 2 / MOTION 2, Dark Zinc palette, 5 mandatory component states, zero mobile horizontal overflow).
