# Changelog

All notable changes to Antigravity Harness are documented in this file.

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
