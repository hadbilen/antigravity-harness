# ADR-0001: Hardened v2.0.0 Governance Scope, Workflow Sandbox, Sealed Test-Boundary, Kernel Locking, and Read-Only Subagent Contract

**Date**: 2026-10-24
**Status**: accepted
**Deciders**: Human Operator (`hadbilen`), Antigravity Harness Maintainers

## Context

The v2.0.0 security, forensic, and cognitive audit (`#01`–`#25` in `tasks.md`) demonstrated five structural boundary gaps across `guard/`, `hooks.json`, `install.py`, and `agents/*.md`:
1. While `~/.gemini/config/` governance artifacts were OS-locked and tracked by `FileIntegrityMonitor` (FIM), the active hook/CLI execution payloads in `data_dir() / "runtime"` (`~/.local/share/antigravity-harness/runtime`) and user-level CLI launchers (`~/.local/bin/{agy-guard,agy-porter,porter}` and Windows `%LOCALAPPDATA%\Programs\antigravity-guard\*`) remained writable (`0755`/`0644`) and outside FIM scope (`#04`), allowing hook tampering without touching `~/.gemini/config/`.
2. `_inspect_workflow_script` in `guard/agy_hooks.py` enforced module restrictions only when `root_mod in _STDLIB_MODULES`, allowing `run_workflow` scripts to import local packages (`guard.os_adapter`, `porter`) or third-party libraries directly, while `invoke_subagent` was absent from `PreToolUse` `matcher`, permitting model-downgrade delegation (`flash` / `flash_lite`) on governance edits (`#03`, `#15c`).
3. `TestBoundaryGuard.verify()` merged human-sealed `snap_auth` with live working-tree `tasks.md` (`## Authorized Test Modifications`) using bare `basename` fallback, enabling an unprivileged agent write to `tasks.md` to self-authorize existing test mutations (`#06`).
4. `guard/paths.py` (`file_lock`) unlinked its `.lock` file in `finally` and evicted `0`-byte files only after `30s`, creating mutual lock-eviction races and stalls when a process crashed between `O_EXCL` creation and PID write (`#11`).
5. Antigravity 2.0 custom subagents ignore `1.x` `tools:` allowlists and default to `access: full` unless `access: read-only` is declared (`#25`), leaving `meta-auditor` and `build-error-resolver` writable when invoked directly.

The decision-driving constraint across all five seams is **non-bypassable human authority over governance, runtime hooks, and test baselines** using strictly the Python standard library on Linux, macOS, and Windows.

## Decision

We adopt five coordinated Tier-3 architectural invariants for v2.0.0:
1. **Unified Governance, Runtime & Launcher Protection (`#04`, `#07`, `#08`):** Include `data_dir() / "runtime"` and installed launcher executables inside the global `"antigravity"` `TargetEnvironment` OS-lock and `FileIntegrityMonitor` baseline scope (when rooted at `config_dir()`), re-baseline FIM after launcher/binary installation, preserve `0o600` (`0o400` when locked) on `mcp_config.json`, enforce `0o700` on snapshot/backup directories, and exclude `config.json*` / `mcp_config.json.*` from `SnapshotEngine`.
2. **Default-Deny Workflow Imports & Subagent Model Gate (`#02`, `#03`, `#15c`):** Enforce strict default-deny (`root_mod not in _ALLOWED_STDLIB_WORKFLOW_MODULES`, permitting `__future__`) across all `ast.Import` and `ast.ImportFrom` nodes in `run_workflow`, fail closed on malformed `PreToolUse` JSON / non-dict `toolCall.args` / split `send_command_input` streams, and add `invoke_subagent` to `PRE_TOOL_USE_MATCHER_TOOLS` and `hooks.json` so governance/customization delegations cannot downgrade below the top catalog reasoning model.
3. **Human-Sealed `TestBoundaryGuard` Trust Boundary (`#06`, `#17a`):** Gate any `PreToolUse` file edit or shell mutation touching `## Authorized Test Modifications` in `tasks.md` with `"force_ask"`, restrict `TestBoundaryGuard.verify()` to trust only human-sealed `snap_auth` (or committed `base_ref:tasks.md`) plus explicit CLI `authorized_modifications` using normalized workspace-relative paths (never bare `basename`), and extend `tdd`-mode AST weakening detection to `globals()`/`vars()`/`__dict__` subscript mutation, `setattr(sys.modules[...])`, and `pytest_*` hook definitions.
4. **Kernel Advisory `file_lock` & Monotonic Lease Finalization (`#11`):** Replace `O_EXCL` create-and-unlink locking in `guard/paths.py` with persistent-inode kernel advisory locks (`fcntl.flock` on POSIX, `msvcrt.locking` on Windows) without unlinking the lock file on release, and enforce monotonic terminal transitions (`STATE_CLOSING` / deleted record rejection plus watcher PID deduplication/termination) in `LeaseManager`.
5. **Antigravity 2.0 `access: read-only` Subagent Contract (`#25`):** Declare `access: read-only` in `agents/meta-auditor.md` and `agents/build-error-resolver.md`, shifting deterministic script execution (`meta_audit.py`) to the orchestrating parent agent before or alongside auditor dispatch.

## Alternatives Considered

### Alternative 1: Protect Only `~/.gemini/config/` and Rely on `PreToolUse` Regex Denies for `runtime/` and Launchers
- **Pros**: Zero changes to `EnvironmentRegistry`, `FileIntegrityMonitor`, or `install.py` upgrade/unlock ordering.
- **Cons**: Leaves `data_dir() / "runtime/guard/agy_hooks.py"` and `~/.local/bin/agy-guard` writable (`0644`/`0755`) at the OS level and unmonitored by `agy-guard verify`, so any unhooked process or novel shell indirection can overwrite the hook runner itself.
- **Why not**: Violates defense-in-depth; a single critical failure mode (silent tampering with the live hook executable) outweighs installer simplicity.

### Alternative 2: Blocklist Known Local Modules (`guard`, `porter`) in `_inspect_workflow_script` Instead of Default-Deny
- **Pros**: Allows arbitrary third-party or workspace helper imports inside `run_workflow` scripts.
- **Cons**: Any workspace module or installed package (`pathlib`-wrapping helpers, `http`/`urllib` wrappers, `ctypes`-backed wheels) becomes an immediate `PreToolUse` escape hatch.
- **Why not**: `GEMINI.md` Rule 15e defines `run_workflow` strictly as orchestration glue; default-deny over `_ALLOWED_STDLIB_WORKFLOW_MODULES` eliminates entire classes of import-based sandbox escapes.

### Alternative 3: Cryptographically Sign `tasks.md` In-Place Instead of Sealing `snap_auth` + `PreToolUse` `force_ask`
- **Pros**: Detects unapproved `tasks.md` authorization edits even without an active `TestBoundaryGuard` snapshot.
- **Cons**: Requires managing per-workspace HMAC secrets or keyrings and breaks normal human Markdown editing of `tasks.md`.
- **Why not**: Combining `PreToolUse` `"force_ask"` on `## Authorized Test Modifications` with human-sealed `snap_auth` inside `TestBoundaryGuard.verify()` (and `base_ref:tasks.md` in git-ref mode) achieves the exact trust boundary with zero secret-management overhead.

### Alternative 4: Keep `O_EXCL` Lockfiles with Shorter Stale-Empty Eviction (`0.5s` Instead of `30s`)
- **Pros**: Minimal diff in `guard/paths.py`.
- **Cons**: Any GC pause or I/O scheduling delay exceeding `0.5s` between `os.open` and `os.write` lets a second contender unlink an active lockfile, breaking mutual exclusion across concurrent hook invocations.
- **Why not**: Kernel advisory locking (`flock` / `msvcrt.locking`) is automatically released by the OS kernel on process crash (`SIGKILL`) and never requires unlinking the inode.

## Consequences

### Positive
- Live hook code (`runtime/`), CLI launchers, and `~/.gemini/config/` share a single OS-permission and cryptographic FIM boundary.
- Agents can neither self-authorize test mutations via `tasks.md`, smuggle admin commands via quoted tokens or split `send_command_input`, nor delegate governance edits to downgraded subagent models.
- Concurrent `PreInvocation`, `PreToolUse`, `Stop`, and `LeaseManager` operations acquire kernel locks without `30s` dead-PID stalls or unlink races.

### Negative
- Re-running `install.py` or human maintenance leases must unlock and re-lock `runtime/` and launcher paths alongside `~/.gemini/config/`.
- Authorizing a legacy test contract change during a snapshot-guarded run requires either passing `--authorize <rel_path>` or human-sealing `tasks.md` via `agy-guard test-boundary snapshot` after approving the `force_ask` prompt.

### Risks
- **Risk**: Hermetic test suites sharing a process-wide `HOME` / `XDG_DATA_HOME` could leave `runtime/` or launcher files read-only (`0444`/`0555`) if an environment lock targets custom temporary config roots.
- **Mitigation**: Attach `data_dir() / "runtime"` and user launcher paths only to the canonical global `"antigravity"` environment rooted at `config_dir()`, and teach `install.py` (`_release_legacy_tree`) to restore owner write bits before rotating `runtime.prev` or overwriting launchers.
