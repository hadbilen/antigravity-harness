"""
guard/doctor.py — Health diagnosis for an environment's governance scope (headless, testable).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

The CLI (`agy-guard doctor`) only renders a DoctorReport; the checks live here so they can
be exercised without a terminal.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from guard.environment import AgentEnvironment, EnvironmentRegistry, RegistryError
from guard.integrity import FileIntegrityMonitor, IntegrityReport
from guard.notifier import load_settings
from guard.paths import move_aside, state_dir


def recover_or_load_registry(
    config_path: Optional[Path] = None,
    *,
    recover: bool = False,
    os_adapter=None,
) -> Tuple[EnvironmentRegistry, Optional[Path]]:
    """Loads EnvironmentRegistry; when `recover=True` and corrupt, quarantines via `move_aside` and re-initializes."""
    try:
        return EnvironmentRegistry(config_path=config_path, os_adapter=os_adapter), None
    except RegistryError as orig_err:
        if not recover:
            raise
        reg_path = Path(config_path).resolve() if config_path is not None else (state_dir() / "environments.json")
        legacy_path = Path.home() / ".gemini" / ".environments.json"
        target = reg_path if os.path.lexists(reg_path) else (legacy_path if os.path.lexists(legacy_path) else reg_path)
        if os.path.lexists(target) and not os.path.islink(target):
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        quarantined = move_aside(target, tag="corrupt")
        if quarantined is None and os.path.lexists(target):
            raise orig_err
        reg = EnvironmentRegistry(config_path=config_path, os_adapter=os_adapter)
        reg.save()
        return reg, quarantined


@dataclass
class DoctorReport:
    env: AgentEnvironment
    root: Path
    monitor: FileIntegrityMonitor
    issues: List[str]
    report: IntegrityReport
    warnings: List[str] = field(default_factory=list)
    infos: List[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.issues and self.report.is_intact and not self.warnings


def world_writable_ancestors(path: Path, depth: int = 3) -> List[str]:
    """Ancestors (up to `depth`) that any local user may write to (sticky dirs such as /tmp excluded)."""
    if os.name == "nt":
        return []  # st_mode carries no ACL information on Windows; every path would look world-writable
    found = []
    current = Path(os.path.realpath(path))
    for _ in range(depth + 1):
        try:
            mode = os.stat(current).st_mode
            # Sticky world-writable dirs (/tmp) do not let other users replace our entries.
            if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                found.append(str(current))
        except OSError:
            break
        if current.parent == current:
            break
        current = current.parent
    return found


def grant_statistics(config_json: Path) -> Optional[dict]:
    """Counts risky permission grants WITHOUT printing their contents."""
    try:
        data = json.loads(config_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    user_settings = data.get("userSettings")
    if user_settings is None:
        user_settings = {}
    elif not isinstance(user_settings, dict):
        return None
    grants = user_settings.get("globalPermissionGrants")
    if grants is None:
        grants = {}
    elif not isinstance(grants, dict):
        return None
    allow = grants.get("allow")
    if allow is None:
        allow = []
    elif not isinstance(allow, list):
        return None
    entries = [e if isinstance(e, str) else json.dumps(e) for e in allow]
    governance_markers = (".gemini/config", ".gemini/antigravity-harness")
    return {
        "total": len(entries),
        "governance_writes": sum(1 for e in entries if e.startswith("write_file") and any(m in e for m in governance_markers)),
        "secret_like": sum(1 for e in entries if re.search(r"(token|api[_-]?key|secret|password)=", e, re.I)),
        "unsandboxed": sum(1 for e in entries if e.startswith("unsandboxed")),
        "oversized": sum(1 for e in entries if len(e) > 500),
    }


def _iter_hook_commands(node: object) -> List[str]:
    cmds: List[str] = []
    if isinstance(node, dict):
        cmd = node.get("command")
        if isinstance(cmd, str) and cmd.strip():
            cmds.append(cmd.strip())
        for v in node.values():
            cmds.extend(_iter_hook_commands(v))
    elif isinstance(node, list):
        for item in node:
            cmds.extend(_iter_hook_commands(item))
    return cmds


def _check_plugins_symlinks(root: Path, warnings: List[str]) -> None:
    """Warns if writable `plugins/` (or `.agents/skills/`) or any entry inside it is a symlink (without following symlinks)."""
    for rel_dir, label in (("plugins", "plugins/"), (".agents/skills", ".agents/skills/")):
        sub_dir = root / rel_dir
        if os.path.islink(sub_dir):
            status_tag = "dangling" if not os.path.exists(sub_dir) else "external/resolved"
            warnings.append(
                f"{label} directory is a symlink ({status_tag}: {sub_dir}); copy-mode protections cannot lock symlinked plugin roots."
            )
            continue
        try:
            if not sub_dir.is_dir():
                continue
        except OSError as exc:
            warnings.append(f"Failed to scan {label} for symlinks: {exc}")
            continue
        symlinks: List[str] = []
        walk_errors: List[str] = []

        def _on_walk_error(err: OSError, _lbl: str = label) -> None:
            walk_errors.append(f"Failed to scan {_lbl} for symlinks: {err}")

        try:
            for cur_root, dirs, files in os.walk(sub_dir, followlinks=False, onerror=_on_walk_error):
                cur_path = Path(cur_root)
                kept_dirs: List[str] = []
                for d in sorted(dirs):
                    entry = cur_path / d
                    if os.path.islink(entry):
                        status_tag = "dangling" if not os.path.exists(entry) else "external/resolved"
                        symlinks.append(f"{entry.relative_to(root).as_posix()} ({status_tag})")
                    else:
                        kept_dirs.append(d)
                dirs[:] = kept_dirs
                for f in sorted(files):
                    entry = cur_path / f
                    if os.path.islink(entry):
                        status_tag = "dangling" if not os.path.exists(entry) else "external/resolved"
                        symlinks.append(f"{entry.relative_to(root).as_posix()} ({status_tag})")
        except OSError as exc:
            warnings.append(f"Failed to scan {label} for symlinks: {exc}")
            continue
        warnings.extend(walk_errors)
        if symlinks:
            preview = ", ".join(symlinks[:10])
            suffix = f" (+{len(symlinks) - 10} more)" if len(symlinks) > 10 else ""
            warnings.append(
                f"Symlink entry detected under writable {label} directory: {preview}{suffix} "
                "(copy-mode protections do not lock symlink targets)."
            )


def _check_hooks_and_runtime_state(root: Path, warnings: List[str], infos: List[str]) -> None:
    import shlex
    from guard import __version__

    hooks_file = root / "hooks.json"
    if hooks_file.is_file():
        try:
            hooks_data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            hooks_data = None
        if not isinstance(hooks_data, dict):
            warnings.append(f"Lifecycle hooks configuration {hooks_file} is not a valid JSON object.")
        else:
            if "upstream-watchdog" not in hooks_data:
                warnings.append(f"Lifecycle hooks configuration {hooks_file} is missing 'upstream-watchdog'.")
            if "harness-gate" not in hooks_data:
                warnings.append(
                    f"Lifecycle hooks configuration {hooks_file} is missing 'harness-gate' (PreInvocation/PreToolUse/Stop)."
                )
            seen_missing = set()
            for cmd in _iter_hook_commands(hooks_data):
                try:
                    tokens = shlex.split(cmd, posix=(os.name != "nt"))
                except ValueError:
                    tokens = cmd.split()
                for tok in tokens:
                    cleaned = tok.strip("\"'")
                    if cleaned.endswith(".py"):
                        script_path = Path(cleaned) if Path(cleaned).is_absolute() else (root / cleaned)
                        if not script_path.is_file() and cleaned not in seen_missing:
                            seen_missing.add(cleaned)
                            warnings.append(
                                f"Lifecycle hook script referenced in {hooks_file.name} does not exist: {cleaned}"
                            )
            if "upstream-watchdog" in hooks_data and "harness-gate" in hooks_data and not seen_missing:
                infos.append("Native lifecycle hooks ('upstream-watchdog' & 'harness-gate') are registered in hooks.json.")
    elif root.is_dir():
        repair_hint = _repair_command_hint()
        has_harness_tree = (
            (root / "skills").is_dir()
            or (root / "agents").is_dir()
            or (state_dir() / "install_receipt.json").is_file()
        )
        if has_harness_tree:
            warnings.append(f"Lifecycle hooks configuration {hooks_file} is missing; native hooks are inactive (run {repair_hint}).")
        else:
            infos.append(f"Lifecycle hooks configuration {hooks_file} is not present; native hooks are inactive (run {repair_hint}).")

    strikes_file = state_dir() / "hook_strikes.json"
    if strikes_file.is_file():
        try:
            strikes = json.loads(strikes_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            strikes = None
        if not isinstance(strikes, dict):
            warnings.append(f"Stop-hook circuit-breaker ledger {strikes_file} is corrupt or not a JSON object.")
        else:
            tripped: List[str] = []
            malformed_strikes = False
            for k, v in strikes.items():
                if not isinstance(v, dict):
                    malformed_strikes = True
                    continue
                try:
                    if int(v.get("count", 0) or 0) >= 3:
                        tripped.append(str(k))
                except (TypeError, ValueError):
                    malformed_strikes = True
            if malformed_strikes:
                warnings.append(f"Stop-hook circuit-breaker ledger {strikes_file} contains malformed strike count(s).")
            if tripped:
                warnings.append(
                    f"Stop-hook circuit breaker reached max strikes (>= 3) for {len(tripped)} session(s) in {strikes_file}."
                )

    receipt_file = state_dir() / "install_receipt.json"
    if receipt_file.is_file():
        try:
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            receipt = None
        if not isinstance(receipt, dict):
            warnings.append(f"Install receipt {receipt_file} is corrupt or not a JSON object.")
        else:
            installed_entries = receipt.get("installed")
            if installed_entries is not None and not isinstance(installed_entries, list):
                warnings.append(f"Install receipt {receipt_file} field 'installed' is not a JSON list.")
            installed_ver = receipt.get("version")
            if installed_ver and str(installed_ver) != str(__version__):
                warnings.append(
                    f"Install receipt version ({installed_ver}) in {receipt_file} does not match active Guard version ({__version__})."
                )

    upstream_file = state_dir() / "upstream_state.json"
    if upstream_file.is_file():
        try:
            upstream_data = json.loads(upstream_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            upstream_data = None
        if not isinstance(upstream_data, dict):
            warnings.append(f"Upstream watchdog state file {upstream_file} is corrupt or not a JSON object.")
        else:
            if "tracked_repositories" in upstream_data and not isinstance(upstream_data.get("tracked_repositories"), dict):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'tracked_repositories' is not a JSON object."
                )
            if "pending_repo_updates" in upstream_data and not isinstance(upstream_data.get("pending_repo_updates"), dict):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'pending_repo_updates' is not a JSON object."
                )
            if (
                "known_placeholder_models" in upstream_data
                and upstream_data.get("known_placeholder_models") is not None
                and not isinstance(upstream_data.get("known_placeholder_models"), dict)
            ):
                warnings.append(
                    f"Upstream watchdog state file {upstream_file} field 'known_placeholder_models' is not a JSON object."
                )
            if upstream_data.get("last_audit_failed"):
                warnings.append(f"Last upstream repository audit failed in {upstream_file}; check network/rate-limit status.")

    # Check for unmanaged top-level ~/.gemini/GEMINI.md or ~/.gemini/AGENTS.md shadowing ~/.gemini/config/
    if root.name == "config" and root.parent.name == ".gemini":
        for top_md_name in ("GEMINI.md", "AGENTS.md"):
            top_md = root.parent / top_md_name
            if top_md.is_file() or os.path.islink(top_md):
                warnings.append(
                    f"Top-level {top_md} exists alongside {root} and may shadow or duplicate global rules in "
                    f"{root / 'GEMINI.md'}."
                )
    _check_workspace_hooks_collision(root, warnings)


def _check_workspace_hooks_collision(ws_root: Path, warnings: List[str]) -> None:
    """Warns if `<ws_root>/.agents/hooks.json` defines or overrides `harness-gate` or `upstream-watchdog`."""
    for rel_ws_hooks in (".agents/hooks.json", ".agent/hooks.json", "_agents/hooks.json", "_agent/hooks.json"):
        ws_hooks_file = ws_root / rel_ws_hooks
        if ws_hooks_file.is_file():
            try:
                ws_hooks_data = json.loads(ws_hooks_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                warnings.append(
                    f"Workspace lifecycle hooks file {rel_ws_hooks} ({ws_hooks_file}) is not a valid JSON object."
                )
                continue
            if isinstance(ws_hooks_data, dict):
                colliding_keys = [k for k in ("harness-gate", "upstream-watchdog") if k in ws_hooks_data]
                if colliding_keys:
                    warnings.append(
                        f"Workspace lifecycle hooks file {rel_ws_hooks} ({ws_hooks_file}) defines {colliding_keys}, which may "
                        "override or disable global Antigravity Harness lifecycle hooks."
                    )


def _repair_command_hint() -> str:
    has_install_py = (Path(__file__).resolve().parent.parent / "install.py").is_file()
    if has_install_py and not os.environ.get("ANTIGRAVITY_SHARE_DIR"):
        return "'python3 install.py'"
    return "'agy-guard init'"


def _is_home_or_ancestor(path: Path) -> bool:
    try:
        resolved = path.resolve()
        home_resolved = Path.home().resolve()
    except OSError:
        return False
    return resolved == home_resolved or home_resolved.is_relative_to(resolved)


def diagnose(env: AgentEnvironment, registry: EnvironmentRegistry, sentinel_active: Optional[bool] = None) -> DoctorReport:
    """Runs every read-only health check for `env`. `sentinel_active` may be injected by callers/tests."""
    root = env.get_root()
    monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
    result = DoctorReport(env=env, root=root, monitor=monitor, issues=registry.protection_issues(env), report=monitor.verify())
    warnings, infos = result.warnings, result.infos

    if not env.is_global:
        if not root.exists():
            warnings.append(
                f"Workspace root {root} for environment '{env.id}' does not exist "
                f"(remove stale entry with 'agy-guard env remove {env.id}')."
            )
        elif _is_home_or_ancestor(root):
            warnings.append(
                f"Non-global environment '{env.id}' is rooted at home/ancestor directory {root} rather than a project workspace "
                f"(review or remove with 'agy-guard env remove {env.id}')."
            )
        else:
            _check_workspace_hooks_collision(root, warnings)

    if result.issues:
        warnings.append(f"Governance scope is not fully write-protected ({len(result.issues)} issue(s)); first: {result.issues[0]}")
    if not result.report.is_intact:
        warnings.append(f"Integrity: {result.report.summary()}")
    if not monitor.is_isolated:
        warnings.append(f"Baseline is stored inside the protected tree ({monitor.state_file}).")
    legacy_baseline = root / ".guard_integrity.json"
    if legacy_baseline.exists():
        warnings.append(f"Legacy baseline {legacy_baseline} is no longer used; remove it after 'agy-guard rebaseline'.")
    legacy_snaps = root / ".guard_snapshots"
    if legacy_snaps.exists():
        warnings.append(
            f"Legacy snapshots in {legacy_snaps} may contain copies of config.json (permission grants, tokens). "
            f"Review and delete them manually."
        )
    moved_legacy = state_dir() / "legacy"
    if moved_legacy.is_dir() and any(moved_legacy.iterdir()):
        warnings.append(
            f"Legacy Guard data moved out of the config tree by the installer is kept in {moved_legacy}; "
            f"it may contain copies of config.json (tokens). Delete it once reviewed."
        )
    backups = sorted(p.name for p in root.glob("backup_*"))
    if backups:
        warnings.append(f"Installer backups inside the config tree: {', '.join(backups)} (move them out).")
    for p in env.get_governance_paths(existing_only=True):
        if os.path.islink(p):
            repair_hint = _repair_command_hint()
            warnings.append(
                f"{p.name} is a symlink (symlink installs cannot be locked); reinstall in copy mode with {repair_hint}."
            )
            break
    writable_sources = set()
    for p in env.get_governance_paths(existing_only=True):
        writable_sources.update(world_writable_ancestors(p))
    if writable_sources:
        warnings.append(f"World-writable locations hold governance content: {', '.join(sorted(writable_sources)[:5])}")
    if env.is_global:
        config_file = root / "config.json"
        stats = grant_statistics(config_file)
        if config_file.is_file() and stats is None:
            warnings.append(f"Antigravity configuration {config_file} is corrupt or not a JSON object.")
        if stats and (stats["governance_writes"] or stats["secret_like"]):
            warnings.append(
                f"Antigravity permission grants: {stats['total']} total, {stats['governance_writes']} persistent write grant(s) "
                f"to governance paths, {stats['secret_like']} containing secret-like values, {stats['unsandboxed']} unsandboxed. "
                f"Review them in Antigravity settings and rotate any exposed tokens."
            )
        _check_hooks_and_runtime_state(root, warnings, infos)
        _check_plugins_symlinks(root, warnings)
        missing_ws: List[str] = []
        home_ws: List[str] = []
        for other in registry.list_environments():
            if other.is_global:
                continue
            other_root = other.get_root()
            if not other_root.exists():
                missing_ws.append(f"{other.id} ({other_root})")
            elif _is_home_or_ancestor(other_root):
                home_ws.append(f"{other.id} ({other_root})")
            else:
                _check_workspace_hooks_collision(other_root, warnings)
        if missing_ws:
            warnings.append(
                f"Registered environment(s) point to missing workspace directories: {', '.join(missing_ws)} "
                f"(clean up with 'agy-guard env remove <id>')."
            )
        if home_ws:
            warnings.append(
                f"Non-global workspace environment(s) are rooted at home/ancestor directory: {', '.join(home_ws)} "
                f"(review or remove with 'agy-guard env remove <id>')."
            )
    watcher_log = state_dir() / "logs" / "lease-watcher.log"
    if watcher_log.is_file():
        try:
            tail = watcher_log.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        if "RELOCK FAILED" in tail or "Traceback" in tail:
            warnings.append(f"The auto-relock watcher reported errors recently; see {watcher_log}.")
    if sentinel_active is None:
        from guard.startup import StartupManager
        sentinel_active = bool(StartupManager(root).status().get("active"))
    if not sentinel_active:
        infos.append("Boot sentinel is not enabled ('agy-guard startup enable').")
    if not load_settings().get("enabled", True):
        infos.append("Desktop notifications are disabled ('agy-guard notify enable'); security events still go to the audit log.")
    return result
