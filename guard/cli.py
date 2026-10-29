"""
guard/cli.py — Command-Line Interface for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Administration commands that weaken protection or change what Guard does (init, init --uninstall,
unlock, rebaseline, snapshot restore/prune, startup enable/disable, env add/remove, lowering an
environment policy, doctor --fix/--recover, disabling notifications, porter stage, test-boundary
re-snapshot, and --authorize overrides) require human operator authorization. Interactive terminal
confirmations exit with code 3 when missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from guard import __version__
from guard.approval import refusal_message, request_approval
from guard.audit_log import audit
from guard.doctor import diagnose, recover_or_load_registry
from guard.environment import (
    ANTIGRAVITY_RUNTIME_ENTRIES,
    VALID_POLICIES,
    AgentEnvironment,
    EnvironmentRegistry,
    RegistryError,
)
from guard.integrity import FileIntegrityMonitor, IntegrityReport
from guard.lease import MAX_LEASE_SECONDS, MIN_LEASE_SECONDS, LeaseManager
from guard.notifier import GuardNotifier, NotificationSeverity, load_settings, save_settings, settings_file
from guard.paths import atomic_write_json, config_dir, copy_entry, data_dir, read_json, state_dir
from guard.porter_bridge import PorterBridge
from guard.provenance import RunProvenanceTracker
from guard.snapshot import SnapshotEngine
from guard.startup import StartupManager
from guard.test_boundary import TestBoundaryGuard
from guard.upstream import UpstreamAuditorBridge

EXIT_APPROVAL_REQUIRED = 3


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------
def _registry(args: Optional[argparse.Namespace] = None) -> EnvironmentRegistry:
    path = getattr(args, "registry", None) if args is not None else None
    return EnvironmentRegistry(config_path=Path(path) if path else None)


def _resolve(registry: EnvironmentRegistry, env_id: Optional[str]) -> Tuple[Optional[AgentEnvironment], str]:
    return registry.resolve_environment(env_id or "antigravity")


def _monitor(env: AgentEnvironment, registry: EnvironmentRegistry) -> FileIntegrityMonitor:
    return FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)


def _refuse(action: str) -> int:
    print(f"[APPROVAL REQUIRED] {refusal_message(action)}", file=sys.stderr)
    return EXIT_APPROVAL_REQUIRED


def _print_report_details(report: IntegrityReport, indent: str = "") -> None:
    if report.baseline_status not in ("ok", "pending_review"):
        for note in report.notes:
            print(f"{indent}Note: {note}")
        return
    for title, items, mark in (
        ("Modified Files", report.modified, "~"),
        ("Unauthorized Added Files", report.added, "+"),
        ("Deleted Files", report.deleted, "-"),
        ("Unreadable Files", report.unreadable, "!"),
    ):
        if items:
            print(f"\n{indent}{title}:")
            for f in items:
                print(f"{indent}  {mark} {f}")
    for note in report.notes:
        print(f"{indent}Note: {note}")


def _print_issues(issues: List[str], limit: int = 6) -> None:
    for issue in issues[:limit]:
        print(f"    - {issue}")
    if len(issues) > limit:
        print(f"    ... and {len(issues) - limit} more")


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_status(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    issues = registry.protection_issues(env) if env.policy == "enforced" else ["policy is not 'enforced'"]
    monitor = _monitor(env, registry)
    report = monitor.verify()
    model_info = UpstreamAuditorBridge().get_model_drift_status()
    leases = LeaseManager(registry=registry).list_leases()
    protected = not issues and report.is_intact

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} - Status        ")
    print("=" * 64)
    print(f"Platform       : {registry.os_adapter.get_platform_name()}")
    print(f"Protection     : {registry.os_adapter.protection_kind()}")
    print(f"Environment    : {env.name} ({env.id}) -> {env.get_root()}")
    if issues:
        print(f"Write Shield   : [UNPROTECTED] {len(issues)} issue(s):")
        _print_issues(issues)
    else:
        print("Write Shield   : [LOCKED] all governance entries write-protected")
    print(f"Integrity (FIM): {report.summary()}")
    location = "[ISOLATED]" if monitor.is_isolated else "[IN TARGET]"
    if not monitor.state_file.exists():
        location = "[MISSING]"
    print(f"Baseline       : {location} {monitor.state_file}")
    if leases:
        for lease in leases:
            print(f"Active Lease   : {lease.env_id} ({lease.state}, {int(lease.remaining_seconds)}s left, id {lease.lease_id})")
    print(f"Active Model   : {model_info['active_model']}")
    print(f"Overall State  : {'PROTECTED' if protected else 'ACTION REQUIRED'}")
    print("-" * 64)
    print("Multi-Environment Governance Matrix:")
    for item in registry.get_status_matrix():
        env_lock = "[LOCKED]" if item["is_locked"] else "[UNLOCKED]"
        print(f"  * {item['name']:<30} {env_lock:<10} ({item['policy']}, {item['file_count']} seams)")
    print("=" * 64)
    return 0 if protected else 1


def _resolve_init_source(explicit_source: Optional[str]) -> Optional[Path]:
    if explicit_source:
        cand = Path(explicit_source).expanduser().resolve()
        return cand if (cand / "GEMINI.md").is_file() and (cand / "skills").is_dir() else None
    env_share = os.environ.get("ANTIGRAVITY_SHARE_DIR", "").strip()
    if env_share:
        cand = Path(env_share).expanduser().resolve()
        return cand if (cand / "GEMINI.md").is_file() and (cand / "skills").is_dir() else None
    cli_path = Path(__file__).resolve()
    for cand in (
        Path("/usr/share/antigravity-harness"),
        cli_path.parent.parent.parent.parent / "share" / "antigravity-harness",
        cli_path.parent.parent,
    ):
        try:
            if (cand / "GEMINI.md").is_file() and (cand / "skills").is_dir():
                return cand.resolve()
        except OSError:
            continue
    return None


def _init_ignore(_src: str, names: List[str]) -> List[str]:
    return [n for n in names if n in ("__pycache__", ".pytest_cache", ".DS_Store") or n.endswith((".pyc", ".pyo"))]


def _release_init_tree(path: Path) -> None:
    if os.path.islink(path) or not path.is_dir():
        return
    for root, dirs, files in os.walk(path):
        for entry in [root] + [os.path.join(root, d) for d in dirs] + [os.path.join(root, f) for f in files]:
            if not os.path.islink(entry):
                try:
                    mode = os.lstat(entry).st_mode
                    if not (mode & 0o200):
                        os.chmod(entry, (mode & 0o7777) | 0o200)
                except OSError:
                    pass


def _trees_identical_init(src: Path, dest: Path) -> bool:
    """Returns True when real directory `dest` has identical relative entries and contents to `src`."""
    if not src.is_dir() or not dest.is_dir() or os.path.islink(dest):
        return False

    def _collect(root_dir: Path, apply_ignore: bool) -> Optional[Dict[str, tuple]]:
        entries: Dict[str, tuple] = {}
        try:
            for cur_root, dirs, files in os.walk(root_dir, followlinks=False):
                if apply_ignore:
                    ignored_dirs = set(_init_ignore(cur_root, dirs))
                    dirs[:] = [d for d in dirs if d not in ignored_dirs]
                    ignored_files = set(_init_ignore(cur_root, files))
                    files = [f for f in files if f not in ignored_files]
                dirs.sort()
                files.sort()
                cur_path = Path(cur_root)
                rel_dir = cur_path.relative_to(root_dir).as_posix()
                if rel_dir != ".":
                    entries[rel_dir] = ("dir",)
                for d in list(dirs):
                    dp = cur_path / d
                    if os.path.islink(dp):
                        rel = dp.relative_to(root_dir).as_posix()
                        entries[rel] = ("symlink", os.readlink(dp))
                        dirs.remove(d)
                for f in files:
                    fp = cur_path / f
                    rel = fp.relative_to(root_dir).as_posix()
                    if os.path.islink(fp):
                        entries[rel] = ("symlink", os.readlink(fp))
                    elif fp.is_file():
                        st = fp.stat()
                        entries[rel] = ("file", st.st_size, hashlib.sha256(fp.read_bytes()).hexdigest())
                    else:
                        return None
        except OSError:
            return None
        return entries

    src_map = _collect(src, apply_ignore=True)
    if src_map is None:
        return False
    dest_map = _collect(dest, apply_ignore=False)
    if dest_map is None:
        return False
    return src_map == dest_map


def _prune_named_backups(prefix: str, keep: int = 10) -> int:
    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        raise ValueError("keep must be an integer >= 1")
    backups_root = state_dir() / "backups"
    if not backups_root.is_dir() or os.path.islink(backups_root):
        return 0
    try:
        dirs = [p for p in backups_root.iterdir() if p.name.startswith(prefix) and p.is_dir() and not os.path.islink(p)]
    except OSError:
        return 0
    dirs.sort(key=lambda p: p.name)
    if len(dirs) <= keep:
        return 0
    removed = 0
    for old_dir in dirs[:-keep]:
        try:
            _release_init_tree(old_dir)
            shutil.rmtree(old_dir)
            removed += 1
        except OSError:
            pass
    return removed


def _uninstall_init_profile(args: argparse.Namespace, target_dir: Path, dry_run: bool) -> int:
    is_win = platform.system().lower() == "windows"
    print("=" * 64)
    print(f"  Antigravity Guard (agy-guard) v{__version__} - User Init Uninstall  ")
    print("=" * 64)
    print(f"Target : {target_dir}")
    print("-" * 64)

    if not dry_run:
        if not request_approval(
            "init --uninstall",
            f"Uninstall Antigravity Harness governance profile from {target_dir}?",
            [
                str(target_dir),
                "Custom user files, sidecars, and non-harness hooks in hooks.json are preserved.",
            ],
        ):
            return _refuse("init --uninstall")

    cleanup_failed = False
    reg_arg = getattr(args, "registry", None)
    reg_cfg = Path(reg_arg) if reg_arg else None
    if dry_run:
        try:
            registry = EnvironmentRegistry(config_path=reg_cfg)
        except RegistryError as exc:
            print(f"[DRY-RUN] corrupt environment registry ({exc}) would be quarantined")
            registry = EnvironmentRegistry(config_path=target_dir / ".dry_run_nonexistent_environments.json")
    else:
        registry, quarantined = recover_or_load_registry(config_path=reg_cfg, recover=True)
        if quarantined is not None:
            print(f"[RECOVERED] Quarantined corrupt environment registry -> {quarantined}")

    env = registry.get_environment("antigravity")
    if env is None or Path(env.get_root()).resolve() != target_dir:
        env = AgentEnvironment(
            id="antigravity",
            name="Antigravity Global Config",
            platform_type="antigravity",
            root_path=str(target_dir),
            policy="enforced",
        )

    try:
        startup_mgr = StartupManager(target_dir=target_dir, registry=registry)
        st_status = startup_mgr.status()
        if st_status.get("installed") or st_status.get("active"):
            if dry_run:
                print(f"[DRY-RUN] disable boot sentinel ({st_status.get('target_path')})")
            else:
                ok_dis, msg_dis = startup_mgr.disable()
                if ok_dis:
                    print(f"[DISABLED] Boot sentinel: {msg_dis}")
                else:
                    print(f"[ERROR] Could not disable boot sentinel: {msg_dis}", file=sys.stderr)
                    cleanup_failed = True
    except Exception as exc:
        print(f"[WARN] Boot sentinel check failed: {exc}", file=sys.stderr)

    if not dry_run:
        lease_mgr = LeaseManager(registry=registry)
        try:
            if lease_mgr.get_active_lease("antigravity") is not None:
                lease_mgr.complete_lease(env_id="antigravity", interactive=False)
        except Exception:
            pass
        if registry.get_environment("antigravity") is not None:
            ok_u, msg_u = registry.unlock("antigravity")
            if not ok_u and target_dir.exists():
                print(f"[WARN] Could not unlock antigravity environment: {msg_u}", file=sys.stderr)
        if os.path.lexists(target_dir) and not os.path.islink(target_dir):
            registry.os_adapter.unlock(target_dir, recursive=True)
            _release_init_tree(target_dir)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    uninstall_backup = state_dir() / "backups" / f"uninstall_{stamp}"

    def _stash_entry(entry: Path, rel_name: Path) -> None:
        dest = uninstall_backup / rel_name
        if dry_run:
            print(f"[DRY-RUN] remove {entry} -> {dest}")
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not is_win:
            for d in (uninstall_backup.parent, uninstall_backup):
                if d.exists() and not os.path.islink(d):
                    try:
                        os.chmod(d, 0o700)
                    except OSError:
                        pass
        if not os.path.islink(entry) and entry.is_dir():
            _release_init_tree(entry)
        elif not os.path.islink(entry) and entry.is_file():
            try:
                os.chmod(entry, (os.lstat(entry).st_mode & 0o7777) | 0o200)
            except OSError:
                pass
        shutil.move(str(entry), str(dest))
        print(f"[REMOVED] {entry} (backed up -> {dest})")

    receipt_path = state_dir() / "install_receipt.json"
    tracked_rel: List[str] = []
    receipt_matches_target = False
    if receipt_path.is_file():
        try:
            rec = json.loads(receipt_path.read_text(encoding="utf-8"))
            if isinstance(rec, dict):
                rec_target = rec.get("target")
                if not rec_target or Path(str(rec_target)).resolve() == target_dir.resolve():
                    receipt_matches_target = True
                    if isinstance(rec.get("installed"), list):
                        tracked_rel = [str(x) for x in rec["installed"] if isinstance(x, str)]
        except (OSError, ValueError) as exc:
            print(f"[WARN] Could not parse {receipt_path} ({exc}); falling back to canonical harness entries.", file=sys.stderr)

    if not tracked_rel:
        tracked_rel = ["GEMINI.md", "DESIGN.md", "MISTAKES.md", ".harness/manifest.json"]
        opt_source = _resolve_init_source(getattr(args, "source", None))
        if opt_source is not None:
            if (opt_source / "agents").is_dir():
                tracked_rel.extend(f"agents/{p.name}" for p in sorted((opt_source / "agents").glob("*.md")))
            if (opt_source / "skills").is_dir():
                tracked_rel.extend(f"skills/{p.name}" for p in sorted((opt_source / "skills").iterdir()) if p.is_dir())
            if (opt_source / "templates").is_dir():
                tracked_rel.extend(
                    f"templates/{p.name}"
                    for p in sorted((opt_source / "templates").iterdir())
                    if p.is_file() and p.name != "config.example.json"
                )

    hooks_path = target_dir / "hooks.json"
    if os.path.lexists(hooks_path):
        if os.path.islink(hooks_path):
            _stash_entry(hooks_path, Path("hooks.json"))
        elif hooks_path.is_file():
            try:
                hooks_data = json.loads(hooks_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"[WARN] {hooks_path} is not valid JSON ({exc}); leaving hooks.json untouched.", file=sys.stderr)
                hooks_data = None
            if isinstance(hooks_data, dict):
                removed_keys = [k for k in ("harness-gate", "upstream-watchdog") if k in hooks_data]
                if removed_keys:
                    remaining = {k: v for k, v in hooks_data.items() if k not in ("harness-gate", "upstream-watchdog")}
                    if remaining:
                        if dry_run:
                            print(f"[DRY-RUN] prune {', '.join(removed_keys)} from {hooks_path} (preserving {len(remaining)} user hook group(s))")
                        else:
                            backup_hooks = uninstall_backup / "hooks.json"
                            backup_hooks.parent.mkdir(parents=True, exist_ok=True)
                            if not is_win:
                                for d in (uninstall_backup.parent, uninstall_backup):
                                    if d.exists() and not os.path.islink(d):
                                        try:
                                            os.chmod(d, 0o700)
                                        except OSError:
                                            pass
                            shutil.copy2(hooks_path, backup_hooks)
                            atomic_write_json(hooks_path, remaining, mode=0o644)
                            print(f"[CLEANED] Removed {', '.join(removed_keys)} from {hooks_path} ({len(remaining)} other hook group(s) preserved)")
                    else:
                        _stash_entry(hooks_path, Path("hooks.json"))

    target_resolved = target_dir.resolve()
    for rel_item in tracked_rel:
        norm_rel = rel_item.replace("\\", "/").strip("/")
        if not norm_rel or norm_rel == "hooks.json":
            continue
        cand_path = Path(rel_item)
        entry = cand_path if cand_path.is_absolute() else (target_dir / norm_rel)
        try:
            parent_resolved = entry.parent.resolve()
            if entry != target_dir and not (parent_resolved == target_resolved or parent_resolved.is_relative_to(target_resolved)):
                continue
        except OSError:
            continue
        if os.path.lexists(entry):
            rel_dest = entry.relative_to(target_dir) if entry.is_relative_to(target_dir) else Path(entry.name)
            try:
                _stash_entry(entry, rel_dest)
            except OSError as exc:
                print(f"[ERROR] Could not remove {entry}: {exc}", file=sys.stderr)
                cleanup_failed = True

    if not dry_run and target_dir.is_dir() and not os.path.islink(target_dir):
        for sub_name in (".harness", "agents", "skills", "templates"):
            sub_dir = target_dir / sub_name
            if sub_dir.is_dir() and not os.path.islink(sub_dir):
                try:
                    if not any(sub_dir.iterdir()):
                        sub_dir.rmdir()
                except OSError:
                    pass

    monitor = _monitor(env, registry)
    state_files = [monitor.state_file, monitor.pending_file]
    if receipt_matches_target or target_dir == config_dir().expanduser().resolve():
        state_files.append(receipt_path)
    for st_file in state_files:
        if os.path.lexists(st_file):
            if dry_run:
                print(f"[DRY-RUN] remove state file {st_file}")
            else:
                registry.os_adapter.unlock(st_file, recursive=False)
                try:
                    if not os.path.islink(st_file):
                        os.chmod(st_file, 0o600)
                    st_file.unlink(missing_ok=True)
                except OSError as exc:
                    print(f"[ERROR] Could not remove state file {st_file}: {exc}", file=sys.stderr)
                    cleanup_failed = True

    if not dry_run:
        _prune_named_backups("uninstall_", keep=10)
    audit("guard.init.uninstall", target=str(target_dir), dry_run=dry_run, ok=(not cleanup_failed))
    print("=" * 64)
    if cleanup_failed:
        print("[ERROR] Profile teardown completed with errors.", file=sys.stderr)
        print("=" * 64)
        return 1
    print(f"[SUCCESS] Uninstalled Antigravity Harness profile at {target_dir}" + (" (dry run)" if dry_run else ""))
    if not dry_run and uninstall_backup.exists():
        print(f"Removed governance files were archived to: {uninstall_backup}")
    print("=" * 64)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Initializes user ~/.gemini/config governance profile, hooks, FIM baseline, and lock from system package."""
    dry_run = bool(getattr(args, "dry_run", False))
    no_lock = bool(getattr(args, "no_lock", False))
    target_override = getattr(args, "target", None)
    target_dir = Path(target_override).expanduser().resolve() if target_override else config_dir().expanduser().resolve()

    if bool(getattr(args, "uninstall", False)):
        return _uninstall_init_profile(args, target_dir, dry_run)

    source_dir = _resolve_init_source(getattr(args, "source", None))
    if source_dir is None:
        hint = getattr(args, "source", None) or os.environ.get("ANTIGRAVITY_SHARE_DIR") or "/usr/share/antigravity-harness"
        print(f"[ERROR] Governance source assets (GEMINI.md, skills/) not found at {hint}.", file=sys.stderr)
        return 1

    is_win = platform.system().lower() == "windows"

    print("=" * 64)
    print(f"    Antigravity Guard (agy-guard) v{__version__} - User Init    ")
    print("=" * 64)
    print(f"Source : {source_dir}")
    print(f"Target : {target_dir}")
    print("-" * 64)

    if dry_run:
        print(f"[DRY-RUN] copy governance assets from {source_dir} -> {target_dir}")
        print(f"[DRY-RUN] merge upstream-watchdog & harness-gate into {target_dir / 'hooks.json'}")
        print(f"[DRY-RUN] establish FIM baseline and {'skip lock (--no-lock)' if no_lock else 'engage OS write protection'}")
        return 0

    if not request_approval(
        "init",
        f"Initialize Antigravity Harness governance in {target_dir}?",
        [
            f"Source: {source_dir}",
            f"Target: {target_dir}",
            "Existing replaced files are backed up before update, then FIM baselined and write-protected.",
        ],
    ):
        return _refuse("init")

    reg_arg = getattr(args, "registry", None)
    registry, quarantined = recover_or_load_registry(config_path=Path(reg_arg) if reg_arg else None, recover=True)
    if quarantined is not None:
        print(f"[RECOVERED] Quarantined corrupt environment registry -> {quarantined}")
    env = registry.get_environment("antigravity")
    if env is None or Path(env.get_root()).resolve() != target_dir:
        env = AgentEnvironment(
            id="antigravity",
            name="Antigravity Global Config",
            platform_type="antigravity",
            root_path=str(target_dir),
            policy="enforced",
        )

    def _engage_init_lock() -> Tuple[bool, str]:
        if target_override and Path(registry.get_environment("antigravity").get_root()).resolve() != target_dir:
            lock_ok_inner = True
            lock_msgs_inner: List[str] = []
            for gp in env.get_governance_paths(existing_only=True):
                ok_part, msg_part = registry.os_adapter.lock(Path(gp), recursive=Path(gp).is_dir())
                lock_ok_inner = lock_ok_inner and ok_part
                if not ok_part and msg_part:
                    lock_msgs_inner.append(msg_part)
            if target_dir.exists() and not os.path.islink(target_dir):
                ok_root, msg_root = registry.os_adapter.lock(target_dir, recursive=False)
                lock_ok_inner = lock_ok_inner and ok_root
                if not ok_root and msg_root:
                    lock_msgs_inner.append(msg_root)
            return lock_ok_inner, ("; ".join(lock_msgs_inner) or f"Protected {target_dir}")
        return registry.lock("antigravity")

    was_locked = bool(
        (not target_override and registry.is_locked("antigravity").get("antigravity", False))
        or any(
            not os.access(p, os.W_OK)
            for p in ([target_dir] if target_dir.exists() else []) + env.get_governance_paths(existing_only=True)
            if not os.path.islink(p)
        )
    )

    lease_mgr = LeaseManager(registry=registry)
    try:
        if lease_mgr.get_active_lease("antigravity") is not None:
            lease_mgr.complete_lease(env_id="antigravity", interactive=False)
    except Exception:
        pass
    registry.unlock("antigravity")
    if target_dir.exists() and not os.path.islink(target_dir):
        registry.os_adapter.unlock(target_dir, recursive=False)
        for rt_name in ANTIGRAVITY_RUNTIME_ENTRIES:
            rt_entry = target_dir / rt_name
            if os.path.lexists(rt_entry) and not os.path.islink(rt_entry):
                registry.os_adapter.unlock(rt_entry, recursive=True)
        for gp in env.get_governance_paths(existing_only=True):
            if not os.path.islink(gp):
                registry.os_adapter.unlock(Path(gp), recursive=True)

    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_dir = state_dir() / "backups" / f"init_{stamp}"
    installed_paths: List[str] = []
    backed_up: List[Tuple[Path, Path]] = []
    placed_new: List[Path] = []

    def _backup_existing(dest: Path) -> bool:
        if not os.path.lexists(dest):
            return False
        rel = dest.relative_to(target_dir) if dest.is_relative_to(target_dir) else Path(dest.name)
        btarget = backup_dir / rel
        btarget.parent.mkdir(parents=True, exist_ok=True)
        if not is_win:
            for d in (backup_dir.parent, backup_dir):
                if d.exists() and not os.path.islink(d):
                    try:
                        os.chmod(d, 0o700)
                    except OSError:
                        pass
        if not os.path.islink(dest) and dest.is_dir():
            _release_init_tree(dest)
        elif not os.path.islink(dest) and dest.is_file():
            try:
                os.chmod(dest, (os.lstat(dest).st_mode & 0o7777) | 0o200)
            except OSError:
                pass
        shutil.move(str(dest), str(btarget))
        backed_up.append((dest, btarget))
        return True

    def _rollback_init() -> None:
        for created in reversed(placed_new):
            try:
                if os.path.islink(created) or created.is_file():
                    created.unlink(missing_ok=True)
                elif created.is_dir():
                    _release_init_tree(created)
                    shutil.rmtree(created, ignore_errors=True)
            except OSError:
                pass
        for orig_dest, bsrc in reversed(backed_up):
            try:
                if os.path.lexists(orig_dest):
                    if os.path.islink(orig_dest) or orig_dest.is_file():
                        orig_dest.unlink(missing_ok=True)
                    elif orig_dest.is_dir():
                        _release_init_tree(orig_dest)
                        shutil.rmtree(orig_dest, ignore_errors=True)
                if os.path.lexists(bsrc):
                    orig_dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(bsrc), str(orig_dest))
            except OSError:
                pass
        if was_locked or not no_lock:
            try:
                _engage_init_lock()
            except Exception:
                pass

    def _place_copy(src: Path, dest: Path) -> None:
        if os.path.lexists(dest) and not os.path.islink(dest):
            if dest.is_file() and src.is_file() and dest.read_bytes() == src.read_bytes():
                installed_paths.append(str(dest))
                return
            if dest.is_dir() and src.is_dir() and _trees_identical_init(src, dest):
                installed_paths.append(str(dest))
                return
        had_existing = _backup_existing(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        copy_entry(src, dest, _init_ignore)
        installed_paths.append(str(dest))
        if not had_existing:
            placed_new.append(dest)

    prior_installed: set[str] = set()
    receipt_path = state_dir() / "install_receipt.json"
    if os.path.lexists(receipt_path):
        try:
            rec = json.loads(receipt_path.read_text(encoding="utf-8"))
            if isinstance(rec, dict) and isinstance(rec.get("installed"), list):
                rec_target = rec.get("target")
                if not rec_target or Path(str(rec_target)).resolve() == target_dir.resolve():
                    prior_installed = {str(p).replace("\\", "/") for p in rec["installed"]}
        except (OSError, ValueError) as exc:
            print(f"[WARN] Could not parse {receipt_path} ({exc}); preserving unrecorded custom entries.", file=sys.stderr)

    try:
        for gname in ("GEMINI.md", "DESIGN.md", "MISTAKES.md"):
            gsrc = source_dir / gname
            if gsrc.is_file():
                _place_copy(gsrc, target_dir / gname)

        msrc = source_dir / ".harness" / "manifest.json"
        if msrc.is_file():
            if os.path.islink(target_dir / ".harness"):
                _backup_existing(target_dir / ".harness")
            _place_copy(msrc, target_dir / ".harness" / "manifest.json")

        agents_src = source_dir / "agents"
        if agents_src.is_dir():
            target_agents = target_dir / "agents"
            if os.path.islink(target_agents):
                _backup_existing(target_agents)
            src_agents = {p.name: p for p in sorted(agents_src.glob("*.md"))}
            if target_agents.is_dir() and not os.path.islink(target_agents):
                for existing in sorted(target_agents.glob("*.md")):
                    if existing.name not in src_agents and f"agents/{existing.name}" in prior_installed:
                        _backup_existing(existing)
            for agent_name, agent_file in src_agents.items():
                _place_copy(agent_file, target_agents / agent_name)

        skills_src = source_dir / "skills"
        if skills_src.is_dir():
            target_skills = target_dir / "skills"
            if os.path.islink(target_skills):
                _backup_existing(target_skills)
            src_skills = {p.name: p for p in sorted(p for p in skills_src.iterdir() if p.is_dir())}
            if target_skills.is_dir() and not os.path.islink(target_skills):
                for existing in sorted(target_skills.iterdir()):
                    if (
                        (existing.is_dir() or os.path.islink(existing))
                        and existing.name not in src_skills
                        and f"skills/{existing.name}" in prior_installed
                    ):
                        _backup_existing(existing)
            for skill_name, skill_dir in src_skills.items():
                _place_copy(skill_dir, target_skills / skill_name)

        templates_src = source_dir / "templates"
        if templates_src.is_dir():
            target_templates = target_dir / "templates"
            if os.path.islink(target_templates):
                _backup_existing(target_templates)
            src_templates = {
                p.name: p
                for p in sorted(templates_src.iterdir())
                if p.is_file() and p.name != "config.example.json"
            }
            if target_templates.is_dir() and not os.path.islink(target_templates):
                for existing in sorted(target_templates.iterdir()):
                    if (
                        (existing.is_file() or os.path.islink(existing))
                        and existing.name not in src_templates
                        and existing.name != "config.example.json"
                        and f"templates/{existing.name}" in prior_installed
                    ):
                        _backup_existing(existing)
            for tmpl_name, tmpl in src_templates.items():
                _place_copy(tmpl, target_templates / tmpl_name)
            example_cfg = templates_src / "config.example.json"
            cfg_dest = target_dir / "config.json"
            if not cfg_dest.exists() and example_cfg.is_file():
                shutil.copy2(example_cfg, cfg_dest)
                if not is_win:
                    os.chmod(cfg_dest, 0o600)

        if not is_win:
            skills_root = target_dir / "skills"
            if skills_root.is_dir() and not os.path.islink(skills_root):
                script_cands: List[Path] = []
                for sdir in skills_root.rglob("scripts"):
                    if sdir.is_dir() and not os.path.islink(sdir):
                        for entry in sdir.rglob("*"):
                            if entry.suffix in (".py", ".sh", ".mjs"):
                                script_cands.append(entry)
                ah_dir = skills_root / "antislop-human"
                if ah_dir.is_dir() and not os.path.islink(ah_dir):
                    script_cands.extend(ah_dir.glob("contrast-*.py"))
                for sc in script_cands:
                    if not os.path.islink(sc) and sc.is_file():
                        try:
                            sc.chmod(sc.stat().st_mode | 0o755)
                        except OSError:
                            pass

        from guard.agy_hooks import PRE_TOOL_USE_MATCHER

        hooks_path = target_dir / "hooks.json"
        existing_hooks: dict = {}
        if hooks_path.is_file():
            try:
                loaded_hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                loaded_hooks = None
                hooks_err = str(exc)
            else:
                hooks_err = "root is not a JSON object"
            if not isinstance(loaded_hooks, dict):
                _rollback_init()
                print(f"[ERROR] {hooks_path} is invalid ({hooks_err}); aborted and rolled back.", file=sys.stderr)
                return 1
            existing_hooks = loaded_hooks

        fhs_hooks = source_dir.parent.parent / "lib" / "antigravity-guard" / "guard" / "agy_hooks.py"
        if fhs_hooks.is_file():
            hooks_script = fhs_hooks.resolve()
        elif getattr(sys, "frozen", False):
            sys_hooks = Path("/usr/lib/antigravity-guard/guard/agy_hooks.py")
            rt_hooks = data_dir() / "runtime" / "guard" / "agy_hooks.py"
            hooks_script = sys_hooks if sys_hooks.is_file() else (rt_hooks if rt_hooks.is_file() else (source_dir / "guard" / "agy_hooks.py"))
        else:
            hooks_script = Path(__file__).resolve().parent / "agy_hooks.py"

        watcher_script = target_dir / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        if getattr(sys, "frozen", False):
            python_bin = "python" if is_win else "python3"
        else:
            python_bin = sys.executable or ("python" if is_win else "python3")

        def _fmt_cmd(*parts: str) -> str:
            return subprocess.list2cmdline([python_bin, *parts]) if is_win else shlex.join([python_bin, *parts])

        merged_hooks = dict(existing_hooks)
        merged_hooks["upstream-watchdog"] = {
            "PreInvocation": [{"type": "command", "command": _fmt_cmd(str(watcher_script)), "timeout": 15}]
        }
        merged_hooks["harness-gate"] = {
            "PreInvocation": [
                {"type": "command", "command": _fmt_cmd(str(hooks_script), "pre-invocation"), "timeout": 5}
            ],
            "PreToolUse": [
                {
                    "matcher": PRE_TOOL_USE_MATCHER,
                    "hooks": [
                        {"type": "command", "command": _fmt_cmd(str(hooks_script), "pre-tool-use"), "timeout": 5}
                    ],
                }
            ],
            "Stop": [
                {"type": "command", "command": _fmt_cmd(str(hooks_script), "stop"), "timeout": 15}
            ],
        }
        if merged_hooks == existing_hooks and not os.path.islink(hooks_path):
            installed_paths.append(str(hooks_path))
        else:
            had_hooks = _backup_existing(hooks_path)
            atomic_write_json(hooks_path, merged_hooks, mode=0o644)
            installed_paths.append(str(hooks_path))
            if not had_hooks:
                placed_new.append(hooks_path)

        installed_rel = [
            str(Path(p).relative_to(target_dir)) if Path(p).is_relative_to(target_dir) else str(p)
            for p in installed_paths
        ]
        atomic_write_json(
            state_dir() / "install_receipt.json",
            {
                "version": __version__,
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "source": str(source_dir),
                "source_commit": "",
                "source_dirty": False,
                "mode": "copy",
                "target": str(target_dir),
                "backup_dir": str(backup_dir) if backup_dir.exists() else None,
                "installed": installed_rel,
            },
        )
        _prune_named_backups("init_", keep=10)
        monitor = _monitor(env, registry)
        count, bpath = monitor.save_baseline()
        print(f"[BASELINE] Integrity baseline established for {count} governance entries -> {bpath}")
    except Exception:
        _rollback_init()
        raise

    if not no_lock:
        lock_ok, lmsg = _engage_init_lock()
        print(f"[{'LOCKED' if lock_ok else 'ERROR'}] {lmsg}")
        if not lock_ok:
            return 1

    audit("guard.init", source=str(source_dir), target=str(target_dir), baseline_entries=count)
    print("=" * 64)
    print(f"[SUCCESS] Initialized Antigravity Harness profile at {target_dir}")
    if backup_dir.exists():
        print(f"Replaced files were backed up to: {backup_dir}")
    print("=" * 64)
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    registry = _registry(args)
    lease_mgr = LeaseManager(registry=registry)
    target = None if getattr(args, "all", False) else (getattr(args, "env", None) or "antigravity")
    if target:
        env, err = registry.resolve_environment(target)
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        if lease_mgr.get_active_lease(env.id) is not None:
            success, msg = lease_mgr.complete_lease(env_id=env.id, interactive=True)
            print(f"[{'LOCKED' if success else 'ERROR'}] {msg}")
            return 0 if success else 1
        envs = [env]
    else:
        envs = registry.list_environments()

    leased_ids = set()
    lease_msgs: List[str] = []
    lease_ok = True
    if target is None:
        for env in envs:
            if lease_mgr.get_active_lease(env.id) is not None:
                leased_ids.add(env.id)
                l_ok, l_msg = lease_mgr.complete_lease(env_id=env.id, interactive=True)
                lease_ok = lease_ok and l_ok
                lease_msgs.append(l_msg)

    # Silent-ingestion guard: before sealing, show what changed since the trusted baseline.
    # Locking never accepts those changes; they stay reported until an approved rebaseline.
    for env in envs:
        if env.id in leased_ids or env.policy != "enforced":
            continue
        report = _monitor(env, registry).verify()
        if not report.is_intact:
            print(f"[{env.name}] Sealing with unreviewed changes: {report.summary()}")
            _print_report_details(report, indent="  ")
            print("  Locking does not accept these changes; review them, then run 'agy-guard rebaseline'.")
    success, msg = registry.lock(env_id=target)
    overall_ok = lease_ok and success
    combined_msg = (" | ".join(lease_msgs + ([msg] if msg else ""))).strip() if lease_msgs else msg
    print(f"[{'LOCKED' if overall_ok else 'ERROR'}] {combined_msg}")
    return 0 if overall_ok else 1


def cmd_unlock(args: argparse.Namespace) -> int:
    registry = _registry(args)
    target = None if getattr(args, "all", False) else (getattr(args, "env", None) or "antigravity")
    if target:
        env, err = registry.resolve_environment(target)
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        details = [f"{env.name}: {len(env.get_governance_paths(existing_only=True))} governance entries"]
    else:
        details = [e.name for e in registry.list_environments()]
    details.append("Prefer 'agy-guard request-unlock' for a time-bounded window with automatic relock.")
    if not request_approval("unlock", "Remove write protection WITHOUT an automatic relock?", details):
        return _refuse("unlock")
    success, msg = registry.unlock(env_id=target)
    print(f"[{'UNLOCKED' if success else 'ERROR'}] {msg}")
    if success:
        print("Remember to run 'agy-guard lock' when maintenance is finished.")
    return 0 if success else 1


def cmd_verify(args: argparse.Namespace) -> int:
    registry = _registry(args)
    if getattr(args, "all", False):
        targets = registry.list_environments()
    else:
        env, err = _resolve(registry, getattr(args, "env", None))
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        targets = [env]
    any_failed = False
    for env in targets:
        report = _monitor(env, registry).verify()
        print(f"[{env.name}] {report.summary()}")
        _print_report_details(report, indent="  ")
        any_failed = any_failed or not report.is_intact
    return 1 if any_failed else 0


def cmd_rebaseline(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    monitor = _monitor(env, registry)
    report = monitor.verify()
    details = [report.summary()]
    details += [f"~ {f}" for f in report.modified[:10]] + [f"+ {f}" for f in report.added[:10]] + [f"- {f}" for f in report.deleted[:10]]
    pending = monitor.load_pending()
    if pending is not None and report.baseline_status != "pending_review":
        details.append(f"NOTE: files changed again after {pending.get('source', 'the maintenance window')} closed; "
                       f"review the list above, it is more than the window's changes.")
    if not request_approval("rebaseline", f"Accept the CURRENT state of {env.name} as trusted?", details):
        return _refuse("rebaseline")
    count, path = monitor.save_baseline()
    print(f"[REBASELINED] Established baseline for {count} entries -> {path} (previous baseline archived)")
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    engine = SnapshotEngine.for_environment(env, registry, integrity_monitor=_monitor(env, registry))
    if args.action == "create":
        snap_id, dest = engine.create_snapshot(label=args.label)
        print(f"[CREATED] Snapshot '{snap_id}' saved to {dest}")
        return 0
    if args.action == "list":
        snaps = engine.list_snapshots()
        if not snaps:
            print("No snapshots recorded.")
            return 0
        print(f"Recorded Snapshots ({len(snaps)}):")
        for s in snaps:
            print(f"  - {s.get('id')}: {s.get('label')} [{s.get('kind')}] ({s.get('created_at')})")
        return 0
    if args.action == "restore":
        if not args.id:
            print("Error: Specify snapshot ID to restore (--id).")
            return 1
        if not request_approval("snapshot restore", f"Replace the governance scope of {env.name} with snapshot {args.id}?",
                                ["A pre-restore backup is taken first", "The integrity baseline is re-established afterwards"]):
            return _refuse("snapshot restore")
        success, msg = engine.restore_snapshot(args.id)
        print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
        return 0 if success else 1
    if args.action == "prune":
        keep = 5 if args.keep is None else args.keep
        if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
            print("Error: --keep must be an integer >= 1.", file=sys.stderr)
            return 1
        if not request_approval("snapshot prune", f"Permanently delete older snapshots of {env.name} (keep {keep} per kind)?",
                                ["Snapshots are forensic evidence and restore points; pruning cannot be undone."]):
            return _refuse("snapshot prune")
        count = engine.prune_snapshots(keep=keep)
        print(f"[PRUNED] Removed {count} older snapshots (kept {keep} per kind).")
        return 0
    return 0


def cmd_porter(args: argparse.Namespace) -> int:
    bridge = PorterBridge()
    report = bridge.inspect_source(args.source)
    print("=" * 64)
    print(f" Porter Pre-Flight Inspection: {report['name']} ({report['target_type']})")
    print("=" * 64)
    print(f"Constitutional Score : {report['alignment_score']}/100")
    print(f"Adaptability Score   : {report['adaptability_score']}/100")
    print(f"Admissible           : {'YES' if report['is_admissible'] else 'NO'}")
    print(f"Content SHA-256      : {report['content_sha256']}")
    if report["violations"]:
        print("\nViolations:")
        for v in report["violations"]:
            print(f"  [X] {v}")
    if report["recommendations"]:
        print("\nRecommendations:")
        for r in report["recommendations"]:
            print(f"  - {r}")
    print("=" * 64)
    if args.action == "inspect":
        return 0 if report["is_admissible"] else 1

    expected = getattr(args, "expect_sha256", None) or report["content_sha256"]
    summary = f"Write '{report['name']}' ({report['target_type']}) into the protected governance tree?"
    details = [f"content sha256 {expected}"]
    if args.force and not report["is_admissible"]:
        details.append("FORCE: constitutional violations above will be ingested")
    if not request_approval("porter stage", summary, details):
        return _refuse("porter stage")
    success, msg = bridge.stage_and_ingest(args.source, target_name=args.name, force=args.force, expected_sha256=expected)
    print(f"[{'SUCCESS' if success else 'REJECTED'}] {msg}")
    return 0 if success else 1


def cmd_upstream(args: argparse.Namespace) -> int:
    bridge = UpstreamAuditorBridge()
    action = getattr(args, "action", "check") or "check"
    if action == "ack":
        ok, msg = bridge.acknowledge_drift(model_name=getattr(args, "model", None))
        print(f"[{'OK' if ok else 'ERROR'}] {msg}")
        return 0 if ok else 1

    if action == "status" or getattr(args, "offline", False):
        from guard.upstream import short_ref

        summary = bridge.get_summary()
        model_info = bridge.get_model_drift_status()
        print(f"Active Model   : {model_info['active_model']} ({model_info['model_source']})")
        print(f"Upstream State : {summary['status']} ({summary['state_file']})")
        for w in summary.get("warnings", []):
            print(f"[WARN] {w}", file=sys.stderr)
        state = bridge.load_state()
        tracked = state.get("tracked_repositories", {})
        if not isinstance(tracked, dict) or not tracked:
            print("[WARN] No tracked repositories configured in upstream state.", file=sys.stderr)
            return 1
        pending = state.get("pending_repo_updates", {})
        if not isinstance(pending, dict):
            pending = {}
        print(f"\nTracked Repositories Ledger ({len(tracked)}, offline):")
        print(f"{'Repository':<24} {'Local':<18} {'Pending':<18} {'Status':<18}")
        print("-" * 80)
        has_offline_errors = summary["status"] != "OK"
        for name in sorted(tracked):
            info = tracked[name]
            if not isinstance(info, dict):
                has_offline_errors = True
                print(f"{name:<24} {'None':<18} {'-':<18} {'Invalid entry':<18}")
                continue
            recorded_raw = str(info.get("last_synced_commit", "")).strip()
            local_sha = short_ref(recorded_raw)
            entry = pending.get(name) if isinstance(pending.get(name), dict) else {}
            pend_sha = short_ref(entry.get("remote", "")) if str(entry.get("recorded", "")).strip() == recorded_raw else ""
            status = "Updates Pending" if pend_sha else "Recorded"
            print(f"{name:<24} {local_sha or 'None':<18} {pend_sha or '-':<18} {status:<18}")
        return 1 if has_offline_errors else 0

    model_info = bridge.get_model_drift_status()
    print(f"Active Model : {model_info['active_model']} ({model_info['model_source']})")
    if bridge.last_load_error:
        print(f"[WARN] {bridge.last_load_error}", file=sys.stderr)
    print("Checking tracked repositories (zero LLM token cost)...")
    results = bridge.check_repositories()
    print(f"\nTracked Repositories Status ({len(results)}):")
    print(f"{'Repository':<24} {'Local':<18} {'Remote':<18} {'Status':<18}")
    print("-" * 80)
    has_errors = bool(bridge.last_load_error) or not results
    if not results:
        print("[WARN] No tracked repositories configured in upstream state.", file=sys.stderr)
    for r in results:
        st_label = str(r.get("status", ""))
        if st_label.startswith(("Network Error", "HTTP Error", "Invalid ", "Unknown", "Worker Error")):
            has_errors = True
        print(f"{r['name']:<24} {r['local_sha'] or 'None':<18} {r['remote_sha'] or 'None':<18} {st_label:<18}")
    return 1 if has_errors else 0


def cmd_doctor(args: argparse.Namespace) -> int:
    reg_arg = getattr(args, "registry", None)
    reg_cfg = Path(reg_arg) if reg_arg else None
    registry, quarantined_reg = recover_or_load_registry(
        config_path=reg_cfg,
        recover=bool(getattr(args, "fix", False)),
    )
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    result = diagnose(env, registry)
    if quarantined_reg is not None:
        result.infos.insert(0, f"Quarantined corrupt environment registry -> {quarantined_reg} and re-initialized defaults.")

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} - Doctor       ")
    print("=" * 64)
    print(f"Environment    : {env.name} -> {result.root}")
    print(f"Protection     : {registry.os_adapter.protection_kind()}")
    print(f"Write Shield   : {'[LOCKED]' if not result.issues else '[UNPROTECTED]'}")
    print(f"Trust Anchor   : {result.monitor.state_file}")
    print(f"Integrity (FIM): {result.report.summary()}")
    print("-" * 64)
    for w in result.warnings:
        print(f"  [WARN] {w}")
    for i in result.infos:
        print(f"  [INFO] {i}")
    if not result.warnings:
        print("[OK] No problems found.")

    if getattr(args, "fix", False):
        print("\n[Auto-Healing]")
        if result.issues:
            ok, msg = registry.lock(env.id)
            print(f"  - Write shield: {'re-engaged' if ok else 'FAILED'}: {msg}")
        if not result.monitor.state_file.exists():
            if request_approval("rebaseline", f"Establish the initial integrity baseline for {env.name}?", [result.report.summary()]):
                cnt, pth = result.monitor.save_baseline()
                print(f"  - Baseline established for {cnt} entries -> {pth}")
            else:
                print(f"  - Baseline NOT established: {refusal_message('rebaseline')}")
        print("Doctor auto-healing completed (nothing was deleted; manual items remain listed above).")
        result.issues = registry.protection_issues(env)
        result.report = result.monitor.verify()
        healed_prefixes: list[str] = []
        if not result.issues:
            healed_prefixes.append("Governance scope")
        if result.report.is_intact:
            healed_prefixes.append("Integrity:")
        if healed_prefixes:
            result.warnings = [w for w in result.warnings if not w.startswith(tuple(healed_prefixes))]

    print("=" * 64)
    return 0 if result.healthy else 1


def cmd_startup(args: argparse.Namespace) -> int:
    manager = StartupManager()
    action = getattr(args, "action", "status") or "status"
    if action == "enable":
        if not request_approval("startup enable", "Register the boot sentinel to run at every login?",
                                [f"Command: {manager.get_guard_command()}", f"Target: {manager.target_dir}"]):
            return _refuse("startup enable")
        ok, msg = manager.enable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        return 0 if ok else 1
    if action == "disable":
        if not request_approval("startup disable", "Disable the boot sentinel?", []):
            return _refuse("startup disable")
        ok, msg = manager.disable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        return 0 if ok else 1
    st = manager.status()
    print("=" * 64)
    print("   Antigravity Guard — Boot Sentinel Status   ")
    print("=" * 64)
    print(f"Platform       : {st['platform']}")
    print(f"Mechanism      : {st['mechanism']}")
    print(f"Service Path   : {st['target_path']}")
    print(f"Installed      : {'YES' if st['installed'] else 'NO'}")
    print(f"Active/Enabled : {'YES' if st['active'] else 'NO'}")
    print("=" * 64)
    return 0


def cmd_boot_check(args: argparse.Namespace) -> int:
    ok, msg = StartupManager().execute_boot_check()
    print(f"[BOOT-SENTINEL] {msg}")
    return 0 if ok else 1


def cmd_test_boundary(args: argparse.Namespace) -> int:
    guard = TestBoundaryGuard(workspace_dir=getattr(args, "dir", None))
    action = getattr(args, "action", "verify")

    if action == "snapshot":
        target = Path(args.output).resolve() if getattr(args, "output", None) else guard.state_file
        prompt = (
            "Overwrite the existing test boundary baseline with the CURRENT tests?"
            if target.exists()
            else "Create a new test boundary baseline from the CURRENT workspace tests?"
        )
        if not request_approval(
            "test-boundary snapshot",
            prompt,
            [str(target), "Snapshotting after editing tests would legitimise those edits."],
        ):
            return _refuse("test-boundary snapshot")
        count, path = guard.snapshot(target_path=getattr(args, "output", None))
        print(f"[TEST-BOUNDARY] Baseline snapshot captured for {count} test & config files -> {path}")
        return 0

    if action == "verify":
        mode = getattr(args, "mode", "bugfix") or "bugfix"
        authorized = set(getattr(args, "authorize", None) or [])
        report = guard.verify(
            mode=mode,
            snapshot_path=getattr(args, "snapshot", None),
            authorized_modifications=authorized,
            base_ref=getattr(args, "base_ref", None),
        )
        print("=" * 64)
        print("      Antigravity Guard — Test & Config Boundary Verification     ")
        print("=" * 64)
        print(f"Workspace      : {report.workspace_dir}")
        print(f"Baseline       : {report.baseline_source or 'n/a'}")
        print(f"Mode           : {report.mode.upper()}")
        print(f"Tracked Files  : {report.total_files}")
        print(f"Status         : {report.summary()}")
        if report.added:
            print(f"New test files : {', '.join(report.added)}")
        if report.extended:
            print(f"Extended files : {', '.join(report.extended)}")
        print("=" * 64)
        if report.violations:
            print("\nViolations Detected:")
            for v in report.violations:
                print(f"  [X] {v}")
            print("\n[BLOCKED] Delivery halted. Test or configuration mutation is prohibited.")
            return 1
        print("[PASS] Test trust boundary is intact. No unauthorized test mutations.")
        return 0

    if action == "run-reproducible":
        if not getattr(args, "cmd", None):
            print("Error: Specify test command using --cmd '<command>'")
            return 1
        passes = args.passes
        if passes < 2:
            print("Error: --passes must be >= 2 to verify reproducibility.", file=sys.stderr)
            return 1
        print(f"[REPRODUCIBILITY-GATE] Running command {passes} consecutive times: {args.cmd}")
        success, msg, codes = guard.run_reproducible(command=args.cmd, passes=passes)
        print(f"[{'PASS' if success else 'FAIL'}] {msg} (Exit Codes: {codes})")
        return 0 if success else 1
    return 0


def cmd_provenance(args: argparse.Namespace) -> int:
    tracker = RunProvenanceTracker(workspace_dir=getattr(args, "dir", None))
    action = getattr(args, "action", "status") or "status"
    if action == "generate":
        if getattr(args, "test_cmd", None) and args.passes < 2:
            print("Error: --passes must be >= 2 to verify reproducibility.", file=sys.stderr)
            return 1
        manifest = tracker.generate_manifest(
            mode=getattr(args, "mode", "bugfix") or "bugfix",
            test_command=getattr(args, "test_cmd", None),
            reproducibility_passes=args.passes,
            base_ref=getattr(args, "base_ref", None),
            authorized_modifications=set(getattr(args, "authorize", None) or []),
        )
        print("=" * 64)
        print("        Antigravity Guard — Run Provenance Manifest Generated     ")
        print("=" * 64)
        print(manifest.to_markdown())
        print("=" * 64)
        print(f"Manifest written -> {tracker.output_file}")
        return 0
    if not tracker.output_file.exists():
        print("No provenance manifest found. Run 'provenance generate' first.")
        return 1
    try:
        data = json.loads(tracker.output_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"Error reading provenance manifest: {e}")
        return 1
    print("=" * 64)
    print("         Antigravity Guard — Active Provenance Manifest          ")
    print("=" * 64)
    print(f"Timestamp       : {data.get('session_timestamp')}")
    print(f"Base Commit     : {data.get('git_base_commit')}")
    print(f"Boundary Status : {'INTACT' if data.get('test_boundary_verified') else 'UNVERIFIED / VIOLATED'}")
    print(f"Reproducibility : {'VERIFIED' if data.get('reproducibility_verified') else 'UNVERIFIED'}")
    print(f"Modified Files  : {len(data.get('files_modified', []))}")
    print("=" * 64)
    return 0


def cmd_env(args: argparse.Namespace) -> int:
    registry = _registry(args)
    action = getattr(args, "action", "list") or "list"
    name = getattr(args, "name", None) or getattr(args, "target", None)

    if action == "list":
        print("=" * 64)
        print("          Antigravity Guard — Registered Environments          ")
        print("=" * 64)
        for item in registry.get_status_matrix():
            print(f"ID       : {item['id']}")
            print(f"Name     : {item['name']}")
            print(f"Platform : {item['platform']}")
            print(f"Root     : {item['root']}")
            print(f"Policy   : {item['policy']}")
            print(f"Shield   : {'[LOCKED]' if item['is_locked'] else '[UNLOCKED]'}")
            print(f"Seams    : {item['file_count']} existing governance entries")
            print("-" * 64)
        print(f"Registry : {registry.config_path}")
        return 0

    if action == "detect":
        workspace = Path(getattr(args, "path", None) or Path.cwd())
        discovered = registry.discover_environments(workspace_dir=workspace, register=not getattr(args, "dry_run", False))
        if registry.last_discovery_note:
            print(f"[NOTE] {registry.last_discovery_note}")
        print(f"Discovered {len(discovered)} coding agent environment(s):")
        for env in discovered:
            paths = env.get_governance_paths(existing_only=True)
            print(f"  - {env.name} (id: {env.id}, platform: {env.platform_type}, policy: {env.policy}) -> {len(paths)} governance entries")
        if not getattr(args, "dry_run", False):
            print(f"\n[SAVED] Environments registered to {registry.config_path}")
        return 0

    if action == "add":
        path = getattr(args, "path", None)
        if not name or not path:
            print("Error: Specify environment name (--name) and path (--path) to add.", file=sys.stderr)
            return 1
        policy_val = getattr(args, "policy", None) or "enforced"
        if policy_val not in VALID_POLICIES:
            print(f"Error: Invalid policy '{policy_val}'. Must be one of {', '.join(VALID_POLICIES)}.", file=sys.stderr)
            return 1
        env_id = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-")
        existing_ids = {e.id for e in registry.list_environments()}
        if not env_id or env_id == "antigravity" or env_id in existing_ids:
            print(
                f"Error: Environment ID '{env_id or name}' is reserved or already registered.",
                file=sys.stderr,
            )
            return 1
        if policy_val != "enforced":
            if not request_approval(
                "env add",
                f"Register environment '{name}' with non-enforced policy '{policy_val}'?",
                ["A non-enforced environment is not write-protected by leases, the boot sentinel or 'agy-guard lock'."],
            ):
                return _refuse("env add")
        env = AgentEnvironment(
            id=env_id,
            name=name,
            platform_type=getattr(args, "type", None) or "custom",
            root_path=str(Path(path).resolve()),
            policy=policy_val,
        )
        try:
            registry.register_environment(env)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(f"[REGISTERED] Environment '{env.id}' added -> {env.root_path}")
        return 0

    if action == "remove":
        if not name:
            print("Error: Specify environment ID to remove.", file=sys.stderr)
            return 1
        if name == "antigravity" or name not in {e.id for e in registry.list_environments()}:
            print(f"Environment '{name}' not found (the global 'antigravity' environment cannot be removed).", file=sys.stderr)
            return 1
        if not request_approval(
            "env remove",
            f"Remove environment '{name}' from Guard protection?",
            ["Unregistering an environment stops integrity verification and re-locking for its governance seams."],
        ):
            return _refuse("env remove")
        if registry.unregister_environment(name):
            print(f"[REMOVED] Environment '{name}' removed from registry.")
            return 0
        print(f"Environment '{name}' not found (the global 'antigravity' environment cannot be removed).", file=sys.stderr)
        return 1

    if action == "policy":
        policy_val = getattr(args, "policy_val", None) or getattr(args, "value", None)
        if not name or not policy_val:
            print(f"Error: usage: agy-guard env policy <id> <{'|'.join(VALID_POLICIES)}>", file=sys.stderr)
            return 1
        if policy_val not in VALID_POLICIES:
            print(f"Error: Invalid policy '{policy_val}'. Must be one of {', '.join(VALID_POLICIES)}.", file=sys.stderr)
            return 1
        current = registry.get_environment(name)
        if current is not None and registry.is_weakening(current.policy, policy_val):
            if not request_approval("env policy", f"Lower the protection of {current.name} from '{current.policy}' to '{policy_val}'?",
                                    ["A non-enforced environment is not re-locked by leases, the boot sentinel or 'agy-guard lock'."]):
                return _refuse("env policy")
        try:
            if registry.set_policy(name, policy_val):
                print(f"[POLICY UPDATED] '{name}' policy set to '{policy_val}'")
                return 0
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(f"Environment '{name}' not found.", file=sys.stderr)
        return 1
    return 0


def cmd_request_unlock(args: argparse.Namespace) -> int:
    manager = LeaseManager(registry=_registry(args))
    success, msg, _ = manager.request_unlock(
        env_id=getattr(args, "env", None) or "antigravity",
        reason=getattr(args, "reason", None) or "Maintenance operation",
        duration_seconds=args.duration,
        interactive=not getattr(args, "non_interactive", False),
    )
    print(f"[{'AUTHORIZED' if success else 'REJECTED'}] {msg}")
    return 0 if success else 1


def cmd_lock_complete(args: argparse.Namespace) -> int:
    ok, msg = LeaseManager(registry=_registry(args)).complete_lease(env_id=getattr(args, "env", None), interactive=True)
    print(f"[{'LOCKED' if ok else 'ERROR'}] {msg}")
    return 0 if ok else 1


def cmd_lease_tick(args: argparse.Namespace) -> int:
    """Internal: waits, then expires every due lease (spawned by request-unlock)."""
    if args.wait:
        time.sleep(max(0, min(args.wait, MAX_LEASE_SECONDS + 5)))
    manager = LeaseManager(
        registry=_registry(args),
        lease_file=Path(args.lease_file) if getattr(args, "lease_file", None) else None,
    )
    expired = manager.check_and_expire_leases()
    remaining = manager.list_leases()
    print(f"[LEASE-TICK] expired {len(expired)} lease(s); {len(remaining)} still recorded.")
    return 0 if not any(l.state == "close_failed" for l in remaining) else 1


def cmd_drift(args: argparse.Namespace) -> int:
    registry = _registry(args)
    if getattr(args, "env", None):
        env, err = registry.resolve_environment(args.env)
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        targets = [env]
    else:
        targets = registry.list_environments()
    any_drift = False
    print("=" * 64)
    print("        Antigravity Guard — Multi-Environment Drift Analysis     ")
    print("=" * 64)
    for env in targets:
        report = _monitor(env, registry).verify()
        if report.is_intact:
            print(f"[INTACT] {env.name} ({env.id}): {report.total_files} governance entries verified.")
            continue
        any_drift = True
        print(f"\n[DRIFT] {env.name} ({env.id}): {report.summary()}")
        _print_report_details(report, indent="   ")
    print("=" * 64)
    return 1 if any_drift else 0


def _default_audit_root() -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    if (repo_root / "skills").is_dir() and (repo_root / "GEMINI.md").is_file():
        return repo_root
    cfg = config_dir()
    if (cfg / "skills").is_dir() and (cfg / "GEMINI.md").is_file():
        return cfg
    for share_cand in (
        repo_root.parent.parent / "share" / "antigravity-harness",
        Path("/usr/share/antigravity-harness"),
    ):
        if (share_cand / "skills").is_dir() and (share_cand / "GEMINI.md").is_file():
            return share_cand.resolve()
    return cfg


def cmd_self_audit(args: argparse.Namespace) -> int:
    lib_root = str(Path(__file__).resolve().parent.parent)
    if lib_root not in sys.path:
        sys.path.insert(0, lib_root)
    try:
        from scripts.meta_audit import MetaAuditEngine
    except ImportError as e:
        print(f"Error: the self-audit engine (scripts/meta_audit.py) is not available in this build: {e}", file=sys.stderr)
        return 2
    root = Path(args.root).resolve() if getattr(args, "root", None) else _default_audit_root()
    engine = MetaAuditEngine(repo_root=root)
    findings = engine.run_all_passes()
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    warnings = [f for f in findings if f.severity == "WARNING"]
    failed = bool(criticals) or (getattr(args, "strict", False) and bool(warnings))

    if getattr(args, "json", False):
        print(json.dumps({
            "root": str(root),
            "is_valid": not failed,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
        return 1 if failed else 0

    print("=" * 64)
    print("    Antigravity Guard — Harness Self-Audit       ")
    print("=" * 64)
    print(f"Audited root: {root}")
    for f in findings:
        print(f"[{f.severity}] {f.pass_name} -> {f.target}")
        print(f"   Message: {f.message}")
        print(f"   Fix    : {f.suggested_fix}\n")
    print("=" * 64)
    if failed:
        print("[FAIL] Self-audit violations detected.")
        return 1
    print("[PASS] Harness self-consistency checks passed.")
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    settings = load_settings()
    action = args.action
    if action == "send":
        # Used by the upstream watcher hook to reach the human instead of the agent's context.
        if not getattr(args, "title", None) or not getattr(args, "message", None):
            print("Error: notify send requires --title and --message.", file=sys.stderr)
            return 1
        severity = NotificationSeverity(getattr(args, "severity", None) or "info")
        delivered = GuardNotifier().notify(title=args.title[:120], message=args.message[:500], severity=severity,
                                           key=getattr(args, "key", None))
        return 0 if delivered else 1
    if action == "status":
        print(f"Notifications: {'enabled' if settings['enabled'] else 'disabled'}; quiet mode: {'on' if settings['quiet'] else 'off'}")
        return 0
    enabled, quiet = settings["enabled"], settings["quiet"]
    if action == "enable":
        enabled = True
    elif action == "disable":
        # Gate on the PERSISTED setting: an AGY_GUARD_NOTIFY override in the caller's environment
        # must not make a persistent "disable" look like a no-op that needs no approval.
        persisted = read_json(settings_file(), default={}) or {}
        if bool(persisted.get("enabled", True)) and not request_approval(
            "notify disable", "Disable ALL desktop notifications, including CRITICAL relock and tamper alerts?",
            ["Events are still written to the audit log, but nobody is alerted."],
        ):
            return _refuse("notify disable")
        enabled = False
    elif action == "quiet":
        quiet = True
    elif action == "normal":
        quiet = False
    path = save_settings(enabled, quiet)
    audit("notify.settings", enabled=enabled, quiet=quiet)
    print(f"[NOTIFY] enabled={enabled} quiet={quiet} -> {path}")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from guard.gui import launch_gui
    return launch_gui()


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agy-guard",
        description=f"Antigravity Guard v{__version__} - governance write protection, integrity monitoring and staging",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--registry", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    def env_opts(p, with_all: bool = False):
        p.add_argument("--env", "-e", help="Environment id (default: antigravity)")
        if with_all:
            p.add_argument("--all", "-a", action="store_true", help="Apply to all registered environments")

    p = subparsers.add_parser("init", help="Initialize ~/.gemini/config governance profile from system package")
    p.add_argument("--source", help="Source directory containing governance assets (default: /usr/share/antigravity-harness)")
    p.add_argument("--target", help="Target configuration directory (default: ~/.gemini/config)")
    p.add_argument("--no-lock", action="store_true", help="Do not write-protect governance seams after initialization")
    p.add_argument("--uninstall", action="store_true", help="Remove ~/.gemini/config governance profile, hooks, and receipt-tracked entries")
    p.add_argument("--yes", "-y", action="store_true", help="Acknowledge uninstall operation (interactive approval still enforced)")
    p.add_argument("--dry-run", action="store_true", help="Preview initialization without writing files")
    p.set_defaults(func=cmd_init)

    p = subparsers.add_parser("status", help="Show write protection, integrity and lease status")
    env_opts(p)
    p.set_defaults(func=cmd_status)

    p = subparsers.add_parser("lock", help="Write-protect governance seams")
    env_opts(p, with_all=True)
    p.set_defaults(func=cmd_lock)

    p = subparsers.add_parser("unlock", help="Remove write protection (human confirmation required)")
    env_opts(p, with_all=True)
    p.set_defaults(func=cmd_unlock)

    p = subparsers.add_parser("verify", help="Run the File Integrity Monitor (FIM) check")
    env_opts(p, with_all=True)
    p.set_defaults(func=cmd_verify)

    p = subparsers.add_parser("rebaseline", help="Accept the current state as trusted (human confirmation required)")
    env_opts(p)
    p.set_defaults(func=cmd_rebaseline)

    p = subparsers.add_parser("snapshot", help="Manage governance snapshots")
    p.add_argument("action", choices=["create", "list", "restore", "prune"], help="Snapshot action")
    p.add_argument("--label", "-l", help="Label for snapshot create")
    p.add_argument("--id", help="Snapshot ID for restore")
    p.add_argument("--keep", type=int, default=5, help="Snapshots to retain per kind during prune (>= 1)")
    env_opts(p)
    p.set_defaults(func=cmd_snapshot)

    p = subparsers.add_parser("porter", help="Porter inspection and staging gate")
    p.add_argument("action", choices=["inspect", "stage"], help="Porter action")
    p.add_argument("source", help="Path to rule file or HTTP(S) URL")
    p.add_argument("--name", "-n", help="Override destination target name")
    p.add_argument("--force", "-f", action="store_true", help="Ingest despite constitutional violations (confirmation required)")
    p.add_argument("--expect-sha256", help="Only ingest if the source still has this content hash (from 'inspect')")
    p.set_defaults(func=cmd_porter)

    p = subparsers.add_parser("upstream", help="Check tracked upstream repositories")
    p.add_argument("action", choices=["check", "status", "ack"], default="check", nargs="?", help="Upstream action")
    p.add_argument("--model", help="Model name to record with 'ack'")
    p.add_argument("--offline", action="store_true", help="Inspect local ledger without network requests")
    p.set_defaults(func=cmd_upstream)

    p = subparsers.add_parser("startup", help="Manage the boot sentinel registration")
    p.add_argument("action", choices=["enable", "disable", "status"], default="status", nargs="?", help="Startup action")
    p.set_defaults(func=cmd_startup)

    p = subparsers.add_parser("boot-check", help="Headless boot verification and lock enforcement")
    p.set_defaults(func=cmd_boot_check)

    p = subparsers.add_parser("gui", help="Launch the desktop interface")
    p.set_defaults(func=cmd_gui)

    p = subparsers.add_parser("doctor", help="Health check (permissions, baseline, legacy state, risky grants)")
    p.add_argument("--fix", "--recover", action="store_true", dest="fix", help="Re-lock and establish a missing baseline")
    env_opts(p)
    p.set_defaults(func=cmd_doctor)

    p = subparsers.add_parser("test-boundary", help="Guard tests and runner configs as a trust boundary")
    p.add_argument("action", choices=["snapshot", "verify", "run-reproducible"], help="Test boundary action")
    p.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Verification mode (default: bugfix)")
    p.add_argument("--dir", help="Target workspace root directory")
    p.add_argument("--output", help="Snapshot output path")
    p.add_argument("--snapshot", help="Custom snapshot path to verify against")
    p.add_argument("--base-ref", help="Verify against a git ref (e.g. origin/main) instead of a stored snapshot")
    p.add_argument("--authorize", action="append", default=[], help="Relative test path authorized for contract modification (repeatable)")
    p.add_argument("--cmd", help="Target test command for run-reproducible")
    p.add_argument("--passes", type=int, default=2, help="Consecutive passes required (>= 2, default: 2)")
    p.set_defaults(func=cmd_test_boundary)

    p = subparsers.add_parser("provenance", help="Generate and inspect the execution provenance manifest")
    p.add_argument("action", choices=["generate", "status"], default="status", nargs="?", help="Provenance action")
    p.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Operating mode for boundary check")
    p.add_argument("--dir", help="Target workspace root directory")
    p.add_argument("--base-ref", help="Git ref for the test boundary baseline (e.g. origin/main)")
    p.add_argument("--authorize", action="append", default=[], help="Relative test path authorized for contract modification (repeatable)")
    p.add_argument("--test-cmd", help="Optional test command to check reproducibility")
    p.add_argument("--passes", type=int, default=2, help="Reproducibility passes (>= 2, default: 2)")
    p.set_defaults(func=cmd_provenance)

    p = subparsers.add_parser("env", help="Manage multi-environment registration and policies")
    p.add_argument("action", choices=["list", "detect", "add", "remove", "policy"], default="list", nargs="?", help="Environment action")
    p.add_argument("target", nargs="?", help="Environment id (for remove/policy)")
    p.add_argument("value", nargs="?", help=f"Policy value for 'policy' ({'|'.join(VALID_POLICIES)})")
    p.add_argument("--name", "-n", help="Environment id or display name")
    p.add_argument("--path", "-p", help="Root path for 'add', workspace for 'detect'")
    p.add_argument("--type", "-t", choices=["antigravity", "claude", "codex", "cursor", "aider", "custom"], help="Platform type")
    p.add_argument("--policy", choices=VALID_POLICIES, help="Policy for 'add'")
    p.add_argument("--policy-val", choices=VALID_POLICIES, help="Policy for 'policy'")
    p.add_argument("--dry-run", action="store_true", help="Preview discovery without saving to registry")
    p.set_defaults(func=cmd_env)

    p = subparsers.add_parser("request-unlock", help="Request a time-bounded unlock (human approval, automatic relock)")
    p.add_argument("--env", "-e", default="antigravity", help="Environment id to unlock")
    p.add_argument("--reason", "-r", default="Maintenance operation", help="Reason for requesting unlock")
    p.add_argument("--duration", "-d", type=int, default=60,
                   help=f"Lease duration in seconds ({MIN_LEASE_SECONDS}-{MAX_LEASE_SECONDS}, default: 60)")
    p.add_argument("--non-interactive", action="store_true", help="Never prompt (the request is then rejected)")
    p.set_defaults(func=cmd_request_unlock)

    p = subparsers.add_parser("lock-complete", help="End maintenance early and re-lock immediately")
    p.add_argument("--env", "-e", help="Environment id (default: all active leases)")
    p.set_defaults(func=cmd_lock_complete)

    p = subparsers.add_parser("lease-tick", help="Internal: expire due leases (used by the auto-relock watcher)")
    p.add_argument("--wait", type=int, default=0, help="Seconds to wait before checking")
    p.add_argument("--lease-file", help=argparse.SUPPRESS)
    p.add_argument("--registry", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_lease_tick)

    p = subparsers.add_parser("drift", help="Analyze drift across registered environments")
    p.add_argument("--env", "-e", help="Environment id to inspect (defaults to all)")
    p.set_defaults(func=cmd_drift)

    p = subparsers.add_parser("self-audit", help="Run the harness meta-consistency self-audit")
    p.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    p.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    p.add_argument("--root", help="Harness root to audit (default: this repository or ~/.gemini/config)")
    p.set_defaults(func=cmd_self_audit)

    p = subparsers.add_parser("notify", help="Configure desktop notifications")
    p.add_argument("action", choices=["status", "enable", "disable", "quiet", "normal", "send"], default="status", nargs="?")
    p.add_argument("--title", help="send: notification title")
    p.add_argument("--message", help="send: notification text")
    p.add_argument("--severity", choices=["info", "warning", "critical"], default="info", help="send: severity")
    p.add_argument("--key", help="send: de-duplication key (cooldown bucket)")
    p.set_defaults(func=cmd_notify)

    return parser



def _robust_console() -> None:
    """Never crash on a console that cannot encode a character (Windows cp1252 pipes): replace it."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

def main(argv: Optional[List[str]] = None) -> int:
    _robust_console()
    parser = build_parser()
    raw_args = sys.argv[1:] if argv is None else list(argv)
    args = parser.parse_args(raw_args)

    if not args.command:
        if not raw_args and sys.stdout.isatty() and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return cmd_gui(args)
        parser.print_help()
        return 0

    try:
        if args.command not in ("lease-tick", "gui", "notify"):
            try:
                LeaseManager(registry=_registry(args)).check_and_expire_leases()
            except Exception as e:  # never let lease housekeeping block the requested command
                print(f"[WARN] Lease housekeeping failed: {e}", file=sys.stderr)
        return args.func(args)
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
